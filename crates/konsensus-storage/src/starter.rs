//! Atomic starter reservations. Every mutation takes the counter write lock before
//! reading grants. Recounting under that lock makes day normalization and refunds
//! one transaction, including a refund before the first admission after midnight.
use crate::{ChannelOpenOperation, StorageError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarterGrant {
    pub request_id: String,
    pub requester_node_id: String,
    pub ln_pubkey: String,
    pub network: String,
    pub invite_id: String,
    pub state: String,
    pub reason: Option<String>,
    pub retry_after_unix: Option<i64>,
    pub attempts: i64,
    pub capacity_sats: i64,
    pub push_sats: i64,
    pub utc_day: String,
    pub open_operation_id: String,
    pub channel_id: Option<String>,
    pub user_channel_id: Option<String>,
    pub funding_txid: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}
impl StarterGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: String,
        requester_node_id: String,
        ln_pubkey: String,
        network: String,
        invite_id: String,
        capacity_sats: i64,
        push_sats: i64,
        now: i64,
    ) -> Self {
        Self {
            open_operation_id: request_id.clone(),
            request_id,
            requester_node_id,
            ln_pubkey: ln_pubkey.to_ascii_lowercase(),
            network,
            invite_id,
            state: "admitted".into(),
            reason: None,
            retry_after_unix: None,
            attempts: 0,
            capacity_sats,
            push_sats,
            utc_day: utc_day(now),
            channel_id: None,
            user_channel_id: None,
            funding_txid: None,
            created_at: now,
            updated_at: now,
        }
    }
}
pub fn utc_day(now: i64) -> String {
    chrono::DateTime::from_timestamp(now, 0)
        .expect("valid Unix timestamp")
        .format("%Y-%m-%d")
        .to_string()
}
/// Hot-path reads never materialize the grant history. Pages use a fixed bound
/// and keyset cursors so a failed grant cannot starve later recovery work.
#[derive(Debug)]
pub enum StarterQuery {
    Request(String),
    Identity {
        requester: String,
        ln_pubkey: String,
    },
    LatestRequester(String),
    Work {
        after: String,
    },
    Recent {
        since: i64,
        after: (i64, String),
    },
}
pub const STARTER_PAGE_SIZE: usize = 128;

#[derive(Debug, Clone)]
pub struct StarterLimits {
    pub max_opens_per_day: i64,
    pub max_concurrent_opens: i64,
    pub lifetime_budget_sats: i64,
}
#[derive(Debug, Default)]
pub struct StarterOutcome {
    pub grant: Option<StarterGrant>,
    pub reason: Option<String>,
    pub original_request_id: Option<String>,
    pub claimed: bool,
}
#[derive(Debug)]
pub struct StarterCounters {
    pub utc_day: String,
    pub day_count: i64,
    pub inflight_count: i64,
    pub committed_sats: i64,
}
#[derive(Debug)]
pub enum StarterUpdate {
    Admit {
        grant: StarterGrant,
        limits: StarterLimits,
    },
    /// Insert operation and transition grant BEFORE the caller can dispatch.
    Claim {
        id: String,
        operation: ChannelOpenOperation,
    },
    /// Release an invalid invite only while no dispatch operation exists.
    CancelInvalidInvite {
        id: String,
    },
    /// Only the live dispatcher may supply proven PaymentNotDispatched evidence.
    NonDispatch {
        id: String,
        reason: String,
        terminal: bool,
    },
    Observe {
        id: String,
        channel_id: String,
        user_channel_id: Option<String>,
        funding_txid: Option<String>,
        ready: bool,
    },
    /// Operator accepts the possible loss. Never refunds capital or identity.
    ResolveUncertain {
        id: String,
    },
    MarkUncertain {
        id: String,
    },
    Rebuild,
}

macro_rules! from_row {
    ($row:ty) => {
        impl sqlx::FromRow<'_, $row> for StarterGrant {
            fn from_row(r: &$row) -> Result<Self, sqlx::Error> {
                use sqlx::Row;
                Ok(Self {
                    request_id: r.try_get("request_id")?,
                    requester_node_id: r.try_get("requester_node_id")?,
                    ln_pubkey: r.try_get("ln_pubkey")?,
                    network: r.try_get("network")?,
                    invite_id: r.try_get("invite_id")?,
                    state: r.try_get("state")?,
                    reason: r.try_get("reason")?,
                    retry_after_unix: r.try_get("retry_after_unix")?,
                    attempts: r.try_get("attempts")?,
                    capacity_sats: r.try_get("capacity_sats")?,
                    push_sats: r.try_get("push_sats")?,
                    utc_day: r.try_get("utc_day")?,
                    open_operation_id: r.try_get("open_operation_id")?,
                    channel_id: r.try_get("channel_id")?,
                    user_channel_id: r.try_get("user_channel_id")?,
                    funding_txid: r.try_get("funding_txid")?,
                    created_at: r.try_get("created_at")?,
                    updated_at: r.try_get("updated_at")?,
                })
            }
        }
        impl sqlx::FromRow<'_, $row> for StarterCounters {
            fn from_row(r: &$row) -> Result<Self, sqlx::Error> {
                use sqlx::Row;
                Ok(Self {
                    utc_day: r.try_get("utc_day")?,
                    day_count: r.try_get("day_count")?,
                    inflight_count: r.try_get("inflight_count")?,
                    committed_sats: r.try_get("committed_sats")?,
                })
            }
        }
    };
}
from_row!(sqlx::sqlite::SqliteRow);
from_row!(sqlx::postgres::PgRow);

// Keep transaction logic identical across the two SQL dialects. All placeholders
// originate in static SQL, never caller input.
macro_rules! backend {
    ($module:ident, $db:ty, $postgres:expr) => {
        pub(crate) mod $module {
            use super::*;
            fn sql(query: &str) -> String {
                if !$postgres {return query.into();}
                let mut n=0;
                query.chars().map(|c| if c=='?' {n+=1;format!("${n}")} else {c.to_string()}).collect()
            }
            pub async fn grants(pool: &sqlx::Pool<$db>) -> Result<Vec<StarterGrant>,StorageError> {
                Ok(sqlx::query_as("SELECT * FROM starter_grants ORDER BY created_at, request_id").fetch_all(pool).await?)
            }
            pub async fn query(pool: &sqlx::Pool<$db>, query: StarterQuery) -> Result<Vec<StarterGrant>,StorageError> {
                Ok(match query {
                    StarterQuery::Request(id) => sqlx::query_as(&sql("SELECT * FROM starter_grants WHERE request_id=?"))
                        .bind(id).fetch_all(pool).await?,
                    StarterQuery::Identity { requester, ln_pubkey } => sqlx::query_as(&sql("SELECT * FROM starter_grants WHERE state<>'refused' AND requester_node_id=? UNION ALL SELECT * FROM starter_grants WHERE state<>'refused' AND ln_pubkey=? LIMIT 1"))
                        .bind(requester).bind(ln_pubkey).fetch_all(pool).await?,
                    StarterQuery::LatestRequester(requester) => sqlx::query_as(&sql("SELECT * FROM starter_grants WHERE requester_node_id=? ORDER BY created_at DESC, request_id DESC LIMIT 1"))
                        .bind(requester).fetch_all(pool).await?,
                    StarterQuery::Work { after } => {
                        // Drive ready-bookkeeping repair from unsettled invites, not
                        // from the ever-growing completed grant history. Invite IDs
                        // are binary in both backends; grant IDs are canonical UUIDs.
                        let hex = if $postgres { "encode(i.id,'hex')" } else { "lower(hex(i.id))" };
                        let id = format!("substr({hex},1,8)||'-'||substr({hex},9,4)||'-'||substr({hex},13,4)||'-'||substr({hex},17,4)||'-'||substr({hex},21,12)");
                        sqlx::query_as(&sql(&format!("SELECT * FROM starter_grants WHERE state IN ('admitted','opening','resolved') AND request_id>? UNION ALL SELECT g.* FROM invites_issued i CROSS JOIN starter_grants g WHERE g.invite_id={id} AND i.state IN ('pending','opening') AND g.state='ready' AND g.request_id>? ORDER BY request_id LIMIT {STARTER_PAGE_SIZE}")))
                            .bind(&after).bind(&after).fetch_all(pool).await?
                    },
                    StarterQuery::Recent { since, after } => sqlx::query_as(&sql(&format!("SELECT * FROM starter_grants WHERE updated_at>=? AND (updated_at,request_id)>(?,?) ORDER BY updated_at,request_id LIMIT {STARTER_PAGE_SIZE}")))
                        .bind(since).bind(after.0).bind(after.1).fetch_all(pool).await?,
                })
            }
            pub async fn has_served_invite(pool: &sqlx::Pool<$db>, peer: &[u8;32]) -> Result<bool,StorageError> {
                let found:Option<i32> = sqlx::query_scalar(&sql("SELECT 1 FROM invites_issued WHERE invitee_pubkey=? AND state IN ('opening','accepted') LIMIT 1"))
                    .bind(peer.as_slice()).fetch_optional(pool).await?;
                Ok(found.is_some())
            }
            pub async fn pending_invite_id(pool: &sqlx::Pool<$db>, peer: &[u8;32]) -> Result<Option<uuid::Uuid>,StorageError> {
                let id:Option<Vec<u8>> = sqlx::query_scalar(&sql("SELECT id FROM invites_issued WHERE invitee_pubkey=? AND state='pending' ORDER BY created_at DESC LIMIT 1"))
                    .bind(peer.as_slice()).fetch_optional(pool).await?;
                id.map(|id|uuid::Uuid::from_slice(&id).map_err(|_|StorageError::Conversion("invalid invite id".into()))).transpose()
            }
            pub async fn counters(pool: &sqlx::Pool<$db>) -> Result<StarterCounters,StorageError> {
                Ok(sqlx::query_as("SELECT * FROM starter_hub_counters WHERE id=1").fetch_one(pool).await?)
            }
            async fn recount(tx: &mut sqlx::Transaction<'_, $db>, day: &str) -> Result<(),StorageError> {
                sqlx::query(&sql("UPDATE starter_hub_counters SET utc_day=?, day_count=(SELECT COUNT(*) FROM starter_grants WHERE state<>'refused' AND utc_day=?), inflight_count=(SELECT COUNT(*) FROM starter_grants WHERE state IN ('admitted','opening')), committed_sats=(SELECT COALESCE(SUM(capacity_sats),0) FROM starter_grants WHERE state<>'refused') WHERE id=1"))
                    .bind(day).bind(day).execute(&mut **tx).await?;
                Ok(())
            }
            pub async fn update(pool: &sqlx::Pool<$db>, update: StarterUpdate, now: Option<i64>) -> Result<StarterOutcome,StorageError> {
                let mut tx=pool.begin().await?;
                // First statement is a WRITE: SQLite acquires its reserved writer
                // lock before any reads (equivalent to BEGIN IMMEDIATE here), and
                // Postgres holds this row exclusively until commit. RAII rollback
                // also protects cancellation at every await.
                sqlx::query("UPDATE starter_hub_counters SET id=id WHERE id=1").execute(&mut *tx).await?;
                let now=now.unwrap_or_else(||chrono::Utc::now().timestamp());
                let day=utc_day(now);
                recount(&mut tx,&day).await?;
                let mut out=StarterOutcome::default();
                let id=match update {
                    StarterUpdate::Admit {mut grant,limits} => {
                        if let Some(existing)=sqlx::query_as::<_,StarterGrant>(&sql("SELECT * FROM starter_grants WHERE request_id=?")).bind(&grant.request_id).fetch_optional(&mut *tx).await? {
                            if existing.requester_node_id!=grant.requester_node_id || existing.ln_pubkey!=grant.ln_pubkey || existing.network!=grant.network {
                                out.reason=Some("operation_mismatch".into());
                            } else {out.grant=Some(existing);}
                            tx.commit().await?;return Ok(out);
                        }
                        let existing:Option<StarterGrant>=sqlx::query_as(&sql("SELECT * FROM starter_grants WHERE state<>'refused' AND (requester_node_id=? OR ln_pubkey=?) LIMIT 1")).bind(&grant.requester_node_id).bind(&grant.ln_pubkey).fetch_optional(&mut *tx).await?;
                        if let Some(existing)=existing {out.reason=Some("already_served".into());out.original_request_id=Some(existing.request_id);tx.commit().await?;return Ok(out);}
                        let c:StarterCounters=sqlx::query_as("SELECT * FROM starter_hub_counters WHERE id=1").fetch_one(&mut *tx).await?;
                        if grant.state!="refused" {
                            let reason=if c.day_count>=limits.max_opens_per_day {Some("daily_cap_reached")}
                            else if c.inflight_count>=limits.max_concurrent_opens {Some("hub_busy")}
                            else if grant.capacity_sats<=0 || c.committed_sats.checked_add(grant.capacity_sats).is_none_or(|v|v>limits.lifetime_budget_sats) {Some("budget_exhausted")}
                            else {None};
                            if let Some(reason)=reason {grant.state="refused".into();grant.reason=Some(reason.into());grant.retry_after_unix=match reason {"daily_cap_reached"=>Some((now/86400+1)*86400),"hub_busy"=>Some(now+600),_=>None};}
                        }
                        // Only the newest refusal is useful for the requester throttle.
                        // Never prune a reservation or dispatch evidence from a live grant.
                        sqlx::query(&sql("DELETE FROM starter_grants WHERE requester_node_id=? AND state='refused'"))
                            .bind(&grant.requester_node_id).execute(&mut *tx).await?;
                        grant.utc_day=day.clone();
                        // ON CONFLICT covers partial-index races as well as PKs;
                        // it does not abort a Postgres transaction with a 500.
                        let inserted=sqlx::query(&sql("INSERT INTO starter_grants (request_id,requester_node_id,ln_pubkey,network,invite_id,state,reason,retry_after_unix,attempts,capacity_sats,push_sats,utc_day,open_operation_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING"))
                            .bind(&grant.request_id).bind(&grant.requester_node_id).bind(&grant.ln_pubkey).bind(&grant.network).bind(&grant.invite_id).bind(&grant.state).bind(&grant.reason).bind(grant.retry_after_unix).bind(grant.attempts).bind(grant.capacity_sats).bind(grant.push_sats).bind(&day).bind(&grant.open_operation_id).bind(now).bind(now).execute(&mut *tx).await?.rows_affected();
                        if inserted==0 {let winner:Option<StarterGrant>=sqlx::query_as(&sql("SELECT * FROM starter_grants WHERE state<>'refused' AND (requester_node_id=? OR ln_pubkey=?) LIMIT 1")).bind(&grant.requester_node_id).bind(&grant.ln_pubkey).fetch_optional(&mut *tx).await?;out.reason=Some("already_served".into());out.original_request_id=winner.map(|g|g.request_id);None}
                        else {out.reason=grant.reason.clone();Some(grant.request_id)}
                    }
                    StarterUpdate::Claim {id,operation} => {
                        if id!=operation.operation_id {return Err(StorageError::Conversion("starter operation id mismatch".into()));}
                        let admitted:Option<StarterGrant>=sqlx::query_as(&sql("SELECT * FROM starter_grants WHERE request_id=? AND state='admitted'")).bind(&id).fetch_optional(&mut *tx).await?;
                        if let Some(grant)=admitted {
                            let invite=uuid::Uuid::parse_str(&grant.invite_id).map_err(|_|StorageError::Conversion("invalid starter invite id".into()))?;
                            // Compete with ONB5's pending->opening CAS in this
                            // transaction. A grant alone never permits two openers.
                            let reserved=sqlx::query(&sql("UPDATE invites_issued SET state='opening',accepted_at=? WHERE id=? AND expiry_unix>? AND (state='pending' OR (state='opening' AND ?>0))"))
                                .bind(now).bind(invite.as_bytes().as_slice()).bind(now).bind(grant.attempts).execute(&mut *tx).await?.rows_affected();
                            if reserved==0 {
                                sqlx::query(&sql("UPDATE starter_grants SET state='refused',reason='already_served',updated_at=? WHERE request_id=?")).bind(now).bind(&id).execute(&mut *tx).await?;
                                recount(&mut tx,&day).await?;
                                tx.commit().await?;
                                return Ok(StarterOutcome{reason:Some("already_served".into()),..Default::default()});
                            }
                            let inserted=sqlx::query(&sql("INSERT INTO channel_open_operations (operation_id,request_hash,state,request,created_at,updated_at) VALUES (?,?,'pending',?,?,?) ON CONFLICT DO NOTHING")).bind(&id).bind(&operation.request_hash).bind(&operation.request).bind(now*1000).bind(now*1000).execute(&mut *tx).await?.rows_affected();
                            if inserted==1 {sqlx::query(&sql("UPDATE starter_grants SET state='opening', attempts=attempts+1,updated_at=? WHERE request_id=?")).bind(now).bind(&id).execute(&mut *tx).await?;out.claimed=true;}
                        }
                        Some(id)
                    }
                    StarterUpdate::CancelInvalidInvite {id} => {
                        let admitted:Option<StarterGrant>=sqlx::query_as(&sql("SELECT * FROM starter_grants WHERE request_id=? AND state='admitted' AND NOT EXISTS (SELECT 1 FROM channel_open_operations WHERE operation_id=starter_grants.open_operation_id)")).bind(&id).fetch_optional(&mut *tx).await?;
                        if let Some(grant)=admitted {
                            let invite=uuid::Uuid::parse_str(&grant.invite_id).map_err(|_|StorageError::Conversion("invalid starter invite id".into()))?;
                            let valid:Option<i32>=sqlx::query_scalar(&sql("SELECT 1 FROM invites_issued WHERE id=? AND expiry_unix>? AND (state='pending' OR (state='opening' AND ?>0))"))
                                .bind(invite.as_bytes().as_slice()).bind(now).bind(grant.attempts).fetch_optional(&mut *tx).await?;
                            if valid.is_none() {
                                sqlx::query(&sql("UPDATE starter_grants SET state='refused',reason='not_invited',updated_at=? WHERE request_id=?")).bind(now).bind(&id).execute(&mut *tx).await?;
                            }
                        }
                        Some(id)
                    }
                    StarterUpdate::NonDispatch {id,reason,terminal} => {
                        // Only pending operations can carry live-dispatch proof.
                        let pending=sqlx::query(&sql("DELETE FROM channel_open_operations WHERE operation_id=? AND state='pending' AND EXISTS (SELECT 1 FROM starter_grants WHERE request_id=? AND state='opening')")).bind(&id).bind(&id).execute(&mut *tx).await?.rows_affected();
                        if pending==1 {
                            if terminal {
                                let grant:StarterGrant=sqlx::query_as(&sql("SELECT * FROM starter_grants WHERE request_id=?")).bind(&id).fetch_one(&mut *tx).await?;
                                let invite=uuid::Uuid::parse_str(&grant.invite_id).map_err(|_|StorageError::Conversion("invalid starter invite id".into()))?;
                                sqlx::query(&sql("UPDATE invites_issued SET state='pending',accepted_at=NULL WHERE id=? AND state='opening'"))
                                    .bind(invite.as_bytes().as_slice()).execute(&mut *tx).await?;
                            }
                            sqlx::query(&sql("UPDATE starter_grants SET state=?,reason=?,retry_after_unix=?,updated_at=? WHERE request_id=?")).bind(if terminal {"refused"}else{"admitted"}).bind(if terminal {Some(reason)}else{None}).bind(if terminal {Some(now+3600)}else{None}).bind(now).bind(&id).execute(&mut *tx).await?;}
                        Some(id)
                    }
                    StarterUpdate::Observe {id,channel_id,user_channel_id,funding_txid,ready} => {
                        sqlx::query(&sql("UPDATE starter_grants SET state=CASE WHEN state='resolved' AND ?='opening' THEN 'resolved' ELSE ? END,channel_id=?,user_channel_id=?,funding_txid=?,updated_at=? WHERE request_id=? AND state IN ('opening','resolved')"))
                            .bind(if ready {"ready"}else{"opening"}).bind(if ready {"ready"}else{"opening"}).bind(channel_id).bind(user_channel_id).bind(funding_txid).bind(now).bind(&id).execute(&mut *tx).await?;
                        Some(id)
                    }
                    StarterUpdate::MarkUncertain {id} => {
                        sqlx::query(&sql("UPDATE channel_open_operations SET state='uncertain',last_error='no_unique_channel_match',updated_at=? WHERE operation_id=? AND state IN ('pending','opened') AND created_at<=? AND EXISTS (SELECT 1 FROM starter_grants WHERE request_id=? AND state='opening')"))
                            .bind(now*1000).bind(&id).bind(now.saturating_mul(1000)-600_000).bind(&id).execute(&mut *tx).await?;
                        Some(id)
                    }
                    StarterUpdate::ResolveUncertain {id} => {
                        sqlx::query(&sql("UPDATE starter_grants SET state='resolved',reason='operator_charged',updated_at=? WHERE request_id=? AND state='opening' AND EXISTS (SELECT 1 FROM channel_open_operations WHERE operation_id=? AND state='uncertain')")).bind(now).bind(&id).bind(&id).execute(&mut *tx).await?;
                        Some(id)
                    }
                    StarterUpdate::Rebuild=>None,
                };
                recount(&mut tx,&day).await?;
                if let Some(id)=id {out.grant=sqlx::query_as(&sql("SELECT * FROM starter_grants WHERE request_id=?")).bind(id).fetch_optional(&mut *tx).await?;}
                tx.commit().await?;
                Ok(out)
            }
        }
    }
}
backend!(sqlite, sqlx::Sqlite, false);
backend!(postgres, sqlx::Postgres, true);
