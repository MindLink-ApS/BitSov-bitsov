//! Newcomer operations use the table installed by migration 031. A retryable
//! refusal is terminal; successors point to the original owner request. Uncertain
//! deliveries never create successors. All create/retry decisions serialize on
//! the existing singleton row, including across separate API/worker processes.
use crate::StorageError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarterRequest {
    pub request_id: String,
    pub hub_node_id: String,
    pub hub_ln_pubkey: String,
    pub network: String,
    pub state: String,
    pub detail: Option<String>,
    pub reason: Option<String>,
    pub retry_allowed: bool,
    pub retry_after_unix: Option<i64>,
    pub original_request_id: Option<String>,
    pub capacity_sats: Option<i64>,
    pub push_sats: Option<i64>,
    pub channel_id: Option<String>,
    pub user_channel_id: Option<String>,
    pub funding_txid: Option<String>,
    pub verified_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_sent_at: Option<i64>,
    pub send_attempts: i64,
}
impl StarterRequest {
    pub fn new(
        request_id: String,
        hub_node_id: String,
        hub_ln_pubkey: String,
        network: String,
        now: i64,
    ) -> Self {
        Self {
            request_id,
            hub_node_id,
            hub_ln_pubkey,
            network,
            state: "requested".into(),
            detail: None,
            reason: None,
            retry_allowed: false,
            retry_after_unix: None,
            original_request_id: None,
            capacity_sats: None,
            push_sats: None,
            channel_id: None,
            user_channel_id: None,
            funding_txid: None,
            verified_at: None,
            created_at: now,
            updated_at: now,
            last_sent_at: None,
            send_attempts: 0,
        }
    }
    pub fn terminal(&self) -> bool {
        matches!(self.state.as_str(), "ready" | "refused")
    }
    pub fn root_id(&self) -> &str {
        self.original_request_id
            .as_deref()
            .unwrap_or(&self.request_id)
    }
}
macro_rules! row {
    ($ty:ty) => {
        impl sqlx::FromRow<'_, $ty> for StarterRequest {
            fn from_row(r: &$ty) -> Result<Self, sqlx::Error> {
                use sqlx::Row;
                Ok(Self {
                    request_id: r.try_get("request_id")?,
                    hub_node_id: r.try_get("hub_node_id")?,
                    hub_ln_pubkey: r.try_get("hub_ln_pubkey")?,
                    network: r.try_get("network")?,
                    state: r.try_get("state")?,
                    detail: r.try_get("detail")?,
                    reason: r.try_get("reason")?,
                    retry_allowed: r.try_get::<i32, _>("retry_allowed")? != 0,
                    retry_after_unix: r.try_get("retry_after_unix")?,
                    original_request_id: r.try_get("original_request_id")?,
                    capacity_sats: r.try_get("capacity_sats")?,
                    push_sats: r.try_get("push_sats")?,
                    channel_id: r.try_get("channel_id")?,
                    user_channel_id: r.try_get("user_channel_id")?,
                    funding_txid: r.try_get("funding_txid")?,
                    verified_at: r.try_get("verified_at")?,
                    created_at: r.try_get("created_at")?,
                    updated_at: r.try_get("updated_at")?,
                    last_sent_at: r.try_get("last_sent_at")?,
                    send_attempts: r.try_get("send_attempts")?,
                })
            }
        }
    };
}
row!(sqlx::sqlite::SqliteRow);
row!(sqlx::postgres::PgRow);
macro_rules! backend {
 ($module:ident,$db:ty,$postgres:expr) => {
 pub(crate) mod $module {
 use super::*;
 fn sql(query: &str) -> String {
    if !$postgres { return query.into(); }
    let mut n=0;
    query.chars().map(|c| if c=='?' { n+=1; format!("${n}") } else { c.to_string() }).collect()
 }
 pub async fn get(pool:&sqlx::Pool<$db>,id:&str) -> Result<Option<StarterRequest>,StorageError> {
    Ok(sqlx::query_as(&sql("SELECT * FROM starter_requests WHERE request_id=?")).bind(id).fetch_optional(pool).await?)
 }
 pub async fn current(pool:&sqlx::Pool<$db>) -> Result<Option<StarterRequest>,StorageError> {
    Ok(sqlx::query_as("SELECT * FROM starter_requests ORDER BY CASE WHEN state='refused' THEN 1 ELSE 0 END, created_at DESC, request_id DESC LIMIT 1").fetch_optional(pool).await?)
 }
 async fn insert(tx:&mut sqlx::Transaction<'_,$db>, r:&StarterRequest) -> Result<(),StorageError> {
    sqlx::query(&sql("INSERT INTO starter_requests (request_id,hub_node_id,hub_ln_pubkey,network,state,detail,reason,retry_allowed,retry_after_unix,original_request_id,capacity_sats,push_sats,channel_id,user_channel_id,funding_txid,verified_at,created_at,updated_at,last_sent_at,send_attempts) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"))
        .bind(&r.request_id)
        .bind(&r.hub_node_id)
        .bind(&r.hub_ln_pubkey)
        .bind(&r.network)
        .bind(&r.state)
        .bind(&r.detail)
        .bind(&r.reason)
        .bind(i32::from(r.retry_allowed))
        .bind(&r.retry_after_unix)
        .bind(&r.original_request_id)
        .bind(&r.capacity_sats)
        .bind(&r.push_sats)
        .bind(&r.channel_id)
        .bind(&r.user_channel_id)
        .bind(&r.funding_txid)
        .bind(&r.verified_at)
        .bind(&r.created_at)
        .bind(&r.updated_at)
        .bind(&r.last_sent_at)
        .bind(&r.send_attempts)
        .execute(&mut **tx).await?;
    Ok(())
 }
 pub async fn create(pool:&sqlx::Pool<$db>,r:&StarterRequest) -> Result<(StarterRequest,bool),StorageError> {
    let mut tx=pool.begin().await?;
    sqlx::query("UPDATE starter_hub_counters SET id=id WHERE id=1").execute(&mut *tx).await?;
    if let Some(row)=sqlx::query_as::<_,StarterRequest>(&sql("SELECT * FROM starter_requests WHERE request_id=? OR state<>'refused' ORDER BY CASE WHEN request_id=? THEN 0 ELSE 1 END LIMIT 1")).bind(&r.request_id).bind(&r.request_id).fetch_optional(&mut *tx).await? {
        tx.commit().await?; return Ok((row,false));
    }
    insert(&mut tx,r).await?;
    tx.commit().await?; Ok((r.clone(),true))
 }
 /// Only called with an original grant identified by authenticated already_served.
 pub async fn adopt(pool:&sqlx::Pool<$db>,r:&StarterRequest)->Result<StarterRequest,StorageError>{
    let mut tx=pool.begin().await?;
    sqlx::query("UPDATE starter_hub_counters SET id=id WHERE id=1").execute(&mut *tx).await?;
    if let Some(live)=sqlx::query_as::<_,StarterRequest>("SELECT * FROM starter_requests WHERE state<>'refused' LIMIT 1").fetch_optional(&mut *tx).await? {
        tx.commit().await?; return Ok(live);
    }
    let mut adopted=r.clone();
    adopted.state="requested".into();adopted.detail=Some("adopted".into());
    adopted.reason=None;adopted.retry_allowed=false;adopted.retry_after_unix=None;
    adopted.original_request_id=None;adopted.send_attempts=0;adopted.last_sent_at=None;
    if let Some(existing)=sqlx::query_as::<_,StarterRequest>(&sql("SELECT * FROM starter_requests WHERE request_id=?")).bind(&r.request_id).fetch_optional(&mut *tx).await? {
        if existing.hub_node_id!=r.hub_node_id || existing.hub_ln_pubkey!=r.hub_ln_pubkey || existing.network!=r.network {tx.commit().await?;return Ok(existing);}
        // Authenticated adoption is the sole exception to refusal terminality:
        // the hub proves this exact UUID now identifies a live grant.
        sqlx::query(&sql("DELETE FROM starter_requests WHERE request_id=? AND state='refused'")).bind(&r.request_id).execute(&mut *tx).await?;
    }
    insert(&mut tx,&adopted).await?;
    tx.commit().await?;Ok(adopted)
 }
 pub async fn rearm(pool:&sqlx::Pool<$db>,id:&str)->Result<(),StorageError>{
    sqlx::query(&sql("UPDATE starter_requests SET send_attempts=0,last_sent_at=NULL WHERE request_id=? AND state IN ('requested','opening') AND send_attempts>=8")).bind(id).execute(pool).await?;
    Ok(())
 }
 pub async fn save(pool:&sqlx::Pool<$db>,r:&StarterRequest) -> Result<(),StorageError> {
    sqlx::query(&sql("UPDATE starter_requests SET original_request_id=?,state=?,detail=?,reason=?,retry_allowed=?,retry_after_unix=?,capacity_sats=?,push_sats=?,channel_id=?,user_channel_id=?,funding_txid=?,verified_at=?,updated_at=?,last_sent_at=?,send_attempts=? WHERE request_id=? AND state NOT IN ('ready','refused')"))
        .bind(&r.original_request_id)
        .bind(&r.state)
        .bind(&r.detail)
        .bind(&r.reason)
        .bind(i32::from(r.retry_allowed))
        .bind(&r.retry_after_unix)
        .bind(&r.capacity_sats)
        .bind(&r.push_sats)
        .bind(&r.channel_id)
        .bind(&r.user_channel_id)
        .bind(&r.funding_txid)
        .bind(&r.verified_at)
        .bind(&r.updated_at)
        .bind(&r.last_sent_at)
        .bind(&r.send_attempts)
        .bind(&r.request_id).execute(pool).await?;
    Ok(())
 }
 pub async fn retry(pool:&sqlx::Pool<$db>,id:&str,now:i64) -> Result<StarterRequest,StorageError> {
    let mut tx=pool.begin().await?;
    sqlx::query("UPDATE starter_hub_counters SET id=id WHERE id=1").execute(&mut *tx).await?;
    let parent:StarterRequest=sqlx::query_as(&sql("SELECT * FROM starter_requests WHERE request_id=?")).bind(id).fetch_one(&mut *tx).await?;
    // Any existing live request wins, regardless of configured hub.
    if let Some(live)=sqlx::query_as::<_,StarterRequest>("SELECT * FROM starter_requests WHERE state<>'refused' LIMIT 1").fetch_optional(&mut *tx).await? {
        tx.commit().await?; return Ok(live);
    }
    let root=parent.root_id();
    let count:i64=sqlx::query_scalar(&sql("SELECT COUNT(*) FROM starter_requests WHERE original_request_id=?")).bind(root).fetch_one(&mut *tx).await?;
    let latest:StarterRequest=sqlx::query_as(&sql("SELECT * FROM starter_requests WHERE request_id=? OR original_request_id=? ORDER BY created_at DESC,request_id DESC LIMIT 1")).bind(root).bind(root).fetch_one(&mut *tx).await?;
    if latest.request_id!=id || !parent.retry_allowed {tx.commit().await?;return Ok(latest);}
    let mut latest=latest;
    if count>=3 {
        latest.detail=Some("auto_retry_exhausted".into());
        sqlx::query(&sql("UPDATE starter_requests SET detail='auto_retry_exhausted' WHERE request_id=?")).bind(id).execute(&mut *tx).await?;
        tx.commit().await?;return Ok(latest);
    }
    let due=parent.retry_after_unix.unwrap_or(i64::MAX).max(parent.updated_at.saturating_add(600 * (1 << count)));
    if due>now {
        latest.retry_after_unix=Some(due);
        sqlx::query(&sql("UPDATE starter_requests SET retry_after_unix=? WHERE request_id=?")).bind(due).bind(id).execute(&mut *tx).await?;
        tx.commit().await?;return Ok(latest);
    }
    let mut child=StarterRequest::new(uuid::Uuid::new_v4().to_string(),parent.hub_node_id.clone(),parent.hub_ln_pubkey.clone(),parent.network.clone(),now.max(parent.created_at+1));
    child.original_request_id=Some(root.into());
    insert(&mut tx,&child).await?;
    tx.commit().await?;Ok(child)
 }
 }
 }
}
backend!(sqlite, sqlx::Sqlite, false);
backend!(postgres, sqlx::Postgres, true);
