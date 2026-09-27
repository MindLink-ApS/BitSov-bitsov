//! The node's own physiology, read locally (O1 v2): energy (N1) and membrane (N2).
//!
//! Both are this node's ledger of itself. They are read scope, loopback clients
//! only in practice, never gossiped, and describe no one else's traffic: there is
//! no global graph here and no route that exports one. Counterparty ids are the
//! ones this node already stores for its own conversations.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use konsensus_storage::{EnergyRow, StorageError};

use crate::auth::scoped::{Read, ScopedAuth};
use crate::error::ApiError;
use crate::membrane::{MembraneEvent, Totals, MEMBRANE_CAPACITY};
use crate::state::AppState;

/// `/status` capability: `GET /api/v1/energy`.
pub const ENERGY_CAPABILITY: &str = "energy_v1";

/// Rows read per energy request. A node past this in one window reports
/// `truncated: true` rather than a silently low total.
const ENERGY_ROW_LIMIT: u32 = 100_000;

const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = 60 * MINUTE_MS;
const DAY_MS: u64 = 24 * HOUR_MS;

/// Energy window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum Window {
    /// Last hour, 12 five-minute buckets.
    #[serde(rename = "1h")]
    Hour,
    /// Last 24 hours, 24 hourly buckets.
    #[serde(rename = "24h")]
    Day,
    /// Last 7 days, 7 daily buckets.
    #[serde(rename = "7d")]
    Week,
}

impl Window {
    fn span_ms(self) -> u64 {
        match self {
            Self::Hour => HOUR_MS,
            Self::Day => DAY_MS,
            Self::Week => 7 * DAY_MS,
        }
    }

    fn bucket_ms(self) -> u64 {
        match self {
            Self::Hour => 5 * MINUTE_MS,
            Self::Day => HOUR_MS,
            Self::Week => DAY_MS,
        }
    }
}

/// `GET /api/v1/energy` query.
#[derive(Debug, Deserialize)]
pub struct EnergyQuery {
    /// `1h`, `24h` (default) or `7d`.
    #[serde(default)]
    pub window: Option<Window>,
}

/// One time bucket. Buckets with no paid message are omitted, never zero-filled.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EnergyBucket {
    /// Bucket start, unix milliseconds (aligned to `bucket_ms`).
    pub start_ms: u64,
    /// Received.
    pub in_msat: u64,
    /// Sent.
    pub out_msat: u64,
}

/// Energy exchanged with one counterparty in the window.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CounterpartyEnergy {
    /// Peer node id (hex) or room id.
    pub counterparty: String,
    /// `"node"` or `"room"`.
    pub counterparty_kind: &'static str,
    /// Received from them.
    pub in_msat: u64,
    /// Sent to them.
    pub out_msat: u64,
    /// Paid messages received.
    pub in_count: u64,
    /// Paid messages sent.
    pub out_count: u64,
}

/// Node-wide totals in the window.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EnergyTotals {
    /// Received.
    pub in_msat: u64,
    /// Sent.
    pub out_msat: u64,
    /// Paid messages received.
    pub in_count: u64,
    /// Paid messages sent.
    pub out_count: u64,
}

/// `GET /api/v1/energy` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnergyResponse {
    /// The window read.
    pub window: Window,
    /// When the node read its store, unix milliseconds.
    pub as_of_ms: u64,
    /// Window start, unix milliseconds.
    pub since_ms: u64,
    /// Bucket width, milliseconds.
    pub bucket_ms: u64,
    /// Oldest first; empty buckets omitted.
    pub buckets: Vec<EnergyBucket>,
    /// Largest total exchange first.
    pub counterparties: Vec<CounterpartyEnergy>,
    /// Node-wide.
    pub totals: EnergyTotals,
    /// True when the row limit cut the window short (totals are then a floor).
    pub truncated: bool,
    /// Where the numbers come from, stated so a client can say so.
    pub source: &'static str,
}

/// Sum stored paid messages into the energy view. Pure, for testing.
#[must_use]
pub fn aggregate(
    rows: &[EnergyRow],
    me: &str,
    window: Window,
    as_of_ms: u64,
    truncated: bool,
) -> EnergyResponse {
    let since_ms = as_of_ms.saturating_sub(window.span_ms());
    let bucket_ms = window.bucket_ms();
    let mut buckets: BTreeMap<u64, EnergyBucket> = BTreeMap::new();
    let mut peers: BTreeMap<String, CounterpartyEnergy> = BTreeMap::new();
    let mut totals = EnergyTotals::default();

    for row in rows {
        if row.timestamp_ms < since_ms || row.amount_msat == 0 {
            continue;
        }
        let is_room = row.recipient_type == "room";
        let (outgoing, counterparty) = if row.sender == me {
            (true, row.recipient_id.clone())
        } else if is_room {
            // A room message from another member: energy that reached us
            // through the room. Attributed to the room, not the member.
            (false, row.recipient_id.clone())
        } else if row.recipient_type == "node" && row.recipient_id == me {
            (false, row.sender.clone())
        } else {
            // Not ours in either direction (e.g. held for relay).
            continue;
        };

        let start_ms = row.timestamp_ms - row.timestamp_ms % bucket_ms;
        let bucket = buckets.entry(start_ms).or_insert_with(|| EnergyBucket {
            start_ms,
            ..EnergyBucket::default()
        });
        let peer = peers
            .entry(counterparty.clone())
            .or_insert_with(|| CounterpartyEnergy {
                counterparty,
                counterparty_kind: if is_room { "room" } else { "node" },
                ..CounterpartyEnergy::default()
            });
        if outgoing {
            bucket.out_msat = bucket.out_msat.saturating_add(row.amount_msat);
            peer.out_msat = peer.out_msat.saturating_add(row.amount_msat);
            peer.out_count += 1;
            totals.out_msat = totals.out_msat.saturating_add(row.amount_msat);
            totals.out_count += 1;
        } else {
            bucket.in_msat = bucket.in_msat.saturating_add(row.amount_msat);
            peer.in_msat = peer.in_msat.saturating_add(row.amount_msat);
            peer.in_count += 1;
            totals.in_msat = totals.in_msat.saturating_add(row.amount_msat);
            totals.in_count += 1;
        }
    }

    let mut counterparties: Vec<CounterpartyEnergy> = peers.into_values().collect();
    counterparties.sort_by(|a, b| {
        (b.in_msat.saturating_add(b.out_msat))
            .cmp(&a.in_msat.saturating_add(a.out_msat))
            .then_with(|| a.counterparty.cmp(&b.counterparty))
    });

    EnergyResponse {
        window,
        as_of_ms,
        since_ms,
        bucket_ms,
        buckets: buckets.into_values().collect(),
        counterparties,
        totals,
        truncated,
        source: "stored paid messages (settled at the gate or paid by this node)",
    }
}

fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

/// `GET /api/v1/energy?window=1h|24h|7d` — sats in and out, per counterparty
/// and per bucket, from this node's own stored paid messages. Read scope.
async fn energy(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Query(q): Query<EnergyQuery>,
) -> Result<Json<EnergyResponse>, ApiError> {
    let window = q.window.unwrap_or(Window::Day);
    let as_of_ms = now_ms();
    let since_ms = as_of_ms.saturating_sub(window.span_ms());
    let rows = state
        .storage
        .energy_rows_since(since_ms, ENERGY_ROW_LIMIT)
        .await
        .map_err(|e| match e {
            StorageError::Unsupported(_) => {
                ApiError::NotFound("energy read not supported by this storage backend".into())
            }
            other => ApiError::Storage(other.to_string()),
        })?;
    let truncated = rows.len() >= ENERGY_ROW_LIMIT as usize;
    let me = state.identity.node_id().to_hex();
    Ok(Json(aggregate(&rows, &me, window, as_of_ms, truncated)))
}

/// `GET /api/v1/membrane` query.
#[derive(Debug, Deserialize)]
pub struct MembraneQuery {
    /// Only events decided after this time (unix ms).
    #[serde(default)]
    pub since: Option<u64>,
    /// At most this many (default 100, max the ring capacity).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// `GET /api/v1/membrane` response.
#[derive(Debug, Serialize)]
pub struct MembraneResponse {
    /// Ring bound; older decisions are gone, not hidden.
    pub capacity: usize,
    /// Counts since the node started (not persisted).
    pub totals: Totals,
    /// Newest first.
    pub events: Vec<Arc<MembraneEvent>>,
}

/// `GET /api/v1/membrane?since=&limit=` — recent admission decisions from the
/// bounded in-memory ring. Read scope. No export, no persistence.
async fn membrane(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MembraneQuery>,
) -> Json<MembraneResponse> {
    let log = state.audit_log.membrane();
    let limit = q.limit.unwrap_or(100).min(MEMBRANE_CAPACITY);
    let (events, totals) = log.read(q.since, limit);
    Json(MembraneResponse {
        capacity: log.capacity(),
        totals,
        events,
    })
}

/// Registers the organism read routes.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/energy", get(energy))
        .route("/api/v1/membrane", get(membrane))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "aa";

    fn row(sender: &str, rtype: &str, rid: &str, ts: u64, amt: u64) -> EnergyRow {
        EnergyRow {
            sender: sender.into(),
            recipient_type: rtype.into(),
            recipient_id: rid.into(),
            timestamp_ms: ts,
            amount_msat: amt,
        }
    }

    #[test]
    fn sums_in_and_out_per_counterparty() {
        let now = 10 * DAY_MS;
        let rows = [
            row("bb", "node", ME, now - 10 * MINUTE_MS, 20_000),
            row("bb", "node", ME, now - 20 * MINUTE_MS, 20_000),
            row(ME, "node", "bb", now - 30 * MINUTE_MS, 5_000),
            row(ME, "node", "cc", now - 2 * HOUR_MS, 7_000),
            row("dd", "room", "room-1", now - 3 * HOUR_MS, 1_000),
            row(ME, "room", "room-1", now - 3 * HOUR_MS, 2_000),
        ];
        let r = aggregate(&rows, ME, Window::Day, now, false);
        assert_eq!(
            r.totals,
            EnergyTotals {
                in_msat: 41_000,
                out_msat: 14_000,
                in_count: 3,
                out_count: 3
            }
        );
        let bb = r
            .counterparties
            .iter()
            .find(|c| c.counterparty == "bb")
            .unwrap();
        assert_eq!(
            (bb.in_msat, bb.out_msat, bb.in_count, bb.out_count),
            (40_000, 5_000, 2, 1)
        );
        let room = r
            .counterparties
            .iter()
            .find(|c| c.counterparty == "room-1")
            .unwrap();
        assert_eq!(
            (room.counterparty_kind, room.in_msat, room.out_msat),
            ("room", 1_000, 2_000)
        );
        assert_eq!(
            r.counterparties[0].counterparty, "bb",
            "largest exchange first"
        );
    }

    #[test]
    fn empty_buckets_are_omitted_and_window_is_respected() {
        let now = 10 * DAY_MS;
        let rows = [
            row("bb", "node", ME, now - 2 * DAY_MS, 99_000), // outside 24h
            row("bb", "node", ME, now - 5 * HOUR_MS, 1_000),
            row("bb", "node", ME, now - HOUR_MS / 2, 2_000),
        ];
        let r = aggregate(&rows, ME, Window::Day, now, false);
        assert_eq!(r.totals.in_msat, 3_000);
        assert_eq!(r.buckets.len(), 2, "gaps are omitted, never zero-filled");
        assert!(r.buckets.iter().all(|b| b.start_ms % HOUR_MS == 0));
        assert!(r.buckets[0].start_ms < r.buckets[1].start_ms);
    }

    #[test]
    fn relayed_and_unpaid_rows_are_not_energy() {
        let now = DAY_MS;
        let rows = [
            row("bb", "node", "cc", now - 1, 50_000),
            row("bb", "node", ME, now - 1, 0),
        ];
        let r = aggregate(&rows, ME, Window::Hour, now, false);
        assert_eq!(r.totals, EnergyTotals::default());
        assert!(r.counterparties.is_empty());
        assert!(r.buckets.is_empty());
    }

    #[test]
    fn window_parses_from_query_strings() {
        for (s, w) in [
            ("1h", Window::Hour),
            ("24h", Window::Day),
            ("7d", Window::Week),
        ] {
            let q: EnergyQuery = serde_urlencoded_like(s);
            assert_eq!(q.window, Some(w));
        }
    }

    fn serde_urlencoded_like(w: &str) -> EnergyQuery {
        serde_json::from_value(serde_json::json!({ "window": w })).unwrap()
    }
}
