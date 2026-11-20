//! Receipt cleanup on call rows is bounded per sweep and still reaches every
//! row: rows whose receipts must be kept never starve a later row whose
//! receipt can be released. Real SQLite call state.

mod common;

use std::sync::Arc;

use konsensus_core::payloads::call::{CallEntry, FreeReplyReceipt, Phase, Side, TOMBSTONE_MS};
use konsensus_core::NodeId;
use konsensus_storage::{OutboxOperation, SqliteStorage};

const CALL: &str = "0123456789abcdef0123456789abcdef";

fn row(peer: &NodeId, operation_id: &str) -> CallEntry {
    let now = konsensus_api::calls::now_ms();
    CallEntry {
        side: Side::Callee, phase: Phase::Ended, deadline_ms: now + TOMBSTONE_MS, pending: None,
        paid_until_ms: None, next_block_seq: 0, end_reason: None, unpaid_notice_used: false,
        free_reply_receipts: vec![FreeReplyReceipt {
            peer: peer.to_hex(), call_id: CALL.into(), kind: 401, operation_id: operation_id.into(),
            request_hash: "digest".into(), phase: "live".into(), applied_ms: now,
        }],
    }
}

fn peer(n: u32) -> NodeId {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_be_bytes());
    NodeId::from_bytes(bytes)
}

#[tokio::test]
async fn kept_receipts_never_starve_cleanup_of_a_later_row() {
    let mut state = common::test_state();
    Arc::get_mut(&mut state).unwrap().storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let store = state.storage.as_ref();
    // 300 rows, first in key order, whose saved replies can still be recovered.
    for n in 0..300u32 {
        let (peer, op_id) = (peer(n), format!("held-{n}"));
        let mut op = OutboxOperation::prepared(op_id.clone(), peer.to_hex(), 401, "digest".into());
        op.state = "payment_unknown".into();
        op.recovery = serde_json::to_vec(&serde_json::json!({
            "free_reply": true, "envelope_ready": true, "free_reply_unresolved": true,
            "dispatched": false, "expected_msat": 0, "fee_ceiling_msat": 0, "admission_msat": 0,
        })).unwrap();
        assert!(store.insert_outbox_operation(&op).await.unwrap());
        store.call_put(&peer, CALL, &row(&peer, &op_id)).await.unwrap();
    }
    // Last in key order: a receipt whose operation is gone, so it can be released.
    let last = NodeId::from_bytes([0xff; 32]);
    store.call_put(&last, CALL, &row(&last, "gone")).await.unwrap();

    let mut sweeps = 0;
    while store.call_get(&last, CALL).await.unwrap().unwrap().free_reply_receipts.len() == 1 {
        sweeps += 1;
        assert!(sweeps <= 3, "a releasable receipt was never reached behind kept ones");
        konsensus_api::handlers::messages::reconcile_operations(&state).await.unwrap();
    }
    // Every kept receipt is still in place.
    for n in 0..300u32 {
        assert_eq!(store.call_get(&peer(n), CALL).await.unwrap().unwrap().free_reply_receipts.len(), 1, "row {n}");
    }
}

/// Rows still holding receipts, in key order (peer hex, call id).
async fn holding(db: &SqliteStorage) -> Vec<(String, String)> {
    sqlx::query_as("SELECT peer, call_id FROM call_state WHERE free_reply_receipts IS NOT NULL ORDER BY peer, call_id")
        .fetch_all(db.pool()).await.unwrap()
}

#[tokio::test]
async fn an_undecodable_row_is_kept_and_never_stalls_cleanup_of_later_rows() {
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let mut state = common::test_state();
    Arc::get_mut(&mut state).unwrap().storage = db.clone();
    let store = state.storage.as_ref();
    // 300 rows whose receipts can all be released (their operations are gone),
    // one of them, inside the first page, with receipts that cannot be decoded.
    for n in 0..300u32 {
        store.call_put(&peer(n), CALL, &row(&peer(n), &format!("gone-{n}"))).await.unwrap();
    }
    let corrupt = peer(5).to_hex();
    sqlx::query("UPDATE call_state SET free_reply_receipts = '{not json' WHERE peer = ?").bind(&corrupt)
        .execute(db.pool()).await.unwrap();

    // One sweep visits exactly the first 256 rows in key order: the corrupt
    // one is skipped and kept, the other 255 are released.
    konsensus_api::handlers::messages::reconcile_operations(&state).await.unwrap();
    let left = holding(&db).await;
    let expected: Vec<(String, String)> = std::iter::once(5).chain(256..300)
        .map(|n| (peer(n).to_hex(), CALL.to_string())).collect();
    assert_eq!(left, expected, "the first sweep did not visit exactly the first 256 rows past the corrupt one");
    // The next sweep continues after it and reaches the end.
    konsensus_api::handlers::messages::reconcile_operations(&state).await.unwrap();
    assert_eq!(holding(&db).await, vec![(corrupt.clone(), CALL.to_string())], "rows behind the corrupt one were not reached");

    // Having reached the end, cleanup starts over: a releasable receipt on a
    // row before the corrupt one is reached again.
    store.call_put(&peer(0), CALL, &row(&peer(0), "gone-again")).await.unwrap();
    let mut sweeps = 0;
    while holding(&db).await.len() > 1 {
        sweeps += 1;
        assert!(sweeps <= 2, "cleanup never wrapped back to the start");
        konsensus_api::handlers::messages::reconcile_operations(&state).await.unwrap();
    }

    // The corrupt row is held: never rewritten, never swept or evicted.
    let raw: Option<String> = sqlx::query_scalar("SELECT free_reply_receipts FROM call_state WHERE peer = ?").bind(&corrupt)
        .fetch_one(db.pool()).await.unwrap();
    assert_eq!(raw.as_deref(), Some("{not json"));
    let far = konsensus_api::calls::now_ms() + 3 * TOMBSTONE_MS;
    store.call_sweep(far, 1_000).await.unwrap();
    store.call_evict_burned(Some(&peer(5)), far, far, 1_000).await.unwrap();
    assert_eq!(holding(&db).await, vec![(corrupt, CALL.to_string())], "the undecodable row was dropped");
}
