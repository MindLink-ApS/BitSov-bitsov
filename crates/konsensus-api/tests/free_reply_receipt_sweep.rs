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
