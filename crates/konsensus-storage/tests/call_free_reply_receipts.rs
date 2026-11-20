//! Free-reply receipts on call rows: stored with the row in one write, read
//! back exactly, absent on rows written before they existed, and keeping
//! their row through every sweep while they are held.
use konsensus_core::payloads::call::{CallEntry, FreeReplyReceipt, Phase, Side, TOMBSTONE_MS};
use konsensus_core::NodeId;
use konsensus_storage::{EncryptedStorage, SqliteStorage, Storage};

const CALL: &str = "0123456789abcdef0123456789abcdef";

fn receipt(op: &str) -> FreeReplyReceipt {
    FreeReplyReceipt {
        peer: NodeId::from_bytes([7; 32]).to_hex(), call_id: CALL.into(), kind: 401,
        operation_id: op.into(), request_hash: "digest".into(), phase: "live".into(), applied_ms: 1_000,
    }
}

/// A callee row that ended at `ended_ms`, with these receipts.
fn ended(ended_ms: u64, receipts: Vec<FreeReplyReceipt>) -> CallEntry {
    CallEntry {
        side: Side::Callee, phase: Phase::Ended, deadline_ms: ended_ms + TOMBSTONE_MS, pending: None,
        paid_until_ms: None, next_block_seq: 0, end_reason: None, unpaid_notice_used: false,
        free_reply_receipts: receipts,
    }
}

async fn round_trip(db: &dyn Storage) {
    let peer = NodeId::from_bytes([7; 32]);
    let with = ended(0, vec![receipt("a"), receipt("b")]);
    db.call_put(&peer, CALL, &with).await.unwrap();
    assert_eq!(db.call_get(&peer, CALL).await.unwrap(), Some(with.clone()));
    assert_eq!(db.call_with_free_reply_receipts(None, 10).await.unwrap(), vec![(peer, CALL.to_string(), with.clone())]);
    assert!(db.call_with_free_reply_receipts(Some((&peer, CALL)), 10).await.unwrap().is_empty());
    // Clearing them is one ordinary write of the row.
    let without = ended(0, Vec::new());
    db.call_put(&peer, CALL, &without).await.unwrap();
    assert_eq!(db.call_get(&peer, CALL).await.unwrap(), Some(without));
    assert!(db.call_with_free_reply_receipts(None, 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn sqlite_and_encrypted_rows_round_trip_their_receipts() {
    round_trip(&SqliteStorage::in_memory().await.unwrap()).await;
    round_trip(&EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[3; 32])).await;
}

#[tokio::test]
async fn a_row_written_before_receipts_existed_reads_with_none() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([7; 32]);
    // Exactly the columns an older node wrote; the new column stays NULL.
    sqlx::query("INSERT INTO call_state (peer, call_id, side, phase, deadline_ms, replay_until_ms, pending_operation_id, pending_kind, pending_request_hash, paid_until_ms, next_block_seq, end_reason, unpaid_notice_used) \
                 VALUES (?, ?, 'callee', 'ringing', 5000, 5000, 'op', 401, 'digest', NULL, 0, NULL, 0)")
        .bind(peer.to_hex()).bind(CALL).execute(db.pool()).await.unwrap();
    let entry = db.call_get(&peer, CALL).await.unwrap().unwrap();
    assert!(entry.free_reply_receipts.is_empty());
    assert_eq!(entry.pending.unwrap().operation_id, "op");
    assert_eq!(db.call_pending().await.unwrap().len(), 1);
    assert!(db.call_with_free_reply_receipts(None, 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn unreadable_receipts_make_the_row_unreadable_not_empty() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([7; 32]);
    db.call_put(&peer, CALL, &ended(0, vec![receipt("a")])).await.unwrap();
    sqlx::query("UPDATE call_state SET free_reply_receipts = 'not json'").execute(db.pool()).await.unwrap();
    assert!(db.call_get(&peer, CALL).await.is_err());
}

#[tokio::test]
async fn sweeps_and_eviction_keep_a_row_while_it_holds_a_receipt() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([7; 32]);
    let other = "fedcba9876543210fedcba9876543210";
    db.call_put(&peer, CALL, &ended(0, vec![receipt("a")])).await.unwrap();
    db.call_put(&peer, other, &ended(0, Vec::new())).await.unwrap();
    let later = 10 * TOMBSTONE_MS;
    assert_eq!(db.call_evict_burned(Some(&peer), later, later, 10).await.unwrap(), 1);
    assert_eq!(db.call_sweep(later, 10).await.unwrap(), 0);
    assert!(db.call_get(&peer, other).await.unwrap().is_none());
    let kept = db.call_get(&peer, CALL).await.unwrap().expect("the receipt keeps its row");
    assert_eq!(kept.free_reply_receipts, vec![receipt("a")]);
    // A held row counts as a burned id, never as an open call.
    let counts = db.call_counts(&peer, later).await.unwrap();
    assert_eq!((counts.open_peer, counts.burned_peer), (0, 1));
    // Once its receipt is released the row is swept like any other.
    db.call_put(&peer, CALL, &ended(0, Vec::new())).await.unwrap();
    assert_eq!(db.call_sweep(later, 10).await.unwrap(), 1);
}
