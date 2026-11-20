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
    assert_eq!(db.call_with_free_reply_receipts(None, 10).await.unwrap(), vec![(peer.to_hex(), CALL.to_string(), Some((peer, with.clone())))]);
    assert!(db.call_with_free_reply_receipts(Some((&peer.to_hex(), CALL)), 10).await.unwrap().is_empty());
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

/// Key order, the page bound and the cursor, including several calls of one
/// peer; an undecodable row is listed in its place without an entry and is
/// kept by every sweep.
#[tokio::test]
async fn receipt_pages_follow_row_keys_and_list_undecodable_rows() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let (low, high) = (NodeId::from_bytes([1; 32]), NodeId::from_bytes([2; 32]));
    let calls = ["0000000000000000000000000000000b", "0000000000000000000000000000000a", "0000000000000000000000000000000c"];
    for call_id in calls {
        db.call_put(&high, call_id, &ended(0, vec![receipt(call_id)])).await.unwrap();
    }
    db.call_put(&low, CALL, &ended(0, vec![receipt("low")])).await.unwrap();
    // Without receipts: never listed.
    db.call_put(&NodeId::from_bytes([0; 32]), CALL, &ended(0, Vec::new())).await.unwrap();
    let keys = |rows: &[konsensus_storage::FreeReplyReceiptRow]| rows.iter().map(|(p, c, _)| (p.clone(), c.clone())).collect::<Vec<_>>();
    let all = db.call_with_free_reply_receipts(None, 10).await.unwrap();
    let mut sorted = calls.to_vec();
    sorted.sort();
    let expected: Vec<(String, String)> = std::iter::once((low.to_hex(), CALL.to_string()))
        .chain(sorted.iter().map(|c| (high.to_hex(), c.to_string()))).collect();
    assert_eq!(keys(&all), expected);
    assert!(all.iter().all(|(_, _, e)| e.is_some()));
    // The bound, then the rest after the cursor, across one peer's calls.
    let first = db.call_with_free_reply_receipts(None, 2).await.unwrap();
    assert_eq!(keys(&first), expected[..2].to_vec());
    let (p, c, _) = first.last().unwrap();
    let rest = db.call_with_free_reply_receipts(Some((p.as_str(), c.as_str())), 2).await.unwrap();
    assert_eq!(keys(&rest), expected[2..].to_vec());
    let (p, c, _) = rest.last().unwrap();
    assert!(db.call_with_free_reply_receipts(Some((p.as_str(), c.as_str())), 2).await.unwrap().is_empty());

    // An undecodable row keeps its place and its column, and survives sweeps.
    sqlx::query("UPDATE call_state SET free_reply_receipts = '{not json' WHERE peer = ? AND call_id = ?")
        .bind(high.to_hex()).bind(sorted[1]).execute(db.pool()).await.unwrap();
    let listed = db.call_with_free_reply_receipts(None, 10).await.unwrap();
    assert_eq!(keys(&listed), expected);
    assert_eq!(listed.iter().map(|(_, _, e)| e.is_some()).collect::<Vec<_>>(), vec![true, true, false, true]);
    let far = 10 * TOMBSTONE_MS;
    db.call_evict_burned(Some(&high), far, far, 10).await.unwrap();
    db.call_sweep(far, 10).await.unwrap();
    let raw: Option<String> = sqlx::query_scalar("SELECT free_reply_receipts FROM call_state WHERE peer = ? AND call_id = ?")
        .bind(high.to_hex()).bind(sorted[1]).fetch_one(db.pool()).await.unwrap();
    assert_eq!(raw.as_deref(), Some("{not json"));
}

/// A value of the wrong type in an integer column (SQLite does not enforce
/// column types here) fails only its own row: the page is still listed, that
/// row by its key without an entry, and sweeps keep it.
#[tokio::test]
async fn a_mistyped_column_fails_only_its_own_row() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let peers: Vec<NodeId> = (1..=3u8).map(|b| NodeId::from_bytes([b; 32])).collect();
    for (n, peer) in peers.iter().enumerate() {
        db.call_put(peer, CALL, &ended(0, vec![receipt(&format!("op{n}"))])).await.unwrap();
    }
    sqlx::query("UPDATE call_state SET deadline_ms = 'not a number' WHERE peer = ?").bind(peers[1].to_hex())
        .execute(db.pool()).await.unwrap();
    let listed = db.call_with_free_reply_receipts(None, 10).await.unwrap();
    assert_eq!(listed.iter().map(|(p, c, e)| (p.clone(), c.clone(), e.is_some())).collect::<Vec<_>>(),
        peers.iter().map(|p| (p.to_hex(), CALL.to_string(), *p != peers[1])).collect::<Vec<_>>());
    assert_eq!(listed[0].2, Some((peers[0], ended(0, vec![receipt("op0")]))));
    let page = db.call_with_free_reply_receipts(Some((&peers[0].to_hex(), CALL)), 1).await.unwrap();
    assert_eq!((page.len(), page[0].0.clone(), page[0].2.is_none()), (1, peers[1].to_hex(), true));
    let far = 10 * TOMBSTONE_MS;
    db.call_evict_burned(Some(&peers[1]), far, far, 10).await.unwrap();
    db.call_sweep(far, 10).await.unwrap();
    let kept: (Option<String>, String) = sqlx::query_as("SELECT free_reply_receipts, CAST(deadline_ms AS TEXT) FROM call_state WHERE peer = ?")
        .bind(peers[1].to_hex()).fetch_one(db.pool()).await.unwrap();
    assert!(kept.0.is_some());
    assert_eq!(kept.1, "not a number");
}
