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

/// Rows still holding receipts, in key order (peer hex, call id); a key that
/// is not valid text is shown lossily.
async fn holding(db: &SqliteStorage) -> Vec<(String, String)> {
    let rows: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as("SELECT CAST(peer AS BLOB), CAST(call_id AS BLOB) FROM call_state WHERE free_reply_receipts IS NOT NULL ORDER BY peer, call_id")
        .fetch_all(db.pool()).await.unwrap();
    rows.into_iter().map(|(p, c)| (String::from_utf8_lossy(&p).into_owned(), String::from_utf8_lossy(&c).into_owned())).collect()
}

#[tokio::test]
async fn an_undecodable_row_is_kept_and_never_stalls_cleanup_of_later_rows() {
    // Receipts that are not valid JSON.
    undecodable_row_case("free_reply_receipts = '{not json'", "free_reply_receipts", "{not json").await;
}

#[tokio::test]
async fn a_row_with_a_mistyped_column_is_kept_and_never_stalls_cleanup_of_later_rows() {
    // SQLite keeps a text value in an integer column of a table that is not STRICT.
    undecodable_row_case("deadline_ms = 'not a number'", "deadline_ms", "not a number").await;
}

/// 300 releasable rows, the sixth damaged by `corruption` (which leaves
/// `column` holding `stored`): cleanup visits exactly the first 256 rows, keeps
/// going behind the damaged one, wraps back to the start, and never changes
/// or drops the damaged row.
async fn undecodable_row_case(corruption: &str, column: &str, stored: &str) {
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
    sqlx::query(&format!("UPDATE call_state SET {corruption} WHERE peer = ?")).bind(&corrupt)
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
    let raw: Option<String> = sqlx::query_scalar(&format!("SELECT CAST({column} AS TEXT) FROM call_state WHERE peer = ?")).bind(&corrupt)
        .fetch_one(db.pool()).await.unwrap();
    assert_eq!(raw.as_deref(), Some(stored));
    let receipts: Option<String> = sqlx::query_scalar("SELECT free_reply_receipts FROM call_state WHERE peer = ?").bind(&corrupt)
        .fetch_one(db.pool()).await.unwrap();
    assert!(receipts.is_some(), "the damaged row lost its receipts");
    let far = konsensus_api::calls::now_ms() + 3 * TOMBSTONE_MS;
    store.call_sweep(far, 1_000).await.unwrap();
    store.call_evict_burned(Some(&peer(5)), far, far, 1_000).await.unwrap();
    assert_eq!(holding(&db).await, vec![(corrupt, CALL.to_string())], "the undecodable row was dropped");
}

/// A row for `peer` whose receipt must be kept: its saved reply can still be recovered.
async fn held(store: &dyn konsensus_storage::Storage, peer: &NodeId, op_id: &str) {
    recoverable(store, peer, op_id).await;
    store.call_put(peer, CALL, &row(peer, op_id)).await.unwrap();
}

/// An operation whose saved reply can still be recovered.
async fn recoverable(store: &dyn konsensus_storage::Storage, peer: &NodeId, op_id: &str) {
    let mut op = OutboxOperation::prepared(op_id.into(), peer.to_hex(), 401, "digest".into());
    op.state = "payment_unknown".into();
    op.recovery = serde_json::to_vec(&serde_json::json!({
        "free_reply": true, "envelope_ready": true, "free_reply_unresolved": true,
        "dispatched": false, "expected_msat": 0, "fee_ceiling_msat": 0, "admission_msat": 0,
    })).unwrap();
    assert!(store.insert_outbox_operation(&op).await.unwrap());
}

#[tokio::test]
async fn a_row_with_an_unreadable_key_never_cuts_a_page_short() {
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let mut state = common::test_state();
    Arc::get_mut(&mut state).unwrap().storage = db.clone();
    let store = state.storage.as_ref();
    // 255 kept rows, then 44 releasable ones behind them.
    for n in 0..255u32 {
        held(store, &peer(n), &format!("held-{n}")).await;
    }
    for n in 256..300u32 {
        store.call_put(&peer(n), CALL, &row(&peer(n), &format!("gone-{n}"))).await.unwrap();
    }
    // Inside the first page (between the 4th and 5th kept rows): a row whose
    // peer is not valid UTF-8 text, as only a damaged database could hold it.
    let receipts = serde_json::to_string(&row(&peer(3), "bad-key").free_reply_receipts).unwrap();
    sqlx::query("INSERT INTO call_state (peer, call_id, side, phase, deadline_ms, replay_until_ms, next_block_seq, unpaid_notice_used, free_reply_receipts) \
                 VALUES (CAST(X'3030303030303033ff' AS TEXT), ?, 'callee', 'ended', 1, 1, 0, 0, ?)")
        .bind(CALL).bind(&receipts).execute(db.pool()).await.unwrap();
    let bad_rows = || sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM call_state WHERE peer = CAST(X'3030303030303033ff' AS TEXT) AND free_reply_receipts IS NOT NULL");

    let mut sweeps = 0;
    while holding(&db).await.len() > 256 {
        sweeps += 1;
        assert!(sweeps <= 3, "rows behind a page holding an unreadable key were never reached");
        konsensus_api::handlers::messages::reconcile_operations(&state).await.unwrap();
    }
    assert_eq!(holding(&db).await.len(), 256, "a kept receipt was released");
    assert_eq!(bad_rows().fetch_one(db.pool()).await.unwrap(), 1, "the row with an unreadable key was dropped");
    let far = konsensus_api::calls::now_ms() + 3 * TOMBSTONE_MS;
    store.call_sweep(far, 1_000).await.unwrap();
    assert_eq!(bad_rows().fetch_one(db.pool()).await.unwrap(), 1, "a sweep dropped the row with an unreadable key");
}

#[tokio::test]
async fn after_an_exactly_full_last_page_the_next_sweep_starts_over_at_once() {
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let mut state = common::test_state();
    Arc::get_mut(&mut state).unwrap().storage = db.clone();
    let store = state.storage.as_ref();
    // Exactly one full page of kept rows.
    for n in 1..=256u32 {
        held(store, &peer(n), &format!("held-{n}")).await;
    }
    konsensus_api::handlers::messages::reconcile_operations(&state).await.unwrap();
    // A releasable receipt before all of them: the very next sweep, finding
    // nothing after the last page, starts over and reaches it.
    store.call_put(&peer(0), CALL, &row(&peer(0), "gone")).await.unwrap();
    konsensus_api::handlers::messages::reconcile_operations(&state).await.unwrap();
    assert_eq!(store.call_get(&peer(0), CALL).await.unwrap().unwrap().free_reply_receipts, vec![],
        "a sweep after an exactly full last page visited nothing");
    assert_eq!(holding(&db).await.len(), 256);
}

/// A row for `peer` and `call_id` holding one receipt whose operation is gone.
fn releasable(peer: &NodeId, call_id: &str, operation_id: &str) -> CallEntry {
    let mut entry = row(peer, operation_id);
    entry.free_reply_receipts[0].call_id = call_id.into();
    entry
}

#[tokio::test]
async fn decoded_receipt_fault_waits_for_wrap_without_loss() {
    let mem = Arc::new(common::MemStorage::new());
    let mut state = common::test_state();
    Arc::get_mut(&mut state).unwrap().storage = mem.clone();
    let store = state.storage.as_ref();
    let p = peer(1);
    let id = |n: u32| format!("c{n:03}");
    // 300 decodable rows in key order. Every receipt can be released except
    // one, whose saved reply can still be recovered.
    let mut stored = Vec::new();
    for n in 0..300u32 {
        let entry = releasable(&p, &id(n), &format!("gone-{n}"));
        store.call_put(&p, &id(n), &entry).await.unwrap();
        stored.push(entry);
    }
    // Last in key order, so it shares the second (short) page.
    let held_id = "z-held";
    recoverable(store, &p, "held-z").await;
    let kept = releasable(&p, held_id, "held-z");
    store.call_put(&p, held_id, &kept).await.unwrap();
    let held_now = || async {
        let mut left = Vec::new();
        for n in 0..300u32 {
            if !store.call_get(&p, &id(n)).await.unwrap().unwrap().free_reply_receipts.is_empty() {
                left.push(n);
            }
        }
        left
    };

    // Inside the first page: reading one row fails, writing another fails.
    *mem.fail_call_get_for.lock().unwrap() = Some(id(5));
    *mem.fail_call_put_for.lock().unwrap() = Some(id(9));
    konsensus_api::handlers::messages::reconcile_operations(&state).await.unwrap();
    *mem.fail_call_get_for.lock().unwrap() = None;
    *mem.fail_call_put_for.lock().unwrap() = None;
    let expected: Vec<u32> = [5, 9].into_iter().chain(256..300).collect();
    assert_eq!(held_now().await, expected, "the first sweep did not keep exactly the failed rows and the rows past its page");

    // Faults gone: the next sweep resumes after the first page. The failed
    // rows are behind the cursor and are not retried yet.
    konsensus_api::handlers::messages::reconcile_operations(&state).await.unwrap();
    assert_eq!(held_now().await, vec![5, 9], "a failed row was retried before the cursor wrapped, or a later row was not reached");

    // Having reached the end, cleanup wraps and releases them.
    konsensus_api::handlers::messages::reconcile_operations(&state).await.unwrap();
    assert_eq!(held_now().await, Vec::<u32>::new(), "a failed row was not retried after the cursor wrapped");

    // No row was lost and nothing but the receipts changed; the receipt whose
    // saved reply can still be recovered is still held.
    for n in 0..300u32 {
        let mut want = stored[n as usize].clone();
        want.free_reply_receipts.clear();
        assert_eq!(store.call_get(&p, &id(n)).await.unwrap(), Some(want), "row {n}");
    }
    assert_eq!(store.call_get(&p, held_id).await.unwrap(), Some(kept), "a receipt that must be kept was released");
}

#[tokio::test]
async fn a_page_listing_more_rows_than_it_covered_is_still_swept() {
    let mem = Arc::new(common::MemStorage::new());
    let mut state = common::test_state();
    Arc::get_mut(&mut state).unwrap().storage = mem.clone();
    let store = state.storage.as_ref();
    for n in 0..3u32 {
        store.call_put(&peer(n), CALL, &row(&peer(n), &format!("gone-{n}"))).await.unwrap();
    }
    // A store whose count of covered rows falls short of the rows it lists.
    *mem.receipt_page_hook.lock().unwrap() = Some(Box::new(|page| page.scanned = 0));
    konsensus_api::handlers::messages::reconcile_operations(&state).await.unwrap();
    for n in 0..3u32 {
        assert_eq!(store.call_get(&peer(n), CALL).await.unwrap().unwrap().free_reply_receipts, vec![], "row {n}");
    }
}

#[tokio::test]
async fn a_stored_empty_receipt_list_is_cleared_once_and_no_longer_listed() {
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let mut state = common::test_state();
    Arc::get_mut(&mut state).unwrap().storage = db.clone();
    let store = state.storage.as_ref();
    // Writes store no receipts as NULL, never as an empty list.
    let mut none = row(&peer(0), "unused");
    none.free_reply_receipts.clear();
    store.call_put(&peer(0), CALL, &none).await.unwrap();
    assert_eq!(holding(&db).await, vec![]);
    // Rows holding an empty list, as only a damaged or hand-edited database could.
    for (n, stored) in [(1u32, "[]"), (2, " [ ] ")] {
        store.call_put(&peer(n), CALL, &row(&peer(n), &format!("gone-{n}"))).await.unwrap();
        sqlx::query("UPDATE call_state SET free_reply_receipts = ? WHERE peer = ?").bind(stored).bind(peer(n).to_hex())
            .execute(db.pool()).await.unwrap();
    }
    let before: Vec<_> = [1u32, 2].iter().map(|n| peer(*n)).collect();
    let mut entries = Vec::new();
    for p in &before {
        entries.push(store.call_get(p, CALL).await.unwrap().unwrap());
    }
    assert_eq!(holding(&db).await.len(), 2);

    konsensus_api::handlers::messages::reconcile_operations(&state).await.unwrap();
    assert_eq!(holding(&db).await, vec![], "a row holding an empty receipt list stays listed by every sweep");
    assert_eq!(store.call_with_free_reply_receipts(None, 256).await.unwrap().scanned, 0);
    // Nothing else about the rows changed.
    for (p, entry) in before.iter().zip(entries) {
        assert_eq!(store.call_get(p, CALL).await.unwrap(), Some(entry));
    }
}
