//! A saved free call reply is queued only after its own call transition, as
//! proven by that transition's receipt on the call row. A reply whose call
//! moved on without it is withdrawn for good; one whose transition cannot be
//! established is held, never queued. Runs on the node's SQLite storage with
//! real restarts, an independently polling outbox reader and a database-side
//! record of the call's state at the instant each reply became queued.
use super::free_reply::{awaiting_device, ledger, reply, ringing, sent, FREE};
use super::*;
use konsensus_core::payloads::call::{CallEntry, Pending, TOMBSTONE_MS};
use konsensus_storage::Storage as _;

fn db_path(fx: &Fx) -> std::path::PathBuf {
    fx.tmp.path().join("calls.sqlite")
}

/// Another connection to the node's database, for faults and observation.
async fn raw(fx: &Fx) -> SqliteStorage {
    SqliteStorage::open(db_path(fx).to_str().unwrap()).await.unwrap()
}

async fn exec(db: &SqliteStorage, sql: &str) {
    sqlx::raw_sql(sql).execute(db.pool()).await.unwrap();
}

/// Whether this database stores free-reply receipts on call rows.
async fn has_receipts(db: &SqliteStorage) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pragma_table_info('call_state') WHERE name = 'free_reply_receipts'")
        .fetch_one(db.pool()).await.unwrap() == 1
}

/// The stored receipts of `call_id` (`None` without receipt storage).
async fn receipts(db: &SqliteStorage, peer: &NodeId, call_id: &str) -> Option<Option<String>> {
    if !has_receipts(db).await {
        return None;
    }
    Some(sqlx::query_scalar::<_, Option<String>>("SELECT free_reply_receipts FROM call_state WHERE peer = ? AND call_id = ?")
        .bind(peer.to_hex()).bind(call_id).fetch_optional(db.pool()).await.unwrap().flatten())
}

/// Record, inside the queueing transaction itself, the call's phase (and its
/// receipts, where stored) at the instant each reply becomes queued.
async fn audit_queueing(fx: &Fx, db: &SqliteStorage) {
    let receipts = if has_receipts(db).await { "free_reply_receipts" } else { "NULL" };
    exec(db, &format!(
        "CREATE TABLE IF NOT EXISTS queued_audit (message_id TEXT, phase TEXT, receipts TEXT);
         CREATE TRIGGER IF NOT EXISTS queued_audit AFTER INSERT ON pending_deliveries BEGIN
           INSERT INTO queued_audit SELECT NEW.message_id,
             (SELECT phase FROM call_state WHERE peer = '{peer}' AND call_id = '{CALL}'),
             (SELECT {receipts} FROM call_state WHERE peer = '{peer}' AND call_id = '{CALL}');
         END;", peer = fx.peer.to_hex())).await;
}

async fn queued(db: &SqliteStorage) -> Vec<(String, Option<String>, Option<String>)> {
    sqlx::query_as("SELECT message_id, phase, receipts FROM queued_audit").fetch_all(db.pool()).await.unwrap()
}

/// An outbox reader scheduled independently of the node, polling its own
/// connection: every reply it ever sees queued, in order.
struct Flusher {
    seen: Arc<std::sync::Mutex<Vec<konsensus_core::MessageId>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Flusher {
    async fn start(fx: &Fx) -> Self {
        let db = raw(fx).await;
        let (seen, peer) = (Arc::new(std::sync::Mutex::new(Vec::new())), fx.peer);
        let log = Arc::clone(&seen);
        let task = tokio::spawn(async move {
            loop {
                if let Ok(pending) = db.get_pending_for_peer(&peer).await {
                    let mut log = log.lock().unwrap();
                    for (id, _) in pending {
                        if !log.contains(&id) { log.push(id); }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        });
        Self { seen, task }
    }
    async fn seen(&self) -> Vec<konsensus_core::MessageId> {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for Flusher {
    fn drop(&mut self) { self.task.abort(); }
}

/// Reopen the node's storage and pairing state as a restarted node would.
async fn restart(fx: &mut Fx) {
    fx.restart();
    let store = SqliteStorage::open(db_path(fx).to_str().unwrap()).await.unwrap();
    fx.state = Arc::new(AppState { storage: Arc::new(EncryptedStorage::new(store, &[7; 32])), ..(*fx.state).clone() });
}

/// Startup recovery, then a sweep.
async fn recover(fx: &Fx) {
    konsensus_api::calls::recover(fx.state.storage.as_ref()).await.unwrap();
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
}

async fn row(fx: &Fx, peer: &NodeId, call_id: &str) -> Option<CallEntry> {
    fx.state.storage.call_get(peer, call_id).await.unwrap()
}

async fn operation(fx: &Fx, id: &str) -> konsensus_storage::OutboxOperation {
    fx.state.storage.get_outbox_operation(id).await.unwrap().unwrap()
}

fn data(op: &konsensus_storage::OutboxOperation) -> Value {
    serde_json::from_slice(&op.recovery).unwrap()
}

/// Rewrite the operation's journal entry as an older node left it.
async fn rewrite(fx: &Fx, id: &str, change: impl FnOnce(&mut Value)) {
    let mut op = operation(fx, id).await;
    let mut recovery = data(&op);
    change(&mut recovery);
    op.recovery = serde_json::to_vec(&recovery).unwrap();
    assert!(fx.state.storage.update_outbox_operation(&op).await.unwrap());
}

/// The caller hangs up; the call ends without this node's reply.
async fn caller_hangs_up(fx: &Fx) {
    konsensus_api::calls::admit_incoming(fx.state.storage.as_ref(), fx.state.identity.node_id(), &fx.peer, 403,
        Some(&json!({"v": 1, "call_id": CALL, "reason": "hangup"}).to_string())).await.unwrap();
}

/// A reply of `kind` signed and saved, with the node stopped before its call
/// moved (and before it could take the saved reply back): the call is still
/// ringing (or waiting for a device) under this reply's own reservation.
async fn saved_before_transition(kind: u16, waiting: bool) -> (Fx, String, Arc<ConnectedStubTransport>, String) {
    let (fx, token, transport) = if waiting { awaiting_device(true, &[FREE], CALL).await } else { ringing(true, &[FREE], CALL).await };
    let db = raw(&fx).await;
    exec(&db, "CREATE TRIGGER stop_move BEFORE UPDATE ON call_state WHEN NEW.phase IN ('live', 'ended') AND OLD.phase NOT IN ('live', 'ended')
                 BEGIN SELECT RAISE(ABORT, 'node stopped'); END;
               CREATE TRIGGER stop_unseal BEFORE UPDATE ON outbox_operations WHEN OLD.payment_hash IS NOT NULL AND NEW.payment_hash IS NULL
                 BEGIN SELECT RAISE(ABORT, 'node stopped'); END;").await;
    let id = uuid::Uuid::new_v4().to_string();
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, kind, CALL, &id)).await;
    assert_ne!(status, StatusCode::OK, "{kind}: {body}");
    assert_eq!(body["reason"], "call_reply_unresolved", "{kind}: {body}");
    exec(&db, "DROP TRIGGER stop_move; DROP TRIGGER stop_unseal;").await;
    let entry = row(&fx, &fx.peer, CALL).await.unwrap();
    assert_eq!(entry.phase, if waiting { Phase::AwaitingDevice } else { Phase::Ringing });
    assert_eq!(entry.pending.map(|p| p.operation_id), Some(id.clone()));
    assert!(data(&operation(&fx, &id).await)["envelope_ready"] == true);
    assert!(sent(&transport, kind).is_empty());
    (fx, token, transport, id)
}

/// The node stops right after the call row moved: no later journal or queue
/// write lands.
async fn stop_after_transition(db: &SqliteStorage) {
    exec(db, &format!(
        "CREATE TRIGGER stop_journal BEFORE UPDATE ON outbox_operations WHEN (SELECT COUNT(*) FROM call_state WHERE call_id = '{CALL}' AND phase IN ('live', 'ended')) > 0
           BEGIN SELECT RAISE(ABORT, 'node stopped'); END;
         CREATE TRIGGER stop_queue BEFORE INSERT ON pending_deliveries
           BEGIN SELECT RAISE(ABORT, 'node stopped'); END;")).await;
}

async fn resume(db: &SqliteStorage) {
    exec(db, "DROP TRIGGER IF EXISTS stop_journal; DROP TRIGGER IF EXISTS stop_queue;").await;
}

/// A reply of `kind` whose call transition was written, with the node
/// stopped before the reply was queued.
async fn moved_before_queueing(kind: u16) -> (Fx, String, Arc<ConnectedStubTransport>, String, SqliteStorage) {
    let (fx, token, transport) = ringing(true, &[FREE], CALL).await;
    let db = raw(&fx).await;
    stop_after_transition(&db).await;
    let id = uuid::Uuid::new_v4().to_string();
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, kind, CALL, &id)).await;
    assert_ne!(status, StatusCode::OK, "{kind}: {body}");
    resume(&db).await;
    let entry = row(&fx, &fx.peer, CALL).await.unwrap();
    assert_eq!((entry.phase, entry.pending), (if kind == 401 { Phase::Live } else { Phase::Ended }, None), "{kind}");
    if let Some(stored) = receipts(&db, &fx.peer, CALL).await {
        assert!(stored.is_some_and(|r| r.contains(&id)), "{kind}: the transition was written without its receipt");
    }
    assert!(sent(&transport, kind).is_empty(), "{kind}");
    (fx, token, transport, id, db)
}

/// No reply was queued or sent, nothing was paid, and the operation is
/// withdrawn for good: the same tap is refused, not prepared again.
async fn assert_withdrawn(fx: &Fx, token: &str, transport: &ConnectedStubTransport, kind: u16, id: &str,
    before: (usize, usize, u64, u64, usize), what: &str) {
    assert!(sent(transport, kind).is_empty(), "{what}: a reply was sent for a call that moved on without it");
    assert_eq!(fx.state.storage.get_pending_for_peer(&fx.peer).await.unwrap(), vec![], "{what}: a reply was queued");
    let op = operation(fx, id).await;
    assert_eq!(op.state, "abandoned", "{what}: the saved reply was not withdrawn");
    assert_eq!(data(&op)["envelope_ready"], false, "{what}");
    let (status, body) = send_request(fx, token, 7_000, reply(fx, kind, CALL, id)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{what}: {body}");
    assert!(body.to_string().contains("operation_abandoned"), "{what}: {body}");
    assert!(sent(transport, kind).is_empty(), "{what}: the same tap sent it");
    assert_eq!(ledger(fx, transport), before, "{what}: something was paid");
}

/// Kept unresolved with its evidence, never queued.
async fn assert_held(fx: &Fx, transport: &ConnectedStubTransport, kind: u16, id: &str, why: &str, what: &str) {
    assert!(sent(transport, kind).is_empty(), "{what}: an unresolved reply was sent");
    assert_eq!(fx.state.storage.get_pending_for_peer(&fx.peer).await.unwrap(), vec![], "{what}: an unresolved reply was queued");
    let op = operation(fx, id).await;
    assert_eq!(op.state, "payment_unknown", "{what}");
    assert!(op.last_error.as_deref().is_some_and(|e| e.contains(why)), "{what}: {:?}", op.last_error);
    let saved = data(&op);
    assert_eq!((saved["envelope_ready"].clone(), saved["free_reply_unresolved"].clone()), (json!(true), json!(true)), "{what}");
    assert!(saved["draft"].is_object(), "{what}: the saved reply's evidence was dropped");
}

// F01: a saved reply whose call is gone (ended by the caller, then swept).
#[tokio::test]
async fn f01_a_saved_reply_whose_call_is_gone_is_withdrawn_never_queued() {
    for kind in [401u16, 403] {
        let (mut fx, token, transport, id) = saved_before_transition(kind, false).await;
        let before = ledger(&fx, &transport);
        caller_hangs_up(&fx).await;
        let far = konsensus_api::calls::now_ms() + 3 * TOMBSTONE_MS;
        assert_eq!(fx.state.storage.call_sweep(far, 100).await.unwrap(), 1);
        assert!(row(&fx, &fx.peer, CALL).await.is_none());
        let flusher = Flusher::start(&fx).await;
        restart(&mut fx).await;
        recover(&fx).await;
        assert!(flusher.seen().await.is_empty(), "{kind}: the outbox reader saw a reply for a call that is gone");
        assert_withdrawn(&fx, &token, &transport, kind, &id, before, &format!("{kind} absent")).await;
    }
}

// F02: the reservation was replaced, or names another call or peer.
#[tokio::test]
async fn f02_a_saved_reply_without_its_own_reservation_is_never_queued() {
    let other_peer = NodeId::from_bytes([77; 32]);
    const OTHER: &str = "99999999888877776666555544443333";
    for case in ["other operation", "other digest", "other kind", "other call", "other peer"] {
        let (fx, token, transport, id) = saved_before_transition(401, false).await;
        let before = ledger(&fx, &transport);
        let mut entry = row(&fx, &fx.peer, CALL).await.unwrap();
        let mine = entry.pending.clone().unwrap();
        let (replaced, elsewhere) = match case {
            "other operation" => (Some(Pending { operation_id: uuid::Uuid::new_v4().to_string(), ..mine.clone() }), None),
            "other digest" => (Some(Pending { request_hash: "another request".into(), ..mine.clone() }), None),
            "other kind" => (Some(Pending { kind: 403, ..mine.clone() }), None),
            "other call" => (None, Some((fx.peer, OTHER))),
            _ => (None, Some((other_peer, CALL))),
        };
        entry.pending = replaced.clone();
        fx.state.storage.call_put(&fx.peer, CALL, &entry).await.unwrap();
        if let Some((peer, call_id)) = elsewhere {
            fx.state.storage.call_put(&peer, call_id, &CallEntry { pending: Some(mine.clone()), ..entry.clone() }).await.unwrap();
        }
        konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
        konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
        assert!(sent(&transport, 401).is_empty(), "{case}: queued without its own transition");
        let now = row(&fx, &fx.peer, CALL).await.unwrap();
        assert_eq!(now.phase, Phase::Ringing, "{case}: the call was moved by a reply that did not reserve it");
        if let Some((peer, call_id)) = elsewhere {
            assert_eq!(row(&fx, &peer, call_id).await.unwrap().phase, Phase::Ringing, "{case}: another call was answered");
        }
        match case {
            "other operation" => {
                assert_eq!(now.pending, replaced, "{case}: another operation's reservation was touched");
                assert_withdrawn(&fx, &token, &transport, 401, &id, before, case).await;
                assert_eq!(row(&fx, &fx.peer, CALL).await.unwrap().pending, replaced, "{case}");
            }
            "other digest" | "other kind" => {
                // This operation's id on another request: contradictory, held.
                assert_eq!(now.pending, replaced, "{case}: the reservation was touched");
                assert_held(&fx, &transport, 401, &id, "evidence_mismatch", case).await;
            }
            _ => assert_withdrawn(&fx, &token, &transport, 401, &id, before, case).await,
        }
    }
}

// F03: the call ended independently (hangup or timeout); an ended call is
// never proof that this reply moved it.
#[tokio::test]
async fn f03_a_call_ended_another_way_never_gets_the_saved_reply() {
    for (kind, waiting) in [(401u16, false), (403, false), (403, true)] {
        for ending in ["hangup", "timeout"] {
            let what = format!("{kind} waiting={waiting} {ending}");
            let (mut fx, token, transport, id) = saved_before_transition(kind, waiting).await;
            let before = ledger(&fx, &transport);
            if ending == "hangup" {
                caller_hangs_up(&fx).await;
            } else {
                let entry = row(&fx, &fx.peer, CALL).await.unwrap();
                let past = CallEntry { deadline_ms: konsensus_api::calls::now_ms() - 1, ..entry };
                fx.state.storage.call_put(&fx.peer, CALL, &past).await.unwrap();
            }
            let flusher = Flusher::start(&fx).await;
            restart(&mut fx).await;
            recover(&fx).await;
            assert!(flusher.seen().await.is_empty(), "{what}: the outbox reader saw the reply");
            let entry = row(&fx, &fx.peer, CALL).await.unwrap();
            assert!(entry.clone().at(konsensus_api::calls::now_ms()).unwrap().phase == Phase::Ended, "{what}: {entry:?}");
            assert_eq!(entry.pending, None, "{what}: the withdrawn reply kept its reservation");
            assert_withdrawn(&fx, &token, &transport, kind, &id, before, &what).await;
        }
    }
}

/// [`saved_before_transition`] moved into fault-injecting storage.
async fn saved_in_memory(kind: u16) -> (Fx, String, Arc<ConnectedStubTransport>, String, Arc<common::MemStorage>) {
    let (mut fx, token, transport) = ringing(true, &[FREE], CALL).await;
    let store = Arc::new(common::MemStorage::new());
    let entry = row(&fx, &fx.peer, CALL).await.unwrap();
    konsensus_storage::Storage::call_put(store.as_ref(), &fx.peer, CALL, &entry).await.unwrap();
    fx.state = Arc::new(AppState { storage: store.clone(), ..(*fx.state).clone() });
    // The call write fails, and so does taking the saved reply back.
    let (failing, mut saved) = (Arc::clone(&store), false);
    *store.outbox_write_hook.lock().unwrap() = Some(Box::new(move |op| {
        let data: Value = serde_json::from_slice(&op.recovery).unwrap_or_default();
        if !saved && op.state == "paying" && data["free_reply"] == true && data["envelope_ready"] == true {
            saved = true;
            *failing.fail_call_put_for.lock().unwrap() = Some(CALL.into());
        } else if saved && op.state == "paying" && data["envelope_ready"] == false {
            return Err(konsensus_storage::StorageError::Serialization("injected journal failure".into()));
        }
        Ok(())
    }));
    let id = uuid::Uuid::new_v4().to_string();
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, kind, CALL, &id)).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    *store.fail_call_put_for.lock().unwrap() = None;
    *store.outbox_write_hook.lock().unwrap() = None;
    assert_eq!(row(&fx, &fx.peer, CALL).await.unwrap().pending.map(|p| p.operation_id), Some(id.clone()));
    (fx, token, transport, id, store)
}

// F04: the call ends after the saved reply was found, before its transition
// takes the call lock; the decision is made on a reread under that lock.
#[tokio::test]
async fn f04_a_call_ended_between_discovery_and_the_call_lock_gets_no_reply() {
    for kind in [401u16, 403] {
        for path in ["recovery sweep", "same tap"] {
            let what = format!("{kind} {path}");
            let (fx, token, transport, id, store) = saved_in_memory(kind).await;
            let before = ledger(&fx, &transport);
            let (racer, peer) = (Arc::clone(&store), fx.peer);
            let entry = row(&fx, &fx.peer, CALL).await.unwrap();
            *store.outbox_read_hook.lock().unwrap() = Some(Box::new(move || {
                // Another task's hangup commits right after the journal read.
                racer.set_call(&peer, CALL, CallEntry {
                    phase: Phase::Ended, pending: None, end_reason: Some(HangupReason::Hangup),
                    deadline_ms: konsensus_api::calls::now_ms() + TOMBSTONE_MS, ..entry
                });
            }));
            if path == "recovery sweep" {
                konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
            } else {
                let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, kind, CALL, &id)).await;
                assert_ne!(status, StatusCode::OK, "{what}: {body}");
            }
            assert!(store.outbox_read_hook.lock().unwrap().is_none(), "{what}: the race never ran");
            assert!(sent(&transport, kind).is_empty(), "{what}: the reply went out after the call ended");
            assert_eq!(store.call_phase(&fx.peer, CALL), Some(Phase::Ended), "{what}");
            assert_eq!(operation(&fx, &id).await.state, "abandoned", "{what}");
            assert_eq!(ledger(&fx, &transport), before, "{what}");
        }
    }
}

// F05: the matching reservation moves the call, with its receipt, before the
// reply is queued; free stays free; the answering client owns the media.
#[tokio::test]
async fn f05_a_matching_reply_moves_its_call_with_its_receipt_before_it_is_queued() {
    for (kind, waiting, to) in [(401u16, false, "live"), (403, false, "ended"), (403, true, "ended")] {
        let what = format!("{kind} waiting={waiting}");
        let (fx, token, transport) = if waiting { awaiting_device(true, &[FREE], CALL).await } else { ringing(true, &[FREE], CALL).await };
        let db = raw(&fx).await;
        audit_queueing(&fx, &db).await;
        let flusher = Flusher::start(&fx).await;
        let before = ledger(&fx, &transport);
        let id = uuid::Uuid::new_v4().to_string();
        let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, kind, CALL, &id)).await;
        assert_eq!(status, StatusCode::OK, "{what}: {body}");
        assert_eq!(body["amount_msat"], 0, "{what}");
        assert_eq!(ledger(&fx, &transport), before, "{what}: a free reply was charged");
        let out = sent(&transport, kind);
        assert_eq!(out.len(), 1, "{what}");
        assert_eq!(out[0].payment_proof.amount_msat, 0, "{what}");
        let audit = queued(&db).await;
        assert_eq!(audit.len(), 1, "{what}");
        assert_eq!(audit[0].0, out[0].id.to_hex(), "{what}");
        assert_eq!(audit[0].1.as_deref(), Some(to), "{what}: the reply was queued before its call moved");
        if has_receipts(&db).await {
            assert!(audit[0].2.as_deref().is_some_and(|r| r.contains(&id)), "{what}: queued without its receipt: {audit:?}");
            // Queued: the receipt is released and the row may age out again.
            assert_eq!(receipts(&db, &fx.peer, CALL).await, Some(None), "{what}");
        }
        assert!(flusher.seen().await.iter().all(|seen| *seen == out[0].id), "{what}");
        assert_eq!(row(&fx, &fx.peer, CALL).await.unwrap().pending, None, "{what}");
        if kind == 401 {
            let claims = konsensus_api::auth::validate_token(&token, &fx.state.jwt_secret).unwrap();
            let binding = konsensus_api::auth::PairingBinding::from_claims(&claims).unwrap().unwrap();
            assert!(fx.service.owns_call_media(&binding, &fx.peer.to_hex(), CALL), "{what}: the answering client lost the media");
        }
    }
    // An answer cannot move a call still waiting for a device: refused, unsent.
    let (fx, token, transport) = awaiting_device(true, &[FREE], CALL).await;
    let before = ledger(&fx, &transport);
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &uuid::Uuid::new_v4().to_string())).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert!(sent(&transport, 401).is_empty());
    assert_eq!(row(&fx, &fx.peer, CALL).await.unwrap().phase, Phase::AwaitingDevice);
    assert_eq!(ledger(&fx, &transport), before);
}

// F06: stopped after the transition and its receipt were written, before the
// reply was queued; a real restart recovers it exactly once.
#[tokio::test]
async fn f06_a_restart_after_the_transition_sends_the_saved_reply_once() {
    for kind in [401u16, 403] {
        let (mut fx, token, transport, id, db) = moved_before_queueing(kind).await;
        let before = ledger(&fx, &transport);
        let moved = row(&fx, &fx.peer, CALL).await.unwrap();
        audit_queueing(&fx, &db).await;
        let flusher = Flusher::start(&fx).await;
        restart(&mut fx).await;
        recover(&fx).await;
        let out = sent(&transport, kind);
        assert_eq!(out.len(), 1, "{kind}: the reply whose transition happened was lost");
        assert_eq!(out[0].payment_proof.amount_msat, 0);
        let audit = queued(&db).await;
        assert_eq!(audit.len(), 1, "{kind}");
        assert_eq!(audit[0].1.as_deref(), Some(moved.phase.as_str()), "{kind}");
        // No second transition, deadline change or reservation.
        let after = row(&fx, &fx.peer, CALL).await.unwrap();
        assert_eq!((after.phase, after.deadline_ms, after.pending.clone()), (moved.phase, moved.deadline_ms, None), "{kind}");
        if has_receipts(&db).await {
            assert_eq!(receipts(&db, &fx.peer, CALL).await, Some(None), "{kind}: the receipt outlived its queued reply");
        }
        // More sweeps, another restart and the same tap: still that one reply.
        konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
        restart(&mut fx).await;
        recover(&fx).await;
        let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, kind, CALL, &id)).await;
        assert_eq!(status, StatusCode::OK, "{kind}: {body}");
        let ids: std::collections::HashSet<_> = sent(&transport, kind).iter().map(|e| e.id).collect();
        assert_eq!(ids, std::collections::HashSet::from([out[0].id]), "{kind}: a second reply was made");
        assert!(flusher.seen().await.iter().all(|seen| *seen == out[0].id), "{kind}");
        assert_eq!(ledger(&fx, &transport), before, "{kind}");
    }
}

// F07: after the transition the caller hung up before the reply was queued;
// the receipt keeps its row through cleanup and the historical answer goes
// out once, without reopening the call.
#[tokio::test]
async fn f07_a_receipt_survives_a_later_end_and_cleanup_until_its_reply_is_queued() {
    let (mut fx, _token, transport, id, db) = moved_before_queueing(401).await;
    caller_hangs_up(&fx).await;
    let ended = row(&fx, &fx.peer, CALL).await.unwrap();
    assert_eq!((ended.phase, ended.end_reason), (Phase::Ended, Some(HangupReason::Hangup)));
    // A sweep that cannot queue the reply yet (its receipt cleanup runs too),
    // then the tombstone runs out and bounds press for room.
    exec(&db, "CREATE TRIGGER stop_queue BEFORE INSERT ON pending_deliveries BEGIN SELECT RAISE(ABORT, 'disk full'); END;").await;
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    assert!(sent(&transport, 401).is_empty());
    let far = konsensus_api::calls::now_ms() + 3 * TOMBSTONE_MS;
    fx.state.storage.call_sweep(far, 100).await.unwrap();
    fx.state.storage.call_evict_burned(Some(&fx.peer), far, far, 100).await.unwrap();
    assert_eq!(row(&fx, &fx.peer, CALL).await, Some(ended.clone()), "cleanup dropped the call row of a reply that can still be recovered");
    resume(&db).await;
    restart(&mut fx).await;
    recover(&fx).await;
    let out = sent(&transport, 401);
    assert_eq!(out.len(), 1, "the answer whose transition happened was lost");
    let after = row(&fx, &fx.peer, CALL).await.unwrap();
    assert_eq!((after.phase, after.end_reason, after.deadline_ms), (Phase::Ended, Some(HangupReason::Hangup), ended.deadline_ms),
        "recovery reopened or rewrote the ended call");
    if has_receipts(&db).await {
        assert_eq!(receipts(&db, &fx.peer, CALL).await, Some(None));
        // Released: the row is swept like any other.
        assert_eq!(fx.state.storage.call_sweep(far, 100).await.unwrap(), 1);
    }
    assert_eq!(operation(&fx, &id).await.message_id, Some(out[0].id.to_hex()));
}

// F08: a failed transition write blocks queueing; a lost acknowledgement is
// resolved by rereading the receipt; an unreadable row stays unresolved.
#[tokio::test]
async fn f08_failed_or_uncertain_transition_writes_never_queue_early() {
    // Before commit: nothing moved, the reply is taken back, the same tap works.
    for kind in [401u16, 403] {
        let (fx, token, transport) = ringing(true, &[FREE], CALL).await;
        let db = raw(&fx).await;
        audit_queueing(&fx, &db).await;
        let flusher = Flusher::start(&fx).await;
        exec(&db, "CREATE TRIGGER fail_move BEFORE UPDATE ON call_state WHEN NEW.phase IN ('live', 'ended')
                     BEGIN SELECT RAISE(ABORT, 'disk full'); END;").await;
        let id = uuid::Uuid::new_v4().to_string();
        let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, kind, CALL, &id)).await;
        assert_eq!(body["reason"], "call_reply_unavailable", "{kind}: {status} {body}");
        konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
        assert!(queued(&db).await.is_empty() && flusher.seen().await.is_empty(), "{kind}: queued before its transition");
        assert_eq!(row(&fx, &fx.peer, CALL).await.unwrap().phase, Phase::Ringing);
        exec(&db, "DROP TRIGGER fail_move;").await;
        let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, kind, CALL, &id)).await;
        assert_eq!(status, StatusCode::OK, "{kind}: {body}");
        assert_eq!(queued(&db).await.len(), 1, "{kind}");
        assert_eq!(sent(&transport, kind).len(), 1, "{kind}");
    }
    // After commit, acknowledgement lost: the reply goes out once, not lost.
    for kind in [401u16, 403] {
        let (mut fx, token, transport) = ringing(true, &[FREE], CALL).await;
        let store = Arc::new(common::MemStorage::new());
        let entry = row(&fx, &fx.peer, CALL).await.unwrap();
        konsensus_storage::Storage::call_put(store.as_ref(), &fx.peer, CALL, &entry).await.unwrap();
        fx.state = Arc::new(AppState { storage: store.clone(), ..(*fx.state).clone() });
        let (arm, mut armed) = (Arc::clone(&store), true);
        *store.outbox_write_hook.lock().unwrap() = Some(Box::new(move |op| {
            let data: Value = serde_json::from_slice(&op.recovery).unwrap_or_default();
            if armed && op.state == "paying" && data["free_reply"] == true && data["envelope_ready"] == true {
                armed = false;
                *arm.lose_call_put_ack_for.lock().unwrap() = Some(CALL.into());
            }
            Ok(())
        }));
        let before = ledger(&fx, &transport);
        let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, kind, CALL, &uuid::Uuid::new_v4().to_string())).await;
        assert!(store.lose_call_put_ack_for.lock().unwrap().is_none(), "{kind}: the lost acknowledgement never happened");
        konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
        assert_eq!(status, StatusCode::OK, "{kind}: a reply whose transition committed was not sent: {body}");
        let ids: std::collections::HashSet<_> = sent(&transport, kind).iter().map(|e| e.id).collect();
        assert_eq!(ids.len(), 1, "{kind}");
        assert_eq!(ledger(&fx, &transport), before, "{kind}");
    }
    // An unreadable receipt stays unresolved until it can be read.
    let (mut fx, _token, transport, id, db) = moved_before_queueing(401).await;
    let Some(Some(stored)) = receipts(&db, &fx.peer, CALL).await else { return };
    exec(&db, &format!("UPDATE call_state SET free_reply_receipts = 'unreadable' WHERE call_id = '{CALL}'")).await;
    audit_queueing(&fx, &db).await;
    restart(&mut fx).await;
    konsensus_api::calls::recover(fx.state.storage.as_ref()).await.unwrap();
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    assert!(sent(&transport, 401).is_empty() && queued(&db).await.is_empty(), "an unreadable receipt let the reply out");
    assert!(matches!(operation(&fx, &id).await.state.as_str(), "paying" | "payment_unknown"));
    sqlx::query("UPDATE call_state SET free_reply_receipts = ? WHERE call_id = ?").bind(&stored).bind(CALL)
        .execute(db.pool()).await.unwrap();
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    assert_eq!(sent(&transport, 401).len(), 1, "a readable receipt again recovers the reply");
}

// F09: the withdrawal itself fails, across real restarts: unresolved and
// unqueued until it is durable; then terminal, and the same tap cannot
// prepare or pay it again.
#[tokio::test]
async fn f09_a_failed_withdrawal_stays_unresolved_until_it_is_durable() {
    let (mut fx, token, transport, id) = saved_before_transition(401, false).await;
    let before = ledger(&fx, &transport);
    caller_hangs_up(&fx).await;
    let db = raw(&fx).await;
    exec(&db, "CREATE TRIGGER fail_withdraw BEFORE UPDATE ON outbox_operations WHEN NEW.state = 'abandoned'
                 BEGIN SELECT RAISE(ABORT, 'disk full'); END;").await;
    for _ in 0..2 {
        restart(&mut fx).await;
        recover(&fx).await;
        assert!(sent(&transport, 401).is_empty(), "a reply was sent while its withdrawal failed");
        let op = operation(&fx, &id).await;
        assert!(matches!(op.state.as_str(), "paying" | "payment_unknown"), "{}", op.state);
        assert_eq!(data(&op)["envelope_ready"], true, "the saved reply was dropped before its withdrawal");
    }
    exec(&db, "DROP TRIGGER fail_withdraw;").await;
    restart(&mut fx).await;
    recover(&fx).await;
    restart(&mut fx).await;
    recover(&fx).await;
    assert_withdrawn(&fx, &token, &transport, 401, &id, before, "after failed withdrawals").await;
}

// F10: no receipt and no evidence either way (saved before the call was
// recorded with it), an empty digest, or two candidate calls: held, never
// inferred as sent or unsent.
#[tokio::test]
async fn f10_legacy_or_contradictory_saved_replies_are_held_not_inferred() {
    // Saved before receipts existed, and its call ended since.
    let (fx, token, transport, id) = saved_before_transition(401, false).await;
    rewrite(&fx, &id, |data| { data.as_object_mut().unwrap().remove("free_reply_call"); }).await;
    caller_hangs_up(&fx).await;
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    assert_held(&fx, &transport, 401, &id, "no_transition_evidence", "legacy").await;
    // Reported once: later sweeps leave the held operation alone.
    let version = operation(&fx, &id).await.version;
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    assert_eq!(operation(&fx, &id).await.version, version, "a held reply was rewritten on every sweep");
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &id)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(sent(&transport, 401).is_empty());

    // Saved before receipts existed, with its own reservation still in place:
    // its call is recorded with it first, then it moves the call and goes out.
    let (fx, _token, transport, id) = saved_before_transition(401, false).await;
    rewrite(&fx, &id, |data| { data.as_object_mut().unwrap().remove("free_reply_call"); }).await;
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    assert_eq!(sent(&transport, 401).len(), 1, "a legacy reply with its own reservation was not recovered");
    assert_eq!(row(&fx, &fx.peer, CALL).await.unwrap().phase, Phase::Live);

    // An empty request digest is not proof, even with the call still ringing.
    let (fx, _token, transport, id) = saved_before_transition(401, false).await;
    sqlx::query("UPDATE outbox_operations SET request_hash = '' WHERE operation_id = ?").bind(&id)
        .execute(raw(&fx).await.pool()).await.unwrap();
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    assert_held(&fx, &transport, 401, &id, "evidence_mismatch", "empty digest").await;
    assert_eq!(row(&fx, &fx.peer, CALL).await.unwrap().phase, Phase::Ringing);

    // Saved before receipts existed, with two calls carrying its reservation.
    let (fx, _token, transport, id) = saved_before_transition(401, false).await;
    const OTHER: &str = "99999999888877776666555544443333";
    rewrite(&fx, &id, |data| { data.as_object_mut().unwrap().remove("free_reply_call"); }).await;
    let entry = row(&fx, &fx.peer, CALL).await.unwrap();
    fx.state.storage.call_put(&fx.peer, OTHER, &entry).await.unwrap();
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    assert_held(&fx, &transport, 401, &id, "evidence_mismatch", "two candidates").await;
    for call_id in [CALL, OTHER] {
        assert_eq!(row(&fx, &fx.peer, call_id).await.unwrap().phase, Phase::Ringing, "{call_id}");
    }
}

// F11: repeated sweeps and taps never repeat the transition, the owner
// promotion or a charge; another payload under the same id conflicts; a
// receipt naming another request is not this reply's proof.
#[tokio::test]
async fn f11_repeats_are_idempotent_and_a_foreign_receipt_is_not_proof() {
    let (fx, token, transport) = ringing(true, &[FREE], CALL).await;
    let id = uuid::Uuid::new_v4().to_string();
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &id)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (once, before) = (row(&fx, &fx.peer, CALL).await.unwrap(), ledger(&fx, &transport));
    let claims = konsensus_api::auth::validate_token(&token, &fx.state.jwt_secret).unwrap();
    let binding = konsensus_api::auth::PairingBinding::from_claims(&claims).unwrap().unwrap();
    for _ in 0..3 {
        konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
        let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &id)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    assert_eq!(row(&fx, &fx.peer, CALL).await.unwrap(), once, "a repeat moved the call again");
    assert_eq!(ledger(&fx, &transport), before, "a repeat charged or reserved");
    assert!(fx.service.owns_call_media(&binding, &fx.peer.to_hex(), CALL));
    let ids: std::collections::HashSet<_> = sent(&transport, 401).iter().map(|e| e.id).collect();
    assert_eq!(ids.len(), 1, "a repeat made a second reply");
    let mut other = reply(&fx, 401, CALL, &id);
    other["plaintext"] = json!(json!({"v": 1, "call_id": CALL, "sdp": "another answer"}).to_string());
    let resent = sent(&transport, 401).len();
    let (status, body) = send_request(&fx, &token, 7_000, other).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("operation_mismatch"), "{body}");
    assert_eq!(sent(&transport, 401).len(), resent, "another payload under the same id was sent");

    // A receipt for this operation naming another request.
    let (mut fx, _token, transport, id, db) = moved_before_queueing(401).await;
    let Some(Some(stored)) = receipts(&db, &fx.peer, CALL).await else { return };
    let digest = operation(&fx, &id).await.request_hash;
    sqlx::query("UPDATE call_state SET free_reply_receipts = ? WHERE call_id = ?")
        .bind(stored.replace(&digest, "another request")).bind(CALL).execute(db.pool()).await.unwrap();
    restart(&mut fx).await;
    recover(&fx).await;
    assert_held(&fx, &transport, 401, &id, "evidence_mismatch", "foreign receipt").await;
}

// F12: an independent outbox reader only ever sees a reply after its call
// moved. A reply that was already queued before this guard existed is not
// retracted by it: the guard governs publication, not past delivery.
#[tokio::test]
async fn f12_queue_visibility_follows_the_transition_and_history_is_not_rewritten() {
    for kind in [401u16, 403] {
        let (fx, token, transport) = ringing(true, &[FREE], CALL).await;
        let db = raw(&fx).await;
        audit_queueing(&fx, &db).await;
        let flusher = Flusher::start(&fx).await;
        let polls = {
            let (store, peer) = (raw(&fx).await, fx.peer);
            let seen_phase = Arc::new(std::sync::Mutex::new(Vec::new()));
            let log = Arc::clone(&seen_phase);
            let task = tokio::spawn(async move {
                loop {
                    if !store.get_pending_for_peer(&peer).await.unwrap_or_default().is_empty() {
                        let phase = store.call_get(&peer, CALL).await.ok().flatten().map(|e| e.phase);
                        log.lock().unwrap().push(phase);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            });
            (seen_phase, task)
        };
        let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, kind, CALL, &uuid::Uuid::new_v4().to_string())).await;
        assert_eq!(status, StatusCode::OK, "{kind}: {body}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        polls.1.abort();
        let to = if kind == 401 { Phase::Live } else { Phase::Ended };
        assert!(polls.0.lock().unwrap().iter().all(|p| *p == Some(to)), "{kind}: a reader saw the reply before its call moved");
        assert!(queued(&db).await.iter().all(|(_, phase, _)| phase.as_deref() == Some(to.as_str())), "{kind}");
        assert!(flusher.seen().await.len() <= 1, "{kind}");
        assert_eq!(sent(&transport, kind).len(), 1, "{kind}");
    }
    // A reply queued for a call that had ended without it, as an older node
    // could leave it: still delivered. Auditing such rows is separate work.
    let (fx, _token, transport, id) = saved_before_transition(401, false).await;
    caller_hangs_up(&fx).await;
    let mut op = operation(&fx, &id).await;
    let env: konsensus_core::UkmEnvelope = serde_json::from_value(data(&op)["draft"].clone()).unwrap();
    op.state = "paid".into();
    assert!(fx.state.storage.commit_outbox_envelope(&op, &env).await.unwrap());
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    assert_eq!(sent(&transport, 401).iter().map(|e| e.id).collect::<Vec<_>>(), vec![env.id], "an already queued reply was retracted or doubled");
    assert_ne!(operation(&fx, &id).await.state, "abandoned");
    assert_eq!(row(&fx, &fx.peer, CALL).await.unwrap().phase, Phase::Ended, "delivery reopened the ended call");
}

// Receipt retention: a receipt left behind by a stop after its reply was
// queued is released by the next sweep, so its row can age out again.
#[tokio::test]
async fn a_receipt_left_after_its_reply_was_queued_is_released_by_a_sweep() {
    let (mut fx, _token, transport, _id, db) = moved_before_queueing(403).await;
    let Some(Some(stored)) = receipts(&db, &fx.peer, CALL).await else { return };
    restart(&mut fx).await;
    recover(&fx).await;
    assert_eq!(sent(&transport, 403).len(), 1);
    // As if the node stopped between queueing the reply and releasing its receipt.
    sqlx::query("UPDATE call_state SET free_reply_receipts = ? WHERE call_id = ?").bind(&stored).bind(CALL)
        .execute(db.pool()).await.unwrap();
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    assert_eq!(receipts(&db, &fx.peer, CALL).await, Some(None), "a receipt outlived its queued reply");
    let far = konsensus_api::calls::now_ms() + 3 * TOMBSTONE_MS;
    assert_eq!(fx.state.storage.call_sweep(far, 100).await.unwrap(), 1);
    assert_eq!(sent(&transport, 403).len(), 1);
}

/// Every distinct reply this node queued or sent for `kind`.
async fn distinct_sent(transport: &ConnectedStubTransport, kind: u16) -> std::collections::HashSet<konsensus_core::MessageId> {
    sent(transport, kind).iter().map(|e| e.id).collect()
}

// F13: the same saved reply recovered by a sweep while the app taps again:
// one reply, queued once, its receipt released, nothing paid.
#[tokio::test]
async fn f13_a_tap_racing_a_recovery_sweep_sends_the_saved_reply_once() {
    for kind in [401u16, 403] {
        for moved in [false, true] {
            let what = format!("{kind} moved={moved}");
            let (fx, token, transport, id, db) = if moved {
                moved_before_queueing(kind).await
            } else {
                let (fx, token, transport, id) = saved_before_transition(kind, false).await;
                let db = raw(&fx).await;
                (fx, token, transport, id, db)
            };
            audit_queueing(&fx, &db).await;
            let before = ledger(&fx, &transport);
            let (tap, sweep) = tokio::join!(
                send_request(&fx, &token, 7_000, reply(&fx, kind, CALL, &id)),
                konsensus_api::handlers::messages::reconcile_operations(&fx.state),
            );
            sweep.unwrap();
            assert!(tap.0 == StatusCode::OK || tap.0 == StatusCode::CONFLICT, "{what}: {tap:?}");
            konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
            let ids = distinct_sent(&transport, kind).await;
            assert_eq!(ids.len(), 1, "{what}: the saved reply was lost or doubled");
            let audit = queued(&db).await;
            assert_eq!(audit.len(), 1, "{what}: queued {} times", audit.len());
            assert_eq!(audit[0].0, ids.iter().next().unwrap().to_hex(), "{what}");
            assert!(fx.state.storage.get_pending_for_peer(&fx.peer).await.unwrap().len() <= 1, "{what}");
            assert_eq!(receipts(&db, &fx.peer, CALL).await, Some(None), "{what}: the receipt was not released");
            assert_eq!(ledger(&fx, &transport), before, "{what}: something was paid");
            assert!(matches!(operation(&fx, &id).await.state.as_str(), "paid" | "sent" | "acked"), "{what}");
        }
    }
}

// F14: a second answer to the same ringing call never gets a reply out:
// while the first is reserved it is refused before anything is saved, and
// two taps at once move the call once.
#[tokio::test]
async fn f14_a_second_answer_to_one_ringing_call_is_refused_never_queued() {
    // The first answer is saved, its transition not yet written.
    let (fx, token, transport, first) = saved_before_transition(401, false).await;
    let before = ledger(&fx, &transport);
    let second = uuid::Uuid::new_v4().to_string();
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &second)).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(body["reason"], "call_signal_in_flight", "{body}");
    assert!(fx.state.storage.get_outbox_operation(&second).await.unwrap().is_none(), "the second answer was saved");
    assert_eq!(row(&fx, &fx.peer, CALL).await.unwrap().pending.map(|p| p.operation_id), Some(first.clone()));
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    assert_eq!(distinct_sent(&transport, 401).await.len(), 1);
    assert_eq!(row(&fx, &fx.peer, CALL).await.unwrap().phase, Phase::Live);
    assert_eq!(ledger(&fx, &transport), before);

    // Two taps at once, distinct operations.
    let (fx, token, transport) = ringing(true, &[FREE], CALL).await;
    let before = ledger(&fx, &transport);
    let (a, b) = (uuid::Uuid::new_v4().to_string(), uuid::Uuid::new_v4().to_string());
    let (ra, rb) = tokio::join!(
        send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &a)),
        send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &b)),
    );
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    assert_eq!([&ra, &rb].iter().filter(|r| r.0 == StatusCode::OK).count(), 1, "{ra:?} {rb:?}");
    let (winner, loser) = if ra.0 == StatusCode::OK { (&a, &b) } else { (&b, &a) };
    assert_eq!(distinct_sent(&transport, 401).await.len(), 1, "both answers went out");
    let entry = row(&fx, &fx.peer, CALL).await.unwrap();
    assert_eq!((entry.phase, entry.pending), (Phase::Live, None));
    assert!(matches!(operation(&fx, winner).await.state.as_str(), "paid" | "sent" | "acked"));
    if let Some(op) = fx.state.storage.get_outbox_operation(loser).await.unwrap() {
        assert!(!matches!(op.state.as_str(), "paid" | "sent" | "acked"), "the losing answer was queued: {}", op.state);
    }
    assert_eq!(ledger(&fx, &transport), before);
    let claims = konsensus_api::auth::validate_token(&token, &fx.state.jwt_secret).unwrap();
    let binding = konsensus_api::auth::PairingBinding::from_claims(&claims).unwrap().unwrap();
    assert!(fx.service.owns_call_media(&binding, &fx.peer.to_hex(), CALL));
}

// F15: a saved free reply never moves a call that went live and paid
// another way; a paid answer never takes the free-reply gate.
#[tokio::test]
async fn f15_a_saved_free_reply_never_moves_a_paid_live_call() {
    for kind in [401u16, 403] {
        let (mut fx, token, transport, id) = saved_before_transition(kind, false).await;
        let before = ledger(&fx, &transport);
        let now = konsensus_api::calls::now_ms();
        let entry = row(&fx, &fx.peer, CALL).await.unwrap();
        let live = CallEntry { phase: Phase::Live, pending: None, paid_until_ms: Some(now + 50_000),
            deadline_ms: now + 60_000, next_block_seq: 1, ..entry };
        fx.state.storage.call_put(&fx.peer, CALL, &live).await.unwrap();
        restart(&mut fx).await;
        recover(&fx).await;
        assert_eq!(row(&fx, &fx.peer, CALL).await, Some(live), "{kind}: the paid live call was changed");
        assert_withdrawn(&fx, &token, &transport, kind, &id, before, &format!("{kind} live")).await;
    }
    // Switch on here, the peer without it: a paid answer, no receipt anywhere.
    let (fx, token, transport) = ringing(true, &[], CALL).await;
    let db = raw(&fx).await;
    audit_queueing(&fx, &db).await;
    let money = fx.wallet.money();
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &uuid::Uuid::new_v4().to_string())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.wallet.money(), money + 1, "the answer must be paid");
    let out = sent(&transport, 401);
    assert_eq!(out.len(), 1);
    assert!(out[0].payment_proof.amount_msat > 0 && out[0].references.is_empty());
    let audit = queued(&db).await;
    assert_eq!(audit.len(), 1);
    assert_eq!((audit[0].1.as_deref(), audit[0].2.as_deref()), (Some("live"), None), "a paid answer wrote a free-reply receipt");
    assert_eq!(receipts(&db, &fx.peer, CALL).await, Some(None));
}

// F16: a call row whose receipt set is full refuses the transition: nothing
// queued or paid, every held receipt kept, the reply taken back unsent. The
// transition definitely did not happen and the reservation still stands, so
// this is the ordinary retryable refusal (`call_reply_unavailable`).
#[tokio::test]
async fn f16_a_full_receipt_set_refuses_the_reply_and_keeps_every_receipt() {
    let (fx, token, transport) = ringing(true, &[FREE], CALL).await;
    let db = raw(&fx).await;
    audit_queueing(&fx, &db).await;
    let held: Vec<_> = (0..konsensus_core::payloads::call::MAX_FREE_REPLY_RECEIPTS).map(|n| konsensus_core::payloads::call::FreeReplyReceipt {
        peer: fx.peer.to_hex(), call_id: CALL.into(), kind: 403, operation_id: format!("held-{n}"),
        request_hash: "digest".into(), phase: "ended".into(), applied_ms: 1,
    }).collect();
    let entry = row(&fx, &fx.peer, CALL).await.unwrap();
    fx.state.storage.call_put(&fx.peer, CALL, &CallEntry { free_reply_receipts: held.clone(), ..entry }).await.unwrap();
    let before = ledger(&fx, &transport);
    let id = uuid::Uuid::new_v4().to_string();
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &id)).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(body["reason"], "call_reply_unavailable", "{body}");
    assert_eq!(body["retry_allowed"], true, "{body}");
    let after = row(&fx, &fx.peer, CALL).await.unwrap();
    assert_eq!(after.free_reply_receipts, held, "a held receipt was dropped");
    assert_eq!(after.phase, Phase::Ringing);
    assert!(queued(&db).await.is_empty() && sent(&transport, 401).is_empty());
    let op = operation(&fx, &id).await;
    // Taken back: definitely unsent and nothing paid, so the journal says released.
    assert_eq!((op.state.as_str(), data(&op)["envelope_ready"].clone()), ("released", json!(false)));
    assert_eq!(ledger(&fx, &transport), before);
}

// F17: a real restart while the reply is saved and the call still rings:
// recovery moves the call with this reply's receipt, then sends it once. A
// restart ends a call still waiting for a device (the caller is told it was
// not reachable), so a decline saved for it is withdrawn, never sent.
#[tokio::test]
async fn f17_a_restart_before_the_transition_sends_the_saved_reply_once() {
    let (mut fx, token, transport, id) = saved_before_transition(403, true).await;
    let before = ledger(&fx, &transport);
    restart(&mut fx).await;
    recover(&fx).await;
    let entry = row(&fx, &fx.peer, CALL).await.unwrap();
    assert_eq!((entry.phase, entry.pending), (Phase::Ended, None), "the restart did not end the device wait");
    assert_withdrawn(&fx, &token, &transport, 403, &id, before, "403 waiting, restarted").await;

    for (kind, waiting, to) in [(401u16, false, "live"), (403, false, "ended")] {
        let what = format!("{kind} waiting={waiting}");
        let (mut fx, token, transport, id) = saved_before_transition(kind, waiting).await;
        let db = raw(&fx).await;
        audit_queueing(&fx, &db).await;
        let before = ledger(&fx, &transport);
        restart(&mut fx).await;
        recover(&fx).await;
        let ids = distinct_sent(&transport, kind).await;
        assert_eq!(ids.len(), 1, "{what}");
        let audit = queued(&db).await;
        assert_eq!(audit.len(), 1, "{what}");
        assert_eq!(audit[0].1.as_deref(), Some(to), "{what}");
        assert!(audit[0].2.as_deref().is_some_and(|r| r.contains(&id)), "{what}: queued without this reply's receipt");
        assert_eq!(receipts(&db, &fx.peer, CALL).await, Some(None), "{what}");
        assert_eq!(ledger(&fx, &transport), before, "{what}");
        let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, kind, CALL, &id)).await;
        assert_eq!(status, StatusCode::OK, "{what}: {body}");
        assert_eq!(distinct_sent(&transport, kind).await, ids, "{what}");
    }
}

/// Fault-injecting storage holding the ringing call; `at_seal` runs once,
/// right when the signed reply is saved, before its call transition.
async fn seal_hook(fx: &mut Fx, at_seal: impl FnOnce(&Arc<common::MemStorage>, &CallEntry) + Send + 'static) -> Arc<common::MemStorage> {
    let store = Arc::new(common::MemStorage::new());
    let entry = row(fx, &fx.peer, CALL).await.unwrap();
    konsensus_storage::Storage::call_put(store.as_ref(), &fx.peer, CALL, &entry).await.unwrap();
    fx.state = Arc::new(AppState { storage: store.clone(), ..(*fx.state).clone() });
    let (hooked, mut action) = (Arc::clone(&store), Some(at_seal));
    *store.outbox_write_hook.lock().unwrap() = Some(Box::new(move |op| {
        let data: Value = serde_json::from_slice(&op.recovery).unwrap_or_default();
        if op.state == "paying" && data["free_reply"] == true && data["envelope_ready"] == true {
            if let Some(action) = action.take() { action(&hooked, &entry); }
        }
        Ok(())
    }));
    store
}

// F18: what the send path reports for each gate outcome.
#[tokio::test]
async fn f18_the_send_path_reports_each_gate_outcome() {
    // Invalid: the call ended right after the reply was saved.
    let (mut fx, token, transport) = ringing(true, &[FREE], CALL).await;
    let peer = fx.peer;
    let store = seal_hook(&mut fx, move |store, entry| store.set_call(&peer, CALL, CallEntry {
        phase: Phase::Ended, pending: None, end_reason: Some(HangupReason::Hangup),
        deadline_ms: konsensus_api::calls::now_ms() + TOMBSTONE_MS, ..entry.clone() })).await;
    let before = ledger(&fx, &transport);
    let id = uuid::Uuid::new_v4().to_string();
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &id)).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!((body["reason"].clone(), body["code"].clone()), (json!("call_reply_expired"), json!("not_dispatched")), "{body}");
    assert_eq!(body["state"], "abandoned", "unsent reported before the withdrawal was saved: {body}");
    assert_eq!(body["retry_allowed"], false, "{body}");
    assert_eq!(store.call_phase(&peer, CALL), Some(Phase::Ended));
    assert_withdrawn(&fx, &token, &transport, 401, &id, before, "ended after save").await;

    // Unknown: the call cannot be read at the transition.
    let (mut fx, token, transport) = ringing(true, &[FREE], CALL).await;
    let store = seal_hook(&mut fx, |store, _| *store.fail_call_get_for.lock().unwrap() = Some(CALL.into())).await;
    let before = ledger(&fx, &transport);
    let id = uuid::Uuid::new_v4().to_string();
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &id)).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(body["reason"], "call_reply_unresolved", "{body}");
    assert_ne!(body["code"], "not_dispatched", "{body}");
    assert_eq!((body["state"].clone(), body["retry_allowed"].clone()), (json!("payment_unknown"), json!(false)), "{body}");
    assert!(sent(&transport, 401).is_empty());
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &id)).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert!(sent(&transport, 401).is_empty(), "an unresolved reply went out on a retry while unreadable");
    *store.fail_call_get_for.lock().unwrap() = None;
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    assert_eq!(distinct_sent(&transport, 401).await.len(), 1, "readable again: the reply is recovered once");
    assert_eq!(ledger(&fx, &transport), before);

    // NotApplied: the transition write fails; the reply is taken back.
    let (mut fx, token, transport) = ringing(true, &[FREE], CALL).await;
    seal_hook(&mut fx, |store, _| *store.fail_call_put_for.lock().unwrap() = Some(CALL.into())).await;
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &uuid::Uuid::new_v4().to_string())).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!((body["reason"].clone(), body["code"].clone()), (json!("call_reply_unavailable"), json!("not_dispatched")), "{body}");
    assert_eq!((body["state"].clone(), body["retry_allowed"].clone()), (json!("released"), json!(true)), "{body}");
    assert!(sent(&transport, 401).is_empty());

    // Held unresolved (saved before receipts existed, call since ended): a
    // retry is refused, not retryable, and sends nothing.
    let (fx, token, transport, id) = saved_before_transition(401, false).await;
    rewrite(&fx, &id, |data| { data.as_object_mut().unwrap().remove("free_reply_call"); }).await;
    caller_hangs_up(&fx).await;
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &id)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!((body["state"].clone(), body["retry_allowed"].clone()), (json!("payment_unknown"), json!(false)), "{body}");
    assert!(body.to_string().contains("payment_unresolved"), "{body}");
    assert!(sent(&transport, 401).is_empty());
}
