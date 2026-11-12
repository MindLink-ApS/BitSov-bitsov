use konsensus_api::calls::{self, MediaDetach};
use konsensus_core::{
    payloads::call::{self as rules, CallEntry, HangupReason, Pending, Phase, Side},
    NodeId,
};
use konsensus_storage::{call_media::PendingMediaDetach, EncryptedStorage, SqliteStorage, Storage};
use std::sync::Arc;

const CALL: &str = "0123456789abcdef0123456789abcdef";
static NOW: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
});
fn peer() -> NodeId {
    NodeId::from_bytes([71; 32])
}
fn paid() -> CallEntry {
    CallEntry {
        side: Side::Callee,
        phase: Phase::Live,
        deadline_ms: *NOW + 70_000,
        pending: Some(Pending {
            operation_id: "pending".into(),
            kind: 403,
            request_hash: "request".into(),
        }),
        paid_until_ms: Some(*NOW + 60_000),
        next_block_seq: 1,
        end_reason: None,
        unpaid_notice_used: false,
    }
}
fn intent(generation: u64, only_unpaid: bool, may_hangup_live: bool) -> PendingMediaDetach {
    PendingMediaDetach {
        peer: peer(),
        call_id: CALL.into(),
        generation,
        only_unpaid,
        may_hangup_live,
        has_stop_policy: true,
    }
}
fn detach(generation: u64, only_unpaid: bool, may_hangup_live: bool) -> MediaDetach {
    MediaDetach {
        generation: Arc::new(tokio::sync::Mutex::new(generation)),
        expected_generation: generation,
        only_unpaid,
        may_hangup_live,
    }
}

async fn replay_contract(store: Arc<dyn Storage>) {
    let original = paid();
    store.call_put(&peer(), CALL, &original).await.unwrap();
    let old = store.call_media_publish(&peer(), CALL).await.unwrap();
    store
        .call_media_record_detach(&intent(old, false, true), false)
        .await
        .unwrap();
    let current = calls::publish_media_attachment(&store, &peer(), CALL)
        .await
        .unwrap();
    assert!(current > old);
    calls::replay_media_detaches(store.as_ref(), *NOW, false)
        .await
        .unwrap();
    assert_eq!(
        store.call_get(&peer(), CALL).await.unwrap().unwrap(),
        original,
        "active replacement survives stale replay"
    );
    // A callback from a previous process has a different mutex, so the durable
    // generation, rather than the in-process guard, must fence its write.
    calls::detach_callee_media(
        store.as_ref(),
        &peer(),
        CALL,
        *NOW,
        &detach(old, false, true),
    )
    .await
    .unwrap();
    assert_eq!(
        store.call_get(&peer(), CALL).await.unwrap().unwrap(),
        original
    );
    let stopped = detach(current, false, true);
    calls::stop_media_attachment(store.as_ref(), &peer(), CALL, &stopped);
    store
        .call_media_record_detach(&intent(current, false, true), false)
        .await
        .unwrap();
    calls::replay_media_detaches(store.as_ref(), *NOW, true)
        .await
        .unwrap();
    let ended = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(ended.phase, Phase::Ended);
    assert_eq!(ended.end_reason, Some(HangupReason::Hangup));
    assert_eq!(ended.pending, original.pending);
    assert_eq!(ended.next_block_seq, 1);
    assert_eq!(ended.paid_until_ms, original.paid_until_ms);
    assert!(rules::receive_block(Some(ended.clone()), 1, *NOW).is_err());
    assert!(store.call_media_pending(0, 256).await.unwrap().is_empty());
    calls::replay_media_detaches(store.as_ref(), *NOW + 20_000, true)
        .await
        .unwrap();
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap().unwrap(), ended);
    // A completed old generation cannot reopen after its call id is reused.
    store.call_put(&peer(), CALL, &original).await.unwrap();
    calls::detach_callee_media(
        store.as_ref(),
        &peer(),
        CALL,
        *NOW,
        &detach(current, false, true),
    )
    .await
    .unwrap();
    assert_eq!(
        store.call_get(&peer(), CALL).await.unwrap().unwrap(),
        original
    );
}

#[tokio::test]
async fn sqlite_replay_fences_replacement_and_is_idempotent() {
    replay_contract(Arc::new(SqliteStorage::in_memory().await.unwrap())).await;
}

#[tokio::test]
async fn encrypted_replay_fences_replacement_and_is_idempotent() {
    replay_contract(Arc::new(EncryptedStorage::new(
        SqliteStorage::in_memory().await.unwrap(),
        &[7; 32],
    )))
    .await;
}

#[tokio::test]
async fn policy_survives_reopen_and_never_ends_a_paid_live_call_after_admission_loss() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.sqlite");
    {
        let store = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
        store.call_put(&peer(), CALL, &paid()).await.unwrap();
        let generation = store.call_media_publish(&peer(), CALL).await.unwrap();
        store
            .call_media_record_detach(&intent(generation, false, false), false)
            .await
            .unwrap();
    }
    let store = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    calls::replay_media_detaches(&store, *NOW, true)
        .await
        .unwrap();
    assert_eq!(
        store.call_get(&peer(), CALL).await.unwrap().unwrap(),
        paid()
    );
    assert_eq!(store.call_media_pending(0, 256).await.unwrap().len(), 1);
}

#[tokio::test]
async fn overdue_replay_preserves_unpaid_expiry_and_closes_resume() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let mut original = paid();
    original.deadline_ms = *NOW - 1;
    original.paid_until_ms = Some(*NOW - 10_001);
    store.call_put(&peer(), CALL, &original).await.unwrap();
    let generation = store.call_media_publish(&peer(), CALL).await.unwrap();
    store
        .call_media_record_detach(&intent(generation, false, false), false)
        .await
        .unwrap();
    calls::replay_media_detaches(&store, *NOW, true)
        .await
        .unwrap();
    let closed = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(
        closed.phase,
        Phase::Live,
        "ordinary maintenance owns the expiry transition"
    );
    assert_eq!(closed.paid_until_ms, Some(0));
    let expired = calls::expire_calls(&store, *NOW).await.unwrap();
    assert_eq!(expired, vec![(peer(), CALL.to_string())]);
    calls::replay_media_detaches(&store, *NOW, false)
        .await
        .unwrap();
    let ended = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(ended.phase, Phase::Ended);
    assert_eq!(ended.end_reason, Some(HangupReason::Unpaid));
    assert_eq!(ended.pending, original.pending);
    assert_eq!(ended.deadline_ms, *NOW - 1 + rules::TOMBSTONE_MS);
    assert_eq!(ended.next_block_seq, 1);
    assert_eq!(ended.paid_until_ms, Some(0));
    assert!(rules::receive_block(Some(ended), 1, *NOW).is_err());
}

#[tokio::test]
async fn completion_append_failure_replays_an_already_committed_write_once() {
    let store = SqliteStorage::in_memory().await.unwrap();
    store.call_put(&peer(), CALL, &paid()).await.unwrap();
    let generation = store.call_media_publish(&peer(), CALL).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_completion BEFORE INSERT ON call_media_detach_intents WHEN NEW.event = 'complete' BEGIN SELECT RAISE(ABORT, 'completion unavailable'); END")
        .execute(store.pool()).await.unwrap();
    calls::replay_media_detaches(&store, *NOW, true)
        .await
        .unwrap();
    let ended = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(ended.phase, Phase::Ended);
    assert_eq!(
        store.call_media_pending(0, 10).await.unwrap()[0].generation,
        generation
    );
    sqlx::query("DROP TRIGGER fail_completion")
        .execute(store.pool())
        .await
        .unwrap();
    calls::replay_media_detaches(&store, *NOW + 50_000, true)
        .await
        .unwrap();
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap().unwrap(), ended);
    assert!(store.call_media_pending(0, 10).await.unwrap().is_empty());
    let history: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM call_media_detach_intents")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        history, 3,
        "publication, one policy and completion stay in history"
    );
}

#[tokio::test]
async fn runtime_recovers_even_when_detach_intent_writes_were_unavailable() {
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let store: Arc<dyn Storage> = db.clone();
    store.call_put(&peer(), CALL, &paid()).await.unwrap();
    let generation = calls::publish_media_attachment(&store, &peer(), CALL)
        .await
        .unwrap();
    let stopped = detach(generation, false, false);
    calls::stop_media_attachment(store.as_ref(), &peer(), CALL, &stopped);
    sqlx::query("CREATE TRIGGER fail_intent BEFORE INSERT ON call_media_detach_intents BEGIN SELECT RAISE(ABORT, 'journal unavailable'); END")
        .execute(db.pool()).await.unwrap();
    assert!(
        calls::detach_callee_media(store.as_ref(), &peer(), CALL, *NOW, &stopped)
            .await
            .is_err()
    );
    sqlx::query("DROP TRIGGER fail_intent")
        .execute(db.pool())
        .await
        .unwrap();
    calls::replay_media_detaches(store.as_ref(), *NOW, false)
        .await
        .unwrap();
    assert_eq!(
        store.call_get(&peer(), CALL).await.unwrap().unwrap(),
        paid(),
        "fallback preserves the admission-loss policy"
    );
    assert_eq!(store.call_media_pending(0, 10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn pending_detach_pins_the_call_id_until_replay_completes() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let mut original = paid();
    original.pending = None;
    original.phase = Phase::Ended;
    original.end_reason = Some(HangupReason::Unpaid);
    original.deadline_ms = *NOW - 1;
    store.call_put(&peer(), CALL, &original).await.unwrap();
    let generation = store.call_media_publish(&peer(), CALL).await.unwrap();
    store
        .call_media_record_detach(&intent(generation, false, false), false)
        .await
        .unwrap();
    assert_eq!(
        store.call_counts(&peer(), *NOW).await.unwrap().burned_total,
        1,
        "expired pinned calls must remain inside capacity accounting"
    );
    assert_eq!(
        store
            .call_evict_burned(Some(&peer()), *NOW, *NOW, 10)
            .await
            .unwrap(),
        0,
        "pending teardown must also survive pressure eviction"
    );
    assert_eq!(
        store.call_sweep(*NOW, 10).await.unwrap(),
        0,
        "pending teardown must not reach a reused call id"
    );
    calls::replay_media_detaches(&store, *NOW, true)
        .await
        .unwrap();
    assert_eq!(store.call_sweep(*NOW, 10).await.unwrap(), 1);
}

#[tokio::test]
#[ignore = "requires BITSOV_TEST_POSTGRES_URL pointing to a disposable PostgreSQL server"]
async fn postgres_replay_fences_replacement_and_is_idempotent() {
    let url = std::env::var("BITSOV_TEST_POSTGRES_URL").unwrap();
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let name = format!("media_detach_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let db_url = format!("{}/{name}", url.rsplit_once('/').unwrap().0);
    {
        let before = konsensus_storage::PostgresStorage::connect(&db_url)
            .await
            .unwrap();
        before.call_put(&peer(), CALL, &paid()).await.unwrap();
        let control = sqlx::PgPool::connect(&db_url).await.unwrap();
        sqlx::raw_sql("DROP TABLE call_media_heads; DROP TABLE call_media_detach_intents; DELETE FROM _konsensus_migrations WHERE version = 40;")
            .execute(&control).await.unwrap();
        control.close().await;
    }
    let upgraded = Arc::new(
        konsensus_storage::PostgresStorage::connect(&db_url)
            .await
            .unwrap(),
    );
    assert_eq!(
        upgraded.call_get(&peer(), CALL).await.unwrap().unwrap(),
        paid()
    );
    replay_contract(upgraded).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test]
async fn replay_pages_past_a_full_batch() {
    let store = SqliteStorage::in_memory().await.unwrap();
    for n in 0..257 {
        let id = format!("{n:032x}");
        store.call_put(&peer(), &id, &paid()).await.unwrap();
        store.call_media_publish(&peer(), &id).await.unwrap();
    }
    calls::replay_media_detaches(&store, *NOW, true)
        .await
        .unwrap();
    assert!(store.call_media_pending(0, 256).await.unwrap().is_empty());
    assert_eq!(
        store
            .call_get(&peer(), &format!("{:032x}", 256))
            .await
            .unwrap()
            .unwrap()
            .phase,
        Phase::Ended
    );
}

#[tokio::test]
async fn replay_failure_does_not_prevent_unpaid_expiry() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let mut original = paid();
    original.deadline_ms = *NOW - 1;
    original.paid_until_ms = Some(*NOW - 10_001);
    store.call_put(&peer(), CALL, &original).await.unwrap();
    store.call_media_publish(&peer(), CALL).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_intent BEFORE INSERT ON call_media_detach_intents BEGIN SELECT RAISE(ABORT, 'journal unavailable'); END")
        .execute(store.pool()).await.unwrap();
    assert_eq!(
        calls::expire_calls(&store, *NOW).await.unwrap(),
        vec![(peer(), CALL.into())]
    );
    let expired = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(expired.phase, Phase::Ended);
    assert_eq!(expired.end_reason, Some(HangupReason::Unpaid));
    assert_eq!(expired.pending, original.pending);
    assert_eq!(expired.next_block_seq, 1);
}

#[tokio::test]
async fn publication_rechecks_admission_after_waiting_for_the_call_lock() {
    let store: Arc<dyn Storage> = Arc::new(SqliteStorage::in_memory().await.unwrap());
    store.call_put(&peer(), CALL, &paid()).await.unwrap();
    let body = format!(r#"{{"call_id":"{CALL}","seq":1}}"#);
    let decision = calls::prepare_incoming_block(store.as_ref(), &peer(), Some(&body), &[9; 32])
        .await
        .unwrap();
    let publishing = {
        let store = store.clone();
        tokio::spawn(async move { calls::publish_media_attachment(&store, &peer(), CALL).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!publishing.is_finished());
    let mut ended = paid();
    ended.phase = Phase::Ended;
    ended.end_reason = Some(HangupReason::Hangup);
    store.call_put(&peer(), CALL, &ended).await.unwrap();
    drop(decision);
    assert!(
        publishing.await.unwrap().is_err(),
        "publication must recheck admission under the call lock"
    );
}

#[tokio::test]
async fn unresolved_detach_refuses_an_invite_reusing_an_aged_call_id() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let mut ended = paid();
    ended.phase = Phase::Ended;
    ended.pending = None;
    ended.end_reason = Some(HangupReason::Unpaid);
    ended.deadline_ms = *NOW - 1;
    store.call_put(&peer(), CALL, &ended).await.unwrap();
    let generation = store.call_media_publish(&peer(), CALL).await.unwrap();
    store
        .call_media_record_detach(&intent(generation, false, false), false)
        .await
        .unwrap();
    let invite = format!(r#"{{"v":1,"call_id":"{CALL}","media":"audio","sdp":"v=0"}}"#);
    assert!(
        calls::admit_incoming(
            &store,
            &NodeId::from_bytes([72; 32]),
            &peer(),
            400,
            Some(&invite)
        )
        .await
        .is_err(),
        "a pending old teardown must refuse reuse through admission as well as storage sweeping"
    );
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap().unwrap(), ended);
}

#[tokio::test]
async fn runtime_fallback_keeps_admission_only_policy_until_unpaid_expiry() {
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let store: Arc<dyn Storage> = db.clone();
    let mut original = paid();
    original.deadline_ms = *NOW - 1;
    original.paid_until_ms = Some(*NOW - 10_001);
    store.call_put(&peer(), CALL, &paid()).await.unwrap();
    let generation = calls::publish_media_attachment(&store, &peer(), CALL)
        .await
        .unwrap();
    store.call_put(&peer(), CALL, &original).await.unwrap();
    let stopped = detach(generation, true, false);
    calls::stop_media_attachment(store.as_ref(), &peer(), CALL, &stopped);
    sqlx::query("CREATE TRIGGER fail_intent BEFORE INSERT ON call_media_detach_intents BEGIN SELECT RAISE(ABORT, 'journal unavailable'); END")
        .execute(db.pool()).await.unwrap();
    assert!(
        calls::detach_callee_media(store.as_ref(), &peer(), CALL, *NOW, &stopped)
            .await
            .is_err()
    );
    sqlx::query("DROP TRIGGER fail_intent")
        .execute(db.pool())
        .await
        .unwrap();
    calls::replay_media_detaches(store.as_ref(), *NOW, false)
        .await
        .unwrap();
    assert_eq!(
        store.call_get(&peer(), CALL).await.unwrap().unwrap(),
        original,
        "admission loss alone cannot act as socket teardown"
    );
    calls::expire_calls(store.as_ref(), *NOW).await.unwrap();
    calls::replay_media_detaches(store.as_ref(), *NOW, false)
        .await
        .unwrap();
    assert_eq!(
        store
            .call_get(&peer(), CALL)
            .await
            .unwrap()
            .unwrap()
            .paid_until_ms,
        Some(0)
    );
}

#[tokio::test]
async fn startup_closes_overdue_resume_after_an_admission_only_detach() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let mut original = paid();
    original.deadline_ms = *NOW - 1;
    original.paid_until_ms = Some(*NOW - 10_001);
    store.call_put(&peer(), CALL, &original).await.unwrap();
    let generation = store.call_media_publish(&peer(), CALL).await.unwrap();
    store
        .call_media_record_detach(&intent(generation, true, false), false)
        .await
        .unwrap();
    calls::replay_media_detaches(&store, *NOW, true)
        .await
        .unwrap();
    let recovered = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(recovered.phase, Phase::Live);
    assert_eq!(
        recovered.paid_until_ms,
        Some(0),
        "no socket from the old process survives startup"
    );
    assert_eq!(recovered.next_block_seq, 1);
}

#[tokio::test]
async fn protected_live_detach_remains_pending_until_expiry_or_replacement() {
    let store = SqliteStorage::in_memory().await.unwrap();
    store.call_put(&peer(), CALL, &paid()).await.unwrap();
    let generation = store.call_media_publish(&peer(), CALL).await.unwrap();
    store
        .call_media_record_detach(&intent(generation, true, false), false)
        .await
        .unwrap();
    calls::replay_media_detaches(&store, *NOW, false)
        .await
        .unwrap();
    assert_eq!(
        store.call_get(&peer(), CALL).await.unwrap().unwrap(),
        paid()
    );
    assert_eq!(
        store.call_media_pending(0, 10).await.unwrap().len(),
        1,
        "a protected Live row still needs its resume window closed after ordinary expiry"
    );
    calls::expire_calls(&store, *NOW + 70_001).await.unwrap();
    calls::replay_media_detaches(&store, *NOW + 70_001, false)
        .await
        .unwrap();
    assert_eq!(
        store
            .call_get(&peer(), CALL)
            .await
            .unwrap()
            .unwrap()
            .paid_until_ms,
        Some(0)
    );
}

#[tokio::test]
async fn publication_and_projection_commit_together() {
    let db = SqliteStorage::in_memory().await.unwrap();
    sqlx::query("CREATE TRIGGER fail_head BEFORE INSERT ON call_media_heads BEGIN SELECT RAISE(ABORT, 'head unavailable'); END")
        .execute(db.pool()).await.unwrap();
    assert!(db.call_media_publish(&peer(), CALL).await.is_err());
    let history: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM call_media_detach_intents")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        history, 0,
        "failed publication must not leave an armed orphan record"
    );
    assert_eq!(db.call_media_generation(&peer(), CALL).await.unwrap(), None);
}

#[tokio::test]
async fn forward_migration_preserves_call_state_and_can_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("upgrade.sqlite");
    {
        let store = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
        store.call_put(&peer(), CALL, &paid()).await.unwrap();
        // Recreate the preceding schema without changing any older migration.
        sqlx::raw_sql("DROP TABLE call_media_heads; DROP TABLE call_media_detach_intents; DELETE FROM _sqlx_migrations WHERE version = 40;")
            .execute(store.pool()).await.unwrap();
    }
    for _ in 0..2 {
        let store = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
        assert_eq!(
            store.call_get(&peer(), CALL).await.unwrap().unwrap(),
            paid()
        );
        assert!(!store.call_media_has_pending(&peer(), CALL).await.unwrap());
        let version: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE version = 40")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(version, 1);
    }
}

#[tokio::test]
async fn expiry_atomically_closes_a_detached_resume_window() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mut original = paid();
    original.deadline_ms = now - 1;
    original.paid_until_ms = Some(now - 10_001);
    store.call_put(&peer(), CALL, &original).await.unwrap();
    let generation = store.call_media_publish(&peer(), CALL).await.unwrap();
    store
        .call_media_record_detach(&intent(generation, true, false), false)
        .await
        .unwrap();
    let hash = [12; 32];
    store
        .record_call_block_invoice(&peer(), CALL, 1, &hash, now + 60_000)
        .await
        .unwrap();
    calls::expire_calls(&store, now).await.unwrap();
    let expired = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(
        expired.paid_until_ms,
        Some(0),
        "expiry cannot expose a resumable row between replay passes"
    );
    let body = format!(r#"{{"call_id":"{CALL}","seq":1}}"#);
    let block = calls::prepare_incoming_block(&store, &peer(), Some(&body), &hash)
        .await
        .unwrap();
    assert!(
        block.refusal().is_some(),
        "a settled block immediately after expiry must not restore detached media"
    );
}

#[tokio::test]
async fn publication_uses_time_after_the_call_lock_wait() {
    let store: Arc<dyn Storage> = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mut original = paid();
    original.deadline_ms = now + 150;
    original.paid_until_ms = Some(now - 10_000 + 150);
    store.call_put(&peer(), CALL, &original).await.unwrap();
    let body = format!(r#"{{"call_id":"{CALL}","seq":1}}"#);
    let decision = calls::prepare_incoming_block(store.as_ref(), &peer(), Some(&body), &[9; 32])
        .await
        .unwrap();
    let publishing = {
        let store = store.clone();
        tokio::spawn(async move { calls::publish_media_attachment(&store, &peer(), CALL).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!publishing.is_finished());
    drop(decision);
    assert!(
        publishing.await.unwrap().is_err(),
        "expired coverage must be checked using the time after the wait"
    );
}

#[tokio::test]
async fn expiry_preserves_resume_while_the_current_socket_is_owned() {
    let store: Arc<dyn Storage> = Arc::new(SqliteStorage::in_memory().await.unwrap());
    store.call_put(&peer(), CALL, &paid()).await.unwrap();
    calls::publish_media_attachment(&store, &peer(), CALL)
        .await
        .unwrap();
    calls::expire_calls(store.as_ref(), *NOW + 70_001)
        .await
        .unwrap();
    let expired = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(expired.paid_until_ms, paid().paid_until_ms);
    assert!(rules::receive_block(Some(expired), 1, *NOW + 70_001).is_ok());
}

#[tokio::test]
async fn a_stopped_socket_refuses_resume_before_its_cleanup_write_commits() {
    let store: Arc<dyn Storage> = Arc::new(SqliteStorage::in_memory().await.unwrap());
    store.call_put(&peer(), CALL, &paid()).await.unwrap();
    let generation = calls::publish_media_attachment(&store, &peer(), CALL)
        .await
        .unwrap();
    let stopped = detach(generation, true, false);
    calls::stop_media_attachment(store.as_ref(), &peer(), CALL, &stopped);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mut expired = paid();
    expired.phase = Phase::Ended;
    expired.end_reason = Some(HangupReason::Unpaid);
    expired.deadline_ms = now - 1 + rules::TOMBSTONE_MS;
    expired.paid_until_ms = Some(now - 10_001);
    store.call_put(&peer(), CALL, &expired).await.unwrap();
    let hash = [13; 32];
    store
        .record_call_block_invoice(&peer(), CALL, 1, &hash, now + 60_000)
        .await
        .unwrap();
    let body = format!(r#"{{"call_id":"{CALL}","seq":1}}"#);
    let block = calls::prepare_incoming_block(store.as_ref(), &peer(), Some(&body), &hash)
        .await
        .unwrap();
    assert!(
        block.refusal().is_some(),
        "a recorded socket stop must win before a detached call can resume"
    );
}

#[tokio::test]
async fn publication_samples_time_after_its_final_storage_read() {
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let store: Arc<dyn Storage> = db.clone();
    let mut original = paid();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    original.deadline_ms = now + 60_000;
    original.paid_until_ms = Some(now + 50_000);
    store.call_put(&peer(), CALL, &original).await.unwrap();
    // Force a slow real read without replacing the storage implementation.
    sqlx::raw_sql("ALTER TABLE call_state RENAME TO delayed_call_state; CREATE VIEW call_state AS SELECT peer, call_id, side, phase, deadline_ms, pending_operation_id, pending_kind, pending_request_hash, paid_until_ms + (WITH RECURSIVE delay(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM delay WHERE x < 5000000) SELECT SUM(x)*0 FROM delay) AS paid_until_ms, next_block_seq, end_reason, unpaid_notice_used FROM delayed_call_state; CREATE TRIGGER shorten_after_publish AFTER INSERT ON call_media_heads BEGIN UPDATE delayed_call_state SET paid_until_ms = CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) - 9900, deadline_ms = CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) + 100; END;")
        .execute(db.pool()).await.unwrap();
    assert_eq!(
        store.call_get(&peer(), CALL).await.unwrap().unwrap(),
        original,
        "the delayed read must still decode the real stored call"
    );
    assert!(
        calls::publish_media_attachment(&store, &peer(), CALL)
            .await
            .is_err(),
        "coverage that expires during the final storage read cannot publish media"
    );
}

#[tokio::test]
async fn pending_media_stopped_live_refuses_renewal_until_replacement() {
    let store: Arc<dyn Storage> = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mut original = paid();
    original.paid_until_ms = Some(now + 5_000);
    original.deadline_ms = now + 15_000;
    assert!(
        rules::receive_block(Some(original.clone()), 1, now).is_ok(),
        "the fixture permits an ordinary renewal"
    );
    store.call_put(&peer(), CALL, &original).await.unwrap();
    let generation = calls::publish_media_attachment(&store, &peer(), CALL)
        .await
        .unwrap();
    let stopped = detach(generation, true, false);
    calls::stop_media_attachment(store.as_ref(), &peer(), CALL, &stopped);
    let hash = [14; 32];
    store
        .record_call_block_invoice(&peer(), CALL, 1, &hash, now + 60_000)
        .await
        .unwrap();
    let body = format!(r#"{{"call_id":"{CALL}","seq":1}}"#);
    let decision = calls::prepare_incoming_block(store.as_ref(), &peer(), Some(&body), &hash)
        .await
        .unwrap();
    assert!(
        decision.refusal().is_some(),
        "a stopped protected Live call must not renew indefinitely without media"
    );
    drop(decision);
    assert_eq!(
        store.call_get(&peer(), CALL).await.unwrap().unwrap(),
        original,
        "the existing paid Live row stays available for reconnection"
    );
    calls::publish_media_attachment(&store, &peer(), CALL)
        .await
        .unwrap();
    let recovered = calls::prepare_incoming_block(store.as_ref(), &peer(), Some(&body), &hash)
        .await
        .unwrap();
    assert!(
        recovered.refusal().is_none(),
        "a published replacement can renew the still-paid call"
    );
}

#[tokio::test]
async fn publication_read_failure_preserves_paid_live_during_maintenance() {
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let store: Arc<dyn Storage> = db.clone();
    let original = paid();
    store.call_put(&peer(), CALL, &original).await.unwrap();
    sqlx::query("CREATE TRIGGER publication_read_failure AFTER INSERT ON call_media_heads BEGIN UPDATE call_state SET side = 'unavailable'; END")
        .execute(db.pool()).await.unwrap();
    assert!(calls::publish_media_attachment(&store, &peer(), CALL)
        .await
        .is_err());
    assert!(store
        .call_media_generation(&peer(), CALL)
        .await
        .unwrap()
        .is_some());
    sqlx::query("DROP TRIGGER publication_read_failure")
        .execute(db.pool())
        .await
        .unwrap();
    store.call_put(&peer(), CALL, &original).await.unwrap();
    calls::expire_calls(store.as_ref(), *NOW).await.unwrap();
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap(), Some(original));
    assert!(store.call_media_has_pending(&peer(), CALL).await.unwrap());
}

#[tokio::test]
async fn reservation_recovery_preserves_a_fresh_attachment() {
    let store: Arc<dyn Storage> = Arc::new(SqliteStorage::in_memory().await.unwrap());
    calls::replay_media_detaches(store.as_ref(), *NOW, true)
        .await
        .unwrap();
    let original = CallEntry {
        pending: None,
        ..paid()
    };
    store.call_put(&peer(), CALL, &original).await.unwrap();
    calls::publish_media_attachment(&store, &peer(), CALL)
        .await
        .unwrap();
    calls::recover(store.as_ref()).await.unwrap();
    calls::expire_calls(store.as_ref(), *NOW).await.unwrap();
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap(), Some(original));
    assert!(calls::call_media_admitted(store.as_ref(), &peer(), CALL, *NOW).await);
}

#[derive(Clone, Default)]
struct ReplayLog(Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for ReplayLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ReplayLog {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

#[tokio::test]
async fn startup_replay_continues_after_individual_state_errors() {
    let db = SqliteStorage::in_memory().await.unwrap();
    for id in ["bad-state", "bad-write", CALL] {
        db.call_put(&peer(), id, &paid()).await.unwrap();
        db.call_media_publish(&peer(), id).await.unwrap();
    }
    sqlx::query("UPDATE call_state SET side = 'unavailable' WHERE call_id = 'bad-state'")
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER replay_write_failure BEFORE UPDATE ON call_state WHEN OLD.call_id = 'bad-write' BEGIN SELECT RAISE(ABORT, 'write unavailable'); END")
        .execute(db.pool()).await.unwrap();
    use tracing::instrument::WithSubscriber;
    let logs = ReplayLog::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .finish();
    calls::replay_media_detaches(&db, *NOW, true)
        .with_subscriber(subscriber)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&logs.0.lock().unwrap())
            .matches("call media detach replay failed")
            .count(),
        2
    );
    assert_eq!(
        db.call_get(&peer(), CALL).await.unwrap().unwrap().phase,
        Phase::Ended
    );
    assert!(db
        .call_media_has_pending(&peer(), "bad-state")
        .await
        .unwrap());
    assert!(db
        .call_media_has_pending(&peer(), "bad-write")
        .await
        .unwrap());
    sqlx::query("DROP TRIGGER replay_write_failure")
        .execute(db.pool())
        .await
        .unwrap();
    db.call_put(&peer(), "bad-state", &paid()).await.unwrap();
    calls::replay_media_detaches(&db, *NOW, true).await.unwrap();
    assert!(db.call_media_pending(0, 256).await.unwrap().is_empty());
}

#[tokio::test]
async fn startup_replay_skips_a_full_page_of_undecodable_heads() {
    let db = SqliteStorage::in_memory().await.unwrap();
    for index in 0..256 {
        db.call_media_publish(&peer(), &format!("bad-{index}"))
            .await
            .unwrap();
    }
    sqlx::query("UPDATE call_media_heads SET peer = 'unavailable'")
        .execute(db.pool())
        .await
        .unwrap();
    db.call_put(&peer(), CALL, &paid()).await.unwrap();
    db.call_media_publish(&peer(), CALL).await.unwrap();
    use tracing::instrument::WithSubscriber;
    let logs = ReplayLog::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .finish();
    calls::replay_media_detaches(&db, *NOW, true)
        .with_subscriber(subscriber)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&logs.0.lock().unwrap())
            .matches("call media pending row unavailable")
            .count(),
        256
    );
    assert_eq!(
        db.call_get(&peer(), CALL).await.unwrap().unwrap().phase,
        Phase::Ended
    );
    let retained: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM call_media_heads WHERE completed = 0")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(retained, 256);
}

#[tokio::test]
async fn startup_replay_requires_a_readable_pending_list() {
    let db = SqliteStorage::in_memory().await.unwrap();
    sqlx::query("DROP TABLE call_media_heads")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(calls::replay_media_detaches(&db, *NOW, true).await.is_err());
}

#[tokio::test]
async fn cancelled_publication_preserves_paid_live_during_maintenance() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(
        SqliteStorage::open(dir.path().join("publication.sqlite").to_str().unwrap())
            .await
            .unwrap(),
    );
    let store: Arc<dyn Storage> = db.clone();
    let original = paid();
    store.call_put(&peer(), CALL, &original).await.unwrap();
    sqlx::raw_sql("ALTER TABLE call_state RENAME TO saved_call_state; CREATE VIEW call_state AS SELECT peer, call_id, side, phase, deadline_ms, pending_operation_id, pending_kind, pending_request_hash, paid_until_ms + CASE WHEN EXISTS (SELECT 1 FROM call_media_heads) THEN (WITH RECURSIVE delay(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM delay WHERE x < 5000000) SELECT SUM(x)*0 FROM delay) ELSE 0 END AS paid_until_ms, next_block_seq, end_reason, unpaid_notice_used FROM saved_call_state;")
        .execute(db.pool()).await.unwrap();
    let publishing = store.clone();
    let task =
        tokio::spawn(
            async move { calls::publish_media_attachment(&publishing, &peer(), CALL).await },
        );
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while db
            .call_media_generation(&peer(), CALL)
            .await
            .unwrap()
            .is_none()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        !task.is_finished(),
        "the final state read remains in progress"
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    sqlx::raw_sql("DROP VIEW call_state; ALTER TABLE saved_call_state RENAME TO call_state;")
        .execute(db.pool())
        .await
        .unwrap();
    calls::expire_calls(store.as_ref(), *NOW).await.unwrap();
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap(), Some(original));
    assert!(store.call_media_has_pending(&peer(), CALL).await.unwrap());
}

#[tokio::test]
#[ignore = "requires BITSOV_TEST_POSTGRES_URL pointing to a disposable PostgreSQL server"]
async fn postgres_startup_replay_continues_after_individual_errors() {
    let url = std::env::var("BITSOV_TEST_POSTGRES_URL").unwrap();
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let name = format!("media_recovery_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let db_url = format!("{}/{name}", url.rsplit_once('/').unwrap().0);
    let db = konsensus_storage::PostgresStorage::connect(&db_url)
        .await
        .unwrap();
    for index in 0..256 {
        db.call_media_publish(&peer(), &format!("bad-{index}"))
            .await
            .unwrap();
    }
    sqlx::query("UPDATE call_media_heads SET peer = 'unavailable'")
        .execute(db.pool())
        .await
        .unwrap();
    for id in ["bad-state", "bad-write", CALL] {
        db.call_put(&peer(), id, &paid()).await.unwrap();
        db.call_media_publish(&peer(), id).await.unwrap();
    }
    sqlx::query("UPDATE call_state SET side = 'unavailable' WHERE call_id = 'bad-state'")
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION fail_recovery_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.call_id = 'bad-write' THEN RAISE EXCEPTION 'write unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER recovery_write_failure BEFORE UPDATE ON call_state FOR EACH ROW EXECUTE FUNCTION fail_recovery_write();")
        .execute(db.pool()).await.unwrap();
    calls::replay_media_detaches(&db, *NOW, true).await.unwrap();
    assert_eq!(
        db.call_get(&peer(), CALL).await.unwrap().unwrap().phase,
        Phase::Ended
    );
    assert!(db
        .call_media_has_pending(&peer(), "bad-state")
        .await
        .unwrap());
    assert!(db
        .call_media_has_pending(&peer(), "bad-write")
        .await
        .unwrap());
    sqlx::raw_sql(
        "DROP TRIGGER recovery_write_failure ON call_state; DROP FUNCTION fail_recovery_write();",
    )
    .execute(db.pool())
    .await
    .unwrap();
    db.call_put(&peer(), "bad-state", &paid()).await.unwrap();
    calls::replay_media_detaches(&db, *NOW, true).await.unwrap();
    assert!(db.call_media_pending(0, 256).await.unwrap().is_empty());
    sqlx::query("DROP TABLE call_media_heads")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(calls::replay_media_detaches(&db, *NOW, true).await.is_err());
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
