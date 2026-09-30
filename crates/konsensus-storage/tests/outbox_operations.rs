use konsensus_storage::{OutboxOperation, SqliteStorage, Storage};

#[tokio::test]
async fn operation_insert_and_claim_survive_restart_and_serialize_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("outbox.db");
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    let mut op = OutboxOperation::prepared("op".into(), "peer".into(), 1, "digest".into());
    assert!(db.insert_outbox_operation(&op).await.unwrap());
    assert!(!db.insert_outbox_operation(&op).await.unwrap());
    op.state = "paying".into();
    let (a, b) = tokio::join!(
        db.update_outbox_operation(&op),
        db.update_outbox_operation(&op)
    );
    assert_ne!(a.unwrap(), b.unwrap());
    drop(db);
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    let loaded = db.get_outbox_operation("op").await.unwrap().unwrap();
    assert_eq!(loaded.state, "paying");
    assert_eq!(loaded.version, 1);
    assert_eq!(db.list_recoverable_operations().await.unwrap().len(), 1);
}

#[tokio::test]
async fn ack_is_atomic_with_pending_removal_and_cannot_be_overwritten() {
    use konsensus_core::{NodeIdentity, PaymentProof, Recipient, UkmEnvelopeBuilder};
    let db = SqliteStorage::in_memory().await.unwrap();
    let (_, sender) = NodeIdentity::generate().unwrap();
    let (_, peer) = NodeIdentity::generate().unwrap();
    let envelope = UkmEnvelopeBuilder::new(
        1,
        *sender.node_id(),
        Recipient::Node(*peer.node_id()),
        vec![1],
        PaymentProof::new([0; 32], [0; 32], 1000),
    )
    .build();
    db.store_message(&envelope).await.unwrap();
    let mut op =
        OutboxOperation::prepared("op".into(), peer.node_id().to_hex(), 1, "digest".into());
    op.state = "paid".into();
    op.message_id = Some(envelope.id.to_hex());
    db.insert_outbox_operation(&op).await.unwrap();
    db.prepare_delivery(&envelope.id, peer.node_id())
        .await
        .unwrap();
    let stale = db.get_outbox_operation("op").await.unwrap().unwrap();
    sqlx::raw_sql("CREATE TRIGGER fail_ack BEFORE UPDATE ON outbox_operations WHEN NEW.state = 'acked' BEGIN SELECT RAISE(ABORT, 'injected ack failure'); END").execute(db.pool()).await.unwrap();
    assert!(db
        .acknowledge_pending(&envelope.id, peer.node_id(), sender.node_id())
        .await
        .is_err());
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 1);
    sqlx::raw_sql("DROP TRIGGER fail_ack")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(!db
        .acknowledge_pending(&envelope.id, sender.node_id(), sender.node_id())
        .await
        .unwrap());
    assert!(db
        .acknowledge_pending(&envelope.id, peer.node_id(), sender.node_id())
        .await
        .unwrap());
    assert!(!db.update_outbox_operation(&stale).await.unwrap());
    assert_eq!(
        db.get_outbox_operation("op").await.unwrap().unwrap().state,
        "acked"
    );
}

#[tokio::test]
async fn encrypted_wrapper_protects_recovery_and_roundtrips() {
    use konsensus_storage::EncryptedStorage;
    let db = SqliteStorage::in_memory().await.unwrap();
    let pool = db.pool().clone();
    let encrypted = EncryptedStorage::new(db, &[7; 32]);
    let mut op = OutboxOperation::prepared("op".into(), "peer".into(), 1, "digest".into());
    op.recovery = b"encrypted envelope draft".to_vec();
    encrypted.insert_outbox_operation(&op).await.unwrap();
    let raw: Vec<u8> = sqlx::query_scalar("SELECT recovery FROM outbox_operations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(raw, op.recovery);
    assert_eq!(
        encrypted.get_outbox_operation("op").await.unwrap().unwrap(),
        op
    );
    op.state = "paying".into();
    assert!(encrypted.update_outbox_operation(&op).await.unwrap());
    assert_eq!(
        encrypted.list_recoverable_operations().await.unwrap()[0].recovery,
        op.recovery
    );
}

#[tokio::test]
async fn paid_commit_rolls_back_envelope_queue_and_operation_together() {
    use konsensus_core::{NodeIdentity, PaymentProof, Recipient, UkmEnvelopeBuilder};
    let db = SqliteStorage::in_memory().await.unwrap();
    let (_, sender) = NodeIdentity::generate().unwrap();
    let (_, peer) = NodeIdentity::generate().unwrap();
    let env = UkmEnvelopeBuilder::new(
        1,
        *sender.node_id(),
        Recipient::Node(*peer.node_id()),
        vec![1],
        PaymentProof::new([0; 32], [0; 32], 1000),
    )
    .build();
    let mut op =
        OutboxOperation::prepared("commit".into(), peer.node_id().to_hex(), 1, "digest".into());
    op.state = "paying".into();
    op.message_id = Some(env.id.to_hex());
    db.insert_outbox_operation(&op).await.unwrap();
    op.state = "paid".into();
    sqlx::raw_sql("CREATE TRIGGER fail_queue BEFORE INSERT ON pending_deliveries BEGIN SELECT RAISE(ABORT, 'injected queue failure'); END").execute(db.pool()).await.unwrap();
    assert!(db.commit_outbox_envelope(&op, &env).await.is_err());
    assert!(db.get_message(&env.id).await.unwrap().is_none());
    assert_eq!(
        db.get_outbox_operation("commit")
            .await
            .unwrap()
            .unwrap()
            .state,
        "paying"
    );
    sqlx::raw_sql("DROP TRIGGER fail_queue")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(db.commit_outbox_envelope(&op, &env).await.unwrap());
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 1);
    assert_eq!(
        db.get_outbox_operation("commit")
            .await
            .unwrap()
            .unwrap()
            .state,
        "paid"
    );
}

#[tokio::test]
async fn indexed_recovery_cost_does_not_grow_with_encrypted_terminal_history() {
    use konsensus_storage::EncryptedStorage;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let raw = SqliteStorage::in_memory().await.unwrap();
    let pool = raw.pool().clone();
    let db = EncryptedStorage::new(raw, &[7; 32]);
    let states = [
        "prepared",
        "released",
        "paying",
        "payment_unknown",
        "paid",
        "sent",
        "acked",
        "rejected_retryable",
        "failed_paid",
    ];
    for state in states {
        for pending in [false, true] {
            let mut op = OutboxOperation::prepared(
                format!("{state}-{pending}"),
                "peer".into(),
                1,
                "request".into(),
            );
            op.state = state.into();
            op.accounting_pending = pending;
            op.recovery = b"opaque recovery".to_vec();
            db.insert_outbox_operation(&op).await.unwrap();
        }
    }
    // Count actual SQLite VM steps on the production query, not elapsed wall
    // time. A full table scan or sort proportional to history fails this test.
    let steps = Arc::new(AtomicUsize::new(0));
    {
        let mut conn = pool.acquire().await.unwrap();
        let counter = steps.clone();
        conn.lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, move || {
                counter.fetch_add(1, Ordering::Relaxed);
                true
            });
    }
    steps.store(0, Ordering::Relaxed);
    let before = db.list_recoverable_operations().await.unwrap();
    let baseline = steps.load(Ordering::Relaxed);
    assert_eq!(before.len(), 14);
    for op in &before {
        assert!(
            op.accounting_pending
                || [
                    "paying",
                    "payment_unknown",
                    "paid",
                    "sent",
                    "rejected_retryable"
                ]
                .contains(&op.state.as_str())
        );
        assert_eq!(op.recovery, b"opaque recovery");
    }
    // Deliberately invalid encrypted bytes prove discarded history is never
    // decrypted by the wrapper. Terminal retention has its own bounded query.
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 20000) INSERT INTO outbox_operations (operation_id, recipient, kind, request_hash, state, settled_msat, readmission_msat, created_at, updated_at, attempts, version, recovery, accounting_pending, recovery_compacted) SELECT 'old-' || x, 'peer', 1, 'request', CASE WHEN x % 2 = 0 THEN 'acked' ELSE 'failed_paid' END, 0, 0, 0, 0, 0, 0, X'FF', FALSE, TRUE FROM n")
        .execute(&pool).await.unwrap();
    steps.store(0, Ordering::Relaxed);
    assert_eq!(db.list_recoverable_operations().await.unwrap(), before);
    let with_history = steps.load(Ordering::Relaxed);
    assert!(
        with_history <= baseline + 64,
        "recovery VM steps grew from {baseline} to {with_history}"
    );
    steps.store(0, Ordering::Relaxed);
    assert!(db
        .list_compactable_operations(1, 100)
        .await
        .unwrap()
        .is_empty());
    assert!(
        steps.load(Ordering::Relaxed) < 100,
        "retention must also use its partial index"
    );
}

#[tokio::test]
async fn migration_025_conservatively_backfills_opaque_accounting_and_preserves_checksums() {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    let dir = tempfile::tempdir().unwrap();
    let migrations = dir.path().join("migrations");
    std::fs::create_dir(&migrations).unwrap();
    for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_str().unwrap();
        if entry.path().is_file() && name < "025" {
            std::fs::copy(entry.path(), migrations.join(name)).unwrap();
        }
    }
    let path = dir.path().join("old.db");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    sqlx::migrate::Migrator::new(migrations.as_path())
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO outbox_operations (operation_id, recipient, kind, request_hash, state, settled_msat, readmission_msat, created_at, updated_at, attempts, version, recovery) VALUES ('old', 'peer', 1, 'digest', 'acked', 0, 0, 0, 0, 0, 0, X'FF')")
        .execute(&pool).await.unwrap();
    pool.close().await;
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    let mut old = db.get_outbox_operation("old").await.unwrap().unwrap();
    assert!(
        old.accounting_pending,
        "migration must not guess about opaque legacy debts"
    );
    assert_eq!(
        db.list_recoverable_operations().await.unwrap(),
        vec![old.clone()]
    );
    old.accounting_pending = false;
    db.update_outbox_operation(&old).await.unwrap();
    assert!(db.list_recoverable_operations().await.unwrap().is_empty());
    assert_eq!(
        db.list_compactable_operations(1, 100).await.unwrap().len(),
        1
    );
    db.pool().close().await;
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    assert!(
        !db.get_outbox_operation("old")
            .await
            .unwrap()
            .unwrap()
            .accounting_pending
    );
}

#[tokio::test]
async fn encrypted_retention_is_batched_and_never_selects_pending_liabilities() {
    use konsensus_storage::EncryptedStorage;
    let db = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
    for i in 0..106 {
        let mut op =
            OutboxOperation::prepared(format!("op-{i}"), "peer".into(), 1, "digest".into());
        op.state = "acked".into();
        op.updated_at = 0;
        op.accounting_pending = i == 105;
        op.recovery = b"old recovery evidence".to_vec();
        db.insert_outbox_operation(&op).await.unwrap();
    }
    let batch = db.list_compactable_operations(1, 100).await.unwrap();
    assert_eq!(batch.len(), 100);
    for mut op in batch {
        assert!(!op.accounting_pending);
        assert_eq!(op.recovery, b"old recovery evidence");
        let stale = op.clone();
        op.recovery = b"permanent receipt".to_vec();
        op.recovery_compacted = true;
        assert!(db.update_outbox_operation(&op).await.unwrap());
        assert!(!db.update_outbox_operation(&stale).await.unwrap());
    }
    assert_eq!(
        db.list_compactable_operations(1, 100).await.unwrap().len(),
        5
    );
    let pending = db.list_recoverable_operations().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].operation_id, "op-105");
    assert_eq!(pending[0].recovery, b"old recovery evidence");
}

#[tokio::test]
async fn failed_prepared_listing_selects_only_prepared_rows_with_an_error() {
    use konsensus_storage::EncryptedStorage;
    let encrypted = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
    for (id, state, error) in [
        ("stuck", "prepared", Some("admission journal: os error 2")),
        ("fresh", "prepared", None),
        ("released", "released", Some("disk gone")),
        ("unknown", "payment_unknown", Some("lost reply")),
    ] {
        let mut op = OutboxOperation::prepared(id.into(), "peer".into(), 1, "digest".into());
        op.state = state.into();
        op.last_error = error.map(Into::into);
        op.recovery = b"{\"dispatched\":false}".to_vec();
        assert!(encrypted.insert_outbox_operation(&op).await.unwrap());
    }
    let listed = encrypted.list_failed_prepared_operations().await.unwrap();
    assert_eq!(listed.iter().map(|op| op.operation_id.as_str()).collect::<Vec<_>>(), ["stuck"]);
    assert_eq!(listed[0].recovery, b"{\"dispatched\":false}", "recovery is decrypted");
}
