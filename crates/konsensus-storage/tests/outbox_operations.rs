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
