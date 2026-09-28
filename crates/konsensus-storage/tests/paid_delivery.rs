use konsensus_core::{NodeId, Nonce, PaymentProof, Recipient, Signature, UkmEnvelope, UkmEnvelopeBuilder};
use konsensus_storage::{SqliteStorage, Storage};
use sha2::{Digest, Sha256};

fn envelope() -> UkmEnvelope {
    UkmEnvelopeBuilder::new(1, NodeId::from_bytes([1; 32]),
        Recipient::Node(NodeId::from_bytes([2; 32])), vec![3; 16],
        PaymentProof::new(Sha256::digest([4; 32]).into(), [4; 32], 1000))
        .timestamp(1).nonce(Nonce::from_bytes([5; 24]))
        .signature(Signature::from_bytes([0; 64])).build()
}

#[tokio::test]
async fn stale_paid_delivery_survives_cleanup_and_retention() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let env = envelope();
    let peer = NodeId::from_bytes([2; 32]);
    db.store_message(&env).await.unwrap();
    db.queue_pending_delivery(&env.id, &peer).await.unwrap();
    for _ in 0..11 { db.increment_pending_attempts(&env.id, &peer).await.unwrap(); }
    db.cleanup_stale_pending(10).await.unwrap();
    db.delete_messages_older_than(10).await.unwrap();
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 1);
    assert!(db.get_message(&env.id).await.unwrap().is_some());
}

#[tokio::test]
async fn acceptance_rolls_back_both_keys_if_message_insert_fails() {
    use konsensus_storage::PaidAcceptance;
    for failure in ["ABORT", "ROLLBACK"] {
        let db = SqliteStorage::in_memory().await.unwrap();
        let env = envelope();
        sqlx::query(&format!("CREATE TRIGGER fail_message BEFORE INSERT ON messages BEGIN SELECT RAISE({failure}, 'injected storage failure'); END"))
            .execute(db.pool()).await.unwrap();
        assert!(db.accept_paid_envelope(&env).await.is_err());
        assert!(!db.has_nonce(&env.nonce).await.unwrap());
        let receipts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_receipts").fetch_one(db.pool()).await.unwrap();
        assert_eq!(receipts, 0, "{failure} must not burn the payment");
        sqlx::query("DROP TRIGGER fail_message").execute(db.pool()).await.unwrap();
        assert_eq!(db.accept_paid_envelope(&env).await.unwrap(), PaidAcceptance::Accepted);
        assert_eq!(db.accept_paid_envelope(&env).await.unwrap(), PaidAcceptance::AlreadyAccepted);
        let messages: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages").fetch_one(db.pool()).await.unwrap();
        assert_eq!(messages, 1);
    }
}

#[tokio::test]
async fn paid_duplicates_bind_immutable_metadata_and_require_durable_message() {
    use konsensus_storage::PaidAcceptance::*;
    let db = SqliteStorage::in_memory().await.unwrap();
    let env = envelope();
    assert_eq!(db.accept_paid_envelope(&env).await.unwrap(), Accepted);
    let mut renewed = env.clone();
    renewed.timestamp += 360_000;
    renewed.signature = Signature::from_bytes([9; 64]);
    assert_eq!(db.accept_paid_envelope(&renewed).await.unwrap(), AlreadyAccepted);
    for variant in 0..5 {
        let mut changed = env.clone();
        match variant {
            0 => changed.id = konsensus_core::MessageId::from_bytes([9; 32]),
            1 => changed.kind += 1,
            2 => changed.sender = NodeId::from_bytes([9; 32]),
            3 => changed.recipient = Recipient::Node(NodeId::from_bytes([9; 32])),
            _ => changed.references.push(konsensus_core::MessageId::from_bytes([9; 32])),
        }
        assert_eq!(db.accept_paid_envelope(&changed).await.unwrap(), PaymentReused);
    }
    db.delete_message(&env.id).await.unwrap();
    assert_eq!(db.accept_paid_envelope(&env).await.unwrap(), PaymentReused,
        "a legacy burned receipt alone must not produce a false duplicate ACK");
}

#[tokio::test]
async fn concurrent_acceptance_has_one_commit_and_one_duplicate() {
    use konsensus_storage::PaidAcceptance::*;
    let db = SqliteStorage::in_memory().await.unwrap();
    let env = envelope();
    let (a, b) = tokio::join!(db.accept_paid_envelope(&env), db.accept_paid_envelope(&env));
    assert!(matches!((a.unwrap(), b.unwrap()), (Accepted, AlreadyAccepted) | (AlreadyAccepted, Accepted)));
}

#[tokio::test]
async fn nonce_conflict_rolls_back_new_payment_receipt() {
    use konsensus_storage::PaidAcceptance::*;
    let db = SqliteStorage::in_memory().await.unwrap();
    let env = envelope();
    db.store_nonce(&env.nonce, &env.sender).await.unwrap();
    assert_eq!(db.accept_paid_envelope(&env).await.unwrap(), NonceReused);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_receipts").fetch_one(db.pool()).await.unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn encrypted_storage_acceptance_and_rewrap_preserve_ciphertext() {
    use konsensus_storage::{EncryptedStorage, PaidAcceptance::*};
    let db = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
    let env = envelope();
    assert_eq!(db.accept_paid_envelope(&env).await.unwrap(), Accepted);
    assert_eq!(db.accept_paid_envelope(&env).await.unwrap(), AlreadyAccepted);
    let mut renewed = env.clone(); renewed.timestamp += 360_000;
    renewed.signature = Signature::from_bytes([9; 64]);
    db.update_message_wrapper(&renewed).await.unwrap();
    assert_eq!(db.get_message(&env.id).await.unwrap().unwrap(), renewed);
    assert_eq!(db.accept_paid_envelope(&renewed).await.unwrap(), AlreadyAccepted);
}

#[tokio::test]
async fn ack_requires_dispatched_outbox_peer_and_own_identity_and_is_consumed_once() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let env = envelope(); let peer = NodeId::from_bytes([2; 32]);
    db.store_message(&env).await.unwrap();
    db.queue_pending_delivery(&env.id, &peer).await.unwrap();
    assert!(!db.acknowledge_pending(&env.id, &peer, &env.sender).await.unwrap());
    db.mark_pending_sent(&env.id, &peer).await.unwrap();
    assert!(!db.acknowledge_pending(&env.id, &env.sender, &env.sender).await.unwrap());
    assert!(!db.acknowledge_pending(&env.id, &peer, &peer).await.unwrap());
    assert!(db.acknowledge_pending(&env.id, &peer, &env.sender).await.unwrap());
    assert!(!db.acknowledge_pending(&env.id, &peer, &env.sender).await.unwrap());
}
