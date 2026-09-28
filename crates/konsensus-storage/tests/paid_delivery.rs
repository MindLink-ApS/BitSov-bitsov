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
async fn paid_duplicates_bind_immutable_metadata_after_content_deletion() {
    use konsensus_storage::PaidAcceptance::*;
    let db = SqliteStorage::in_memory().await.unwrap();
    let env = envelope();
    assert_eq!(db.accept_paid_envelope(&env).await.unwrap(), Accepted);
    let mut renewed = env.clone();
    renewed.timestamp += 360_000;
    renewed.signature = Signature::from_bytes([9; 64]);
    assert_eq!(db.accept_paid_envelope(&renewed).await.unwrap(), AlreadyAccepted);
    let peer = NodeId::from_bytes([2; 32]);
    db.prepare_delivery(&env.id, &peer).await.unwrap();
    assert!(!db.acknowledge_pending_payment(&env.id, &peer, &env.sender, &[8; 32]).await.unwrap());
    assert!(db.acknowledge_pending_payment(&env.id, &peer, &env.sender, &env.payment_proof.payment_hash).await.unwrap());
    db.delete_message(&env.id).await.unwrap();
    assert_eq!(db.accept_paid_envelope(&renewed).await.unwrap(), AlreadyAccepted);
    assert!(db.get_message(&env.id).await.unwrap().is_none());
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
    assert_eq!(db.accept_paid_envelope(&env).await.unwrap(), AlreadyAccepted,
        "an accepted receipt remains ACKable without resurrecting deleted content");
    assert!(db.get_message(&env.id).await.unwrap().is_none());
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
    let peer = NodeId::from_bytes([2; 32]);
    db.prepare_delivery(&env.id, &peer).await.unwrap();
    assert!(!db.acknowledge_pending_payment(&env.id, &peer, &env.sender, &[8; 32]).await.unwrap());
    assert!(db.acknowledge_pending_payment(&env.id, &peer, &env.sender, &env.payment_proof.payment_hash).await.unwrap());
    db.delete_message(&env.id).await.unwrap();
    assert_eq!(db.accept_paid_envelope(&renewed).await.unwrap(), AlreadyAccepted);
    assert!(db.get_message(&env.id).await.unwrap().is_none());
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

// Subprocess exit intentionally skips transaction/connection destructors.
#[tokio::test]
async fn crash_before_commit_worker() {
    let Ok(path) = std::env::var("BITSOV_TEST_CRASH_ACCEPT_DB") else { return; };
    let db = SqliteStorage::open(&path).await.unwrap();
    let env = envelope();
    let mut tx = db.pool().begin().await.unwrap();
    sqlx::query("INSERT INTO payment_receipts (payment_hash, message_id, sender) VALUES (?, ?, ?)")
        .bind(hex::encode(env.payment_proof.payment_hash)).bind(env.id.to_hex()).bind(env.sender.to_hex())
        .execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO nonces (nonce_hex, sender) VALUES (?, ?)")
        .bind(hex::encode(env.nonce.as_bytes())).bind(env.sender.to_hex()).execute(&mut *tx).await.unwrap();
    std::process::exit(91);
}

#[tokio::test]
async fn recipient_process_exit_before_commit_does_not_burn_keys() {
    let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("recipient.db");
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    db.pool().close().await;
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_before_commit_worker", "--nocapture"])
        .env("BITSOV_TEST_CRASH_ACCEPT_DB", &path).output().unwrap();
    assert_eq!(result.status.code(), Some(91), "{}", String::from_utf8_lossy(&result.stderr));
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    let env = envelope();
    assert!(!db.has_nonce(&env.nonce).await.unwrap());
    assert_eq!(db.accept_paid_envelope(&env).await.unwrap(), konsensus_storage::PaidAcceptance::Accepted);
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM payment_receipts").fetch_one(db.pool()).await.unwrap(), 1);
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM messages").fetch_one(db.pool()).await.unwrap(), 1);
}

#[tokio::test]
async fn legacy_limbo_heals_only_the_bound_sender_and_id_and_rolls_back_on_failure() {
    use konsensus_storage::PaidAcceptance::*;
    let db = SqliteStorage::in_memory().await.unwrap();
    let env = envelope();
    db.store_payment_receipt(&env.payment_proof.payment_hash, &env.sender, &env.id).await.unwrap();
    db.store_nonce(&env.nonce, &env.sender).await.unwrap();
    for change_sender in [true, false] {
        let mut other = env.clone();
        if change_sender { other.sender = NodeId::from_bytes([9; 32]); }
        else { other.id = konsensus_core::MessageId::from_bytes([9; 32]); }
        assert_eq!(db.accept_paid_envelope(&other).await.unwrap(), PaymentReused);
    }
    sqlx::query("CREATE TRIGGER fail_heal BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'heal failed'); END")
        .execute(db.pool()).await.unwrap();
    assert!(db.accept_paid_envelope(&env).await.is_err());
    assert!(db.has_nonce(&env.nonce).await.unwrap());
    sqlx::query("DROP TRIGGER fail_heal").execute(db.pool()).await.unwrap();
    let (a, b) = tokio::join!(db.accept_paid_envelope(&env), db.accept_paid_envelope(&env));
    assert!(matches!((a.unwrap(), b.unwrap()), (Accepted, AlreadyAccepted) | (AlreadyAccepted, Accepted)));
    assert_eq!(db.get_message(&env.id).await.unwrap().unwrap(), env);
}

#[tokio::test]
async fn migration_does_not_assume_offline_legacy_rows_were_dispatched() {
    let db = SqliteStorage::in_memory().await.unwrap();
    sqlx::query("CREATE TEMP TABLE pending_deliveries (message_id TEXT, recipient_id TEXT)")
        .execute(db.pool()).await.unwrap();
    sqlx::query("INSERT INTO pending_deliveries VALUES ('offline', 'peer')").execute(db.pool()).await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/020_pending_delivery_state.sql")).execute(db.pool()).await.unwrap();
    sqlx::query("CREATE TEMP TABLE payment_receipts (payment_hash TEXT, message_id TEXT, sender TEXT)").execute(db.pool()).await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/021_paid_delivery_rejections.sql")).execute(db.pool()).await.unwrap();
    let dispatched: i64 = sqlx::query_scalar("SELECT dispatched FROM pending_deliveries").fetch_one(db.pool()).await.unwrap();
    assert_eq!(dispatched, 0, "only a new dispatch can establish ACK authority");
}

#[tokio::test]
async fn retention_cannot_turn_an_accepted_receipt_into_legacy_limbo() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let env = envelope();
    assert_eq!(db.accept_paid_envelope(&env).await.unwrap(), konsensus_storage::PaidAcceptance::Accepted);
    db.delete_messages_older_than(10).await.unwrap();
    assert!(db.get_message(&env.id).await.unwrap().is_none());
    assert_eq!(db.accept_paid_envelope(&env).await.unwrap(), konsensus_storage::PaidAcceptance::AlreadyAccepted);
    assert!(db.get_message(&env.id).await.unwrap().is_none());
}

#[tokio::test]
async fn upgrade_from_original_slice_one_preserves_checksums_and_spent_receipts() {
    let dir = tempfile::tempdir().unwrap();
    let migrations = dir.path().join("migrations");
    std::fs::create_dir(&migrations).unwrap();
    for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_file() { continue; }
        let name = entry.file_name();
        if name.to_str().unwrap()[..3].parse::<u32>().unwrap() <= 20 {
            std::fs::copy(entry.path(), migrations.join(name)).unwrap();
        }
    }
    let path = dir.path().join("upgrade.db");
    let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(&path).create_if_missing(true)
    ).await.unwrap();
    sqlx::migrate::Migrator::new(migrations.as_path()).await.unwrap().run(&pool).await.unwrap();
    let env = envelope();
    // Build a real pre-021 accepted message plus an offline pending row.
    sqlx::query("INSERT INTO messages (id, kind, sender, recipient_type, recipient_id, timestamp_ms, ciphertext, payment_hash, preimage, amount_msat, signature, nonce, references_json) VALUES (?, 1, ?, 'node', ?, 1, ?, ?, ?, 1000, ?, ?, '[]')")
        .bind(env.id.to_hex()).bind(env.sender.to_hex()).bind(NodeId::from_bytes([2; 32]).to_hex())
        .bind(&env.ciphertext).bind(hex::encode(env.payment_proof.payment_hash)).bind(hex::encode(env.payment_proof.preimage))
        .bind(hex::encode(env.signature.as_bytes())).bind(hex::encode(env.nonce.as_bytes())).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO payment_receipts (payment_hash, message_id, sender) VALUES (?, ?, ?)")
        .bind(hex::encode(env.payment_proof.payment_hash)).bind(env.id.to_hex()).bind(env.sender.to_hex()).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO pending_deliveries (message_id, recipient_id, dispatched) VALUES (?, ?, 1)")
        .bind(env.id.to_hex()).bind(NodeId::from_bytes([2; 32]).to_hex()).execute(&pool).await.unwrap();
    pool.close().await;
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    assert!(!db.acknowledge_pending(&env.id, &NodeId::from_bytes([2; 32]), &env.sender).await.unwrap());
    db.delete_message(&env.id).await.unwrap();
    assert_eq!(db.accept_paid_envelope(&env).await.unwrap(), konsensus_storage::PaidAcceptance::AlreadyAccepted);
    assert!(db.get_message(&env.id).await.unwrap().is_none());
}

#[tokio::test]
async fn encrypted_terminal_rejection_survives_restart_and_housekeeping() {
    use konsensus_storage::EncryptedStorage;
    let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("sender.db");
    let env = envelope(); let peer = NodeId::from_bytes([2; 32]);
    {
        let db = EncryptedStorage::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap(), &[7; 32]);
        db.store_message(&env).await.unwrap();
        db.prepare_delivery(&env.id, &peer).await.unwrap();
        assert!(!db.reject_pending(&env.id, &env.sender, &env.sender, "invalid signature: forged peer", true).await.unwrap());
        assert!(!db.reject_pending(&env.id, &peer, &peer, "invalid signature: wrong owner", true).await.unwrap());
        assert!(db.reject_pending(&env.id, &peer, &env.sender, "invalid signature: rejected", true).await.unwrap());
    }
    let db = EncryptedStorage::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap(), &[7; 32]);
    db.cleanup_stale_pending(1).await.unwrap();
    db.delete_messages_older_than(10).await.unwrap();
    assert!(db.get_pending_for_peer(&peer).await.unwrap().is_empty());
    assert!(db.get_pending_peers().await.unwrap().is_empty());
    assert!(db.mark_pending_sent(&env.id, &peer).await.is_err());
    assert_eq!(db.get_message(&env.id).await.unwrap().unwrap(), env);
}

#[tokio::test]
async fn retained_receipt_matches_all_immutable_fields_after_content_deletion() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let env = envelope();
    db.accept_paid_envelope(&env).await.unwrap();
    db.delete_messages_older_than(10).await.unwrap();
    for variant in 0..8 {
        let mut other = env.clone();
        match variant {
            0 => other.id = konsensus_core::MessageId::from_bytes([9; 32]),
            1 => other.sender = NodeId::from_bytes([9; 32]),
            2 => other.kind += 1,
            3 => other.recipient = Recipient::Node(NodeId::from_bytes([9; 32])),
            4 => other.nonce = Nonce::from_bytes([9; 24]),
            5 => other.references.push(konsensus_core::MessageId::from_bytes([9; 32])),
            6 => other.payment_proof.amount_msat += 1,
            _ => other.payment_proof.preimage = [9; 32],
        }
        assert_eq!(db.accept_paid_envelope(&other).await.unwrap(), konsensus_storage::PaidAcceptance::PaymentReused, "variant {variant}");
    }
    let mut renewed = env.clone(); renewed.timestamp += 7 * 86400_000;
    renewed.signature = Signature::from_bytes([8; 64]);
    assert_eq!(db.accept_paid_envelope(&renewed).await.unwrap(), konsensus_storage::PaidAcceptance::AlreadyAccepted);
    assert!(db.get_message(&env.id).await.unwrap().is_none());
}
