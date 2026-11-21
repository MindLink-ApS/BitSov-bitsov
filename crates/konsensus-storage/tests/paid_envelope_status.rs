use konsensus_core::{
    MessageId, NodeId, Nonce, PaymentProof, Recipient, Signature, UkmEnvelope, UkmEnvelopeBuilder,
};
use konsensus_storage::{EncryptedStorage, PaidAcceptance::*, SqliteStorage, Storage};
use sha2::{Digest, Sha256};

fn envelope(seed: u8) -> UkmEnvelope {
    // Receipt classification must work independently of ratchet readability.
    UkmEnvelopeBuilder::new(
        1,
        NodeId::from_bytes([1; 32]),
        Recipient::Node(NodeId::from_bytes([2; 32])),
        vec![seed; 16],
        PaymentProof::new(Sha256::digest([seed; 32]).into(), [seed; 32], 1_000),
    )
    .nonce(Nonce::from_bytes([seed; 24]))
    .signature(Signature::from_bytes([0; 64]))
    .build()
}

async fn counts(db: &SqliteStorage) -> (i64, i64, i64) {
    let receipts = sqlx::query_scalar("SELECT COUNT(*) FROM payment_receipts")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let nonces = sqlx::query_scalar("SELECT COUNT(*) FROM nonces")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let messages = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
        .fetch_one(db.pool())
        .await
        .unwrap();
    (receipts, nonces, messages)
}

#[tokio::test]
async fn paid_envelope_status_fresh_probe_preserves_replay_authority() {
    for encrypted in [false, true] {
        let wrapper = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
        let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
        let env = envelope(4);
        // Probing must stop before message insertion, including when insertion
        // would fail. A probe must neither hide that failure nor consume keys.
        sqlx::query("CREATE TRIGGER fail_new_message BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'message unavailable'); END")
            .execute(wrapper.inner().pool()).await.unwrap();
        for _ in 0..2 {
            assert_eq!(store.paid_envelope_status(&env).await.unwrap(), None);
            assert_eq!(counts(wrapper.inner()).await, (0, 0, 0));
        }
        assert!(store.accept_paid_envelope(&env).await.is_err());
        assert_eq!(counts(wrapper.inner()).await, (0, 0, 0));
        sqlx::query("DROP TRIGGER fail_new_message")
            .execute(wrapper.inner().pool())
            .await
            .unwrap();
        assert_eq!(store.accept_paid_envelope(&env).await.unwrap(), Accepted);
        assert_eq!(
            store.paid_envelope_status(&env).await.unwrap(),
            Some(AlreadyAccepted)
        );
        assert_eq!(counts(wrapper.inner()).await, (1, 1, 1));
        assert_eq!(store.get_message(&env.id).await.unwrap(), Some(env));
    }
}

#[tokio::test]
async fn paid_envelope_status_preserves_withdrawal_and_used_proof_classification() {
    for encrypted in [false, true] {
        let wrapper = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
        let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
        let env = envelope(4);
        assert_eq!(store.accept_paid_envelope(&env).await.unwrap(), Accepted);
        store.reject_accepted_envelope(&env).await.unwrap();
        assert_eq!(
            store.paid_envelope_status(&env).await.unwrap(),
            Some(Withdrawn)
        );
        let mut changed = env.clone();
        changed.ciphertext = b"a different unreadable envelope".to_vec();
        changed.id = MessageId::compute(&changed.ciphertext, &changed.nonce);
        assert_eq!(
            store.paid_envelope_status(&changed).await.unwrap(),
            Some(PaymentReused)
        );
        assert_eq!(counts(wrapper.inner()).await, (1, 1, 0));
        let accepted: i32 = sqlx::query_scalar("SELECT accepted FROM payment_receipts")
            .fetch_one(wrapper.inner().pool())
            .await
            .unwrap();
        assert_eq!(accepted, -1);
    }
}

#[tokio::test]
async fn paid_envelope_status_nonce_conflict_rolls_back_speculative_receipt() {
    for encrypted in [false, true] {
        let wrapper = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
        let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
        let env = envelope(4);
        store.store_nonce(&env.nonce, &env.sender).await.unwrap();
        assert_eq!(
            store.paid_envelope_status(&env).await.unwrap(),
            Some(NonceReused)
        );
        assert_eq!(counts(wrapper.inner()).await, (0, 1, 0));
    }
}

#[tokio::test]
async fn paid_envelope_status_classifies_held_acceptance_without_releasing_it() {
    for encrypted in [false, true] {
        let wrapper = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
        let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
        let env = envelope(4);
        assert!(store.call_admission_hold(&env, 1).await.unwrap());
        assert_eq!(store.accept_paid_envelope(&env).await.unwrap(), Accepted);
        assert!(!store.is_paid_envelope_accepted(&env).await.unwrap());
        assert_eq!(
            store.paid_envelope_status(&env).await.unwrap(),
            Some(AlreadyAccepted)
        );
        assert!(store.call_admission_held(&env.id).await.unwrap());
        assert!(store.get_message(&env.id).await.unwrap().is_none());
        assert_eq!(counts(wrapper.inner()).await, (1, 1, 1));
    }
}

#[tokio::test]
async fn paid_envelope_status_heals_legacy_metadata_without_replaying_message() {
    for encrypted in [false, true] {
        let wrapper = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
        let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
        let env = envelope(4);
        store
            .store_payment_receipt(&env.payment_proof.payment_hash, &env.sender, &env.id)
            .await
            .unwrap();
        store.store_message(&env).await.unwrap();
        store.store_nonce(&env.nonce, &env.sender).await.unwrap();
        assert_eq!(
            store.paid_envelope_status(&env).await.unwrap(),
            Some(AlreadyAccepted)
        );
        let metadata: (i32, Option<i64>, Option<String>, Option<String>) =
            sqlx::query_as("SELECT accepted, kind, nonce, references_json FROM payment_receipts")
                .fetch_one(wrapper.inner().pool())
                .await
                .unwrap();
        assert_eq!(
            metadata,
            (
                1,
                Some(1),
                Some(hex::encode(env.nonce.as_bytes())),
                Some("[]".into())
            )
        );
        assert_eq!(counts(wrapper.inner()).await, (1, 1, 1));
        assert_eq!(store.get_message(&env.id).await.unwrap(), Some(env.clone()));
        // The healed receipt survives content deletion and still classifies
        // without resurrecting the original ciphertext.
        store.delete_message(&env.id).await.unwrap();
        assert_eq!(
            store.paid_envelope_status(&env).await.unwrap(),
            Some(AlreadyAccepted)
        );
        assert_eq!(counts(wrapper.inner()).await, (1, 1, 0));
    }
}

#[tokio::test]
async fn paid_envelope_status_leaves_legacy_limbo_available_for_readable_retry() {
    for encrypted in [false, true] {
        for nonce_present in [false, true] {
            let wrapper =
                EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
            let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
            let env = envelope(4);
            store
                .store_payment_receipt(&env.payment_proof.payment_hash, &env.sender, &env.id)
                .await
                .unwrap();
            if nonce_present {
                store.store_nonce(&env.nonce, &env.sender).await.unwrap();
            }
            assert_eq!(store.paid_envelope_status(&env).await.unwrap(), None);
            assert_eq!(
                counts(wrapper.inner()).await,
                (1, i64::from(nonce_present), 0)
            );
            let metadata: (i32, Option<i64>) =
                sqlx::query_as("SELECT accepted, kind FROM payment_receipts")
                    .fetch_one(wrapper.inner().pool())
                    .await
                    .unwrap();
            assert_eq!(metadata, (0, None));
            assert_eq!(store.accept_paid_envelope(&env).await.unwrap(), Accepted);
            assert_eq!(
                store.paid_envelope_status(&env).await.unwrap(),
                Some(AlreadyAccepted)
            );
            assert_eq!(counts(wrapper.inner()).await, (1, 1, 1));
        }
    }
}

#[tokio::test]
async fn paid_envelope_status_preserves_exact_immutable_binding_checks() {
    for encrypted in [false, true] {
        let wrapper = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
        let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
        let env = envelope(4);
        assert_eq!(store.accept_paid_envelope(&env).await.unwrap(), Accepted);
        for mutation in 0..9 {
            let mut changed = env.clone();
            match mutation {
                0 => changed.id = MessageId::from_bytes([9; 32]),
                1 => changed.sender = NodeId::from_bytes([9; 32]),
                2 => changed.kind = 2,
                3 => changed.recipient = Recipient::Node(NodeId::from_bytes([9; 32])),
                4 => changed.payment_proof.preimage[0] ^= 1,
                5 => changed.payment_proof.amount_msat += 1,
                6 => changed.nonce = Nonce::from_bytes([9; 24]),
                7 => changed.references.push(MessageId::from_bytes([9; 32])),
                _ => changed.payment_proof.payment_hash[0] ^= 1,
            }
            let expected = if mutation == 8 {
                NonceReused
            } else {
                PaymentReused
            };
            assert_eq!(
                store.paid_envelope_status(&changed).await.unwrap(),
                Some(expected),
                "mutation={mutation}"
            );
            assert_eq!(counts(wrapper.inner()).await, (1, 1, 1));
            assert_eq!(store.get_message(&env.id).await.unwrap(), Some(env.clone()));
        }
    }
}

#[tokio::test]
async fn paid_envelope_status_faults_roll_back_receipt_and_metadata_changes() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let env = envelope(4);
    sqlx::query("CREATE TRIGGER fail_status_nonce BEFORE INSERT ON nonces BEGIN SELECT RAISE(ABORT, 'nonce unavailable'); END")
        .execute(db.pool()).await.unwrap();
    assert!(db.paid_envelope_status(&env).await.is_err());
    assert_eq!(counts(&db).await, (0, 0, 0));
    sqlx::query("DROP TRIGGER fail_status_nonce")
        .execute(db.pool())
        .await
        .unwrap();
    db.store_payment_receipt(&env.payment_proof.payment_hash, &env.sender, &env.id)
        .await
        .unwrap();
    db.store_message(&env).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_status_metadata BEFORE UPDATE ON payment_receipts BEGIN SELECT RAISE(ABORT, 'metadata unavailable'); END")
        .execute(db.pool()).await.unwrap();
    assert!(db.paid_envelope_status(&env).await.is_err());
    let metadata: (i32, Option<i64>) =
        sqlx::query_as("SELECT accepted, kind FROM payment_receipts")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(metadata, (0, None));
    assert_eq!(counts(&db).await, (1, 0, 1));
    sqlx::query("DROP TRIGGER fail_status_metadata")
        .execute(db.pool())
        .await
        .unwrap();
    assert_eq!(
        db.paid_envelope_status(&env).await.unwrap(),
        Some(AlreadyAccepted)
    );
    assert_eq!(counts(&db).await, (1, 0, 1));
}

#[tokio::test]
async fn paid_envelope_status_does_not_bypass_a_durable_deferral() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let env = envelope(4);
    assert!(db.defer_unreadable_envelope(&env).await.unwrap());
    assert!(db.paid_envelope_status(&env).await.is_err());
    assert!(db.is_envelope_deferred(&env).await.unwrap());
    assert_eq!(counts(&db).await, (0, 0, 0));
}
