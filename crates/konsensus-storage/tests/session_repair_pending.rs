use konsensus_core::{
    MessageId, NodeId, Nonce, PaymentProof, Recipient, Signature, UkmEnvelope, UkmEnvelopeBuilder,
};
use konsensus_storage::{
    EncryptedStorage, OutboxOperation, PaidAcceptance, SqliteStorage, Storage,
};
use sha2::{Digest, Sha256};

fn envelope(sender: NodeId, recipient: Recipient, amount: u64) -> UkmEnvelope {
    UkmEnvelopeBuilder::new(
        1,
        sender,
        recipient,
        b"unreadable ciphertext".to_vec(),
        PaymentProof::new(Sha256::digest([4; 32]).into(), [4; 32], amount),
    )
    .timestamp(1)
    .nonce(Nonce::from_bytes([5; 24]))
    .signature(Signature::from_bytes([0; 64]))
    .build()
}

async fn deferred_outgoing(store: &dyn Storage, own: NodeId, peer: NodeId) -> UkmEnvelope {
    let env = envelope(own, Recipient::Node(peer), 1_000);
    let mut op = OutboxOperation::prepared(
        "repair-operation".into(),
        peer.to_hex(),
        1,
        "request".into(),
    );
    op.state = "paid".into();
    op.payment_hash = Some(hex::encode(env.payment_proof.payment_hash));
    op.message_id = Some(env.id.to_hex());
    op.settled_msat = 1_000;
    assert!(store.insert_outbox_operation(&op).await.unwrap());
    assert!(store.commit_outbox_envelope(&op, &env).await.unwrap());
    assert!(
        !store.session_repair_pending(&own, &peer).await.unwrap(),
        "payment without a recipient deferral is insufficient"
    );
    store.mark_pending_sent(&env.id, &peer).await.unwrap();
    assert!(store
        .reject_pending(
            &env.id,
            &peer,
            &own,
            "session_handover: retry this operation",
            false
        )
        .await
        .unwrap());
    env
}

#[tokio::test]
async fn session_repair_pending_requires_an_unconsumed_positive_direct_deferral() {
    let own = NodeId::from_bytes([2; 32]);
    let peer = NodeId::from_bytes([1; 32]);
    for encrypted in [false, true] {
        let wrapper = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
        let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
        assert!(!store.session_repair_pending(&own, &peer).await.unwrap());
        let env = envelope(peer, Recipient::Node(own), 1_000);
        assert!(store.defer_unreadable_envelope(&env).await.unwrap());
        assert!(store.session_repair_pending(&own, &peer).await.unwrap());
        assert!(!store.session_repair_pending(&peer, &own).await.unwrap());
        assert!(!store
            .session_repair_pending(&own, &NodeId::from_bytes([9; 32]))
            .await
            .unwrap());
        assert!(!store.has_nonce(&env.nonce).await.unwrap());
        // Any durable receipt consumes this proof; a retained deferral alone
        // must not keep authorizing reconnection after that point.
        store
            .store_payment_receipt(&env.payment_proof.payment_hash, &env.sender, &env.id)
            .await
            .unwrap();
        assert!(!store.session_repair_pending(&own, &peer).await.unwrap());
    }
}

#[tokio::test]
async fn session_repair_pending_excludes_zero_price_and_other_destinations() {
    let own = NodeId::from_bytes([2; 32]);
    let peer = NodeId::from_bytes([1; 32]);
    for encrypted in [false, true] {
        for (sender, recipient, amount) in [
            (peer, Recipient::Node(own), 0),
            (peer, Recipient::Broadcast, 1_000),
            (peer, Recipient::Node(NodeId::from_bytes([9; 32])), 1_000),
            (NodeId::from_bytes([9; 32]), Recipient::Node(own), 1_000),
        ] {
            let wrapper =
                EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
            let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
            let env = envelope(sender, recipient, amount);
            assert!(store.defer_unreadable_envelope(&env).await.unwrap());
            assert!(!store.session_repair_pending(&own, &peer).await.unwrap());
        }
    }
}

#[tokio::test]
async fn session_repair_pending_conflicting_deferral_terms_cannot_widen_authority() {
    let own = NodeId::from_bytes([2; 32]);
    let peer = NodeId::from_bytes([1; 32]);
    for encrypted in [false, true] {
        for (recipient, amount) in [(Recipient::Broadcast, 1_000), (Recipient::Node(own), 0)] {
            let wrapper =
                EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
            let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
            let original = envelope(peer, recipient, amount);
            assert!(store.defer_unreadable_envelope(&original).await.unwrap());
            let mut changed = original.clone();
            changed.recipient = Recipient::Node(own);
            changed.payment_proof.amount_msat = 1_000;
            // ID covers ciphertext and nonce, not these signed terms.
            assert_eq!(changed.id, original.id);
            assert!(!store.defer_unreadable_envelope(&changed).await.unwrap());
            assert!(!store.is_envelope_deferred(&changed).await.unwrap());
            assert!(store.is_envelope_deferred(&original).await.unwrap());
            assert!(!store.session_repair_pending(&own, &peer).await.unwrap());
        }
    }
}

#[tokio::test]
async fn session_repair_pending_clears_after_replacement_acceptance() {
    let own = NodeId::from_bytes([2; 32]);
    let peer = NodeId::from_bytes([1; 32]);
    let store = SqliteStorage::in_memory().await.unwrap();
    let old = envelope(peer, Recipient::Node(own), 1_000);
    assert!(store.defer_unreadable_envelope(&old).await.unwrap());
    assert!(store.session_repair_pending(&own, &peer).await.unwrap());
    let mut replacement = old.clone();
    replacement.ciphertext = b"replacement ciphertext".to_vec();
    replacement.id = MessageId::compute(&replacement.ciphertext, &replacement.nonce);
    assert_eq!(
        store.accept_paid_envelope(&replacement).await.unwrap(),
        PaidAcceptance::Accepted
    );
    assert!(!store.session_repair_pending(&own, &peer).await.unwrap());
}

#[tokio::test]
async fn session_repair_pending_requires_a_bound_active_outgoing_operation() {
    let own = NodeId::from_bytes([1; 32]);
    let peer = NodeId::from_bytes([2; 32]);
    for encrypted in [false, true] {
        let wrapper = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
        let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
        let env = deferred_outgoing(store, own, peer).await;
        for state in ["paid", "sent", "rejected_retryable"] {
            sqlx::query("UPDATE outbox_operations SET state = ?")
                .bind(state)
                .execute(wrapper.inner().pool())
                .await
                .unwrap();
            assert!(
                store.session_repair_pending(&own, &peer).await.unwrap(),
                "{state}"
            );
        }
        assert!(!store.session_repair_pending(&peer, &own).await.unwrap());
        assert!(!store
            .session_repair_pending(&own, &NodeId::from_bytes([9; 32]))
            .await
            .unwrap());
        // Housekeeping marks repeated deliveries stalled without withdrawing
        // their paid obligation or their right to retry on this connection.
        for _ in 0..10 {
            store
                .increment_pending_attempts(&env.id, &peer)
                .await
                .unwrap();
        }
        assert_eq!(store.cleanup_stale_pending(10).await.unwrap(), 1);
        let pending_state: String = sqlx::query_scalar("SELECT state FROM pending_deliveries")
            .fetch_one(wrapper.inner().pool())
            .await
            .unwrap();
        assert_eq!(pending_state, "stalled");
        assert!(store.session_repair_pending(&own, &peer).await.unwrap());
        assert!(store
            .acknowledge_pending(&env.id, &peer, &own)
            .await
            .unwrap());
        assert!(!store.session_repair_pending(&own, &peer).await.unwrap());
    }
}

#[tokio::test]
async fn session_repair_pending_outgoing_binding_mutations_fail_closed() {
    let own = NodeId::from_bytes([1; 32]);
    let peer = NodeId::from_bytes([2; 32]);
    for encrypted in [false, true] {
        for mutation in 0..20 {
            let wrapper =
                EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
            let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
            deferred_outgoing(store, own, peer).await;
            assert!(store.session_repair_pending(&own, &peer).await.unwrap());
            let statement = match mutation {
                0 => "UPDATE outbox_operations SET recipient = 'other'",
                1 => "UPDATE outbox_operations SET payment_hash = 'other'",
                2 => "UPDATE outbox_operations SET settled_msat = 0",
                3 => "UPDATE outbox_operations SET settled_msat = 1001",
                4 => "UPDATE outbox_operations SET kind = 2",
                5 => "UPDATE outbox_operations SET state = 'failed_paid'",
                6 => "UPDATE outbox_operations SET last_error = 'undecryptable: old peer'",
                7 => "UPDATE outbox_operations SET last_error = 'sessionXhandover: unrelated'",
                8 => "UPDATE messages SET sender = 'other'",
                9 => "UPDATE messages SET recipient_type = 'broadcast'",
                10 => "UPDATE messages SET recipient_id = 'other'",
                11 => "UPDATE messages SET amount_msat = 0",
                12 => "UPDATE messages SET payment_hash = 'other'",
                13 => "UPDATE pending_deliveries SET recipient_id = 'other'",
                14 => "UPDATE pending_deliveries SET state = 'failed_paid'",
                15 => "UPDATE pending_deliveries SET dispatched = 0",
                16 => "UPDATE pending_deliveries SET rejection_reason = 'session_handover: other operation'",
                17 => "DELETE FROM pending_deliveries",
                18 => "UPDATE pending_deliveries SET state = 'unknown'",
                _ => "UPDATE messages SET amount_msat = 0",
            };
            sqlx::query(statement)
                .execute(wrapper.inner().pool())
                .await
                .unwrap();
            if matches!(mutation, 6 | 7) {
                sqlx::query("UPDATE pending_deliveries SET rejection_reason = (SELECT last_error FROM outbox_operations)")
                    .execute(wrapper.inner().pool()).await.unwrap();
            }
            if mutation == 19 {
                sqlx::query("UPDATE outbox_operations SET settled_msat = 0")
                    .execute(wrapper.inner().pool()).await.unwrap();
            }
            assert!(
                !store.session_repair_pending(&own, &peer).await.unwrap(),
                "mutation={mutation}"
            );
        }
    }
}
