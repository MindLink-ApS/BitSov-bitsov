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


#[tokio::test]
async fn deferral_limits_fifty_envelopes_per_proof_and_sender() {
    let own = NodeId::from_bytes([2; 32]);
    let peer = NodeId::from_bytes([1; 32]);
    for encrypted in [false, true] {
        let wrapper = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
        let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
        let original = envelope(peer, Recipient::Node(own), 1_000);
        for n in 0..50 {
            let mut env = original.clone();
            env.ciphertext = vec![n];
            env.id = MessageId::compute(&env.ciphertext, &env.nonce);
            let admitted = store.defer_unreadable_envelope(&env).await.unwrap();
            assert_eq!(admitted, n < 3, "proof slot {n}");
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM envelope_deferrals")
            .fetch_one(wrapper.inner().pool()).await.unwrap();
        assert_eq!(count, 3);
        // More proofs from this sender share a separate bound.
        for n in 1..50 {
            let mut env = original.clone();
            env.ciphertext = vec![n];
            env.id = MessageId::compute(&env.ciphertext, &env.nonce);
            env.payment_proof = PaymentProof::new(Sha256::digest([n; 32]).into(), [n; 32], 1_000);
            let _ = store.defer_unreadable_envelope(&env).await.unwrap();
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM envelope_deferrals")
            .fetch_one(wrapper.inner().pool()).await.unwrap();
        assert_eq!(count, 12);
        assert!(store.session_repair_pending(&own, &peer).await.unwrap());
    }
}

#[tokio::test]
async fn deferral_expiry_ends_standing_without_cleanup_or_retry_extension() {
    let own = NodeId::from_bytes([2; 32]);
    let peer = NodeId::from_bytes([1; 32]);
    for encrypted in [false, true] {
        let wrapper = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
        let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
        let env = envelope(peer, Recipient::Node(own), 1_000);
        assert!(store.defer_unreadable_envelope(&env).await.unwrap());
        sqlx::query("UPDATE envelope_deferrals SET expires_at_ms = 1")
            .execute(wrapper.inner().pool()).await.unwrap();
        assert!(!store.session_repair_pending(&own, &peer).await.unwrap());
        assert!(!store.is_envelope_deferred(&env).await.unwrap());
    }
}

#[tokio::test]
async fn deferral_deadline_is_bounded_by_freshness_and_exact_retries_keep_it() {
    let wrapper = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
    let store: &dyn Storage = &wrapper;
    let own = NodeId::from_bytes([2; 32]);
    let peer = NodeId::from_bytes([1; 32]);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let mut env = envelope(peer, Recipient::Node(own), 1_000);
    env.timestamp = (now - 290_000) as u64;
    assert!(store.defer_unreadable_envelope(&env).await.unwrap());
    let first = store.session_repair_expires_at(&own, &peer).await.unwrap().unwrap();
    assert_eq!(first, now + 10_000);
    // Renewing the signed wrapper of an existing ID cannot renew its deadline.
    env.timestamp = (now + 300_000) as u64;
    assert!(store.defer_unreadable_envelope(&env).await.unwrap());
    assert_eq!(store.session_repair_expires_at(&own, &peer).await.unwrap(), Some(first));
    let mut future = env.clone();
    future.ciphertext = b"future wrapper".to_vec();
    future.id = MessageId::compute(&future.ciphertext, &future.nonce);
    future.timestamp = u64::MAX;
    assert!(store.defer_unreadable_envelope(&future).await.unwrap());
    let deadline = store.session_repair_expires_at(&own, &peer).await.unwrap().unwrap();
    let after = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    assert!(deadline <= after + 300_000);
    let mut stale = env.clone();
    stale.timestamp = (now - 300_001) as u64;
    stale.ciphertext = b"stale wrapper".to_vec();
    stale.id = MessageId::compute(&stale.ciphertext, &stale.nonce);
    assert!(!store.defer_unreadable_envelope(&stale).await.unwrap());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM envelope_deferrals")
        .fetch_one(wrapper.inner().pool()).await.unwrap();
    assert_eq!(count, 2, "stale input cannot allocate a deferral row");
}

#[tokio::test]
async fn deferral_cleanup_is_bounded_preserves_live_rows_and_releases_slots() {
    for encrypted in [false, true] {
        let wrapper = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
        let store: &dyn Storage = if encrypted { &wrapper } else { wrapper.inner() };
        let own = NodeId::from_bytes([2; 32]);
        let peer = NodeId::from_bytes([1; 32]);
        let original = envelope(peer, Recipient::Node(own), 1_000);
        for n in 0..3 {
            let mut env = original.clone();
            env.ciphertext = vec![n];
            env.id = MessageId::compute(&env.ciphertext, &env.nonce);
            assert!(store.defer_unreadable_envelope(&env).await.unwrap());
        }
        sqlx::query("UPDATE envelope_deferrals SET expires_at_ms = 1")
            .execute(wrapper.inner().pool()).await.unwrap();
        assert_eq!(store.cleanup_expired_deferrals(1, 0).await.unwrap(), 0);
        assert_eq!(store.cleanup_expired_deferrals(1, 2).await.unwrap(), 2);
        // The last expired slot is reclaimed by the insertion path.
        assert!(store.defer_unreadable_envelope(&original).await.unwrap());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM envelope_deferrals")
            .fetch_one(wrapper.inner().pool()).await.unwrap();
        assert_eq!(count, 1);
        assert_eq!(store.cleanup_expired_deferrals(1, u32::MAX).await.unwrap(), 0);
        assert!(store.is_envelope_deferred(&original).await.unwrap());
    }
}

#[tokio::test]
async fn deferral_caps_hold_for_concurrent_writers() {
    for same_proof in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let path = format!("sqlite:{}", dir.path().join("deferrals.db").display());
        let store = std::sync::Arc::new(SqliteStorage::open(&path).await.unwrap());
        let mut tasks = tokio::task::JoinSet::new();
        for n in 0..50 {
            let store = store.clone();
            tasks.spawn(async move {
                let mut env = envelope(NodeId::from_bytes([1; 32]), Recipient::Node(NodeId::from_bytes([2; 32])), 1_000);
                env.ciphertext = vec![n];
                env.id = MessageId::compute(&env.ciphertext, &env.nonce);
                if !same_proof {
                    env.payment_proof = PaymentProof::new(Sha256::digest([n; 32]).into(), [n; 32], 1_000);
                }
                store.defer_unreadable_envelope(&env).await.unwrap()
            });
        }
        let mut admitted = 0;
        while let Some(result) = tasks.join_next().await { admitted += i64::from(result.unwrap()); }
        assert_eq!(admitted, if same_proof { 3 } else { 12 });
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM envelope_deferrals")
            .fetch_one(store.pool()).await.unwrap();
        assert_eq!(count, admitted);
    }
}

#[tokio::test]
async fn deferral_expired_fence_does_not_block_readable_acceptance() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let env = envelope(NodeId::from_bytes([1; 32]), Recipient::Node(NodeId::from_bytes([2; 32])), 1_000);
    assert!(store.defer_unreadable_envelope(&env).await.unwrap());
    sqlx::query("UPDATE envelope_deferrals SET expires_at_ms = 0").execute(store.pool()).await.unwrap();
    assert!(matches!(store.paid_envelope_status(&env).await, Ok(None)), "expired fence must not block status lookup");
    assert_eq!(store.accept_paid_envelope(&env).await.unwrap(), PaidAcceptance::Accepted);
}

#[tokio::test]
async fn deferral_cleanup_clamps_a_large_requested_batch() {
    let store = SqliteStorage::in_memory().await.unwrap();
    sqlx::query("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 513) INSERT INTO envelope_deferrals (message_id, sender, payment_hash, recipient_type, recipient_id, amount_msat) SELECT CAST(i AS TEXT), 'sender', 'proof', 'node', 'recipient', 1 FROM n")
        .execute(store.pool()).await.unwrap();
    assert_eq!(store.cleanup_expired_deferrals(0, u32::MAX).await.unwrap(), 256);
    assert_eq!(store.cleanup_expired_deferrals(0, u32::MAX).await.unwrap(), 256);
    assert_eq!(store.cleanup_expired_deferrals(0, u32::MAX).await.unwrap(), 1);
}

#[tokio::test]
async fn deferral_expired_backlog_does_not_take_active_slots() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let own = NodeId::from_bytes([2; 32]);
    let peer = NodeId::from_bytes([1; 32]);
    let env = envelope(peer, Recipient::Node(own), 1_000);
    sqlx::query("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 513) INSERT INTO envelope_deferrals (message_id, sender, payment_hash, recipient_type, recipient_id, amount_msat) SELECT CAST(i AS TEXT), ?1, ?2, 'node', ?3, 1000 FROM n")
        .bind(peer.to_hex()).bind(hex::encode(env.payment_proof.payment_hash)).bind(own.to_hex())
        .execute(store.pool()).await.unwrap();
    assert!(store.defer_unreadable_envelope(&env).await.unwrap());
    assert!(store.session_repair_pending(&own, &peer).await.unwrap());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM envelope_deferrals")
        .fetch_one(store.pool()).await.unwrap();
    assert_eq!(count, 258, "one insertion reclaims at most 256 expired rows");
}
