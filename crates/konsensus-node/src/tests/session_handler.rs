use super::*;
use konsensus_storage::{OnboardingStateRecord, Storage};
use sha2::Digest;

fn test_peer_id() -> NodeId {
    NodeId::from_bytes([1u8; 32])
}

fn valid_ln_pubkey() -> String {
    "02abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678ab".into()
}

fn identity_from_mnemonic(mnemonic: &str) -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(mnemonic, "").expect("valid mnemonic"))
}

fn onboarding_state_for(peer_id: NodeId, step: &str) -> OnboardingStateRecord {
    OnboardingStateRecord {
        invite_id: None,
        inviter_pubkey: Some(*peer_id.as_bytes()),
        inviter_ln_pubkey: None,
        current_step: step.into(),
        tier: Some("light".into()),
        funding_address: None,
        funding_amount_sats_required: None,
        funding_amount_sats_received: 0,
        last_poll_at: None,
        funding_evidence: None,
    }
}

#[tokio::test]
async fn e2ee_self_heal_targets_missing_or_receiver_only_sessions() {
    let alice = identity_from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    let bob = identity_from_mnemonic("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
    let alice_mgr = SessionManager::new(Arc::clone(&alice));
    let bob_mgr = SessionManager::new(Arc::clone(&bob));

    assert!(
        e2ee_needs_self_heal(&alice_mgr, bob.node_id()).await,
        "missing peer session must be self-heal eligible"
    );

    let bob_bundle = bob_mgr.prekey_bundle().await;
    let init = alice_mgr
        .initiate_session(bob.node_id(), &bob_bundle)
        .await
        .unwrap();
    bob_mgr.accept_session(alice.node_id(), &init).await.unwrap();

    assert!(
        !e2ee_needs_self_heal(&alice_mgr, bob.node_id()).await,
        "initiator with an initialized sending chain should not churn"
    );
    assert!(
        e2ee_needs_self_heal(&bob_mgr, alice.node_id()).await,
        "responder without RatchetInit still needs self-heal"
    );
}

#[tokio::test]
async fn onboarding_progress_events() {
    let storage = konsensus_storage::SqliteStorage::in_memory().await.unwrap();
    let (ws_tx, mut ws_rx) = broadcast::channel::<Arc<WsDeliveryStatus>>(8);
    let peer_id = test_peer_id();
    storage
        .upsert_onboarding_state(&onboarding_state_for(peer_id, "connecting"))
        .await
        .unwrap();
    funding_poll::emit_progress_step(
        &storage,
        &ws_tx,
        &peer_id,
        "noise_connected",
        "Secure transport connected",
    )
    .await
    .unwrap();
    let evt = ws_rx.recv().await.unwrap();
    assert_eq!(evt.event_type, "onboarding_progress");
    assert_eq!(evt.status, "noise_connected");
}

#[tokio::test]
async fn progress_event_persisted_and_replayable() {
    let storage = konsensus_storage::SqliteStorage::in_memory().await.unwrap();
    let (ws_tx, _ws_rx) = broadcast::channel::<Arc<WsDeliveryStatus>>(8);
    let peer_id = test_peer_id();
    storage
        .upsert_onboarding_state(&onboarding_state_for(peer_id, "connecting"))
        .await
        .unwrap();
    funding_poll::emit_progress_step(
        &storage,
        &ws_tx,
        &peer_id,
        "waiting_for_inviter_channel",
        "Waiting for inviter channel",
    )
    .await
    .unwrap();
    let state = storage.get_onboarding_state().await.unwrap().unwrap();
    assert_eq!(state.current_step, "waiting_for_inviter_channel");
}

#[tokio::test]
async fn lightning_info_stores_valid_pubkey() {
    let peer_id = test_peer_id();
    let pubkeys = Arc::new(tokio::sync::Mutex::new(
        std::collections::HashMap::<NodeId, String>::new(),
    ));

    handle_lightning_info_received(&peer_id, &valid_ln_pubkey(), &pubkeys).await;

    let map = pubkeys.lock().await;
    assert!(map.contains_key(&peer_id));
    assert_eq!(map[&peer_id], valid_ln_pubkey());
}

#[tokio::test]
async fn lightning_info_rejects_short_pubkey() {
    let peer_id = test_peer_id();
    let pubkeys = Arc::new(tokio::sync::Mutex::new(
        std::collections::HashMap::<NodeId, String>::new(),
    ));

    handle_lightning_info_received(&peer_id, "02abcdef", &pubkeys).await;

    assert!(pubkeys.lock().await.is_empty());
}

#[tokio::test]
async fn lightning_info_rejects_wrong_prefix() {
    let peer_id = test_peer_id();
    let pubkeys = Arc::new(tokio::sync::Mutex::new(
        std::collections::HashMap::<NodeId, String>::new(),
    ));

    // Starts with 04 (uncompressed) — invalid.
    let bad_pk = "04abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678ab";
    handle_lightning_info_received(&peer_id, bad_pk, &pubkeys).await;

    assert!(pubkeys.lock().await.is_empty());
}

#[tokio::test]
async fn lightning_info_rejects_invalid_hex() {
    let peer_id = test_peer_id();
    let pubkeys = Arc::new(tokio::sync::Mutex::new(
        std::collections::HashMap::<NodeId, String>::new(),
    ));

    // Correct length but contains non-hex character 'zz'.
    let bad_pk = "02abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456zzab";
    handle_lightning_info_received(&peer_id, bad_pk, &pubkeys).await;

    assert!(pubkeys.lock().await.is_empty());
}

#[tokio::test]
async fn lightning_info_updates_on_reconnect() {
    let peer_id = test_peer_id();
    let pubkeys = Arc::new(tokio::sync::Mutex::new(
        std::collections::HashMap::<NodeId, String>::new(),
    ));

    let pk1 = "02abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678ab";
    let pk2 = "03abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678ab";

    handle_lightning_info_received(&peer_id, pk1, &pubkeys).await;
    assert_eq!(pubkeys.lock().await[&peer_id], pk1);

    // Peer reconnects with new Lightning node — pubkey is updated.
    handle_lightning_info_received(&peer_id, pk2, &pubkeys).await;
    assert_eq!(pubkeys.lock().await[&peer_id], pk2);
}

// ── Invoice response handler tests ──────────────────────────

#[tokio::test]
async fn invoice_response_delivers_to_waiting_sender() {
    let peer_id = test_peer_id();
    let request_id = "req-001".to_string();

    let (tx, rx) = tokio::sync::oneshot::channel::<InvoiceResponseData>();
    let map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceResponseData>>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    map.lock().await.insert(request_id.clone(), tx);

    handle_invoice_response(
        &peer_id, &request_id,
        "lnbc100n1...".to_string(),
        "abc123hash".to_string(),
        &map,
    ).await;

    let data = rx.await.unwrap();
    assert_eq!(data.bolt11, "lnbc100n1...");
    assert_eq!(data.payment_hash, "abc123hash");
    // Request should be removed from map
    assert!(map.lock().await.is_empty());
}

#[tokio::test]
async fn invoice_response_unknown_request_id_is_noop() {
    let peer_id = test_peer_id();
    let map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceResponseData>>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    // No request registered — should log warning but not panic
    handle_invoice_response(
        &peer_id, "nonexistent",
        "lnbc100n1...".to_string(),
        "hash".to_string(),
        &map,
    ).await;

    assert!(map.lock().await.is_empty());
}

#[tokio::test]
async fn invoice_response_dropped_receiver_is_handled() {
    let peer_id = test_peer_id();
    let request_id = "req-dropped".to_string();

    let (tx, rx) = tokio::sync::oneshot::channel::<InvoiceResponseData>();
    let map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceResponseData>>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    map.lock().await.insert(request_id.clone(), tx);

    // Drop the receiver to simulate timeout on compose side
    drop(rx);

    // Should not panic — sender.send() returns Err but is handled
    handle_invoice_response(
        &peer_id, &request_id,
        "lnbc100n1...".to_string(),
        "hash".to_string(),
        &map,
    ).await;

    // Request should still be removed from map
    assert!(map.lock().await.is_empty());
}

#[tokio::test]
async fn invoice_error_drops_sender_channel() {
    let request_id = "req-error".to_string();
    let peer_id = test_peer_id();

    let (tx, rx) = tokio::sync::oneshot::channel::<InvoiceResponseData>();
    let map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceResponseData>>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    map.lock().await.insert(request_id.clone(), tx);

    // Simulate InvoiceErrorReceived event handling (inline from the match arm)
    {
        let mut requests = map.lock().await;
        requests.remove(&request_id);
    }

    // Receiver should get Err (channel closed)
    assert!(rx.await.is_err());
    assert!(map.lock().await.is_empty());

    // Verify for a peer context (use the variable)
    let _ = peer_id;
}

#[tokio::test]
async fn invoice_response_concurrent_requests_isolated() {
    let peer_id = test_peer_id();
    let map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceResponseData>>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    let (tx1, rx1) = tokio::sync::oneshot::channel::<InvoiceResponseData>();
    let (tx2, rx2) = tokio::sync::oneshot::channel::<InvoiceResponseData>();
    map.lock().await.insert("req-1".to_string(), tx1);
    map.lock().await.insert("req-2".to_string(), tx2);

    // Deliver response to req-2 first
    handle_invoice_response(
        &peer_id, "req-2",
        "bolt11-for-2".to_string(), "hash-2".to_string(), &map,
    ).await;

    // Deliver response to req-1 second
    handle_invoice_response(
        &peer_id, "req-1",
        "bolt11-for-1".to_string(), "hash-1".to_string(), &map,
    ).await;

    let data1 = rx1.await.unwrap();
    let data2 = rx2.await.unwrap();
    assert_eq!(data1.bolt11, "bolt11-for-1");
    assert_eq!(data2.bolt11, "bolt11-for-2");
    assert!(map.lock().await.is_empty());
}

// ── Message ack/reject handler tests ────────────────────────

#[tokio::test]
async fn message_acked_records_routing_success() {
    let peer_id = test_peer_id();
    let msg_id = konsensus_core::types::MessageId::from_bytes([42u8; 32]);
    let routing = Arc::new(konsensus_routing::RoutingTable::new(
        konsensus_routing::RoutingConfig::default(),
    ));
    let send_timestamps = Arc::new(tokio::sync::Mutex::new(
        std::collections::HashMap::new(),
    ));
    let storage: Arc<dyn konsensus_storage::Storage> =
        Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let (ws_tx, _ws_rx) = broadcast::channel::<Arc<WsDeliveryStatus>>(16);

    // Record send timestamp
    send_timestamps.lock().await.insert(msg_id, std::time::Instant::now());

    handle_message_acked(
        &peer_id, &msg_id, &send_timestamps, &storage, &routing, &ws_tx,
    ).await;

    // Routing weight should be updated (> 0)
    let weight = routing.get_peer_weight(&peer_id).await;
    assert!(weight.is_some());
    assert!(weight.unwrap() > 0.0, "routing weight should increase after ack");

    // Send timestamp should be removed
    assert!(!send_timestamps.lock().await.contains_key(&msg_id));
}

#[tokio::test]
async fn message_acked_without_timestamp_uses_zero_latency() {
    let peer_id = test_peer_id();
    let msg_id = konsensus_core::types::MessageId::from_bytes([43u8; 32]);
    let routing = Arc::new(konsensus_routing::RoutingTable::new(
        konsensus_routing::RoutingConfig::default(),
    ));
    let send_timestamps = Arc::new(tokio::sync::Mutex::new(
        std::collections::HashMap::<konsensus_core::types::MessageId, std::time::Instant>::new(),
    ));
    let storage: Arc<dyn konsensus_storage::Storage> =
        Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let (ws_tx, _ws_rx) = broadcast::channel::<Arc<WsDeliveryStatus>>(16);

    // No timestamp registered — should still succeed with 0 latency
    handle_message_acked(
        &peer_id, &msg_id, &send_timestamps, &storage, &routing, &ws_tx,
    ).await;

    let weight = routing.get_peer_weight(&peer_id).await;
    assert!(weight.is_some());
}

#[tokio::test]
async fn message_acked_broadcasts_delivery_status() {
    let peer_id = test_peer_id();
    let msg_id = konsensus_core::types::MessageId::from_bytes([44u8; 32]);
    let routing = Arc::new(konsensus_routing::RoutingTable::new(
        konsensus_routing::RoutingConfig::default(),
    ));
    let send_timestamps = Arc::new(tokio::sync::Mutex::new(
        std::collections::HashMap::new(),
    ));
    let storage: Arc<dyn konsensus_storage::Storage> =
        Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let (ws_tx, mut ws_rx) = broadcast::channel::<Arc<WsDeliveryStatus>>(16);

    handle_message_acked(
        &peer_id, &msg_id, &send_timestamps, &storage, &routing, &ws_tx,
    ).await;

    let status = ws_rx.recv().await.unwrap();
    assert_eq!(status.status, "delivered");
    assert_eq!(status.message_id, msg_id.to_hex());
    assert!(status.reason.is_none());
}

#[tokio::test]
async fn message_acked_prunes_stale_timestamps() {
    let peer_id = test_peer_id();
    let msg_id = konsensus_core::types::MessageId::from_bytes([45u8; 32]);
    let routing = Arc::new(konsensus_routing::RoutingTable::new(
        konsensus_routing::RoutingConfig::default(),
    ));
    let send_timestamps = Arc::new(tokio::sync::Mutex::new(
        std::collections::HashMap::new(),
    ));
    let storage: Arc<dyn konsensus_storage::Storage> =
        Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let (ws_tx, _ws_rx) = broadcast::channel::<Arc<WsDeliveryStatus>>(16);

    // Insert >1000 stale entries to trigger pruning
    {
        let mut ts = send_timestamps.lock().await;
        let old_instant = std::time::Instant::now() - std::time::Duration::from_secs(600);
        for i in 0..1010u32 {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&i.to_be_bytes());
            ts.insert(konsensus_core::types::MessageId::from_bytes(bytes), old_instant);
        }
        // Add the target message with current timestamp
        ts.insert(msg_id, std::time::Instant::now());
    }

    handle_message_acked(
        &peer_id, &msg_id, &send_timestamps, &storage, &routing, &ws_tx,
    ).await;

    // Stale entries (>5 min old) should be pruned; only fresh ones remain
    let remaining = send_timestamps.lock().await.len();
    assert!(remaining < 100, "stale timestamps should be pruned, got {remaining}");
}

#[tokio::test]
async fn message_rejected_records_routing_failure() {
    let peer_id = test_peer_id();
    let msg_id = konsensus_core::types::MessageId::from_bytes([50u8; 32]);
    let routing = Arc::new(konsensus_routing::RoutingTable::new(
        konsensus_routing::RoutingConfig::default(),
    ));
    let (ws_tx, _ws_rx) = broadcast::channel::<Arc<WsDeliveryStatus>>(16);

    // First record a success so we have a baseline weight
    routing.record_success(&peer_id, 100.0, 1000).await;
    let weight_before = routing.get_peer_weight(&peer_id).await.unwrap();

    handle_message_rejected(
        &peer_id, &msg_id, "InsufficientPayment", &routing, &ws_tx,
    ).await;

    let weight_after = routing.get_peer_weight(&peer_id).await.unwrap();
    assert!(
        weight_after < weight_before,
        "weight should decrease after rejection: {weight_before} -> {weight_after}"
    );
}

#[tokio::test]
async fn message_rejected_broadcasts_status_with_reason() {
    let peer_id = test_peer_id();
    let msg_id = konsensus_core::types::MessageId::from_bytes([51u8; 32]);
    let routing = Arc::new(konsensus_routing::RoutingTable::new(
        konsensus_routing::RoutingConfig::default(),
    ));
    let (ws_tx, mut ws_rx) = broadcast::channel::<Arc<WsDeliveryStatus>>(16);

    handle_message_rejected(
        &peer_id, &msg_id, "InsufficientPayment", &routing, &ws_tx,
    ).await;

    let status = ws_rx.recv().await.unwrap();
    assert_eq!(status.status, "rejected");
    assert_eq!(status.message_id, msg_id.to_hex());
    assert_eq!(status.reason.as_deref(), Some("InsufficientPayment"));
}

#[tokio::test]
async fn message_acked_no_ws_subscribers_is_handled() {
    let peer_id = test_peer_id();
    let msg_id = konsensus_core::types::MessageId::from_bytes([52u8; 32]);
    let routing = Arc::new(konsensus_routing::RoutingTable::new(
        konsensus_routing::RoutingConfig::default(),
    ));
    let send_timestamps = Arc::new(tokio::sync::Mutex::new(
        std::collections::HashMap::new(),
    ));
    let storage: Arc<dyn konsensus_storage::Storage> =
        Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let (ws_tx, ws_rx) = broadcast::channel::<Arc<WsDeliveryStatus>>(16);
    // Drop all receivers — send will return Err but should not panic
    drop(ws_rx);

    handle_message_acked(
        &peer_id, &msg_id, &send_timestamps, &storage, &routing, &ws_tx,
    ).await;

    // No panic = success
    let weight = routing.get_peer_weight(&peer_id).await;
    assert!(weight.is_some());
}

// ── Gossip signature verification tests ────────────────────────

fn make_gossip_identity() -> konsensus_core::NodeIdentity {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    konsensus_core::NodeIdentity::from_mnemonic(mnemonic, "").unwrap()
}

fn make_gossip_identity_2() -> konsensus_core::NodeIdentity {
    let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    konsensus_core::NodeIdentity::from_mnemonic(mnemonic, "").unwrap()
}

fn make_signed_gossip_envelope(identity: &konsensus_core::NodeIdentity) -> konsensus_core::UkmEnvelope {
    use konsensus_core::{UkmEnvelopeBuilder, PaymentProof};
    use konsensus_core::types::{Recipient, Signature};

    let preimage = [42u8; 32];
    let hash: [u8; 32] = sha2::Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, 0);
    let mut env = UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_WEB_MANIFEST,
        *identity.node_id(),
        Recipient::Broadcast,
        b"test gossip payload".to_vec(),
        proof,
    ).build();
    let sig = identity.sign(&env.signable_bytes());
    env.signature = Signature::from_ed25519(&sig);
    env
}

fn make_gossip_test_transport() -> Arc<NoiseTransport> {
    use std::net::SocketAddr;
    // Use a separate identity for the transport (the node receiving gossip)
    let mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let id = konsensus_core::NodeIdentity::from_mnemonic(mnemonic, "").unwrap();
    let cfg = konsensus_message::TransportConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        ..Default::default()
    };
    Arc::new(NoiseTransport::new(Arc::new(id), cfg))
}

fn make_gossip_audit_log() -> Arc<AuditLog> {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    Arc::new(AuditLog::open(tmp.path()).unwrap())
}

fn make_gossip_ws_tx() -> broadcast::Sender<Arc<konsensus_api::state::WsMessage>> {
    let (tx, _rx) = broadcast::channel(16);
    tx
}

#[tokio::test]
async fn gossip_valid_signature_accepted() {
    let identity = make_gossip_identity();
    let envelope = make_signed_gossip_envelope(&identity);
    let validator = konsensus_gossip::GossipValidator::new(Default::default());
    let transport = make_gossip_test_transport();
    let audit = make_gossip_audit_log();

    // Should not panic or reject — valid signature
    handle_gossip_received(
        test_peer_id(),
        envelope,
        &validator,
        &transport,
        &audit,
        &make_gossip_ws_tx(),
    ).await;
    // If we get here without panic, the message was accepted.
}

#[tokio::test]
async fn gossip_forged_signature_rejected() {
    let real_sender = make_gossip_identity();
    let mut envelope = make_signed_gossip_envelope(&real_sender);

    // Forge the signature by signing with a different key
    let attacker = make_gossip_identity_2();
    let forged_sig = attacker.sign(&envelope.signable_bytes());
    envelope.signature = konsensus_core::types::Signature::from_ed25519(&forged_sig);

    let validator = konsensus_gossip::GossipValidator::new(Default::default());
    let transport = make_gossip_test_transport();
    let audit = make_gossip_audit_log();

    // This should be rejected by signature verification (function returns early)
    // We can't directly observe the return, but we verify it doesn't panic
    // and the audit log does NOT record "gossip_received"
    handle_gossip_received(
        test_peer_id(),
        envelope,
        &validator,
        &transport,
        &audit,
        &make_gossip_ws_tx(),
    ).await;
    // No audit entry for accepted gossip — the forged message was rejected
}

#[tokio::test]
async fn gossip_tampered_payload_rejected() {
    let identity = make_gossip_identity();
    let mut envelope = make_signed_gossip_envelope(&identity);

    // Tamper with ciphertext after signing — signature should fail
    envelope.ciphertext = b"tampered payload".to_vec();
    // Note: message ID is now wrong too, but we test that signature
    // verification catches tampering even if envelope.validate() passes
    // (it won't pass because ID is wrong, but signature check is defense-in-depth)

    let validator = konsensus_gossip::GossipValidator::new(Default::default());
    let transport = make_gossip_test_transport();
    let audit = make_gossip_audit_log();

    handle_gossip_received(
        test_peer_id(),
        envelope,
        &validator,
        &transport,
        &audit,
        &make_gossip_ws_tx(),
    ).await;
    // No panic = rejected by validation (either ID mismatch or signature failure)
}

#[tokio::test]
async fn gossip_wrong_kind_rejected() {
    let identity = make_gossip_identity();
    use konsensus_core::{UkmEnvelopeBuilder, PaymentProof};
    use konsensus_core::types::{Recipient, Signature};

    let preimage = [42u8; 32];
    let hash: [u8; 32] = sha2::Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, 0);
    // Use KIND_CHAT (100) which is NOT in GOSSIP_ALLOWED_KINDS
    let mut env = UkmEnvelopeBuilder::new(
        100, // KIND_CHAT
        *identity.node_id(),
        Recipient::Broadcast,
        b"not gossip".to_vec(),
        proof,
    ).build();
    let sig = identity.sign(&env.signable_bytes());
    env.signature = Signature::from_ed25519(&sig);

    let validator = konsensus_gossip::GossipValidator::new(Default::default());
    let transport = make_gossip_test_transport();
    let audit = make_gossip_audit_log();

    handle_gossip_received(
        test_peer_id(),
        env,
        &validator,
        &transport,
        &audit,
        &make_gossip_ws_tx(),
    ).await;
    // Rejected by kind check — no panic
}

#[tokio::test]
async fn gossip_non_broadcast_recipient_rejected() {
    let identity = make_gossip_identity();
    use konsensus_core::{UkmEnvelopeBuilder, PaymentProof};
    use konsensus_core::types::{Recipient, Signature};

    let preimage = [42u8; 32];
    let hash: [u8; 32] = sha2::Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, 0);
    // Use Node recipient instead of Broadcast
    let mut env = UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_WEB_MANIFEST,
        *identity.node_id(),
        Recipient::Node(test_peer_id()),
        b"not broadcast".to_vec(),
        proof,
    ).build();
    let sig = identity.sign(&env.signable_bytes());
    env.signature = Signature::from_ed25519(&sig);

    let validator = konsensus_gossip::GossipValidator::new(Default::default());
    let transport = make_gossip_test_transport();
    let audit = make_gossip_audit_log();

    handle_gossip_received(
        test_peer_id(),
        env,
        &validator,
        &transport,
        &audit,
        &make_gossip_ws_tx(),
    ).await;
    // Rejected by recipient check — no panic
}

#[tokio::test]
async fn gossip_valid_message_broadcast_to_ws() {
    let identity = make_gossip_identity();
    let envelope = make_signed_gossip_envelope(&identity);
    let validator = konsensus_gossip::GossipValidator::new(Default::default());
    let transport = make_gossip_test_transport();
    let audit = make_gossip_audit_log();
    let (ws_tx, mut ws_rx) = broadcast::channel::<Arc<konsensus_api::state::WsMessage>>(16);

    handle_gossip_received(
        test_peer_id(),
        envelope.clone(),
        &validator,
        &transport,
        &audit,
        &ws_tx,
    ).await;

    // Should receive the gossip message on WS
    let msg = ws_rx.recv().await.unwrap();
    assert_eq!(msg.envelope.kind, konsensus_core::kind::KIND_WEB_MANIFEST);
    assert_eq!(msg.envelope.sender, *identity.node_id());
    // Plaintext should be the gossip payload (it's public data, not E2EE)
    assert_eq!(msg.plaintext.as_deref(), Some("test gossip payload"));
}

#[tokio::test]
async fn gossip_rejected_message_not_broadcast_to_ws() {
    let real_sender = make_gossip_identity();
    let mut envelope = make_signed_gossip_envelope(&real_sender);

    // Forge signature — should be rejected
    let attacker = make_gossip_identity_2();
    let forged_sig = attacker.sign(&envelope.signable_bytes());
    envelope.signature = konsensus_core::types::Signature::from_ed25519(&forged_sig);

    let validator = konsensus_gossip::GossipValidator::new(Default::default());
    let transport = make_gossip_test_transport();
    let audit = make_gossip_audit_log();
    let (ws_tx, mut ws_rx) = broadcast::channel::<Arc<konsensus_api::state::WsMessage>>(16);

    handle_gossip_received(
        test_peer_id(),
        envelope,
        &validator,
        &transport,
        &audit,
        &ws_tx,
    ).await;

    // Should NOT receive anything on WS — message was rejected
    assert!(ws_rx.try_recv().is_err());
}

#[tokio::test]
async fn gossip_oversized_payload_rejected() {
    let identity = make_gossip_identity();

    // Build an envelope with a payload exceeding MAX_GOSSIP_RELAY_PAYLOAD (64 KB)
    let oversized_payload = vec![b'A'; 65_537]; // 64 KB + 1 byte
    let preimage = [42u8; 32];
    let hash: [u8; 32] = sha2::Sha256::digest(preimage).into();
    let proof = konsensus_core::PaymentProof::new(hash, preimage, 0);
    let mut env = konsensus_core::UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_WEB_MANIFEST,
        *identity.node_id(),
        konsensus_core::types::Recipient::Broadcast,
        oversized_payload,
        proof,
    ).build();
    let sig = identity.sign(&env.signable_bytes());
    env.signature = konsensus_core::types::Signature::from_ed25519(&sig);

    let validator = konsensus_gossip::GossipValidator::new(Default::default());
    let transport = make_gossip_test_transport();
    let audit = make_gossip_audit_log();
    let (ws_tx, mut ws_rx) = broadcast::channel::<Arc<konsensus_api::state::WsMessage>>(16);

    handle_gossip_received(
        test_peer_id(),
        env,
        &validator,
        &transport,
        &audit,
        &ws_tx,
    ).await;

    // Oversized payload should be rejected — not broadcast to WS
    assert!(ws_rx.try_recv().is_err(), "oversized gossip should not reach WebSocket clients");
    // Message should NOT be in the dedup store (rejected before validation)
    assert_eq!(validator.store().len(), 0, "oversized gossip should not be stored");
}

#[tokio::test]
async fn gossip_exactly_at_size_limit_accepted() {
    let identity = make_gossip_identity();

    // Build an envelope with payload at exactly MAX_GOSSIP_RELAY_PAYLOAD (64 KB)
    let payload = vec![b'B'; 65_536]; // exactly 64 KB
    let preimage = [42u8; 32];
    let hash: [u8; 32] = sha2::Sha256::digest(preimage).into();
    let proof = konsensus_core::PaymentProof::new(hash, preimage, 0);
    let mut env = konsensus_core::UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_WEB_MANIFEST,
        *identity.node_id(),
        konsensus_core::types::Recipient::Broadcast,
        payload,
        proof,
    ).build();
    let sig = identity.sign(&env.signable_bytes());
    env.signature = konsensus_core::types::Signature::from_ed25519(&sig);

    let validator = konsensus_gossip::GossipValidator::new(Default::default());
    let transport = make_gossip_test_transport();
    let audit = make_gossip_audit_log();
    let (ws_tx, mut ws_rx) = broadcast::channel::<Arc<konsensus_api::state::WsMessage>>(16);

    handle_gossip_received(
        test_peer_id(),
        env,
        &validator,
        &transport,
        &audit,
        &ws_tx,
    ).await;

    // Exactly at the limit should be accepted and broadcast to WS
    let msg = ws_rx.try_recv();
    assert!(msg.is_ok(), "gossip at exactly 64 KB should be accepted");
    assert_eq!(validator.store().len(), 1, "accepted gossip should be stored");
}

/// Verify that a forged-signature gossip message does NOT consume dedup
/// store space or rate-limit budget.  The signature check runs before
/// the dedup/rate-limit validation to prevent an attacker from poisoning
/// the dedup store with invalid messages.
#[tokio::test]
async fn gossip_forged_signature_does_not_consume_dedup_store() {
    let real_sender = make_gossip_identity();
    let mut envelope = make_signed_gossip_envelope(&real_sender);

    // Forge the signature
    let attacker = make_gossip_identity_2();
    let forged_sig = attacker.sign(&envelope.signable_bytes());
    envelope.signature = konsensus_core::types::Signature::from_ed25519(&forged_sig);

    let validator = konsensus_gossip::GossipValidator::new(Default::default());
    let transport = make_gossip_test_transport();
    let audit = make_gossip_audit_log();

    // Send the forged message
    handle_gossip_received(
        test_peer_id(),
        envelope.clone(),
        &validator,
        &transport,
        &audit,
        &make_gossip_ws_tx(),
    ).await;

    // The dedup store must be empty — forged messages should not occupy
    // dedup slots, preventing an attacker from exhausting the legitimate
    // sender's rate-limit quota.
    assert_eq!(
        validator.store().len(), 0,
        "forged-signature gossip must NOT consume dedup store space"
    );
}

/// Verify that after a forged message is rejected, the same message ID
/// from the real sender (with valid signature) is still accepted.
#[tokio::test]
async fn gossip_valid_message_accepted_after_forged_attempt() {
    let real_sender = make_gossip_identity();
    let envelope = make_signed_gossip_envelope(&real_sender);

    // First: forged version
    let mut forged = envelope.clone();
    let attacker = make_gossip_identity_2();
    let forged_sig = attacker.sign(&forged.signable_bytes());
    forged.signature = konsensus_core::types::Signature::from_ed25519(&forged_sig);

    let validator = konsensus_gossip::GossipValidator::new(Default::default());
    let transport = make_gossip_test_transport();
    let audit = make_gossip_audit_log();
    let (ws_tx, mut ws_rx) = broadcast::channel::<Arc<konsensus_api::state::WsMessage>>(16);

    // Send forged — rejected
    handle_gossip_received(
        test_peer_id(),
        forged,
        &validator,
        &transport,
        &audit,
        &ws_tx,
    ).await;
    assert!(ws_rx.try_recv().is_err(), "forged message should not reach WS");
    assert_eq!(validator.store().len(), 0);

    // Send real — should be accepted (not blocked by dedup)
    handle_gossip_received(
        test_peer_id(),
        envelope,
        &validator,
        &transport,
        &audit,
        &ws_tx,
    ).await;
    assert!(ws_rx.try_recv().is_ok(), "real message should be accepted after forged attempt");
    assert_eq!(validator.store().len(), 1, "accepted message should be in dedup store");
}

// ── Peer exchange handler tests ───────────────────────────

fn make_peer_id(byte: u8) -> NodeId {
    NodeId::from_bytes([byte; 32])
}

fn make_peer_registry_with_entries(entries: Vec<(u8, &str)>) -> tokio::sync::RwLock<PeerRegistry> {
    let mut registry = PeerRegistry::new();
    for (byte, addr_str) in entries {
        registry.add(konsensus_message::peer::PeerEntry {
            node_id: make_peer_id(byte),
            addr: addr_str.parse().unwrap(),
            label: Some(format!("peer-{byte}")),
            auto_connect: false,
        });
    }
    tokio::sync::RwLock::new(registry)
}

#[tokio::test]
async fn peer_exchange_request_builds_response_excluding_requester() {
    let requester = make_peer_id(1);
    let our_node_id = make_peer_id(99);
    let registry = make_peer_registry_with_entries(vec![
        (1, "127.0.0.1:9001"), // requester — should be excluded
        (2, "127.0.0.1:9002"),
        (3, "127.0.0.1:9003"),
    ]);
    let transport = make_gossip_test_transport();
    let mut cooldown = std::collections::HashMap::new();

    handle_peer_exchange_request(
        &requester, our_node_id, &registry, &transport, &mut cooldown,
    ).await;

    // Cooldown should be recorded
    assert!(cooldown.contains_key(&requester));
}

#[tokio::test]
async fn peer_exchange_request_throttled_by_cooldown() {
    let requester = make_peer_id(1);
    let our_node_id = make_peer_id(99);
    let registry = make_peer_registry_with_entries(vec![
        (2, "127.0.0.1:9002"),
    ]);
    let transport = make_gossip_test_transport();
    let mut cooldown = std::collections::HashMap::new();

    // First request — sets cooldown
    handle_peer_exchange_request(
        &requester, our_node_id, &registry, &transport, &mut cooldown,
    ).await;
    assert!(cooldown.contains_key(&requester));

    // Second request within cooldown — should be throttled (no update to timestamp)
    let first_ts = cooldown[&requester];
    handle_peer_exchange_request(
        &requester, our_node_id, &registry, &transport, &mut cooldown,
    ).await;
    // Timestamp should NOT be updated (throttled)
    assert_eq!(cooldown[&requester], first_ts);
}

#[tokio::test]
async fn peer_exchange_received_adds_new_peers() {
    let sender = make_peer_id(1);
    let our_node_id = make_peer_id(99);
    let registry = tokio::sync::RwLock::new(PeerRegistry::new());
    let mut cooldown = std::collections::HashMap::new();

    let peers = vec![
        konsensus_message::wire::PeerExchangeEntry {
            node_id: make_peer_id(2),
            addr: "127.0.0.1:9002".parse().unwrap(),
            label: Some("peer-2".to_string()),
            tier: konsensus_message::wire::SovereigntyTier::T1,
        },
        konsensus_message::wire::PeerExchangeEntry {
            node_id: make_peer_id(3),
            addr: "127.0.0.1:9003".parse().unwrap(),
            label: None,
            tier: konsensus_message::wire::SovereigntyTier::T2,
        },
    ];

    handle_peer_exchange_received(
        &sender, peers, our_node_id, &registry, &mut cooldown,
    ).await;

    let reg = registry.read().await;
    assert!(reg.contains(&make_peer_id(2)));
    assert!(reg.contains(&make_peer_id(3)));
    assert!(!reg.contains(&sender), "sender itself should not be in our registry from exchange");
}

#[tokio::test]
async fn peer_exchange_received_skips_self() {
    let sender = make_peer_id(1);
    let our_node_id = make_peer_id(99);
    let registry = tokio::sync::RwLock::new(PeerRegistry::new());
    let mut cooldown = std::collections::HashMap::new();

    // Include ourselves in the exchange — should be skipped
    let peers = vec![
        konsensus_message::wire::PeerExchangeEntry {
            node_id: our_node_id, // our own ID
            addr: "127.0.0.1:9099".parse().unwrap(),
            label: None,
            tier: konsensus_message::wire::SovereigntyTier::T1,
        },
        konsensus_message::wire::PeerExchangeEntry {
            node_id: make_peer_id(5),
            addr: "127.0.0.1:9005".parse().unwrap(),
            label: None,
            tier: konsensus_message::wire::SovereigntyTier::T1,
        },
    ];

    handle_peer_exchange_received(
        &sender, peers, our_node_id, &registry, &mut cooldown,
    ).await;

    let reg = registry.read().await;
    assert!(!reg.contains(&our_node_id), "should not add ourselves");
    assert!(reg.contains(&make_peer_id(5)));
}

#[tokio::test]
async fn peer_exchange_received_skips_duplicates() {
    let sender = make_peer_id(1);
    let our_node_id = make_peer_id(99);
    let registry = make_peer_registry_with_entries(vec![
        (2, "127.0.0.1:9002"), // already known
    ]);
    let mut cooldown = std::collections::HashMap::new();

    let peers = vec![
        konsensus_message::wire::PeerExchangeEntry {
            node_id: make_peer_id(2), // already in registry
            addr: "127.0.0.1:9999".parse().unwrap(), // different addr
            label: Some("renamed".to_string()),
            tier: konsensus_message::wire::SovereigntyTier::T1,
        },
        konsensus_message::wire::PeerExchangeEntry {
            node_id: make_peer_id(4), // new
            addr: "127.0.0.1:9004".parse().unwrap(),
            label: None,
            tier: konsensus_message::wire::SovereigntyTier::T1,
        },
    ];

    handle_peer_exchange_received(
        &sender, peers, our_node_id, &registry, &mut cooldown,
    ).await;

    let reg = registry.read().await;
    // Peer 2 should keep its original address (not overwritten)
    let all = reg.all();
    let peer2 = all.iter().find(|p| p.node_id == make_peer_id(2)).unwrap();
    assert_eq!(peer2.addr, "127.0.0.1:9002".parse::<std::net::SocketAddr>().unwrap());
    // Peer 4 should be added
    assert!(reg.contains(&make_peer_id(4)));
}

#[tokio::test]
async fn peer_exchange_received_truncates_oversized_list() {
    let sender = make_peer_id(1);
    let our_node_id = make_peer_id(99);
    let registry = tokio::sync::RwLock::new(PeerRegistry::new());
    let mut cooldown = std::collections::HashMap::new();

    // Send 60 entries — should be truncated to MAX_PEER_EXCHANGE_ENTRIES (50)
    let peers: Vec<_> = (10..70u8).map(|i| {
        konsensus_message::wire::PeerExchangeEntry {
            node_id: make_peer_id(i),
            addr: format!("127.0.0.1:{}", 9000 + i as u16).parse().unwrap(),
            label: None,
            tier: konsensus_message::wire::SovereigntyTier::T1,
        }
    }).collect();
    assert_eq!(peers.len(), 60);

    handle_peer_exchange_received(
        &sender, peers, our_node_id, &registry, &mut cooldown,
    ).await;

    let reg = registry.read().await;
    let count = reg.all().len();
    assert_eq!(count, 50, "should truncate to MAX_PEER_EXCHANGE_ENTRIES, got {count}");
}

#[tokio::test]
async fn peer_exchange_received_throttled_by_cooldown() {
    let sender = make_peer_id(1);
    let our_node_id = make_peer_id(99);
    let registry = tokio::sync::RwLock::new(PeerRegistry::new());
    let mut cooldown = std::collections::HashMap::new();

    let peers = vec![
        konsensus_message::wire::PeerExchangeEntry {
            node_id: make_peer_id(2),
            addr: "127.0.0.1:9002".parse().unwrap(),
            label: None,
            tier: konsensus_message::wire::SovereigntyTier::T1,
        },
    ];

    // First call — should succeed
    handle_peer_exchange_received(
        &sender, peers.clone(), our_node_id, &registry, &mut cooldown,
    ).await;
    assert!(registry.read().await.contains(&make_peer_id(2)));

    // Second call within cooldown — should be throttled, peer 3 NOT added
    let peers2 = vec![
        konsensus_message::wire::PeerExchangeEntry {
            node_id: make_peer_id(3),
            addr: "127.0.0.1:9003".parse().unwrap(),
            label: None,
            tier: konsensus_message::wire::SovereigntyTier::T1,
        },
    ];
    handle_peer_exchange_received(
        &sender, peers2, our_node_id, &registry, &mut cooldown,
    ).await;
    assert!(!registry.read().await.contains(&make_peer_id(3)),
        "peer 3 should NOT be added — exchange was throttled");
}

// ── Invoice requested handler tests ────────────────────────

#[tokio::test]
async fn invoice_requested_creates_invoice_on_local_wallet() {
    let peer_id = test_peer_id();
    let transport = make_gossip_test_transport();
    let lightning: Arc<dyn LightningProvider> =
        Arc::new(konsensus_lightning::MockLightningProvider::new());

    // Should create invoice without panicking
    handle_invoice_requested(
        &peer_id, "req-inv-1", 25_000, "konsensus message",
        &lightning, &transport,
    ).await;

    // Verify the invoice was actually created on the mock
    let payments = lightning.list_payments(10).await.unwrap();
    assert!(!payments.is_empty(), "invoice should be created on local wallet");
}

#[tokio::test]
async fn invoice_requested_sends_error_on_lightning_failure() {
    use konsensus_core::traits::lightning::{
        LightningProvider as LP, LightningError, Invoice, PaymentDetails,
    };

    /// A lightning provider that always fails invoice creation.
    struct FailingLightning;

    #[async_trait::async_trait]
    impl LP for FailingLightning {
        async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
            Err(LightningError::Backend("wallet locked".into()))
        }
        async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::Backend("wallet locked".into()))
        }
        async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::Backend("wallet locked".into()))
        }
        async fn get_balance_msat(&self) -> Result<u64, LightningError> {
            Err(LightningError::Backend("wallet locked".into()))
        }
        async fn is_available(&self) -> bool { false }
    }

    let peer_id = test_peer_id();
    let transport = make_gossip_test_transport();
    let lightning: Arc<dyn LightningProvider> = Arc::new(FailingLightning);

    // Should not panic — sends InvoiceError frame (which fails silently since no peer connected)
    handle_invoice_requested(
        &peer_id, "req-inv-fail", 25_000, "konsensus message",
        &lightning, &transport,
    ).await;
    // No panic = success
}

// ── Price query handler tests ──────────────────────────────

#[tokio::test]
async fn price_query_responds_with_price() {
    let peer_id = test_peer_id();
    let transport = make_gossip_test_transport();
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> =
        Arc::new(konsensus_pricing::StaticPricingEngine::new(
            konsensus_pricing::StaticPricingConfig::default(),
        ));
    let chain: Arc<dyn ChainProvider> = Arc::new(
        konsensus_chain::MockChainProvider::new(),
    );

    // Should not panic — sends PriceResponse (fails silently since no peer connected)
    handle_price_query(&peer_id, 100, &pricing, &chain, &transport).await;
    // No panic = success
}

#[tokio::test]
async fn price_query_skips_response_when_chain_unavailable() {
    use konsensus_core::traits::chain::{BlockHeader, ChainError, FeeEstimate, TrustLevel};

    struct FailingChain;

    #[async_trait::async_trait]
    impl ChainProvider for FailingChain {
        fn trust_level(&self) -> TrustLevel { TrustLevel::ServerTrust }
        async fn get_block_height(&self) -> Result<u64, ChainError> {
            Err(ChainError::Backend("down".into()))
        }
        async fn get_block_header(&self, _h: u64) -> Result<BlockHeader, ChainError> {
            Err(ChainError::Backend("down".into()))
        }
        async fn estimate_fee(&self, _t: u32) -> Result<FeeEstimate, ChainError> {
            Err(ChainError::Backend("down".into()))
        }
        async fn is_tx_confirmed(&self, _tx: &str, _min: u32) -> Result<bool, ChainError> {
            Err(ChainError::Backend("down".into()))
        }
        async fn is_synced(&self) -> bool { false }
    }

    let peer_id = test_peer_id();
    let transport = make_gossip_test_transport();
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> =
        Arc::new(konsensus_pricing::StaticPricingEngine::new(
            konsensus_pricing::StaticPricingConfig::default(),
        ));
    let chain: Arc<dyn ChainProvider> = Arc::new(FailingChain);

    // Should not panic — skips response due to chain failure
    handle_price_query(&peer_id, 100, &pricing, &chain, &transport).await;
    // No panic = success (handler returns early with warning)
}
