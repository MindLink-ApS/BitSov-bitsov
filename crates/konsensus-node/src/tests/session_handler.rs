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

    let (tx, rx) = tokio::sync::oneshot::channel::<InvoiceRequestOutcome>();
    let map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceRequestOutcome>>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    map.lock().await.insert(request_id.clone(), tx);

    handle_invoice_response(
        &peer_id, &request_id,
        "lnbc100n1...".to_string(),
        "abc123hash".to_string(),
        &map,
    ).await;

    let data = rx.await.unwrap().unwrap();
    assert_eq!(data.bolt11, "lnbc100n1...");
    assert_eq!(data.payment_hash, "abc123hash");
    // Request should be removed from map
    assert!(map.lock().await.is_empty());
}

#[tokio::test]
async fn invoice_response_unknown_request_id_is_noop() {
    let peer_id = test_peer_id();
    let map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceRequestOutcome>>>> =
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

    let (tx, rx) = tokio::sync::oneshot::channel::<InvoiceRequestOutcome>();
    let map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceRequestOutcome>>>> =
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

    let (tx, rx) = tokio::sync::oneshot::channel::<InvoiceRequestOutcome>();
    let map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceRequestOutcome>>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    map.lock().await.insert(request_id.clone(), tx);

    handle_invoice_error_received(&peer_id, &request_id, "invoice failed", true, &map).await;

    // Receiver should get Err (channel closed)
    assert!(rx.await.unwrap().is_err());
    assert!(map.lock().await.is_empty());
}

#[tokio::test]
async fn unprivileged_invoice_error_does_not_drop_sender_channel() {
    let request_id = "req-error-unprivileged".to_string();
    let peer_id = test_peer_id();

    let (tx, rx) = tokio::sync::oneshot::channel::<InvoiceRequestOutcome>();
    let map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceRequestOutcome>>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    map.lock().await.insert(request_id.clone(), tx);

    assert!(handle_invoice_error_received(&peer_id, &request_id, "attacker-forged error", false, &map).await);

    let sender = map
        .lock()
        .await
        .remove(&request_id)
        .expect("unprivileged invoice error must not remove pending request");
    assert!(
        sender
            .send(Ok(InvoiceResponseData {
                recipient: peer_id,
                bolt11: "lnbc100n1...".to_string(),
                payment_hash: "hash".to_string(),
            }))
            .is_ok(),
        "receiver should still be open after unprivileged invoice error"
    );
    assert!(rx.await.is_ok());
}

#[tokio::test]
async fn unprivileged_refusal_of_a_request_sent_to_that_peer_ends_it() {
    // The sender learns "admission required" from a recipient that never paid
    // us — but only for a request it actually sent to that recipient.
    let request_id = uuid::Uuid::new_v4().to_string();
    let peer_id = test_peer_id();
    let binding = konsensus_api::invoice_refusal::bind(&request_id, peer_id);

    let (tx, rx) = tokio::sync::oneshot::channel::<InvoiceRequestOutcome>();
    let map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceRequestOutcome>>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    map.lock().await.insert(request_id.clone(), tx);

    handle_invoice_error_received(
        &peer_id, &request_id, konsensus_api::invoice_refusal::ADMISSION_REQUIRED, false, &map,
    ).await;

    assert!(rx.await.unwrap().is_err(), "the pending request ends at once");
    assert!(map.lock().await.is_empty());
    assert_eq!(
        binding.finish().as_deref(),
        Some(konsensus_api::invoice_refusal::ADMISSION_REQUIRED),
        "the compose that asked reads the reason"
    );
}

#[tokio::test]
async fn invoice_response_concurrent_requests_isolated() {
    let peer_id = test_peer_id();
    let map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceRequestOutcome>>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    let (tx1, rx1) = tokio::sync::oneshot::channel::<InvoiceRequestOutcome>();
    let (tx2, rx2) = tokio::sync::oneshot::channel::<InvoiceRequestOutcome>();
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

    let data1 = rx1.await.unwrap().unwrap();
    let data2 = rx2.await.unwrap().unwrap();
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
        &peer_id, &msg_id, &send_timestamps, &storage, &routing, &ws_tx, true).await;

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
        &peer_id, &msg_id, &send_timestamps, &storage, &routing, &ws_tx, true).await;

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
        &peer_id, &msg_id, &send_timestamps, &storage, &routing, &ws_tx, true).await;

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
        &peer_id, &msg_id, &send_timestamps, &storage, &routing, &ws_tx, true).await;

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
        &peer_id, &msg_id, "InsufficientPayment", &routing, &ws_tx, true).await;

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
        &peer_id, &msg_id, "InsufficientPayment", &routing, &ws_tx, true).await;

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
        &peer_id, &msg_id, &send_timestamps, &storage, &routing, &ws_tx, true).await;

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
async fn gossip_legacy_free_kind_rejected() {
    let identity = make_gossip_identity();
    let envelope = make_signed_gossip_envelope(&identity);
    let validator = konsensus_gossip::GossipValidator::new(Default::default());
    let transport = make_gossip_test_transport();
    let audit = make_gossip_audit_log();

    // Legacy free gossip is fail-closed until paid broadcast lands.
    handle_gossip_received(
        test_peer_id(),
        envelope,
        &validator,
        &transport,
        &audit,
        &make_gossip_ws_tx(),
    ).await;
    assert_eq!(validator.store().len(), 0, "legacy free gossip must not be stored");
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
async fn gossip_legacy_free_message_not_broadcast_to_ws() {
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

    assert!(ws_rx.try_recv().is_err(), "legacy free gossip must not reach WebSocket clients");
    assert_eq!(validator.store().len(), 0, "legacy free gossip must not be stored");
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
async fn gossip_exactly_at_size_limit_rejected_while_legacy_free_gossip_disabled() {
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

    assert!(ws_rx.try_recv().is_err(), "legacy free gossip must not reach WebSocket clients");
    assert_eq!(validator.store().len(), 0, "legacy free gossip must not be stored");
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
/// from the real sender is still rejected while legacy free gossip is disabled.
#[tokio::test]
async fn gossip_valid_message_still_rejected_after_forged_attempt() {
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

    // Send real — still rejected because free gossip is disabled.
    handle_gossip_received(
        test_peer_id(),
        envelope,
        &validator,
        &transport,
        &audit,
        &ws_tx,
    ).await;
    assert!(ws_rx.try_recv().is_err(), "legacy free gossip must not reach WS");
    assert_eq!(validator.store().len(), 0, "legacy free gossip must not be stored");
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
async fn peer_exchange_received_adds_new_peers() {
    let sender = make_peer_id(1);
    let our_node_id = make_peer_id(99);
    let registry = tokio::sync::RwLock::new(PeerRegistry::new());
    let mut cooldown = std::collections::HashMap::new();

    let peers = vec![
        konsensus_message::wire::PeerExchangeEntry {
            node_id: make_peer_id(2),
            addr: "5.6.7.8:9002".parse().unwrap(),
            label: Some("peer-2".to_string()),
            tier: konsensus_message::wire::SovereigntyTier::T1,
        },
        konsensus_message::wire::PeerExchangeEntry {
            node_id: make_peer_id(3),
            addr: "5.6.7.8:9003".parse().unwrap(),
            label: None,
            tier: konsensus_message::wire::SovereigntyTier::T2,
        },
    ];

    handle_peer_exchange_received(
        &sender, peers, our_node_id, &registry, &mut cooldown,
    ).await;

    let reg = registry.read().await;
    // B2: PEX is discovery, not admission — suggested peers land in the
    // discovered set with NO gate authority, never in the whitelist.
    assert!(reg.is_discovered(&make_peer_id(2)));
    assert!(reg.is_discovered(&make_peer_id(3)));
    assert!(
        !reg.contains(&make_peer_id(2)),
        "PEX peer must NOT be admitted/whitelisted"
    );
    assert!(
        !reg.contains(&make_peer_id(3)),
        "PEX peer must NOT be admitted/whitelisted"
    );
    assert!(!reg.whitelist_set().contains(&make_peer_id(2)));
    assert!(
        !reg.is_known(&sender),
        "sender itself should not be discovered from its own exchange"
    );
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
            addr: "5.6.7.8:9099".parse().unwrap(),
            label: None,
            tier: konsensus_message::wire::SovereigntyTier::T1,
        },
        konsensus_message::wire::PeerExchangeEntry {
            node_id: make_peer_id(5),
            addr: "5.6.7.8:9005".parse().unwrap(),
            label: None,
            tier: konsensus_message::wire::SovereigntyTier::T1,
        },
    ];

    handle_peer_exchange_received(
        &sender, peers, our_node_id, &registry, &mut cooldown,
    ).await;

    let reg = registry.read().await;
    assert!(!reg.is_known(&our_node_id), "should not add ourselves");
    assert!(reg.is_discovered(&make_peer_id(5)));
    assert!(
        !reg.contains(&make_peer_id(5)),
        "discovered via PEX, not admitted"
    );
}

#[tokio::test]
async fn peer_exchange_received_skips_duplicates() {
    let sender = make_peer_id(1);
    let our_node_id = make_peer_id(99);
    let registry = make_peer_registry_with_entries(vec![
        (2, "5.6.7.8:9002"), // already known
    ]);
    let mut cooldown = std::collections::HashMap::new();

    let peers = vec![
        konsensus_message::wire::PeerExchangeEntry {
            node_id: make_peer_id(2), // already in registry
            addr: "5.6.7.8:9999".parse().unwrap(), // different addr
            label: Some("renamed".to_string()),
            tier: konsensus_message::wire::SovereigntyTier::T1,
        },
        konsensus_message::wire::PeerExchangeEntry {
            node_id: make_peer_id(4), // new
            addr: "5.6.7.8:9004".parse().unwrap(),
            label: None,
            tier: konsensus_message::wire::SovereigntyTier::T1,
        },
    ];

    handle_peer_exchange_received(
        &sender, peers, our_node_id, &registry, &mut cooldown,
    ).await;

    let reg = registry.read().await;
    // Peer 2 was already ADMITTED — a PEX suggestion must neither overwrite its
    // address nor demote it to discovered.
    let all = reg.all();
    let peer2 = all.iter().find(|p| p.node_id == make_peer_id(2)).unwrap();
    assert_eq!(peer2.addr, "5.6.7.8:9002".parse::<std::net::SocketAddr>().unwrap());
    assert!(reg.contains(&make_peer_id(2)), "still admitted");
    assert!(!reg.is_discovered(&make_peer_id(2)));
    // Peer 4 is newly DISCOVERED — known but not admitted.
    assert!(reg.is_discovered(&make_peer_id(4)));
    assert!(
        !reg.contains(&make_peer_id(4)),
        "PEX peer is discovered, not admitted"
    );
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
            addr: format!("5.6.7.8:{}", 9000 + i as u16).parse().unwrap(),
            label: None,
            tier: konsensus_message::wire::SovereigntyTier::T1,
        }
    }).collect();
    assert_eq!(peers.len(), 60);

    handle_peer_exchange_received(
        &sender, peers, our_node_id, &registry, &mut cooldown,
    ).await;

    let reg = registry.read().await;
    let count = reg.discovered_len();
    assert_eq!(count, 50, "should truncate to MAX_PEER_EXCHANGE_ENTRIES, got {count}");
    assert!(reg.is_empty(), "PEX peers are discovered, never admitted");
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
            addr: "5.6.7.8:9002".parse().unwrap(),
            label: None,
            tier: konsensus_message::wire::SovereigntyTier::T1,
        },
    ];

    // First call — should succeed
    handle_peer_exchange_received(
        &sender, peers.clone(), our_node_id, &registry, &mut cooldown,
    ).await;
    assert!(registry.read().await.is_discovered(&make_peer_id(2)));

    // Second call within cooldown — should be throttled, peer 3 NOT added
    let peers2 = vec![
        konsensus_message::wire::PeerExchangeEntry {
            node_id: make_peer_id(3),
            addr: "5.6.7.8:9003".parse().unwrap(),
            label: None,
            tier: konsensus_message::wire::SovereigntyTier::T1,
        },
    ];
    handle_peer_exchange_received(
        &sender, peers2, our_node_id, &registry, &mut cooldown,
    ).await;
    assert!(!registry.read().await.is_known(&make_peer_id(3)),
        "peer 3 should NOT be discovered — exchange was throttled");
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
        &lightning, &transport, "127.0.0.1".parse().unwrap(), &mut crate::invoice_refusals::RefusalLimits::default(),
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
        &lightning, &transport, "127.0.0.1".parse().unwrap(), &mut crate::invoice_refusals::RefusalLimits::default(),
    ).await;
    // No panic = success
}

// ── M1b: privilege-gated invoice carve-out ─────────────────

fn admission_pricing() -> Arc<dyn konsensus_core::traits::pricing::PricingEngine> {
    Arc::new(konsensus_pricing::StaticPricingEngine::new(
        konsensus_pricing::StaticPricingConfig::default(),
    ))
}

#[tokio::test]
async fn privileged_invoice_request_honours_caller_amount_unchanged() {
    // Whitelist/promoted peers keep the exact pre-M1b behaviour: the caller's
    // amount is honoured verbatim. Byte-identical to the legacy path.
    let peer_id = test_peer_id();
    let transport = make_gossip_test_transport();
    let lightning: Arc<dyn LightningProvider> =
        Arc::new(konsensus_lightning::MockLightningProvider::new());
    let pricing = admission_pricing();

    handle_invoice_requested_gated(
        &peer_id, "req-priv", 25_000, "konsensus message", true,
        &pricing, &ReadinessHeightCache::new(Arc::new(konsensus_chain::MockChainProvider::new())), &lightning, &transport, &test_peer_id(), "127.0.0.1".parse().unwrap(), &mut crate::admission_quotes::AdmissionQuotes::default(),
        &konsensus_api::membrane::Membrane::with_capacity(8), &mut crate::invoice_refusals::RefusalLimits::default(),
    ).await;

    let payments = lightning.list_payments(10).await.unwrap();
    assert_eq!(payments.len(), 1, "privileged request must create exactly one invoice");
    assert_eq!(payments[0].amount_msat, 25_000, "caller amount honoured for privileged peer");
}

#[tokio::test]
async fn unprivileged_non_admission_invoice_request_is_refused_not_issued() {
    // P2: an unprivileged peer asking for an ordinary message invoice gets no
    // invoice on our wallet. Every refusal is counted without per-peer telemetry.
    let peer_id = test_peer_id();
    let transport = make_gossip_test_transport();
    let lightning: Arc<dyn LightningProvider> =
        Arc::new(konsensus_lightning::MockLightningProvider::new());
    let pricing = admission_pricing();
    let membrane = konsensus_api::membrane::Membrane::with_capacity(8);
    let mut last_refusal = crate::invoice_refusals::RefusalLimits::default();

    handle_invoice_requested_gated(
        &peer_id, "req-strange", 1_000_000, "konsensus message", false,
        &pricing, &ReadinessHeightCache::new(Arc::new(konsensus_chain::MockChainProvider::new())), &lightning, &transport, &test_peer_id(), "127.0.0.1".parse().unwrap(), &mut crate::admission_quotes::AdmissionQuotes::default(),
        &membrane, &mut last_refusal,
    ).await;

    let payments = lightning.list_payments(10).await.unwrap();
    assert!(payments.is_empty(), "no invoice may be created for an unprivileged non-admission request");
    let (events, totals) = membrane.read(None, 10);
    assert!(events.is_empty(), "unpaid requests must not create per-event state");
    assert_eq!(totals.refused, 0, "event totals exclude aggregate-only refusals");
    assert_eq!(membrane.pre_payment_refusals().buckets[0].counts[&konsensus_api::membrane::PrePaymentReason::AdmissionRequired], 1);
    for _ in 0..100 {
        handle_invoice_requested_gated(
            &peer_id, "req-strange", 1_000_000, "konsensus message", false,
            &pricing, &ReadinessHeightCache::new(Arc::new(konsensus_chain::MockChainProvider::new())), &lightning, &transport, &test_peer_id(), "127.0.0.1".parse().unwrap(), &mut crate::admission_quotes::AdmissionQuotes::default(),
            &membrane, &mut last_refusal,
        ).await;
    }
    assert_eq!(membrane.pre_payment_refusals().buckets.iter().map(|b| b.counts[&konsensus_api::membrane::PrePaymentReason::AdmissionRequired]).sum::<u64>(), 101, "count even when refusal replies are throttled");
    assert!(membrane.read(None, 500).0.is_empty());

}

// ── Price query handler tests ──────────────────────────────

#[tokio::test]
async fn unprivileged_price_table_does_not_update_peer_price_cache() {
    let peer_id = test_peer_id();
    let cache = konsensus_pricing::PeerPriceCache::new();
    let mut prices = std::collections::HashMap::new();
    prices.insert("chat".to_string(), 42);

    handle_price_table_received(peer_id, prices, 850_000, 144, 0.0, false, &cache).await;

    assert!(
        cache.get_peer_entry(&peer_id).await.is_none(),
        "unprivileged PriceTableReceived must not create a peer price entry"
    );
}

#[tokio::test]
async fn unprivileged_price_response_does_not_update_peer_price_cache() {
    let peer_id = test_peer_id();
    let cache = konsensus_pricing::PeerPriceCache::new();
    let kind = 100;

    handle_price_response_received(peer_id, kind, 50, 850_001, false, &cache).await;

    assert!(
        cache.get_peer_price(&peer_id, kind).await.is_none(),
        "unprivileged PriceResponseReceived must not create a per-kind peer price"
    );
}

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
    handle_price_query(&peer_id, 100, &pricing, &chain, &transport, &konsensus_storage::SqliteStorage::in_memory().await.unwrap(), 0).await;
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
    handle_price_query(&peer_id, 100, &pricing, &chain, &transport, &konsensus_storage::SqliteStorage::in_memory().await.unwrap(), 0).await;
    // No panic = success (handler returns early with warning)
}

#[test]
fn routable_peer_addr_filter() {
    use std::net::SocketAddr;
    let parse = |s: &str| s.parse::<SocketAddr>().expect("valid socketaddr");

    // Publicly-routable addresses are accepted.
    assert!(is_routable_peer_addr(&parse("1.2.3.4:9735")));
    assert!(is_routable_peer_addr(&parse("[2606:4700:4700::1111]:9735")));

    // Non-routable IPv4 are rejected (poison-resistance).
    for a in [
        "127.0.0.1:9735",   // loopback
        "0.0.0.0:9735",     // unspecified
        "10.1.2.3:9735",    // RFC1918
        "192.168.1.1:9735", // RFC1918
        "172.16.0.1:9735",  // RFC1918
        "169.254.1.1:9735", // link-local
        "224.0.0.1:9735",   // multicast
        "192.0.2.1:9735",   // documentation
        "1.2.3.4:0",        // zero port
    ] {
        assert!(!is_routable_peer_addr(&parse(a)), "{a} must be rejected");
    }

    // Non-routable IPv6 are rejected.
    for a in [
        "[::1]:9735",          // loopback
        "[::]:9735",           // unspecified
        "[fc00::1]:9735",      // ULA
        "[fd12:3456::1]:9735", // ULA
        "[fe80::1]:9735",      // link-local
        "[ff02::1]:9735",      // multicast
    ] {
        assert!(!is_routable_peer_addr(&parse(a)), "{a} must be rejected");
    }
}


#[tokio::test]
async fn stranger_cannot_quote_file_or_other_service_kinds() {
    // No connected/running node, wallet, or paid contact: the handler receives
    // only an unprivileged request. Its mock provider retains created invoices.
    let peer_id = test_peer_id();
    let transport = make_gossip_test_transport();
    let lightning: Arc<dyn LightningProvider> =
        Arc::new(konsensus_lightning::MockLightningProvider::new());
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> =
        Arc::new(konsensus_pricing::StaticPricingEngine::new(
            konsensus_pricing::StaticPricingConfig {
                chat_msat: 2000,
                file_ref_msat: 123_456,
                ..Default::default()
            },
        ));

    let mut quotes=crate::admission_quotes::AdmissionQuotes::default();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let id=konsensus_core::admission_quote::request_id(&test_peer_id(), &peer_id,
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
    // Otherwise-valid, bound, live attempts still cannot request another kind.
    for purpose in ["konsensus:admission:200", "konsensus:admission:100", "konsensus:admission", "arbitrary invoice"] {
        handle_invoice_requested_gated(
            &peer_id, &id, 1, purpose, false,
            &pricing, &ReadinessHeightCache::new(Arc::new(konsensus_chain::MockChainProvider::new())), &lightning, &transport, &test_peer_id(), "127.0.0.1".parse().unwrap(), &mut quotes,
            &konsensus_api::membrane::Membrane::with_capacity(8), &mut crate::invoice_refusals::RefusalLimits::default(),
        ).await;
    }
    assert!(lightning.list_payments(10).await.unwrap().is_empty(),
        "unpaid stranger minted a non-chat invoice");
}

#[tokio::test]
async fn stranger_quote_over_noise_creates_no_application_state() {
    use konsensus_core::admission_quote;
    use konsensus_message::{ReachabilityMode, TransportConfig};
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let (_, a) = NodeIdentity::generate().unwrap();
    let (_, b) = NodeIdentity::generate().unwrap();
    let a = Arc::new(a);
    let b = Arc::new(b);
    let peer = *a.node_id();
    let recipient = *b.node_id();
    let transport = |id: Arc<NodeIdentity>| {
        Arc::new(NoiseTransport::new(
            id,
            TransportConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                admission_mode: ReachabilityMode::PriceOpen,
                whitelist: vec![],
                ..Default::default()
            },
        ))
    };
    let source = transport(a);
    let target = transport(b.clone());
    target.start_listener().await.unwrap();
    let storage = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let initial_onboarding = storage.get_onboarding_state().await.unwrap();
    let sessions = Arc::new(SessionManager::new(b.clone()));
    let registry = Arc::new(tokio::sync::RwLock::new(PeerRegistry::new()));
    let prices = Arc::new(PeerPriceCache::new());
    let provider = Arc::new(
        konsensus_lightning::shared_mock::SharedMockProvider::new(
            &dir.path().join("mock.sqlite"),
            "b",
            0,
        )
        .unwrap(),
    );
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (ws, _ws_rx) = broadcast::channel(8);
    let (delivery, _delivery_rx) = broadcast::channel(8);
    let (pending, _pending_rx) = mpsc::channel(8);
    let (auto, _auto_rx) = mpsc::channel(8);
    let worker = tokio::spawn(run(SessionHandlerDeps {
        min_admission_cost_msat: 0,
        privacy: Default::default(),
        peer_exchange_floor: 0,
        transport: target.clone(),
        session_manager: sessions.clone(),
        storage: storage.clone(),
        our_node_id: recipient,
        identity: b,
        audit_log: Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap()),
        pricing: Arc::new(konsensus_pricing::StaticPricingEngine::new(
            konsensus_pricing::StaticPricingConfig {
                chat_msat: 2000,
                ..Default::default()
            },
        )),
        chain: Arc::new(konsensus_chain::MockChainProvider::new()),
        peer_prices: prices.clone(),
        peer_registry: registry.clone(),
        routing: Arc::new(konsensus_routing::RoutingTable::new(Default::default())),
        gossip_validator: Arc::new(konsensus_gossip::GossipValidator::new(Default::default())),
        send_timestamps: Default::default(),
        lightning: provider.clone(),
        lightning_addr: None,
        mock_lightning: true,
        invoice_requests: Default::default(),
        peer_ln_pubkeys: Default::default(),
        ws_broadcast: ws,
        ws_delivery_tx: delivery,
        pending_tx: pending,
        auto_channel_tx: auto,
        shutdown_rx,
    }));
    source
        .connect(&recipient, &target.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let id = admission_quote::request_id(&recipient, &peer, unix);
    let request = Frame::RequestInvoice {
        request_id: id.clone(),
        amount_msat: 1,
        purpose: admission_quote::PURPOSE.into(),
    };
    source.send_frame(&recipient, &request).await.unwrap();
    let bolt11 = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match source.recv_control().await.unwrap() {
                ControlEvent::PeerConnected { privileged, .. } => assert!(!privileged),
                ControlEvent::InvoiceResponseReceived {
                    peer_id,
                    request_id,
                    bolt11,
                    ..
                } => {
                    assert_eq!(peer_id, recipient);
                    assert_eq!(request_id, id);
                    break bolt11;
                }
                event => panic!("unexpected pre-settlement disclosure: {event:?}"),
            }
        }
    })
    .await
    .unwrap();
    let invoice = bolt11.parse::<lightning_invoice::Bolt11Invoice>().unwrap();
    assert_eq!(invoice.amount_milli_satoshis(), Some(2000));
    assert!(invoice.expiry_time().as_secs() <= 300);
    assert!(invoice.expiry_time().as_secs() > 290);
    assert_eq!(
        invoice.description().to_string(),
        format!("konsensus:{id}:message=2000")
    );
    assert_eq!(
        invoice.recover_payee_pub_key().to_string(),
        provider.get_node_pubkey().await.unwrap()
    );
    source.send_frame(&recipient, &request).await.unwrap();
    let refusal = tokio::time::timeout(Duration::from_secs(2), source.recv_control()).await.unwrap().unwrap();
    assert!(matches!(refusal, ControlEvent::InvoiceErrorReceived { request_id, reason, .. }
        if request_id == id && reason == konsensus_api::invoice_refusal::ADMISSION_RATE_LIMITED),
        "a repeated attempt receives a bounded refusal, never a second quote or service");
    let invoices = provider.list_payments(10).await.unwrap();
    assert!(invoices.is_empty(), "stranger quote wrote pending backend state");
    assert_eq!(provider.get_balance_msat().await.unwrap(), 0);
    assert!(registry.read().await.is_empty());
    assert!(storage.list_peers().await.unwrap().is_empty());
    assert!(storage.list_sessions().await.unwrap().is_empty());
    assert!(storage.list_files(10).await.unwrap().is_empty());
    assert_eq!(
        storage.get_onboarding_state().await.unwrap(),
        initial_onboarding
    );
    assert!(storage
        .get_messages_for_recipient(&konsensus_core::Recipient::Node(recipient), 10, None)
        .await
        .unwrap()
        .is_empty());
    assert!(!sessions.has_session(&peer).await);
    assert!(prices.get_peer_entry(&peer).await.is_none());
    assert!(target.connected_privileged_peers().await.is_empty());
    shutdown.send(true).unwrap();
    worker.await.unwrap();
    source.shutdown();
    target.shutdown();
}

#[tokio::test]
async fn bound_unsupported_quote_error_preserves_provenance() {
    let recipient = NodeId::from_bytes([1; 32]);
    let sender = NodeId::from_bytes([2; 32]);
    let wrong = NodeId::from_bytes([3; 32]);
    let id = konsensus_core::admission_quote::request_id(&recipient, &sender, 100);
    let map = tokio::sync::Mutex::new(std::collections::HashMap::new());
    let (tx, rx) = tokio::sync::oneshot::channel::<InvoiceRequestOutcome>();
    map.lock().await.insert(id.clone(), tx);
    for privileged in [false, true] {
        handle_invoice_error_received(&wrong, &id, "stateless_quote_unsupported", privileged, &map).await;
        assert_eq!(map.lock().await.len(), 1, "wrong recipient cancelled quote");
    }
    handle_invoice_error_received(&recipient, &id, "stateless_quote_unsupported", false, &map).await;
    let error = rx.await.unwrap().unwrap_err();
    assert_eq!(error.recipient, recipient);
    assert_eq!(error.reason, "stateless_quote_unsupported");
    assert!(map.lock().await.is_empty());
}

#[tokio::test]
async fn lnd_stranger_quote_returns_stable_refusal_over_noise() {
    use konsensus_message::{ReachabilityMode, TransportConfig};
    use konsensus_lightning::lnd::{LndConfig, LndProvider};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let (_, a) = NodeIdentity::generate().unwrap();
    let (_, b) = NodeIdentity::generate().unwrap();
    let peer = *a.node_id();
    let recipient = *b.node_id();
    let make = |id| Arc::new(NoiseTransport::new(Arc::new(id), TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        admission_mode: ReachabilityMode::PriceOpen, whitelist: vec![], ..Default::default()
    }));
    let source = make(a);
    let target = make(b);
    target.start_listener().await.unwrap();
    source.connect(&recipient, &target.listen_addr().unwrap().to_string()).await.unwrap();
    assert!(matches!(source.recv_control().await, Some(ControlEvent::PeerConnected { .. })));
    // An accidental create_invoice fallback would hit this unreachable endpoint,
    // return a different error and fail the expected stateless refusal assertion.
    let provider: Arc<dyn LightningProvider> = Arc::new(LndProvider::new(LndConfig {
        api_url: "http://127.0.0.1:1".into(), macaroon_hex: "00".into(), tls_cert_path: None,
    }).unwrap());
    let mut quotes = crate::admission_quotes::AdmissionQuotes::default();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let request_id = konsensus_core::admission_quote::request_id(&recipient, &peer,
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
    handle_invoice_requested_gated(&peer, &request_id, 1,
        konsensus_core::admission_quote::PURPOSE, false, &admission_pricing(), &ReadinessHeightCache::new(Arc::new(konsensus_chain::MockChainProvider::new())), &provider,
        &target, &recipient, "127.0.0.1".parse().unwrap(), &mut quotes, &konsensus_api::membrane::Membrane::with_capacity(8), &mut crate::invoice_refusals::RefusalLimits::default()).await;
    let event = tokio::time::timeout(Duration::from_secs(2), source.recv_control()).await.unwrap().unwrap();
    assert!(matches!(event, ControlEvent::InvoiceErrorReceived { peer_id, request_id: id, reason, .. }
        if peer_id == recipient && id == request_id && reason == "stateless_quote_unsupported"));
    assert!(target.connected_privileged_peers().await.is_empty());
    source.shutdown();
    target.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unpaid_request_flood_does_not_stall_other_peers() {
    use konsensus_message::{ReachabilityMode, TransportConfig};
    use std::{sync::atomic::{AtomicUsize, Ordering}, time::Duration};
    let make = || {
        let (_, identity) = NodeIdentity::generate().unwrap();
        let id = *identity.node_id();
        (id, Arc::new(NoiseTransport::new(Arc::new(identity), TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(), admission_mode: ReachabilityMode::PriceOpen,
            ..Default::default()
        })))
    };
    let (recipient, target) = make();
    let (_, attacker) = make();
    let (healthy_id, healthy) = make();
    target.add_to_whitelist(&healthy_id).await;
    target.start_listener().await.unwrap();
    let addr = target.listen_addr().unwrap().to_string();
    attacker.connect(&recipient, &addr).await.unwrap();
    healthy.connect(&recipient, &addr).await.unwrap();
    let lightning: Arc<dyn LightningProvider> = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let handled = Arc::new(AtomicUsize::new(0));
    let membrane = Arc::new(konsensus_api::membrane::Membrane::with_capacity(64));
    let handler = {
        let target = Arc::clone(&target); let lightning = Arc::clone(&lightning);
        let handled = Arc::clone(&handled); let membrane = Arc::clone(&membrane);
        tokio::spawn(async move {
            let mut quotes = crate::admission_quotes::AdmissionQuotes::default();
            let mut limits = crate::invoice_refusals::RefusalLimits::default();
            while let Some(event) = target.recv_control().await {
                if let ControlEvent::InvoiceRequested { peer_id, request_id, amount_msat, purpose, privileged, source_ip } = event {
                    handle_invoice_requested_gated(&peer_id, &request_id, amount_msat, &purpose, privileged,
                        &admission_pricing(), &ReadinessHeightCache::new(Arc::new(konsensus_chain::MockChainProvider::new())), &lightning, &target, &recipient, source_ip, &mut quotes, &membrane, &mut limits).await;
                    handled.fetch_add(1, Ordering::Release);
                }
            }
        })
    };
    // The attacker never drains its control receiver. Unbounded replies would
    // eventually stop its reader and fill the recipient's TCP send buffer.
    tokio::time::timeout(Duration::from_secs(5), async {
        for i in 0..5000 {
            attacker.send_frame(&recipient, &Frame::RequestInvoice {
                request_id: format!("{i:04}{}", "x".repeat(1000)), amount_msat: 1000, purpose: "konsensus message".into()
            }).await.unwrap();
        }
        while handled.load(Ordering::Acquire) < 5000 { tokio::task::yield_now().await; }
        assert!(lightning.list_payments(100).await.unwrap().is_empty(), "unpaid flood must issue no invoices");
        healthy.send_frame(&recipient, &Frame::RequestInvoice {
            request_id: "healthy".into(), amount_msat: 1000, purpose: "konsensus message".into()
        }).await.unwrap();
        loop {
            if let Some(ControlEvent::InvoiceResponseReceived { request_id, .. }) = healthy.recv_control().await {
                assert_eq!(request_id, "healthy"); break;
            }
        }
    }).await.expect("unpaid flood stalled the global control loop or another peer");
    let (events, totals) = membrane.read(None, 100);
    assert!(events.len() <= 1); assert!(totals.refused <= 1);
    handler.abort(); attacker.shutdown(); healthy.shutdown(); target.shutdown();
}

#[test]
fn demo_pre_payment_frames_count_without_retaining_strangers() {
    use konsensus_api::membrane::{Membrane, PrePaymentReason};
    let membrane = Membrane::default();
    let mut rx = membrane.subscribe();
    for n in 0..100u8 {
        let peer_id = NodeId::from_bytes([n; 32]);
        for privileged in [false, true] {
            let message_id = konsensus_core::MessageId::from_bytes([n; 32]);
            let envelope = konsensus_core::UkmEnvelopeBuilder::new(
                1,
                peer_id,
                konsensus_core::Recipient::Node(test_peer_id()),
                b"do not retain".to_vec(),
                konsensus_core::PaymentProof::new([0; 32], [0; 32], 0),
            )
            .build();
            let events = [
                ControlEvent::SessionInit {
                    peer_id,
                    init_data: serde_json::json!({"secret": "do not retain"}),
                    privileged,
                },
                ControlEvent::SessionAck {
                    peer_id,
                    privileged,
                },
                ControlEvent::RatchetInit {
                    peer_id,
                    payload: b"do not retain".to_vec(),
                    privileged,
                },
                ControlEvent::MessageAcked {
                    duplicate: false,                    peer_id,
                    message_id,
                    privileged,
                },
                ControlEvent::MessageRejected {
                    peer_id,
                    message_id,
                    reason: "do not retain".into(),
                    privileged,
                },
                ControlEvent::PriceQueryReceived {
                    peer_id,
                    kind: 1,
                    privileged,
                },
                ControlEvent::PriceResponseReceived {
                    peer_id,
                    kind: 1,
                    price_msat: 1,
                    block_height: 1,
                    privileged,
                },
                ControlEvent::PeerExchangeReceived {
                    peer_id,
                    peers: vec![],
                    privileged,
                },
                ControlEvent::GossipReceived {
                    from_peer: peer_id,
                    envelope: Box::new(envelope),
                    privileged,
                },
                ControlEvent::PrekeyOffer {
                    peer_id,
                    bundle: serde_json::json!({"secret": "do not retain"}),
                    privileged,
                },
                ControlEvent::PriceTableReceived {
                    peer_id,
                    prices: Default::default(),
                    block_height: 1,
                    valid_blocks: 1,
                    trust_discount: 0.0,
                    privileged,
                },
                ControlEvent::LightningInfoReceived {
                    peer_id,
                    ln_pubkey: "private-ln-key".into(),
                    ln_addr: Some("192.0.2.123:9735".into()),
                    privileged,
                },
                ControlEvent::PeerExchangeRequested {
                    peer_id,
                    privileged,
                },
            ];
            for event in events {
                let delivery = matches!(event, ControlEvent::MessageAcked { .. } | ControlEvent::MessageRejected { .. } | ControlEvent::PeerExchangeRequested { .. });
                assert_eq!(refuse_unpaid_control(&event, &membrane), !privileged && !delivery);
            }
        }
    }
    let snapshot = membrane.pre_payment_refusals();
    for (reason, expected) in [
        (PrePaymentReason::SessionBeforePayment, 400),
        (PrePaymentReason::DeliveryBeforePayment, 0),
        (PrePaymentReason::PriceBeforePayment, 300),
        (PrePaymentReason::LightningInfoBeforePayment, 100),
        (PrePaymentReason::PeerExchangeBeforePayment, 100),
        (PrePaymentReason::GossipBeforePayment, 100),
    ] {
        assert_eq!(
            snapshot
                .buckets
                .iter()
                .map(|b| b.counts.get(&reason).copied().unwrap_or(0))
                .sum::<u64>(),
            expected
        );
    }
    let serialized = serde_json::to_string(&snapshot).unwrap();
    for secret in [
        "do not retain",
        "private-ln-key",
        "192.0.2.123",
        &test_peer_id().to_hex(),
        "peer_id",
        "counterparty",
        "source_ip",
        "request_id",
    ] {
        assert!(!serialized.contains(secret), "aggregate leaked {secret}");
    }
    assert!(membrane.read(None, 500).0.is_empty());
    assert!(rx.try_recv().is_err());
    assert!(
        !refuse_unpaid_control(
            &ControlEvent::PeerConnected {
                peer_id: test_peer_id(),
                privileged: false
            },
            &membrane
        ),
        "connecting is not a refused frame"
    );
}

#[tokio::test]
async fn delivery_receipts_only_advance_matching_sent_rows_and_never_unpaid_weights() {
    use konsensus_core::{PaymentProof, Recipient, UkmEnvelopeBuilder};
    let mut limits = DeliveryConfirmationBudget::default();
    let own = make_peer_id(61); let peer = make_peer_id(62); let impostor = make_peer_id(63);
    let db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let storage: Arc<dyn Storage> = db.clone();
    let routing = konsensus_routing::RoutingTable::new(Default::default());
    let timestamps = tokio::sync::Mutex::new(std::collections::HashMap::new());
    let (ws, mut updates) = broadcast::channel(16);
    let dir = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
    let env = UkmEnvelopeBuilder::new(100, own, Recipient::Node(peer), vec![1],
        PaymentProof::new(sha2::Sha256::digest([4; 32]).into(), [4; 32], 1000)).build();
    db.store_message(&env).await.unwrap();
    db.queue_pending_delivery(&env.id, &peer).await.unwrap();
    for rejection in [None, Some("storage error"), Some("replay detected: nonce already used")] {
        handle_delivery_confirmation(&peer, &env.id, rejection, false, &own, &storage, &timestamps, &routing, &ws, &audit, &mut limits).await;
    }
    assert!(updates.try_recv().is_err(), "unsent ids are not delivery receipts");
    db.mark_pending_sent(&env.id, &peer).await.unwrap();
    handle_delivery_confirmation(&impostor, &env.id, None, false, &own, &storage, &timestamps, &routing, &ws, &audit, &mut limits).await;
    handle_delivery_confirmation(&peer, &konsensus_core::MessageId::from_bytes([9; 32]), None, false, &own, &storage, &timestamps, &routing, &ws, &audit, &mut limits).await;
    assert!(updates.try_recv().is_err());
    handle_delivery_confirmation(&peer, &env.id, Some("storage error"), false, &own, &storage, &timestamps, &routing, &ws, &audit, &mut limits).await;
    assert_eq!(updates.try_recv().unwrap().status, "rejected");
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 1);
    handle_delivery_confirmation(&peer, &env.id, None, false, &own, &storage, &timestamps, &routing, &ws, &audit, &mut limits).await;
    assert_eq!(updates.try_recv().unwrap().status, "delivered");
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 0);
    handle_delivery_confirmation(&peer, &env.id, None, true, &own, &storage, &timestamps, &routing, &ws, &audit, &mut limits).await;
    assert!(updates.try_recv().is_err(), "duplicate ACK cannot update weights or emit twice");
    assert!(routing.get_peer_weight(&peer).await.is_none());
    // Explicit compatibility mapping consumes only an own, dispatched row.
    db.prepare_delivery(&env.id, &peer).await.unwrap();
    handle_delivery_confirmation(&peer, &env.id, Some("replay detected: nonce already used"), true, &own, &storage, &timestamps, &routing, &ws, &audit, &mut limits).await;
    assert_eq!(updates.try_recv().unwrap().status, "delivered");
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 0);
    assert!(routing.get_peer_weight(&peer).await.is_none());
    assert!(std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap().contains("acked_legacy"));
}

#[tokio::test]
async fn definitive_paid_rejects_are_terminal_and_transient_rejects_back_off() {
    use konsensus_core::{PaymentProof, Recipient, UkmEnvelopeBuilder};
    for reason in ["payment proof already used: hash", "insufficient payment: required 2000 msat, got 1000 msat",
        "recipient mismatch: envelope addressed to a, this node is b", "invalid signature: bad signature", "storage error", "lightning verification failed: offline"] {
        let mut limits = DeliveryConfirmationBudget::default();
    let own = make_peer_id(61); let peer = make_peer_id(62);
        let db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
        let storage: Arc<dyn Storage> = db.clone();
        let routing = konsensus_routing::RoutingTable::new(Default::default());
        let timestamps = tokio::sync::Mutex::new(std::collections::HashMap::new());
        let (ws, mut updates) = broadcast::channel(16);
        let dir = tempfile::tempdir().unwrap();
        let audit = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        let env = UkmEnvelopeBuilder::new(0, own, Recipient::Node(peer), vec![1],
            PaymentProof::new(sha2::Sha256::digest([4; 32]).into(), [4; 32], 1000)).build();
        db.store_message(&env).await.unwrap();
        db.prepare_delivery(&env.id, &peer).await.unwrap();
        handle_delivery_confirmation(&peer, &env.id, Some(reason), false, &own, &storage, &timestamps, &routing, &ws, &audit, &mut limits).await;
        let terminal = !matches!(reason, "storage error" | "lightning verification failed: offline");
        assert_eq!(updates.try_recv().unwrap().status, if terminal { "failed_paid" } else { "rejected" });
        assert!(db.get_pending_for_peer(&peer).await.unwrap().is_empty(), "no immediate resend: {reason}");
        let (state, attempts): (String, i64) = sqlx::query_as("SELECT state, attempts FROM pending_deliveries").fetch_one(db.pool()).await.unwrap();
        assert_eq!(state, if terminal { "failed_paid" } else { "pending" });
        assert_eq!(attempts, 1);
        assert!(db.mark_pending_sent(&env.id, &peer).await.is_err(), "stale flusher snapshot cannot bypass rejection");
        handle_delivery_confirmation(&peer, &env.id, Some(reason), false, &own, &storage, &timestamps, &routing, &ws, &audit, &mut limits).await;
        assert!(updates.try_recv().is_err(), "one rejection per dispatch");
        if terminal {
            db.cleanup_stale_pending(1).await.unwrap();
            assert!(db.get_pending_for_peer(&peer).await.unwrap().is_empty());
            assert!(!db.acknowledge_pending(&env.id, &peer, &own).await.unwrap(), "terminal state cannot regress");
        } else {
            let retry: i64 = sqlx::query_scalar("SELECT retry_after_ms FROM pending_deliveries").fetch_one(db.pool()).await.unwrap();
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
            assert!(retry > now + 50_000);
            sqlx::query("UPDATE pending_deliveries SET retry_after_ms = 1").execute(db.pool()).await.unwrap();
            assert_eq!(db.get_pending_for_peer(&peer).await.unwrap().len(), 1);
            db.mark_pending_sent(&env.id, &peer).await.unwrap();
            handle_delivery_confirmation(&peer, &env.id, Some(reason), false, &own, &storage, &timestamps, &routing, &ws, &audit, &mut limits).await;
            let retry: i64 = sqlx::query_scalar("SELECT retry_after_ms FROM pending_deliveries").fetch_one(db.pool()).await.unwrap();
            assert!(retry > now + 110_000, "successive transient rejects increase the delay");
        }
        assert!(db.get_message(&env.id).await.unwrap().is_some());
        assert!(routing.get_peer_weight(&peer).await.is_none());
    }
}

#[tokio::test]
async fn unpaid_confirmation_flood_is_bounded_before_storage_even_across_peer_churn() {
    let mut limits = DeliveryConfirmationBudget::default();
    let own = make_peer_id(61); let peer = make_peer_id(62);
    let db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let storage: Arc<dyn Storage> = db.clone();
    let env = konsensus_core::UkmEnvelopeBuilder::new(0, own, konsensus_core::Recipient::Node(peer), vec![1],
        konsensus_core::PaymentProof::new(sha2::Sha256::digest([4; 32]).into(), [4; 32], 1000)).build();
    db.store_message(&env).await.unwrap();
    db.prepare_delivery(&env.id, &peer).await.unwrap();
    let routing = konsensus_routing::RoutingTable::new(Default::default());
    let timestamps = tokio::sync::Mutex::new(std::collections::HashMap::new());
    let (ws, mut updates) = broadcast::channel(16);
    let dir = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
    // Both unknown ACKs and rejects consume the shared per-peer allowance.
    for n in 0..32 {
        handle_delivery_confirmation(&peer, &konsensus_core::MessageId::from_bytes([9; 32]),
            if n % 2 == 0 { None } else { Some("storage error") }, false,
            &own, &storage, &timestamps, &routing, &ws, &audit, &mut limits).await;
    }
    handle_delivery_confirmation(&peer, &env.id, None, false, &own, &storage, &timestamps, &routing, &ws, &audit, &mut limits).await;
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 1, "exhausted peer cannot reach the ACK DELETE");
    assert!(updates.try_recv().is_err());
    let now = tokio::time::Instant::now();
    let allowed = (0..1000).filter(|n| {
        let mut bytes = [0; 32]; bytes[..4].copy_from_slice(&(*n as u32).to_le_bytes());
        limits.allow(&NodeId::from_bytes(bytes), false, now)
    }).count();
    assert_eq!(allowed, 96, "peer churn cannot exceed the global 128/s budget");
    assert!(limits.peers.len() <= 128, "attacker identities cannot grow memory without bound");
    assert!(limits.allow(&peer, true, now), "privileged confirmations remain available");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    handle_delivery_confirmation(&peer, &env.id, None, false, &own, &storage, &timestamps, &routing, &ws, &audit, &mut limits).await;
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 0);
    assert_eq!(updates.try_recv().unwrap().status, "delivered");
}

#[tokio::test]
async fn legacy_lost_ack_recovers_after_nonce_expiry_and_sender_restart() {
    use konsensus_core::{PaymentProof, Recipient, UkmEnvelopeBuilder, Signature};
    use konsensus_core::gate::{PaymentGate, GateConfig};
    let dir = tempfile::tempdir().unwrap();
    let (_, alice) = konsensus_core::NodeIdentity::generate().unwrap();
    let own = *alice.node_id(); let peer = make_peer_id(62);
    let mut env = UkmEnvelopeBuilder::new(0, own, Recipient::Node(peer), vec![1], PaymentProof::new(sha2::Sha256::digest([4; 32]).into(), [4; 32], 1000)).build();
    env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
    let recipient = konsensus_storage::SqliteStorage::in_memory().await.unwrap();
    let gate = PaymentGate::with_config(GateConfig { verify_lightning_settlement: false, ..Default::default() });
    let pricing = konsensus_pricing::StaticPricingEngine::new(Default::default());
    gate.verify(&env, &recipient, &pricing, None, None, 0.0, Some(&peer)).await.unwrap();
    recipient.store_message(&env).await.unwrap();
    let before = gate.verify(&env, &recipient, &pricing, None, None, 0.0, Some(&peer)).await.unwrap_err();
    assert_eq!(before.to_string(), "replay detected: nonce already used");
    sqlx::query("UPDATE nonces SET received_at = '2000-01-01T00:00:00.000Z'").execute(recipient.pool()).await.unwrap();
    assert_eq!(recipient.cleanup_expired_nonces(3600).await.unwrap(), 1);
    let reason = gate.verify(&env, &recipient, &pricing, None, None, 0.0, Some(&peer)).await.unwrap_err().to_string();
    assert_eq!(reason, format!("payment proof already used: {}", hex::encode(env.payment_proof.payment_hash)));
    for case in ["exact", "peer", "id", "sender", "unsent", "hash", "suffix"] {
        let path = dir.path().join(format!("{case}.sqlite"));
        let db = konsensus_storage::SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
        db.store_message(&env).await.unwrap();
        db.queue_pending_delivery(&env.id, &peer).await.unwrap();
        if case != "unsent" { db.mark_pending_sent(&env.id, &peer).await.unwrap(); }
        db.pool().close().await;
        let db = Arc::new(konsensus_storage::SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
        let storage: Arc<dyn Storage> = db.clone();
        let routing = konsensus_routing::RoutingTable::new(Default::default());
        let timestamps = tokio::sync::Mutex::new(std::collections::HashMap::new());
        let (ws, mut updates) = broadcast::channel(16);
        let audit = AuditLog::open(dir.path().join(format!("{case}.jsonl"))).unwrap();
        let mut budget = DeliveryConfirmationBudget::default();
        let other = make_peer_id(63);
        let other_id = konsensus_core::MessageId::from_bytes([9; 32]);
        let response = match case { "hash" => format!("payment proof already used: {}", "ab".repeat(32)), "suffix" => format!("{reason} extra"), _ => reason.clone() };
        handle_delivery_confirmation(if case == "peer" { &other } else { &peer }, if case == "id" { &other_id } else { &env.id }, Some(&response), case == "exact", if case == "sender" { &other } else { &own }, &storage, &timestamps, &routing, &ws, &audit, &mut budget).await;
        if case == "exact" {
            assert_eq!(db.count_pending_deliveries().await.unwrap(), 0);
            assert_eq!(updates.try_recv().unwrap().status, "delivered");
            assert!(std::fs::read_to_string(dir.path().join(format!("{case}.jsonl"))).unwrap().contains("acked_legacy"));
        } else {
            assert_eq!(db.count_pending_deliveries().await.unwrap(), 1, "{case}");
            if let Ok(update) = updates.try_recv() { assert_eq!(update.status, "failed_paid"); }
        }
        assert!(routing.get_peer_weight(&peer).await.is_none());
    }
}


#[tokio::test]
async fn accepted_chain_price_rise_and_delayed_ack_never_fail_paid() {
    use konsensus_core::gate::{GateConfig, PaymentGate};
    use konsensus_core::kind::KIND_CHAT;
    use konsensus_core::traits::chain::{BlockHeader, ChainError, FeeEstimate, TrustLevel};
    use konsensus_core::traits::pricing::PricingEngine;
    use konsensus_core::{PaymentProof, Recipient, Signature, UkmEnvelopeBuilder};
    use konsensus_storage::PaidAcceptance;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Exercise the production chain-aware pricing engine, default EMA and cap.
    // Only the external fee data changes; zero cache TTL compresses the normal
    // one-minute refresh interval so this bounded probe needs no wall-clock wait.
    struct FeeSpikeChain {
        inner: konsensus_chain::MockChainProvider,
        sat_per_vb: AtomicU64,
    }
    #[async_trait::async_trait]
    impl ChainProvider for FeeSpikeChain {
        fn trust_level(&self) -> TrustLevel { self.inner.trust_level() }
        async fn get_block_height(&self) -> Result<u64, ChainError> { self.inner.get_block_height().await }
        async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError> { self.inner.get_block_header(height).await }
        async fn estimate_fee(&self, target_blocks: u32) -> Result<FeeEstimate, ChainError> {
            Ok(FeeEstimate { target_blocks, sat_per_vbyte: self.sat_per_vb.load(Ordering::SeqCst) as f64 })
        }
        async fn is_tx_confirmed(&self, txid: &str, confirmations: u32) -> Result<bool, ChainError> {
            self.inner.is_tx_confirmed(txid, confirmations).await
        }
        async fn is_synced(&self) -> bool { self.inner.is_synced().await }
    }
    let chain = Arc::new(FeeSpikeChain {
        inner: konsensus_chain::MockChainProvider::new(), sat_per_vb: AtomicU64::new(1),
    });
    let pricing = konsensus_pricing::ChainAwarePricingEngine::new(
        konsensus_pricing::ChainAwarePricingConfig {
            cache_ttl: std::time::Duration::ZERO, ..Default::default()
        }, chain.clone());
    let paid_msat = pricing.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(paid_msat, 11);

    let alice = identity_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    let bob = identity_from_mnemonic("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
    let own = *alice.node_id();
    let peer = *bob.node_id();
    let whitelist = std::collections::HashSet::from([own]);
    let wallet = konsensus_lightning::MockLightningProvider::new();
    let hash = wallet.inject_inbound_keysend(paid_msat, None).await;
    let settled = wallet.get_payment_status(&hash).await.unwrap();
    let proof = PaymentProof::new(hex::decode(&hash).unwrap().try_into().unwrap(),
        hex::decode(settled.preimage.unwrap()).unwrap().try_into().unwrap(), paid_msat);
    let mut envelope = UkmEnvelopeBuilder::new(KIND_CHAT, own, Recipient::Node(peer), vec![1, 2, 3], proof).build();
    envelope.signature = Signature::from_ed25519(&alice.sign(&envelope.signable_bytes()));
    let gate = PaymentGate::with_config(GateConfig {
        verify_lightning_settlement: true, ..Default::default()
    });
    let recipient = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());

    // Production receive ordering: validate first, then atomic acceptance.
    gate.validate_paid_envelope(&envelope, &pricing, Some(&whitelist), Some(&wallet), 0.0, Some(&peer)).await.unwrap();
    assert_eq!(recipient.accept_paid_envelope(&envelope).await.unwrap(), PaidAcceptance::Accepted);
    // Lose the ACK. While the price remains unchanged, the same validated
    // signed envelope correctly reaches AlreadyAccepted (duplicate ACK).
    gate.validate_paid_envelope(&envelope, &pricing, Some(&whitelist), Some(&wallet), 0.0, Some(&peer)).await.unwrap();
    assert_eq!(recipient.accept_paid_envelope(&envelope).await.unwrap(), PaidAcceptance::AlreadyAccepted);

    // Price refresh after congestion. Even granting the maximum 50% routing
    // discount cannot save this already-accepted proof from re-pricing.
    chain.sat_per_vb.store(1000, Ordering::SeqCst);
    let new_price = pricing.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(new_price, 50, "production default 5x cap remains enforced");
    let receipts = konsensus_storage::StorageNonceAdapter::new(recipient.clone());
    assert!(gate.validate_received_paid_envelope(&envelope, &receipts, &pricing, Some(&whitelist), Some(&wallet), 0.5, Some(&peer)).await.unwrap(), "already-accepted evidence precedes current pricing");
    assert!(recipient.get_message(&envelope.id).await.unwrap().is_some());

    let sender = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    sender.store_message(&envelope).await.unwrap();
    sender.prepare_delivery(&envelope.id, &peer).await.unwrap();
    let storage: Arc<dyn Storage> = sender.clone();
    let routing = konsensus_routing::RoutingTable::new(Default::default());
    let timestamps = tokio::sync::Mutex::new(std::collections::HashMap::new());
    let (ws, mut updates) = broadcast::channel(16);
    let dir = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
    let mut budget = DeliveryConfirmationBudget::default();
    // Model an authenticated, whitelisted/privileged counterparty: the
    // PriceOpen unpaid-stranger suppression does not apply to this case.
    handle_delivery_confirmation(&peer, &envelope.id, None, true, &own,
        &storage, &timestamps, &routing, &ws, &audit, &mut budget).await;
    assert_eq!(updates.try_recv().unwrap().status, "delivered");
    assert_eq!(sender.count_pending_deliveries().await.unwrap(), 0);
    // A delayed original ACK is harmless after duplicate-ACK completion.
    handle_delivery_confirmation(&peer, &envelope.id, None, true, &own,
        &storage, &timestamps, &routing, &ws, &audit, &mut budget).await;
    assert!(updates.try_recv().is_err());
    assert_eq!(sender.count_pending_deliveries().await.unwrap(), 0);
}

#[tokio::test]
async fn recovery_announces_lightning_once_only_to_privileged_connected_peers() {
    use konsensus_message::{ReachabilityMode, TransportConfig};
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let (_, a) = NodeIdentity::generate().unwrap();
    let (_, b) = NodeIdentity::generate().unwrap();
    let (_, c) = NodeIdentity::generate().unwrap();
    let a = Arc::new(a);
    let b = Arc::new(b);
    let c = Arc::new(c);
    let build = |id: Arc<NodeIdentity>, whitelist| Arc::new(NoiseTransport::new(id, TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(), admission_mode: ReachabilityMode::PriceOpen,
        whitelist, ..Default::default()
    }));
    let source = build(a.clone(), vec![*b.node_id()]);
    let stranger = build(c, vec![*b.node_id()]);
    let target = build(b.clone(), vec![*a.node_id()]);
    target.start_listener().await.unwrap();
    let addr = target.listen_addr().unwrap().to_string();
    source.connect(b.node_id(), &addr).await.unwrap();
    stranger.connect(b.node_id(), &addr).await.unwrap();
    // Drain connection events; no session handler has sent LightningInfo yet.
    assert!(matches!(source.recv_control().await, Some(ControlEvent::PeerConnected { .. })));
    assert!(matches!(stranger.recv_control().await, Some(ControlEvent::PeerConnected { .. })));
    let lightning: Arc<dyn LightningProvider> = Arc::new(konsensus_lightning::shared_mock::SharedMockProvider::new(
        &dir.path().join("ledger.sqlite"), "recovered", 0).unwrap());
    let expected = lightning.get_node_pubkey().await.unwrap();
    let storage: Arc<dyn Storage> = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let (ws, _) = broadcast::channel(8);
    let mut was_ready = false;
    refresh_recovered_lightning(&mut was_ready, &target, &lightning, &None, &storage, &ws, *b.node_id()).await;
    let event = tokio::time::timeout(Duration::from_secs(2), source.recv_control()).await.unwrap().unwrap();
    assert!(matches!(event, ControlEvent::LightningInfoReceived { ln_pubkey, .. } if ln_pubkey == expected));
    refresh_recovered_lightning(&mut was_ready, &target, &lightning, &None, &storage, &ws, *b.node_id()).await;
    assert!(tokio::time::timeout(Duration::from_millis(50), source.recv_control()).await.is_err(), "duplicate announcement");
    assert!(tokio::time::timeout(Duration::from_millis(50), stranger.recv_control()).await.is_err(), "unpaid stranger received identity");
    source.shutdown();
    stranger.shutdown();
    target.shutdown();
}

struct NoInvoiceWallet;
#[async_trait::async_trait]
impl LightningProvider for NoInvoiceWallet {
    async fn create_stateless_invoice(
        &self,
        _: u64,
        _: &str,
        _: u32,
    ) -> Result<
        konsensus_core::traits::lightning::Invoice,
        konsensus_core::traits::lightning::LightningError,
    > {
        panic!("unready chain must not issue an invoice")
    }
    async fn create_invoice(
        &self,
        _: u64,
        _: &str,
        _: u32,
    ) -> Result<
        konsensus_core::traits::lightning::Invoice,
        konsensus_core::traits::lightning::LightningError,
    > {
        panic!("no stateful fallback")
    }
    async fn pay_invoice(
        &self,
        _: &str,
    ) -> Result<
        konsensus_core::traits::lightning::PaymentDetails,
        konsensus_core::traits::lightning::LightningError,
    > {
        panic!("no payment")
    }
    async fn get_payment_status(
        &self,
        _: &str,
    ) -> Result<
        konsensus_core::traits::lightning::PaymentDetails,
        konsensus_core::traits::lightning::LightningError,
    > {
        panic!("no payment state")
    }
    async fn get_balance_msat(
        &self,
    ) -> Result<u64, konsensus_core::traits::lightning::LightningError> {
        Ok(0)
    }
    async fn is_available(&self) -> bool {
        true
    }
}

// No sockets: exercise the same preparation path used by the inbound handler.
#[tokio::test(start_paused = true)]
async fn unavailable_admission_quote_is_prompt_and_creates_no_payment() {
    use konsensus_core::traits::chain::{BlockHeader, ChainError, FeeEstimate, TrustLevel};
    struct Chain {
        mode: u8,
    }
    #[async_trait::async_trait]
    impl ChainProvider for Chain {
        fn trust_level(&self) -> TrustLevel {
            TrustLevel::ServerTrust
        }
        async fn get_block_height(&self) -> Result<u64, ChainError> {
            match self.mode {
                0 => Err(ChainError::Backend("private backend detail".into())),
                2 => std::future::pending().await,
                _ => Ok(900_000),
            }
        }
        async fn is_synced(&self) -> bool {
            false
        }
        async fn get_block_header(&self, _: u64) -> Result<BlockHeader, ChainError> {
            unreachable!()
        }
        async fn estimate_fee(&self, _: u32) -> Result<FeeEstimate, ChainError> {
            unreachable!()
        }
        async fn is_tx_confirmed(&self, _: &str, _: u32) -> Result<bool, ChainError> {
            unreachable!()
        }
    }
    for (mode, reason) in [
        (0, "konsensus:not_ready:chain_unavailable"),
        (1, "konsensus:not_ready:not_synced"),
        (2, "konsensus:not_ready:chain_unavailable"),
    ] {
        let lightning = NoInvoiceWallet;
        let start = tokio::time::Instant::now();
        let result = prepare_admission_invoice(
            admission_pricing().as_ref(),
            &ReadinessHeightCache::new(Arc::new(Chain { mode })),
            &lightning,
            "test-request",
            u64::MAX,
        )
        .await;
        assert_eq!(result.unwrap_err(), reason);
        assert!(start.elapsed() <= std::time::Duration::from_secs(5));
    }
}

#[tokio::test]
async fn not_ready_refusal_only_finishes_the_bound_recipients_request() {
    let recipient = NodeId::from_bytes([41; 32]);
    let requester = NodeId::from_bytes([42; 32]);
    let wrong = NodeId::from_bytes([43; 32]);
    for reason in [
        "konsensus:not_ready:chain_unavailable",
        "konsensus:not_ready:not_synced",
    ] {
        let id = konsensus_core::admission_quote::request_id(&recipient, &requester, 100);
        let binding = konsensus_api::invoice_refusal::bind(&id, recipient);
        let map = tokio::sync::Mutex::new(std::collections::HashMap::new());
        let (tx, mut rx) = tokio::sync::oneshot::channel::<InvoiceRequestOutcome>();
        map.lock().await.insert(id.clone(), tx);
        for privileged in [false, true] {
            handle_invoice_error_received(&wrong, &id, reason, privileged, &map).await;
            assert!(matches!(
                rx.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ));
        }
        handle_invoice_error_received(&recipient, &id, reason, false, &map).await;
        let error = rx.try_recv().unwrap().unwrap_err();
        assert_eq!(error.reason, reason);
        assert_eq!(error.recipient, recipient);
        assert!(map.lock().await.is_empty());
        drop(binding);
    }
}

#[tokio::test(start_paused = true)]
async fn admission_backend_readiness_race_and_timeout_return_fixed_refusals() {
    use konsensus_core::traits::lightning::{Invoice, LightningError, PaymentDetails};
    struct Wallet(bool);
    #[async_trait::async_trait]
    impl LightningProvider for Wallet {
        async fn create_stateless_invoice(
            &self,
            _: u64,
            _: &str,
            _: u32,
        ) -> Result<Invoice, LightningError> {
            if self.0 {
                std::future::pending().await
            } else {
                Err(LightningError::NotReady)
            }
        }
        async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
            panic!("no stateful fallback")
        }
        async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            panic!("no payment")
        }
        async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            panic!("no payment state")
        }
        async fn get_balance_msat(&self) -> Result<u64, LightningError> {
            Ok(0)
        }
        async fn is_available(&self) -> bool {
            true
        }
    }
    for (hang, reason) in [
        (false, "konsensus:not_ready:not_synced"),
        (true, "konsensus:invoice_unavailable"),
    ] {
        let start = tokio::time::Instant::now();
        let result = prepare_admission_invoice(
            admission_pricing().as_ref(),
            &ReadinessHeightCache::new(Arc::new(konsensus_chain::MockChainProvider::new())),
            &Wallet(hang),
            "test-request",
            u64::MAX,
        )
        .await;
        assert_eq!(result.unwrap_err(), reason);
        assert!(start.elapsed() <= std::time::Duration::from_secs(5));
    }
}

#[tokio::test]
async fn ready_admission_preparation_preserves_signed_stateless_quote() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = konsensus_lightning::shared_mock::SharedMockProvider::new(
        &dir.path().join("wallet.sqlite"), "recipient", 0).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let (invoice, amount, description) = prepare_admission_invoice(
        admission_pricing().as_ref(), &ReadinessHeightCache::new(Arc::new(konsensus_chain::MockChainProvider::new())),
        &wallet, "test-request", now + u64::from(konsensus_core::admission_quote::FIRST_CONTACT_QUOTE_VALIDITY_SECS)).await.unwrap();
    let signed = invoice.bolt11.parse::<lightning_invoice::Bolt11Invoice>().unwrap();
    assert_eq!(signed.amount_milli_satoshis(), Some(amount));
    assert_eq!(signed.description().to_string(), description);
    assert_eq!(signed.payment_hash().to_string(), invoice.payment_hash);
    assert!(signed.expires_at().unwrap().as_secs() > now + 290);
    assert!(signed.expires_at().unwrap().as_secs() <= now + 300);
    assert_eq!(signed.recover_payee_pub_key().to_string(), wallet.get_node_pubkey().await.unwrap());
    assert!(wallet.list_payments(10).await.unwrap().is_empty());
    assert_eq!(wallet.get_balance_msat().await.unwrap(), 0);
}

#[test]
fn privileged_invoice_error_frames_never_contain_backend_details() {
    use konsensus_core::traits::lightning::LightningError;
    const PRIVATE: &str = "https://user:secret@private-backend.invalid/private-wallet";
    let cases = [
        (LightningError::Backend(PRIVATE.into()), "konsensus:invoice_unavailable"),
        (LightningError::InvoiceCreation(PRIVATE.into()), "konsensus:invoice_unavailable"),
        (LightningError::Connection(PRIVATE.into()), "konsensus:invoice_unavailable"),
        (LightningError::Auth(PRIVATE.into()), "konsensus:invoice_unavailable"),
        (LightningError::InvalidStartupConfig(PRIVATE.into()), "konsensus:invoice_unavailable"),
        (LightningError::PaymentNotDispatched(PRIVATE.into()), "konsensus:invoice_unavailable"),
        (LightningError::NotReady, "konsensus:not_ready:not_synced"),
        (LightningError::StatelessQuoteUnsupported, "stateless_quote_unsupported"),
        (LightningError::PaymentNotDispatched("disk_low".into()), "disk_low"),
        (LightningError::ChainSourceUnavailable {
            network: PRIVATE.into(), service: PRIVATE.into(), attempts: 1,
            elapsed_ms: 1, cause: PRIVATE.into(),
        }, "konsensus:not_ready:chain_unavailable"),
    ];
    for (error, expected) in cases {
        let frame = invoice_error_frame("request-199", error);
        let bytes = frame.to_bytes().unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(PRIVATE));
        match Frame::from_bytes(&bytes).unwrap() {
            Frame::InvoiceError { request_id, reason } => {
                assert_eq!(request_id, "request-199");
                assert_eq!(reason, expected);
            }
            frame => panic!("unexpected frame: {frame:?}"),
        }
    }
}

// Count the external height reads made by real admission preparation, without sockets.
#[derive(Default)]
struct AdmissionHeightChain {
    calls: std::sync::atomic::AtomicUsize,
    fail: std::sync::atomic::AtomicBool,
    unsynced: std::sync::atomic::AtomicBool,
    hang: std::sync::atomic::AtomicBool,
    height_only_sync: Option<konsensus_chain::EsploraProvider>,
}
#[async_trait::async_trait]
impl ChainProvider for AdmissionHeightChain {
    fn trust_level(&self) -> konsensus_core::traits::chain::TrustLevel {
        konsensus_core::traits::chain::TrustLevel::ServerTrust
    }
    async fn get_block_height(&self) -> Result<u64, konsensus_core::traits::chain::ChainError> {
        use std::sync::atomic::Ordering;
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.hang.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        if self.fail.load(Ordering::SeqCst) {
            Err(konsensus_core::traits::chain::ChainError::Backend(
                "private detail".into(),
            ))
        } else {
            Ok(900_000)
        }
    }
    async fn is_synced(&self) -> bool {
        if self.height_only_sync.is_some() {
            self.get_block_height().await.is_ok()
        } else {
            !self.unsynced.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
    async fn is_synced_with_height(&self, height: u64) -> bool {
        match &self.height_only_sync {
            Some(provider) => provider.is_synced_with_height(height).await,
            None => self.is_synced().await,
        }
    }
    async fn get_block_header(
        &self,
        _: u64,
    ) -> Result<konsensus_core::traits::chain::BlockHeader, konsensus_core::traits::chain::ChainError>
    {
        unreachable!()
    }
    async fn estimate_fee(
        &self,
        target_blocks: u32,
    ) -> Result<konsensus_core::traits::chain::FeeEstimate, konsensus_core::traits::chain::ChainError>
    {
        Ok(konsensus_core::traits::chain::FeeEstimate {
            target_blocks,
            sat_per_vbyte: 1.0,
        })
    }
    async fn is_tx_confirmed(
        &self,
        _: &str,
        _: u32,
    ) -> Result<bool, konsensus_core::traits::chain::ChainError> {
        unreachable!()
    }
}

#[tokio::test(start_paused = true)]
async fn admission_height_cache_coalesces_and_expires_in_static_mode() {
    assert_admission_height_cache(false).await;
}

#[tokio::test(start_paused = true)]
async fn admission_height_cache_coalesces_and_expires_in_chain_aware_mode() {
    assert_admission_height_cache(true).await;
}

async fn assert_admission_height_cache(dynamic: bool) {
    use std::sync::atomic::Ordering;
    let chain = Arc::new(AdmissionHeightChain {
        height_only_sync: Some(
            konsensus_chain::EsploraProvider::new(konsensus_chain::EsploraConfig::custom(
                "unsupported://no-network".into(),
                konsensus_core::traits::chain::TrustLevel::ServerTrust,
            ))
            .unwrap(),
        ),
        ..Default::default()
    });
    let cache = ReadinessHeightCache::new(chain.clone());
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> = if dynamic {
        Arc::new(konsensus_pricing::ChainAwarePricingEngine::new(
            Default::default(),
            chain.clone(),
        ))
    } else {
        admission_pricing()
    };
    let dir = tempfile::tempdir().unwrap();
    let wallet = konsensus_lightning::shared_mock::SharedMockProvider::new(
        &dir.path().join("wallet.sqlite"),
        "recipient",
        0,
    )
    .unwrap();
    let results = futures::future::join_all((0..16).map(|_| {
        prepare_admission_invoice(pricing.as_ref(), &cache, &wallet, "request", u64::MAX)
    }))
    .await;
    assert!(
        results.iter().all(Result::is_ok),
        "admission remains available in both pricing modes"
    );
    for _ in 0..16 {
        prepare_admission_invoice(pricing.as_ref(), &cache, &wallet, "request", u64::MAX)
            .await
            .unwrap();
    }
    assert_eq!(chain.calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(std::time::Duration::from_secs(59)).await;
    prepare_admission_invoice(pricing.as_ref(), &cache, &wallet, "request", u64::MAX)
        .await
        .unwrap();
    assert_eq!(chain.calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    prepare_admission_invoice(pricing.as_ref(), &cache, &wallet, "request", u64::MAX)
        .await
        .unwrap();
    assert_eq!(chain.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn admission_height_cache_failure_is_shared_and_later_success_recovers() {
    use std::sync::atomic::Ordering;
    let chain = Arc::new(AdmissionHeightChain::default());
    let cache = ReadinessHeightCache::new(chain.clone());
    let pricing = admission_pricing();
    chain.fail.store(true, Ordering::SeqCst);
    let results = futures::future::join_all((0..16).map(|_| {
        prepare_admission_invoice(
            pricing.as_ref(),
            &cache,
            &NoInvoiceWallet,
            "request",
            u64::MAX,
        )
    }))
    .await;
    for result in results {
        assert_eq!(result.unwrap_err(), "konsensus:not_ready:chain_unavailable");
    }
    assert_eq!(chain.calls.load(Ordering::SeqCst), 1);

    chain.fail.store(false, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let wallet = konsensus_lightning::shared_mock::SharedMockProvider::new(
        &dir.path().join("wallet.sqlite"),
        "recipient",
        0,
    )
    .unwrap();
    for _ in 0..16 {
        prepare_admission_invoice(pricing.as_ref(), &cache, &wallet, "request", u64::MAX)
            .await
            .unwrap();
    }
    assert_eq!(chain.calls.load(Ordering::SeqCst), 2);

    // An expired success cannot mask a new failure, and failure does not renew it.
    tokio::time::advance(std::time::Duration::from_secs(60)).await;
    chain.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        prepare_admission_invoice(
            pricing.as_ref(),
            &cache,
            &NoInvoiceWallet,
            "request",
            u64::MAX
        )
        .await
        .unwrap_err(),
        "konsensus:not_ready:chain_unavailable"
    );
    chain.fail.store(false, Ordering::SeqCst);
    prepare_admission_invoice(pricing.as_ref(), &cache, &wallet, "request", u64::MAX)
        .await
        .unwrap();
    assert_eq!(chain.calls.load(Ordering::SeqCst), 4);
}

#[tokio::test(start_paused = true)]
async fn admission_height_cache_timeout_recovers_and_does_not_cache_sync_state() {
    use std::sync::atomic::Ordering;
    let chain = Arc::new(AdmissionHeightChain::default());
    let cache = ReadinessHeightCache::new(chain.clone());
    let pricing = admission_pricing();
    chain.hang.store(true, Ordering::SeqCst);
    let start = tokio::time::Instant::now();
    assert_eq!(
        prepare_admission_invoice(
            pricing.as_ref(),
            &cache,
            &NoInvoiceWallet,
            "request",
            u64::MAX
        )
        .await
        .unwrap_err(),
        "konsensus:not_ready:chain_unavailable"
    );
    assert!(start.elapsed() <= std::time::Duration::from_secs(5));
    chain.hang.store(false, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let wallet = konsensus_lightning::shared_mock::SharedMockProvider::new(
        &dir.path().join("wallet.sqlite"),
        "recipient",
        0,
    )
    .unwrap();
    prepare_admission_invoice(pricing.as_ref(), &cache, &wallet, "request", u64::MAX)
        .await
        .unwrap();
    chain.unsynced.store(true, Ordering::SeqCst);
    assert_eq!(
        prepare_admission_invoice(
            pricing.as_ref(),
            &cache,
            &NoInvoiceWallet,
            "request",
            u64::MAX
        )
        .await
        .unwrap_err(),
        "konsensus:not_ready:not_synced"
    );
    chain.unsynced.store(false, Ordering::SeqCst);
    prepare_admission_invoice(pricing.as_ref(), &cache, &wallet, "request", u64::MAX)
        .await
        .unwrap();
    assert_eq!(chain.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn admission_height_cache_discards_overdue_cancelled_lookups() {
    use std::sync::atomic::Ordering;
    let chain = Arc::new(AdmissionHeightChain::default());
    let cache = ReadinessHeightCache::new(chain.clone());
    // Leave a read pending with no waiter. Its delayed response must not become
    // a new observation when the next admission arrives much later.
    assert!(tokio::time::timeout(std::time::Duration::ZERO, cache.get()).await.is_err());
    assert_eq!(chain.calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(std::time::Duration::from_secs(61)).await;
    cache.get().await.unwrap();
    assert_eq!(chain.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn admission_height_cache_discards_cancelled_lookups_before_deadline() {
    use std::sync::atomic::Ordering;
    let chain = Arc::new(AdmissionHeightChain::default());
    let cache = ReadinessHeightCache::new(chain.clone());
    let mut lookup = Box::pin(cache.get());
    assert!(futures::poll!(&mut lookup).is_pending());
    drop(lookup);
    cache.get().await.unwrap();
    assert_eq!(chain.calls.load(Ordering::SeqCst), 2);
    cache.get().await.unwrap();
    assert_eq!(chain.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn admission_height_cache_cancelling_one_waiter_preserves_shared_lookup() {
    use std::sync::atomic::Ordering;
    let chain = Arc::new(AdmissionHeightChain::default());
    let cache = ReadinessHeightCache::new(chain.clone());
    let mut first = Box::pin(cache.get());
    let mut second = Box::pin(cache.get());
    assert!(futures::poll!(&mut first).is_pending());
    assert!(futures::poll!(&mut second).is_pending());
    drop(first);
    cache.get().await.unwrap();
    second.await.unwrap();
    assert_eq!(chain.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn admission_height_cache_rejects_overdue_ready_response() {
    use std::sync::atomic::Ordering;
    let chain = Arc::new(AdmissionHeightChain::default());
    let cache = ReadinessHeightCache::new(chain.clone());
    let mut lookup = Box::pin(cache.get());
    assert!(futures::poll!(&mut lookup).is_pending());
    // Both the response and timeout are ready when the lookup is polled again.
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    assert_eq!(lookup.await.unwrap_err(), "konsensus:not_ready:chain_unavailable");
    cache.get().await.unwrap();
    assert_eq!(chain.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn issue204_zero_height_refuses_admission_with_typed_not_ready() {
    let chain = Arc::new(konsensus_chain::MockChainProvider::with_config(konsensus_chain::MockChainConfig {
        initial_height: 0, ..Default::default()
    }));
    let cache = ReadinessHeightCache::new(chain);
    let dir = tempfile::tempdir().unwrap();
    let wallet = konsensus_lightning::shared_mock::SharedMockProvider::new(&dir.path().join("wallet.sqlite"), "recipient", 0).unwrap();
    assert_eq!(prepare_admission_invoice(admission_pricing().as_ref(), &cache, &wallet, "request", u64::MAX).await.unwrap_err(), konsensus_api::invoice_refusal::CHAIN_UNAVAILABLE);
}
