//! Integration test: 3-node encrypted message exchange.
//!
//! Validates the full BitSov v2 message pipeline:
//! 1. Three nodes connect and federate (Noise_XX + whitelist)
//! 2. E2EE sessions established automatically (X3DH + Double Ratchet)
//! 3. Encrypted messages pass through payment gate (Principle 2)
//! 4. Receiver decrypts successfully (Principle 4 — no plaintext in transit)
//!
//! This test uses in-process components (no config files, no external services).

use std::collections::HashSet;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio::time::{sleep, timeout, Duration};

use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::gate::PaymentGate;
use konsensus_core::identity::NodeIdentity;
use konsensus_core::types::{NodeId, PaymentProof, Recipient, Signature};
use konsensus_core::MessageTransport;
use konsensus_crypto::{ratchet_message_from_bytes, ratchet_message_to_bytes, SessionManager};
use konsensus_message::wire::{Capability, SovereigntyTier};
use konsensus_message::{NoiseTransport, TransportConfig};
use konsensus_pricing::StaticPricingConfig;

const MNEMONIC_ALICE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEMONIC_BOB: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
const MNEMONIC_CAROL: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn make_identity(mnemonic: &str) -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(mnemonic, "").expect("valid mnemonic"))
}

/// Build a transport with port 0 (OS-assigned) and the given whitelist.
fn make_transport(identity: &Arc<NodeIdentity>, whitelist: Vec<NodeId>) -> Arc<NoiseTransport> {
    let config = TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        tier: SovereigntyTier::T1,
        capabilities: vec![Capability::X3dh],
        whitelist,
        version: 2,
    };
    Arc::new(NoiseTransport::new(Arc::clone(identity), config))
}

/// Build and sign a UKM envelope with valid payment proof.
fn make_envelope(
    identity: &NodeIdentity,
    recipient: NodeId,
    ciphertext: Vec<u8>,
) -> UkmEnvelope {
    let preimage = rand::random::<[u8; 32]>();
    let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(payment_hash, preimage, 100);

    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        0, // KIND_CHAT
        *identity.node_id(),
        Recipient::Node(recipient),
        ciphertext,
        proof,
    )
    .timestamp(chrono::Utc::now().timestamp_millis() as u64)
    .build();

    let sig = identity.sign(&envelope.signable_bytes());
    envelope.signature = Signature::from_ed25519(&sig);
    envelope.validate().expect("envelope should be valid");
    envelope
}

/// Wait for a bidirectional E2EE session to be established.
///
/// Uses `can_send` instead of `has_session` to ensure the sending chain
/// is initialized (the acceptor needs the initiator's RatchetInit message).
async fn wait_for_session(mgr: &SessionManager, peer: &NodeId, label: &str) {
    for _ in 0..50 {
        if mgr.can_send(peer).await {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("{label}: timed out waiting for bidirectional E2EE session with {peer}");
}

/// Process control events for automatic E2EE session establishment.
///
/// This replicates the session handler logic from main.rs, needed because
/// integration tests don't boot the full node binary.
async fn run_session_handler(
    transport: Arc<NoiseTransport>,
    session_manager: Arc<SessionManager>,
    our_node_id: NodeId,
) {
    tokio::spawn(async move {
        loop {
            let Some(event) = transport.recv_control().await else {
                break;
            };
            match event {
                konsensus_message::ControlEvent::PeerConnected { peer_id } => {
                    let bundle = session_manager.prekey_bundle().await;
                    let bundle_json = serde_json::to_value(&bundle).unwrap();
                    let frame = konsensus_message::Frame::PrekeyOffer { bundle: bundle_json };
                    let _ = transport.send_frame(&peer_id, &frame).await;
                }
                konsensus_message::ControlEvent::PrekeyOffer { peer_id, bundle } => {
                    if our_node_id.as_bytes() >= peer_id.as_bytes() {
                        continue; // Not the initiator
                    }
                    if session_manager.has_session(&peer_id).await {
                        continue;
                    }
                    let peer_bundle: konsensus_crypto::SerializablePrekeyBundle =
                        serde_json::from_value(bundle).unwrap();
                    match session_manager.initiate_session(&peer_id, &peer_bundle).await {
                        Ok(init_data) => {
                            let init_json = serde_json::to_value(&init_data).unwrap();
                            let frame = konsensus_message::Frame::SessionInit { init_data: init_json };
                            let _ = transport.send_frame(&peer_id, &frame).await;
                        }
                        Err(e) => eprintln!("X3DH initiation failed: {e}"),
                    }
                }
                konsensus_message::ControlEvent::SessionInit { peer_id, init_data } => {
                    if session_manager.has_session(&peer_id).await {
                        continue;
                    }
                    let init: konsensus_crypto::SerializableSessionInit =
                        serde_json::from_value(init_data).unwrap();
                    match session_manager.accept_session(&peer_id, &init).await {
                        Ok(()) => {
                            let frame = konsensus_message::Frame::SessionAck;
                            let _ = transport.send_frame(&peer_id, &frame).await;
                        }
                        Err(e) => eprintln!("session accept failed: {e}"),
                    }
                }
                konsensus_message::ControlEvent::SessionAck { peer_id } => {
                    // Session established (initiator side) — send ratchet init
                    // so the acceptor can initialize their sending chain.
                    if let Ok(ratchet_msg) = session_manager.encrypt(&peer_id, b"ratchet-init").await {
                        let payload = konsensus_crypto::ratchet_message_to_bytes(&ratchet_msg);
                        let frame = konsensus_message::Frame::RatchetInit { payload };
                        let _ = transport.send_frame(&peer_id, &frame).await;
                    }
                }
                konsensus_message::ControlEvent::RatchetInit { peer_id, payload } => {
                    // Acceptor decrypts ratchet init → initializes sending chain
                    if let Ok(ratchet_msg) = konsensus_crypto::ratchet_message_from_bytes(&payload) {
                        let _ = session_manager.decrypt(&peer_id, &ratchet_msg).await;
                    }
                }
                _ => {}
            }
        }
    });
}

/// Test: three nodes connect, establish E2EE sessions, and exchange
/// encrypted, payment-gated messages in all directions.
#[tokio::test]
async fn three_nodes_federate_and_exchange_encrypted_messages() {
    // ── Setup identities ──────────────────────────────────────────────
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let id_carol = make_identity(MNEMONIC_CAROL);

    let alice_id = *id_alice.node_id();
    let bob_id = *id_bob.node_id();
    let carol_id = *id_carol.node_id();

    // Verify all three have distinct identities
    assert_ne!(alice_id, bob_id);
    assert_ne!(bob_id, carol_id);
    assert_ne!(alice_id, carol_id);

    // ── Setup transports (fully meshed whitelist) ─────────────────────
    let transport_alice = make_transport(&id_alice, vec![bob_id, carol_id]);
    let transport_bob = make_transport(&id_bob, vec![alice_id, carol_id]);
    let transport_carol = make_transport(&id_carol, vec![alice_id, bob_id]);

    // Start all listeners
    transport_alice.start_listener().await.unwrap();
    transport_bob.start_listener().await.unwrap();
    transport_carol.start_listener().await.unwrap();

    let _addr_alice = transport_alice.listen_addr().expect("alice addr");
    let addr_bob = transport_bob.listen_addr().expect("bob addr");
    let addr_carol = transport_carol.listen_addr().expect("carol addr");

    // ── Setup E2EE session managers ───────────────────────────────────
    let session_alice = Arc::new(SessionManager::new(Arc::clone(&id_alice)));
    let session_bob = Arc::new(SessionManager::new(Arc::clone(&id_bob)));
    let session_carol = Arc::new(SessionManager::new(Arc::clone(&id_carol)));

    // Start session handlers (replicate main.rs control event handling)
    run_session_handler(Arc::clone(&transport_alice), Arc::clone(&session_alice), alice_id).await;
    run_session_handler(Arc::clone(&transport_bob), Arc::clone(&session_bob), bob_id).await;
    run_session_handler(Arc::clone(&transport_carol), Arc::clone(&session_carol), carol_id).await;

    sleep(Duration::from_millis(100)).await;

    // ── Connect: Alice→Bob, Alice→Carol, Bob→Carol ────────────────────
    transport_alice.connect(&bob_id, &addr_bob.to_string()).await.unwrap();
    transport_alice.connect(&carol_id, &addr_carol.to_string()).await.unwrap();
    transport_bob.connect(&carol_id, &addr_carol.to_string()).await.unwrap();

    // Wait for connections to establish
    sleep(Duration::from_millis(500)).await;

    assert!(transport_alice.is_connected(&bob_id).await, "Alice should be connected to Bob");
    assert!(transport_alice.is_connected(&carol_id).await, "Alice should be connected to Carol");
    assert!(transport_bob.is_connected(&alice_id).await, "Bob should be connected to Alice");
    assert!(transport_bob.is_connected(&carol_id).await, "Bob should be connected to Carol");
    assert!(transport_carol.is_connected(&alice_id).await, "Carol should be connected to Alice");
    assert!(transport_carol.is_connected(&bob_id).await, "Carol should be connected to Bob");

    // ── Wait for E2EE sessions to auto-establish ─────────────────────
    wait_for_session(&session_alice, &bob_id, "Alice→Bob").await;
    wait_for_session(&session_alice, &carol_id, "Alice→Carol").await;
    wait_for_session(&session_bob, &alice_id, "Bob→Alice").await;
    wait_for_session(&session_bob, &carol_id, "Bob→Carol").await;
    wait_for_session(&session_carol, &alice_id, "Carol→Alice").await;
    wait_for_session(&session_carol, &bob_id, "Carol→Bob").await;

    // ── Test 1: Alice sends encrypted message to Bob ──────────────────
    let plaintext = b"Hello Bob! This is Alice, sending via the sovereign mesh.";

    // Encrypt with Double Ratchet
    let ratchet_msg = session_alice.encrypt(&bob_id, plaintext).await.unwrap();
    let ciphertext = ratchet_message_to_bytes(&ratchet_msg);

    // Verify ciphertext is NOT plaintext (Principle 4)
    assert_ne!(&ciphertext, plaintext.as_slice());
    assert!(!ciphertext.windows(plaintext.len()).any(|w| w == plaintext));

    // Build signed envelope with payment proof (Principle 2)
    let envelope = make_envelope(&id_alice, bob_id, ciphertext);

    // Send via transport
    transport_alice.send(&bob_id, &envelope).await.unwrap();

    // Bob receives
    let received = timeout(Duration::from_secs(3), transport_bob.recv())
        .await
        .expect("Bob should receive within 3s")
        .unwrap();

    assert_eq!(received.id, envelope.id);
    assert_eq!(received.sender, alice_id);

    // Bob verifies payment gate
    let gate = PaymentGate::new();
    let whitelist: HashSet<NodeId> = [alice_id, carol_id].into_iter().collect();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = konsensus_pricing::StaticPricingEngine::new(StaticPricingConfig::default());

    gate.verify(&received, &nonce_store, &pricing, Some(&whitelist), None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0)
        .await
        .expect("payment gate should pass");

    // Bob decrypts
    let ratchet_msg_received = ratchet_message_from_bytes(&received.ciphertext)
        .expect("should parse ratchet message");
    let decrypted = session_bob.decrypt(&alice_id, &ratchet_msg_received).await.unwrap();
    assert_eq!(&decrypted, plaintext, "Bob should decrypt Alice's message");

    // ── Test 2: Bob sends encrypted message to Carol ──────────────────
    let plaintext2 = b"Hey Carol, Bob here. Network is working!";

    let ratchet_msg2 = session_bob.encrypt(&carol_id, plaintext2).await.unwrap();
    let ciphertext2 = ratchet_message_to_bytes(&ratchet_msg2);
    let envelope2 = make_envelope(&id_bob, carol_id, ciphertext2);

    transport_bob.send(&carol_id, &envelope2).await.unwrap();

    let received2 = timeout(Duration::from_secs(3), transport_carol.recv())
        .await
        .expect("Carol should receive within 3s")
        .unwrap();

    assert_eq!(received2.sender, bob_id);

    let whitelist_carol: HashSet<NodeId> = [alice_id, bob_id].into_iter().collect();
    let nonce_store2 = InMemoryNonceStore::new();
    gate.verify(&received2, &nonce_store2, &pricing, Some(&whitelist_carol), None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0)
        .await
        .expect("Carol's payment gate should pass");

    let ratchet_msg_received2 = ratchet_message_from_bytes(&received2.ciphertext).unwrap();
    let decrypted2 = session_carol.decrypt(&bob_id, &ratchet_msg_received2).await.unwrap();
    assert_eq!(&decrypted2, plaintext2, "Carol should decrypt Bob's message");

    // ── Test 3: Carol sends encrypted message to Alice ────────────────
    let plaintext3 = b"Alice, Carol here. Full triangle confirmed!";

    let ratchet_msg3 = session_carol.encrypt(&alice_id, plaintext3).await.unwrap();
    let ciphertext3 = ratchet_message_to_bytes(&ratchet_msg3);
    let envelope3 = make_envelope(&id_carol, alice_id, ciphertext3);

    transport_carol.send(&alice_id, &envelope3).await.unwrap();

    let received3 = timeout(Duration::from_secs(3), transport_alice.recv())
        .await
        .expect("Alice should receive within 3s")
        .unwrap();

    assert_eq!(received3.sender, carol_id);

    let nonce_store3 = InMemoryNonceStore::new();
    let whitelist_alice: HashSet<NodeId> = [bob_id, carol_id].into_iter().collect();
    gate.verify(&received3, &nonce_store3, &pricing, Some(&whitelist_alice), None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0)
        .await
        .expect("Alice's payment gate should pass");

    let ratchet_msg_received3 = ratchet_message_from_bytes(&received3.ciphertext).unwrap();
    let decrypted3 = session_alice.decrypt(&carol_id, &ratchet_msg_received3).await.unwrap();
    assert_eq!(&decrypted3, plaintext3, "Alice should decrypt Carol's message");

    // ── Test 4: Verify payment gate rejects non-whitelisted sender ────
    // Carol's envelope but verified against a whitelist that excludes Carol
    let nonce_store4 = InMemoryNonceStore::new();
    let restricted_whitelist: HashSet<NodeId> = [bob_id].into_iter().collect(); // No Carol
    let result = gate.verify(&received3, &nonce_store4, &pricing, Some(&restricted_whitelist), None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0)
        .await;
    assert!(result.is_err(), "should reject message from non-whitelisted sender");

    // ── Cleanup ────────────────────────────────────────────────────────
    transport_alice.shutdown();
    transport_bob.shutdown();
    transport_carol.shutdown();
}

/// In-memory nonce store for testing (avoids needing SQLite).
struct InMemoryNonceStore {
    seen: tokio::sync::Mutex<HashSet<Vec<u8>>>,
}

impl InMemoryNonceStore {
    fn new() -> Self {
        Self {
            seen: tokio::sync::Mutex::new(HashSet::new()),
        }
    }
}

#[async_trait::async_trait]
impl konsensus_core::gate::NonceStore for InMemoryNonceStore {
    async fn check_and_store(
        &self,
        nonce: &konsensus_core::types::Nonce,
        _sender: &NodeId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let mut seen = self.seen.lock().await;
        Ok(seen.insert(nonce.as_bytes().to_vec()))
    }
}
