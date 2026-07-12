//! Integration test: large message chunking through the full E2EE pipeline.
//!
//! Validates that payloads exceeding the Noise 65KB limit are correctly
//! chunked, transported, and reassembled end-to-end:
//! 1. Two nodes connect and establish E2EE (X3DH + Double Ratchet)
//! 2. Sender encrypts a large payload (100KB+) via Double Ratchet
//! 3. Noise transport automatically chunks the encrypted payload
//! 4. Receiver reassembles, verifies payment gate, decrypts
//! 5. Decrypted plaintext matches original byte-for-byte
//!
//! This proves C2 (Noise 65KB chunking) works through the full stack.

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

const MNEMONIC_ALICE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEMONIC_BOB: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

fn make_identity(mnemonic: &str) -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(mnemonic, "").expect("valid mnemonic"))
}

fn make_transport(identity: &Arc<NodeIdentity>, whitelist: Vec<NodeId>) -> Arc<NoiseTransport> {
    let config = TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        tier: SovereigntyTier::T1,
        capabilities: vec![Capability::X3dh],
        whitelist,
        version: 2,
        admission_mode: konsensus_message::ReachabilityMode::Whitelist,
        cookie_mode: Default::default(),
    };
    Arc::new(NoiseTransport::new(Arc::clone(identity), config))
}

fn make_envelope(identity: &NodeIdentity, recipient: NodeId, ciphertext: Vec<u8>) -> UkmEnvelope {
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

async fn wait_for_session(mgr: &SessionManager, peer: &NodeId, label: &str) {
    for _ in 0..50 {
        if mgr.can_send(peer).await {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("{label}: timed out waiting for bidirectional E2EE session with {peer}");
}

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
                konsensus_message::ControlEvent::PeerConnected { peer_id, .. } => {
                    let bundle = session_manager.prekey_bundle().await;
                    let bundle_json = serde_json::to_value(&bundle).unwrap();
                    let frame = konsensus_message::Frame::PrekeyOffer { bundle: bundle_json };
                    let _ = transport.send_frame(&peer_id, &frame).await;
                }
                konsensus_message::ControlEvent::PrekeyOffer { peer_id, bundle, .. } => {
                    if our_node_id.as_bytes() >= peer_id.as_bytes() {
                        continue;
                    }
                    if session_manager.has_session(&peer_id).await {
                        continue;
                    }
                    let peer_bundle: konsensus_crypto::SerializablePrekeyBundle =
                        serde_json::from_value(bundle).unwrap();
                    match session_manager.initiate_session(&peer_id, &peer_bundle).await {
                        Ok(init_data) => {
                            let init_json = serde_json::to_value(&init_data).unwrap();
                            let frame =
                                konsensus_message::Frame::SessionInit { init_data: init_json };
                            let _ = transport.send_frame(&peer_id, &frame).await;
                        }
                        Err(e) => eprintln!("X3DH initiation failed: {e}"),
                    }
                }
                konsensus_message::ControlEvent::SessionInit { peer_id, init_data, .. } => {
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
                konsensus_message::ControlEvent::SessionAck { peer_id, .. } => {
                    if let Ok(ratchet_msg) =
                        session_manager.encrypt(&peer_id, b"ratchet-init").await
                    {
                        let payload = ratchet_message_to_bytes(&ratchet_msg);
                        let frame = konsensus_message::Frame::RatchetInit { payload };
                        let _ = transport.send_frame(&peer_id, &frame).await;
                    }
                }
                konsensus_message::ControlEvent::RatchetInit { peer_id, payload, .. } => {
                    if let Ok(ratchet_msg) = ratchet_message_from_bytes(&payload) {
                        let _ = session_manager.decrypt(&peer_id, &ratchet_msg).await;
                    }
                }
                _ => {}
            }
        }
    });
}

struct InMemoryNonceStore {
    seen: tokio::sync::Mutex<HashSet<Vec<u8>>>,
    seen_payment_hashes: tokio::sync::Mutex<HashSet<[u8; 32]>>,
}

impl InMemoryNonceStore {
    fn new() -> Self {
        Self {
            seen: tokio::sync::Mutex::new(HashSet::new()),
            seen_payment_hashes: tokio::sync::Mutex::new(HashSet::new()),
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

    async fn check_and_store_payment_hash(
        &self,
        payment_hash: &[u8; 32],
        _sender: &NodeId,
        _message_id: &konsensus_core::MessageId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let mut seen = self.seen_payment_hashes.lock().await;
        Ok(seen.insert(*payment_hash))
    }
}

/// Parameters for sending and verifying a message through the E2EE pipeline.
struct SendVerifyParams<'a> {
    session_sender: &'a SessionManager,
    session_receiver: &'a SessionManager,
    transport_sender: &'a NoiseTransport,
    transport_receiver: &'a NoiseTransport,
    id_sender: &'a NodeIdentity,
    sender_id: &'a NodeId,
    receiver_id: &'a NodeId,
    payload_size: usize,
    label: &'a str,
}

/// Send a message of the given size through the full E2EE pipeline and verify roundtrip.
async fn send_and_verify(p: &SendVerifyParams<'_>) {
    let label = p.label;

    // Generate deterministic test payload
    let plaintext: Vec<u8> = (0..p.payload_size)
        .map(|i| (i % 256) as u8)
        .collect();

    // Encrypt with Double Ratchet
    let ratchet_msg = p.session_sender
        .encrypt(p.receiver_id, &plaintext)
        .await
        .unwrap_or_else(|e| panic!("{label}: encrypt failed: {e}"));
    let ciphertext = ratchet_message_to_bytes(&ratchet_msg);

    // Verify ciphertext differs from plaintext
    assert_ne!(
        ciphertext.len(),
        plaintext.len(),
        "{label}: ciphertext should differ in size from plaintext"
    );

    // Build signed envelope
    let envelope = make_envelope(p.id_sender, *p.receiver_id, ciphertext);

    // Send via Noise transport (triggers chunking for >65KB)
    p.transport_sender
        .send(p.receiver_id, &envelope)
        .await
        .unwrap_or_else(|e| panic!("{label}: transport send failed: {e}"));

    // Receive
    let received = timeout(Duration::from_secs(10), p.transport_receiver.recv())
        .await
        .unwrap_or_else(|_| panic!("{label}: timed out waiting for message"))
        .unwrap_or_else(|e| panic!("{label}: recv failed: {e}"));

    assert_eq!(received.sender, *p.sender_id, "{label}: sender mismatch");

    // Verify payment gate
    let gate = PaymentGate::new();
    let whitelist: HashSet<NodeId> = [*p.sender_id].into_iter().collect();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = konsensus_pricing::StaticPricingEngine::new(StaticPricingConfig::default());

    gate.verify(
        &received,
        &nonce_store,
        &pricing,
        Some(&whitelist),
        None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
        None,
    )
    .await
    .unwrap_or_else(|e| panic!("{label}: payment gate failed: {e}"));

    // Decrypt
    let ratchet_msg_received = ratchet_message_from_bytes(&received.ciphertext)
        .unwrap_or_else(|e| panic!("{label}: ratchet parse failed: {e}"));
    let decrypted = p.session_receiver
        .decrypt(p.sender_id, &ratchet_msg_received)
        .await
        .unwrap_or_else(|e| panic!("{label}: decrypt failed: {e}"));

    assert_eq!(
        decrypted.len(),
        plaintext.len(),
        "{label}: decrypted length mismatch (expected {})", p.payload_size
    );
    assert_eq!(
        decrypted, plaintext,
        "{label}: decrypted content does not match original"
    );
}

/// Test: large messages (100KB, 256KB, 1MB) survive the full E2EE pipeline
/// including Noise chunking, Double Ratchet encryption, and payment gate.
#[tokio::test]
async fn large_messages_survive_full_e2ee_pipeline() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);

    let alice_id = *id_alice.node_id();
    let bob_id = *id_bob.node_id();

    let transport_alice = make_transport(&id_alice, vec![bob_id]);
    let transport_bob = make_transport(&id_bob, vec![alice_id]);

    transport_alice.start_listener().await.unwrap();
    transport_bob.start_listener().await.unwrap();

    let addr_bob = transport_bob.listen_addr().expect("bob addr");

    let session_alice = Arc::new(SessionManager::new(Arc::clone(&id_alice)));
    let session_bob = Arc::new(SessionManager::new(Arc::clone(&id_bob)));

    run_session_handler(
        Arc::clone(&transport_alice),
        Arc::clone(&session_alice),
        alice_id,
    )
    .await;
    run_session_handler(
        Arc::clone(&transport_bob),
        Arc::clone(&session_bob),
        bob_id,
    )
    .await;

    sleep(Duration::from_millis(100)).await;
    transport_alice
        .connect(&bob_id, &addr_bob.to_string())
        .await
        .unwrap();
    sleep(Duration::from_millis(500)).await;

    wait_for_session(&session_alice, &bob_id, "Alice→Bob").await;
    wait_for_session(&session_bob, &alice_id, "Bob→Alice").await;

    // ── Test 1: Small message (1 byte — boundary) ────────────────────────
    send_and_verify(&SendVerifyParams {
        session_sender: &session_alice, session_receiver: &session_bob,
        transport_sender: &transport_alice, transport_receiver: &transport_bob,
        id_sender: &id_alice, sender_id: &alice_id, receiver_id: &bob_id,
        payload_size: 1, label: "1-byte",
    }).await;

    // ── Test 2: Exactly 65000 bytes (Noise chunk boundary) ───────────────
    send_and_verify(&SendVerifyParams {
        session_sender: &session_alice, session_receiver: &session_bob,
        transport_sender: &transport_alice, transport_receiver: &transport_bob,
        id_sender: &id_alice, sender_id: &alice_id, receiver_id: &bob_id,
        payload_size: 65_000, label: "65000-byte (chunk boundary)",
    }).await;

    // ── Test 3: Just over chunk boundary (65520 bytes) ───────────────────
    send_and_verify(&SendVerifyParams {
        session_sender: &session_alice, session_receiver: &session_bob,
        transport_sender: &transport_alice, transport_receiver: &transport_bob,
        id_sender: &id_alice, sender_id: &alice_id, receiver_id: &bob_id,
        payload_size: 65_520, label: "65520-byte (over boundary)",
    }).await;

    // ── Test 4: 100 KB — requires multiple chunks ────────────────────────
    send_and_verify(&SendVerifyParams {
        session_sender: &session_alice, session_receiver: &session_bob,
        transport_sender: &transport_alice, transport_receiver: &transport_bob,
        id_sender: &id_alice, sender_id: &alice_id, receiver_id: &bob_id,
        payload_size: 100_000, label: "100KB",
    }).await;

    // ── Test 5: 256 KB ───────────────────────────────────────────────────
    send_and_verify(&SendVerifyParams {
        session_sender: &session_alice, session_receiver: &session_bob,
        transport_sender: &transport_alice, transport_receiver: &transport_bob,
        id_sender: &id_alice, sender_id: &alice_id, receiver_id: &bob_id,
        payload_size: 256_000, label: "256KB",
    }).await;

    // ── Test 6: 1 MB — the big one ──────────────────────────────────────
    send_and_verify(&SendVerifyParams {
        session_sender: &session_alice, session_receiver: &session_bob,
        transport_sender: &transport_alice, transport_receiver: &transport_bob,
        id_sender: &id_alice, sender_id: &alice_id, receiver_id: &bob_id,
        payload_size: 1_000_000, label: "1MB",
    }).await;

    // ── Test 7: Bidirectional — Bob sends large message back to Alice ────
    send_and_verify(&SendVerifyParams {
        session_sender: &session_bob, session_receiver: &session_alice,
        transport_sender: &transport_bob, transport_receiver: &transport_alice,
        id_sender: &id_bob, sender_id: &bob_id, receiver_id: &alice_id,
        payload_size: 200_000, label: "200KB (Bob→Alice)",
    }).await;

    transport_alice.shutdown();
    transport_bob.shutdown();
}
