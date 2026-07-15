//! Integration test: E2EE session recovery after node restart.
//!
//! Validates that when a node restarts (loses in-memory sessions), the
//! stale session recovery logic re-negotiates E2EE automatically:
//! 1. Two nodes connect and establish a bidirectional E2EE session
//! 2. They exchange encrypted messages successfully
//! 3. One node "restarts" — new transport, new SessionManager (fresh state)
//! 4. The restarted node reconnects to the surviving node
//! 5. The surviving node detects stale session (decryption or PrekeyOffer)
//!    and re-negotiates
//! 6. Both nodes can exchange encrypted messages again

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
use konsensus_message::{ControlEvent, Frame, NoiseTransport, TransportConfig};
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

/// Session handler that supports stale session replacement (mirrors main.rs).
///
/// Unlike the basic handler in three_node_test.rs, this one replaces existing
/// sessions when a PrekeyOffer or SessionInit arrives — matching the production
/// stale session recovery logic.
async fn run_resilient_session_handler(
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
                ControlEvent::PeerConnected { peer_id, .. } => {
                    let bundle = session_manager.prekey_bundle().await;
                    let bundle_json = serde_json::to_value(&bundle).unwrap();
                    let frame = Frame::PrekeyOffer {
                        bundle: bundle_json,
                    };
                    let _ = transport.send_frame(&peer_id, &frame).await;
                }
                ControlEvent::PrekeyOffer { peer_id, bundle, .. } => {
                    if our_node_id.as_bytes() >= peer_id.as_bytes() {
                        continue; // Not the initiator
                    }
                    // Replace stale session if one exists (restart recovery)
                    if session_manager.has_session(&peer_id).await {
                        session_manager.remove_session(&peer_id).await;
                    }
                    let peer_bundle: konsensus_crypto::SerializablePrekeyBundle =
                        serde_json::from_value(bundle).unwrap();
                    match session_manager.initiate_session(&peer_id, &peer_bundle).await {
                        Ok(init_data) => {
                            let init_json = serde_json::to_value(&init_data).unwrap();
                            let frame = Frame::SessionInit {
                                init_data: init_json,
                            };
                            let _ = transport.send_frame(&peer_id, &frame).await;
                        }
                        Err(e) => eprintln!("X3DH initiation failed: {e}"),
                    }
                }
                ControlEvent::SessionInit { peer_id, init_data, .. } => {
                    // Replace stale session if one exists (restart recovery)
                    if session_manager.has_session(&peer_id).await {
                        session_manager.remove_session(&peer_id).await;
                    }
                    let init: konsensus_crypto::SerializableSessionInit =
                        serde_json::from_value(init_data).unwrap();
                    match session_manager.accept_session(&peer_id, &init).await {
                        Ok(()) => {
                            let frame = Frame::SessionAck;
                            let _ = transport.send_frame(&peer_id, &frame).await;
                        }
                        Err(e) => eprintln!("session accept failed: {e}"),
                    }
                }
                ControlEvent::SessionAck { peer_id, .. } => {
                    if let Ok(ratchet_msg) =
                        session_manager.encrypt(&peer_id, b"ratchet-init").await
                    {
                        let payload = ratchet_message_to_bytes(&ratchet_msg);
                        let frame = Frame::RatchetInit { payload };
                        let _ = transport.send_frame(&peer_id, &frame).await;
                    }
                }
                ControlEvent::RatchetInit { peer_id, payload, .. } => {
                    if let Ok(ratchet_msg) = ratchet_message_from_bytes(&payload) {
                        let _ = session_manager.decrypt(&peer_id, &ratchet_msg).await;
                    }
                }
                _ => {}
            }
        }
    });
}

async fn wait_for_session(mgr: &SessionManager, peer: &NodeId, label: &str) {
    for _ in 0..80 {
        if mgr.can_send(peer).await {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("{label}: timed out waiting for bidirectional E2EE session with {peer}");
}

/// Test: a node restarts and automatically re-establishes E2EE with its peer.
#[tokio::test]
async fn session_recovers_after_node_restart() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let alice_id = *id_alice.node_id();
    let bob_id = *id_bob.node_id();

    // ── Phase 1: Initial connection and E2EE ─────────────────────────
    let transport_alice = make_transport(&id_alice, vec![bob_id]);
    let transport_bob = make_transport(&id_bob, vec![alice_id]);

    transport_alice.start_listener().await.unwrap();
    transport_bob.start_listener().await.unwrap();

    let addr_bob = transport_bob.listen_addr().expect("bob addr");

    let session_alice = Arc::new(SessionManager::new(Arc::clone(&id_alice)));
    let session_bob = Arc::new(SessionManager::new(Arc::clone(&id_bob)));

    run_resilient_session_handler(
        Arc::clone(&transport_alice),
        Arc::clone(&session_alice),
        alice_id,
    )
    .await;
    run_resilient_session_handler(
        Arc::clone(&transport_bob),
        Arc::clone(&session_bob),
        bob_id,
    )
    .await;

    sleep(Duration::from_millis(100)).await;

    // Alice connects to Bob
    transport_alice
        .connect(&bob_id, &addr_bob.to_string())
        .await
        .unwrap();

    // Wait for bidirectional E2EE session
    wait_for_session(&session_alice, &bob_id, "Alice→Bob (initial)").await;
    wait_for_session(&session_bob, &alice_id, "Bob→Alice (initial)").await;

    // Verify initial encrypted exchange works
    let plaintext1 = b"Pre-restart message from Alice";
    let ratchet_msg = session_alice.encrypt(&bob_id, plaintext1).await.unwrap();
    let ciphertext = ratchet_message_to_bytes(&ratchet_msg);
    let envelope = make_envelope(&id_alice, bob_id, ciphertext);
    transport_alice.send(&bob_id, &envelope).await.unwrap();

    let received = timeout(Duration::from_secs(3), transport_bob.recv())
        .await
        .expect("Bob should receive within 3s")
        .unwrap();
    let rm = ratchet_message_from_bytes(&received.ciphertext).unwrap();
    let decrypted = session_bob.decrypt(&alice_id, &rm).await.unwrap();
    assert_eq!(&decrypted, plaintext1, "initial message should decrypt");

    // ── Phase 2: Bob "restarts" — new transport, fresh session state ──
    transport_bob.shutdown();
    // Small delay for shutdown to propagate
    sleep(Duration::from_millis(300)).await;

    // Bob comes back with fresh state (simulating process restart)
    let transport_bob2 = make_transport(&id_bob, vec![alice_id]);
    transport_bob2.start_listener().await.unwrap();
    let addr_bob2 = transport_bob2.listen_addr().expect("bob2 addr");

    // Fresh session manager — no prior sessions (restart lost them)
    let session_bob2 = Arc::new(SessionManager::new(Arc::clone(&id_bob)));
    assert_eq!(
        session_bob2.session_count().await,
        0,
        "restarted Bob should have no sessions"
    );

    run_resilient_session_handler(
        Arc::clone(&transport_bob2),
        Arc::clone(&session_bob2),
        bob_id,
    )
    .await;

    sleep(Duration::from_millis(100)).await;

    // Alice must disconnect from the dead Bob before connecting to the new one.
    // In production, the connection supervisor's keepalive ping detects dead
    // connections and removes them automatically, then reconnects. Here we
    // simulate that cleanup explicitly.
    transport_alice.disconnect(&bob_id).await.unwrap();
    sleep(Duration::from_millis(100)).await;

    // Alice reconnects to Bob's new address
    transport_alice
        .connect(&bob_id, &addr_bob2.to_string())
        .await
        .unwrap();

    // ── Phase 3: Sessions re-negotiate automatically ─────────────────
    // Alice's session handler receives PeerConnected, sends PrekeyOffer.
    // Bob's handler also sends PrekeyOffer. The tiebreaker picks the
    // initiator. Alice's old session is replaced with a new one.
    wait_for_session(&session_alice, &bob_id, "Alice→Bob (post-restart)").await;
    wait_for_session(&session_bob2, &alice_id, "Bob→Alice (post-restart)").await;

    // ── Phase 4: Verify encrypted messaging works after re-negotiation ─
    // Alice sends to Bob (new session)
    let plaintext2 = b"Post-restart message from Alice to Bob";
    let ratchet_msg2 = session_alice.encrypt(&bob_id, plaintext2).await.unwrap();
    let ciphertext2 = ratchet_message_to_bytes(&ratchet_msg2);
    let envelope2 = make_envelope(&id_alice, bob_id, ciphertext2);
    transport_alice.send(&bob_id, &envelope2).await.unwrap();

    let received2 = timeout(Duration::from_secs(3), transport_bob2.recv())
        .await
        .expect("Bob2 should receive within 3s")
        .unwrap();

    // Verify payment gate on the re-negotiated message
    let gate = PaymentGate::new();
    let whitelist: HashSet<NodeId> = [alice_id].into_iter().collect();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = konsensus_pricing::StaticPricingEngine::new(StaticPricingConfig::default());
    gate.verify(
        &received2,
        &nonce_store,
        &pricing,
        Some(&whitelist),
        None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
        None,
    )
    .await
    .expect("payment gate should pass after re-negotiation");

    let rm2 = ratchet_message_from_bytes(&received2.ciphertext).unwrap();
    let decrypted2 = session_bob2.decrypt(&alice_id, &rm2).await.unwrap();
    assert_eq!(
        &decrypted2, plaintext2,
        "Bob should decrypt Alice's post-restart message"
    );

    // Bob sends back to Alice (verify bidirectional)
    let plaintext3 = b"Post-restart reply from Bob to Alice";
    let ratchet_msg3 = session_bob2.encrypt(&alice_id, plaintext3).await.unwrap();
    let ciphertext3 = ratchet_message_to_bytes(&ratchet_msg3);
    let envelope3 = make_envelope(&id_bob, alice_id, ciphertext3);
    transport_bob2.send(&alice_id, &envelope3).await.unwrap();

    let received3 = timeout(Duration::from_secs(3), transport_alice.recv())
        .await
        .expect("Alice should receive within 3s")
        .unwrap();

    let rm3 = ratchet_message_from_bytes(&received3.ciphertext).unwrap();
    let decrypted3 = session_alice.decrypt(&bob_id, &rm3).await.unwrap();
    assert_eq!(
        &decrypted3, plaintext3,
        "Alice should decrypt Bob's post-restart reply"
    );

    // ── Cleanup ──────────────────────────────────────────────────────
    transport_alice.shutdown();
    transport_bob2.shutdown();
}

/// In-memory nonce store for testing.
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
