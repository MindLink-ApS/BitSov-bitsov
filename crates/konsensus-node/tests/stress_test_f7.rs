//! F7 Stress Test: 20 rapid messages alpha↔beta alternating.
//!
//! Validates:
//! - All 20 messages delivered (no drops)
//! - Every message has a valid payment proof
//! - Timing: average message latency and payment verification latency logged
//! - Any failures are flagged explicitly

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::time::{sleep, timeout};

use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::gate::PaymentGate;
use konsensus_core::identity::NodeIdentity;
use konsensus_core::types::{NodeId, PaymentProof, Recipient, Signature};
use konsensus_core::MessageTransport;
use konsensus_crypto::{ratchet_message_from_bytes, ratchet_message_to_bytes, SessionManager};
use konsensus_message::wire::{Capability, SovereigntyTier};
use konsensus_message::{NoiseTransport, TransportConfig};
use konsensus_pricing::StaticPricingConfig;

const MNEMONIC_ALPHA: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEMONIC_BETA: &str =
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

const MSG_COUNT: usize = 20;

// ── Helpers ──────────────────────────────────────────────────────────────────

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
                        let payload = konsensus_crypto::ratchet_message_to_bytes(&ratchet_msg);
                        let frame = konsensus_message::Frame::RatchetInit { payload };
                        let _ = transport.send_frame(&peer_id, &frame).await;
                    }
                }
                konsensus_message::ControlEvent::RatchetInit { peer_id, payload, .. } => {
                    if let Ok(ratchet_msg) = konsensus_crypto::ratchet_message_from_bytes(&payload)
                    {
                        let _ = session_manager.decrypt(&peer_id, &ratchet_msg).await;
                    }
                }
                _ => {}
            }
        }
    });
}

// ── In-memory nonce store ─────────────────────────────────────────────────────

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

// ── Timing records ────────────────────────────────────────────────────────────

struct MessageTiming {
    /// Index of this message (0-based)
    index: usize,
    /// Direction: true = alpha→beta, false = beta→alpha
    alpha_to_beta: bool,
    /// Round-trip from send() call to recv() returning the envelope
    message_latency_ms: u128,
    /// Time to run payment gate verification
    payment_verify_ms: u128,
    /// Whether all checks passed
    ok: bool,
    /// Failure note if any
    failure: Option<String>,
}

// ── Main stress test ──────────────────────────────────────────────────────────

/// F7: 20 rapid messages alternating alpha↔beta, all delivered with payment proofs.
#[tokio::test]
async fn f7_stress_20_messages_alternating() {
    // ── Identities ────────────────────────────────────────────────────────
    let id_alpha = make_identity(MNEMONIC_ALPHA);
    let id_beta = make_identity(MNEMONIC_BETA);

    let alpha_id = *id_alpha.node_id();
    let beta_id = *id_beta.node_id();
    assert_ne!(alpha_id, beta_id, "distinct node ids required");

    // ── Transports ────────────────────────────────────────────────────────
    let transport_alpha = make_transport(&id_alpha, vec![beta_id]);
    let transport_beta = make_transport(&id_beta, vec![alpha_id]);

    transport_alpha.start_listener().await.unwrap();
    transport_beta.start_listener().await.unwrap();

    let addr_beta = transport_beta.listen_addr().expect("beta addr");

    // ── Session managers ──────────────────────────────────────────────────
    let session_alpha = Arc::new(SessionManager::new(Arc::clone(&id_alpha)));
    let session_beta = Arc::new(SessionManager::new(Arc::clone(&id_beta)));

    run_session_handler(Arc::clone(&transport_alpha), Arc::clone(&session_alpha), alpha_id).await;
    run_session_handler(Arc::clone(&transport_beta), Arc::clone(&session_beta), beta_id).await;

    sleep(Duration::from_millis(100)).await;

    // ── Connect alpha → beta ──────────────────────────────────────────────
    transport_alpha.connect(&beta_id, &addr_beta.to_string()).await.unwrap();
    sleep(Duration::from_millis(500)).await;

    assert!(transport_alpha.is_connected(&beta_id).await, "alpha→beta connected");
    assert!(transport_beta.is_connected(&alpha_id).await, "beta→alpha connected");

    // ── Wait for E2EE sessions ────────────────────────────────────────────
    wait_for_session(&session_alpha, &beta_id, "alpha→beta session").await;
    wait_for_session(&session_beta, &alpha_id, "beta→alpha session").await;

    // ── Payment gate + nonce stores ───────────────────────────────────────
    let gate = PaymentGate::new();
    let pricing = konsensus_pricing::StaticPricingEngine::new(StaticPricingConfig::default());
    let nonce_alpha = InMemoryNonceStore::new(); // alpha receives from beta
    let nonce_beta = InMemoryNonceStore::new();  // beta receives from alpha
    let whitelist_alpha: HashSet<NodeId> = [beta_id].into_iter().collect();
    let whitelist_beta: HashSet<NodeId> = [alpha_id].into_iter().collect();

    // ── Stress loop ───────────────────────────────────────────────────────
    let mut timings: Vec<MessageTiming> = Vec::with_capacity(MSG_COUNT);
    let mut failures: Vec<String> = Vec::new();

    eprintln!("\n=== F7 Stress Test: {MSG_COUNT} rapid alternating messages ===");

    for i in 0..MSG_COUNT {
        let alpha_to_beta = i % 2 == 0; // even → alpha→beta, odd → beta→alpha
        let direction = if alpha_to_beta { "alpha→beta" } else { "beta→alpha" };
        let plaintext = format!("F7 stress msg #{i:02} direction={direction}");
        let plaintext_bytes = plaintext.as_bytes();

        let send_start = Instant::now();

        // Encrypt and send
        let (envelope, receiver_transport, receiver_session, sender_id, receiver_id, nonce_store, whitelist) =
            if alpha_to_beta {
                let rm = session_alpha.encrypt(&beta_id, plaintext_bytes).await.unwrap();
                let ct = ratchet_message_to_bytes(&rm);
                let env = make_envelope(&id_alpha, beta_id, ct);
                transport_alpha.send(&beta_id, &env).await.unwrap();
                (
                    env,
                    &transport_beta,
                    &session_beta,
                    alpha_id,
                    beta_id,
                    &nonce_beta,
                    &whitelist_beta,
                )
            } else {
                let rm = session_beta.encrypt(&alpha_id, plaintext_bytes).await.unwrap();
                let ct = ratchet_message_to_bytes(&rm);
                let env = make_envelope(&id_beta, alpha_id, ct);
                transport_beta.send(&alpha_id, &env).await.unwrap();
                (
                    env,
                    &transport_alpha,
                    &session_alpha,
                    beta_id,
                    alpha_id,
                    &nonce_alpha,
                    &whitelist_alpha,
                )
            };

        // Receive
        let recv_result = timeout(Duration::from_secs(5), receiver_transport.recv()).await;
        let message_latency_ms = send_start.elapsed().as_millis();

        let received = match recv_result {
            Ok(Ok(env)) => env,
            Ok(Err(e)) => {
                let msg = format!("msg #{i} ({direction}): recv error: {e}");
                eprintln!("  FAIL: {msg}");
                failures.push(msg.clone());
                timings.push(MessageTiming {
                    index: i,
                    alpha_to_beta,
                    message_latency_ms,
                    payment_verify_ms: 0,
                    ok: false,
                    failure: Some(msg),
                });
                continue;
            }
            Err(_) => {
                let msg = format!("msg #{i} ({direction}): recv timed out after 5s");
                eprintln!("  FAIL: {msg}");
                failures.push(msg.clone());
                timings.push(MessageTiming {
                    index: i,
                    alpha_to_beta,
                    message_latency_ms,
                    payment_verify_ms: 0,
                    ok: false,
                    failure: Some(msg),
                });
                continue;
            }
        };

        // Verify envelope identity
        if received.id != envelope.id {
            let msg = format!(
                "msg #{i} ({direction}): envelope id mismatch: got {:?}",
                received.id
            );
            eprintln!("  FAIL: {msg}");
            failures.push(msg.clone());
            timings.push(MessageTiming {
                index: i,
                alpha_to_beta,
                message_latency_ms,
                payment_verify_ms: 0,
                ok: false,
                failure: Some(msg),
            });
            continue;
        }

        if received.sender != sender_id {
            let msg = format!("msg #{i} ({direction}): wrong sender");
            eprintln!("  FAIL: {msg}");
            failures.push(msg.clone());
            timings.push(MessageTiming {
                index: i,
                alpha_to_beta,
                message_latency_ms,
                payment_verify_ms: 0,
                ok: false,
                failure: Some(msg),
            });
            continue;
        }

        // Payment gate verification (timed)
        let gate_start = Instant::now();
        let gate_result = gate
            .verify(
                &received,
                nonce_store,
                &pricing,
                Some(whitelist),
                None::<&dyn konsensus_core::traits::lightning::LightningProvider>,
                0.0,
                None,
            )
            .await;
        let payment_verify_ms = gate_start.elapsed().as_millis();

        let mut ok = true;
        let mut failure = None;

        if let Err(e) = gate_result {
            let msg = format!("msg #{i} ({direction}): payment gate rejected: {e}");
            eprintln!("  FAIL: {msg}");
            failures.push(msg.clone());
            ok = false;
            failure = Some(msg);
        } else {
            // Decrypt to verify E2EE integrity
            let ratchet_msg = match ratchet_message_from_bytes(&received.ciphertext) {
                Ok(rm) => rm,
                Err(e) => {
                    let msg = format!("msg #{i} ({direction}): ratchet parse failed: {e}");
                    eprintln!("  FAIL: {msg}");
                    failures.push(msg.clone());
                    timings.push(MessageTiming {
                        index: i,
                        alpha_to_beta,
                        message_latency_ms,
                        payment_verify_ms,
                        ok: false,
                        failure: Some(msg),
                    });
                    continue;
                }
            };

            match receiver_session.decrypt(&sender_id, &ratchet_msg).await {
                Ok(decrypted) => {
                    if decrypted != plaintext_bytes {
                        let msg = format!("msg #{i} ({direction}): decrypted content mismatch");
                        eprintln!("  FAIL: {msg}");
                        failures.push(msg.clone());
                        ok = false;
                        failure = Some(msg);
                    } else {
                        eprintln!(
                            "  OK   #{i:02} {direction:>12}  msg_latency={message_latency_ms}ms  payment_verify={payment_verify_ms}ms"
                        );
                    }
                }
                Err(e) => {
                    let msg = format!("msg #{i} ({direction}): decrypt failed: {e}");
                    eprintln!("  FAIL: {msg}");
                    failures.push(msg.clone());
                    ok = false;
                    failure = Some(msg);
                }
            }
        }

        timings.push(MessageTiming {
            index: i,
            alpha_to_beta,
            message_latency_ms,
            payment_verify_ms,
            ok,
            failure,
        });
    }

    // ── Summary ───────────────────────────────────────────────────────────
    let delivered = timings.iter().filter(|t| t.ok).count();
    let failed = timings.iter().filter(|t| !t.ok).count();

    let avg_msg_latency = if delivered > 0 {
        timings.iter().filter(|t| t.ok).map(|t| t.message_latency_ms).sum::<u128>()
            / delivered as u128
    } else {
        0
    };

    let avg_payment_latency = if delivered > 0 {
        timings.iter().filter(|t| t.ok).map(|t| t.payment_verify_ms).sum::<u128>()
            / delivered as u128
    } else {
        0
    };

    eprintln!("\n=== F7 Results ===");
    eprintln!("  Sent:      {MSG_COUNT}");
    eprintln!("  Delivered: {delivered}");
    eprintln!("  Failed:    {failed}");
    eprintln!("  Avg message latency:         {avg_msg_latency}ms");
    eprintln!("  Avg payment verify latency:  {avg_payment_latency}ms");

    if !failures.is_empty() {
        eprintln!("\n  Failures:");
        for f in &failures {
            eprintln!("    - {f}");
        }
    }

    // ── Assertions ────────────────────────────────────────────────────────
    assert_eq!(
        delivered, MSG_COUNT,
        "All {MSG_COUNT} messages must be delivered; {failed} failed. Failures: {failures:?}"
    );

    // Sanity: average latency must be reasonable (< 10s per message)
    assert!(
        avg_msg_latency < 10_000,
        "avg message latency {avg_msg_latency}ms exceeds 10s — something is badly wrong"
    );

    // ── Cleanup ───────────────────────────────────────────────────────────
    transport_alpha.shutdown();
    transport_beta.shutdown();

    eprintln!("=== F7 PASS ===\n");
}
