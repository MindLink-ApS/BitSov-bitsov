//! F8 Persistence Test: beta node restart with database survival.
//!
//! Validates three guarantees after a node restart:
//! 1. **Message persistence** — all messages stored pre-restart are in the DB after restart.
//! 2. **E2EE session re-establishment** — sessions restored from storage or re-negotiated.
//! 3. **Lightning channel reconnect** — payment gate passes immediately after restart.
//!
//! This test uses a real SQLite file (via tempfile) to ensure the database
//! survives across simulated process restarts, mirroring the production path
//! where the binary is killed and respawned by systemd.
//!
//! Recovery time is measured and logged for each phase.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::time::{sleep, timeout};

use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::gate::PaymentGate;
use konsensus_core::identity::NodeIdentity;
use konsensus_core::types::{NodeId, Nonce, PaymentProof, Recipient, Signature};
use konsensus_core::{MessageTransport, UkmEnvelopeBuilder};
use konsensus_crypto::{ratchet_message_from_bytes, ratchet_message_to_bytes, SessionManager};
use konsensus_message::wire::{Capability, SovereigntyTier};
use konsensus_message::{ControlEvent, Frame, NoiseTransport, TransportConfig};
use konsensus_pricing::StaticPricingConfig;
use konsensus_storage::{SqliteStorage, Storage};

const MNEMONIC_ALPHA: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEMONIC_BETA: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

/// Number of messages to store before the restart.
const PRE_RESTART_MSG_COUNT: usize = 12;

// ── Helpers ───────────────────────────────────────────────────────────────────

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

    let mut envelope = UkmEnvelopeBuilder::new(
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

/// Build a raw envelope without E2EE (for persistence-only message storage).
fn make_stored_envelope(sender: NodeId, recipient: NodeId, seq: usize) -> UkmEnvelope {
    let preimage = [seq as u8; 32];
    let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(payment_hash, preimage, 100);
    let ciphertext = format!("encrypted-payload-{seq}").into_bytes();
    let nonce = Nonce::from_bytes([(seq % 256) as u8; 24]);

    UkmEnvelopeBuilder::new(0, sender, Recipient::Node(recipient), ciphertext, proof)
        .timestamp(1_700_000_000_000 + seq as u64 * 1000)
        .nonce(nonce)
        .signature(Signature::from_bytes([seq as u8; 64]))
        .build()
}

/// Session handler that supports stale session replacement (matches production main.rs).
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
                    let frame = Frame::PrekeyOffer { bundle: bundle_json };
                    let _ = transport.send_frame(&peer_id, &frame).await;
                }
                ControlEvent::PrekeyOffer { peer_id, bundle, .. } => {
                    if our_node_id.as_bytes() >= peer_id.as_bytes() {
                        continue; // Not the initiator
                    }
                    // Replace stale session (restart recovery path)
                    if session_manager.has_session(&peer_id).await {
                        session_manager.remove_session(&peer_id).await;
                    }
                    let peer_bundle: konsensus_crypto::SerializablePrekeyBundle =
                        serde_json::from_value(bundle).unwrap();
                    match session_manager.initiate_session(&peer_id, &peer_bundle).await {
                        Ok(init_data) => {
                            let init_json = serde_json::to_value(&init_data).unwrap();
                            let frame = Frame::SessionInit { init_data: init_json };
                            let _ = transport.send_frame(&peer_id, &frame).await;
                        }
                        Err(e) => eprintln!("X3DH initiation failed: {e}"),
                    }
                }
                ControlEvent::SessionInit { peer_id, init_data, .. } => {
                    // Replace stale session (restart recovery path)
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

// ── In-memory nonce store (for payment gate in tests) ────────────────────────

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

// ── StorageSessionAdapter (mirrors main.rs) ───────────────────────────────────

struct StorageSessionAdapter {
    storage: Arc<SqliteStorage>,
}

#[async_trait::async_trait]
impl konsensus_crypto::SessionStore for StorageSessionAdapter {
    async fn save_session(
        &self,
        peer_id: &NodeId,
        state_json: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.storage
            .store_session(peer_id, state_json)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    async fn load_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        self.storage
            .load_session(peer_id)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    async fn delete_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.storage
            .delete_session(peer_id)
            .await
            .map(|_| ())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    async fn list_sessions(
        &self,
    ) -> Result<Vec<NodeId>, Box<dyn std::error::Error + Send + Sync>> {
        self.storage
            .list_sessions()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}

// ── Count messages in storage ─────────────────────────────────────────────────

async fn count_messages(db: &SqliteStorage, recipient: NodeId) -> usize {
    db.get_messages_for_recipient(&Recipient::Node(recipient), 1000, None)
        .await
        .unwrap()
        .len()
}

// ── Main F8 test ──────────────────────────────────────────────────────────────

/// F8: Persistence test — beta node restart with full recovery verification.
///
/// Phases:
///   Phase 0 — Store PRE_RESTART_MSG_COUNT messages in beta's SQLite DB.
///   Phase 1 — Establish alpha↔beta E2EE session, exchange pre-restart message.
///   Phase 2 — Record message count, simulate beta restart (new transport + sessions,
///              same DB file).
///   Phase 3 — Verify: (1) messages still in DB, (2) E2EE re-establishes,
///              (3) payment-gated messages flow again (Lightning reconnect proxy).
///   Log — recovery time for each step.
#[tokio::test]
async fn f8_persistence_survives_beta_restart() {
    eprintln!("\n=== F8 Persistence Test: beta node restart ===");

    // ── Identities ────────────────────────────────────────────────────────
    let id_alpha = make_identity(MNEMONIC_ALPHA);
    let id_beta = make_identity(MNEMONIC_BETA);
    let alpha_id = *id_alpha.node_id();
    let beta_id = *id_beta.node_id();
    assert_ne!(alpha_id, beta_id);

    // ── Databases — real temp files (not in-memory) to survive "restarts" ─
    let beta_db_dir = tempfile::tempdir().expect("tempdir");
    let beta_db_path = beta_db_dir.path().join("beta.db");
    let beta_db_path_str = format!("sqlite:{}", beta_db_path.display());

    let beta_db = Arc::new(
        SqliteStorage::open(&beta_db_path_str)
            .await
            .expect("beta db open"),
    );

    // ── Phase 0: Store PRE_RESTART_MSG_COUNT messages in beta's DB ────────
    eprintln!("[Phase 0] Seeding {} messages into beta DB…", PRE_RESTART_MSG_COUNT);
    let seed_start = Instant::now();

    for seq in 0..PRE_RESTART_MSG_COUNT {
        let env = make_stored_envelope(alpha_id, beta_id, seq);
        beta_db.store_message(&env).await.expect("store message");
    }

    let pre_restart_count = count_messages(&beta_db, beta_id).await;
    let seed_elapsed = seed_start.elapsed();
    assert_eq!(
        pre_restart_count, PRE_RESTART_MSG_COUNT,
        "all seeded messages should be in DB before restart"
    );
    eprintln!(
        "[Phase 0] OK — {pre_restart_count} messages stored in {seed_elapsed:?}"
    );

    // ── Phase 1: Connect alpha↔beta, establish E2EE, send a pre-restart msg ─
    eprintln!("[Phase 1] Establishing alpha↔beta E2EE session…");

    let transport_alpha = make_transport(&id_alpha, vec![beta_id]);
    let transport_beta = make_transport(&id_beta, vec![alpha_id]);

    transport_alpha.start_listener().await.unwrap();
    transport_beta.start_listener().await.unwrap();

    let addr_beta = transport_beta.listen_addr().expect("beta addr");

    // Alpha uses in-memory sessions; beta uses persistent sessions (SQLite)
    let session_alpha = Arc::new(SessionManager::new(Arc::clone(&id_alpha)));
    let beta_session_store: Arc<dyn konsensus_crypto::SessionStore> =
        Arc::new(StorageSessionAdapter { storage: Arc::clone(&beta_db) });
    let session_beta =
        Arc::new(SessionManager::with_store(Arc::clone(&id_beta), beta_session_store));

    run_resilient_session_handler(
        Arc::clone(&transport_alpha),
        Arc::clone(&session_alpha),
        alpha_id,
    )
    .await;
    run_resilient_session_handler(
        Arc::clone(&transport_beta),
        Arc::clone(&session_beta),
        beta_id,
    )
    .await;

    sleep(Duration::from_millis(100)).await;
    transport_alpha
        .connect(&beta_id, &addr_beta.to_string())
        .await
        .unwrap();

    wait_for_session(&session_alpha, &beta_id, "alpha→beta (pre-restart)").await;
    wait_for_session(&session_beta, &alpha_id, "beta→alpha (pre-restart)").await;

    // Send one E2EE message before restart and store it in beta's DB
    let pre_msg = b"Pre-restart message - must survive beta restart";
    let ratchet_msg = session_alpha.encrypt(&beta_id, pre_msg).await.unwrap();
    let ciphertext = ratchet_message_to_bytes(&ratchet_msg);
    let env = make_envelope(&id_alpha, beta_id, ciphertext.clone());

    transport_alpha.send(&beta_id, &env).await.unwrap();
    let received = timeout(Duration::from_secs(5), transport_beta.recv())
        .await
        .expect("beta receives pre-restart message")
        .unwrap();

    // Persist the received envelope into beta's DB (simulating node's receive handler)
    beta_db.store_message(&received).await.expect("persist received msg");

    let count_after_live_msg = count_messages(&beta_db, beta_id).await;
    eprintln!(
        "[Phase 1] OK — E2EE session established, {} messages now in beta DB",
        count_after_live_msg
    );

    // ── Phase 2: Simulate beta restart ────────────────────────────────────
    eprintln!("[Phase 2] Simulating beta node restart (kill + start)…");
    let restart_start = Instant::now();

    // Kill beta's transport (simulates process termination)
    transport_beta.shutdown();
    sleep(Duration::from_millis(300)).await;

    // ── Restart: new transport + fresh in-memory sessions for beta
    // (Beta will restore sessions from its persistent SQLite DB)
    let transport_beta2 = make_transport(&id_beta, vec![alpha_id]);
    transport_beta2.start_listener().await.unwrap();
    let addr_beta2 = transport_beta2.listen_addr().expect("beta2 addr");

    // Open the SAME DB file — this is what a real restart does
    let beta_db2 = Arc::new(
        SqliteStorage::open(&beta_db_path_str)
            .await
            .expect("beta db2 open (same file)"),
    );
    let beta_session_store2: Arc<dyn konsensus_crypto::SessionStore> =
        Arc::new(StorageSessionAdapter { storage: Arc::clone(&beta_db2) });
    let session_beta2 =
        Arc::new(SessionManager::with_store(Arc::clone(&id_beta), beta_session_store2));

    // Restore persisted sessions (mirrors startup logic in main.rs)
    let session_restore_start = Instant::now();
    let restored = session_beta2.restore_sessions().await;
    let session_restore_elapsed = session_restore_start.elapsed();
    eprintln!(
        "[Phase 2] Session restore: {restored} sessions in {session_restore_elapsed:?}"
    );

    // ── Verify 1: Messages survived the restart ───────────────────────────
    eprintln!("[Phase 2] Verifying message persistence…");
    let post_restart_count = count_messages(&beta_db2, beta_id).await;
    assert_eq!(
        post_restart_count, count_after_live_msg,
        "message count must be identical before and after restart: expected {count_after_live_msg}, got {post_restart_count}"
    );
    eprintln!(
        "[Phase 2] OK — {post_restart_count} messages survived restart (expected {count_after_live_msg})"
    );

    // ── Phase 3: E2EE re-establishment + Lightning reconnect ──────────────
    eprintln!("[Phase 3] Reconnecting alpha → restarted beta…");

    run_resilient_session_handler(
        Arc::clone(&transport_beta2),
        Arc::clone(&session_beta2),
        beta_id,
    )
    .await;

    sleep(Duration::from_millis(100)).await;

    // Alpha disconnects from dead beta, reconnects to new address
    transport_alpha.disconnect(&beta_id).await.unwrap();
    sleep(Duration::from_millis(100)).await;

    transport_alpha
        .connect(&beta_id, &addr_beta2.to_string())
        .await
        .unwrap();

    // ── Verify 2: E2EE session re-establishes automatically ───────────────
    // We wait for alpha's session, which is guaranteed NEW (alpha had no
    // pre-existing session that could mask early completion).
    // For beta2, the restored session's `can_send` is already true, so
    // `wait_for_session` would return early. Instead we wait for alpha's
    // session first, then let the negotiation settle to ensure beta2 has
    // processed the full handshake (SessionInit + RatchetInit).
    wait_for_session(&session_alpha, &beta_id, "alpha→beta (post-restart)").await;

    // Give the session handlers time to finish the full round-trip:
    // SessionInit → SessionAck → RatchetInit → decrypt on beta2 side.
    // Without this settle window, beta2's handler may still be mid-replacement
    // (removed old session, not yet inserted new one) when we call decrypt.
    sleep(Duration::from_millis(500)).await;

    let session_elapsed = restart_start.elapsed();
    eprintln!("[Phase 3] E2EE re-established in {session_elapsed:?} from restart initiation");

    // ── Verify 3: Payment gate passes (Lightning channel reconnect) ───────
    // Alpha sends a new payment-gated message to restarted beta
    let post_msg = b"Post-restart message - E2EE + payment gate must work";
    let ratchet_msg2 = session_alpha.encrypt(&beta_id, post_msg).await.unwrap();
    let ciphertext2 = ratchet_message_to_bytes(&ratchet_msg2);
    let env2 = make_envelope(&id_alpha, beta_id, ciphertext2);

    transport_alpha.send(&beta_id, &env2).await.unwrap();

    let lightning_recv_start = Instant::now();
    let received2 = timeout(Duration::from_secs(5), transport_beta2.recv())
        .await
        .expect("beta2 receives post-restart message within 5s")
        .unwrap();
    let recv_elapsed = lightning_recv_start.elapsed();

    // Verify payment gate on the post-restart message
    let gate = PaymentGate::new();
    let whitelist: HashSet<NodeId> = [alpha_id].into_iter().collect();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = konsensus_pricing::StaticPricingEngine::new(StaticPricingConfig::default());

    gate.verify(
        &received2,
        &nonce_store,
        &pricing,
        Some(&whitelist),
        None::<&dyn konsensus_core::traits::lightning::LightningProvider>,
        0.0,
        None,
    )
    .await
    .expect("payment gate must pass after Lightning reconnect");

    eprintln!(
        "[Phase 3] Payment gate passed — message received in {recv_elapsed:?}"
    );

    // Decrypt the post-restart message to confirm E2EE integrity
    let rm2 = ratchet_message_from_bytes(&received2.ciphertext).unwrap();
    let decrypted2 = session_beta2.decrypt(&alpha_id, &rm2).await.unwrap();
    assert_eq!(&decrypted2, post_msg, "post-restart message must decrypt correctly");

    // Beta sends back to alpha (bidirectional verify)
    let reply_msg = b"Beta reply - bidirectional after restart confirmed";
    let ratchet_msg3 = session_beta2.encrypt(&alpha_id, reply_msg).await.unwrap();
    let ciphertext3 = ratchet_message_to_bytes(&ratchet_msg3);
    let env3 = make_envelope(&id_beta, alpha_id, ciphertext3);
    transport_beta2.send(&alpha_id, &env3).await.unwrap();

    let received3 = timeout(Duration::from_secs(5), transport_alpha.recv())
        .await
        .expect("alpha receives beta reply within 5s")
        .unwrap();

    let rm3 = ratchet_message_from_bytes(&received3.ciphertext).unwrap();
    let decrypted3 = session_alpha.decrypt(&beta_id, &rm3).await.unwrap();
    assert_eq!(&decrypted3, reply_msg, "alpha must decrypt beta's post-restart reply");

    let total_recovery = restart_start.elapsed();

    // ── Summary ───────────────────────────────────────────────────────────
    eprintln!("\n=== F8 Results ===");
    eprintln!("  Messages before restart:  {count_after_live_msg}");
    eprintln!("  Messages after restart:   {post_restart_count}");
    eprintln!("  Sessions restored:        {restored}");
    eprintln!("  Session restore time:     {session_restore_elapsed:?}");
    eprintln!("  E2EE re-established:      {session_elapsed:?} (from restart)");
    eprintln!("  Post-restart recv:        {recv_elapsed:?}");
    eprintln!("  Total recovery time:      {total_recovery:?}");
    eprintln!("=== F8 PASS ===\n");

    // ── Cleanup ───────────────────────────────────────────────────────────
    transport_alpha.shutdown();
    transport_beta2.shutdown();
    // beta_db_dir is dropped here, cleaning up the temp SQLite file
}
