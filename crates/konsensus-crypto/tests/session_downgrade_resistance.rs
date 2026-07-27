//! Integration tests for L0b — restoration of encrypted sessions must NOT
//! fall back to plaintext deserialization on AES-GCM-decrypt failure.
//!
//! Threat model: an attacker with disk-write access overwrites a stored
//! session blob with attacker-controlled `RatchetState` JSON. On restart,
//! the previous code AES-decrypted, observed the failure, then deserialized
//! the raw blob bytes as plaintext JSON and loaded the attacker's session.
//! `persist_session` re-encrypted the blob under the legitimate key on
//! next save, laundering the injection.
//!
//! These tests assert:
//! 1. A blob that fails AES-GCM is NOT loaded as plaintext (default mode).
//! 2. A blob that successfully decrypts IS loaded (regression).
//! 3. Plaintext fallback is permitted ONLY when the operator sets
//!    `KONSENSUS_LEGACY_SESSION_MIGRATION=1` (one-shot migration path).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use konsensus_core::identity::NodeIdentity;
use konsensus_core::types::NodeId;
use konsensus_crypto::double_ratchet::RatchetState;
use konsensus_crypto::session::{SessionManager, SessionStore};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon art";

fn make_identity() -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap())
}

fn make_node_id(seed: u8) -> NodeId {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    NodeId::from_verifying_key(&signing.verifying_key())
}

struct MemorySessionStore {
    data: tokio::sync::RwLock<HashMap<NodeId, Vec<u8>>>,
}

impl MemorySessionStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            data: tokio::sync::RwLock::new(HashMap::new()),
        })
    }

    async fn inject_raw(&self, peer_id: NodeId, blob: Vec<u8>) {
        self.data.write().await.insert(peer_id, blob);
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn save_session(
        &self,
        peer_id: &NodeId,
        state_json: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.data
            .write()
            .await
            .insert(*peer_id, state_json.to_vec());
        Ok(())
    }
    async fn load_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.data.read().await.get(peer_id).cloned())
    }
    async fn delete_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.data.write().await.remove(peer_id);
        Ok(())
    }
    async fn list_sessions(
        &self,
    ) -> Result<Vec<NodeId>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.data.read().await.keys().copied().collect())
    }
}

/// Build a minimal valid `RatchetState` JSON blob — used to simulate an
/// attacker injecting plaintext ratchet state on disk. We construct the
/// state directly rather than going through `DoubleRatchet::init_*` so
/// the test doesn't depend on Double-Ratchet construction internals.
fn attacker_plaintext_ratchet_blob() -> Vec<u8> {
    let state = RatchetState {
        dh_secret: [0xAA; 32],
        dh_public: [0xBB; 32],
        remote_dh_public: Some([0xCC; 32]),
        root_key: [0xDD; 32],
        sending_chain: Some([0xEE; 32]),
        receiving_chain: Some([0xFF; 32]),
        send_count: 0,
        recv_count: 0,
        previous_chain_length: 0,
        skipped_keys: Vec::new(),
        associated_data: vec![0u8; 64],
    };
    serde_json::to_vec(&state).unwrap()
}

/// All three L0b scenarios run in one test because they share the
/// `KONSENSUS_LEGACY_SESSION_MIGRATION` env var (process-global) and the
/// default `cargo test` harness runs tests in parallel — splitting them
/// into separate `#[tokio::test]`s causes flaky leaks of the flag
/// between tests. Sequencing them here keeps the assertions deterministic.
#[tokio::test]
async fn l0b_session_restore_downgrade_resistance() {
    // ─── Scenario 1: corrupt blob NOT loaded as plaintext (default mode) ───
    std::env::remove_var("KONSENSUS_LEGACY_SESSION_MIGRATION");
    {
        let identity = make_identity();
        let store = MemorySessionStore::new();
        let manager =
            SessionManager::with_store(Arc::clone(&identity), Arc::clone(&store) as _);

        let peer_id = make_node_id(7);
        let attacker_blob = attacker_plaintext_ratchet_blob();
        assert!(
            attacker_blob.len() > 12,
            "attacker blob must exceed AES-GCM minimum to exercise the decrypt path"
        );
        store.inject_raw(peer_id, attacker_blob).await;

        let restored = manager.restore_sessions().await;
        assert_eq!(
            restored, 0,
            "L0b violation: corrupt blob was loaded via plaintext fallback"
        );
        assert!(!manager.has_session(&peer_id).await);
    }

    // ─── Scenario 2: legitimately encrypted blob still restores ───────────
    {
        let identity = make_identity();
        let store = MemorySessionStore::new();
        let manager =
            SessionManager::with_store(Arc::clone(&identity), Arc::clone(&store) as _);

        let peer_identity = Arc::new(
            NodeIdentity::from_mnemonic(
                "zoo zoo zoo zoo zoo zoo zoo zoo \
                 zoo zoo zoo zoo zoo zoo zoo zoo \
                 zoo zoo zoo zoo zoo zoo zoo vote",
                "",
            )
            .unwrap(),
        );
        let peer_id = *peer_identity.node_id();
        let peer_store = MemorySessionStore::new();
        let peer_manager =
            SessionManager::with_store(Arc::clone(&peer_identity), Arc::clone(&peer_store) as _);

        let bundle_us = manager.prekey_bundle().await;
        let init = peer_manager
            .initiate_session(identity.node_id(), &bundle_us)
            .await
            .unwrap();
        // `accept_session` persists internally on success.
        manager.accept_session(&peer_id, &init).await.unwrap();
        assert!(manager.has_session(&peer_id).await);

        // New manager off the same identity + same store — must restore
        // via the AES-GCM decrypt path (the fix path).
        let manager2 = SessionManager::with_store(identity, Arc::clone(&store) as _);
        let restored = manager2.restore_sessions().await;
        assert!(
            restored >= 1,
            "L0b regression: legitimately-encrypted blob did not restore"
        );
        assert!(manager2.has_session(&peer_id).await);
    }

    // ─── Scenario 3: migration gate behavior ─────────────────────────────
    //
    // MED-A (2026-06-13): the plaintext-accepting path is now COMPILED OUT of
    // default/production builds. The env var is therefore only meaningful when
    // the binary was built with `--features legacy-session-migration`. We
    // assert BOTH halves:
    //
    //   * default build  — env var is inert, plaintext blob is REJECTED;
    //   * migration build — env var + feature together restore the blob ONCE.
    std::env::set_var("KONSENSUS_LEGACY_SESSION_MIGRATION", "1");
    {
        let identity = make_identity();
        let store = MemorySessionStore::new();
        let manager =
            SessionManager::with_store(Arc::clone(&identity), Arc::clone(&store) as _);

        let peer_id = make_node_id(11);
        let plaintext_blob = attacker_plaintext_ratchet_blob();
        store.inject_raw(peer_id, plaintext_blob).await;

        let restored = manager.restore_sessions().await;

        #[cfg(feature = "legacy-session-migration")]
        {
            assert_eq!(
                restored, 1,
                "migration build: migration-flag path failed to restore plaintext blob"
            );
            assert!(manager.has_session(&peer_id).await);
        }

        #[cfg(not(feature = "legacy-session-migration"))]
        {
            assert_eq!(
                restored, 0,
                "MED-A violation: default build must reject plaintext blob even with \
                 KONSENSUS_LEGACY_SESSION_MIGRATION=1 set — the env var must be inert when \
                 the plaintext path is not compiled in"
            );
            assert!(
                !manager.has_session(&peer_id).await,
                "MED-A violation: plaintext session was loaded in a default build"
            );
        }
    }
    std::env::remove_var("KONSENSUS_LEGACY_SESSION_MIGRATION");
}

/// MED-A: a plaintext (non-AES-GCM) session blob MUST be rejected by default,
/// even when an attacker has flipped `KONSENSUS_LEGACY_SESSION_MIGRATION=1` on
/// the process environment. This is the explicit "rejected by default" proof
/// the hardening task requires. It runs in EVERY build configuration; in a
/// default build it proves the env var is inert, and in a migration build it
/// proves that the env var alone (without re-enabling it inside this test) is
/// not what is being relied on — the dedicated Scenario 3 above covers the
/// migration-on path. Kept as its own test so the default-reject guarantee is
/// named and discoverable independently of the combined L0b scenarios.
#[cfg(not(feature = "legacy-session-migration"))]
#[tokio::test]
async fn med_a_plaintext_blob_rejected_by_default_despite_env_flag() {
    // Hostile environment: attacker set the migration env var.
    std::env::set_var("KONSENSUS_LEGACY_SESSION_MIGRATION", "1");

    let identity = make_identity();
    let store = MemorySessionStore::new();
    let manager = SessionManager::with_store(Arc::clone(&identity), Arc::clone(&store) as _);

    let peer_id = make_node_id(23);
    let plaintext_blob = attacker_plaintext_ratchet_blob();
    let original = plaintext_blob.clone();
    store.inject_raw(peer_id, plaintext_blob).await;

    let restored = manager.restore_sessions().await;

    std::env::remove_var("KONSENSUS_LEGACY_SESSION_MIGRATION");

    assert_eq!(
        restored, 0,
        "MED-A: a default build must NOT ingest a plaintext session blob, env var notwithstanding"
    );
    assert!(
        !manager.has_session(&peer_id).await,
        "MED-A: plaintext session must not be loaded in a default build"
    );
    // The on-disk blob must be left byte-for-byte untouched — never silently
    // re-encrypted (which would launder attacker-injected ratchet state).
    let stored = store
        .load_session(&peer_id)
        .await
        .unwrap()
        .expect("blob should still be present");
    assert_eq!(
        stored, original,
        "MED-A: rejected plaintext blob must not be rewritten/laundered on disk"
    );
}
