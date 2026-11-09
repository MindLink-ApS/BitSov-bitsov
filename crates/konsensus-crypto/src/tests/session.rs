use super::*;

const TEST_MNEMONIC_A: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art";

const TEST_MNEMONIC_B: &str =
    "zoo zoo zoo zoo zoo zoo zoo zoo \
     zoo zoo zoo zoo zoo zoo zoo zoo \
     zoo zoo zoo zoo zoo zoo zoo vote";

fn make_identity(mnemonic: &str) -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(mnemonic, "").unwrap())
}

#[tokio::test]
async fn prekey_bundle_generation() {
    let identity = make_identity(TEST_MNEMONIC_A);
    let mgr = SessionManager::new(identity);

    let bundle = mgr.prekey_bundle().await;
    assert!(!bundle.identity_key.is_empty());
    assert!(!bundle.signed_prekey.is_empty());
    assert!(!bundle.signed_prekey_sig.is_empty());
    assert!(!bundle.node_id.is_empty());
    assert!(bundle.one_time_prekey.is_some());
    assert!(bundle.one_time_prekey_id.is_some());
}

#[tokio::test]
async fn full_session_establishment() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_a = *id_a.node_id();
    let node_b = *id_b.node_id();

    let mgr_a = SessionManager::new(id_a);
    let mgr_b = SessionManager::new(id_b);

    // B publishes prekey bundle
    let bundle_b = mgr_b.prekey_bundle().await;

    // A initiates session with B
    let init_data = mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();

    // B accepts session from A
    mgr_b.accept_session(&node_a, &init_data).await.unwrap();

    // Both have active sessions
    assert!(mgr_a.has_session(&node_b).await);
    assert!(mgr_b.has_session(&node_a).await);
}

#[tokio::test]
async fn encrypt_decrypt_roundtrip() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_a = *id_a.node_id();
    let node_b = *id_b.node_id();

    let mgr_a = SessionManager::new(id_a);
    let mgr_b = SessionManager::new(id_b);

    // Establish session
    let bundle_b = mgr_b.prekey_bundle().await;
    let init_data = mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();
    mgr_b.accept_session(&node_a, &init_data).await.unwrap();

    // A encrypts for B
    let plaintext = b"Hello from A to B!";
    let encrypted = mgr_a.encrypt(&node_b, plaintext).await.unwrap();

    // B decrypts from A
    let decrypted = mgr_b.decrypt(&node_a, &encrypted).await.unwrap();
    assert_eq!(decrypted, plaintext);
}

#[tokio::test]
async fn preview_decrypt_preserves_session_for_retries_and_normal_decryption() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_a = *id_a.node_id();
    let node_b = *id_b.node_id();
    let mgr_a = SessionManager::new(id_a);
    let mgr_b = SessionManager::new(id_b);
    let init = mgr_a.initiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    mgr_b.accept_session(&node_a, &init).await.unwrap();
    let message = mgr_a.encrypt(&node_b, b"block zero").await.unwrap();
    let mut corrupt = message.clone();
    corrupt.ciphertext[0] ^= 1;
    assert!(mgr_b.preview_decrypt(&node_a, &corrupt).await.is_err());
    for _ in 0..2 {
        assert_eq!(mgr_b.preview_decrypt(&node_a, &message).await.unwrap(), b"block zero");
    }
    assert_eq!(mgr_b.decrypt(&node_a, &message).await.unwrap(), b"block zero");
    assert!(mgr_b.preview_decrypt(&node_a, &message).await.is_err());
    let next = mgr_a.encrypt(&node_b, b"next signal").await.unwrap();
    assert_eq!(mgr_b.decrypt(&node_a, &next).await.unwrap(), b"next signal");
}

#[tokio::test]
async fn bidirectional_messages() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_a = *id_a.node_id();
    let node_b = *id_b.node_id();

    let mgr_a = SessionManager::new(id_a);
    let mgr_b = SessionManager::new(id_b);

    let bundle_b = mgr_b.prekey_bundle().await;
    let init_data = mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();
    mgr_b.accept_session(&node_a, &init_data).await.unwrap();

    // A → B
    let msg1 = mgr_a.encrypt(&node_b, b"Hello B").await.unwrap();
    assert_eq!(mgr_b.decrypt(&node_a, &msg1).await.unwrap(), b"Hello B");

    // B → A
    let msg2 = mgr_b.encrypt(&node_a, b"Hello A").await.unwrap();
    assert_eq!(mgr_a.decrypt(&node_b, &msg2).await.unwrap(), b"Hello A");

    // A → B again
    let msg3 = mgr_a.encrypt(&node_b, b"How are you?").await.unwrap();
    assert_eq!(
        mgr_b.decrypt(&node_a, &msg3).await.unwrap(),
        b"How are you?"
    );
}

#[tokio::test]
async fn ratchet_message_serialization() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_a = *id_a.node_id();
    let node_b = *id_b.node_id();

    let mgr_a = SessionManager::new(id_a);
    let mgr_b = SessionManager::new(id_b);

    let bundle_b = mgr_b.prekey_bundle().await;
    let init_data = mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();
    mgr_b.accept_session(&node_a, &init_data).await.unwrap();

    // Encrypt
    let original = b"test message for serialization";
    let encrypted = mgr_a.encrypt(&node_b, original).await.unwrap();

    // Serialize to bytes
    let bytes = ratchet_message_to_bytes(&encrypted);
    assert!(bytes.len() >= 40);

    // Deserialize
    let deserialized = ratchet_message_from_bytes(&bytes).unwrap();
    assert_eq!(deserialized.header, encrypted.header);
    assert_eq!(deserialized.ciphertext, encrypted.ciphertext);

    // Decrypt the deserialized message
    let plaintext = mgr_b.decrypt(&node_a, &deserialized).await.unwrap();
    assert_eq!(plaintext, original);
}

#[tokio::test]
async fn no_session_encrypt_fails() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let node_b = NodeId::from_bytes([99u8; 32]);

    let mgr_a = SessionManager::new(id_a);

    let result = mgr_a.encrypt(&node_b, b"hello").await;
    assert!(matches!(result, Err(SessionError::NoSession(_))));
}

#[tokio::test]
async fn duplicate_session_rejected() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_b = *id_b.node_id();

    let mgr_a = SessionManager::new(id_a);
    let mgr_b = SessionManager::new(id_b);

    let bundle_b = mgr_b.prekey_bundle().await;
    mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();

    // Second initiation should fail
    let bundle_b2 = mgr_b.prekey_bundle().await;
    let result = mgr_a.initiate_session(&node_b, &bundle_b2).await;
    assert!(matches!(result, Err(SessionError::SessionExists(_))));
}

#[tokio::test]
async fn remove_session() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_b = *id_b.node_id();

    let mgr_a = SessionManager::new(id_a);
    let mgr_b = SessionManager::new(id_b);

    let bundle_b = mgr_b.prekey_bundle().await;
    mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();
    assert!(mgr_a.has_session(&node_b).await);

    assert!(mgr_a.remove_session(&node_b).await);
    assert!(!mgr_a.has_session(&node_b).await);
}

#[tokio::test]
async fn one_time_prekey_consumed() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_a = *id_a.node_id();

    let mgr_a = SessionManager::new(id_a);
    let mgr_b = SessionManager::new(id_b);

    // Get bundle (includes OPK id=0)
    let bundle = mgr_b.prekey_bundle().await;
    let opk_id = bundle.one_time_prekey_id.unwrap();

    // Initiate session (consumes OPK)
    let init_data = mgr_a.initiate_session(
        &NodeId::from_hex(&bundle.node_id).unwrap(),
        &bundle,
    ).await.unwrap();

    // Accept session (should consume the OPK on Bob's side)
    mgr_b.accept_session(&node_a, &init_data).await.unwrap();

    // The OPK with that ID should be consumed
    let otpks = mgr_b.one_time_prekeys.read().await;
    assert!(otpks.iter().all(|k| k.id != opk_id));
}

/// In-memory session store for testing persistence.
struct MemorySessionStore {
    data: tokio::sync::RwLock<HashMap<NodeId, Vec<u8>>>,
}

impl MemorySessionStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            data: tokio::sync::RwLock::new(HashMap::new()),
        })
    }
}

#[async_trait]
impl super::SessionStore for MemorySessionStore {
    async fn save_session(
        &self,
        peer_id: &NodeId,
        state_json: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.data.write().await.insert(*peer_id, state_json.to_vec());
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

#[tokio::test]
async fn session_persistence_and_restore() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_a = *id_a.node_id();
    let node_b = *id_b.node_id();

    // Shared persistent store
    let store_a = MemorySessionStore::new();
    let store_b = MemorySessionStore::new();

    // Phase 1: Establish sessions with persistence
    let mgr_a = SessionManager::with_store(Arc::clone(&id_a), store_a.clone());
    let mgr_b = SessionManager::with_store(Arc::clone(&id_b), store_b.clone());

    let bundle_b = mgr_b.prekey_bundle().await;
    let init_data = mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();
    mgr_b.accept_session(&node_a, &init_data).await.unwrap();

    // Exchange some messages to advance the ratchet
    let msg1 = mgr_a.encrypt(&node_b, b"hello from A").await.unwrap();
    assert_eq!(mgr_b.decrypt(&node_a, &msg1).await.unwrap(), b"hello from A");
    let msg2 = mgr_b.encrypt(&node_a, b"hello from B").await.unwrap();
    assert_eq!(mgr_a.decrypt(&node_b, &msg2).await.unwrap(), b"hello from B");

    // Verify sessions were persisted
    assert!(store_a.data.read().await.contains_key(&node_b));
    assert!(store_b.data.read().await.contains_key(&node_a));

    // Phase 2: Simulate restart — create new managers with same store
    let mgr_a2 = SessionManager::with_store(Arc::clone(&id_a), store_a.clone());
    let mgr_b2 = SessionManager::with_store(Arc::clone(&id_b), store_b.clone());

    // No sessions in memory yet
    assert!(!mgr_a2.has_session(&node_b).await);
    assert!(!mgr_b2.has_session(&node_a).await);

    // Restore from storage
    assert_eq!(mgr_a2.restore_sessions().await, 1);
    assert_eq!(mgr_b2.restore_sessions().await, 1);

    // Sessions are back
    assert!(mgr_a2.has_session(&node_b).await);
    assert!(mgr_b2.has_session(&node_a).await);

    // Verify restored sessions can continue communicating
    let msg3 = mgr_a2.encrypt(&node_b, b"after restart A").await.unwrap();
    assert_eq!(mgr_b2.decrypt(&node_a, &msg3).await.unwrap(), b"after restart A");

    let msg4 = mgr_b2.encrypt(&node_a, b"after restart B").await.unwrap();
    assert_eq!(mgr_a2.decrypt(&node_b, &msg4).await.unwrap(), b"after restart B");
}

#[tokio::test]
async fn remove_session_deletes_from_store() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_b = *id_b.node_id();

    let store = MemorySessionStore::new();
    let mgr_a = SessionManager::with_store(id_a, store.clone());
    let mgr_b = SessionManager::new(id_b);

    let bundle_b = mgr_b.prekey_bundle().await;
    mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();

    // Session persisted
    assert!(store.data.read().await.contains_key(&node_b));

    // Remove session
    assert!(mgr_a.remove_session(&node_b).await);

    // Removed from store too
    assert!(!store.data.read().await.contains_key(&node_b));
}

#[tokio::test]
async fn active_sessions_list() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_b = *id_b.node_id();

    let mgr_a = SessionManager::new(id_a);
    let mgr_b = SessionManager::new(id_b);

    assert!(mgr_a.active_sessions().await.is_empty());

    let bundle_b = mgr_b.prekey_bundle().await;
    mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();

    let sessions = mgr_a.active_sessions().await;
    assert_eq!(sessions.len(), 1);
    assert!(sessions.contains(&node_b));
}

#[tokio::test]
async fn session_stored_encrypted_not_plaintext() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_b = *id_b.node_id();

    let store = MemorySessionStore::new();
    let mgr_a = SessionManager::with_store(Arc::clone(&id_a), store.clone());
    let mgr_b = SessionManager::new(id_b);

    let bundle_b = mgr_b.prekey_bundle().await;
    mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();

    // The stored blob should NOT be valid JSON (it's encrypted)
    let stored_blob = store.data.read().await.get(&node_b).cloned().unwrap();
    assert!(
        serde_json::from_slice::<serde_json::Value>(&stored_blob).is_err(),
        "session state should be encrypted, not plaintext JSON"
    );

    // It should start with a 12-byte nonce + AES-GCM ciphertext
    assert!(stored_blob.len() > 12, "encrypted blob must contain nonce + ciphertext");
}

#[tokio::test]
async fn restore_migrates_plaintext_to_encrypted() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_a = *id_a.node_id();
    let node_b = *id_b.node_id();

    let store = MemorySessionStore::new();

    // Phase 1: Establish session and manually store plaintext (simulating old format)
    let mgr_a = SessionManager::new(Arc::clone(&id_a));
    let mgr_b = SessionManager::new(id_b);

    let bundle_b = mgr_b.prekey_bundle().await;
    let init_data = mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();
    mgr_b.accept_session(&node_a, &init_data).await.unwrap();

    // Export state and store as plaintext JSON (old format)
    let msg1 = mgr_a.encrypt(&node_b, b"test").await.unwrap();
    let _ = mgr_b.decrypt(&node_a, &msg1).await.unwrap();

    // Get the ratchet state from mgr_a and store as plaintext
    // (We need to get it via the internal state — use a fresh manager to extract it)
    {
        let sessions = mgr_a.sessions.read().await;
        let session = sessions.get(&node_b).unwrap();
        let state = session.ratchet.export_state();
        let plaintext_blob = serde_json::to_vec(&state).unwrap();
        store.data.write().await.insert(node_b, plaintext_blob);
    }

    // Verify it's currently plaintext JSON
    {
        let data = store.data.read().await;
        let blob = data.get(&node_b).unwrap();
        assert!(serde_json::from_slice::<serde_json::Value>(blob).is_ok(),
            "should be plaintext JSON before migration");
    }

    // Phase 2: Create new manager with store and restore.
    //
    // L0b (2026-04-30): plaintext-fallback restore is OFF by default.
    // MED-A (2026-06-13): the plaintext-accepting code is now COMPILED OUT of
    // default/production builds. The operator must BOTH build with
    // `--features legacy-session-migration` AND set
    // `KONSENSUS_LEGACY_SESSION_MIGRATION=1` for one migration boot. The env
    // var alone is inert in a default build.
    //
    // This test therefore asserts BOTH halves of the gate:
    //   * default build (feature off): the env var is ignored, the plaintext
    //     blob is rejected, nothing is restored, and the on-disk blob is left
    //     untouched as plaintext;
    //   * migration build (feature on): the plaintext blob migrates to
    //     encrypted, as the legacy one-shot path intends.
    std::env::set_var("KONSENSUS_LEGACY_SESSION_MIGRATION", "1");
    let migration_dir = tempfile::tempdir().unwrap();
    let mgr_a2 = SessionManager::with_store(Arc::clone(&id_a), store.clone())
        .with_record_policy(crate::record_cipher::LegacyReadPolicy::in_data_dir(migration_dir.path()));
    let restored = mgr_a2.restore_sessions().await;
    std::env::remove_var("KONSENSUS_LEGACY_SESSION_MIGRATION");

    #[cfg(feature = "legacy-session-migration")]
    {
        assert_eq!(
            restored, 1,
            "migration build: should restore the plaintext session under migration flag"
        );
        // After restore, the session should have been re-encrypted.
        let data = store.data.read().await;
        let blob = data.get(&node_b).unwrap();
        assert!(
            serde_json::from_slice::<serde_json::Value>(blob).is_err(),
            "session should be re-encrypted after migration"
        );
    }

    #[cfg(not(feature = "legacy-session-migration"))]
    {
        assert_eq!(
            restored, 0,
            "default build: env var must be inert — plaintext blob must be rejected"
        );
        // The on-disk blob must be left exactly as it was — still plaintext,
        // never silently re-encrypted (no laundering of injected state).
        let data = store.data.read().await;
        let blob = data.get(&node_b).unwrap();
        assert!(
            serde_json::from_slice::<serde_json::Value>(blob).is_ok(),
            "default build: untouched plaintext blob must remain plaintext (not laundered)"
        );
    }
}

// ── ratchet_message_from_bytes deserialization edge cases ──────────

#[test]
fn ratchet_message_from_bytes_empty_payload() {
    let result = ratchet_message_from_bytes(&[]);
    assert!(result.is_err());
    match result {
        Err(SessionError::InvalidPeerData(msg)) => {
            assert!(
                msg.contains("too short"),
                "error should mention 'too short', got: {msg}"
            );
            assert!(
                msg.contains("0 bytes"),
                "error should mention '0 bytes', got: {msg}"
            );
        }
        other => panic!("expected InvalidPeerData, got: {other:?}"),
    }
}

#[test]
fn ratchet_message_from_bytes_under_minimum_header() {
    // Various sizes under the 40-byte minimum header
    for size in [1, 10, 20, 39] {
        let data = vec![0u8; size];
        let result = ratchet_message_from_bytes(&data);
        assert!(
            result.is_err(),
            "{size}-byte payload should be rejected as too short"
        );
        match result {
            Err(SessionError::InvalidPeerData(msg)) => {
                assert!(
                    msg.contains("too short"),
                    "error for {size}-byte payload should mention 'too short', got: {msg}"
                );
            }
            other => panic!(
                "expected InvalidPeerData for {size}-byte payload, got: {other:?}"
            ),
        }
    }
}

#[test]
fn ratchet_message_from_bytes_exactly_minimum_header() {
    // Exactly 40 bytes: valid header with empty ciphertext
    let header = MessageHeader {
        dh_public: [7u8; 32],
        previous_chain_length: 3,
        message_number: 42,
    };
    let bytes = header.to_bytes();
    assert_eq!(bytes.len(), 40);

    let result = ratchet_message_from_bytes(&bytes);
    assert!(
        result.is_ok(),
        "exactly 40 bytes should parse successfully"
    );
    let msg = result.unwrap();
    assert_eq!(msg.header.dh_public, [7u8; 32]);
    assert_eq!(msg.header.previous_chain_length, 3);
    assert_eq!(msg.header.message_number, 42);
    assert!(
        msg.ciphertext.is_empty(),
        "40-byte payload should have empty ciphertext"
    );
}

#[test]
fn ratchet_message_from_bytes_header_plus_one_byte() {
    // 41 bytes: valid header with 1-byte ciphertext
    let header = MessageHeader {
        dh_public: [0xAB; 32],
        previous_chain_length: 0,
        message_number: 1,
    };
    let mut data = header.to_bytes().to_vec();
    data.push(0xFF);

    let result = ratchet_message_from_bytes(&data);
    assert!(result.is_ok(), "41 bytes should parse successfully");
    let msg = result.unwrap();
    assert_eq!(msg.ciphertext, vec![0xFF]);
}

#[test]
fn parse_x25519_key_invalid_hex() {
    let result = parse_x25519_key("not_valid_hex_zzzz");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, SessionError::InvalidPeerData(_)));
}

#[test]
fn parse_x25519_key_wrong_length() {
    // Valid hex but only 16 bytes instead of 32
    let result = parse_x25519_key(&hex::encode([0u8; 16]));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, SessionError::InvalidPeerData(_)));
}

#[test]
fn parse_x25519_key_empty() {
    let result = parse_x25519_key("");
    assert!(result.is_err());
}

#[test]
fn parse_x25519_key_valid() {
    let key_bytes = [7u8; 32];
    let result = parse_x25519_key(&hex::encode(key_bytes));
    assert!(result.is_ok());
}

#[test]
fn deserialize_prekey_bundle_invalid_identity_key() {
    let bundle = SerializablePrekeyBundle {
        identity_key: "bad_hex".into(),
        signed_prekey: hex::encode([0u8; 32]),
        signed_prekey_sig: hex::encode([0u8; 64]),
        node_id: hex::encode([0u8; 32]),
        one_time_prekey: None,
        one_time_prekey_id: None,
    };
    assert!(deserialize_prekey_bundle(&bundle).is_err());
}

#[test]
fn deserialize_prekey_bundle_invalid_signature() {
    let bundle = SerializablePrekeyBundle {
        identity_key: hex::encode([0u8; 32]),
        signed_prekey: hex::encode([0u8; 32]),
        signed_prekey_sig: "not_hex".into(),
        node_id: hex::encode([0u8; 32]),
        one_time_prekey: None,
        one_time_prekey_id: None,
    };
    assert!(deserialize_prekey_bundle(&bundle).is_err());
}

#[test]
fn deserialize_prekey_bundle_short_signature() {
    // Valid hex but not 64 bytes for Ed25519 signature
    let bundle = SerializablePrekeyBundle {
        identity_key: hex::encode([0u8; 32]),
        signed_prekey: hex::encode([0u8; 32]),
        signed_prekey_sig: hex::encode([0u8; 32]), // Too short for sig
        node_id: hex::encode([0u8; 32]),
        one_time_prekey: None,
        one_time_prekey_id: None,
    };
    assert!(deserialize_prekey_bundle(&bundle).is_err());
}

#[test]
fn deserialize_prekey_bundle_invalid_node_id() {
    let bundle = SerializablePrekeyBundle {
        identity_key: hex::encode([0u8; 32]),
        signed_prekey: hex::encode([0u8; 32]),
        signed_prekey_sig: hex::encode([0u8; 64]),
        node_id: "short".into(),
        one_time_prekey: None,
        one_time_prekey_id: None,
    };
    assert!(deserialize_prekey_bundle(&bundle).is_err());
}

#[test]
fn ratchet_message_from_bytes_too_short() {
    // Less than 40 bytes should fail
    let result = ratchet_message_from_bytes(&[0u8; 39]);
    assert!(result.is_err());
}

#[test]
fn ratchet_message_from_bytes_exact_header() {
    // Exactly 40 bytes — header only, empty ciphertext
    let result = ratchet_message_from_bytes(&[0u8; 40]);
    assert!(result.is_ok());
    assert!(result.unwrap().ciphertext.is_empty());
}

#[test]
fn ratchet_message_roundtrip_preserves_data() {
    let msg = RatchetMessage {
        header: MessageHeader {
            dh_public: [0xABu8; 32],
            previous_chain_length: 42,
            message_number: 999,
        },
        ciphertext: vec![1, 2, 3, 4, 5],
    };

    let bytes = ratchet_message_to_bytes(&msg);
    let recovered = ratchet_message_from_bytes(&bytes).unwrap();

    assert_eq!(recovered.header, msg.header);
    assert_eq!(recovered.ciphertext, msg.ciphertext);
}

#[tokio::test]
async fn replenish_prekeys_when_empty() {
    let identity = make_identity(TEST_MNEMONIC_A);
    let mgr = SessionManager::new(identity);

    // Consume all OPKs
    {
        let mut otpks = mgr.one_time_prekeys.write().await;
        otpks.clear();
    }

    // Replenish
    mgr.replenish_prekeys().await;

    let otpks = mgr.one_time_prekeys.read().await;
    assert_eq!(otpks.len(), 10, "should replenish to 10 OPKs from empty");
}

#[tokio::test]
async fn replenish_prekeys_when_already_full() {
    let identity = make_identity(TEST_MNEMONIC_A);
    let mgr = SessionManager::new(identity);

    let initial_count = mgr.one_time_prekeys.read().await.len();
    assert_eq!(initial_count, 10, "starts with 10 OPKs");

    // Replenish should be a no-op
    mgr.replenish_prekeys().await;

    let count = mgr.one_time_prekeys.read().await.len();
    assert_eq!(count, 10, "should still be 10 OPKs");
}

#[tokio::test]
async fn replenish_prekeys_partial() {
    let identity = make_identity(TEST_MNEMONIC_A);
    let mgr = SessionManager::new(identity);

    // Reduce to 3 OPKs (below threshold of 5)
    {
        let mut otpks = mgr.one_time_prekeys.write().await;
        otpks.truncate(3);
    }

    mgr.replenish_prekeys().await;

    let count = mgr.one_time_prekeys.read().await.len();
    assert_eq!(count, 10, "should replenish to 10 from 3");
}

#[tokio::test]
async fn remove_nonexistent_session_returns_false() {
    let identity = make_identity(TEST_MNEMONIC_A);
    let mgr = SessionManager::new(identity);

    let fake_peer = NodeId::from_bytes([99u8; 32]);
    assert!(!mgr.remove_session(&fake_peer).await);
}

#[tokio::test]
async fn decrypt_without_session_fails() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let node_b = NodeId::from_bytes([99u8; 32]);

    let mgr_a = SessionManager::new(id_a);

    // Fake ratchet message
    let fake_msg = RatchetMessage {
        header: MessageHeader {
            dh_public: [0u8; 32],
            previous_chain_length: 0,
            message_number: 0,
        },
        ciphertext: vec![1, 2, 3],
    };

    let result = mgr_a.decrypt(&node_b, &fake_msg).await;
    assert!(matches!(result, Err(SessionError::NoSession(_))));
}

#[tokio::test]
async fn stored_session_cannot_move_to_another_peer() {
    let identity = make_identity(TEST_MNEMONIC_A);
    let other = SessionManager::new(make_identity(TEST_MNEMONIC_B));
    let store = MemorySessionStore::new();
    let manager = SessionManager::with_store(identity.clone(), store.clone());
    let peer = *other.identity.node_id();
    manager.initiate_session(&peer, &other.prekey_bundle().await).await.unwrap();
    let moved = NodeId::from_bytes([19; 32]);
    for after_send in [false, true] {
        if after_send {
            manager.encrypt(&peer, b"persisted send").await.unwrap();
        }
        let blob = store.load_session(&peer).await.unwrap().unwrap();
        store.save_session(&moved, &blob).await.unwrap();
        let restarted = SessionManager::with_store(identity.clone(), store.clone());
        assert_eq!(restarted.restore_sessions().await, 1);
        assert!(restarted.has_session(&peer).await);
        assert!(!restarted.has_session(&moved).await);
    }
}

#[test]
fn session_v1_is_readable_only_before_local_cutoff() {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
    let identity = make_identity(TEST_MNEMONIC_A);
    let dir = tempfile::tempdir().unwrap();
    let policy = LegacyReadPolicy::in_data_dir(dir.path());
    let manager = SessionManager::new(identity.clone()).with_record_policy(policy.clone());
    let key = blake3::derive_key(SESSION_ENCRYPTION_CTX, identity.aes_key());
    let nonce = [3u8; 12];
    let mut blob = nonce.to_vec();
    blob.extend(Aes256Gcm::new_from_slice(&key).unwrap().encrypt((&nonce).into(), b"legacy".as_slice()).unwrap());
    let peer = NodeId::from_bytes([19; 32]);
    assert_eq!(manager.decrypt_session_blob(&peer, &blob).unwrap(), b"legacy");
    policy.complete().unwrap();
    assert!(manager.decrypt_session_blob(&peer, &blob).is_err());
    assert!(manager.decrypt_or_migrate_blob(&peer, b"{}", true).is_none());
}

// ── Validate before replace ─────────────────────────────────────────

#[tokio::test]
async fn reinitiate_session_replaces_only_after_the_bundle_validates() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_a = *id_a.node_id();
    let node_b = *id_b.node_id();
    let mgr_a = SessionManager::new(id_a);
    let mgr_b = SessionManager::new(id_b);

    let init = mgr_a
        .initiate_session(&node_b, &mgr_b.prekey_bundle().await)
        .await
        .unwrap();
    mgr_b.accept_session(&node_a, &init).await.unwrap();

    // A forged signature and a malformed key are refused before anything
    // is touched: the session keeps working.
    let genuine = mgr_b.prekey_bundle().await;
    let mut forged = genuine.clone();
    forged.signed_prekey_sig = hex::encode([0u8; 64]);
    assert!(matches!(
        mgr_a.reinitiate_session(&node_b, &forged).await,
        Err(SessionError::KeyAgreement(_))
    ));
    let mut short = genuine.clone();
    short.identity_key = hex::encode([1u8; 31]);
    assert!(matches!(
        mgr_a.reinitiate_session(&node_b, &short).await,
        Err(SessionError::InvalidPeerData(_))
    ));
    let msg = mgr_a.encrypt(&node_b, b"still here").await.unwrap();
    assert_eq!(mgr_b.decrypt(&node_a, &msg).await.unwrap(), b"still here");

    // The non-replacing entry point still refuses while a session exists;
    // a valid bundle through the replacing one re-keys.
    assert!(matches!(
        mgr_a.initiate_session(&node_b, &genuine).await,
        Err(SessionError::SessionExists(_))
    ));
    let init = mgr_a.reinitiate_session(&node_b, &genuine).await.unwrap();
    assert!(mgr_a.can_send(&node_b).await);
    // Until the peer confirms, the initiator stays on the session it has.
    let msg = mgr_a.encrypt(&node_b, b"old session").await.unwrap();
    assert_eq!(mgr_b.decrypt(&node_a, &msg).await.unwrap(), b"old session");
    mgr_b.reaccept_session(&node_a, &init).await.unwrap();
    assert!(mgr_a.confirm_session(&node_b).await);
    let msg = mgr_a.encrypt(&node_b, b"new session").await.unwrap();
    assert_eq!(mgr_b.decrypt(&node_a, &msg).await.unwrap(), b"new session");
}

#[tokio::test]
async fn reaccept_session_refuses_bad_inits_and_consumes_no_prekey() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let node_a = *id_a.node_id();
    let node_b = *id_b.node_id();
    let mgr_a = SessionManager::new(id_a);
    let mgr_b = SessionManager::new(id_b);

    let init = mgr_a
        .initiate_session(&node_b, &mgr_b.prekey_bundle().await)
        .await
        .unwrap();
    mgr_b.accept_session(&node_a, &init).await.unwrap();

    let pool_before: Vec<u32> = mgr_b
        .one_time_prekeys
        .read()
        .await
        .iter()
        .map(|k| k.id)
        .collect();
    let held = pool_before[0];
    let key = hex::encode([2u8; 32]);
    let unknown_prekey = SerializableSessionInit {
        identity_key: key.clone(),
        ephemeral_key: key.clone(),
        one_time_prekey_id: Some(u32::MAX),
        ratchet_key: key.clone(),
    };
    assert!(matches!(
        mgr_b.reaccept_session(&node_a, &unknown_prekey).await,
        Err(SessionError::InvalidPeerData(_))
    ));
    let bad_key = SerializableSessionInit {
        identity_key: "not hex".into(),
        one_time_prekey_id: Some(held),
        ..unknown_prekey.clone()
    };
    assert!(matches!(
        mgr_b.reaccept_session(&node_a, &bad_key).await,
        Err(SessionError::InvalidPeerData(_))
    ));
    let bad_ratchet_key = SerializableSessionInit {
        ratchet_key: hex::encode([3u8; 16]),
        one_time_prekey_id: Some(held),
        ..unknown_prekey.clone()
    };
    assert!(matches!(
        mgr_b.reaccept_session(&node_a, &bad_ratchet_key).await,
        Err(SessionError::InvalidPeerData(_))
    ));

    // Nothing consumed, nothing replaced.
    let pool_after: Vec<u32> = mgr_b
        .one_time_prekeys
        .read()
        .await
        .iter()
        .map(|k| k.id)
        .collect();
    assert_eq!(
        pool_after, pool_before,
        "a refused init consumes no one-time pre-key"
    );
    let msg = mgr_a.encrypt(&node_b, b"still here").await.unwrap();
    assert_eq!(mgr_b.decrypt(&node_a, &msg).await.unwrap(), b"still here");

    // The non-replacing entry point is as strict about the pre-key id.
    let mgr_c = SessionManager::new(make_identity(TEST_MNEMONIC_B));
    assert!(matches!(
        mgr_c.accept_session(&node_a, &unknown_prekey).await,
        Err(SessionError::InvalidPeerData(_))
    ));
    assert!(!mgr_c.has_session(&node_a).await);
}

/// A derived session knows its age; one restored from storage does not, so
/// nothing is ever judged older than it.
#[tokio::test]
async fn session_age_is_known_only_for_a_session_derived_here() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let (node_a, node_b) = (*id_a.node_id(), *id_b.node_id());
    let store_b = MemorySessionStore::new();
    let mgr_a = SessionManager::new(Arc::clone(&id_a));
    let mgr_b = SessionManager::with_store(Arc::clone(&id_b), store_b.clone());
    assert!(!mgr_a.session_newer_than(&node_b, 0).await, "no session");

    let init_data = mgr_a.initiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    mgr_b.accept_session(&node_a, &init_data).await.unwrap();
    assert!(mgr_a.session_newer_than(&node_b, 0).await);
    assert!(mgr_b.session_newer_than(&node_a, 0).await);
    assert!(!mgr_a.session_newer_than(&node_b, u64::MAX).await);
    assert!(!mgr_b.session_newer_than(&node_a, u64::MAX).await);

    let restored = SessionManager::with_store(id_b, store_b);
    assert_eq!(restored.restore_sessions().await, 1);
    assert!(restored.has_session(&node_a).await);
    assert!(!restored.session_newer_than(&node_a, 0).await, "age unknown after a restore");
}

/// A replacement never confirmed changes nothing, however it ends; an unexpected
/// confirmation changes nothing either. The first session is confirmed once.
#[tokio::test]
async fn an_unconfirmed_replacement_leaves_the_session_in_use() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let (node_a, node_b) = (*id_a.node_id(), *id_b.node_id());
    let mgr_a = SessionManager::new(Arc::clone(&id_a));
    let mgr_b = SessionManager::new(Arc::clone(&id_b));
    let init = mgr_a.initiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    mgr_b.accept_session(&node_a, &init).await.unwrap();
    assert!(mgr_a.confirm_session(&node_b).await, "the first session was awaited");
    assert!(!mgr_a.confirm_session(&node_b).await, "once");
    assert!(!mgr_b.confirm_session(&node_a).await, "the responder awaits nothing");

    let roundtrip = async |text: &[u8]| {
        let msg = mgr_a.encrypt(&node_b, text).await.unwrap();
        assert_eq!(mgr_b.decrypt(&node_a, &msg).await.unwrap(), text);
    };
    roundtrip(b"first").await;
    mgr_a.reinitiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    roundtrip(b"still the first session").await;
    roundtrip(b"however long it stays unconfirmed").await;
}

/// A well-formed init whose keys the peer does not share leaves the session in use:
/// the acceptor moves only when a message decrypts under the new session, and a real
/// re-key does that. An acknowledgement does not confirm a session we only accepted.
#[tokio::test]
async fn an_accepted_session_is_proven_only_by_a_message_under_it() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let (node_a, node_b) = (*id_a.node_id(), *id_b.node_id());
    let mgr_a = SessionManager::new(Arc::clone(&id_a));
    let mgr_b = SessionManager::new(Arc::clone(&id_b));
    let init = mgr_a.initiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    mgr_b.accept_session(&node_a, &init).await.unwrap();

    let key = hex::encode(*X25519Public::from(&x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng())).as_bytes());
    let unproven = SerializableSessionInit { identity_key: key.clone(), ephemeral_key: key.clone(), one_time_prekey_id: None, ratchet_key: key };
    mgr_b.reaccept_session(&node_a, &unproven).await.unwrap();
    assert!(!mgr_b.confirm_session(&node_a).await, "an ack proves nothing here");
    let msg = mgr_a.encrypt(&node_b, b"same session").await.unwrap();
    assert_eq!(mgr_b.decrypt(&node_a, &msg).await.unwrap(), b"same session");

    let init = mgr_a.reinitiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    mgr_b.reaccept_session(&node_a, &init).await.unwrap();
    assert!(mgr_a.confirm_session(&node_b).await);
    let msg = mgr_a.encrypt(&node_b, b"new session").await.unwrap();
    assert_eq!(mgr_b.preview_decrypt(&node_a, &msg).await.unwrap(), b"new session");
    assert_eq!(mgr_b.decrypt(&node_a, &msg).await.unwrap(), b"new session");
    let back = mgr_b.encrypt(&node_a, b"on the new session").await.unwrap();
    assert_eq!(mgr_a.decrypt(&node_b, &back).await.unwrap(), b"on the new session");
}

/// The renegotiation mark lasts until a new session is installed.
#[tokio::test]
async fn a_new_session_clears_the_renegotiation_mark() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let (node_a, node_b) = (*id_a.node_id(), *id_b.node_id());
    let mgr_a = SessionManager::new(Arc::clone(&id_a));
    let mgr_b = SessionManager::new(Arc::clone(&id_b));
    let init = mgr_a.initiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    mgr_b.accept_session(&node_a, &init).await.unwrap();
    assert!(!mgr_a.needs_renegotiation(&node_b).await);
    mgr_a.mark_needs_renegotiation(&node_b).await;
    mgr_b.mark_needs_renegotiation(&node_a).await;
    assert!(mgr_a.needs_renegotiation(&node_b).await);

    let init = mgr_a.reinitiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    assert!(mgr_a.needs_renegotiation(&node_b).await, "not until the peer confirms");
    mgr_b.reaccept_session(&node_a, &init).await.unwrap();
    assert!(mgr_b.needs_renegotiation(&node_a).await, "not until the new session is proven");
    assert!(mgr_a.confirm_session(&node_b).await);
    assert!(!mgr_a.needs_renegotiation(&node_b).await);
    let msg = mgr_a.encrypt(&node_b, b"ratchet-init").await.unwrap();
    mgr_b.decrypt(&node_a, &msg).await.unwrap();
    assert!(!mgr_b.needs_renegotiation(&node_a).await);
}

/// A message that decrypts shows the two sides agree, so the mark clears. A session
/// the peer has not confirmed is reported until it does.
#[tokio::test]
async fn a_readable_message_clears_the_mark_and_confirmation_is_reported() {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let (node_a, node_b) = (*id_a.node_id(), *id_b.node_id());
    let mgr_a = SessionManager::new(Arc::clone(&id_a));
    let mgr_b = SessionManager::new(Arc::clone(&id_b));
    let init = mgr_a.initiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    mgr_b.accept_session(&node_a, &init).await.unwrap();
    assert!(mgr_a.awaiting_confirmation(&node_b).await);
    assert!(!mgr_b.awaiting_confirmation(&node_a).await, "the acceptor awaits nothing");
    assert!(mgr_a.confirm_session(&node_b).await);
    assert!(!mgr_a.awaiting_confirmation(&node_b).await);

    mgr_b.mark_needs_renegotiation(&node_a).await;
    let msg = mgr_a.encrypt(&node_b, b"readable").await.unwrap();
    assert_eq!(mgr_b.preview_decrypt(&node_a, &msg).await.unwrap(), b"readable");
    assert!(mgr_b.needs_renegotiation(&node_a).await, "a preview changes nothing");
    assert_eq!(mgr_b.decrypt(&node_a, &msg).await.unwrap(), b"readable");
    assert!(!mgr_b.needs_renegotiation(&node_a).await);
}

/// A store whose saves fail on demand.
#[derive(Default)]
struct FlakyStore {
    data: tokio::sync::RwLock<HashMap<NodeId, Vec<u8>>>,
    fail: std::sync::atomic::AtomicBool,
    /// When set, every second save fails.
    alternate: std::sync::atomic::AtomicBool,
    saves: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl SessionStore for FlakyStore {
    async fn save_session(&self, peer_id: &NodeId, state_json: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::sync::atomic::Ordering::SeqCst;
        let save = self.saves.fetch_add(1, SeqCst);
        // Saves take time, so that a send racing this one has a chance to interleave.
        tokio::task::yield_now().await;
        if self.fail.load(SeqCst) || (self.alternate.load(SeqCst) && save.is_multiple_of(2)) {
            return Err("test: disk full".into());
        }
        self.data.write().await.insert(*peer_id, state_json.to_vec());
        Ok(())
    }
    async fn load_session(&self, peer_id: &NodeId) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.data.read().await.get(peer_id).cloned())
    }
    async fn delete_session(&self, peer_id: &NodeId) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.data.write().await.remove(peer_id);
        Ok(())
    }
    async fn list_sessions(&self) -> Result<Vec<NodeId>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.data.read().await.keys().copied().collect())
    }
}

/// A sender with a store and a receiver holding the matching session.
async fn saving_sender() -> (Arc<NodeIdentity>, Arc<FlakyStore>, SessionManager, SessionManager, NodeId, NodeId) {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let (node_a, node_b) = (*id_a.node_id(), *id_b.node_id());
    let store = Arc::new(FlakyStore::default());
    let sender = SessionManager::with_store(Arc::clone(&id_a), store.clone());
    let receiver = SessionManager::new(id_b);
    let init = sender.initiate_session(&node_b, &receiver.prekey_bundle().await).await.unwrap();
    receiver.accept_session(&node_a, &init).await.unwrap();
    (id_a, store, sender, receiver, node_a, node_b)
}

/// A failed save returns no ciphertext. The chain goes back, so the next send takes
/// the same position and the receiver sees no gap.
#[tokio::test]
async fn failed_save_withholds_the_ciphertext_and_puts_the_chain_back() {
    use std::sync::atomic::Ordering::SeqCst;
    let (_, store, sender, receiver, node_a, node_b) = saving_sender().await;
    let first = sender.encrypt(&node_b, b"first").await.unwrap();
    assert_eq!(receiver.decrypt(&node_a, &first).await.unwrap(), b"first");

    store.fail.store(true, SeqCst);
    assert!(matches!(sender.encrypt(&node_b, b"withheld").await, Err(SessionError::NotPersisted)));
    assert!(sender.has_session(&node_b).await, "the session stays");

    store.fail.store(false, SeqCst);
    let next = sender.encrypt(&node_b, b"next").await.unwrap();
    assert_eq!(next.header.message_number, first.header.message_number + 1, "the chain was put back");
    assert_eq!(receiver.decrypt(&node_a, &next).await.unwrap(), b"next");
}

/// Failed save, then a restart: nothing that left is sent again under the same key
/// and nonce. Before this fix the failed send left anyway, and the restored chain
/// then used its position again for a different plaintext.
#[tokio::test]
async fn failed_save_then_restart_repeats_no_key_and_nonce() {
    use std::sync::atomic::Ordering::SeqCst;
    let (id_a, store, sender, receiver, node_a, node_b) = saving_sender().await;
    let mut released = vec![sender.encrypt(&node_b, b"saved").await.unwrap()];

    store.fail.store(true, SeqCst);
    if let Ok(message) = sender.encrypt(&node_b, b"not saved").await {
        released.push(message);
    }
    store.fail.store(false, SeqCst);
    drop(sender);

    let restarted = SessionManager::with_store(id_a, store.clone());
    assert_eq!(restarted.restore_sessions().await, 1);
    released.push(restarted.encrypt(&node_b, b"after the restart").await.unwrap());

    // Key and nonce both derive from the chain position, so one position must never
    // carry two messages.
    let mut positions: Vec<_> = released.iter().map(|m| (m.header.dh_public, m.header.message_number)).collect();
    positions.sort();
    positions.dedup();
    assert_eq!(positions.len(), released.len(), "a chain position was used twice");
    let texts: Vec<&[u8]> = vec![b"saved", b"after the restart"];
    for (message, text) in released.iter().zip(texts) {
        assert_eq!(receiver.decrypt(&node_a, message).await.unwrap(), text);
    }
}

/// Both sides with a store, a session each way, and everything that has left so far.
async fn saving_pair() -> (Arc<NodeIdentity>, Arc<NodeIdentity>, Arc<FlakyStore>, Arc<FlakyStore>, SessionManager, SessionManager, NodeId, NodeId, Vec<(RatchetMessage, bool)>) {
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let (node_a, node_b) = (*id_a.node_id(), *id_b.node_id());
    let (store_a, store_b) = (Arc::new(FlakyStore::default()), Arc::new(FlakyStore::default()));
    let mgr_a = SessionManager::with_store(Arc::clone(&id_a), store_a.clone());
    let mgr_b = SessionManager::with_store(Arc::clone(&id_b), store_b.clone());
    let init = mgr_a.initiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    mgr_b.accept_session(&node_a, &init).await.unwrap();
    let first = mgr_a.encrypt(&node_b, b"first").await.unwrap();
    mgr_b.decrypt(&node_a, &first).await.unwrap();
    let back = mgr_b.encrypt(&node_a, b"back").await.unwrap();
    mgr_a.decrypt(&node_b, &back).await.unwrap();
    (id_a, id_b, store_a, store_b, mgr_a, mgr_b, node_a, node_b, vec![(first, true), (back, false)])
}

/// One position must never carry two messages, per sender: key and nonce derive from it.
fn assert_no_position_twice(released: &[(RatchetMessage, bool)]) {
    let mut positions: Vec<_> = released.iter().map(|(m, from_a)| (*from_a, m.header.dh_public, m.header.message_number)).collect();
    positions.sort();
    positions.dedup();
    assert_eq!(positions.len(), released.len(), "a chain position was used twice");
}

/// A replacement, a resent `RatchetInit`, a read under the replaced session, then both
/// sides restart. Every message that left has its own position, and they still talk.
#[tokio::test]
async fn a_replacement_and_a_restart_repeat_no_position() {
    let (id_a, id_b, store_a, store_b, mgr_a, mgr_b, node_a, node_b, mut released) = saving_pair().await;
    let stale = mgr_b.encrypt(&node_a, b"under the replaced session").await.unwrap();
    released.push((stale.clone(), false));

    let init = mgr_a.reinitiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    mgr_b.reaccept_session(&node_a, &init).await.unwrap();
    assert!(mgr_a.confirm_session(&node_b).await);
    assert_eq!(mgr_a.decrypt(&node_b, &stale).await.unwrap(), b"under the replaced session");

    // The first `RatchetInit` is lost; the next moves the acceptor over.
    released.push((mgr_a.encrypt(&node_b, b"ratchet-init").await.unwrap(), true));
    let resent = mgr_a.encrypt(&node_b, b"ratchet-init").await.unwrap();
    released.push((resent.clone(), true));
    mgr_b.decrypt(&node_a, &resent).await.unwrap();
    released.push((mgr_b.encrypt(&node_a, b"on the new session").await.unwrap(), false));
    drop((mgr_a, mgr_b));

    let (mgr_a, mgr_b) = (SessionManager::with_store(id_a, store_a), SessionManager::with_store(id_b, store_b));
    assert_eq!(mgr_a.restore_sessions().await, 1);
    assert_eq!(mgr_b.restore_sessions().await, 1);
    let (to_b, to_a) = (mgr_a.encrypt(&node_b, b"after").await.unwrap(), mgr_b.encrypt(&node_a, b"after").await.unwrap());
    released.extend([(to_b.clone(), true), (to_a.clone(), false)]);
    assert_no_position_twice(&released);
    assert_eq!(mgr_b.decrypt(&node_a, &to_b).await.unwrap(), b"after");
    assert_eq!(mgr_a.decrypt(&node_b, &to_a).await.unwrap(), b"after");
}

/// The save fails right after the initiator moves to a new session. Nothing under it
/// leaves. A restart goes back to the saved session, where sends carry on from where
/// they were, and the peer that still holds that session reads them.
#[tokio::test]
async fn a_replacement_that_could_not_be_saved_repeats_no_position_after_a_restart() {
    use std::sync::atomic::Ordering::SeqCst;
    let (id_a, _, store_a, _, mgr_a, mgr_b, node_a, node_b, mut released) = saving_pair().await;
    released.push((mgr_a.encrypt(&node_b, b"saved").await.unwrap(), true));

    let init = mgr_a.reinitiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    mgr_b.reaccept_session(&node_a, &init).await.unwrap();
    store_a.fail.store(true, SeqCst);
    assert!(mgr_a.confirm_session(&node_b).await);
    assert!(matches!(mgr_a.encrypt(&node_b, b"ratchet-init").await, Err(SessionError::NotPersisted)));
    drop(mgr_a);
    store_a.fail.store(false, SeqCst);

    let restarted = SessionManager::with_store(id_a, store_a);
    assert_eq!(restarted.restore_sessions().await, 1);
    let after = restarted.encrypt(&node_b, b"after the restart").await.unwrap();
    released.push((after.clone(), true));
    assert_no_position_twice(&released);
    assert_eq!(mgr_b.decrypt(&node_a, &released[2].0).await.unwrap(), b"saved");
    assert_eq!(mgr_b.decrypt(&node_a, &after).await.unwrap(), b"after the restart");
}

/// The same on the acceptor: it moves over on a message, the save fails, and nothing
/// under the new session leaves. A restart puts it back on the saved session.
#[tokio::test]
async fn an_acceptor_that_could_not_save_the_move_repeats_no_position_after_a_restart() {
    use std::sync::atomic::Ordering::SeqCst;
    let (_, id_b, _, store_b, mgr_a, mgr_b, node_a, node_b, mut released) = saving_pair().await;
    released.push((mgr_b.encrypt(&node_a, b"saved").await.unwrap(), false));

    let init = mgr_a.reinitiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    mgr_b.reaccept_session(&node_a, &init).await.unwrap();
    assert!(mgr_a.confirm_session(&node_b).await);
    let moves_it = mgr_a.encrypt(&node_b, b"ratchet-init").await.unwrap();
    store_b.fail.store(true, SeqCst);
    mgr_b.decrypt(&node_a, &moves_it).await.unwrap();
    assert!(matches!(mgr_b.encrypt(&node_a, b"withheld").await, Err(SessionError::NotPersisted)));
    drop(mgr_b);
    store_b.fail.store(false, SeqCst);

    let restarted = SessionManager::with_store(id_b, store_b);
    assert_eq!(restarted.restore_sessions().await, 1);
    let after = restarted.encrypt(&node_a, b"after the restart").await.unwrap();
    released.push((after.clone(), false));
    assert_no_position_twice(&released);
    // The initiator replaced that session, and can still read under it.
    assert_eq!(mgr_a.decrypt(&node_b, &after).await.unwrap(), b"after the restart");
}

/// A replaced session reads what was encrypted under it, on a preview too, and that
/// shows the peer has not moved over, so a `RatchetInit` is owed once. A restored
/// manager has no replaced session: it never reaches storage.
#[tokio::test]
async fn a_replaced_session_only_reads_and_is_not_saved() {
    let (id_a, _, store_a, _, mgr_a, mgr_b, node_a, node_b, _) = saving_pair().await;
    let first = mgr_b.encrypt(&node_a, b"first").await.unwrap();
    let second = mgr_b.encrypt(&node_a, b"second").await.unwrap();
    let init = mgr_a.reinitiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    mgr_b.reaccept_session(&node_a, &init).await.unwrap();
    assert!(mgr_a.confirm_session(&node_b).await);
    assert!(!mgr_a.take_ratchet_init_owed(&node_b).await);

    assert_eq!(mgr_a.preview_decrypt(&node_b, &first).await.unwrap(), b"first");
    assert!(!mgr_a.take_ratchet_init_owed(&node_b).await, "a preview changes nothing");
    assert_eq!(mgr_a.decrypt(&node_b, &first).await.unwrap(), b"first");
    assert!(mgr_a.take_ratchet_init_owed(&node_b).await);
    assert!(!mgr_a.take_ratchet_init_owed(&node_b).await, "once");
    mgr_a.mark_needs_renegotiation(&node_b).await;
    assert_eq!(mgr_a.decrypt(&node_b, &second).await.unwrap(), b"second");
    assert!(mgr_a.needs_renegotiation(&node_b).await, "this says nothing about the session in use");

    // What it sends is under the new session: the acceptor moves over on it.
    let sent = mgr_a.encrypt_recovery_probe(&node_b).await.unwrap();
    mgr_b.decrypt(&node_a, &sent).await.unwrap();
    assert!(mgr_a.preview_decrypt(&node_b, &mgr_b.encrypt(&node_a, b"on it").await.unwrap()).await.is_ok());

    drop(mgr_a);
    let restored = SessionManager::with_store(id_a, store_a);
    assert_eq!(restored.restore_sessions().await, 1);
    let late = mgr_b.encrypt(&node_a, b"late").await.unwrap();
    assert!(restored.preview_decrypt(&node_b, &late).await.is_ok(), "the saved session is the new one");
}

/// A replaced session stops reading after its time, and then goes.
#[tokio::test]
async fn a_replaced_session_stops_reading_after_its_time() {
    let (_, _, _, _, mgr_a, mgr_b, node_a, node_b, _) = saving_pair().await;
    let late = mgr_b.encrypt(&node_a, b"late").await.unwrap();
    let init = mgr_a.reinitiate_session(&node_b, &mgr_b.prekey_bundle().await).await.unwrap();
    mgr_b.reaccept_session(&node_a, &init).await.unwrap();
    assert!(mgr_a.confirm_session(&node_b).await);
    assert!(mgr_a.preview_decrypt(&node_b, &late).await.is_ok());

    mgr_a.expire_retired_sessions().await;
    assert!(mgr_a.sessions.read().await[&node_b].retired.is_some(), "still in its time");
    mgr_a.sessions.write().await.get_mut(&node_b).unwrap().retired.as_mut().unwrap().since -= RETIRED_SESSION_READS_FOR + std::time::Duration::from_secs(1);
    assert!(mgr_a.preview_decrypt(&node_b, &late).await.is_err());
    assert!(mgr_a.decrypt(&node_b, &late).await.is_err());
    mgr_a.expire_retired_sessions().await;
    assert!(mgr_a.sessions.read().await[&node_b].retired.is_none());
}

/// Sends racing a failing save never build on a chain that is then put back: every
/// ciphertext that left has its own position and reads at the receiver.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_sends_with_failing_saves_never_share_a_position() {
    use std::sync::atomic::Ordering::SeqCst;
    let (_, store, sender, receiver, node_a, node_b) = saving_sender().await;
    let sender = Arc::new(sender);
    store.alternate.store(true, SeqCst);
    let mut tasks = Vec::new();
    for n in 0..64u8 {
        let (sender, node_b) = (Arc::clone(&sender), node_b);
        tasks.push(tokio::spawn(async move { sender.encrypt(&node_b, &[n]).await }));
    }
    let mut released = Vec::new();
    for task in tasks {
        if let Ok(message) = task.await.unwrap() {
            released.push(message);
        }
    }
    assert!(!released.is_empty() && released.len() < 64, "some saves failed: {}", released.len());
    released.sort_by_key(|m| m.header.message_number);
    let numbers: Vec<u32> = released.iter().map(|m| m.header.message_number).collect();
    assert_eq!(numbers, (0..released.len() as u32).collect::<Vec<_>>(), "no gaps and no repeats");
    for message in &released {
        receiver.decrypt(&node_a, message).await.unwrap();
    }
}

/// Receiving keeps its existing rule: a failed save does not refuse a readable
/// message, so a paid envelope is not burned for that alone.
#[tokio::test]
async fn failed_save_does_not_refuse_a_readable_message() {
    use std::sync::atomic::Ordering::SeqCst;
    let id_a = make_identity(TEST_MNEMONIC_A);
    let id_b = make_identity(TEST_MNEMONIC_B);
    let (node_a, node_b) = (*id_a.node_id(), *id_b.node_id());
    let store = Arc::new(FlakyStore::default());
    let sender = SessionManager::new(id_a);
    let receiver = SessionManager::with_store(id_b, store.clone());
    let init = sender.initiate_session(&node_b, &receiver.prekey_bundle().await).await.unwrap();
    receiver.accept_session(&node_a, &init).await.unwrap();
    store.fail.store(true, SeqCst);
    let message = sender.encrypt(&node_b, b"readable").await.unwrap();
    assert_eq!(receiver.decrypt(&node_a, &message).await.unwrap(), b"readable");
}

/// Each boot starts its one-time pre-key ids at its own random point, and they count
/// up from there.
#[tokio::test]
async fn prekey_ids_start_at_a_random_point_per_boot() {
    let identity = make_identity(TEST_MNEMONIC_A);
    let mut starts = Vec::new();
    for _ in 0..4 {
        let manager = SessionManager::new(Arc::clone(&identity));
        starts.push(manager.prekey_bundle().await.one_time_prekey_id.unwrap());
    }
    let with_store = SessionManager::with_store(Arc::clone(&identity), MemorySessionStore::new());
    starts.push(with_store.prekey_bundle().await.one_time_prekey_id.unwrap());
    let mut distinct = starts.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), starts.len(), "every boot picks its own: {starts:?}");
}

/// A ratchet failure during a send leaves the chain as it was, with a store and
/// without one, so the next send takes the same position.
#[tokio::test]
async fn failed_aead_leaves_the_chain_as_it_was() {
    let (_, _store, sender, receiver, node_a, node_b) = saving_sender().await;
    let plain_sender = SessionManager::new(make_identity(TEST_MNEMONIC_A));
    let plain_receiver = SessionManager::new(make_identity(TEST_MNEMONIC_B));
    let init = plain_sender.initiate_session(&node_b, &plain_receiver.prekey_bundle().await).await.unwrap();
    plain_receiver.accept_session(&node_a, &init).await.unwrap();

    // Without a store this runs on this task's thread, where the failure is armed.
    crate::double_ratchet::FAIL_NEXT_AEAD_ENCRYPT.with(|fail| fail.set(true));
    assert!(plain_sender.encrypt(&node_b, b"fails").await.is_err());
    let message = plain_sender.encrypt(&node_b, b"next").await.unwrap();
    assert_eq!(message.header.message_number, 0, "the chain did not advance");
    assert_eq!(plain_receiver.decrypt(&node_a, &message).await.unwrap(), b"next");

    let message = sender.encrypt(&node_b, b"with a store").await.unwrap();
    assert_eq!(receiver.decrypt(&node_a, &message).await.unwrap(), b"with a store");
}

/// One point in different bytes compares equal; different points and bad hex do not.
#[test]
fn same_x25519_point_ignores_the_top_bit_only() {
    let key = [7u8; 32];
    let mut top_bit = key;
    top_bit[31] ^= 0x80;
    assert!(same_x25519_point(&hex::encode(key), &hex::encode(top_bit)));
    let mut other = key;
    other[0] ^= 0x01;
    assert!(!same_x25519_point(&hex::encode(key), &hex::encode(other)));
    assert!(!same_x25519_point(&hex::encode(key), "not hex"));
}

#[tokio::test]
async fn recovery_handover_holds_marked_sends_but_allows_recovery_probes() {
    for stored in [false, true] {
        let a_id = make_identity(TEST_MNEMONIC_A);
        let b_id = make_identity(TEST_MNEMONIC_B);
        let (aid, bid) = (*a_id.node_id(), *b_id.node_id());
        let a = if stored { SessionManager::with_store(a_id, Arc::new(FlakyStore::default())) } else { SessionManager::new(a_id) };
        let b = SessionManager::new(b_id);
        let init = a.initiate_session(&bid, &b.prekey_bundle().await).await.unwrap();
        b.accept_session(&aid, &init).await.unwrap();
        a.confirm_session(&bid).await;
        a.mark_needs_renegotiation(&bid).await;
        assert!(matches!(a.encrypt(&bid, b"application").await, Err(SessionError::HandoverPending)));
        let probe = a.encrypt_recovery_probe(&bid).await.unwrap();
        b.decrypt(&aid, &probe).await.unwrap();
        let reply = b.encrypt(&aid, b"reply").await.unwrap();
        a.decrypt(&bid, &reply).await.unwrap();
        let sent = a.encrypt(&bid, b"application").await.unwrap();
        assert_eq!(b.decrypt(&aid, &sent).await.unwrap(), b"application");
    }
}
