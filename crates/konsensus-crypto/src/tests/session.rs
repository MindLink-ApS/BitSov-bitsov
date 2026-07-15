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
    let mgr_a2 = SessionManager::with_store(Arc::clone(&id_a), store.clone());
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
