use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use super::*;
use tracing_subscriber::layer::SubscriberExt;

use konsensus_core::identity::NodeIdentity;
use konsensus_core::types::{MessageId, NodeId, Nonce, Recipient, Signature};
use konsensus_core::{PaymentProof, UkmEnvelopeBuilder};
use konsensus_storage::error::StorageError;
use konsensus_storage::models::{FileMetadata, FileRecord, Peer, Room};
use konsensus_storage::Storage;
use sha2::{Digest, Sha256};

// ── Minimal in-memory Storage for tests ─────────────────────────────

struct TestStorage {
    messages: Mutex<HashMap<String, konsensus_core::UkmEnvelope>>,
    files: Mutex<HashMap<String, FileRecord>>,
    plaintexts: Mutex<HashMap<String, Vec<u8>>>,
}

impl TestStorage {
    fn new() -> Self {
        Self {
            messages: Mutex::new(HashMap::new()),
            files: Mutex::new(HashMap::new()),
            plaintexts: Mutex::new(HashMap::new()),
        }
    }

    fn file_count(&self) -> usize {
        self.files.lock().unwrap().len()
    }

    fn only_file_size(&self) -> Option<u64> {
        self.files.lock().unwrap().values().next().map(|file| file.size_bytes)
    }

    fn has_plaintext(&self, id: &MessageId) -> bool {
        self.plaintexts.lock().unwrap().contains_key(&id.to_hex())
    }
}

#[async_trait::async_trait]
impl Storage for TestStorage {
    async fn store_message(
        &self,
        envelope: &konsensus_core::UkmEnvelope,
    ) -> Result<(), StorageError> {
        self.messages
            .lock()
            .unwrap()
            .insert(envelope.id.to_hex(), envelope.clone());
        Ok(())
    }
    async fn get_message(
        &self,
        id: &MessageId,
    ) -> Result<Option<konsensus_core::UkmEnvelope>, StorageError> {
        Ok(self.messages.lock().unwrap().get(&id.to_hex()).cloned())
    }
    async fn get_messages_for_recipient(
        &self,
        _r: &Recipient,
        _l: u32,
        _b: Option<u64>,
    ) -> Result<Vec<konsensus_core::UkmEnvelope>, StorageError> {
        Ok(vec![])
    }
    async fn get_conversation_messages(
        &self,
        _a: &str,
        _b: &str,
        _c: bool,
        _d: u32,
        _e: Option<u64>,
    ) -> Result<Vec<konsensus_core::UkmEnvelope>, StorageError> {
        Ok(vec![])
    }
    async fn delete_message(&self, _id: &MessageId) -> Result<bool, StorageError> {
        Ok(false)
    }
    async fn delete_messages_older_than(&self, _b: u64) -> Result<u64, StorageError> {
        Ok(0)
    }
    async fn create_room(&self, _r: &Room) -> Result<(), StorageError> {
        Ok(())
    }
    async fn get_room(&self, _id: &konsensus_core::RoomId) -> Result<Option<Room>, StorageError> {
        Ok(None)
    }
    async fn list_rooms(&self) -> Result<Vec<Room>, StorageError> {
        Ok(vec![])
    }
    async fn add_room_member(
        &self,
        _r: &konsensus_core::RoomId,
        _m: &NodeId,
    ) -> Result<(), StorageError> {
        Ok(())
    }
    async fn remove_room_member(
        &self,
        _r: &konsensus_core::RoomId,
        _m: &NodeId,
    ) -> Result<(), StorageError> {
        Ok(())
    }
    async fn delete_room(&self, _id: &konsensus_core::RoomId) -> Result<bool, StorageError> {
        Ok(false)
    }
    async fn get_room_members(
        &self,
        _r: &konsensus_core::RoomId,
    ) -> Result<Vec<NodeId>, StorageError> {
        Ok(vec![])
    }
    async fn upsert_peer(&self, _p: &Peer) -> Result<(), StorageError> {
        Ok(())
    }
    async fn get_peer(&self, _id: &NodeId) -> Result<Option<Peer>, StorageError> {
        Ok(None)
    }
    async fn list_peers(&self) -> Result<Vec<Peer>, StorageError> {
        Ok(vec![])
    }
    async fn delete_peer(&self, _id: &NodeId) -> Result<bool, StorageError> {
        Ok(false)
    }
    // This general route fixture accepts replay keys; the real SQLite and gate
    // suites exercise atomic replay rejection and rollback.
    async fn store_paid_nonce(
        &self,
        _nonce: &Nonce,
        _hash: &[u8; 32],
        _sender: &NodeId,
        _message: &MessageId,
    ) -> Result<konsensus_core::gate::PaidReplay, StorageError> {
        Ok(konsensus_core::gate::PaidReplay::Accepted)
    }

    async fn store_nonce(&self, _n: &Nonce, _s: &NodeId) -> Result<bool, StorageError> {
        Ok(true)
    }
    async fn has_nonce(&self, _n: &Nonce) -> Result<bool, StorageError> {
        Ok(false)
    }
    // HARD-5 (#237) made the Storage `store_payment_receipt` default fail-closed.
    // This in-memory test stub accepts fresh payment hashes (mirrors MemStorage +
    // store_nonce above) so a covering proof verifies; replay coverage lives in the
    // konsensus-storage backend suites.
    async fn store_payment_receipt(
        &self,
        _h: &[u8; 32],
        _s: &NodeId,
        _m: &MessageId,
    ) -> Result<bool, StorageError> {
        Ok(true)
    }
    async fn cleanup_expired_nonces(&self, _a: u64) -> Result<u64, StorageError> {
        Ok(0)
    }
    async fn store_session(&self, _p: &NodeId, _b: &[u8]) -> Result<(), StorageError> {
        Ok(())
    }
    async fn load_session(&self, _p: &NodeId) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }
    async fn delete_session(&self, _p: &NodeId) -> Result<bool, StorageError> {
        Ok(false)
    }
    async fn list_sessions(&self) -> Result<Vec<NodeId>, StorageError> {
        Ok(vec![])
    }
    async fn queue_pending_delivery(
        &self,
        _m: &MessageId,
        _r: &NodeId,
    ) -> Result<(), StorageError> {
        Ok(())
    }
    async fn get_pending_for_peer(
        &self,
        _r: &NodeId,
    ) -> Result<Vec<(MessageId, u32)>, StorageError> {
        Ok(vec![])
    }
    async fn remove_pending_delivery(
        &self,
        _m: &MessageId,
        _r: &NodeId,
    ) -> Result<(), StorageError> {
        Ok(())
    }
    async fn increment_pending_attempts(
        &self,
        _m: &MessageId,
        _r: &NodeId,
    ) -> Result<(), StorageError> {
        Ok(())
    }
    async fn get_pending_peers(&self) -> Result<Vec<NodeId>, StorageError> {
        Ok(vec![])
    }
    async fn count_pending_deliveries(&self) -> Result<u64, StorageError> {
        Ok(0)
    }
    async fn clear_pending_for_peer(&self, _r: &NodeId) -> Result<u64, StorageError> {
        Ok(0)
    }
    async fn cleanup_stale_pending(&self, _m: u32) -> Result<u64, StorageError> {
        Ok(0)
    }
    async fn store_file(&self, file: &FileRecord) -> Result<(), StorageError> {
        self.files
            .lock()
            .unwrap()
            .insert(file.id.clone(), file.clone());
        Ok(())
    }
    async fn get_file(&self, id: &str) -> Result<Option<FileRecord>, StorageError> {
        Ok(self.files.lock().unwrap().get(id).cloned())
    }
    async fn get_file_metadata(&self, _id: &str) -> Result<Option<FileMetadata>, StorageError> {
        Ok(None)
    }
    async fn list_files(&self, _l: u32) -> Result<Vec<FileMetadata>, StorageError> {
        Ok(vec![])
    }
    async fn delete_file(&self, _id: &str) -> Result<bool, StorageError> {
        Ok(false)
    }
    async fn store_message_plaintext(
        &self,
        id: &MessageId,
        data: &[u8],
    ) -> Result<(), StorageError> {
        self.plaintexts
            .lock()
            .unwrap()
            .insert(id.to_hex(), data.to_vec());
        Ok(())
    }
    async fn get_message_plaintext(&self, id: &MessageId) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.plaintexts.lock().unwrap().get(&id.to_hex()).cloned())
    }
}

// ── Test helpers ─────────────────────────────────────────────────────

fn test_identity(mnemonic: &str) -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(mnemonic, "").unwrap())
}

fn alice_identity() -> Arc<NodeIdentity> {
    test_identity("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
}

fn bob_identity() -> Arc<NodeIdentity> {
    test_identity("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
}

fn make_valid_proof(amount_msat: u64) -> PaymentProof {
    let preimage = [42u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    PaymentProof::new(hash, preimage, amount_msat)
}

fn make_envelope(
    sender: &NodeIdentity,
    recipient: NodeId,
    kind: u16,
    ciphertext: Vec<u8>,
) -> konsensus_core::UkmEnvelope {
    let proof = make_valid_proof(1_000);
    let mut env = UkmEnvelopeBuilder::new(
        kind,
        *sender.node_id(),
        Recipient::Node(recipient),
        ciphertext,
        proof,
    )
    .build();
    let sig = sender.sign(&env.signable_bytes());
    env.signature = Signature::from_ed25519(&sig);
    env
}

fn make_audit_log() -> Arc<AuditLog> {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    Arc::new(AuditLog::open(tmp.path()).unwrap())
}

fn make_transport(identity: &Arc<NodeIdentity>) -> Arc<konsensus_message::NoiseTransport> {
    use std::net::SocketAddr;
    let cfg = konsensus_message::TransportConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        ..Default::default()
    };
    Arc::new(konsensus_message::NoiseTransport::new(
        Arc::clone(identity),
        cfg,
    ))
}

/// Establish bidirectional E2EE sessions between two session managers.
async fn establish_sessions(
    alice_mgr: &SessionManager,
    bob_mgr: &SessionManager,
    alice_id: &NodeIdentity,
    bob_id: &NodeIdentity,
) {
    let bob_bundle = bob_mgr.prekey_bundle().await;
    let init_data = alice_mgr
        .initiate_session(bob_id.node_id(), &bob_bundle)
        .await
        .unwrap();
    bob_mgr
        .accept_session(alice_id.node_id(), &init_data)
        .await
        .unwrap();
}

// ── process_file_message tests ──────────────────────────────────────

#[tokio::test]
async fn process_file_valid_stores_file() {
    let alice = alice_identity();
    let bob = bob_identity();
    let storage: Arc<dyn Storage> = Arc::new(TestStorage::new());
    let audit = make_audit_log();

    let file_data = b"hello world file content";
    let hash = blake3::hash(file_data).to_hex().to_string();
    let data_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, file_data);

    let payload = serde_json::json!({
        "filename": "test.txt",
        "mime_type": "text/plain",
        "size_bytes": file_data.len(),
        "blake3_hash": hash,
        "data_b64": data_b64,
    });
    let bytes = serde_json::to_vec(&payload).unwrap();

    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_FILE_REF,
        b"encrypted".to_vec(),
    );
    let sender = *alice.node_id();

    let result = process_file_message(&bytes, &sender, &envelope, &storage, &audit).await;

    assert_eq!(result, Ok("[file: test.txt]".to_string()));
}

#[tokio::test]
async fn process_file_records_decoded_length_not_the_claimed_size() {
    let alice = alice_identity();
    let bob = bob_identity();
    let storage = Arc::new(TestStorage::new());
    let audit = make_audit_log();

    let file_data = b"hi";
    let hash = blake3::hash(file_data).to_hex().to_string();
    let data_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, file_data);
    let payload = serde_json::json!({
        "filename": "short.bin",
        "mime_type": "application/octet-stream",
        "size_bytes": u64::MAX,
        "blake3_hash": hash,
        "data_b64": data_b64,
    });
    let bytes = serde_json::to_vec(&payload).unwrap();
    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_FILE_REF,
        b"encrypted".to_vec(),
    );
    let stored = process_file_message(
        &bytes,
        alice.node_id(),
        &envelope,
        &(Arc::clone(&storage) as Arc<dyn Storage>),
        &audit,
    )
    .await;
    assert_eq!(stored, Ok("[file: short.bin]".to_string()));
    assert_eq!(storage.only_file_size(), Some(u64::try_from(file_data.len()).unwrap()));
}

#[tokio::test]
async fn process_file_hash_mismatch_is_refused() {
    let alice = alice_identity();
    let bob = bob_identity();
    let storage: Arc<dyn Storage> = Arc::new(TestStorage::new());
    let audit = make_audit_log();

    let file_data = b"hello world";
    let data_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, file_data);

    let payload = serde_json::json!({
        "filename": "corrupt.txt",
        "mime_type": "text/plain",
        "size_bytes": file_data.len(),
        "blake3_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "data_b64": data_b64,
    });
    let bytes = serde_json::to_vec(&payload).unwrap();

    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_FILE_REF,
        b"encrypted".to_vec(),
    );
    let sender = *alice.node_id();

    let result = process_file_message(&bytes, &sender, &envelope, &storage, &audit).await;

    // A hash mismatch is a damaged file: refused, never stored, never shown.
    assert_eq!(
        result,
        Err(ReceiptRefusal::FileCorrupted(
            "the file data does not match its hash"
        ))
    );
    assert!(storage.list_files(10).await.unwrap().is_empty());
}

#[tokio::test]
async fn process_file_invalid_json_is_refused() {
    let alice = alice_identity();
    let bob = bob_identity();
    let storage: Arc<dyn Storage> = Arc::new(TestStorage::new());
    let audit = make_audit_log();

    let bytes = b"not json";
    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_FILE_REF,
        b"enc".to_vec(),
    );
    let sender = *alice.node_id();

    let result = process_file_message(bytes, &sender, &envelope, &storage, &audit).await;
    assert_eq!(
        result,
        Err(ReceiptRefusal::FileCorrupted("the payload is not a file"))
    );
}

#[tokio::test]
async fn process_file_invalid_base64_is_refused() {
    let alice = alice_identity();
    let bob = bob_identity();
    let storage: Arc<dyn Storage> = Arc::new(TestStorage::new());
    let audit = make_audit_log();

    let payload = serde_json::json!({
        "filename": "broken.bin",
        "mime_type": "application/octet-stream",
        "size_bytes": 100,
        "blake3_hash": "abc123",
        "data_b64": "!!!not-valid-base64!!!",
    });
    let bytes = serde_json::to_vec(&payload).unwrap();

    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_FILE_REF,
        b"enc".to_vec(),
    );
    let sender = *alice.node_id();

    let result = process_file_message(&bytes, &sender, &envelope, &storage, &audit).await;

    // Undecodable data is a damaged file: refused, not reported as arrived.
    assert_eq!(
        result,
        Err(ReceiptRefusal::FileCorrupted("the file data is not base64"))
    );
}

// ── decrypt_and_process tests ───────────────────────────────────────

#[tokio::test]
async fn decrypt_no_session_is_refused() {
    let alice = alice_identity();
    let bob = bob_identity();
    let session_mgr = SessionManager::new(Arc::clone(&bob));
    let plaintext_cipher = PlaintextCacheCipher::new(bob.aes_key());
    let storage: Arc<dyn Storage> = Arc::new(TestStorage::new());
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_CHAT,
        b"encrypted".to_vec(),
    );
    let sender = *alice.node_id();

    let result = decrypt_and_process(
        &envelope,
        &sender,
        &session_mgr,
        &plaintext_cipher,
        &storage,
        &None,
        &Default::default(),
        &(Arc::new(konsensus_chain::MockChainProvider::new()) as Arc<dyn ChainProvider>),
        &(Arc::new(konsensus_pricing::StaticPricingEngine::new(
            Default::default(),
        )) as Arc<dyn konsensus_core::traits::pricing::PricingEngine>),
        &bob,
        &transport,
        &audit,
        &PaymentGate::new(),
        0.0,
        true,
        None,
    )
    .await;

    assert_eq!(
        result,
        Err(ReceiptRefusal::Undecryptable(
            "no E2EE session with the sender"
        )),
        "a paid message with no session to read it is refused, not acknowledged"
    );
}

#[tokio::test]
async fn decrypt_invalid_ratchet_message_is_refused() {
    let alice = alice_identity();
    let bob = bob_identity();
    let bob_mgr = SessionManager::new(Arc::clone(&bob));
    let alice_mgr = SessionManager::new(Arc::clone(&alice));
    let plaintext_cipher = PlaintextCacheCipher::new(bob.aes_key());
    let storage: Arc<dyn Storage> = Arc::new(TestStorage::new());
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    // Establish session so has_session returns true
    establish_sessions(&alice_mgr, &bob_mgr, &alice, &bob).await;

    // Send garbage ciphertext that isn't a valid ratchet message
    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_CHAT,
        b"not-a-ratchet-msg".to_vec(),
    );
    let sender = *alice.node_id();

    let result = decrypt_and_process(
        &envelope,
        &sender,
        &bob_mgr,
        &plaintext_cipher,
        &storage,
        &None,
        &Default::default(),
        &(Arc::new(konsensus_chain::MockChainProvider::new()) as Arc<dyn ChainProvider>),
        &(Arc::new(konsensus_pricing::StaticPricingEngine::new(
            Default::default(),
        )) as Arc<dyn konsensus_core::traits::pricing::PricingEngine>),
        &bob,
        &transport,
        &audit,
        &PaymentGate::new(),
        0.0,
        true,
        None,
    )
    .await;

    assert_eq!(
        result,
        Err(ReceiptRefusal::Undecryptable(
            "ciphertext is not a ratchet message"
        )),
        "a paid message that is not a ratchet message is refused, not acknowledged"
    );
}

#[tokio::test]
async fn decrypt_valid_message_returns_plaintext_and_caches() {
    let alice = alice_identity();
    let bob = bob_identity();
    let bob_mgr = SessionManager::new(Arc::clone(&bob));
    let alice_mgr = SessionManager::new(Arc::clone(&alice));
    let plaintext_cipher = PlaintextCacheCipher::new(bob.aes_key());
    let storage = Arc::new(TestStorage::new());
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    establish_sessions(&alice_mgr, &bob_mgr, &alice, &bob).await;

    // Alice encrypts a message that Bob can decrypt
    let ratchet_msg = alice_mgr
        .encrypt(bob.node_id(), b"Hello from Alice!")
        .await
        .unwrap();
    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(&ratchet_msg);

    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_CHAT,
        ciphertext,
    );
    let sender = *alice.node_id();
    let storage_dyn: Arc<dyn Storage> = Arc::clone(&storage) as _;

    let result = decrypt_and_process(
        &envelope,
        &sender,
        &bob_mgr,
        &plaintext_cipher,
        &storage_dyn,
        &None,
        &Default::default(),
        &(Arc::new(konsensus_chain::MockChainProvider::new()) as Arc<dyn ChainProvider>),
        &(Arc::new(konsensus_pricing::StaticPricingEngine::new(
            Default::default(),
        )) as Arc<dyn konsensus_core::traits::pricing::PricingEngine>),
        &bob,
        &transport,
        &audit,
        &PaymentGate::new(),
        0.0,
        true,
        None,
    )
    .await;

    assert_eq!(result, Ok(Some("Hello from Alice!".to_string())));
    // Verify plaintext was cached in storage
    assert!(storage.has_plaintext(&envelope.id));
}

#[tokio::test]
async fn decrypt_file_ref_stores_and_returns_label() {
    let alice = alice_identity();
    let bob = bob_identity();
    let bob_mgr = SessionManager::new(Arc::clone(&bob));
    let alice_mgr = SessionManager::new(Arc::clone(&alice));
    let plaintext_cipher = PlaintextCacheCipher::new(bob.aes_key());
    let storage = Arc::new(TestStorage::new());
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    establish_sessions(&alice_mgr, &bob_mgr, &alice, &bob).await;

    // Create a valid file payload
    let file_data = b"PDF file content";
    let hash = blake3::hash(file_data).to_hex().to_string();
    let data_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, file_data);
    let payload = serde_json::json!({
        "filename": "report.pdf",
        "mime_type": "application/pdf",
        "size_bytes": file_data.len(),
        "blake3_hash": hash,
        "data_b64": data_b64,
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    let ratchet_msg = alice_mgr
        .encrypt(bob.node_id(), &payload_bytes)
        .await
        .unwrap();
    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(&ratchet_msg);

    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_FILE_REF,
        ciphertext,
    );
    let sender = *alice.node_id();
    let storage_dyn: Arc<dyn Storage> = Arc::clone(&storage) as _;

    let result = decrypt_and_process(
        &envelope,
        &sender,
        &bob_mgr,
        &plaintext_cipher,
        &storage_dyn,
        &None,
        &Default::default(),
        &(Arc::new(konsensus_chain::MockChainProvider::new()) as Arc<dyn ChainProvider>),
        &(Arc::new(konsensus_pricing::StaticPricingEngine::new(
            Default::default(),
        )) as Arc<dyn konsensus_core::traits::pricing::PricingEngine>),
        &bob,
        &transport,
        &audit,
        &PaymentGate::new(),
        0.0,
        true,
        None,
    )
    .await;

    assert_eq!(result, Ok(Some("[file: report.pdf]".to_string())));
    assert_eq!(storage.file_count(), 1);
}

// ── process_web_manifest tests ──────────────────────────────────────

#[tokio::test]
async fn web_manifest_no_content_server_returns_label() {
    let alice = alice_identity();
    let bob = bob_identity();
    let session_mgr = SessionManager::new(Arc::clone(&bob));
    let chain: Arc<dyn ChainProvider> = Arc::new(konsensus_chain::MockChainProvider::new());
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> = Arc::new(
        konsensus_pricing::StaticPricingEngine::new(Default::default()),
    );
    let transport = make_transport(&bob);

    let sender = *alice.node_id();

    let request = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_WEB_MANIFEST,
        b"enc".to_vec(),
    );
    let result = process_web_manifest(
        &sender,
        &request,
        &None,
        &chain,
        &pricing,
        &bob,
        &session_mgr,
        &transport,
        &PaymentGate::new(),
        0.0,
    )
    .await;

    assert_eq!(result, Some("[web manifest request]".to_string()));
}

#[tokio::test]
async fn web_manifest_with_content_server_returns_label() {
    let alice = alice_identity();
    let bob = bob_identity();
    let session_mgr = SessionManager::new(Arc::clone(&bob));
    let chain: Arc<dyn ChainProvider> = Arc::new(konsensus_chain::MockChainProvider::new());
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> = Arc::new(
        konsensus_pricing::StaticPricingEngine::new(Default::default()),
    );
    let transport = make_transport(&bob);

    let tmp_dir = tempfile::tempdir().unwrap();
    let cs = Arc::new(
        ContentServer::new(crate::content_server::ContentServerConfig {
            content_dir: tmp_dir.path().to_path_buf(),
            max_file_size: 4 * 1024 * 1024,
            cache_seconds: 3600,
            site_name: "Test Node".to_string(),
        })
        .unwrap(),
    );

    let sender = *alice.node_id();
    let request = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_WEB_MANIFEST,
        b"enc".to_vec(),
    );

    let result = process_web_manifest(
        &sender,
        &request,
        &Some(cs),
        &chain,
        &pricing,
        &bob,
        &session_mgr,
        &transport,
        &PaymentGate::new(),
        0.0,
    )
    .await;

    assert_eq!(result, Some("[web manifest request]".to_string()));
}

#[tokio::test]
async fn web_reply_is_bound_to_request_payment_not_self_minted() {
    // The reply proof reuses the request hash/preimage at amount 0 and references
    // the request id — never a fresh generate_valid_proof amount.
    let alice = alice_identity();
    let bob = bob_identity();
    let request = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_PAGE_REQUEST,
        b"enc".to_vec(),
    );
    assert!(request.payment_proof.amount_msat > 0);

    let bound = konsensus_core::reply_bound_proof(&request.payment_proof);
    assert_eq!(bound.amount_msat, 0);
    assert_eq!(bound.payment_hash, request.payment_proof.payment_hash);
    assert_eq!(bound.preimage, request.payment_proof.preimage);

    let reply = UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_PAGE_RESPONSE,
        *bob.node_id(),
        Recipient::Node(*alice.node_id()),
        b"page-bytes".to_vec(),
        bound,
    )
    .references(vec![request.id])
    .build();
    assert!(konsensus_core::is_web_service_reply(&reply));
    assert_eq!(reply.references, vec![request.id]);
    // A self-minted priced proof would have a different hash or non-zero amount.
    assert_ne!(
        reply.payment_proof.amount_msat,
        request.payment_proof.amount_msat
    );
}

// ── process_page_request tests ──────────────────────────────────────

#[tokio::test]
async fn page_request_invalid_json_returns_none() {
    let alice = alice_identity();
    let bob = bob_identity();
    let session_mgr = SessionManager::new(Arc::clone(&bob));
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> = Arc::new(
        konsensus_pricing::StaticPricingEngine::new(Default::default()),
    );
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_PAGE_REQUEST,
        b"enc".to_vec(),
    );
    let sender = *alice.node_id();

    let result = process_page_request(
        b"not json",
        &sender,
        &envelope,
        &None,
        &Default::default(),
        &pricing,
        &bob,
        &session_mgr,
        &transport,
        &audit,
        &PaymentGate::new(),
        &konsensus_chain::MockChainProvider::new(),
    )
    .await;

    assert!(result.is_none());
}

#[tokio::test]
async fn page_request_no_content_server_returns_label() {
    let alice = alice_identity();
    let bob = bob_identity();
    let session_mgr = SessionManager::new(Arc::clone(&bob));
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> = Arc::new(
        konsensus_pricing::StaticPricingEngine::new(Default::default()),
    );
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_PAGE_REQUEST,
        b"enc".to_vec(),
    );
    let sender = *alice.node_id();

    let page_req = konsensus_core::payloads::content::PageRequest {
        request_id: "req-1".to_string(),
        path: "/index.md".to_string(),
        method: "GET".to_string(),
        accept: vec!["text/html".to_string()],
    };
    let bytes = serde_json::to_vec(&page_req).unwrap();

    let result = process_page_request(
        &bytes,
        &sender,
        &envelope,
        &None,
        &Default::default(),
        &pricing,
        &bob,
        &session_mgr,
        &transport,
        &audit,
        &PaymentGate::new(),
        &konsensus_chain::MockChainProvider::new(),
    )
    .await;

    assert_eq!(result, Some("[page request: /index.md]".to_string()));
}

#[tokio::test]
async fn page_request_with_content_server_serves_page() {
    let alice = alice_identity();
    let bob = bob_identity();
    let session_mgr = SessionManager::new(Arc::clone(&bob));
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> = Arc::new(
        konsensus_pricing::StaticPricingEngine::new(Default::default()),
    );
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    let tmp_dir = tempfile::tempdir().unwrap();
    std::fs::write(tmp_dir.path().join("hello.md"), "# Hello World\nTest page.").unwrap();
    let cs = Arc::new(
        ContentServer::new(crate::content_server::ContentServerConfig {
            content_dir: tmp_dir.path().to_path_buf(),
            max_file_size: 4 * 1024 * 1024,
            cache_seconds: 3600,
            site_name: "Test Node".to_string(),
        })
        .unwrap(),
    );

    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_PAGE_REQUEST,
        b"enc".to_vec(),
    );
    let sender = *alice.node_id();

    let page_req = konsensus_core::payloads::content::PageRequest {
        request_id: "req-2".to_string(),
        path: "/hello.md".to_string(),
        method: "GET".to_string(),
        accept: vec!["text/html".to_string()],
    };
    let bytes = serde_json::to_vec(&page_req).unwrap();

    let result = process_page_request(
        &bytes,
        &sender,
        &envelope,
        &Some(cs),
        &Default::default(),
        &pricing,
        &bob,
        &session_mgr,
        &transport,
        &audit,
        &PaymentGate::new(),
        &konsensus_chain::MockChainProvider::new(),
    )
    .await;

    assert_eq!(result, Some("[page request: /hello.md]".to_string()));
}

#[tokio::test]
async fn page_request_nonexistent_path_returns_label() {
    let alice = alice_identity();
    let bob = bob_identity();
    let session_mgr = SessionManager::new(Arc::clone(&bob));
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> = Arc::new(
        konsensus_pricing::StaticPricingEngine::new(Default::default()),
    );
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    let tmp_dir = tempfile::tempdir().unwrap();
    let cs = Arc::new(
        ContentServer::new(crate::content_server::ContentServerConfig {
            content_dir: tmp_dir.path().to_path_buf(),
            max_file_size: 4 * 1024 * 1024,
            cache_seconds: 3600,
            site_name: "Test Node".to_string(),
        })
        .unwrap(),
    );

    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_PAGE_REQUEST,
        b"enc".to_vec(),
    );
    let sender = *alice.node_id();

    let page_req = konsensus_core::payloads::content::PageRequest {
        request_id: "req-3".to_string(),
        path: "/nonexistent.md".to_string(),
        method: "GET".to_string(),
        accept: vec!["text/html".to_string()],
    };
    let bytes = serde_json::to_vec(&page_req).unwrap();

    let result = process_page_request(
        &bytes,
        &sender,
        &envelope,
        &Some(cs),
        &Default::default(),
        &pricing,
        &bob,
        &session_mgr,
        &transport,
        &audit,
        &PaymentGate::new(),
        &konsensus_chain::MockChainProvider::new(),
    )
    .await;

    assert_eq!(result, Some("[page request: /nonexistent.md]".to_string()));
}

// ── decrypt_and_process with stale session ──────────────────────────

#[tokio::test]
async fn decrypt_failure_keeps_the_session_and_asks_to_renegotiate() {
    let alice = alice_identity();
    let bob = bob_identity();
    let bob_mgr = SessionManager::new(Arc::clone(&bob));
    let alice_mgr = SessionManager::new(Arc::clone(&alice));
    let plaintext_cipher = PlaintextCacheCipher::new(bob.aes_key());
    let storage: Arc<dyn Storage> = Arc::new(TestStorage::new());
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    // Establish sessions
    establish_sessions(&alice_mgr, &bob_mgr, &alice, &bob).await;

    // Alice encrypts with a DIFFERENT session manager (simulating stale keys)
    let alice_mgr2 = SessionManager::new(Arc::clone(&alice));
    let bob_mgr2 = SessionManager::new(Arc::clone(&bob));
    establish_sessions(&alice_mgr2, &bob_mgr2, &alice, &bob).await;

    // Encrypt with the second session (bob_mgr can't decrypt this)
    let ratchet_msg = alice_mgr2
        .encrypt(bob.node_id(), b"stale message")
        .await
        .unwrap();
    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(&ratchet_msg);

    let mut envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_CHAT,
        ciphertext,
    );
    // Stamped past Bob's session settling, so the failure counts against it.
    envelope.timestamp += 11_000;
    let sender = *alice.node_id();

    // Before: session exists
    assert!(bob_mgr.has_session(alice.node_id()).await);

    let result = decrypt_and_process(
        &envelope,
        &sender,
        &bob_mgr,
        &plaintext_cipher,
        &storage,
        &None,
        &Default::default(),
        &(Arc::new(konsensus_chain::MockChainProvider::new()) as Arc<dyn ChainProvider>),
        &(Arc::new(konsensus_pricing::StaticPricingEngine::new(
            Default::default(),
        )) as Arc<dyn konsensus_core::traits::pricing::PricingEngine>),
        &bob,
        &transport,
        &audit,
        &PaymentGate::new(),
        0.0,
        true,
        None,
    )
    .await;

    // Decryption failed → refused, never acknowledged as delivered
    assert_eq!(
        result,
        Err(ReceiptRefusal::Undecryptable(
            "the session could not decrypt the ciphertext"
        ))
    );
    // The session stays, and the node asks for a replacement
    assert!(bob_mgr.has_session(alice.node_id()).await);
    assert!(bob_mgr.needs_renegotiation(alice.node_id()).await);
}

/// A second envelope that still cannot be read does not ask again. The first
/// request stands, and the session stays usable.
#[tokio::test(flavor = "current_thread")]
async fn a_second_undecryptable_envelope_asks_only_once() {
    struct Asks(Arc<AtomicUsize>);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Asks {
        fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            let mut message = String::new();
            struct Take<'a>(&'a mut String);
            impl tracing::field::Visit for Take<'_> {
                fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                    if field.name() == "message" {
                        self.0.push_str(&format!("{value:?}"));
                    }
                }
            }
            event.record(&mut Take(&mut message));
            if message.contains("asking to renegotiate") {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    let alice = alice_identity();
    let bob = bob_identity();
    let bob_mgr = SessionManager::new(Arc::clone(&bob));
    let alice_mgr = SessionManager::new(Arc::clone(&alice));
    let transport = make_transport(&bob);
    establish_sessions(&alice_mgr, &bob_mgr, &alice, &bob).await;

    let alice_mgr2 = SessionManager::new(Arc::clone(&alice));
    let bob_bundle = bob_mgr.prekey_bundle().await;
    let init = alice_mgr2.initiate_session(bob.node_id(), &bob_bundle).await.unwrap();
    drop(init);
    let foreign = alice_mgr2.encrypt(bob.node_id(), b"not this session").await.unwrap();
    let mut envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_CHAT,
        konsensus_crypto::ratchet_message_to_bytes(&foreign),
    );
    envelope.timestamp += 11_000;

    let asks = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(Asks(Arc::clone(&asks)));
    let _guard = tracing::subscriber::set_default(subscriber);
    note_unreadable_envelope(&envelope, alice.node_id(), &bob_mgr, &transport).await;
    note_unreadable_envelope(&envelope, alice.node_id(), &bob_mgr, &transport).await;
    assert_eq!(asks.load(Ordering::SeqCst), 1, "the second envelope does not ask again");
    assert!(bob_mgr.needs_renegotiation(alice.node_id()).await);
    assert!(bob_mgr.has_session(alice.node_id()).await);
}

// ── Non-UTF8 plaintext ──────────────────────────────────────────────

#[tokio::test]
async fn decrypt_non_utf8_returns_none() {
    let alice = alice_identity();
    let bob = bob_identity();
    let bob_mgr = SessionManager::new(Arc::clone(&bob));
    let alice_mgr = SessionManager::new(Arc::clone(&alice));
    let plaintext_cipher = PlaintextCacheCipher::new(bob.aes_key());
    let storage: Arc<dyn Storage> = Arc::new(TestStorage::new());
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    establish_sessions(&alice_mgr, &bob_mgr, &alice, &bob).await;

    // Encrypt invalid UTF-8 bytes
    let invalid_utf8: &[u8] = &[0xFF, 0xFE, 0xFD, 0x80, 0x81];
    let ratchet_msg = alice_mgr
        .encrypt(bob.node_id(), invalid_utf8)
        .await
        .unwrap();
    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(&ratchet_msg);

    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_CHAT,
        ciphertext,
    );
    let sender = *alice.node_id();

    let result = decrypt_and_process(
        &envelope,
        &sender,
        &bob_mgr,
        &plaintext_cipher,
        &storage,
        &None,
        &Default::default(),
        &(Arc::new(konsensus_chain::MockChainProvider::new()) as Arc<dyn ChainProvider>),
        &(Arc::new(konsensus_pricing::StaticPricingEngine::new(
            Default::default(),
        )) as Arc<dyn konsensus_core::traits::pricing::PricingEngine>),
        &bob,
        &transport,
        &audit,
        &PaymentGate::new(),
        0.0,
        true,
        None,
    )
    .await;

    // Non-UTF8 for a chat message returns None
    assert_eq!(
        result,
        Ok(None),
        "kept, but not text: nothing to show, still delivered"
    );
}

// ── HARD-11: registry read guard released before the gate await ──────
//
// Review objection on #230: the code shape scopes the read guard before
// `PaymentGate::verify().await`, but no test proved the REAL seam — that a peer
// add/remove (a registry writer) can acquire the write lock while verification
// is pending. These tests drive the extracted `whitelist_then_verify` helper
// (the exact code `run()` calls) with a payment gate that blocks mid-`verify`,
// and assert a concurrent writer is NOT stalled behind it.

use konsensus_core::kind::KindCategory;
use konsensus_core::traits::pricing::{PricingEngine, PricingError};
use konsensus_message::peer::PeerEntry;

/// A `PricingEngine` that parks inside `get_price_msat` (the method
/// `PaymentGate::verify_price` calls) until released by the test, so the test can
/// observe lock state *while* `verify().await` is pending. It fires `entered`
/// once the gate await has reached pricing — by which point the registry read
/// guard in `whitelist_then_verify` has provably been dropped.
struct BlockingPricing {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Semaphore>,
}

#[async_trait::async_trait]
impl PricingEngine for BlockingPricing {
    async fn get_price_msat(&self, _kind: u16) -> Result<u64, PricingError> {
        // Inside verify(), past the read-guard drop. Signal, then block.
        self.entered.notify_one();
        let _permit = self.release.acquire().await.expect("semaphore closed");
        Ok(1) // The 1,000-msat proof covers the admission floor.
    }
    async fn get_category_price_msat(&self, _c: KindCategory) -> Result<u64, PricingError> {
        self.entered.notify_one();
        let _permit = self.release.acquire().await.expect("semaphore closed");
        Ok(1)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[tokio::test]
async fn whitelist_read_guard_released_before_gate_await() {
    let alice = alice_identity();
    let bob = bob_identity();
    let sender = *alice.node_id();

    // Registry with the sender whitelisted.
    let registry = Arc::new(tokio::sync::RwLock::new(PeerRegistry::new()));
    {
        let mut w = registry.write().await;
        w.add(PeerEntry {
            node_id: sender,
            addr: "127.0.0.1:9999".parse().unwrap(),
            label: None,
            auto_connect: false,
        });
    }

    let storage: Arc<dyn Storage> = Arc::new(TestStorage::new());
    let nonce_adapter = Arc::new(konsensus_storage::StorageNonceAdapter::new(Arc::clone(
        &storage,
    )));
    let gate = PaymentGate::new();

    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let pricing = BlockingPricing {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    };

    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_CHAT,
        b"ciphertext-bytes".to_vec(),
    );

    // Drive the real seam: take the read lock, drop it, then await verify(),
    // which parks inside BlockingPricing with no registry lock held.
    let registry_for_task = Arc::clone(&registry);
    let handle = tokio::spawn(async move {
        whitelist_then_verify(
            &envelope,
            &konsensus_api::membrane::Membrane::default(),
            registry_for_task.as_ref(),
            &gate,
            nonce_adapter.as_ref(),
            &pricing,
            None,
            0.0,
            None,
            // M1a: Whitelist mode keeps this lock-release test passing Some(&whitelist)
            // into the gate (HARD-11 seam preserved); the new arg does not change it.
            konsensus_message::ReachabilityMode::Whitelist,
            true,
        )
        .await
    });

    // Wait until verify() has reached pricing → the read guard is dropped.
    entered.notified().await;

    // PROOF: a registry writer acquires the write lock while verify() is pending.
    // If the read guard were held across the await, this would block until the
    // gate finished; assert it completes well within a generous timeout.
    let write_acquired = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut w = registry.write().await;
        w.remove(&sender); // a real mutation: revoke the peer mid-verification
    })
    .await;
    assert!(
        write_acquired.is_ok(),
        "registry write lock must be acquirable while gate verify() is pending \
         — the read guard must NOT be held across the await (HARD-11)"
    );

    // Release pricing so verify() finishes and the task joins cleanly.
    release.add_permits(1);
    let result = handle.await.unwrap();
    assert!(
        result.is_ok(),
        "whitelisted message with a covering proof should verify: {result:?}"
    );
}

// ── corrective price-table rate-limit (no free connection back) ──────

#[tokio::test]
async fn corrective_price_table_is_per_peer_cooldown_throttled() {
    let mut map: HashMap<NodeId, tokio::time::Instant> = HashMap::new();
    let a = NodeId::from_bytes([1u8; 32]);
    let b = NodeId::from_bytes([2u8; 32]);
    let t0 = tokio::time::Instant::now();

    // First send to `a` is allowed (false = not rate-limited).
    assert!(!corrective_price_table_rate_limited(&mut map, &a, t0));
    // A second within the cooldown is throttled — an unpaid flood resends nothing.
    assert!(corrective_price_table_rate_limited(
        &mut map,
        &a,
        t0 + std::time::Duration::from_secs(5)
    ));
    // A different peer is independent — a legitimate mis-priced sender is unaffected.
    assert!(!corrective_price_table_rate_limited(
        &mut map,
        &b,
        t0 + std::time::Duration::from_secs(5)
    ));
    // After the cooldown fully elapses, `a` may receive one corrective table again.
    assert!(!corrective_price_table_rate_limited(
        &mut map,
        &a,
        t0 + CORRECTIVE_PRICE_TABLE_COOLDOWN + std::time::Duration::from_secs(1)
    ));
}

#[tokio::test]
async fn unpaid_stranger_envelope_is_silent_and_creates_no_records() {
    rejected_envelope_disclosures(false).await;
}

#[tokio::test]
async fn whitelisted_price_open_peer_keeps_detailed_rejection() {
    rejected_envelope_disclosures(true).await;
}

async fn rejected_envelope_disclosures(privileged: bool) {
    use konsensus_core::traits::pricing::{PricingEngine, PricingError};
    use konsensus_message::{ControlEvent, ReachabilityMode, TransportConfig};
    use std::time::Duration;

    struct ObservedPricing(Arc<tokio::sync::Notify>);
    #[async_trait::async_trait]
    impl PricingEngine for ObservedPricing {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        async fn get_price_msat(&self, _: u16) -> Result<u64, PricingError> {
            self.0.notify_one();
            Ok(2000)
        }
        async fn get_category_price_msat(
            &self,
            _: konsensus_core::kind::KindCategory,
        ) -> Result<u64, PricingError> {
            Ok(2000)
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let alice = alice_identity();
    let bob = bob_identity();
    let make_open_transport = |id: Arc<NodeIdentity>| {
        Arc::new(NoiseTransport::new(
            id,
            TransportConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                admission_mode: ReachabilityMode::PriceOpen,
                whitelist: if privileged {
                    vec![*alice.node_id(), *bob.node_id()]
                } else {
                    vec![]
                },
                ..Default::default()
            },
        ))
    };
    let source = make_open_transport(alice.clone());
    let target = make_open_transport(bob.clone());
    target.start_listener().await.unwrap();
    let storage: Arc<dyn Storage> =
        Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let sessions = Arc::new(SessionManager::new(bob.clone()));
    let registry = Arc::new(tokio::sync::RwLock::new(PeerRegistry::new()));
    let audit_path = dir.path().join("audit.jsonl");
    let checked_price = Arc::new(tokio::sync::Notify::new());
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (ws_tx, _ws_rx) = broadcast::channel(8);
    let worker = tokio::spawn(run(MsgHandlerDeps {
        transport: target.clone(),
        transport_ack: target.clone(),
        storage: storage.clone(),
        gate: Arc::new(PaymentGate::with_config(konsensus_core::gate::GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        })),
        pricing: Arc::new(ObservedPricing(checked_price.clone())),
        lightning: Arc::new(konsensus_lightning::MockLightningProvider::new()),
        chain: Arc::new(konsensus_chain::MockChainProvider::new()),
        peer_registry: registry.clone(),
        session_manager: sessions.clone(),
        nonce_adapter: Arc::new(konsensus_storage::StorageNonceAdapter::new(storage.clone())),
        content_server: None,
        front_door: Default::default(),
        routing: Arc::new(RoutingTable::new(Default::default())),
        identity: bob.clone(),
        plaintext_cipher: Arc::new(PlaintextCacheCipher::new(bob.aes_key())),
        ws_tx,
        audit_log: Arc::new(AuditLog::open(&audit_path).unwrap()),
        admission_mode: ReachabilityMode::PriceOpen,
        relay_engine: None,
        shutdown_rx,
    }));
    source
        .connect(bob.node_id(), &target.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    assert!(
        matches!(source.recv_control().await.unwrap(), ControlEvent::PeerConnected { privileged: actual, .. } if actual == privileged)
    );
    // A correctly signed envelope with a self-generated hash/preimage is not
    // evidence of payment. File kind also probes the arbitrary-kind price leak.
    let envelope = make_envelope(&alice, *bob.node_id(), 200, b"unpaid".to_vec());
    source
        .send_frame(bob.node_id(), &Frame::Message(Box::new(envelope.clone())))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), checked_price.notified())
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_millis(200), source.recv_control()).await;
    shutdown.send(true).unwrap();
    worker.await.unwrap();
    source.shutdown();
    target.shutdown();
    if privileged {
        assert!(
            matches!(response, Ok(Some(ControlEvent::MessageRejected { .. }))),
            "privileged peer lost detailed rejection: {response:?}"
        );
        assert!(!std::fs::read(&audit_path).unwrap().is_empty());
    } else {
        assert!(
            response.is_err(),
            "unpaid stranger received a response: {response:?}"
        );
        assert_eq!(std::fs::read(&audit_path).unwrap(), b"");
    }
    assert!(!storage.has_nonce(&envelope.nonce).await.unwrap());
    assert!(storage.get_message(&envelope.id).await.unwrap().is_none());
    assert!(storage.list_peers().await.unwrap().is_empty());
    assert!(storage.list_sessions().await.unwrap().is_empty());
    assert!(registry.read().await.is_empty());
    assert!(!sessions.has_session(alice.node_id()).await);
}

// Exercise the actual gate seam used by the receive loop, before post-gate exits.
#[tokio::test]
async fn membrane_records_gate_admission_before_relay_and_storage_outcomes() {
    use konsensus_api::membrane::{Code, Membrane};
    let alice = alice_identity();
    let bob = bob_identity();
    let registry = tokio::sync::RwLock::new(PeerRegistry::new());
    let store = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let nonce = konsensus_storage::StorageNonceAdapter::new(store.clone());
    let pricing = BlockingPricing {
        entered: Arc::new(tokio::sync::Notify::new()),
        release: Arc::new(tokio::sync::Semaphore::new(1)),
    };
    let gate = PaymentGate::new();
    let membrane = Membrane::default();
    let payload = serde_json::to_vec(&serde_json::json!({"binding_id":vec![0;16],"quota_bytes":100000,"ttl_max_secs":3600,"depositor_whitelist_root":vec![0;32],"created_at":1})).unwrap();
    let env = make_envelope(&alice, *bob.node_id(), 600, payload);
    whitelist_then_verify(
        &env,
        &membrane,
        &registry,
        &gate,
        &nonce,
        &pricing,
        None,
        0.0,
        None,
        konsensus_message::ReachabilityMode::PriceOpen,
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        membrane.read(None, 500).0.len(),
        1,
        "gate admission must exist BEFORE post-gate dispatch"
    );
    let relay = crate::relay::RelayEngine::new(
        Arc::new(crate::relay::InMemoryRelayStore::new()),
        crate::relay::RelayPolicy::inert_default(),
    );
    let replies = crate::relay::dispatch::handle_relay_control(&relay, &env, bob.node_id()).await;
    assert!(matches!(
        replies.as_slice(),
        [(_, Frame::MessageAck { .. })]
    ));
    // The same authenticated envelope is a replay, not a second admission.
    assert!(whitelist_then_verify(
        &env,
        &membrane,
        &registry,
        &gate,
        &nonce,
        &pricing,
        None,
        0.0,
        None,
        konsensus_message::ReachabilityMode::PriceOpen,
        true
    )
    .await
    .is_err());
    let (events, totals) = membrane.read(None, 500);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].code, Code::Replay);
    assert_eq!(totals.admitted, 1);
    assert_eq!(totals.first_contacts, 1);
    // A fresh proof passes the same seam even if downstream message storage fails.
    let store2 = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let nonce2 = konsensus_storage::StorageNonceAdapter::new(store2.clone());
    let env2 = make_envelope(&alice, *bob.node_id(), 100, vec![1]);
    whitelist_then_verify(
        &env2,
        &membrane,
        &registry,
        &gate,
        &nonce2,
        &pricing,
        None,
        0.0,
        None,
        konsensus_message::ReachabilityMode::PriceOpen,
        true,
    )
    .await
    .unwrap();
    store2.pool().close().await;
    assert!(store2.store_message(&env2).await.is_err());
    assert_eq!(membrane.read(None, 500).1.admitted, 2);
}

#[tokio::test]
async fn membrane_observes_unpaid_insufficient_stale_and_first_contact_decisions() {
    use konsensus_api::membrane::{Code, Membrane};
    let alice = alice_identity();
    let bob = bob_identity();
    let registry = tokio::sync::RwLock::new(PeerRegistry::new());
    let store: Arc<dyn Storage> = Arc::new(TestStorage::new());
    let nonce = konsensus_storage::StorageNonceAdapter::new(store);
    let membrane = Membrane::default();
    let pricing = BlockingPricing {
        entered: Arc::new(tokio::sync::Notify::new()),
        release: Arc::new(tokio::sync::Semaphore::new(1)),
    };
    for (case, expected) in [
        ("unpaid", Code::Unpaid),
        ("insufficient", Code::InsufficientPayment),
        ("stale", Code::Stale),
        ("invite", Code::InviteOnly),
        ("bad_sig", Code::BadSignature),
        ("paid", Code::Settled),
        ("contact", Code::Settled),
    ] {
        let gate = PaymentGate::with_config(konsensus_core::gate::GateConfig {
            min_admission_cost_msat: if case == "insufficient" { 2_000 } else { 0 },
            ..Default::default()
        });
        if case == "contact" {
            registry.write().await.add(PeerEntry {
                node_id: *alice.node_id(),
                addr: "127.0.0.1:9999".parse().unwrap(),
                label: None,
                auto_connect: false,
            });
        }
        let mut env = make_envelope(&alice, *bob.node_id(), 100, vec![1]);
        if case == "unpaid" {
            env.payment_proof = make_valid_proof(0);
        }
        if case == "stale" {
            env.timestamp = 1;
        }
        env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
        if case == "bad_sig" {
            env.signature = Signature::from_ed25519(&bob.sign(&env.signable_bytes()));
        }
        let mode = if case == "invite" {
            konsensus_message::ReachabilityMode::Whitelist
        } else {
            konsensus_message::ReachabilityMode::PriceOpen
        };
        let _ = whitelist_then_verify(
            &env, &membrane, &registry, &gate, &nonce, &pricing, None, 0.0, None, mode, true,
        )
        .await;
        let (events, _) = membrane.read(None, 500);
        assert_eq!(events[0].code, expected, "{case}");
        assert_eq!(
            events[0].counterparty.is_some(),
            matches!(case, "unpaid" | "insufficient" | "paid" | "contact")
        );
    }
    assert_eq!(membrane.read(None, 500).1.first_contacts, 1);
}

/// Exercise the production Noise receive loop, full settlement gate and SQLite
/// commit. A failed commit and a lost ACK must never consume a second payment.
#[tokio::test]
async fn paid_acceptance_storage_retry_and_lost_ack_are_idempotent() {
    paid_acceptance_retry_case(false, false, false, false).await;
}

#[tokio::test]
async fn legacy_limbo_heals_only_after_signature_and_settlement_gate() {
    paid_acceptance_retry_case(true, false, false, false).await;
}

#[tokio::test]
async fn lost_ack_survives_recipient_retention_and_sender_restart() {
    paid_acceptance_retry_case(false, true, false, false).await;
}

#[tokio::test]
async fn lost_ack_after_price_rise_still_gets_duplicate_ack() {
    paid_acceptance_retry_case(false, true, true, false).await;
}

struct MutableDeliveryPrice(std::sync::atomic::AtomicU64);
#[async_trait::async_trait]
impl konsensus_core::traits::pricing::PricingEngine for MutableDeliveryPrice {
    fn category_price_overrides(&self) -> Option<Vec<u16>> {
        Some(Vec::new())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get_price_msat(
        &self,
        _: u16,
    ) -> Result<u64, konsensus_core::traits::pricing::PricingError> {
        Ok(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
    async fn get_category_price_msat(
        &self,
        _: konsensus_core::kind::KindCategory,
    ) -> Result<u64, konsensus_core::traits::pricing::PricingError> {
        self.get_price_msat(0).await
    }
}

#[tokio::test]
async fn quoted_payment_delayed_until_price_rise_is_accepted_once_over_noise() {
    paid_acceptance_retry_case(false, false, false, true).await;
}

async fn paid_acceptance_retry_case(
    legacy: bool,
    retained: bool,
    price_rise: bool,
    queued_price_rise: bool,
) {
    use konsensus_message::{ControlEvent, ReachabilityMode, TransportConfig};
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let alice = alice_identity();
    let bob = bob_identity();
    let transport = |id| {
        Arc::new(NoiseTransport::new(
            id,
            TransportConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                admission_mode: ReachabilityMode::PriceOpen,
                ..Default::default()
            },
        ))
    };
    let source = transport(alice.clone());
    let target = transport(bob.clone());
    target.start_listener().await.unwrap();
    let db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let storage: Arc<dyn Storage> = db.clone();
    source
        .connect(bob.node_id(), &target.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    assert!(matches!(
        source.recv_control().await.unwrap(),
        ControlEvent::PeerConnected {
            privileged: false,
            ..
        }
    ));
    if queued_price_rise {
        while !matches!(
            target.recv_control().await.unwrap(),
            ControlEvent::PeerConnected { .. }
        ) {}
        crate::delivery_prices::send_price_frame(
            &target,
            db.as_ref(),
            alice.node_id(),
            &Frame::PriceTable {
                prices: std::collections::HashMap::from([("communication".into(), 1_000)]),
                block_height: 1,
                valid_blocks: 10,
                trust_discount: 0.0,
            },
            &MutableDeliveryPrice(std::sync::atomic::AtomicU64::new(1_000)),
            0,
        )
        .await
        .unwrap();
        assert!(matches!(
            source.recv_control().await.unwrap(),
            ControlEvent::PriceTableReceived { .. }
        ));
    }
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let hash = wallet.inject_inbound_keysend(1_000, None).await;
    let payment = wallet.get_payment_status(&hash).await.unwrap();
    let proof = PaymentProof::new(
        hex::decode(&hash).unwrap().try_into().unwrap(),
        hex::decode(payment.preimage.unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        1_000,
    );
    let sessions_a = SessionManager::new(alice.clone());
    let sessions_b = Arc::new(SessionManager::new(bob.clone()));
    establish_sessions(&sessions_a, &sessions_b, &alice, &bob).await;
    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(
        &sessions_a
            .encrypt(bob.node_id(), b"paid exactly once")
            .await
            .unwrap(),
    );
    let mut env = UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_CHAT,
        *alice.node_id(),
        Recipient::Node(*bob.node_id()),
        ciphertext,
        proof,
    )
    .build();
    env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
    let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (ws_tx, mut ws_rx) = broadcast::channel(8);
    let pricing = Arc::new(MutableDeliveryPrice(std::sync::atomic::AtomicU64::new(
        1_000,
    )));
    let worker = tokio::spawn(run(MsgHandlerDeps {
        transport: target.clone(),
        transport_ack: target.clone(),
        storage: storage.clone(),
        gate: Arc::new(PaymentGate::with_config(konsensus_core::gate::GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        })),
        pricing: pricing.clone(),
        lightning: wallet,
        chain: Arc::new(konsensus_chain::MockChainProvider::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        session_manager: sessions_b,
        nonce_adapter: Arc::new(konsensus_storage::StorageNonceAdapter::new(storage)),
        content_server: None,
        front_door: Default::default(),
        routing: Arc::new(RoutingTable::new(Default::default())),
        identity: bob.clone(),
        plaintext_cipher: Arc::new(PlaintextCacheCipher::new(bob.aes_key())),
        ws_tx,
        audit_log: audit.clone(),
        admission_mode: ReachabilityMode::PriceOpen,
        relay_engine: None,
        shutdown_rx,
    }));
    if queued_price_rise {
        pricing.0.store(10_000, std::sync::atomic::Ordering::SeqCst);
    }
    if legacy {
        db.store_payment_receipt(&env.payment_proof.payment_hash, &env.sender, &env.id)
            .await
            .unwrap();
        db.store_nonce(&env.nonce, &env.sender).await.unwrap();
        let mut forged = env.clone();
        forged.signature = Signature::from_bytes([0; 64]);
        source.send(bob.node_id(), &forged).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while audit
                .membrane()
                .read(None, 100)
                .0
                .first()
                .is_none_or(|e| e.code != konsensus_api::membrane::Code::BadSignature)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(db.get_message(&env.id).await.unwrap().is_none());
        assert!(!target
            .connected_privileged_peers()
            .await
            .contains(alice.node_id()));
    }
    sqlx::query("CREATE TRIGGER fail_message BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
        .execute(db.pool()).await.unwrap();
    source.send(bob.node_id(), &env).await.unwrap();
    let rejected = tokio::time::timeout(Duration::from_secs(5), source.recv_control())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(rejected, ControlEvent::MessageRejected { reason, .. } if reason == "storage error")
    );
    assert_eq!(db.has_nonce(&env.nonce).await.unwrap(), legacy);
    assert_eq!(audit.membrane().read(None, 100).1.admitted, 0);
    assert!(!target
        .connected_privileged_peers()
        .await
        .contains(alice.node_id()));
    sqlx::query("DROP TRIGGER fail_message")
        .execute(db.pool())
        .await
        .unwrap();
    source.send(bob.node_id(), &env).await.unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match source.recv_control().await.unwrap() {
                event @ ControlEvent::MessageAcked { .. } => break event,
                event @ ControlEvent::MessageRejected { .. } => panic!("expected ACK: {event:?}"),
                // PSI-SPEED can publish its eager PrekeyOffer before the ACK.
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        ack,
        ControlEvent::MessageAcked {
            duplicate: false,
            ..
        }
    ));
    let message = tokio::time::timeout(Duration::from_secs(5), ws_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(message.plaintext.as_deref(), Some("paid exactly once"));
    assert_eq!(audit.membrane().read(None, 100).1.admitted, 1);
    assert!(target
        .connected_privileged_peers()
        .await
        .contains(alice.node_id()));
    if retained {
        assert_eq!(
            db.delete_messages_older_than(env.timestamp + 1)
                .await
                .unwrap(),
            1
        );
        let path = dir.path().join("sender.sqlite");
        let sender_db = konsensus_storage::SqliteStorage::open(path.to_str().unwrap())
            .await
            .unwrap();
        sender_db.store_message(&env).await.unwrap();
        sender_db
            .prepare_delivery(&env.id, bob.node_id())
            .await
            .unwrap();
        sender_db.pool().close().await;
        let reopened = konsensus_storage::SqliteStorage::open(path.to_str().unwrap())
            .await
            .unwrap();
        env = reopened.get_message(&env.id).await.unwrap().unwrap();
        env.timestamp += 1;
        env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
        reopened.update_message_wrapper(&env).await.unwrap();
        assert_eq!(
            reopened
                .get_pending_for_peer(bob.node_id())
                .await
                .unwrap()
                .len(),
            1
        );
    }
    if price_rise {
        pricing.0.store(10_000, std::sync::atomic::Ordering::SeqCst);
    }
    // Treat the first ACK as dropped. Reconnect so a second promotion would be observable.
    source.disconnect(bob.node_id()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while target.is_connected(alice.node_id()).await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    source
        .connect(bob.node_id(), &target.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    while !matches!(
        source.recv_control().await.unwrap(),
        ControlEvent::PeerConnected { .. }
    ) {}
    source.send(bob.node_id(), &env).await.unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match source.recv_control().await.unwrap() {
                event @ ControlEvent::MessageAcked { .. } => break event,
                event @ ControlEvent::MessageRejected { .. } => panic!("expected ACK: {event:?}"),
                // PSI-SPEED can publish its eager PrekeyOffer before the ACK.
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        ack,
        ControlEvent::MessageAcked {
            duplicate: true,
            ..
        }
    ));
    assert!(!target
        .connected_privileged_peers()
        .await
        .contains(alice.node_id()));
    assert!(ws_rx.try_recv().is_err());
    assert_eq!(audit.membrane().read(None, 100).1.admitted, 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM messages")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        if retained { 0 } else { 1 }
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM payment_receipts")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        1
    );
    // Even a previously accepted id must still pass full signature validation.
    let mut tampered = env.clone();
    tampered.signature = Signature::from_bytes([0; 64]);
    source.send(bob.node_id(), &tampered).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while audit.membrane().read(None, 100).0.first().unwrap().code
            != konsensus_api::membrane::Code::BadSignature
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!target
        .connected_privileged_peers()
        .await
        .contains(alice.node_id()));
    assert!(ws_rx.try_recv().is_err());
    pricing.0.store(1_000, std::sync::atomic::Ordering::SeqCst);
    // A different valid id cannot reuse that payment or be promoted.
    let mut reused = UkmEnvelopeBuilder::new(
        env.kind,
        env.sender,
        env.recipient,
        vec![8],
        env.payment_proof.clone(),
    )
    .build();
    reused.signature = Signature::from_ed25519(&alice.sign(&reused.signable_bytes()));
    source.send(bob.node_id(), &reused).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while audit.membrane().read(None, 100).0.first().unwrap().code
            != konsensus_api::membrane::Code::ProofReused
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!target
        .connected_privileged_peers()
        .await
        .contains(alice.node_id()));
    shutdown.send(true).unwrap();
    worker.await.unwrap();
    source.shutdown();
    target.shutdown();
}

/// An offered price is a recipient-side contract, not an arbitrary claim in a
/// refreshed envelope. A fresh inbound settlement binds its time and amount.
#[tokio::test]
async fn queued_paid_proof_honours_offered_price_before_acceptance() {
    use konsensus_core::gate::GateConfig;
    let alice = alice_identity();
    let bob = bob_identity();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("quotes.sqlite");
    let db = Arc::new(
        konsensus_storage::SqliteStorage::open(path.to_str().unwrap())
            .await
            .unwrap(),
    );
    let wallet = konsensus_lightning::MockLightningProvider::new();
    let hash = wallet.inject_inbound_keysend(1_000, None).await;
    let paid = wallet.get_payment_status(&hash).await.unwrap();
    db.record_delivery_prices(
        alice.node_id(),
        &[("category:communication".into(), 1_000)],
        &[1],
        paid.timestamp.saturating_sub(1),
        paid.timestamp + 3599,
    )
    .await
    .unwrap();
    db.pool().close().await;
    let db = Arc::new(
        konsensus_storage::SqliteStorage::open(path.to_str().unwrap())
            .await
            .unwrap(),
    );
    let proof = PaymentProof::new(
        hex::decode(hash).unwrap().try_into().unwrap(),
        hex::decode(paid.preimage.unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        1_000,
    );
    let mut env = UkmEnvelopeBuilder::new(
        0,
        *alice.node_id(),
        Recipient::Node(*bob.node_id()),
        vec![1],
        proof,
    )
    .build();
    env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
    let gate = PaymentGate::with_config(GateConfig {
        verify_lightning_settlement: true,
        ..Default::default()
    });
    let nonce = konsensus_storage::StorageNonceAdapter::new(db.clone());
    let pricing = MutableDeliveryPrice(std::sync::atomic::AtomicU64::new(10_000));
    let registry = tokio::sync::RwLock::new(PeerRegistry::new());
    let membrane = konsensus_api::membrane::Membrane::default();
    let result = whitelist_then_verify(
        &env,
        &membrane,
        &registry,
        &gate,
        &nonce,
        &pricing,
        Some(&wallet),
        0.0,
        Some(bob.node_id()),
        konsensus_message::ReachabilityMode::PriceOpen,
        false,
    )
    .await;
    assert!(
        result.is_ok(),
        "a queued paid proof retains the recipient's unexpired offered price: {result:?}"
    );
    assert!(
        db.get_message(&env.id).await.unwrap().is_none(),
        "validation must not consume the paid identity"
    );
    assert!(!db.has_nonce(&env.nonce).await.unwrap());
    for case in [
        "underpaid",
        "wrong_kind",
        "wrong_sender",
        "wrong_recipient",
        "unknown_proof",
    ] {
        let mut invalid = env.clone();
        match case {
            "underpaid" => invalid.payment_proof.amount_msat = 1,
            "wrong_kind" => invalid.kind = 200,
            "wrong_sender" => invalid.sender = *bob.node_id(),
            "wrong_recipient" => invalid.recipient = Recipient::Node(*alice.node_id()),
            _ => invalid.payment_proof = make_valid_proof(1_000),
        }
        let signer = if case == "wrong_sender" { &bob } else { &alice };
        invalid.signature = Signature::from_ed25519(&signer.sign(&invalid.signable_bytes()));
        assert!(
            whitelist_then_verify(
                &invalid,
                &membrane,
                &registry,
                &gate,
                &nonce,
                &pricing,
                Some(&wallet),
                0.0,
                Some(bob.node_id()),
                konsensus_message::ReachabilityMode::PriceOpen,
                false
            )
            .await
            .is_err(),
            "{case}"
        );
    }
    sqlx::query("UPDATE delivery_price_quotes SET expires_at = issued_at")
        .execute(db.pool())
        .await
        .unwrap();
    env.timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
    assert!(
        whitelist_then_verify(
            &env,
            &membrane,
            &registry,
            &gate,
            &nonce,
            &pricing,
            Some(&wallet),
            0.0,
            Some(bob.node_id()),
            konsensus_message::ReachabilityMode::PriceOpen,
            false
        )
        .await
        .is_err(),
        "renewing the wrapper cannot renew an expired offer"
    );
}

/// Characterize the documented v1 limit: offers have no tariff revision or
/// request/payment binding, so a raise cannot distinguish an in-flight paid
/// read from a custom client's later payment against the same old offer.
#[tokio::test]
async fn porch_tariff_raise_keeps_old_offer_for_payments_before_and_after_raise() {
    use konsensus_core::gate::{GateConfig, GateRejection};
    use konsensus_core::traits::pricing::PricingEngine;

    let alice = alice_identity();
    let bob = bob_identity();
    for paid_before_raise in [true, false] {
        let db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
        let wallet = konsensus_lightning::MockLightningProvider::new();
        let pricing = MutableDeliveryPrice(std::sync::atomic::AtomicU64::new(1000));
        let issued = crate::peer_exchange::now();
        let old_price = pricing.get_price_msat(500).await.unwrap();
        db.record_delivery_prices(
            alice.node_id(),
            &[("kind:500".into(), old_price)],
            &[],
            issued,
            issued + 300,
        )
        .await
        .unwrap();
        let earlier_payment = if paid_before_raise {
            Some(wallet.inject_inbound_keysend(1000, None).await)
        } else {
            None
        };
        pricing.0.store(2000, std::sync::atomic::Ordering::SeqCst);
        // Even publishing a higher offer does not revoke the earlier one.
        db.record_delivery_prices(
            alice.node_id(),
            &[("kind:500".into(), 2000)],
            &[],
            issued,
            issued + 3600,
        )
        .await
        .unwrap();
        let hash = match earlier_payment {
            Some(hash) => hash,
            None => wallet.inject_inbound_keysend(1000, None).await,
        };
        let paid = wallet.get_payment_status(&hash).await.unwrap();
        let proof = PaymentProof::new(
            hex::decode(hash).unwrap().try_into().unwrap(),
            hex::decode(paid.preimage.unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            1000,
        );
        let mut env = UkmEnvelopeBuilder::new(
            500,
            *alice.node_id(),
            Recipient::Node(*bob.node_id()),
            vec![1],
            proof,
        )
        .build();
        env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
        let gate = PaymentGate::with_config(GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        });
        let nonce = konsensus_storage::StorageNonceAdapter::new(db.clone());
        assert!(!gate
            .validate_received_paid_envelope(
                &env,
                &nonce,
                &pricing,
                None,
                Some(&wallet),
                0.0,
                Some(bob.node_id())
            )
            .await
            .unwrap());
        // Whole-second offer expiry is inclusive. A payment after expiry only
        // qualifies for the higher quote; timely payments retain one hour to deliver.
        assert_eq!(
            db.delivery_price_floor(&env, issued + 300, issued + 300)
                .await
                .unwrap(),
            Some(1000)
        );
        assert_eq!(
            db.delivery_price_floor(&env, issued + 301, issued + 301)
                .await
                .unwrap(),
            Some(2000)
        );
        assert_eq!(
            db.delivery_price_floor(&env, issued + 300, issued + 3900)
                .await
                .unwrap(),
            Some(1000)
        );
        assert_eq!(
            db.delivery_price_floor(&env, issued + 300, issued + 3901)
                .await
                .unwrap(),
            None
        );
        // Deleting the old offer would reject even a payment settled BEFORE
        // the raise, which is why supersession needs a richer protocol/store.
        sqlx::query("DELETE FROM delivery_price_quotes WHERE amount_msat = 1000")
            .execute(db.pool())
            .await
            .unwrap();
        assert!(matches!(
            gate.validate_received_paid_envelope(
                &env,
                &nonce,
                &pricing,
                None,
                Some(&wallet),
                0.0,
                Some(bob.node_id())
            )
            .await,
            Err(GateRejection::InsufficientPayment { .. })
        ));
    }
}

#[tokio::test]
async fn category_offer_binds_original_kind_exclusion_after_tariffs_converge() {
    category_offer_kind_transition(2000, 3000, 3000, false).await;
}

#[tokio::test]
async fn category_offer_binds_original_kind_inclusion_after_tariffs_diverge() {
    category_offer_kind_transition(1000, 2000, 3000, true).await;
}

async fn category_offer_kind_transition(
    old_longform: u64,
    new_chat: u64,
    new_longform: u64,
    allowed: bool,
) {
    use konsensus_core::traits::pricing::PricingEngine;
    let alice = alice_identity();
    let bob = bob_identity();
    let db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let transport = |id| {
        Arc::new(NoiseTransport::new(
            id,
            konsensus_message::TransportConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                admission_mode: konsensus_message::ReachabilityMode::PriceOpen,
                ..Default::default()
            },
        ))
    };
    let payer = transport(alice.clone());
    let payee = transport(bob.clone());
    payee.start_listener().await.unwrap();
    payer
        .connect(bob.node_id(), &payee.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    payer.recv_control().await.unwrap();
    payee.recv_control().await.unwrap();
    let old = konsensus_pricing::StaticPricingEngine::new(konsensus_pricing::StaticPricingConfig {
        chat_msat: 1000,
        longform_msat: old_longform,
        ..Default::default()
    });
    assert_eq!(
        old.get_price_msat(konsensus_core::kind::KIND_LONGFORM)
            .await
            .unwrap(),
        old_longform
    );
    let frame = Frame::PriceTable {
        prices: konsensus_pricing::peer_prices::build_price_table(&old).await,
        block_height: 1,
        valid_blocks: 10,
        trust_discount: 0.0,
    };
    crate::delivery_prices::send_price_frame(&payee, db.as_ref(), alice.node_id(), &frame, &old, 0)
        .await
        .unwrap();
    assert!(matches!(
        payer.recv_control().await.unwrap(),
        konsensus_message::ControlEvent::PriceTableReceived { .. }
    ));
    let wallet = konsensus_lightning::MockLightningProvider::new();
    let hash = wallet.inject_inbound_keysend(1000, None).await;
    let details = wallet.get_payment_status(&hash).await.unwrap();
    let proof = PaymentProof::new(
        hex::decode(hash).unwrap().try_into().unwrap(),
        hex::decode(details.preimage.unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        1000,
    );
    let mut env = UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_LONGFORM,
        *alice.node_id(),
        Recipient::Node(*bob.node_id()),
        vec![1],
        proof,
    )
    .build();
    env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
    let new = konsensus_pricing::StaticPricingEngine::new(konsensus_pricing::StaticPricingConfig {
        chat_msat: new_chat,
        longform_msat: new_longform,
        ..Default::default()
    });
    let gate = PaymentGate::with_config(konsensus_core::gate::GateConfig {
        verify_lightning_settlement: true,
        ..Default::default()
    });
    let nonce = konsensus_storage::StorageNonceAdapter::new(db);
    let result = gate
        .validate_received_paid_envelope(
            &env,
            &nonce,
            &new,
            None,
            Some(&wallet),
            0.0,
            Some(bob.node_id()),
        )
        .await;
    payer.shutdown();
    payee.shutdown();
    assert_eq!(
        result.is_ok(),
        allowed,
        "the original offer's kind eligibility is immutable: {result:?}"
    );
}

#[tokio::test]
async fn discounted_kind_offer_survives_price_rise() {
    for (raw_price, discount, expected) in [(2000, 0.5, 1000), (2001, 0.25, 1501)] {
        discounted_kind_offer_case(
            konsensus_core::kind::KIND_LONGFORM,
            raw_price,
            discount,
            expected,
            true,
            0,
        )
        .await;
    }
}

#[tokio::test]
async fn porch_adverts_match_durable_offer_and_gate() {
    for kind in [500, 501, 502, 510, 599] {
        for send_response in [false, true] {
            for (base, expected) in [(1000, 1000), (3000, 1500)] {
                discounted_kind_offer_case(kind, base, 0.5, expected, send_response, 0).await;
            }
        }
    }
}

#[tokio::test]
async fn porch_adverts_admission_matches_offer_and_gate() {
    for kind in [500, 501] {
        for response in [false, true] {
            discounted_kind_offer_case(kind, 1000, 0.5, 2000, response, 2000).await;
        }
    }
}

async fn discounted_kind_offer_case(
    kind: u16,
    raw_price: u64,
    discount: f64,
    expected: u64,
    send_response: bool,
    admission: u64,
) {
    use konsensus_core::gate::GateConfig;
    use konsensus_core::traits::pricing::PricingEngine;
    use konsensus_message::{ControlEvent, ReachabilityMode, TransportConfig};

    let alice = alice_identity();
    let bob = bob_identity();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recipient.sqlite");
    let db = Arc::new(
        konsensus_storage::SqliteStorage::open(path.to_str().unwrap())
            .await
            .unwrap(),
    );
    let transport = |id| {
        Arc::new(NoiseTransport::new(
            id,
            TransportConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                admission_mode: ReachabilityMode::PriceOpen,
                ..Default::default()
            },
        ))
    };
    let source = transport(alice.clone());
    let target = transport(bob.clone());
    target.start_listener().await.unwrap();
    source
        .connect(bob.node_id(), &target.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    assert!(matches!(
        source.recv_control().await.unwrap(),
        ControlEvent::PeerConnected { .. }
    ));
    assert!(matches!(
        target.recv_control().await.unwrap(),
        ControlEvent::PeerConnected { .. }
    ));
    // Simulate the same generation-bound bought connection used by the
    // production admission completion path; price events must pass its gate.
    let since = source.connected_since(bob.node_id()).await.unwrap();
    source.mark_admission_paid(bob.node_id(), since).await;
    assert!(source.admission_paid_on_connection(bob.node_id()).await);

    let old = konsensus_pricing::StaticPricingEngine::new(konsensus_pricing::StaticPricingConfig {
        chat_msat: 1000,
        longform_msat: raw_price,
        web_content_msat: raw_price,
        ..Default::default()
    });
    let prices = konsensus_pricing::peer_prices::build_price_table(&old).await;
    let cache = konsensus_pricing::PeerPriceCache::new();
    crate::delivery_prices::send_price_frame(
        &target,
        db.as_ref(),
        alice.node_id(),
        &Frame::PriceTable {
            prices,
            block_height: 1,
            valid_blocks: 10,
            trust_discount: discount,
        },
        &old,
        admission,
    )
    .await
    .unwrap();
    // Cache frames exactly as production handle_price_table_received and
    // handle_price_response_received do for an authenticated bought peer.
    match source.recv_control().await.unwrap() {
        ControlEvent::PriceTableReceived {
            peer_id,
            prices,
            block_height,
            valid_blocks,
            trust_discount,
            privileged,
        } => {
            assert!(
                privileged,
                "production session handler must accept this price table"
            );
            cache
                .update(peer_id, prices, block_height, valid_blocks, trust_discount)
                .await;
        }
        event => panic!("unexpected event: {event:?}"),
    }
    if send_response {
        let raw_kind_price = old.get_price_msat(kind).await.unwrap();
        crate::delivery_prices::send_price_frame(
            &target,
            db.as_ref(),
            alice.node_id(),
            &Frame::PriceResponse {
                kind,
                price_msat: raw_kind_price,
                block_height: 1,
            },
            &old,
            admission,
        )
        .await
        .unwrap();
        match source.recv_control().await.unwrap() {
            ControlEvent::PriceResponseReceived {
                peer_id,
                kind,
                price_msat,
                block_height,
                privileged,
            } => {
                assert!(
                    privileged,
                    "production session handler must accept this price response"
                );
                assert_eq!(price_msat, raw_price, "wire price stays undiscounted");
                cache
                    .update_kind_price(peer_id, kind, price_msat, block_height)
                    .await;
            }
            event => panic!("unexpected event: {event:?}"),
        }
    }
    let offered = cache
        .get_fresh_discounted_peer_price(
            bob.node_id(),
            kind,
            1,
            std::time::Duration::from_secs(3600),
        )
        .await
        .unwrap();
    assert_eq!(
        offered, expected,
        "production sender applies the retained table discount once"
    );

    let wallet = konsensus_lightning::MockLightningProvider::new();
    // Pay exactly the advertised amount: the advert must already satisfy the gate.
    let paid_msat = offered;
    let hash = wallet.inject_inbound_keysend(paid_msat, None).await;
    let settled = wallet.get_payment_status(&hash).await.unwrap();
    let proof = PaymentProof::new(
        hex::decode(hash).unwrap().try_into().unwrap(),
        hex::decode(settled.preimage.unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        paid_msat,
    );
    let mut env = UkmEnvelopeBuilder::new(
        kind,
        *alice.node_id(),
        Recipient::Node(*bob.node_id()),
        vec![1],
        proof,
    )
    .build();
    env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
    let nonce = konsensus_storage::StorageNonceAdapter::new(db.clone());
    let gate = PaymentGate::with_config(GateConfig {
        verify_lightning_settlement: true,
        min_admission_cost_msat: admission,
        ..Default::default()
    });
    assert!(
        !gate
            .validate_received_paid_envelope(
                &env,
                &nonce,
                &old,
                None,
                Some(&wallet),
                discount,
                Some(bob.node_id()),
            )
            .await
            .unwrap(),
        "payment covers the issue-time discounted tariff"
    );
    assert!(db.get_message(&env.id).await.unwrap().is_none());

    // Reopen the recipient store before first acceptance: only the durable
    // effective offer survives, not the transport's advertised discount.
    db.pool().close().await;
    let db = Arc::new(
        konsensus_storage::SqliteStorage::open(path.to_str().unwrap())
            .await
            .unwrap(),
    );
    let nonce = konsensus_storage::StorageNonceAdapter::new(db.clone());
    let new = konsensus_pricing::StaticPricingEngine::new(konsensus_pricing::StaticPricingConfig {
        chat_msat: 1000,
        longform_msat: 4000,
        web_content_msat: 4000,
        ..Default::default()
    });
    let recorded = db
        .delivery_price_floor(&env, settled.timestamp, settled.timestamp)
        .await
        .unwrap();
    let result = gate
        .validate_received_paid_envelope(
            &env,
            &nonce,
            &new,
            None,
            Some(&wallet),
            0.0,
            Some(bob.node_id()),
        )
        .await;
    source.shutdown();
    target.shutdown();
    assert_eq!(
        recorded,
        Some(offered),
        "persist the exact discounted sender price"
    );
    assert!(
        matches!(result, Ok(false)),
        "recipient-issued discounted kind price must survive repricing: {result:?}"
    );
}

#[tokio::test]
async fn kind_offer_establishes_discount_on_new_connection() {
    use konsensus_core::kind::KIND_LONGFORM;
    use konsensus_message::{ControlEvent, TransportConfig};
    let alice = alice_identity();
    let bob = bob_identity();
    let source = NoiseTransport::new(
        alice.clone(),
        TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![*bob.node_id()],
            ..Default::default()
        },
    );
    let target = NoiseTransport::new(
        bob.clone(),
        TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![*alice.node_id()],
            ..Default::default()
        },
    );
    target.start_listener().await.unwrap();
    source
        .connect(bob.node_id(), &target.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    source.recv_control().await.unwrap();
    target.recv_control().await.unwrap();
    let pricing =
        konsensus_pricing::StaticPricingEngine::new(konsensus_pricing::StaticPricingConfig {
            chat_msat: 1000,
            longform_msat: 2001,
            ..Default::default()
        });
    let db = konsensus_storage::SqliteStorage::in_memory().await.unwrap();
    let cache = konsensus_pricing::PeerPriceCache::new();
    // The sender cache outlives a transport reconnect; its old discount must
    // be explicitly replaced before publishing a new undiscounted kind offer.
    cache
        .update(
            *bob.node_id(),
            HashMap::from([("messaging".into(), 2001)]),
            1,
            10,
            0.5,
        )
        .await;
    crate::delivery_prices::send_price_frame(
        &target,
        &db,
        alice.node_id(),
        &Frame::PriceResponse {
            kind: KIND_LONGFORM,
            price_msat: 2001,
            block_height: 1,
        },
        &pricing,
        0,
    )
    .await
    .unwrap();
    match source.recv_control().await.unwrap() {
        ControlEvent::PriceTableReceived {
            peer_id,
            prices,
            block_height,
            valid_blocks,
            trust_discount,
            ..
        } => {
            assert_eq!(trust_discount, 0.0);
            cache
                .update(peer_id, prices, block_height, valid_blocks, trust_discount)
                .await;
        }
        event => panic!("table must establish the discount first: {event:?}"),
    }
    match source.recv_control().await.unwrap() {
        ControlEvent::PriceResponseReceived {
            peer_id,
            kind,
            price_msat,
            block_height,
            ..
        } => {
            assert_eq!(price_msat, 2001);
            cache
                .update_kind_price(peer_id, kind, price_msat, block_height)
                .await;
        }
        event => panic!("expected raw kind response: {event:?}"),
    }
    let price = cache
        .get_discounted_peer_price(bob.node_id(), KIND_LONGFORM)
        .await
        .unwrap();
    assert_eq!(price, 2001);
    let persisted: i64 =
        sqlx::query_scalar("SELECT amount_msat FROM delivery_price_quotes WHERE scope = ?")
            .bind(format!("kind:{KIND_LONGFORM}"))
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(persisted as u64, price);
    source.shutdown();
    target.shutdown();
}

#[tokio::test]
async fn kind_offer_publication_serializes_discount_and_fails_closed() {
    use konsensus_message::{ControlEvent, TransportConfig};
    let alice = alice_identity();
    let bob = bob_identity();
    let source = Arc::new(NoiseTransport::new(
        alice.clone(),
        TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![*bob.node_id()],
            ..Default::default()
        },
    ));
    let target = Arc::new(NoiseTransport::new(
        bob.clone(),
        TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![*alice.node_id()],
            ..Default::default()
        },
    ));
    target.start_listener().await.unwrap();
    source
        .connect(bob.node_id(), &target.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    source.recv_control().await.unwrap();
    target.recv_control().await.unwrap();
    let table = Frame::PriceTable {
        prices: HashMap::new(),
        block_height: 1,
        valid_blocks: 10,
        trust_discount: 0.5,
    };
    target.send_frame(alice.node_id(), &table).await.unwrap();
    assert!(matches!(
        source.recv_control().await.unwrap(),
        ControlEvent::PriceTableReceived { .. }
    ));
    let response = Frame::PriceResponse {
        kind: 1,
        price_msat: 2000,
        block_height: 1,
    };
    let newer = Frame::PriceTable {
        trust_discount: 0.0,
        prices: HashMap::new(),
        block_height: 1,
        valid_blocks: 10,
    };
    assert!(target
        .send_price_frame_with(alice.node_id(), &newer, &newer, |_, _| async {
            Err(konsensus_core::traits::transport::TransportError::Other(
                "disk fault".into(),
            ))
        })
        .await
        .is_err());
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let writer = target.clone();
    let peer = *alice.node_id();
    let pending = tokio::spawn(async move {
        writer
            .send_price_frame_with(
                &peer,
                &response,
                &table,
                |discount, needs_table| async move {
                    assert_eq!(
                        discount, 0.5,
                        "failed persistence must not change the advertised discount"
                    );
                    assert!(!needs_table);
                    entered_tx.send(()).unwrap();
                    release_rx.await.unwrap();
                    Ok(())
                },
            )
            .await
            .unwrap();
    });
    entered_rx.await.unwrap();
    let refresh = target.send_frame(alice.node_id(), &newer);
    tokio::pin!(refresh);
    tokio::select! {
        result = &mut refresh => panic!("table overtook persistence: {result:?}"),
        _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
    }
    release_tx.send(()).unwrap();
    pending.await.unwrap();
    refresh.await.unwrap();
    // No frame from failed persistence; the response using the old discount
    // precedes the new table, even though the latter tried to send concurrently.
    assert!(matches!(
        source.recv_control().await.unwrap(),
        ControlEvent::PriceResponseReceived {
            price_msat: 2000,
            ..
        }
    ));
    assert!(matches!(
        source.recv_control().await.unwrap(),
        ControlEvent::PriceTableReceived {
            trust_discount: 0.0,
            ..
        }
    ));
    source.shutdown();
    target.shutdown();
}

/// The caller's journal of a settled, dispatched paid block, as compose
/// leaves it before the callee's grant ACK arrives.
async fn journal_dispatched_block(store: &konsensus_storage::SqliteStorage, env: &konsensus_core::UkmEnvelope, call_id: &str, seq: u32) {
    let Recipient::Node(peer) = env.recipient else { panic!("a block goes to one node") };
    store.store_message(env).await.unwrap();
    let mut op = konsensus_storage::OutboxOperation::prepared(format!("block-{call_id}-{seq}"), peer.to_hex(), 404, format!("request-{seq}"));
    op.state = "sent".into();
    op.message_id = Some(env.id.to_hex());
    op.recovery = serde_json::to_vec(&serde_json::json!({
        "call_block": [call_id, seq], "dispatched": true, "expected_msat": env.payment_proof.amount_msat,
        "fee_ceiling_msat": 0, "admission_msat": 0,
    })).unwrap();
    store.insert_outbox_operation(&op).await.unwrap();
    store.queue_pending_delivery(&env.id, &peer).await.unwrap();
    store.mark_pending_sent(&env.id, &peer).await.unwrap();
}

/// 1:1 call signalling (kinds 400-403) end to end over Noise, through the
/// real receive loop: the offer is admitted only when paid at the recipient's
/// `call_msat`, once per call id; answer/ICE/hangup reach the app only for a
/// live call with that sender, from the right side. Nothing refused is
/// forwarded to the WebSocket.
#[tokio::test]
async fn paid_call_signalling_is_single_use_and_forwarded_only_for_a_live_call() {
    use konsensus_message::{ControlEvent, ReachabilityMode, TransportConfig};
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let alice = alice_identity();
    let bob = bob_identity();
    let transport = |id| {
        Arc::new(NoiseTransport::new(
            id,
            TransportConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                capabilities: crate::node::default_advertised_capabilities(false),
                admission_mode: ReachabilityMode::PriceOpen,
                ..Default::default()
            },
        ))
    };
    let source = transport(alice.clone());
    let target = transport(bob.clone());
    target.start_listener().await.unwrap();
    let db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let storage: Arc<dyn Storage> = db.clone();
    source
        .connect(bob.node_id(), &target.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    while !matches!(
        source.recv_control().await.unwrap(),
        ControlEvent::PeerConnected { .. }
    ) {}
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let sessions_a = SessionManager::new(alice.clone());
    let sessions_b = Arc::new(SessionManager::new(bob.clone()));
    establish_sessions(&sessions_a, &sessions_b, &alice, &bob).await;
    let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
    let (ws_tx, mut ws_rx) = broadcast::channel(16);
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> = Arc::new(
        konsensus_pricing::StaticPricingEngine::new(Default::default()),
    );
    // The receive loop over Bob's durable store; started again for a restart.
    let start = |shutdown_rx| tokio::spawn(run(MsgHandlerDeps {
        transport: target.clone(),
        transport_ack: target.clone(),
        storage: storage.clone(),
        gate: Arc::new(PaymentGate::with_config(konsensus_core::gate::GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        })),
        pricing: pricing.clone(),
        lightning: wallet.clone(),
        chain: Arc::new(konsensus_chain::MockChainProvider::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        session_manager: sessions_b.clone(),
        nonce_adapter: Arc::new(konsensus_storage::StorageNonceAdapter::new(storage.clone())),
        content_server: None,
        front_door: Default::default(),
        routing: Arc::new(RoutingTable::new(Default::default())),
        identity: bob.clone(),
        plaintext_cipher: Arc::new(PlaintextCacheCipher::new(bob.aes_key())),
        ws_tx: ws_tx.clone(),
        audit_log: audit.clone(),
        admission_mode: ReachabilityMode::PriceOpen,
        relay_engine: None,
        shutdown_rx,
    }));
    let (mut shutdown, shutdown_rx) = watch::channel(false);
    let mut worker = start(shutdown_rx);

    // Alice pays `msat` to Bob and sends one signal of `kind`.
    let signal = |kind: u16, msat: u64, body: String| {
        let (wallet, sessions_a, alice, bob, db) =
            (wallet.clone(), &sessions_a, alice.clone(), bob.clone(), db.clone());
        async move {
            let hash = if kind == 404 {
                // Issue and bind a real invoice before paying it. These fixtures
                // model issuance before the delayed settlement/delivery below.
                let invoice = wallet.create_invoice(msat, "call block",
                    konsensus_core::payloads::call::CALL_BLOCK_INVOICE_EXPIRY_SECS).await.unwrap();
                let block = konsensus_core::payloads::call::CallSignal::parse(404, &body).unwrap();
                db.record_call_block_invoice(alice.node_id(), &block.call_id, block.seq.unwrap(),
                    &hex::decode(&invoice.payment_hash).unwrap().try_into().unwrap(),
                    chrono::Utc::now().timestamp_millis() as u64 + 120_000).await.unwrap();
                wallet.pay_invoice(&invoice.bolt11).await.unwrap();
                invoice.payment_hash
            } else {
                wallet.inject_inbound_keysend(msat, None).await
            };
            let payment = wallet.get_payment_status(&hash).await.unwrap();
            let proof = PaymentProof::new(
                hex::decode(&hash).unwrap().try_into().unwrap(),
                hex::decode(payment.preimage.unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                msat,
            );
            let ciphertext = konsensus_crypto::ratchet_message_to_bytes(
                &sessions_a
                    .encrypt(bob.node_id(), body.as_bytes())
                    .await
                    .unwrap(),
            );
            let mut env = UkmEnvelopeBuilder::new(
                kind,
                *alice.node_id(),
                Recipient::Node(*bob.node_id()),
                ciphertext,
                proof,
            )
            .build();
            env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
            env
        }
    };
    let outcome = |source: Arc<NoiseTransport>| async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match source.recv_control().await.unwrap() {
                    ControlEvent::MessageAcked { duplicate, .. } => break Ok(duplicate),
                    ControlEvent::MessageRejected { reason, .. } => break Err(reason),
                    _ => {}
                }
            }
        })
        .await
        .unwrap()
    };
    let id = format!("{:032x}", rand::random::<u128>());
    let offer = format!(
        r#"{{"v":1,"call_id":"{id}","media":"audio","sdp":"v=0\r\no=- 1 1 IN IP4 127.0.0.1"}}"#
    );

    // Underpaid by a stranger (the realtime price, not the call admission):
    // dropped without a word, nothing rings.
    let env = signal(400, 50, offer.clone()).await;
    source.send(bob.node_id(), &env).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(ws_rx.try_recv().is_err());

    // Paid at Bob's call_msat (10 000 msat default): rings Bob's app once.
    let env = signal(400, 10_000, offer.clone()).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Ok(false));
    let rung = tokio::time::timeout(Duration::from_secs(5), ws_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (rung.envelope.kind, rung.plaintext.as_deref()),
        (400, Some(offer.as_str()))
    );
    // Now a paid peer: an underpaid offer for another call is refused openly.
    let under = format!(
        r#"{{"v":1,"call_id":"{:032x}","media":"video","sdp":"v=0"}}"#,
        rand::random::<u128>()
    );
    let env_under = signal(400, 9_999, under).await;
    source.send(bob.node_id(), &env_under).await.unwrap();
    assert!(outcome(source.clone())
        .await
        .unwrap_err()
        .to_lowercase()
        .contains("insufficient"));
    assert!(ws_rx.try_recv().is_err());
    // The same envelope again is a duplicate: acked, never forwarded twice.
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Ok(true));
    // A freshly paid offer reusing the call id is a replay: refused.
    let env = signal(400, 10_000, offer.clone()).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert!(outcome(source.clone())
        .await
        .unwrap_err()
        .contains("replayed"));
    assert!(ws_rx.try_recv().is_err());
    // Review P1: the refused signal is withdrawn (no history/resync), and a
    // resend of the very same paid envelope is refused, not duplicate-ACKed.
    assert!(db.get_message(&env.id).await.unwrap().is_none());
    assert!(!db.is_paid_envelope_accepted(&env).await.unwrap());
    source.send(bob.node_id(), &env).await.unwrap();
    assert!(outcome(source.clone()).await.is_err());
    assert!(ws_rx.try_recv().is_err());

    // Alice made the offer, so an answer from Alice is from the wrong side.
    let env = signal(
        401,
        1_000,
        format!(r#"{{"v":1,"call_id":"{id}","sdp":"v=0"}}"#),
    )
    .await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert!(outcome(source.clone()).await.is_err());
    // ICE for this live call reaches the app; ICE for an unknown call does not.
    let ice = |call: &str| {
        format!(
            r#"{{"v":1,"call_id":"{call}","candidate":"candidate:1 1 udp 2130706431 127.0.0.1 9 typ host","sdp_mid":"0","sdp_mline_index":0}}"#
        )
    };
    let env = signal(402, 1_000, ice(&id)).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Ok(false));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), ws_rx.recv())
            .await
            .unwrap()
            .unwrap()
            .envelope
            .kind,
        402
    );
    let other = format!("{:032x}", rand::random::<u128>());
    let env = signal(402, 1_000, ice(&other)).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert!(outcome(source.clone())
        .await
        .unwrap_err()
        .contains("no live call"));
    // Hangup ends it; later ICE for that call is refused.
    let env = signal(
        403,
        1_000,
        format!(r#"{{"v":1,"call_id":"{id}","reason":"hangup"}}"#),
    )
    .await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Ok(false));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), ws_rx.recv())
            .await
            .unwrap()
            .unwrap()
            .envelope
            .kind,
        403
    );
    let env = signal(402, 1_000, ice(&id)).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert!(outcome(source.clone()).await.is_err());
    assert!(ws_rx.try_recv().is_err());

    // Block zero may take longer than ten seconds to reach the callee.
    // The paid interval stays anchored to answer, and the gate remains single-use.
    use konsensus_core::payloads::call::{self as calls, HangupReason, Phase};
    let block_id = format!("{:032x}", rand::random::<u128>());
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let answered_at = now - 20_000;
    let pending = calls::reserve(Some(calls::receive(None, 400, None, answered_at).unwrap()), 401, "answer", "hash", answered_at).unwrap();
    let entry = calls::commit(pending, "answer", answered_at).unwrap();
    db.call_put(alice.node_id(), &block_id, &entry).await.unwrap();
    let block = |seq| format!(r#"{{"v":1,"call_id":"{block_id}","seq":{seq}}}"#);
    // A generic 3600-second invoice cannot buy call media, even for a valid seq.
    let invoice = wallet.create_invoice(10_000, "generic", 3600).await.unwrap();
    let payment = wallet.pay_invoice(&invoice.bolt11).await.unwrap();
    let mut generic = signal(404, 10_000, block(0)).await;
    generic.payment_proof = PaymentProof::new(
        hex::decode(&invoice.payment_hash).unwrap().try_into().unwrap(),
        hex::decode(payment.preimage.unwrap()).unwrap().try_into().unwrap(), 10_000);
    generic.signature = Signature::from_ed25519(&alice.sign(&generic.signable_bytes()));
    source.send(bob.node_id(), &generic).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Err("call_block_overpayment".into()));
    assert_eq!(db.call_get(alice.node_id(), &block_id).await.unwrap(), Some(entry.clone()));
    assert!(ws_rx.try_recv().is_err());
    assert!(db.is_paid_envelope_rejected(&generic).await.unwrap());
    source.send(bob.node_id(), &generic).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Err("call_block_overpayment".into()));
    let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    assert!(log.lines().map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .any(|event| event["event"] == "call.block_overpayment" && event["detail"]["message_id"] == generic.id.to_hex()));

    let env = signal(404, 10_000, block(0)).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Ok(false));
    assert_eq!(ws_rx.recv().await.unwrap().envelope.kind, 404);
    let paid = db.call_get(alice.node_id(), &block_id).await.unwrap().unwrap();
    assert_eq!(paid.paid_until_ms, Some(answered_at + 60_000));
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Ok(true));
    assert!(ws_rx.try_recv().is_err());

    // A block paid before local media detaches is retained for reconciliation.
    let cut_id = "10000000000000000000000000000004";
    let cut_now = chrono::Utc::now().timestamp_millis() as u64;
    let cut_paid = calls::CallEntry {
        paid_until_ms: Some(cut_now + 20_000), deadline_ms: cut_now + 30_000,
        ..paid.clone()
    };
    db.call_put(alice.node_id(), cut_id, &cut_paid).await.unwrap();
    let in_flight = signal(404, 10_000,
        format!(r#"{{"call_id":"{cut_id}","seq":1}}"#)).await;
    let media = crate::call_media::CallMediaRouter::new(target.clone(),
        Arc::new(crate::call_media::PaidCallAdmission::new(db.clone())));
    use konsensus_api::call_media::CallMediaPort;
    drop(media.attach(alice.node_id(), cut_id, None).await.unwrap());
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if db.call_get(alice.node_id(), cut_id).await.unwrap().unwrap().phase == Phase::Ended { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("detachment ends the callee call");
    source.send(bob.node_id(), &in_flight).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Err("call_block_overpayment".into()));
    assert!(db.is_paid_envelope_rejected(&in_flight).await.unwrap());
    assert!(db.has_nonce(&in_flight.nonce).await.unwrap());
    assert!(ws_rx.try_recv().is_err());
    let after_cut = db.call_get(alice.node_id(), cut_id).await.unwrap().unwrap();
    assert_eq!(after_cut.phase, Phase::Ended);
    assert_eq!(after_cut.end_reason, Some(HangupReason::Hangup));
    assert_eq!(after_cut.next_block_seq, 1);
    assert_eq!(after_cut.paid_until_ms, cut_paid.paid_until_ms);
    source.send(bob.node_id(), &in_flight).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Err("call_block_overpayment".into()));
    let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    let records: Vec<serde_json::Value> = log.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|event: &serde_json::Value| event["event"] == "call.block_overpayment"
            && event["detail"]["message_id"] == in_flight.id.to_hex()).collect();
    assert_eq!(records.len(), 1, "one reconciliation record on replay");
    assert_eq!(records[0]["detail"]["payment_hash"], hex::encode(in_flight.payment_proof.payment_hash));
    assert_eq!(records[0]["detail"]["amount_msat"], 10_000);
    assert_eq!(records[0]["detail"]["reconciliation_required"], true);

    // An overdue socket cut retains expiry ownership while reconciling a settled renewal.
    let overdue_id = format!("{:032x}", rand::random::<u128>());
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let live = calls::CallEntry {
        deadline_ms: now + 30_000, paid_until_ms: Some(now + 20_000), ..paid.clone()
    };
    db.call_put(alice.node_id(), &overdue_id, &live).await.unwrap();
    let settled = signal(404, 10_000, format!(r#"{{"call_id":"{overdue_id}","seq":1}}"#)).await;
    let media = crate::call_media::CallMediaRouter::new(target.clone(),
        Arc::new(crate::call_media::PaidCallAdmission::new(db.clone())));
    let attachment = media.attach(alice.node_id(), &overdue_id, None).await.unwrap();
    let overdue = calls::CallEntry {
        deadline_ms: now - 1, paid_until_ms: Some(now - 10_001), ..live
    };
    db.call_put(alice.node_id(), &overdue_id, &overdue).await.unwrap();
    drop(attachment);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if db.call_get(alice.node_id(), &overdue_id).await.unwrap().unwrap().paid_until_ms == Some(0) { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("overdue socket cut closes resume before maintenance");
    let closed = calls::CallEntry { paid_until_ms: Some(0), ..overdue };
    assert_eq!(db.call_get(alice.node_id(), &overdue_id).await.unwrap(), Some(closed.clone()));
    source.send(bob.node_id(), &settled).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Err("call_block_overpayment".into()));
    assert!(db.is_paid_envelope_rejected(&settled).await.unwrap());
    assert!(db.has_nonce(&settled.nonce).await.unwrap());
    assert!(!db.is_paid_envelope_accepted(&settled).await.unwrap());
    assert!(ws_rx.try_recv().is_err());
    assert_eq!(db.call_get(alice.node_id(), &overdue_id).await.unwrap(), Some(closed));
    assert_eq!(media.attach(alice.node_id(), &overdue_id, None).await.err(), Some(konsensus_api::call_media::AttachRefusal::NotAdmitted));
    source.send(bob.node_id(), &settled).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Err("call_block_overpayment".into()));
    let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    let records: Vec<serde_json::Value> = log.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|event: &serde_json::Value| event["event"] == "call.block_overpayment"
            && event["detail"]["message_id"] == settled.id.to_hex()).collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["detail"]["payment_hash"], hex::encode(settled.payment_proof.payment_hash));
    assert_eq!(records[0]["detail"]["amount_msat"], 10_000);
    assert_eq!(records[0]["detail"]["reconciliation_required"], true);

    // Media cut after Unpaid expiry retains the reason and audits a settled renewal.
    for socket_drop in [false, true] {
        let unpaid_id = format!("{:032x}", rand::random::<u128>());
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let live = calls::CallEntry {
            deadline_ms: now + 30_000, paid_until_ms: Some(now + 20_000), ..paid.clone()
        };
        db.call_put(alice.node_id(), &unpaid_id, &live).await.unwrap();
        let settled = signal(404, 10_000, format!(r#"{{"call_id":"{unpaid_id}","seq":1}}"#)).await;
        let media = crate::call_media::CallMediaRouter::new(target.clone(),
            Arc::new(crate::call_media::PaidCallAdmission::new(db.clone())));
        use konsensus_api::call_media::CallMediaPort as _;
        let mut attachment = Some(media.attach(alice.node_id(), &unpaid_id, None).await.unwrap());
        let expired = calls::CallEntry {
            phase: Phase::Ended, end_reason: Some(HangupReason::Unpaid),
            deadline_ms: now - 1 + calls::TOMBSTONE_MS, paid_until_ms: Some(now - 10_001), ..live
        };
        assert!(calls::receive_block(Some(expired.clone()), 1, now).is_ok());
        db.call_put(alice.node_id(), &unpaid_id, &expired).await.unwrap();
        if socket_drop { drop(attachment.take()); }
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let ended = db.call_get(alice.node_id(), &unpaid_id).await.unwrap().unwrap();
                if calls::receive_block(Some(ended), 1, chrono::Utc::now().timestamp_millis() as u64).is_err() { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("Unpaid media cut must close the resume window");
        let ended = db.call_get(alice.node_id(), &unpaid_id).await.unwrap().unwrap();
        assert_eq!(ended.end_reason, Some(HangupReason::Unpaid));
        assert_eq!(ended.paid_until_ms, Some(0));
        assert_eq!(ended.deadline_ms, expired.deadline_ms);
        assert_eq!(ended.next_block_seq, expired.next_block_seq);
        source.send(bob.node_id(), &settled).await.unwrap();
        assert_eq!(outcome(source.clone()).await, Err("call_block_overpayment".into()));
        assert!(db.is_paid_envelope_rejected(&settled).await.unwrap());
        assert!(db.has_nonce(&settled.nonce).await.unwrap());
        assert!(!db.is_paid_envelope_accepted(&settled).await.unwrap());
        assert!(db.get_message(&settled.id).await.unwrap().is_none());
        assert!(ws_rx.try_recv().is_err());
        assert_eq!(db.call_get(alice.node_id(), &unpaid_id).await.unwrap(), Some(ended.clone()));
        source.send(bob.node_id(), &settled).await.unwrap();
        assert_eq!(outcome(source.clone()).await, Err("call_block_overpayment".into()));
        assert_eq!(db.call_get(alice.node_id(), &unpaid_id).await.unwrap(), Some(ended));
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let records: Vec<serde_json::Value> = log.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .filter(|event: &serde_json::Value| event["event"] == "call.block_overpayment"
                && event["detail"]["message_id"] == settled.id.to_hex()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["detail"]["reconciliation_required"], true);
        assert_eq!(records[0]["detail"]["payment_hash"], hex::encode(settled.payment_proof.payment_hash));
        drop(attachment);
    }

    // Outside the resume window the settled block is a durable, terminal
    // overpayment. Its proof is single-use; the audit survives reopening.
    let late_id = format!("{:032x}", rand::random::<u128>());
    let late_initial = calls::CallEntry { deadline_ms: now - calls::CALL_BLOCK_RESUME_MS - 1, ..entry };
    db.call_put(alice.node_id(), &late_id, &late_initial).await.unwrap();
    let env = signal(404, 10_000, format!(r#"{{"v":1,"call_id":"{late_id}","seq":0}}"#)).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Err("call_block_overpayment".into()));
    assert!(db.has_nonce(&env.nonce).await.unwrap());
    assert!(db.get_message(&env.id).await.unwrap().is_none());
    assert!(db.get_message_plaintext(&env.id).await.unwrap().is_none());
    assert!(!db.is_paid_envelope_accepted(&env).await.unwrap());
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Err("call_block_overpayment".into()));
    assert!(!db.store_payment_receipt(&env.payment_proof.payment_hash, alice.node_id(), &env.id).await.unwrap());
    assert!(ws_rx.try_recv().is_err());
    assert!(!konsensus_api::calls::call_media_admitted(db.as_ref(), alice.node_id(), &late_id, now).await);
    let audit_entries = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    let events: Vec<serde_json::Value> = audit_entries.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    let overpayment = events.iter().find(|event| event["event"] == "call.block_overpayment"
        && event["detail"]["message_id"] == env.id.to_hex()).expect("durable overpayment audit");
    assert_eq!(overpayment["detail"]["call_id"], late_id);
    assert_eq!(overpayment["detail"]["seq"], 0);
    assert_eq!(overpayment["detail"]["amount_msat"], 10_000);
    assert_eq!(overpayment["detail"]["payment_hash"], hex::encode(env.payment_proof.payment_hash));
    assert_eq!(overpayment["detail"]["reconciliation_required"], true);
    assert_eq!(events.iter().filter(|event| event["event"] == "call.block_overpayment"
        && event["detail"]["message_id"] == env.id.to_hex()).count(), 1);

    // An incorrect sequence is also an audited overpayment, never a grant.
    let wrong_id = format!("{:032x}", rand::random::<u128>());
    let wrong_entry = calls::CallEntry { deadline_ms: now + 30_000, ..late_initial.clone() };
    db.call_put(alice.node_id(), &wrong_id, &wrong_entry).await.unwrap();
    let wrong = signal(404, 10_000, format!(r#"{{"call_id":"{wrong_id}","seq":1}}"#)).await;
    source.send(bob.node_id(), &wrong).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Err("call_block_overpayment".into()));
    assert!(db.is_paid_envelope_rejected(&wrong).await.unwrap());
    assert_eq!(db.call_get(alice.node_id(), &wrong_id).await.unwrap(), Some(wrong_entry));
    let audit_entries = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    assert!(audit_entries.lines().map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .any(|event| event["event"] == "call.block_overpayment" && event["detail"]["call_id"] == wrong_id
            && event["detail"]["seq"] == 1 && event["detail"]["reconciliation_required"] == true));

    // A paid block whose call-state write fails leaves explicit evidence for
    // reconciliation, bound to its retained payment receipt, without media.
    let failed_id = format!("{:032x}", rand::random::<u128>());
    let failed_entry = calls::CallEntry { deadline_ms: now + 30_000, ..late_initial.clone() };
    db.call_put(alice.node_id(), &failed_id, &failed_entry).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_call_commit BEFORE UPDATE ON call_state BEGIN SELECT RAISE(ABORT, 'injected call commit failure'); END")
        .execute(db.pool()).await.unwrap();
    let failed = signal(404, 10_000, format!(r#"{{"v":1,"call_id":"{failed_id}","seq":0}}"#)).await;
    source.send(bob.node_id(), &failed).await.unwrap();
    assert!(outcome(source.clone()).await.is_err());
    sqlx::query("DROP TRIGGER fail_call_commit").execute(db.pool()).await.unwrap();
    assert!(ws_rx.try_recv().is_err());
    assert_eq!(db.call_get(alice.node_id(), &failed_id).await.unwrap(), Some(failed_entry));
    assert!(db.get_message(&failed.id).await.unwrap().is_none());
    assert!(db.get_message_plaintext(&failed.id).await.unwrap().is_none());
    let receipt: (String, i64, i32) = sqlx::query_as("SELECT message_id, amount_msat, accepted FROM payment_receipts WHERE payment_hash = ?")
        .bind(hex::encode(failed.payment_proof.payment_hash)).fetch_one(db.pool()).await.unwrap();
    assert_eq!(receipt, (failed.id.to_hex(), 10_000, -1));
    let audit_entries = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    let reconciliation = audit_entries.lines().map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|event| event["event"] == "call.block_commit_failed" && event["detail"]["message_id"] == failed.id.to_hex())
        .expect("failed paid block needs a reconciliation record");
    assert_eq!(reconciliation["detail"]["call_id"], failed_id);
    assert_eq!(reconciliation["detail"]["seq"], 0);
    assert_eq!(reconciliation["detail"]["amount_msat"], 10_000);
    assert_eq!(reconciliation["detail"]["reconciliation_required"], true);

    // A settled next renewal within the window resumes even after the
    // callee already emitted its single-use Unpaid notice, and tells the caller.
    let expired = calls::CallEntry { deadline_ms: now - 1, ..paid };
    let ended = calls::CallEntry { unpaid_notice_used: true, ..expired.clone().at(now).unwrap() };
    db.call_put(alice.node_id(), &block_id, &ended).await.unwrap();
    let env = signal(404, 10_000, block(1)).await;
    source.send(bob.node_id(), &env).await.unwrap();
    let grant = tokio::time::timeout(Duration::from_secs(5), source.recv_control()).await.unwrap().unwrap();
    let granted_until = match grant {
        ControlEvent::MessageAcked { message_id, paid_until_ms: Some(paid_until_ms), duplicate: false, .. } => {
            assert_eq!(message_id, env.id);
            assert!(paid_until_ms >= now + 60_000);
            paid_until_ms
        },
        other => panic!("expected paid interval confirmation, got {other:?}"),
    };
    assert_eq!(ws_rx.recv().await.unwrap().envelope.kind, 404);
    let resumed = db.call_get(alice.node_id(), &block_id).await.unwrap().unwrap();
    assert_eq!(resumed.phase, Phase::Live);
    assert_eq!(resumed.next_block_seq, 2);
    assert_eq!(resumed.paid_until_ms, Some(granted_until));
    source.send(bob.node_id(), &env).await.unwrap();
    assert!(matches!(source.recv_control().await.unwrap(), ControlEvent::MessageAcked { paid_until_ms: Some(paid_until_ms), duplicate: true, .. } if paid_until_ms == granted_until));
    assert_eq!(db.call_get(alice.node_id(), &block_id).await.unwrap(), Some(resumed));

    // The peer can observe the callee's unpaid termination even after its
    // own timer expired. Replaying that envelope never notifies the app twice.
    let ended = calls::CallEntry { side: calls::Side::Caller, ..expired.at(now).unwrap() };
    assert_eq!(ended.end_reason, Some(HangupReason::Unpaid));
    db.call_put(alice.node_id(), &block_id, &ended).await.unwrap();
    let env = signal(403, 1_000, format!(r#"{{"v":1,"call_id":"{block_id}","reason":"unpaid"}}"#)).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Ok(false));
    let notification = ws_rx.recv().await.unwrap();
    assert_eq!(notification.plaintext.as_deref(), Some(format!(r#"{{"v":1,"call_id":"{block_id}","reason":"unpaid"}}"#).as_str()));
    assert_eq!(db.call_get(alice.node_id(), &block_id).await.unwrap(), Some(calls::CallEntry { unpaid_notice_used: true, ..ended }));
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Ok(true));
    assert!(ws_rx.try_recv().is_err());
    assert_eq!(db.call_get(alice.node_id(), &block_id).await.unwrap().unwrap().phase, Phase::Ended);
    let second = signal(403, 1_000, format!(r#"{{"v":1,"call_id":"{block_id}","reason":"unpaid"}}"#)).await;
    assert_ne!(second.id, env.id);
    source.send(bob.node_id(), &second).await.unwrap();
    assert!(outcome(source.clone()).await.is_err());
    assert!(ws_rx.try_recv().is_err(), "a distinct paid notice must not reach the app twice");

    // A committed block is never withdrawn by a failure of the generic
    // (second) plaintext write: its interval is granted, so the sender gets
    // the normal grant ACK and the caller reconciles to paid. The fault hits
    // ONLY that write: the metadata write before commit finds the fresh row's
    // cache empty, any later write would find it set and abort.
    sqlx::query("CREATE TRIGGER fail_second_plaintext BEFORE UPDATE OF plaintext_enc ON messages WHEN OLD.plaintext_enc IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected second plaintext write failure'); END")
        .execute(db.pool()).await.unwrap();
    let grant_outcome = |source: Arc<NoiseTransport>, id: MessageId| async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match source.recv_control().await.unwrap() {
                    ControlEvent::MessageAcked { message_id, duplicate, paid_until_ms, .. } if message_id == id => break Ok((duplicate, paid_until_ms)),
                    ControlEvent::MessageRejected { message_id, reason, .. } if message_id == id => break Err(reason),
                    _ => {}
                }
            }
        }).await.unwrap()
    };
    let caller_db = konsensus_storage::SqliteStorage::in_memory().await.unwrap();
    let caller_cipher = PlaintextCacheCipher::new(alice.aes_key());
    let fault_id = format!("{:032x}", rand::random::<u128>());
    let fault_block = |seq: u32| format!(r#"{{"v":1,"call_id":"{fault_id}","seq":{seq}}}"#);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let answered_at = now - 20_000;
    let pending = calls::reserve(Some(calls::receive(None, 400, None, answered_at).unwrap()), 401, "answer", "hash", answered_at).unwrap();
    let fault_entry = calls::commit(pending, "answer", answered_at).unwrap();
    db.call_put(alice.node_id(), &fault_id, &fault_entry).await.unwrap();

    // Delayed block zero. The caller advanced its sequence when it settled.
    let caller_entry = calls::CallEntry { side: calls::Side::Caller, next_block_seq: 1, ..fault_entry.clone() };
    caller_db.call_put(bob.node_id(), &fault_id, &caller_entry).await.unwrap();
    assert!(!konsensus_api::calls::call_media_admitted(&caller_db, bob.node_id(), &fault_id, now).await);
    let env0 = signal(404, 10_000, fault_block(0)).await;
    journal_dispatched_block(&caller_db, &env0, &fault_id, 0).await;
    source.send(bob.node_id(), &env0).await.unwrap();
    let granted0 = match grant_outcome(source.clone(), env0.id).await {
        Ok((false, Some(until))) => until,
        other => panic!("a committed block must be granted, not withdrawn: {other:?}"),
    };
    assert_eq!(granted0, answered_at + 60_000);
    assert_eq!(ws_rx.recv().await.unwrap().envelope.kind, 404);
    let callee0 = db.call_get(alice.node_id(), &fault_id).await.unwrap().unwrap();
    assert_eq!((callee0.phase, callee0.next_block_seq, callee0.paid_until_ms), (Phase::Live, 1, Some(granted0)));
    assert!(db.get_message(&env0.id).await.unwrap().is_some(), "not withdrawn");
    assert!(db.is_paid_envelope_accepted(&env0).await.unwrap());
    assert!(!db.is_paid_envelope_rejected(&env0).await.unwrap());
    // Duplicate: the same durable grant is replayed, never extended.
    source.send(bob.node_id(), &env0).await.unwrap();
    assert_eq!(grant_outcome(source.clone(), env0.id).await, Ok((true, Some(granted0))));
    assert_eq!(db.call_get(alice.node_id(), &fault_id).await.unwrap(), Some(callee0.clone()));
    assert!(ws_rx.try_recv().is_err());
    // The caller applies the ACK (and its duplicate) and is paid to the same boundary.
    for _ in 0..2 {
        konsensus_api::calls::receive_block_grant(&caller_db, &caller_cipher, alice.node_id(), bob.node_id(), &env0.id, granted0).await.unwrap();
    }
    let caller0 = caller_db.call_get(bob.node_id(), &fault_id).await.unwrap().unwrap();
    assert_eq!((caller0.phase, caller0.next_block_seq, caller0.paid_until_ms), (Phase::Live, 1, Some(granted0)));
    let at = chrono::Utc::now().timestamp_millis() as u64;
    assert!(konsensus_api::calls::call_media_admitted(db.as_ref(), alice.node_id(), &fault_id, at).await);
    assert!(konsensus_api::calls::call_media_admitted(&caller_db, bob.node_id(), &fault_id, at).await);

    // Resumed renewal after both timers expired: only the grant ACK reopens
    // the caller, so it must survive the same second-write failure.
    let expired = calls::CallEntry { deadline_ms: now - 1, ..callee0 };
    let callee_ended = calls::CallEntry { unpaid_notice_used: true, ..expired.clone().at(now).unwrap() };
    db.call_put(alice.node_id(), &fault_id, &callee_ended).await.unwrap();
    let caller_ended = calls::CallEntry { side: calls::Side::Caller, next_block_seq: 2, ..expired }.at(now).unwrap();
    assert_eq!((caller_ended.phase, caller_ended.end_reason), (Phase::Ended, Some(HangupReason::Unpaid)));
    caller_db.call_put(bob.node_id(), &fault_id, &caller_ended).await.unwrap();
    let env1 = signal(404, 10_000, fault_block(1)).await;
    journal_dispatched_block(&caller_db, &env1, &fault_id, 1).await;
    source.send(bob.node_id(), &env1).await.unwrap();
    let granted1 = match grant_outcome(source.clone(), env1.id).await {
        Ok((false, Some(until))) => until,
        other => panic!("a committed resume must be granted, not withdrawn: {other:?}"),
    };
    assert!(granted1 >= now + 60_000);
    assert_eq!(ws_rx.recv().await.unwrap().envelope.kind, 404);
    let callee1 = db.call_get(alice.node_id(), &fault_id).await.unwrap().unwrap();
    assert_eq!((callee1.phase, callee1.next_block_seq, callee1.paid_until_ms), (Phase::Live, 2, Some(granted1)));
    assert!(db.get_message(&env1.id).await.unwrap().is_some(), "not withdrawn");
    assert!(!db.is_paid_envelope_rejected(&env1).await.unwrap());
    source.send(bob.node_id(), &env1).await.unwrap();
    assert_eq!(grant_outcome(source.clone(), env1.id).await, Ok((true, Some(granted1))));
    assert_eq!(db.call_get(alice.node_id(), &fault_id).await.unwrap(), Some(callee1));
    assert!(ws_rx.try_recv().is_err());
    assert!(!konsensus_api::calls::call_media_admitted(&caller_db, bob.node_id(), &fault_id, now).await);
    for _ in 0..2 {
        konsensus_api::calls::receive_block_grant(&caller_db, &caller_cipher, alice.node_id(), bob.node_id(), &env1.id, granted1).await.unwrap();
    }
    let caller1 = caller_db.call_get(bob.node_id(), &fault_id).await.unwrap().unwrap();
    assert_eq!((caller1.phase, caller1.next_block_seq, caller1.paid_until_ms), (Phase::Live, 2, Some(granted1)));
    let at = chrono::Utc::now().timestamp_millis() as u64;
    assert!(konsensus_api::calls::call_media_admitted(db.as_ref(), alice.node_id(), &fault_id, at).await);
    assert!(konsensus_api::calls::call_media_admitted(&caller_db, bob.node_id(), &fault_id, at).await);

    // One payment each, kept accepted; no withdrawal and no reconciliation event.
    for env in [&env0, &env1] {
        let receipts: Vec<(String, i32)> = sqlx::query_as("SELECT message_id, accepted FROM payment_receipts WHERE payment_hash = ?")
            .bind(hex::encode(env.payment_proof.payment_hash)).fetch_all(db.pool()).await.unwrap();
        assert_eq!(receipts, vec![(env.id.to_hex(), 1)]);
    }
    let audit_entries = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    assert!(!audit_entries.lines().map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .any(|event| (event["event"] == "message.rejected" || event["event"] == "call.block_commit_failed"
            || event["event"] == "call.block_overpayment")
            && (event["detail"]["message_id"] == env0.id.to_hex() || event["detail"]["message_id"] == env1.id.to_hex())));
    sqlx::query("DROP TRIGGER fail_second_plaintext").execute(db.pool()).await.unwrap();

    // Review P1 (#441): a failing hold release can no longer strand a committed
    // grant behind a hold that recovery withdraws. The grant and the release
    // are one transaction: under the fault the grant rolls back with the
    // release (no interval, a refusal, a reconciliation record), and a block
    // that did commit has no hold left, so neither restart recovery nor a
    // retry under the same fault can withdraw it; a retry re-ACKs the same
    // boundary and never grants twice.
    let receipts = |env: &konsensus_core::UkmEnvelope| {
        let (pool, hash) = (db.pool().clone(), hex::encode(env.payment_proof.payment_hash));
        async move {
            sqlx::query_as::<_, (String, i32)>("SELECT message_id, accepted FROM payment_receipts WHERE payment_hash = ?")
                .bind(hash).fetch_all(&pool).await.unwrap()
        }
    };
    let audited = |id: MessageId| -> Vec<String> {
        std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap().lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|event| event["detail"]["message_id"] == id.to_hex())
            .map(|event| event["event"].as_str().unwrap().to_owned()).collect()
    };
    let fail_release = "CREATE TRIGGER fail_release BEFORE DELETE ON call_admission_hold BEGIN SELECT RAISE(ABORT, 'injected hold release failure'); END";
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let answered_at = now - 20_000;
    let answered = || calls::commit(calls::reserve(Some(calls::receive(None, 400, None, answered_at).unwrap()),
        401, "answer", "hash", answered_at).unwrap(), "answer", answered_at).unwrap();

    // The release fails: the grant rolls back with it and the block is refused.
    let stranded_id = format!("{:032x}", rand::random::<u128>());
    let stranded_entry = answered();
    db.call_put(alice.node_id(), &stranded_id, &stranded_entry).await.unwrap();
    sqlx::query(fail_release).execute(db.pool()).await.unwrap();
    let stranded = signal(404, 10_000, format!(r#"{{"v":1,"call_id":"{stranded_id}","seq":0}}"#)).await;
    source.send(bob.node_id(), &stranded).await.unwrap();
    assert_eq!(grant_outcome(source.clone(), stranded.id).await, Err("storage error".into()));
    assert!(ws_rx.try_recv().is_err());
    assert_eq!(db.call_get(alice.node_id(), &stranded_id).await.unwrap(), Some(stranded_entry.clone()),
        "a grant must never be committed without the release of its hold");
    assert!(!konsensus_api::calls::call_media_admitted(db.as_ref(), alice.node_id(), &stranded_id, now).await);
    assert!(db.call_admission_held(&stranded.id).await.unwrap(), "its withdrawal failed too: it stays hidden");
    // Still held: a retry is refused, never acknowledged or granted.
    source.send(bob.node_id(), &stranded).await.unwrap();
    assert_eq!(grant_outcome(source.clone(), stranded.id).await, Err("call signal withdrawn".into()));
    assert_eq!(db.call_get(alice.node_id(), &stranded_id).await.unwrap(), Some(stranded_entry.clone()));
    sqlx::query("DROP TRIGGER fail_release").execute(db.pool()).await.unwrap();

    // A block that commits is admitted in the same transaction: no hold remains.
    let kept_id = format!("{:032x}", rand::random::<u128>());
    db.call_put(alice.node_id(), &kept_id, &answered()).await.unwrap();
    let caller_entry = calls::CallEntry { side: calls::Side::Caller, next_block_seq: 1, ..answered() };
    caller_db.call_put(bob.node_id(), &kept_id, &caller_entry).await.unwrap();
    let kept = signal(404, 10_000, format!(r#"{{"v":1,"call_id":"{kept_id}","seq":0}}"#)).await;
    journal_dispatched_block(&caller_db, &kept, &kept_id, 0).await;
    source.send(bob.node_id(), &kept).await.unwrap();
    let kept_until = match grant_outcome(source.clone(), kept.id).await {
        Ok((false, Some(until))) => until,
        other => panic!("a committed block must be granted: {other:?}"),
    };
    assert_eq!(kept_until, answered_at + 60_000);
    assert_eq!(ws_rx.recv().await.unwrap().envelope.kind, 404);
    assert!(!db.call_admission_held(&kept.id).await.unwrap());
    let callee_kept = db.call_get(alice.node_id(), &kept_id).await.unwrap().unwrap();
    assert_eq!((callee_kept.phase, callee_kept.next_block_seq, callee_kept.paid_until_ms), (Phase::Live, 1, Some(kept_until)));

    // That ACK is lost and Bob restarts: startup recovery withdraws only the
    // stranded block. The release fault is back for everything that follows.
    shutdown.send(true).unwrap();
    worker.await.unwrap();
    assert_eq!(konsensus_api::calls::withdraw_held(db.as_ref(), true).await.unwrap(), 1);
    sqlx::query(fail_release).execute(db.pool()).await.unwrap();
    let (restarted, shutdown_rx) = watch::channel(false);
    shutdown = restarted;
    worker = start(shutdown_rx);

    // The stranded block: withdrawn, never granted, refused on retry, and its
    // settled payment is on record for reconciliation.
    assert_eq!(receipts(&stranded).await, vec![(stranded.id.to_hex(), -1)]);
    assert!(db.get_message(&stranded.id).await.unwrap().is_none());
    source.send(bob.node_id(), &stranded).await.unwrap();
    assert_eq!(grant_outcome(source.clone(), stranded.id).await, Err("call_block_overpayment".into()));
    assert_eq!(db.call_get(alice.node_id(), &stranded_id).await.unwrap(), Some(stranded_entry));
    assert!(audited(stranded.id).contains(&"call.block_commit_failed".to_owned()));

    // The committed block survived recovery; the retry re-ACKs the same
    // boundary without a second grant, and the caller's media gate opens.
    assert!(db.get_message(&kept.id).await.unwrap().is_some(), "not withdrawn");
    assert_eq!(receipts(&kept).await, vec![(kept.id.to_hex(), 1)]);
    assert!(!konsensus_api::calls::call_media_admitted(&caller_db, bob.node_id(), &kept_id, now).await);
    source.send(bob.node_id(), &kept).await.unwrap();
    assert_eq!(grant_outcome(source.clone(), kept.id).await, Ok((true, Some(kept_until))));
    assert!(ws_rx.try_recv().is_err());
    assert_eq!(db.call_get(alice.node_id(), &kept_id).await.unwrap(), Some(callee_kept));
    for _ in 0..2 {
        konsensus_api::calls::receive_block_grant(&caller_db, &caller_cipher, alice.node_id(), bob.node_id(), &kept.id, kept_until).await.unwrap();
    }
    let caller_kept = caller_db.call_get(bob.node_id(), &kept_id).await.unwrap().unwrap();
    assert_eq!((caller_kept.phase, caller_kept.next_block_seq, caller_kept.paid_until_ms), (Phase::Live, 1, Some(kept_until)));
    let at = chrono::Utc::now().timestamp_millis() as u64;
    assert!(konsensus_api::calls::call_media_admitted(db.as_ref(), alice.node_id(), &kept_id, at).await);
    assert!(konsensus_api::calls::call_media_admitted(&caller_db, bob.node_id(), &kept_id, at).await);
    assert_eq!(receipts(&kept).await, vec![(kept.id.to_hex(), 1)]);
    assert!(audited(kept.id).is_empty(), "no withdrawal, overpayment or reconciliation for a kept grant");
    sqlx::query("DROP TRIGGER fail_release").execute(db.pool()).await.unwrap();
    shutdown.send(true).unwrap();
    worker.await.unwrap();
    source.shutdown();
    target.shutdown();
}

/// Rooms (#155): every incoming chat is held (invisible to history,
/// plaintext, duplicate ACKs) from before its paid acceptance until it is
/// decrypted and its room binding admitted, over Noise through the real
/// receive loop. A valid room chat and plain chat are released and reach the
/// app; a binding whose roster lacks this node, or whose roster does not match
/// its room id, is withdrawn and refused terminally. If the withdrawal (or
/// the release) fails, the chat stays held and hidden, a resend is refused,
/// and the sweep withdraws it.
#[tokio::test]
async fn room_chats_stay_hidden_until_their_binding_is_admitted() {
    use konsensus_core::payloads::room::RoomBinding;
    use konsensus_message::{ControlEvent, ReachabilityMode, TransportConfig};
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let alice = alice_identity();
    let bob = bob_identity();
    let transport = |id| {
        Arc::new(NoiseTransport::new(
            id,
            TransportConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                admission_mode: ReachabilityMode::PriceOpen,
                ..Default::default()
            },
        ))
    };
    let source = transport(alice.clone());
    let target = transport(bob.clone());
    target.start_listener().await.unwrap();
    let db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let storage: Arc<dyn Storage> = db.clone();
    source
        .connect(bob.node_id(), &target.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    while !matches!(
        source.recv_control().await.unwrap(),
        ControlEvent::PeerConnected { .. }
    ) {}
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let sessions_a = SessionManager::new(alice.clone());
    let sessions_b = Arc::new(SessionManager::new(bob.clone()));
    establish_sessions(&sessions_a, &sessions_b, &alice, &bob).await;
    let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (ws_tx, mut ws_rx) = broadcast::channel(16);
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> = Arc::new(
        konsensus_pricing::StaticPricingEngine::new(Default::default()),
    );
    let worker = tokio::spawn(run(MsgHandlerDeps {
        transport: target.clone(),
        transport_ack: target.clone(),
        storage: storage.clone(),
        gate: Arc::new(PaymentGate::with_config(konsensus_core::gate::GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        })),
        pricing,
        lightning: wallet.clone(),
        chain: Arc::new(konsensus_chain::MockChainProvider::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        session_manager: sessions_b,
        nonce_adapter: Arc::new(konsensus_storage::StorageNonceAdapter::new(storage)),
        content_server: None,
        front_door: Default::default(),
        routing: Arc::new(RoutingTable::new(Default::default())),
        identity: bob.clone(),
        plaintext_cipher: Arc::new(PlaintextCacheCipher::new(bob.aes_key())),
        ws_tx,
        audit_log: audit,
        admission_mode: ReachabilityMode::PriceOpen,
        relay_engine: None,
        shutdown_rx,
    }));

    // Alice pays Bob and sends one chat.
    let chat = |body: String| {
        let (wallet, sessions_a, alice, bob) =
            (wallet.clone(), &sessions_a, alice.clone(), bob.clone());
        async move {
            let msat = 10_000;
            let hash = wallet.inject_inbound_keysend(msat, None).await;
            let payment = wallet.get_payment_status(&hash).await.unwrap();
            let proof = PaymentProof::new(
                hex::decode(&hash).unwrap().try_into().unwrap(),
                hex::decode(payment.preimage.unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                msat,
            );
            let ciphertext = konsensus_crypto::ratchet_message_to_bytes(
                &sessions_a
                    .encrypt(bob.node_id(), body.as_bytes())
                    .await
                    .unwrap(),
            );
            let mut env = UkmEnvelopeBuilder::new(
                0,
                *alice.node_id(),
                Recipient::Node(*bob.node_id()),
                ciphertext,
                proof,
            )
            .build();
            env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
            env
        }
    };
    let outcome = |source: Arc<NoiseTransport>| async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match source.recv_control().await.unwrap() {
                    ControlEvent::MessageAcked { duplicate, .. } => break Ok(duplicate),
                    ControlEvent::MessageRejected { reason, .. } => break Err(reason),
                    _ => {}
                }
            }
        })
        .await
        .unwrap()
    };
    let room_chat = |room: &RoomBinding, text: &str| {
        serde_json::json!({"v": 1, "room": room, "msg": format!("{:032x}", rand::random::<u128>()), "text": text}).to_string()
    };
    let outsider = NodeId::from_bytes([0xee; 32]);
    let room = RoomBinding::create(&[*alice.node_id(), *bob.node_id(), outsider]).unwrap();
    let hidden = |env: konsensus_core::UkmEnvelope| {
        let db = db.clone();
        async move {
            assert!(
                db.get_message(&env.id).await.unwrap().is_none(),
                "stored message visible"
            );
            assert!(
                db.get_message_plaintext(&env.id).await.unwrap().is_none(),
                "plaintext visible"
            );
            assert!(
                !db.get_messages_for_recipient(&env.recipient, 100, None)
                    .await
                    .unwrap()
                    .iter()
                    .any(|e| e.id == env.id),
                "listed"
            );
            assert!(
                !db.is_paid_envelope_accepted(&env).await.unwrap(),
                "would be duplicate-ACKed"
            );
        }
    };

    // Admitted: released before the app sees it.
    let text = room_chat(&room, "hello room");
    let env = chat(text.clone()).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Ok(false));
    let got = tokio::time::timeout(Duration::from_secs(5), ws_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.plaintext.as_deref(), Some(text.as_str()));
    assert!(!db.call_admission_held(&env.id).await.unwrap());
    assert!(db.get_message(&env.id).await.unwrap().is_some());
    let plain = chat("plain chat".into()).await;
    source.send(bob.node_id(), &plain).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Ok(false));
    assert!(
        db.get_message(&plain.id).await.unwrap().is_some(),
        "plain chat is released too"
    );
    let _ = ws_rx.recv().await;

    // Refused after decryption: withdrawn, terminal, never shown.
    let not_bob = RoomBinding::create(&[*alice.node_id(), outsider]).unwrap();
    let mut swapped = room.clone();
    swapped.roster = RoomBinding::create(&[
        *alice.node_id(),
        *bob.node_id(),
        NodeId::from_bytes([0xdd; 32]),
    ])
    .unwrap()
    .roster;
    for (text, code) in [
        (room_chat(&not_bob, "x"), "room_recipient_not_member:"),
        (room_chat(&swapped, "x"), "room_binding_invalid:"),
    ] {
        let env = chat(text).await;
        source.send(bob.node_id(), &env).await.unwrap();
        let reason = outcome(source.clone()).await.unwrap_err();
        assert!(reason.starts_with(code), "{reason}");
        hidden(env.clone()).await;
        source.send(bob.node_id(), &env).await.unwrap();
        assert!(
            outcome(source.clone()).await.is_err(),
            "a resend is not re-accepted"
        );
        assert!(ws_rx.try_recv().is_err());
    }

    // The withdrawal fails: still held, so hidden; a resend is refused, not
    // duplicate-ACKed; the startup sweep withdraws it.
    sqlx::raw_sql("CREATE TRIGGER fail_withdraw BEFORE DELETE ON messages BEGIN SELECT RAISE(ABORT, 'disk fault'); END").execute(db.pool()).await.unwrap();
    let env = chat(room_chat(&not_bob, "stuck")).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert!(outcome(source.clone())
        .await
        .unwrap_err()
        .starts_with("room_recipient_not_member:"));
    assert!(db.call_admission_held(&env.id).await.unwrap());
    hidden(env.clone()).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(
        outcome(source.clone()).await,
        Err("message withdrawn".into())
    );
    sqlx::raw_sql("DROP TRIGGER fail_withdraw")
        .execute(db.pool())
        .await
        .unwrap();
    assert_eq!(
        konsensus_api::calls::withdraw_held(db.as_ref(), true)
            .await
            .unwrap(),
        1
    );
    hidden(env.clone()).await;

    // The release fails: an admitted chat is withheld (hidden), never ACKed.
    sqlx::raw_sql("CREATE TRIGGER fail_release BEFORE DELETE ON call_admission_hold BEGIN SELECT RAISE(ABORT, 'disk fault'); END").execute(db.pool()).await.unwrap();
    let env = chat(room_chat(&room, "withheld")).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Err("storage error".into()));
    hidden(env.clone()).await;
    assert!(ws_rx.try_recv().is_err());
    sqlx::raw_sql("DROP TRIGGER fail_release")
        .execute(db.pool())
        .await
        .unwrap();
    shutdown.send(true).unwrap();
    worker.await.unwrap();
    source.shutdown();
    target.shutdown();
}

#[tokio::test]
async fn porch_wire_manifest_matches_discounted_gate_price() {
    let dir = tempfile::tempdir().unwrap();
    let content = ContentServer::new(crate::content_server::ContentServerConfig {
        content_dir: dir.path().to_path_buf(),
        max_file_size: 4096,
        cache_seconds: 60,
        site_name: "Porch".into(),
    })
    .unwrap();
    let gate = PaymentGate::with_config(konsensus_core::gate::GateConfig {
        min_admission_cost_msat: 2000,
        ..Default::default()
    });
    for (base, expected) in [(1000, 2000), (5000, 2500)] {
        let pricing =
            konsensus_pricing::StaticPricingEngine::new(konsensus_pricing::StaticPricingConfig {
                web_content_msat: base,
                ..Default::default()
            });
        let manifest = priced_manifest(&content, 1, &pricing, &gate, 0.5)
            .await
            .unwrap();
        assert_eq!(manifest.default_price_msat, expected);
    }
}

#[tokio::test]
async fn porch_card_repricing_failure_returns_correlated_error() {
    use konsensus_core::front_door::{FrontDoorCard, FrontDoorFields};
    let bob = bob_identity();
    let dir = tempfile::tempdir().unwrap();
    let store = konsensus_api::handlers::front_door::FrontDoorStore::load(
        Some(dir.path()),
        None,
        &bob.node_id().to_hex(),
    );
    let fields: FrontDoorFields = serde_json::from_value(serde_json::json!({
        "network": "regtest", "endpoint": "node.example.org:9000",
        "seq": 1, "issued_at": 1000,
        "prices": {"admission_msat": 1000, "message_msat": 1000,
                   "page_msat": 500, "price_epoch": 0},
        "profile": {"kind": "person", "display_name": "Legacy"}
    }))
    .unwrap();
    *store.card.lock().await = Some(FrontDoorCard::issue(&bob, fields).unwrap());
    // A directory at the atomic temporary-file path makes saving fail on any OS.
    std::fs::create_dir(dir.path().join("front-door.json.tmp")).unwrap();
    let pricing = konsensus_pricing::StaticPricingEngine::new(Default::default());
    let response = priced_card_response(
        "paid-request",
        &store,
        &bob,
        &pricing,
        &PaymentGate::new(),
        &konsensus_chain::MockChainProvider::new(),
        1001,
    )
    .await;
    assert_eq!(response.request_id, "paid-request");
    assert_eq!(
        response.status,
        konsensus_core::payloads::content::PageStatus::InternalError
    );
    assert_eq!(response.cache_seconds, 0);
    assert!(
        !response.body.contains("page_msat"),
        "never serve the stale price"
    );
}

// ── Honest receipts: refuse what cannot be read or kept ─────────────

/// Bob's live receive loop (`run`) behind a PriceOpen Noise transport, an
/// in-memory SQLite store and a mock wallet, with Alice connected and holding
/// an E2EE session with Bob (`sessions_a` with Bob's manager).
struct ReceiveLoop {
    alice: Arc<NodeIdentity>,
    bob: Arc<NodeIdentity>,
    source: Arc<NoiseTransport>,
    target: Arc<NoiseTransport>,
    db: Arc<konsensus_storage::SqliteStorage>,
    wallet: Arc<konsensus_lightning::MockLightningProvider>,
    sessions_a: SessionManager,
    sessions_b: Arc<SessionManager>,
    audit_path: std::path::PathBuf,
    ws_rx: broadcast::Receiver<Arc<WsMessage>>,
    shutdown: watch::Sender<bool>,
    worker: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

async fn receive_loop() -> ReceiveLoop {
    receive_loop_ordered(false).await
}

async fn receive_loop_ordered(lower_sender: bool) -> ReceiveLoop {
    use konsensus_message::{ControlEvent, ReachabilityMode, TransportConfig};
    let dir = tempfile::tempdir().unwrap();
    let alice = alice_identity();
    let bob = bob_identity();
    let (alice, bob) = if lower_sender && alice.node_id().as_bytes() > bob.node_id().as_bytes() { (bob, alice) } else { (alice, bob) };
    let transport = |id| {
        Arc::new(NoiseTransport::new(
            id,
            TransportConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                admission_mode: ReachabilityMode::PriceOpen,
                ..Default::default()
            },
        ))
    };
    let source = transport(alice.clone());
    let target = transport(bob.clone());
    target.start_listener().await.unwrap();
    let db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let storage: Arc<dyn Storage> = db.clone();
    source
        .connect(bob.node_id(), &target.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    assert!(matches!(
        source.recv_control().await.unwrap(),
        ControlEvent::PeerConnected { .. }
    ));
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let sessions_a = SessionManager::new(alice.clone());
    let sessions_b = Arc::new(SessionManager::new(bob.clone()));
    establish_sessions(&sessions_a, &sessions_b, &alice, &bob).await;
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditLog::open(&audit_path).unwrap());
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (ws_tx, ws_rx) = broadcast::channel(8);
    let worker = tokio::spawn(run(MsgHandlerDeps {
        transport: target.clone(),
        transport_ack: target.clone(),
        storage: storage.clone(),
        gate: Arc::new(PaymentGate::with_config(konsensus_core::gate::GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        })),
        pricing: Arc::new(MutableDeliveryPrice(std::sync::atomic::AtomicU64::new(
            1_000,
        ))),
        lightning: wallet.clone(),
        chain: Arc::new(konsensus_chain::MockChainProvider::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        session_manager: sessions_b.clone(),
        nonce_adapter: Arc::new(konsensus_storage::StorageNonceAdapter::new(storage)),
        content_server: None,
        front_door: Default::default(),
        routing: Arc::new(RoutingTable::new(Default::default())),
        identity: bob.clone(),
        plaintext_cipher: Arc::new(PlaintextCacheCipher::new(bob.aes_key())),
        ws_tx,
        audit_log: audit,
        admission_mode: ReachabilityMode::PriceOpen,
        relay_engine: None,
        shutdown_rx,
    }));
    ReceiveLoop {
        alice,
        bob,
        source,
        target,
        db,
        wallet,
        sessions_a,
        sessions_b,
        audit_path,
        ws_rx,
        shutdown,
        worker,
        _dir: dir,
    }
}

impl ReceiveLoop {
    /// A signed envelope from Alice to Bob paid with a fresh settled keysend.
    async fn paid_envelope(&self, kind: u16, ciphertext: Vec<u8>) -> konsensus_core::UkmEnvelope {
        let hash = self.wallet.inject_inbound_keysend(1_000, None).await;
        let payment = self.wallet.get_payment_status(&hash).await.unwrap();
        let proof = PaymentProof::new(
            hex::decode(&hash).unwrap().try_into().unwrap(),
            hex::decode(payment.preimage.unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            1_000,
        );
        let mut env = UkmEnvelopeBuilder::new(
            kind,
            *self.alice.node_id(),
            Recipient::Node(*self.bob.node_id()),
            ciphertext,
            proof,
        )
        .build();
        env.signature = Signature::from_ed25519(&self.alice.sign(&env.signable_bytes()));
        env
    }

    /// Alice's ciphertext for Bob under their session.
    async fn ciphertext(&self, plaintext: &[u8]) -> Vec<u8> {
        konsensus_crypto::ratchet_message_to_bytes(
            &self
                .sessions_a
                .encrypt(self.bob.node_id(), plaintext)
                .await
                .unwrap(),
        )
    }

    /// Send `env` and return Bob's delivery verdict: an ACK or a reject.
    async fn verdict(&self, env: &konsensus_core::UkmEnvelope) -> konsensus_message::ControlEvent {
        use konsensus_message::ControlEvent;
        self.source.send(self.bob.node_id(), env).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                // Prekey offers and the like are not delivery verdicts.
                if let event @ (ControlEvent::MessageAcked { .. }
                | ControlEvent::MessageRejected { .. }) =
                    self.source.recv_control().await.unwrap()
                {
                    break event;
                }
            }
        })
        .await
        .expect("Bob answers every paid envelope")
    }

    /// The receipt state Bob keeps for `env`'s payment: 1 accepted, -1
    /// application-rejected (the payment stays burned), None unknown.
    async fn receipt_state(&self, env: &konsensus_core::UkmEnvelope) -> Option<i32> {
        sqlx::query_scalar("SELECT accepted FROM payment_receipts WHERE message_id = ?")
            .bind(env.id.to_hex())
            .fetch_optional(self.db.pool())
            .await
            .unwrap()
    }

    fn audit_log(&self) -> String {
        std::fs::read_to_string(&self.audit_path).unwrap_or_default()
    }

    async fn stop(self) {
        self.shutdown.send(true).unwrap();
        self.worker.await.unwrap();
        self.source.shutdown();
        self.target.shutdown();
    }
}

fn file_payload(filename: &str, sent: &[u8], received: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "filename": filename,
        "mime_type": "application/octet-stream",
        "size_bytes": received.len(),
        "blake3_hash": blake3::hash(sent).to_hex().to_string(),
        "data_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, received),
    }))
    .unwrap()
}

/// Alice's paid chat under a session Bob does not hold, stamped `offset_ms` from now.
async fn unreadable_chat_stamped(net: &ReceiveLoop, offset_ms: i64) -> konsensus_core::UkmEnvelope {
    let stale_a = SessionManager::new(net.alice.clone());
    let stale_b = SessionManager::new(net.bob.clone());
    establish_sessions(&stale_a, &stale_b, &net.alice, &net.bob).await;
    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(
        &stale_a.encrypt(net.bob.node_id(), b"unreadable").await.unwrap(),
    );
    let mut env = net.paid_envelope(konsensus_core::kind::KIND_CHAT, ciphertext).await;
    env.timestamp = env.timestamp.saturating_add_signed(offset_ms);
    env.signature = Signature::from_ed25519(&net.alice.sign(&env.signable_bytes()));
    env
}

/// An envelope from before Bob's session, or stamped just after it (still in
/// flight when Alice took the new session, or her clock ahead), was encrypted
/// under an earlier one. It is refused like any unreadable one and Bob's working
/// session stays: no duplicate of either envelope reaches the decrypt, and the
/// next message reads fine.
#[tokio::test]
async fn envelope_from_before_the_session_settled_does_not_remove_it() {
    use konsensus_message::ControlEvent;
    let mut net = receive_loop().await;
    for offset_ms in [-60_000, 0, 5_000] {
        let env = unreadable_chat_stamped(&net, offset_ms).await;
        let verdict = net.verdict(&env).await;
        assert!(
            matches!(&verdict, ControlEvent::MessageRejected { message_id, reason, .. }
                if *message_id == env.id && reason.starts_with("session_handover:")),
            "{offset_ms}: got {verdict:?}"
        );
        assert!(net.sessions_b.has_session(net.alice.node_id()).await, "{offset_ms}: the session stays");
        assert!(!net.sessions_b.needs_renegotiation(net.alice.node_id()).await, "{offset_ms}: and no renegotiation");
        // The same bytes again retain their durable recovery deferral.
        let again = net.verdict(&env).await;
        assert!(matches!(&again, ControlEvent::MessageRejected { reason, .. } if reason.starts_with("session_handover:")), "got {again:?}");
        assert!(net.sessions_b.has_session(net.alice.node_id()).await);
    }

    let ciphertext = net.ciphertext(b"still readable").await;
    let next = net.paid_envelope(konsensus_core::kind::KIND_CHAT, ciphertext).await;
    let verdict = net.verdict(&next).await;
    assert!(matches!(verdict, ControlEvent::MessageAcked { message_id, .. } if message_id == next.id), "got {verdict:?}");
    let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), net.ws_rx.recv()).await.unwrap().unwrap();
    assert_eq!(delivered.plaintext.as_deref(), Some("still readable"));
    // A duplicate of a read envelope is acknowledged again without a decrypt; its
    // message key is spent, so reaching the decrypt would fail.
    let verdict = net.verdict(&next).await;
    assert!(matches!(verdict, ControlEvent::MessageAcked { message_id, duplicate: true, .. } if message_id == next.id), "got {verdict:?}");
    assert!(net.sessions_b.has_session(net.alice.node_id()).await, "a duplicate costs no session");
    net.stop().await;
}

/// An envelope stamped well after the session was derived and still unreadable
/// may mean the two sides disagree. Bob asks for a replacement and keeps the session
/// in use until one is confirmed: Alice's next message still reads.
#[tokio::test]
async fn unreadable_envelope_after_the_session_settled_keeps_it_and_offers() {
    use konsensus_message::ControlEvent;
    let net = receive_loop().await;
    let env = unreadable_chat_stamped(&net, 11_000).await;

    net.source.send(net.bob.node_id(), &env).await.unwrap();
    let mut offered = false;
    let rejected = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match net.source.recv_control().await.unwrap() {
                ControlEvent::PrekeyOffer { .. } => offered = true,
                ControlEvent::MessageRejected { .. } => break true,
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    assert!(rejected && offered, "refused, after offering");
    assert!(net.sessions_b.has_session(net.alice.node_id()).await, "the session stays");
    assert!(net.sessions_b.needs_renegotiation(net.alice.node_id()).await);

    let ciphertext = net.ciphertext(b"still readable").await;
    let next = net.paid_envelope(konsensus_core::kind::KIND_CHAT, ciphertext).await;
    let verdict = net.verdict(&next).await;
    assert!(matches!(verdict, ControlEvent::MessageAcked { message_id, .. } if message_id == next.id), "got {verdict:?}");
    net.stop().await;
}

/// A session restored from storage has no known age. An unreadable envelope still
/// does not cost it, and the peer's next message reads under it.
#[tokio::test]
async fn restored_session_survives_an_unreadable_envelope() {
    #[derive(Default)]
    struct Memory(std::sync::Mutex<std::collections::HashMap<NodeId, Vec<u8>>>);
    #[async_trait::async_trait]
    impl konsensus_crypto::SessionStore for Memory {
        async fn save_session(&self, peer: &NodeId, state: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.0.lock().unwrap().insert(*peer, state.to_vec());
            Ok(())
        }
        async fn load_session(&self, peer: &NodeId) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.0.lock().unwrap().get(peer).cloned())
        }
        async fn delete_session(&self, peer: &NodeId) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.0.lock().unwrap().remove(peer);
            Ok(())
        }
        async fn list_sessions(&self) -> Result<Vec<NodeId>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.0.lock().unwrap().keys().copied().collect())
        }
    }
    let alice = alice_identity();
    let bob = bob_identity();
    let store = Arc::new(Memory::default());
    let alice_mgr = SessionManager::new(Arc::clone(&alice));
    let live = SessionManager::with_store(Arc::clone(&bob), store.clone());
    establish_sessions(&alice_mgr, &live, &alice, &bob).await;
    let bob_mgr = SessionManager::with_store(Arc::clone(&bob), store.clone());
    assert_eq!(bob_mgr.restore_sessions().await, 1);

    let foreign_a = SessionManager::new(Arc::clone(&alice));
    let foreign_b = SessionManager::new(Arc::clone(&bob));
    establish_sessions(&foreign_a, &foreign_b, &alice, &bob).await;
    let unreadable = foreign_a.encrypt(bob.node_id(), b"unreadable").await.unwrap();
    let mut envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_CHAT,
        konsensus_crypto::ratchet_message_to_bytes(&unreadable),
    );
    envelope.timestamp = 1;
    let storage: Arc<dyn Storage> = Arc::new(TestStorage::new());
    let result = decrypt_and_process(
        &envelope,
        alice.node_id(),
        &bob_mgr,
        &PlaintextCacheCipher::new(bob.aes_key()),
        &storage,
        &None,
        &Default::default(),
        &(Arc::new(konsensus_chain::MockChainProvider::new()) as Arc<dyn ChainProvider>),
        &(Arc::new(konsensus_pricing::StaticPricingEngine::new(
            Default::default(),
        )) as Arc<dyn konsensus_core::traits::pricing::PricingEngine>),
        &bob,
        &make_transport(&bob),
        &make_audit_log(),
        &PaymentGate::new(),
        0.0,
        true,
        None,
    )
    .await;
    assert!(matches!(result, Err(ReceiptRefusal::Undecryptable(_))));
    assert!(bob_mgr.has_session(alice.node_id()).await, "the restored session stays");
    assert!(store.0.lock().unwrap().contains_key(alice.node_id()), "and stays on disk");
    let readable = alice_mgr.encrypt(bob.node_id(), b"still readable").await.unwrap();
    assert_eq!(bob_mgr.decrypt(alice.node_id(), &readable).await.unwrap(), b"still readable");
}

/// A restart's sequence for a block already in flight. The block passes its preview
/// under the old session, a re-key completes, and the real decrypt then fails. The
/// grant stands in the caller of this function; here the new session must survive.
#[tokio::test]
async fn block_stale_at_its_real_decrypt_does_not_cost_the_new_session() {
    let alice = alice_identity();
    let bob = bob_identity();
    let alice_mgr = SessionManager::new(Arc::clone(&alice));
    let bob_mgr = SessionManager::new(Arc::clone(&bob));
    // Bob initiates and Alice accepts, the shape where Bob could not recover alone.
    establish_sessions(&bob_mgr, &alice_mgr, &bob, &alice).await;
    assert!(bob_mgr.confirm_session(alice.node_id()).await);
    let first = bob_mgr.encrypt(alice.node_id(), b"ratchet-init").await.unwrap();
    alice_mgr.decrypt(bob.node_id(), &first).await.unwrap();

    let block = alice_mgr.encrypt(bob.node_id(), b"{}").await.unwrap();
    let envelope = make_envelope(
        alice.as_ref(),
        *bob.node_id(),
        konsensus_core::kind::KIND_CALL_BLOCK,
        konsensus_crypto::ratchet_message_to_bytes(&block),
    );
    assert_eq!(bob_mgr.preview_decrypt(alice.node_id(), &block).await.unwrap(), b"{}");

    // The session before is gone, so nothing Bob holds can read the block.
    assert!(bob_mgr.remove_session(alice.node_id()).await);
    let init = bob_mgr.reinitiate_session(alice.node_id(), &alice_mgr.prekey_bundle().await).await.unwrap();
    alice_mgr.reaccept_session(bob.node_id(), &init).await.unwrap();
    assert!(bob_mgr.confirm_session(alice.node_id()).await);
    let again = bob_mgr.encrypt(alice.node_id(), b"ratchet-init").await.unwrap();
    alice_mgr.decrypt(bob.node_id(), &again).await.unwrap();

    let storage: Arc<dyn Storage> = Arc::new(TestStorage::new());
    for preview in [None, Some(b"{}".to_vec())] {
    let verified = preview.is_some();
    let result = decrypt_and_process(
        &envelope,
        alice.node_id(),
        &bob_mgr,
        &PlaintextCacheCipher::new(bob.aes_key()),
        &storage,
        &None,
        &Default::default(),
        &(Arc::new(konsensus_chain::MockChainProvider::new()) as Arc<dyn ChainProvider>),
        &(Arc::new(konsensus_pricing::StaticPricingEngine::new(
            Default::default(),
        )) as Arc<dyn konsensus_core::traits::pricing::PricingEngine>),
        &bob,
        &make_transport(&bob),
        &make_audit_log(),
        &PaymentGate::new(),
        0.0,
        false,
        preview,
    )
    .await;
    if verified { assert_eq!(result.unwrap(), Some("{}".into())); }
    else { assert!(matches!(result, Err(ReceiptRefusal::Undecryptable(_)))); }
    }
    assert!(!bob_mgr.needs_renegotiation(alice.node_id()).await, "stale, so no renegotiation");
    let next = alice_mgr.encrypt(bob.node_id(), b"next block").await.unwrap();
    assert_eq!(bob_mgr.decrypt(alice.node_id(), &next).await.unwrap(), b"next block");
}

/// A paid block Bob cannot read is refused before it consumes its proof. Unreadable
/// under the session he holds, he also asks for a replacement; past the skip limit,
/// which a later delivery can cure, he does not. Neither touches the session.
#[tokio::test]
async fn unreadable_block_asks_to_renegotiate_and_keeps_the_session() {
    use konsensus_message::ControlEvent;
    let net = receive_loop().await;
    let refused = |verdict: &ControlEvent, id| {
        matches!(verdict, ControlEvent::MessageRejected { message_id, .. } if *message_id == id)
    };

    // Past the ratchet's skip limit on the session Bob does hold.
    for _ in 0..1_001 {
        net.ciphertext(b"not delivered").await;
    }
    let ahead = net.ciphertext(b"{}").await;
    let env = net.paid_envelope(konsensus_core::kind::KIND_CALL_BLOCK, ahead).await;
    let verdict = net.verdict(&env).await;
    assert!(
        matches!(&verdict, ControlEvent::MessageRejected { reason, .. } if reason.starts_with("session_handover:")),
        "the retryable reason: {verdict:?}"
    );
    assert!(!net.sessions_b.needs_renegotiation(net.alice.node_id()).await);

    let stale_a = SessionManager::new(net.alice.clone());
    let stale_b = SessionManager::new(net.bob.clone());
    establish_sessions(&stale_a, &stale_b, &net.alice, &net.bob).await;
    let stale = konsensus_crypto::ratchet_message_to_bytes(
        &stale_a.encrypt(net.bob.node_id(), b"{}").await.unwrap(),
    );
    let mut env = net.paid_envelope(konsensus_core::kind::KIND_CALL_BLOCK, stale).await;
    env.timestamp += 11_000;
    env.signature = Signature::from_ed25519(&net.alice.sign(&env.signable_bytes()));
    let verdict = net.verdict(&env).await;
    assert!(refused(&verdict, env.id), "got {verdict:?}");
    assert!(net.sessions_b.needs_renegotiation(net.alice.node_id()).await);
    assert!(net.sessions_b.has_session(net.alice.node_id()).await, "preview refusals touch no session");
    net.stop().await;
}

/// Readability refusals leave the proof available for a recovery retry. The app
/// sees no message until the ciphertext can be read.
#[tokio::test]
async fn undecryptable_paid_chat_is_refused_not_acknowledged() {
    use konsensus_message::ControlEvent;
    let mut net = receive_loop().await;

    // Alice's ciphertext comes from a session Bob never had.
    let stale_a = SessionManager::new(net.alice.clone());
    let stale_b = SessionManager::new(net.bob.clone());
    establish_sessions(&stale_a, &stale_b, &net.alice, &net.bob).await;
    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(
        &stale_a
            .encrypt(net.bob.node_id(), b"unreadable")
            .await
            .unwrap(),
    );
    let mut env = net
        .paid_envelope(konsensus_core::kind::KIND_CHAT, ciphertext)
        .await;
    // Stamped past Bob's session settling, so the failure counts against it.
    env.timestamp += 11_000;
    env.signature = Signature::from_ed25519(&net.alice.sign(&env.signable_bytes()));

    let verdict = net.verdict(&env).await;
    assert!(
        matches!(&verdict, ControlEvent::MessageRejected { message_id, reason, .. }
            if *message_id == env.id && reason.starts_with("session_handover:")),
        "expected a typed reject, got {verdict:?}"
    );
    assert!(
        net.db.get_message(&env.id).await.unwrap().is_none(),
        "withdrawn from history"
    );
    assert!(net
        .db
        .get_message_plaintext(&env.id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        net.receipt_state(&env).await,
        None,
        "unreadable ciphertext must not consume the proof"
    );
    assert!(net.ws_rx.try_recv().is_err(), "the app never saw it");
    assert!(
        net.audit_log().contains("message.rejected"),
        "{}",
        net.audit_log()
    );
    assert!(
        net.sessions_b.has_session(net.alice.node_id()).await,
        "one unreadable envelope does not cost the session"
    );

    // A repeated attempt keeps the same retryable classification.
    let again = net.verdict(&env).await;
    assert!(
        matches!(&again, ControlEvent::MessageRejected { reason, .. } if reason.starts_with("session_handover:")),
        "a resend remains retryable: {again:?}"
    );
    assert!(net.ws_rx.try_recv().is_err());
    assert!(net.db.get_message(&env.id).await.unwrap().is_none());
    net.stop().await;
}

/// A received file that fails its integrity check is reported failed to the
/// app (never listed, never stored, audited) and to the sender (a typed
/// reject, never a delivered ACK); the session stays usable for the next file.
#[tokio::test]
async fn corrupted_file_is_failed_to_the_app_and_the_sender() {
    use konsensus_message::ControlEvent;
    let mut net = receive_loop().await;

    let damaged = net
        .ciphertext(&file_payload(
            "damaged.bin",
            b"the bytes that were sent",
            b"the bytes that arrived",
        ))
        .await;
    let env = net
        .paid_envelope(konsensus_core::kind::KIND_FILE_REF, damaged)
        .await;

    let verdict = net.verdict(&env).await;
    assert!(
        matches!(&verdict, ControlEvent::MessageRejected { message_id, reason, .. }
            if *message_id == env.id && reason == "file_corrupted: the file data does not match its hash"),
        "expected a typed reject, got {verdict:?}"
    );
    assert!(
        net.db.list_files(10).await.unwrap().is_empty(),
        "never stored"
    );
    assert!(
        net.db.get_message(&env.id).await.unwrap().is_none(),
        "never listed as received"
    );
    assert!(net
        .db
        .get_message_plaintext(&env.id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        net.receipt_state(&env).await,
        Some(-1),
        "the integrity refusal retains its receipt"
    );
    assert!(net.ws_rx.try_recv().is_err(), "the app never saw it arrive");
    let audit = net.audit_log();
    assert!(
        audit.contains("file.integrity_failed") && audit.contains("message.rejected"),
        "{audit}"
    );

    // An intact file after it is received as usual: the session was not harmed.
    let intact = net
        .ciphertext(&file_payload("intact.bin", b"intact", b"intact"))
        .await;
    let env = net
        .paid_envelope(konsensus_core::kind::KIND_FILE_REF, intact)
        .await;
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageAcked {
            duplicate: false,
            ..
        }
    ));
    assert_eq!(net.db.list_files(10).await.unwrap().len(), 1);
    assert_eq!(net.receipt_state(&env).await, Some(1));
    let shown = tokio::time::timeout(std::time::Duration::from_secs(5), net.ws_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(shown.plaintext.as_deref(), Some("[file: intact.bin]"));
    net.stop().await;
}

/// The admission-proof carve-out is the compose handler's exact shape: a
/// `KIND_CHAT` carrying the marker is acknowledged as received; the marker
/// under any other kind is an ordinary paid envelope and is refused like one,
/// never acknowledged, never published.
#[tokio::test]
async fn admission_proof_is_acknowledged_but_the_marker_under_another_kind_is_refused() {
    use konsensus_message::ControlEvent;
    let mut net = receive_loop().await;

    let proof = net
        .paid_envelope(
            konsensus_core::kind::KIND_CHAT,
            ADMISSION_ENVELOPE_MARKER.to_vec(),
        )
        .await;
    assert!(matches!(
        net.verdict(&proof).await,
        ControlEvent::MessageAcked {
            duplicate: false,
            ..
        }
    ));
    assert_eq!(net.receipt_state(&proof).await, Some(1));
    let published = tokio::time::timeout(std::time::Duration::from_secs(5), net.ws_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(published.envelope.id, proof.id);
    assert!(
        published.plaintext.is_none(),
        "a proof carries nothing to read"
    );

    let file = net
        .paid_envelope(
            konsensus_core::kind::KIND_FILE_REF,
            ADMISSION_ENVELOPE_MARKER.to_vec(),
        )
        .await;
    let verdict = net.verdict(&file).await;
    assert!(
        matches!(&verdict, ControlEvent::MessageRejected { message_id, reason, .. }
            if *message_id == file.id && reason.starts_with("session_handover:")),
        "the marker under another kind is no proof: {verdict:?}"
    );
    assert!(net.db.list_files(10).await.unwrap().is_empty());
    assert!(
        net.db.get_message(&file.id).await.unwrap().is_none(),
        "withdrawn"
    );
    assert_eq!(net.receipt_state(&file).await, None);
    assert!(net.ws_rx.try_recv().is_err(), "never published");
    net.stop().await;
}

/// A chat whose plaintext cannot be stored is refused, not acknowledged: the
/// envelope is withdrawn, the receipt stays burned as application-rejected,
/// the app sees nothing, and the session is unharmed for the next chat.
#[tokio::test]
async fn plaintext_store_failure_is_refused_not_acknowledged() {
    use konsensus_message::ControlEvent;
    let mut net = receive_loop().await;
    sqlx::query("CREATE TRIGGER fail_plaintext BEFORE UPDATE OF plaintext_enc ON messages BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
        .execute(net.db.pool())
        .await
        .unwrap();

    let env = net
        .paid_envelope(
            konsensus_core::kind::KIND_CHAT,
            net.ciphertext(b"cannot be kept").await,
        )
        .await;
    let verdict = net.verdict(&env).await;
    assert!(
        matches!(&verdict, ControlEvent::MessageRejected { message_id, reason, .. }
            if *message_id == env.id && reason == "not_persisted: the plaintext could not be stored"),
        "{verdict:?}"
    );
    assert!(
        net.db.get_message(&env.id).await.unwrap().is_none(),
        "withdrawn"
    );
    assert!(net
        .db
        .get_message_plaintext(&env.id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(net.receipt_state(&env).await, Some(-1));
    assert!(net.ws_rx.try_recv().is_err(), "the app never saw it");
    // The replay keys stay consumed: the same bytes are refused, not acknowledged.
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageRejected { reason, .. } if reason == "message withdrawn"
    ));
    assert!(net.ws_rx.try_recv().is_err());

    sqlx::query("DROP TRIGGER fail_plaintext")
        .execute(net.db.pool())
        .await
        .unwrap();
    let env = net
        .paid_envelope(
            konsensus_core::kind::KIND_CHAT,
            net.ciphertext(b"kept").await,
        )
        .await;
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageAcked {
            duplicate: false,
            ..
        }
    ));
    let shown = tokio::time::timeout(std::time::Duration::from_secs(5), net.ws_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(shown.plaintext.as_deref(), Some("kept"));
    net.stop().await;
}

/// A file that cannot be stored is refused, not acknowledged, and never
/// surfaced as received.
#[tokio::test]
async fn file_store_failure_is_refused_not_acknowledged() {
    use konsensus_message::ControlEvent;
    let mut net = receive_loop().await;
    sqlx::query("CREATE TRIGGER fail_file BEFORE INSERT ON files BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
        .execute(net.db.pool())
        .await
        .unwrap();

    let intact = net
        .ciphertext(&file_payload("intact.bin", b"intact", b"intact"))
        .await;
    let env = net
        .paid_envelope(konsensus_core::kind::KIND_FILE_REF, intact)
        .await;
    let verdict = net.verdict(&env).await;
    assert!(
        matches!(&verdict, ControlEvent::MessageRejected { message_id, reason, .. }
            if *message_id == env.id && reason == "not_persisted: the file could not be stored"),
        "{verdict:?}"
    );
    assert!(net.db.list_files(10).await.unwrap().is_empty());
    assert!(
        net.db.get_message(&env.id).await.unwrap().is_none(),
        "withdrawn"
    );
    assert!(net
        .db
        .get_message_plaintext(&env.id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(net.receipt_state(&env).await, Some(-1));
    assert!(net.ws_rx.try_recv().is_err(), "the app never saw it arrive");
    net.stop().await;
}

/// When even the withdrawal fails, the refused chat is still never
/// acknowledged or published: its admission hold keeps it hidden, a resend is
/// refused as withdrawn, and the sweep withdraws it later.
#[tokio::test]
async fn withdrawal_failure_still_refuses_and_keeps_the_chat_hidden() {
    use konsensus_message::ControlEvent;
    let mut net = receive_loop().await;
    sqlx::query("CREATE TRIGGER fail_plaintext BEFORE UPDATE OF plaintext_enc ON messages BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
        .execute(net.db.pool())
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER fail_withdraw BEFORE DELETE ON messages BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
        .execute(net.db.pool())
        .await
        .unwrap();

    let env = net
        .paid_envelope(
            konsensus_core::kind::KIND_CHAT,
            net.ciphertext(b"cannot be kept").await,
        )
        .await;
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageRejected { reason, .. } if reason == "not_persisted: the plaintext could not be stored"
    ));
    // The withdrawal rolled back whole: the row is still there, still held,
    // and the hold hides it from history.
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE id = ?")
        .bind(env.id.to_hex())
        .fetch_one(net.db.pool())
        .await
        .unwrap();
    assert_eq!(rows, 1, "the delete was rolled back");
    assert!(
        net.db.call_admission_held(&env.id).await.unwrap(),
        "the hold keeps it hidden"
    );
    assert!(
        net.db.get_message(&env.id).await.unwrap().is_none(),
        "hidden from history"
    );
    assert_eq!(net.receipt_state(&env).await, Some(1));
    assert!(net.ws_rx.try_recv().is_err(), "the app never saw it");

    // A resend is refused as withdrawn, never acknowledged as a duplicate.
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageRejected { reason, .. } if reason == "message withdrawn"
    ));
    assert!(net.ws_rx.try_recv().is_err());

    // The sweep finishes the withdrawal once the store recovers.
    sqlx::query("DROP TRIGGER fail_withdraw")
        .execute(net.db.pool())
        .await
        .unwrap();
    assert_eq!(net.db.call_admission_withdraw(u64::MAX).await.unwrap(), 1);
    assert!(net.db.get_message(&env.id).await.unwrap().is_none());
    assert_eq!(net.receipt_state(&env).await, Some(-1));
    net.stop().await;
}

/// A file is held until it is stored. When the file store and then the
/// withdrawal both fail, the hold keeps the envelope out of history and off
/// the duplicate-ACK path: a resend is refused as withdrawn, nothing is
/// published, and the sweep finishes the withdrawal.
#[tokio::test]
async fn file_withdrawal_failure_keeps_the_file_hidden_and_refuses_a_resend() {
    use konsensus_message::ControlEvent;
    let mut net = receive_loop().await;
    sqlx::query("CREATE TRIGGER fail_file BEFORE INSERT ON files BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
        .execute(net.db.pool())
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER fail_withdraw BEFORE DELETE ON messages BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
        .execute(net.db.pool())
        .await
        .unwrap();

    let intact = net
        .ciphertext(&file_payload("intact.bin", b"intact", b"intact"))
        .await;
    let env = net
        .paid_envelope(konsensus_core::kind::KIND_FILE_REF, intact)
        .await;
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageRejected { reason, .. } if reason == "not_persisted: the file could not be stored"
    ));
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE id = ?")
        .bind(env.id.to_hex())
        .fetch_one(net.db.pool())
        .await
        .unwrap();
    assert_eq!(rows, 1, "the delete was rolled back");
    assert!(
        net.db.call_admission_held(&env.id).await.unwrap(),
        "the hold keeps it hidden"
    );
    assert!(
        net.db.get_message(&env.id).await.unwrap().is_none(),
        "hidden from history"
    );
    assert!(net
        .db
        .get_message_plaintext(&env.id)
        .await
        .unwrap()
        .is_none());
    assert!(net.db.list_files(10).await.unwrap().is_empty());
    assert!(net.ws_rx.try_recv().is_err(), "the app never saw it arrive");

    // A resend is refused as withdrawn, never acknowledged as a duplicate.
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageRejected { reason, .. } if reason == "message withdrawn"
    ));
    assert!(net.ws_rx.try_recv().is_err());

    sqlx::query("DROP TRIGGER fail_withdraw")
        .execute(net.db.pool())
        .await
        .unwrap();
    assert_eq!(net.db.call_admission_withdraw(u64::MAX).await.unwrap(), 1);
    assert_eq!(net.receipt_state(&env).await, Some(-1));
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageRejected { reason, .. } if reason == "message withdrawn"
    ));
    assert!(net.ws_rx.try_recv().is_err());
    net.stop().await;
}

/// Every paid envelope is held until it is kept, whatever its kind. A
/// long-form message whose plaintext store and withdrawal both fail stays
/// hidden and unacknowledged; a resend is refused as withdrawn, the sweep
/// finishes the withdrawal, and a sound message of the same kind is received
/// and released as usual.
#[tokio::test]
async fn any_kind_withdrawal_failure_keeps_the_message_hidden_and_refuses_a_resend() {
    use konsensus_message::ControlEvent;
    let mut net = receive_loop().await;
    sqlx::query("CREATE TRIGGER fail_plaintext BEFORE UPDATE OF plaintext_enc ON messages BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
        .execute(net.db.pool())
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER fail_withdraw BEFORE DELETE ON messages BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
        .execute(net.db.pool())
        .await
        .unwrap();

    let env = net
        .paid_envelope(
            konsensus_core::kind::KIND_LONGFORM,
            net.ciphertext(b"a long one").await,
        )
        .await;
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageRejected { reason, .. } if reason == "not_persisted: the plaintext could not be stored"
    ));
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE id = ?")
        .bind(env.id.to_hex())
        .fetch_one(net.db.pool())
        .await
        .unwrap();
    assert_eq!(rows, 1, "the delete was rolled back");
    assert!(
        net.db.call_admission_held(&env.id).await.unwrap(),
        "the hold keeps it hidden"
    );
    assert!(
        net.db.get_message(&env.id).await.unwrap().is_none(),
        "hidden from history"
    );
    assert!(net
        .db
        .get_message_plaintext(&env.id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(net.receipt_state(&env).await, Some(1));
    assert!(net.ws_rx.try_recv().is_err(), "the app never saw it");

    // A resend is refused as withdrawn, never acknowledged as a duplicate.
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageRejected { reason, .. } if reason == "message withdrawn"
    ));
    assert!(net.ws_rx.try_recv().is_err());

    // The sweep finishes the withdrawal once the store recovers; the resend
    // is still refused, now from the rejected receipt.
    sqlx::query("DROP TRIGGER fail_withdraw")
        .execute(net.db.pool())
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER fail_plaintext")
        .execute(net.db.pool())
        .await
        .unwrap();
    assert_eq!(net.db.call_admission_withdraw(u64::MAX).await.unwrap(), 1);
    assert_eq!(net.receipt_state(&env).await, Some(-1));
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageRejected { reason, .. } if reason == "message withdrawn"
    ));
    assert!(net.ws_rx.try_recv().is_err());

    // A sound message of the same kind is received, released and published.
    let env = net
        .paid_envelope(
            konsensus_core::kind::KIND_LONGFORM,
            net.ciphertext(b"another long one").await,
        )
        .await;
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageAcked {
            duplicate: false,
            ..
        }
    ));
    assert!(
        !net.db.call_admission_held(&env.id).await.unwrap(),
        "released once kept"
    );
    assert_eq!(
        net.db.get_message(&env.id).await.unwrap().map(|m| m.id),
        Some(env.id)
    );
    let shown = tokio::time::timeout(std::time::Duration::from_secs(5), net.ws_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(shown.plaintext.as_deref(), Some("another long one"));
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageAcked {
            duplicate: true,
            ..
        }
    ));
    net.stop().await;
}

/// A corrupted file whose withdrawal also fails stays hidden and
/// unacknowledged; a resend is refused as withdrawn.
#[tokio::test]
async fn corrupted_file_with_failed_withdrawal_stays_hidden() {
    use konsensus_message::ControlEvent;
    let mut net = receive_loop().await;
    sqlx::query("CREATE TRIGGER fail_withdraw BEFORE DELETE ON messages BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
        .execute(net.db.pool())
        .await
        .unwrap();

    let damaged = net
        .ciphertext(&file_payload("damaged.bin", b"sent", b"arrived"))
        .await;
    let env = net
        .paid_envelope(konsensus_core::kind::KIND_FILE_REF, damaged)
        .await;
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageRejected { reason, .. } if reason == "file_corrupted: the file data does not match its hash"
    ));
    assert!(
        net.db.call_admission_held(&env.id).await.unwrap(),
        "the hold keeps it hidden"
    );
    assert!(net.db.get_message(&env.id).await.unwrap().is_none());
    assert!(net
        .db
        .get_message_plaintext(&env.id)
        .await
        .unwrap()
        .is_none());
    assert!(net.db.list_files(10).await.unwrap().is_empty());
    assert!(net.ws_rx.try_recv().is_err(), "the app never saw it arrive");
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageRejected { reason, .. } if reason == "message withdrawn"
    ));
    assert!(net.ws_rx.try_recv().is_err());
    sqlx::query("DROP TRIGGER fail_withdraw")
        .execute(net.db.pool())
        .await
        .unwrap();
    assert_eq!(net.db.call_admission_withdraw(u64::MAX).await.unwrap(), 1);
    assert_eq!(net.receipt_state(&env).await, Some(-1));
    net.stop().await;
}

/// A hold inherited from an earlier attempt (its paid acceptance rolled back
/// and its hold cleanup failed) is released before the successful retry is
/// published and acknowledged, so the acknowledged message is never hidden
/// and the sweep leaves it alone. Checked for a chat and for a long-form
/// message, the two release paths.
#[tokio::test]
async fn inherited_hold_is_released_before_a_retry_is_acknowledged() {
    use konsensus_message::ControlEvent;
    for kind in [
        konsensus_core::kind::KIND_CHAT,
        konsensus_core::kind::KIND_LONGFORM,
    ] {
        let mut net = receive_loop().await;
        sqlx::query("CREATE TRIGGER fail_message BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
            .execute(net.db.pool())
            .await
            .unwrap();
        sqlx::query("CREATE TRIGGER fail_release BEFORE DELETE ON call_admission_hold BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
            .execute(net.db.pool())
            .await
            .unwrap();

        let env = net
            .paid_envelope(kind, net.ciphertext(b"retried").await)
            .await;
        assert!(matches!(
            net.verdict(&env).await,
            ControlEvent::MessageRejected { reason, .. } if reason == "storage error"
        ));
        assert!(
            net.db.call_admission_held(&env.id).await.unwrap(),
            "the hold outlived the failed attempt"
        );
        assert!(net.ws_rx.try_recv().is_err());

        // The store recovers; the sender retries the same bytes.
        sqlx::query("DROP TRIGGER fail_message")
            .execute(net.db.pool())
            .await
            .unwrap();
        sqlx::query("DROP TRIGGER fail_release")
            .execute(net.db.pool())
            .await
            .unwrap();
        assert!(matches!(
            net.verdict(&env).await,
            ControlEvent::MessageAcked {
                duplicate: false,
                ..
            }
        ));
        assert!(
            !net.db.call_admission_held(&env.id).await.unwrap(),
            "kind {kind}: released before the ACK"
        );
        let shown = tokio::time::timeout(std::time::Duration::from_secs(5), net.ws_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(shown.plaintext.as_deref(), Some("retried"));
        assert_eq!(
            net.db.get_message(&env.id).await.unwrap().map(|m| m.id),
            Some(env.id),
            "visible in history"
        );
        assert_eq!(
            net.db.call_admission_withdraw(u64::MAX).await.unwrap(),
            0,
            "nothing for the sweep"
        );
        assert_eq!(net.receipt_state(&env).await, Some(1));
        assert!(
            net.db.get_message(&env.id).await.unwrap().is_some(),
            "kept after the sweep"
        );
        assert!(matches!(
            net.verdict(&env).await,
            ControlEvent::MessageAcked {
                duplicate: true,
                ..
            }
        ));
        net.stop().await;
    }
}

/// A web reply whose send chain could not be saved does not leave. It costs no
/// session, and the next reply reads at the requester with no gap.
#[tokio::test]
async fn reply_is_not_sent_when_its_save_fails() {
    use crate::flaky_session_store::FlakySessionStore;
    use konsensus_core::traits::transport::MessageTransport;
    let net = receive_loop().await;
    let store = Arc::new(FlakySessionStore::default());
    let replier = SessionManager::with_store(net.bob.clone(), store.clone());
    let requester = SessionManager::new(net.alice.clone());
    establish_sessions(&replier, &requester, &net.bob, &net.alice).await;
    let request = net.paid_envelope(konsensus_core::kind::KIND_PAGE_REQUEST, vec![1]).await;
    let reply = |text: &'static str| {
        let (replier, target, bob, alice, request) = (&replier, &net.target, &net.bob, &net.alice, &request);
        async move {
            send_encrypted_response(alice.node_id(), request, &text, konsensus_core::kind::KIND_PAGE_RESPONSE, bob, replier, target).await;
        }
    };

    store.fail(true);
    reply("withheld").await;
    let nothing = tokio::time::timeout(std::time::Duration::from_millis(500), net.source.recv()).await;
    assert!(nothing.is_err(), "nothing left for a failed save");
    assert!(replier.has_session(net.alice.node_id()).await);

    store.fail(false);
    reply("sent").await;
    let envelope = tokio::time::timeout(std::time::Duration::from_secs(5), net.source.recv()).await.unwrap().unwrap();
    let message = konsensus_crypto::ratchet_message_from_bytes(&envelope.ciphertext).unwrap();
    assert_eq!(message.header.message_number, 0, "the withheld reply left no gap");
    assert_eq!(requester.decrypt(net.bob.node_id(), &message).await.unwrap(), b"\"sent\"");
    net.stop().await;
}

/// A chain source whose tip cannot be read.
struct TipDown;

#[async_trait::async_trait]
impl ChainProvider for TipDown {
    fn trust_level(&self) -> konsensus_core::traits::chain::TrustLevel {
        konsensus_core::traits::chain::TrustLevel::FullValidation
    }
    async fn get_block_height(&self) -> Result<u64, konsensus_core::traits::chain::ChainError> {
        Err(konsensus_core::traits::chain::ChainError::Connection("down".into()))
    }
    async fn get_block_header(
        &self,
        _height: u64,
    ) -> Result<konsensus_core::traits::chain::BlockHeader, konsensus_core::traits::chain::ChainError>
    {
        Err(konsensus_core::traits::chain::ChainError::Connection("down".into()))
    }
    async fn estimate_fee(
        &self,
        _target_blocks: u32,
    ) -> Result<konsensus_core::traits::chain::FeeEstimate, konsensus_core::traits::chain::ChainError>
    {
        Err(konsensus_core::traits::chain::ChainError::Connection("down".into()))
    }
    async fn is_tx_confirmed(
        &self,
        _txid: &str,
        _min_confirmations: u32,
    ) -> Result<bool, konsensus_core::traits::chain::ChainError> {
        Err(konsensus_core::traits::chain::ChainError::Connection("down".into()))
    }
    async fn is_synced(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn web_manifest_is_not_sent_without_a_chain_tip() {
    let net = receive_loop().await;
    let site = tempfile::tempdir().unwrap();
    std::fs::write(site.path().join("index.md"), "# Home\n").unwrap();
    let content = Some(Arc::new(
        ContentServer::new(crate::content_server::ContentServerConfig {
            content_dir: site.path().to_path_buf(),
            max_file_size: 4 * 1024 * 1024,
            cache_seconds: 3600,
            site_name: "Test Node".to_string(),
        })
        .unwrap(),
    ));
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> = Arc::new(
        konsensus_pricing::StaticPricingEngine::new(Default::default()),
    );
    let request = net
        .paid_envelope(konsensus_core::kind::KIND_WEB_MANIFEST, vec![1])
        .await;
    // A session the replier can send on (it initiated it).
    let replier = SessionManager::new(net.bob.clone());
    let requester = SessionManager::new(net.alice.clone());
    establish_sessions(&replier, &requester, &net.bob, &net.alice).await;

    let down: Arc<dyn ChainProvider> = Arc::new(TipDown);
    let served = process_web_manifest(
        net.alice.node_id(), &request, &content, &down, &pricing, &net.bob,
        &replier, &net.target, &PaymentGate::new(), 0.0,
    )
    .await;
    assert_eq!(served, None);
    let nothing = tokio::time::timeout(std::time::Duration::from_millis(500), net.source.recv()).await;
    assert!(nothing.is_err(), "no manifest anchored to a made-up height");

    let up: Arc<dyn ChainProvider> = Arc::new(konsensus_chain::MockChainProvider::new());
    let served = process_web_manifest(
        net.alice.node_id(), &request, &content, &up, &pricing, &net.bob,
        &replier, &net.target, &PaymentGate::new(), 0.0,
    )
    .await;
    assert_eq!(served, Some("[web manifest request]".to_string()));
    let envelope = tokio::time::timeout(std::time::Duration::from_secs(5), net.source.recv())
        .await
        .unwrap()
        .unwrap();
    let message = konsensus_crypto::ratchet_message_from_bytes(&envelope.ciphertext).unwrap();
    let plaintext = requester.decrypt(net.bob.node_id(), &message).await.unwrap();
    let manifest: konsensus_core::payloads::content::WebManifest =
        serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(manifest.block_height, 886_000);
    assert_eq!(manifest.pages.len(), 1);
    net.stop().await;
}

/// A paid envelope may arrive before its SessionInit. Its proof remains available
/// and a retry is delivered once the responder receives the handover.
#[tokio::test]
async fn recovery_handover_paid_chat_retries_after_session_init() {
    use konsensus_message::ControlEvent;
    let net = receive_loop().await;
    let fresh = SessionManager::new(net.alice.clone());
    let init = fresh.initiate_session(net.bob.node_id(), &net.sessions_b.prekey_bundle().await).await.unwrap();
    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(&fresh.encrypt(net.bob.node_id(), b"handover retry").await.unwrap());
    let env = net.paid_envelope(konsensus_core::kind::KIND_CHAT, ciphertext).await;
    for _ in 0..2 {
        let verdict = net.verdict(&env).await;
        assert!(matches!(&verdict, ControlEvent::MessageRejected { reason, .. } if reason.starts_with("session_handover:")), "{verdict:?}");
        assert_eq!(net.receipt_state(&env).await, None);
        assert!(net.db.get_message(&env.id).await.unwrap().is_none());
    }
    net.sessions_b.reaccept_session(net.alice.node_id(), &init).await.unwrap();
    let again = net.verdict(&env).await;
    assert!(matches!(&again, ControlEvent::MessageRejected { reason, .. } if reason.starts_with("session_handover:")), "{again:?}");
    let mut replacement = env.clone();
    replacement.ciphertext = konsensus_crypto::ratchet_message_to_bytes(&fresh.encrypt(net.bob.node_id(), b"handover retry").await.unwrap());
    replacement.id = konsensus_core::MessageId::compute(&replacement.ciphertext, &replacement.nonce);
    replacement.signature = Signature::from_ed25519(&net.alice.sign(&replacement.signable_bytes()));
    let verdict = net.verdict(&replacement).await;
    assert!(matches!(verdict, ControlEvent::MessageAcked { .. }), "{verdict:?}");
    assert_eq!(net.receipt_state(&replacement).await, Some(1));
    assert!(net.db.get_message_plaintext(&replacement.id).await.unwrap().is_some());
    net.stop().await;
}

/// Omit the optional one-time prekey only so the test can reconstruct this
/// exact receiver session later. Real X3DH, encryption and the receive loop run.
async fn recovery_handover_session(net: &ReceiveLoop) -> konsensus_crypto::SerializableSessionInit {
    let mut bundle = net.sessions_b.prekey_bundle().await;
    bundle.one_time_prekey = None;
    bundle.one_time_prekey_id = None;
    let init = if net.sessions_a.has_session(net.bob.node_id()).await {
        net.sessions_a
            .reinitiate_session(net.bob.node_id(), &bundle)
            .await
            .unwrap()
    } else {
        net.sessions_a
            .initiate_session(net.bob.node_id(), &bundle)
            .await
            .unwrap()
    };
    net.sessions_b
        .reaccept_session(net.alice.node_id(), &init)
        .await
        .unwrap();
    assert!(net.sessions_a.confirm_session(net.bob.node_id()).await);
    init
}

fn recovery_handover_replacement(
    net: &ReceiveLoop,
    old: &konsensus_core::UkmEnvelope,
    ciphertext: Vec<u8>,
) -> konsensus_core::UkmEnvelope {
    let mut replacement = old.clone();
    replacement.ciphertext = ciphertext;
    replacement.id = MessageId::compute(&replacement.ciphertext, &replacement.nonce);
    replacement.timestamp = chrono::Utc::now().timestamp_millis() as u64;
    replacement.signature = Signature::from_ed25519(&net.alice.sign(&replacement.signable_bytes()));
    assert_ne!(replacement.id, old.id);
    assert_eq!(replacement.payment_proof, old.payment_proof);
    assert_eq!(replacement.nonce, old.nonce);
    replacement
}

async fn recovery_handover_expect_deferred(net: &ReceiveLoop, old: &konsensus_core::UkmEnvelope) {
    use konsensus_message::ControlEvent;
    let verdict = net.verdict(old).await;
    assert!(
        matches!(&verdict, ControlEvent::MessageRejected { message_id, reason, .. }
        if *message_id == old.id && reason.starts_with("session_handover:")),
        "{verdict:?}"
    );
    assert_eq!(
        net.receipt_state(old).await,
        None,
        "a deferral consumes no proof"
    );
    assert!(
        !net.db.has_nonce(&old.nonce).await.unwrap(),
        "a deferral consumes no nonce"
    );
    assert!(net.db.get_message(&old.id).await.unwrap().is_none());
}

#[tokio::test]
async fn recovery_handover_stale_high_counter_chat_reencrypts_without_repaying() {
    use konsensus_message::ControlEvent;
    let mut net = receive_loop_ordered(true).await;
    let old_init = recovery_handover_session(&net).await;
    let mut earlier = Vec::new();
    for _ in 0..1_001 {
        earlier.push(
            net.sessions_a
                .encrypt(net.bob.node_id(), b"earlier frame")
                .await
                .unwrap(),
        );
    }
    let text = b"paid chat survives a stale high counter";
    let old_message = net
        .sessions_a
        .encrypt(net.bob.node_id(), text)
        .await
        .unwrap();
    assert!(old_message.header.message_number > 1_000);
    let old = net
        .paid_envelope(
            konsensus_core::kind::KIND_CHAT,
            konsensus_crypto::ratchet_message_to_bytes(&old_message),
        )
        .await;

    // The receiver loses the old root and finishes recovery. A stale high
    // counter fails the skip bound before AEAD; earlier fresh-session frames
    // can never repair it.
    assert!(net.sessions_b.remove_session(net.alice.node_id()).await);
    let new_init = recovery_handover_session(&net).await;
    let ratchet_init = net
        .sessions_a
        .encrypt(net.bob.node_id(), b"ratchet-init")
        .await
        .unwrap();
    net.sessions_b
        .decrypt(net.alice.node_id(), &ratchet_init)
        .await
        .unwrap();
    assert!(matches!(
        net.sessions_b
            .preview_decrypt(net.alice.node_id(), &old_message)
            .await,
        Err(konsensus_crypto::SessionError::Ratchet(
            konsensus_crypto::RatchetError::TooManySkipped(..)
        ))
    ));
    recovery_handover_expect_deferred(&net, &old).await;
    assert!(net.ws_rx.try_recv().is_err());

    // Reconstruct the original root and deliver its missing prefix. Although
    // the old envelope is now readable, the durable deferral forbids it from
    // winning admission while its replacement is being prepared.
    assert!(net.sessions_b.remove_session(net.alice.node_id()).await);
    net.sessions_b
        .reaccept_session(net.alice.node_id(), &old_init)
        .await
        .unwrap();
    for frame in &earlier {
        net.sessions_b
            .decrypt(net.alice.node_id(), frame)
            .await
            .unwrap();
    }
    assert_eq!(
        net.sessions_b
            .preview_decrypt(net.alice.node_id(), &old_message)
            .await
            .unwrap(),
        text
    );
    recovery_handover_expect_deferred(&net, &old).await;
    assert!(net.ws_rx.try_recv().is_err());

    assert!(net.sessions_b.remove_session(net.alice.node_id()).await);
    net.sessions_b
        .reaccept_session(net.alice.node_id(), &new_init)
        .await
        .unwrap();
    net.sessions_b
        .decrypt(net.alice.node_id(), &ratchet_init)
        .await
        .unwrap();
    let replacement = recovery_handover_replacement(&net, &old, net.ciphertext(text).await);
    let verdict = net.verdict(&replacement).await;
    assert!(
        matches!(&verdict, ControlEvent::MessageAcked { message_id, duplicate: false, .. }
        if *message_id == replacement.id),
        "{verdict:?}"
    );
    let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), net.ws_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivered.envelope.id, replacement.id);
    assert_eq!(
        delivered.plaintext.as_deref(),
        Some(std::str::from_utf8(text).unwrap())
    );
    let verdict = net.verdict(&replacement).await;
    assert!(
        matches!(&verdict, ControlEvent::MessageAcked { message_id, duplicate: true, .. }
        if *message_id == replacement.id),
        "{verdict:?}"
    );
    assert!(
        matches!(net.verdict(&old).await,
        ControlEvent::MessageRejected { message_id, .. }
        if message_id == old.id),
        "the old identity remains deferred after the proof is accepted for its replacement"
    );
    assert!(net.ws_rx.try_recv().is_err(), "exactly one delivery");
    let receipts: Vec<(String, i32)> =
        sqlx::query_as("SELECT message_id, accepted FROM payment_receipts WHERE payment_hash = ?")
            .bind(hex::encode(old.payment_proof.payment_hash))
            .fetch_all(net.db.pool())
            .await
            .unwrap();
    assert_eq!(receipts, vec![(replacement.id.to_hex(), 1)]);
    assert!(net.db.has_nonce(&old.nonce).await.unwrap());
    net.stop().await;
}

#[tokio::test]
async fn recovery_handover_lower_id_block_keeps_one_grant_after_reencryption() {
    use konsensus_core::payloads::call as calls;
    use konsensus_message::ControlEvent;
    let mut net = receive_loop_ordered(true).await;
    assert!(net.alice.node_id().as_bytes() < net.bob.node_id().as_bytes());
    let old_init = recovery_handover_session(&net).await;
    let call_id = "9876543210abcdef9876543210abcdef";
    let text = serde_json::json!({"call_id":call_id,"seq":0}).to_string();
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let ringing = calls::receive(None, 400, None, now).unwrap();
    let initial = calls::commit(
        calls::reserve(Some(ringing), 401, "answer", "request", now).unwrap(),
        "answer",
        now,
    )
    .unwrap();
    net.db
        .call_put(net.alice.node_id(), call_id, &initial)
        .await
        .unwrap();
    let invoice = net
        .wallet
        .create_invoice(
            1_000,
            "recovery block",
            calls::CALL_BLOCK_INVOICE_EXPIRY_SECS,
        )
        .await
        .unwrap();
    net.db
        .record_call_block_invoice(
            net.alice.node_id(),
            call_id,
            0,
            &hex::decode(&invoice.payment_hash)
                .unwrap()
                .try_into()
                .unwrap(),
            now + 120_000,
        )
        .await
        .unwrap();
    let payment = net.wallet.pay_invoice(&invoice.bolt11).await.unwrap();
    let proof = PaymentProof::new(
        hex::decode(&invoice.payment_hash)
            .unwrap()
            .try_into()
            .unwrap(),
        hex::decode(payment.preimage.unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        1_000,
    );
    let old_message = net
        .sessions_a
        .encrypt(net.bob.node_id(), text.as_bytes())
        .await
        .unwrap();
    let mut old = UkmEnvelopeBuilder::new(
        404,
        *net.alice.node_id(),
        Recipient::Node(*net.bob.node_id()),
        konsensus_crypto::ratchet_message_to_bytes(&old_message),
        proof,
    )
    .build();
    old.signature = Signature::from_ed25519(&net.alice.sign(&old.signable_bytes()));

    assert!(net.sessions_b.remove_session(net.alice.node_id()).await);
    let new_init = recovery_handover_session(&net).await;
    let ratchet_init = net
        .sessions_a
        .encrypt(net.bob.node_id(), b"ratchet-init")
        .await
        .unwrap();
    net.sessions_b
        .decrypt(net.alice.node_id(), &ratchet_init)
        .await
        .unwrap();
    assert!(net
        .sessions_b
        .preview_decrypt(net.alice.node_id(), &old_message)
        .await
        .is_err());
    recovery_handover_expect_deferred(&net, &old).await;
    assert_eq!(
        net.db.call_get(net.alice.node_id(), call_id).await.unwrap(),
        Some(initial.clone())
    );

    // The lower-ID block could also have merely overtaken an earlier frame.
    // Restoring readability cannot undo the refusal's durable fence.
    assert!(net.sessions_b.remove_session(net.alice.node_id()).await);
    net.sessions_b
        .reaccept_session(net.alice.node_id(), &old_init)
        .await
        .unwrap();
    assert_eq!(
        net.sessions_b
            .preview_decrypt(net.alice.node_id(), &old_message)
            .await
            .unwrap(),
        text.as_bytes()
    );
    recovery_handover_expect_deferred(&net, &old).await;
    assert_eq!(
        net.db.call_get(net.alice.node_id(), call_id).await.unwrap(),
        Some(initial.clone())
    );

    assert!(net.sessions_b.remove_session(net.alice.node_id()).await);
    net.sessions_b
        .reaccept_session(net.alice.node_id(), &new_init)
        .await
        .unwrap();
    net.sessions_b
        .decrypt(net.alice.node_id(), &ratchet_init)
        .await
        .unwrap();
    let replacement =
        recovery_handover_replacement(&net, &old, net.ciphertext(text.as_bytes()).await);
    let until = match net.verdict(&replacement).await {
        ControlEvent::MessageAcked {
            message_id,
            duplicate: false,
            paid_until_ms: Some(until),
            ..
        } => {
            assert_eq!(message_id, replacement.id);
            until
        }
        other => panic!("replacement must return its grant: {other:?}"),
    };
    let granted = net
        .db
        .call_get(net.alice.node_id(), call_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (granted.next_block_seq, granted.paid_until_ms),
        (1, Some(until))
    );
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), net.ws_rx.recv())
            .await
            .unwrap()
            .unwrap()
            .envelope
            .id,
        replacement.id
    );
    assert!(matches!(net.verdict(&replacement).await,
        ControlEvent::MessageAcked { message_id, duplicate: true, paid_until_ms: Some(repeated), .. }
        if message_id == replacement.id && repeated == until));
    assert_eq!(
        net.db.call_get(net.alice.node_id(), call_id).await.unwrap(),
        Some(granted)
    );
    assert!(
        matches!(net.verdict(&old).await,
        ControlEvent::MessageRejected { message_id, .. }
        if message_id == old.id),
        "the old identity cannot acquire or replay a grant after replacement acceptance"
    );
    assert!(
        net.ws_rx.try_recv().is_err(),
        "one application delivery and one interval"
    );

    // The sender can bind this new-ID grant to the original call operation;
    // repeating the grant never advances the caller by another sequence.
    let caller = konsensus_storage::SqliteStorage::in_memory().await.unwrap();
    caller
        .call_put(
            net.bob.node_id(),
            call_id,
            &calls::CallEntry {
                side: calls::Side::Caller,
                next_block_seq: 1,
                ..initial
            },
        )
        .await
        .unwrap();
    journal_dispatched_block(&caller, &replacement, call_id, 0).await;
    let cipher = PlaintextCacheCipher::new(net.alice.aes_key());
    for _ in 0..2 {
        konsensus_api::calls::receive_block_grant(
            &caller,
            &cipher,
            net.alice.node_id(),
            net.bob.node_id(),
            &replacement.id,
            until,
        )
        .await
        .unwrap();
    }
    let caller_granted = caller
        .call_get(net.bob.node_id(), call_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (caller_granted.next_block_seq, caller_granted.paid_until_ms),
        (1, Some(until))
    );
    let receipts: Vec<(String, i32)> =
        sqlx::query_as("SELECT message_id, accepted FROM payment_receipts WHERE payment_hash = ?")
            .bind(hex::encode(old.payment_proof.payment_hash))
            .fetch_all(net.db.pool())
            .await
            .unwrap();
    assert_eq!(receipts, vec![(replacement.id.to_hex(), 1)]);
    assert!(net.db.get_message(&old.id).await.unwrap().is_none());
    assert!(!net.audit_log().contains("call.block_overpayment"));
    net.stop().await;
}

async fn recovery_reconnect_receive_loop(pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine>, sender_higher: bool) -> ReceiveLoop {
    use konsensus_message::{ControlEvent, ReachabilityMode, TransportConfig};
    let dir = tempfile::tempdir().unwrap();
    let alice = alice_identity();
    let bob = bob_identity();
    let (alice, bob) = if (alice.node_id().as_bytes() > bob.node_id().as_bytes()) != sender_higher { (bob, alice) } else { (alice, bob) };
    let transport = |id| {
        Arc::new(NoiseTransport::new(
            id,
            TransportConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                admission_mode: ReachabilityMode::PriceOpen,
                ..Default::default()
            },
        ))
    };
    let source = transport(alice.clone());
    let target = transport(bob.clone());
    target.start_listener().await.unwrap();
    let db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let storage: Arc<dyn Storage> = db.clone();
    source
        .connect(bob.node_id(), &target.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    assert!(matches!(
        source.recv_control().await.unwrap(),
        ControlEvent::PeerConnected { .. }
    ));
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let sessions_a = SessionManager::new(alice.clone());
    let sessions_b = Arc::new(SessionManager::new(bob.clone()));
    establish_sessions(&sessions_a, &sessions_b, &alice, &bob).await;
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditLog::open(&audit_path).unwrap());
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (ws_tx, ws_rx) = broadcast::channel(8);
    let worker = tokio::spawn(run(MsgHandlerDeps {
        transport: target.clone(),
        transport_ack: target.clone(),
        storage: storage.clone(),
        gate: Arc::new(PaymentGate::with_config(konsensus_core::gate::GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        })),
        pricing,
        lightning: wallet.clone(),
        chain: Arc::new(konsensus_chain::MockChainProvider::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        session_manager: sessions_b.clone(),
        nonce_adapter: Arc::new(konsensus_storage::StorageNonceAdapter::new(storage)),
        content_server: None,
        front_door: Default::default(),
        routing: Arc::new(RoutingTable::new(Default::default())),
        identity: bob.clone(),
        plaintext_cipher: Arc::new(PlaintextCacheCipher::new(bob.aes_key())),
        ws_tx,
        audit_log: audit,
        admission_mode: ReachabilityMode::PriceOpen,
        relay_engine: None,
        shutdown_rx,
    }));
    ReceiveLoop {
        alice,
        bob,
        source,
        target,
        db,
        wallet,
        sessions_a,
        sessions_b,
        audit_path,
        ws_rx,
        shutdown,
        worker,
        _dir: dir,
    }
}

fn recovery_reconnect_pricing() -> Arc<dyn konsensus_core::traits::pricing::PricingEngine> {
    Arc::new(MutableDeliveryPrice(std::sync::atomic::AtomicU64::new(1_000)))
}

async fn recovery_reconnect_next_control(transport: &NoiseTransport) -> konsensus_message::ControlEvent {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let event = transport.recv_control().await.unwrap();
            if !matches!(event, konsensus_message::ControlEvent::PeerConnected { .. }) { return event; }
        }
    }).await.expect("control frame arrives")
}

async fn recovery_reconnect_next_stamp(transport: &NoiseTransport) -> bool {
    use konsensus_message::ControlEvent::*;
    match recovery_reconnect_next_control(transport).await {
        PrekeyOffer { privileged, .. } | SessionInit { privileged, .. }
        | SessionAck { privileged, .. } | RatchetInit { privileged, .. }
        | MessageAcked { privileged, .. } | MessageRejected { privileged, .. }
        | PriceTableReceived { privileged, .. } | PriceQueryReceived { privileged, .. }
        | PriceResponseReceived { privileged, .. } | InvoiceRequested { privileged, .. }
        | PeerExchangeRequested { privileged, .. } | PeerExchangeReceived { privileged, .. }
        | LightningInfoReceived { privileged, .. } | GossipReceived { privileged, .. } => privileged,
        other => panic!("unexpected event {other:?}"),
    }
}

async fn recovery_reconnect_lost_session_envelope(net: &ReceiveLoop) -> konsensus_core::UkmEnvelope {
    let ciphertext = net.ciphertext(b"paid cached-keysend recovery").await;
    assert!(net.sessions_b.remove_session(net.alice.node_id()).await);
    net.paid_envelope(konsensus_core::kind::KIND_CHAT, ciphertext).await
}

async fn recovery_reconnect_reconnect(net: &ReceiveLoop) {
    let previous = net.target.connected_since(net.alice.node_id()).await.unwrap();
    net.source.disconnect(net.bob.node_id()).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while net.target.is_connected(net.alice.node_id()).await { tokio::task::yield_now().await; }
    }).await.unwrap();
    net.source.connect(net.bob.node_id(), &net.target.listen_addr().unwrap().to_string()).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while net.target.connected_since(net.alice.node_id()).await.is_none_or(|now| now == previous) {
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
}

#[tokio::test]
async fn recovery_reconnect_verified_keysend_deferral_opens_only_session_controls_and_resets() {
    use konsensus_message::{ControlEvent, Frame};
    let net = recovery_reconnect_receive_loop(recovery_reconnect_pricing(), true).await;
    let env = recovery_reconnect_lost_session_envelope(&net).await;
    assert!(matches!(net.verdict(&env).await, ControlEvent::MessageRejected { reason, .. } if reason.starts_with("session_handover:")));
    assert_eq!(net.target.connected_session_peers().await, vec![*net.alice.node_id()],
        "a verified deferred keysend must permit session recovery on this connection");
    assert!(net.target.connected_privileged_peers().await.is_empty());
    assert!(!net.target.admission_paid_on_connection(net.alice.node_id()).await);
    assert_eq!(net.receipt_state(&env).await, None);
    assert!(!net.db.has_nonce(&env.nonce).await.unwrap());

    let frames = vec![
        (Frame::PrekeyOffer { bundle: serde_json::json!({}) }, true),
        (Frame::SessionInit { init_data: serde_json::json!({}) }, true),
        (Frame::SessionAck, true),
        (Frame::RatchetInit { payload: vec![1, 2, 3] }, true),
        (Frame::MessageAck { id: env.id, duplicate: false, paid_until_ms: None }, false),
        (Frame::MessageReject { id: env.id, reason: "storage error".into() }, false),
        (Frame::PriceQuery { kind: 0 }, false),
        (Frame::PriceResponse { kind: 0, price_msat: 1000, block_height: 1 }, false),
        (Frame::PriceTable { prices: HashMap::from([("chat".into(), 1000)]), block_height: 1, valid_blocks: 10, trust_discount: 0.0 }, false),
        (Frame::RequestInvoice { request_id: "service".into(), amount_msat: 1000, purpose: "konsensus message".into() }, false),
        (Frame::PeerExchangeRequest, false),
        (Frame::PeerExchangeResponse { peers: vec![] }, false),
        (Frame::LightningInfo { ln_pubkey: "02".repeat(33), ln_addr: None }, false),
        (Frame::Gossip(Box::new(env.clone())), false),
    ];
    for (frame, allowed) in frames {
        net.source.send_frame(net.bob.node_id(), &frame).await.unwrap();
        assert_eq!(recovery_reconnect_next_stamp(&net.target).await, allowed, "{frame:?}");
    }
    net.source.send_frame(net.bob.node_id(), &Frame::CallMedia {
        call_id: "0123456789abcdef0123456789abcdef".into(), seq: 0, data: vec![1],
    }).await.unwrap();
    net.source.send_frame(net.bob.node_id(), &Frame::PriceQuery { kind: 1 }).await.unwrap();
    assert!(!recovery_reconnect_next_stamp(&net.target).await, "reader passed the media frame");
    assert!(tokio::time::timeout(std::time::Duration::from_millis(100), net.target.recv_call_media()).await.is_err());

    recovery_reconnect_reconnect(&net).await;
    assert!(net.target.connected_session_peers().await.is_empty(), "repair standing resets on reconnect");
    assert!(net.source.connected_session_peers().await.is_empty());
    net.source.send_frame(net.bob.node_id(), &Frame::SessionAck).await.unwrap();
    assert!(!recovery_reconnect_next_stamp(&net.target).await);
    // The same durable, still-unspent proof can open repair on the new connection.
    assert!(matches!(net.verdict(&env).await, ControlEvent::MessageRejected { reason, .. } if reason.starts_with("session_handover:")));
    assert_eq!(net.target.connected_session_peers().await, vec![*net.alice.node_id()]);
    assert!(net.target.connected_privileged_peers().await.is_empty());
    assert_eq!(net.wallet.list_payments(100).await.unwrap().len(), 1);
    net.stop().await;
}

#[tokio::test]
async fn recovery_reconnect_failed_durable_deferral_grants_no_repair() {
    use konsensus_message::ControlEvent;
    let net = recovery_reconnect_receive_loop(recovery_reconnect_pricing(), true).await;
    let env = recovery_reconnect_lost_session_envelope(&net).await;
    sqlx::query("CREATE TRIGGER no_repair_fence BEFORE INSERT ON envelope_deferrals BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
        .execute(net.db.pool()).await.unwrap();
    assert!(matches!(net.verdict(&env).await, ControlEvent::MessageRejected { reason, .. } if reason == "storage error"));
    assert!(net.target.connected_session_peers().await.is_empty());
    assert!(net.target.connected_privileged_peers().await.is_empty());
    assert!(!net.target.admission_paid_on_connection(net.alice.node_id()).await);
    assert!(!net.db.is_envelope_deferred(&env).await.unwrap());
    assert_eq!(net.receipt_state(&env).await, None);
    assert!(!net.db.has_nonce(&env.nonce).await.unwrap());
    net.stop().await;
}

#[tokio::test]
async fn recovery_reconnect_verification_on_replaced_connection_cannot_grant_repair() {
    use konsensus_message::ControlEvent;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let net = recovery_reconnect_receive_loop(Arc::new(BlockingPricing { entered: entered.clone(), release: release.clone() }), true).await;
    let env = recovery_reconnect_lost_session_envelope(&net).await;
    net.source.send(net.bob.node_id(), &env).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified()).await.unwrap();
    recovery_reconnect_reconnect(&net).await;
    release.add_permits(1);
    let event = recovery_reconnect_next_control(&net.source).await;
    assert!(matches!(event, ControlEvent::MessageRejected { reason, .. } if reason == "storage error"),
        "verification from the old generation authorizes no new connection");
    assert!(net.target.connected_session_peers().await.is_empty());
    assert!(net.target.connected_privileged_peers().await.is_empty());
    assert!(!net.target.admission_paid_on_connection(net.alice.node_id()).await);
    assert!(net.db.is_envelope_deferred(&env).await.unwrap(), "only the ciphertext deferral survives");
    assert!(matches!(net.verdict(&env).await, ControlEvent::MessageRejected { reason, .. } if reason.starts_with("session_handover:")));
    assert_eq!(net.target.connected_session_peers().await, vec![*net.alice.node_id()]);
    net.stop().await;
}

async fn recovery_reconnect_start_session_handler(
    id: Arc<NodeIdentity>, sessions: Arc<SessionManager>, transport: Arc<NoiseTransport>,
    storage: Arc<dyn Storage>, wallet: Arc<dyn konsensus_core::traits::lightning::LightningProvider>,
    audit_path: std::path::PathBuf, shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let (pending_tx, pending_rx) = tokio::sync::mpsc::channel(8);
    let (auto_channel_tx, auto_rx) = tokio::sync::mpsc::channel(8);
    let deps = crate::session_handler::SessionHandlerDeps {
        content_server: None, front_door: Default::default(), privacy: Default::default(), peer_exchange_floor: 0,
        transport, session_manager: sessions, storage, our_node_id: *id.node_id(), identity: id,
        audit_log: Arc::new(AuditLog::open(audit_path).unwrap()), min_admission_cost_msat: 1000,
        pricing: recovery_reconnect_pricing(), chain: Arc::new(konsensus_chain::MockChainProvider::new()),
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        routing: Arc::new(RoutingTable::new(Default::default())),
        gossip_validator: Arc::new(konsensus_gossip::GossipValidator::new(Default::default())),
        send_timestamps: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        lightning: wallet, lightning_addr: None, mock_lightning: false,
        invoice_requests: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        ws_broadcast: broadcast::channel(8).0, ws_delivery_tx: broadcast::channel(8).0,
        pending_tx, auto_channel_tx, starter_newcomer_tx: None, starter_hub_tx: None, shutdown_rx,
    };
    tokio::spawn(async move {
        let _receivers = (pending_rx, auto_rx);
        crate::session_handler::run(deps).await;
    })
}

/// An unpaid connection must not serialize the dispatcher behind storage.
#[tokio::test]
async fn recovery_reconnect_storage_wait_does_not_stall_unpaid_controls() {
    unpaid_repair_wait_keeps_control_loop_live(false).await;
}

#[tokio::test]
async fn recovery_reconnect_connection_lock_does_not_stall_unpaid_controls() {
    unpaid_repair_wait_keeps_control_loop_live(true).await;
}

async fn unpaid_repair_wait_keeps_control_loop_live(hold_connection: bool) {
    use konsensus_message::{ControlEvent, Frame, NoiseTransport, ReachabilityMode, TransportConfig};
    let net = recovery_reconnect_receive_loop(recovery_reconnect_pricing(), true).await;
    let pending = if hold_connection { None } else {
        let env = konsensus_core::UkmEnvelopeBuilder::new(0, *net.bob.node_id(), Recipient::Node(*net.alice.node_id()),
            b"paid ciphertext".to_vec(), konsensus_core::PaymentProof::new([19; 32], [20; 32], 1000)).build();
        let operation = recovery_reconnect_journal_paid(&net.db, &env).await;
        Some((env, operation))
    };
    // Hold the selected resource until after the response and shutdown.
    let held = if hold_connection { None } else { Some(net.db.pool().acquire().await.unwrap()) };
    let blocked = if hold_connection {
        let locked = Arc::new(tokio::sync::Notify::new());
        let (target, peer, ready) = (net.target.clone(), *net.alice.node_id(), locked.clone());
        let task = tokio::spawn(async move {
            let frame = Frame::PriceTable { prices: Default::default(), block_height: 0, valid_blocks: 1, trust_discount: 0.0 };
            target.send_price_frame_with(&peer, &frame, &frame, |_, _| async {
                ready.notify_one();
                std::future::pending().await
            }).await
        });
        locked.notified().await;
        Some(task)
    } else { None };
    let worker = recovery_reconnect_start_session_handler(
        net.bob.clone(), net.sessions_b.clone(), net.target.clone(), net.db.clone(),
        net.wallet.clone(), net._dir.path().join("control-session.jsonl"), net.shutdown.subscribe(),
    ).await;
    // A fabricated confirmation is not bought authority. Fill the bounded
    // confirmation queue while its first durable lookup cannot complete.
    for n in 0..if hold_connection { 0 } else { 256u16 } {
        let mut bytes = [0; 32];
        bytes[..2].copy_from_slice(&n.to_le_bytes());
        let id = konsensus_core::MessageId::from_bytes(bytes);
        let frame = if n % 2 == 0 {
            Frame::MessageReject { id, reason: "session_handover: unbound".into() }
        } else {
            Frame::MessageAck { id, duplicate: false, paid_until_ms: None }
        };
        net.source.send_frame(net.bob.node_id(), &frame).await.unwrap();
    }
    if let Some((env, _)) = &pending {
        net.source.send_frame(net.bob.node_id(), &Frame::MessageAck {
            id: env.id, duplicate: false, paid_until_ms: None,
        }).await.unwrap();
    }
    let healthy = Arc::new(NoiseTransport::new(
        Arc::new(NodeIdentity::generate().unwrap().1),
        TransportConfig { admission_mode: ReachabilityMode::PriceOpen, ..Default::default() },
    ));
    healthy.connect(net.bob.node_id(), &net.target.listen_addr().unwrap().to_string()).await.unwrap();
    healthy.send_frame(net.bob.node_id(), &Frame::RequestInvoice {
        request_id: "other-peer".into(), amount_msat: 1000, purpose: "konsensus message".into(),
    }).await.unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Some(ControlEvent::InvoiceErrorReceived { request_id, reason, .. }) = healthy.recv_control().await {
                assert_eq!(request_id, "other-peer");
                assert_eq!(reason, konsensus_api::invoice_refusal::ADMISSION_REQUIRED);
                break;
            }
        }
    }).await;
    // Shutdown must also finish with the reconnect query still blocked.
    net.shutdown.send(true).unwrap();
    let stopped = tokio::time::timeout(std::time::Duration::from_secs(1), worker).await;
    drop(held);
    if let Some(task) = blocked { task.abort(); let _ = task.await; }
    healthy.shutdown();
    net.worker.await.unwrap();
    if response.is_err() { net.source.shutdown(); net.target.shutdown(); }
    assert!(response.is_ok(), "unpaid reconnect resource wait stalled another peer (connection lock: {hold_connection})");
    stopped.expect("blocked repair prevented shutdown").unwrap();
    if let Some((env, operation)) = pending {
        let before = net.db.get_outbox_operation(&operation).await.unwrap().unwrap();
        assert_eq!(before.state, "paid", "lost/queued ACK cannot complete a blocked durable match");
        assert_eq!(before.settled_msat, 1000);
        let (stop, shutdown_rx) = watch::channel(false);
        let retry = recovery_reconnect_start_session_handler(net.bob.clone(), net.sessions_b.clone(),
            net.target.clone(), net.db.clone(), net.wallet.clone(), net._dir.path().join("retry-session.jsonl"), shutdown_rx).await;
        net.source.send_frame(net.bob.node_id(), &Frame::MessageAck {
            id: env.id, duplicate: true, paid_until_ms: None,
        }).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let after = net.db.get_outbox_operation(&operation).await.unwrap().unwrap();
                if after.state == "acked" {
                    assert_eq!(after.settled_msat, 1000);
                    assert_eq!(after.payment_hash, before.payment_hash);
                    assert_eq!(after.message_id, before.message_id);
                    break;
                }
                tokio::task::yield_now().await;
            }
        }).await.expect("authentic ACK retry completes the original paid operation after queue/shutdown loss");
        assert_eq!(net.db.count_pending_deliveries().await.unwrap(), 0);
        assert!(net.wallet.list_payments(100).await.unwrap().is_empty(), "confirmation retries never issue another payment");
        stop.send(true).unwrap();
        retry.await.unwrap();
    }
    net.source.shutdown();
    net.target.shutdown();
}

#[tokio::test]
async fn recovery_reconnect_queued_rejection_keeps_a_newer_session_usable() {
    use konsensus_message::{ControlEvent, Frame};
    let net = recovery_reconnect_receive_loop(recovery_reconnect_pricing(), true).await;
    let env = konsensus_core::UkmEnvelopeBuilder::new(0, *net.bob.node_id(), Recipient::Node(*net.alice.node_id()),
        b"old paid ciphertext".to_vec(), konsensus_core::PaymentProof::new([29; 32], [30; 32], 1000)).build();
    let operation = recovery_reconnect_journal_paid(&net.db, &env).await;
    let held = net.db.pool().acquire().await.unwrap();
    let worker = recovery_reconnect_start_session_handler(net.bob.clone(), net.sessions_b.clone(),
        net.target.clone(), net.db.clone(), net.wallet.clone(), net._dir.path().join("queued-session.jsonl"), net.shutdown.subscribe()).await;
    net.source.send_frame(net.bob.node_id(), &Frame::MessageReject {
        id: env.id, reason: "session_handover: old ciphertext".into(),
    }).await.unwrap();
    // Same-source wire order makes this response a dispatch barrier: the
    // rejection is queued, but its storage match is still held above.
    net.source.send_frame(net.bob.node_id(), &Frame::RequestInvoice {
        request_id: "queued-barrier".into(), amount_msat: 1000, purpose: "konsensus message".into(),
    }).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Some(ControlEvent::InvoiceErrorReceived { request_id, .. }) = net.source.recv_control().await {
                assert_eq!(request_id, "queued-barrier"); break;
            }
        }
    }).await.expect("rejection storage does not block later controls");
    let replacement = SessionManager::new(net.alice.clone());
    let init = replacement.initiate_session(net.bob.node_id(), &net.sessions_b.prekey_bundle().await).await.unwrap();
    assert!(net.sessions_b.remove_session(net.alice.node_id()).await);
    net.sessions_b.accept_session(net.alice.node_id(), &init).await.unwrap();
    assert!(replacement.confirm_session(net.bob.node_id()).await);
    let ratchet_init = replacement.encrypt(net.bob.node_id(), b"replacement ready").await.unwrap();
    assert_eq!(net.sessions_b.decrypt(net.alice.node_id(), &ratchet_init).await.unwrap(), b"replacement ready");
    assert!(net.sessions_b.can_send(net.alice.node_id()).await);
    drop(held);
    // A following authentic ACK is a FIFO completion barrier for the delayed
    // rejection and still completes the original paid operation without repay.
    net.source.send_frame(net.bob.node_id(), &Frame::MessageAck {
        id: env.id, duplicate: false, paid_until_ms: None,
    }).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while net.db.get_outbox_operation(&operation).await.unwrap().unwrap().state != "acked" { tokio::task::yield_now().await; }
    }).await.expect("following ACK completes after the queued rejection");
    let marked = net.sessions_b.needs_renegotiation(net.alice.node_id()).await;
    net.shutdown.send(true).unwrap();
    worker.await.unwrap();
    net.worker.await.unwrap();
    net.source.shutdown();
    net.target.shutdown();
    assert!(!marked, "a queued rejection must not invalidate a newer healthy session");
    assert!(net.sessions_b.encrypt(net.alice.node_id(), b"still usable").await.is_ok());
}

#[tokio::test]
async fn recovery_reconnect_both_unprivileged_sides_recover_a_paid_keysend_without_readmission() {
    let mut net = recovery_reconnect_receive_loop(recovery_reconnect_pricing(), true).await;
    let env = recovery_reconnect_lost_session_envelope(&net).await;
    let sessions_a = Arc::new(std::mem::replace(&mut net.sessions_a, SessionManager::new(net.alice.clone())));
    let source_db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    source_db.store_message(&env).await.unwrap();
    source_db.prepare_delivery(&env.id, net.bob.node_id()).await.unwrap();
    let source_worker = recovery_reconnect_start_session_handler(net.alice.clone(), sessions_a.clone(), net.source.clone(),
        source_db, Arc::new(konsensus_lightning::MockLightningProvider::new()),
        net._dir.path().join("source-session.jsonl"), net.shutdown.subscribe()).await;
    let target_worker = recovery_reconnect_start_session_handler(net.bob.clone(), net.sessions_b.clone(), net.target.clone(),
        net.db.clone(), net.wallet.clone(), net._dir.path().join("target-session.jsonl"), net.shutdown.subscribe()).await;
    net.source.send(net.bob.node_id(), &env).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if net.source.connected_session_peers().await.contains(net.bob.node_id())
                && net.target.connected_session_peers().await.contains(net.alice.node_id()) { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("both ends admit repair on the matched paid proof");
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if sessions_a.can_send(net.bob.node_id()).await && net.sessions_b.can_send(net.alice.node_id()).await
                && !sessions_a.needs_renegotiation(net.bob.node_id()).await
                && !sessions_a.replacement_pending(net.bob.node_id()).await
                && !net.sessions_b.awaiting_confirmation(net.alice.node_id()).await { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("the real control handlers complete X3DH and ratchet initialization");
    assert!(net.source.connected_privileged_peers().await.is_empty());
    assert!(net.target.connected_privileged_peers().await.is_empty());
    assert!(!net.source.admission_paid_on_connection(net.bob.node_id()).await);
    assert!(!net.target.admission_paid_on_connection(net.alice.node_id()).await);
    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(&sessions_a.encrypt(net.bob.node_id(), b"paid cached-keysend recovery").await.unwrap());
    let replacement = recovery_handover_replacement(&net, &env, ciphertext);
    net.source.send(net.bob.node_id(), &replacement).await.unwrap();
    let shown = tokio::time::timeout(std::time::Duration::from_secs(5), net.ws_rx.recv()).await.unwrap().unwrap();
    assert_eq!(shown.plaintext.as_deref(), Some("paid cached-keysend recovery"));
    assert_eq!(net.receipt_state(&replacement).await, Some(1));
    assert_eq!(net.wallet.list_payments(100).await.unwrap().len(), 1, "no second payment or readmission");
    net.stop().await;
    source_worker.await.unwrap();
    target_worker.await.unwrap();
}

async fn recovery_reconnect_journal_paid(
    db: &konsensus_storage::SqliteStorage,
    env: &konsensus_core::UkmEnvelope,
) -> String {
    let Recipient::Node(peer) = env.recipient else { panic!("direct message") };
    let id = uuid::Uuid::new_v4().to_string();
    let mut op = konsensus_storage::OutboxOperation::prepared(id.clone(), peer.to_hex(), env.kind, "same request".into());
    op.state = "paid".into();
    op.message_id = Some(env.id.to_hex());
    op.payment_hash = Some(hex::encode(env.payment_proof.payment_hash));
    op.settled_msat = i64::try_from(env.payment_proof.amount_msat).unwrap();
    op.accounting_pending = false;
    assert!(db.insert_outbox_operation(&op).await.unwrap());
    assert!(db.commit_outbox_envelope(&op, env).await.unwrap());
    db.mark_pending_sent(&env.id, &peer).await.unwrap();
    id
}

#[tokio::test]
async fn recovery_reconnect_pending_paid_act_reauthorizes_repair_after_drop_before_x3dh() {
    use konsensus_message::ControlEvent;
    let mut net = recovery_reconnect_receive_loop(recovery_reconnect_pricing(), true).await;
    let env = recovery_reconnect_lost_session_envelope(&net).await;
    let source_db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let operation = recovery_reconnect_journal_paid(&source_db, &env).await;
    let verdict = net.verdict(&env).await;
    let ControlEvent::MessageRejected { reason, .. } = verdict else { panic!("expected paid deferral") };
    assert!(reason.starts_with("session_handover:"));
    // These are the same durable match and mark as the sender's control loop.
    // The loop is held here so the drop deterministically precedes X3DH.
    assert!(source_db.reject_pending(&env.id, net.bob.node_id(), net.alice.node_id(), &reason, false).await.unwrap());
    let old_source = net.source.connected_since(net.bob.node_id()).await.unwrap();
    assert!(net.source.allow_session_repair(net.bob.node_id(), old_source, std::time::Instant::now() + std::time::Duration::from_secs(60)).await);
    net.sessions_a.mark_needs_renegotiation(net.bob.node_id()).await;
    assert!(source_db.session_repair_pending(net.alice.node_id(), net.bob.node_id()).await.unwrap());
    assert!(net.db.session_repair_pending(net.bob.node_id(), net.alice.node_id()).await.unwrap());

    recovery_reconnect_reconnect(&net).await;
    assert!(net.source.connected_session_peers().await.is_empty(), "connection-local source flag reset");
    assert!(net.target.connected_session_peers().await.is_empty(), "connection-local recipient flag reset");
    let sessions_a = Arc::new(std::mem::replace(&mut net.sessions_a, SessionManager::new(net.alice.clone())));
    let target_worker = recovery_reconnect_start_session_handler(net.bob.clone(), net.sessions_b.clone(), net.target.clone(),
        net.db.clone(), net.wallet.clone(), net._dir.path().join("target-obligation.jsonl"), net.shutdown.subscribe()).await;
    // Start the sender loop after the recipient revalidates. This fixes the
    // schedule without sleeps; its offer then reaches a repair-eligible reader.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !net.target.connected_session_peers().await.contains(net.alice.node_id()) {
            tokio::task::yield_now().await;
        }
    }).await.expect("recipient revalidates its durable deferral");
    let source_worker = recovery_reconnect_start_session_handler(net.alice.clone(), sessions_a.clone(), net.source.clone(),
        source_db.clone(), Arc::new(konsensus_lightning::MockLightningProvider::new()),
        net._dir.path().join("source-obligation.jsonl"), net.shutdown.subscribe()).await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if net.source.connected_session_peers().await.contains(net.bob.node_id())
                && net.target.connected_session_peers().await.contains(net.alice.node_id()) { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("PeerConnected revalidates both unfinished paid obligations");
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if sessions_a.can_send(net.bob.node_id()).await && net.sessions_b.can_send(net.alice.node_id()).await
                && !sessions_a.needs_renegotiation(net.bob.node_id()).await
                && !sessions_a.replacement_pending(net.bob.node_id()).await
                && !net.sessions_b.awaiting_confirmation(net.alice.node_id()).await { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("new connection repairs without replaying fenced application bytes");
    assert!(net.source.connected_privileged_peers().await.is_empty());
    assert!(net.target.connected_privileged_peers().await.is_empty());
    assert!(!net.source.admission_paid_on_connection(net.bob.node_id()).await);
    assert!(!net.target.admission_paid_on_connection(net.alice.node_id()).await);
    assert_eq!(net.receipt_state(&env).await, None);
    assert!(!net.db.has_nonce(&env.nonce).await.unwrap());

    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(&sessions_a.encrypt(net.bob.node_id(), b"paid cached-keysend recovery").await.unwrap());
    let replacement = recovery_handover_replacement(&net, &env, ciphertext);
    let mut next = source_db.get_outbox_operation(&operation).await.unwrap().unwrap();
    next.state = "paid".into();
    next.message_id = Some(replacement.id.to_hex());
    next.last_error = None;
    next.last_sent_at = None;
    assert!(source_db.replace_outbox_envelope(&next, &env.id, &replacement, None).await.unwrap());
    source_db.mark_pending_sent(&replacement.id, net.bob.node_id()).await.unwrap();
    net.source.send(net.bob.node_id(), &replacement).await.unwrap();
    let shown = tokio::time::timeout(std::time::Duration::from_secs(5), net.ws_rx.recv()).await.unwrap().unwrap();
    assert_eq!(shown.plaintext.as_deref(), Some("paid cached-keysend recovery"));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while source_db.get_outbox_operation(&operation).await.unwrap().unwrap().state != "acked" {
            tokio::task::yield_now().await;
        }
    }).await.expect("replacement ACK completes the one paid operation");
    assert!(!source_db.session_repair_pending(net.alice.node_id(), net.bob.node_id()).await.unwrap());
    assert!(!net.db.session_repair_pending(net.bob.node_id(), net.alice.node_id()).await.unwrap());
    assert_eq!(net.wallet.list_payments(100).await.unwrap().len(), 1);
    assert_eq!(net.receipt_state(&replacement).await, Some(1));
    assert_eq!(source_db.count_pending_deliveries().await.unwrap(), 0);

    recovery_reconnect_reconnect(&net).await;
    assert!(net.source.connected_session_peers().await.is_empty(), "fulfilled act grants no future repair standing");
    assert!(net.target.connected_session_peers().await.is_empty(), "durable receipt retired the deferral");
    net.stop().await;
    source_worker.await.unwrap();
    target_worker.await.unwrap();
}

#[tokio::test]
async fn recovery_reconnect_non_direct_failure_grants_no_fence_or_repair() {
    use konsensus_message::ControlEvent;
    let net = recovery_reconnect_receive_loop(recovery_reconnect_pricing(), true).await;
    let mut env = recovery_reconnect_lost_session_envelope(&net).await;
    env.recipient = Recipient::Room(konsensus_core::RoomId::new());
    env.signature = Signature::from_ed25519(&net.alice.sign(&env.signable_bytes()));
    assert!(matches!(net.verdict(&env).await, ControlEvent::MessageRejected { reason, .. } if reason.starts_with("session_pending:")));
    assert!(!net.db.is_envelope_deferred(&env).await.unwrap());
    assert!(!net.db.session_repair_pending(net.bob.node_id(), net.alice.node_id()).await.unwrap());
    assert!(net.target.connected_session_peers().await.is_empty());
    assert!(net.target.connected_privileged_peers().await.is_empty());
    assert_eq!(net.receipt_state(&env).await, None);
    assert!(!net.db.has_nonce(&env.nonce).await.unwrap());
    net.stop().await;
}

#[tokio::test]
async fn recovery_reconnect_zero_price_bound_reply_grants_no_fence_or_repair() {
    use konsensus_message::ControlEvent;
    let net = recovery_reconnect_receive_loop(recovery_reconnect_pricing(), true).await;
    // A legitimate zero-price reply is bound to our outgoing settled request.
    // It is gate-valid, and cannot confer the sender's admission authority.
    // The deferred mock path stores the raw hash used by settlement lookup.
    net.wallet.defer_next_keysend_settlement(0).await;
    let sent = net.wallet.keysend(&"02".repeat(33), 1000, None).await.unwrap();
    let paid = net.wallet.get_payment_status(&sent.payment_hash).await.unwrap();
    let hash: [u8; 32] = hex::decode(&paid.payment_hash).unwrap().try_into().unwrap();
    let preimage: [u8; 32] = hex::decode(paid.preimage.unwrap()).unwrap().try_into().unwrap();
    let request = MessageId::from_bytes([47; 32]);
    net.db.record_outgoing_web_request(&hash, konsensus_core::OutstandingWebRequest {
        request_id: request, peer: *net.alice.node_id(), expected_reply_kind: konsensus_core::kind::KIND_PAGE_RESPONSE,
        expires_at_ms: chrono::Utc::now().timestamp_millis() as u64 + konsensus_core::OUTSTANDING_TTL_MS,
    }).await.unwrap();
    let mut env = UkmEnvelopeBuilder::new(konsensus_core::kind::KIND_PAGE_RESPONSE,
        *net.alice.node_id(), Recipient::Node(*net.bob.node_id()), b"not a ratchet message".to_vec(),
        PaymentProof::new(hash, preimage, 0)).references(vec![request]).build();
    env.signature = Signature::from_ed25519(&net.alice.sign(&env.signable_bytes()));
    assert!(konsensus_core::is_web_service_reply(&env));
    assert!(matches!(net.verdict(&env).await, ControlEvent::MessageRejected { reason, .. } if reason.starts_with("session_pending:")));
    assert!(!net.db.is_envelope_deferred(&env).await.unwrap());
    assert!(!net.db.session_repair_pending(net.bob.node_id(), net.alice.node_id()).await.unwrap());
    assert!(net.target.connected_session_peers().await.is_empty());
    assert!(net.target.connected_privileged_peers().await.is_empty());
    assert_eq!(net.receipt_state(&env).await, None);
    assert!(!net.db.has_nonce(&env.nonce).await.unwrap());
    net.stop().await;
}

#[tokio::test]
async fn recovery_reconnect_outgoing_repair_standing_checks_generation_and_frame_kind() {
    use konsensus_message::{Frame, Standing};
    let net = recovery_reconnect_receive_loop(recovery_reconnect_pricing(), true).await;
    let env = recovery_reconnect_lost_session_envelope(&net).await;
    let since = net.target.connected_since(net.alice.node_id()).await.unwrap();
    let control = Frame::SessionAck.to_bytes().unwrap();
    assert!(net.target.send_raw_frame_on(net.alice.node_id(), since, Standing::SessionRepair, &control).await.is_err());
    assert!(matches!(net.verdict(&env).await, konsensus_message::ControlEvent::MessageRejected { reason, .. } if reason.starts_with("session_handover:")));
    net.target.send_raw_frame_on(net.alice.node_id(), since, Standing::SessionRepair, &control).await.unwrap();
    let metadata = Frame::PriceQuery { kind: 1 }.to_bytes().unwrap();
    assert!(net.target.send_raw_frame_on(net.alice.node_id(), since, Standing::SessionRepair, &metadata).await.is_err());
    recovery_reconnect_reconnect(&net).await;
    assert!(!net.target.allow_session_repair(net.alice.node_id(), since, std::time::Instant::now() + std::time::Duration::from_secs(60)).await);
    assert!(net.target.send_raw_frame_on(net.alice.node_id(), since, Standing::SessionRepair, &control).await.is_err());
    net.stop().await;
}

#[tokio::test]
async fn recovery_reconnect_deferral_expiry_ends_live_and_reconnected_standing() {
    use konsensus_message::{ControlEvent, Frame, Standing};
    let net = recovery_reconnect_receive_loop(recovery_reconnect_pricing(), true).await;
    let env = recovery_reconnect_lost_session_envelope(&net).await;
    assert!(matches!(net.verdict(&env).await, ControlEvent::MessageRejected { reason, .. } if reason.starts_with("session_handover:")));
    let since = net.target.connected_since(net.alice.node_id()).await.unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    sqlx::query("UPDATE envelope_deferrals SET expires_at_ms = ?")
        .bind(now + 500).execute(net.db.pool()).await.unwrap();
    assert!(crate::session_handler::allow_paid_session_repair(net.db.as_ref(), net.bob.node_id(), net.alice.node_id(), &net.target, since).await);
    assert!(net.target.session_repair_on_connection(net.alice.node_id()).await);
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    assert!(!net.db.session_repair_pending(net.bob.node_id(), net.alice.node_id()).await.unwrap());
    assert!(!net.target.session_repair_on_connection(net.alice.node_id()).await, "live connection must lose expired permission");
    assert!(net.target.connected_session_peers().await.is_empty());
    let control = Frame::SessionAck.to_bytes().unwrap();
    assert!(net.target.send_raw_frame_on(net.alice.node_id(), since, Standing::SessionRepair, &control).await.is_err());
    net.source.send_frame(net.bob.node_id(), &Frame::SessionAck).await.unwrap();
    assert!(!recovery_reconnect_next_stamp(&net.target).await, "expired repair cannot authorize incoming controls");
    recovery_reconnect_reconnect(&net).await;
    let since = net.target.connected_since(net.alice.node_id()).await.unwrap();
    assert!(!crate::session_handler::allow_paid_session_repair(net.db.as_ref(), net.bob.node_id(), net.alice.node_id(), &net.target, since).await);
    assert!(net.target.connected_session_peers().await.is_empty());
    assert!(!net.db.has_nonce(&env.nonce).await.unwrap());
    net.stop().await;
}

#[tokio::test]
async fn media_state_read_failure_keeps_paid_block_retryable() {
    use konsensus_core::payloads::call::{CallEntry, Phase, Side};
    use konsensus_message::ControlEvent;
    let net = receive_loop().await;
    let call_id = "0123456789abcdef0123456789abcdef";
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let original = CallEntry {
        side: Side::Callee,
        phase: Phase::Live,
        deadline_ms: now + 30_000,
        pending: None,
        paid_until_ms: Some(now + 20_000),
        next_block_seq: 1,
        end_reason: None,
        unpaid_notice_used: false,
    };
    net.db
        .call_put(net.alice.node_id(), call_id, &original)
        .await
        .unwrap();
    let body = format!(r#"{{"call_id":"{call_id}","seq":1}}"#);
    let env = net
        .paid_envelope(404, net.ciphertext(body.as_bytes()).await)
        .await;
    net.db
        .record_call_block_invoice(
            net.alice.node_id(),
            call_id,
            1,
            &env.payment_proof.payment_hash,
            now + 60_000,
        )
        .await
        .unwrap();
    sqlx::query("ALTER TABLE call_media_heads RENAME TO saved_media_heads")
        .execute(net.db.pool())
        .await
        .unwrap();
    let response = net.verdict(&env).await;
    assert!(
        matches!(response, ControlEvent::MessageRejected { ref reason, .. }
        if reason.contains("call media state unavailable")),
        "{response:?}"
    );
    assert_eq!(net.receipt_state(&env).await, None);
    assert!(!net.db.has_nonce(&env.nonce).await.unwrap());
    assert!(net.db.get_message(&env.id).await.unwrap().is_none());
    assert_eq!(
        net.db.call_get(net.alice.node_id(), call_id).await.unwrap(),
        Some(original.clone())
    );
    sqlx::query("ALTER TABLE saved_media_heads RENAME TO call_media_heads")
        .execute(net.db.pool())
        .await
        .unwrap();
    assert!(matches!(
        net.verdict(&env).await,
        ControlEvent::MessageAcked { .. }
    ));
    assert_eq!(net.receipt_state(&env).await, Some(1));
    let renewed = net
        .db
        .call_get(net.alice.node_id(), call_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(renewed.phase, Phase::Live);
    assert_eq!(renewed.next_block_seq, 2);
    assert!(renewed.paid_until_ms.unwrap() > original.paid_until_ms.unwrap());
    net.stop().await;
}
