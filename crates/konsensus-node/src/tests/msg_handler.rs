use super::*;
use std::collections::HashMap;
use std::sync::Mutex;

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

    fn has_plaintext(&self, id: &MessageId) -> bool {
        self.plaintexts.lock().unwrap().contains_key(&id.to_hex())
    }
}

#[async_trait::async_trait]
impl Storage for TestStorage {
    async fn store_message(&self, envelope: &konsensus_core::UkmEnvelope) -> Result<(), StorageError> {
        self.messages.lock().unwrap().insert(envelope.id.to_hex(), envelope.clone());
        Ok(())
    }
    async fn get_message(&self, id: &MessageId) -> Result<Option<konsensus_core::UkmEnvelope>, StorageError> {
        Ok(self.messages.lock().unwrap().get(&id.to_hex()).cloned())
    }
    async fn get_messages_for_recipient(&self, _r: &Recipient, _l: u32, _b: Option<u64>) -> Result<Vec<konsensus_core::UkmEnvelope>, StorageError> { Ok(vec![]) }
    async fn get_conversation_messages(&self, _a: &str, _b: &str, _c: bool, _d: u32, _e: Option<u64>) -> Result<Vec<konsensus_core::UkmEnvelope>, StorageError> { Ok(vec![]) }
    async fn delete_message(&self, _id: &MessageId) -> Result<bool, StorageError> { Ok(false) }
    async fn delete_messages_older_than(&self, _b: u64) -> Result<u64, StorageError> { Ok(0) }
    async fn create_room(&self, _r: &Room) -> Result<(), StorageError> { Ok(()) }
    async fn get_room(&self, _id: &konsensus_core::RoomId) -> Result<Option<Room>, StorageError> { Ok(None) }
    async fn list_rooms(&self) -> Result<Vec<Room>, StorageError> { Ok(vec![]) }
    async fn add_room_member(&self, _r: &konsensus_core::RoomId, _m: &NodeId) -> Result<(), StorageError> { Ok(()) }
    async fn remove_room_member(&self, _r: &konsensus_core::RoomId, _m: &NodeId) -> Result<(), StorageError> { Ok(()) }
    async fn delete_room(&self, _id: &konsensus_core::RoomId) -> Result<bool, StorageError> { Ok(false) }
    async fn get_room_members(&self, _r: &konsensus_core::RoomId) -> Result<Vec<NodeId>, StorageError> { Ok(vec![]) }
    async fn upsert_peer(&self, _p: &Peer) -> Result<(), StorageError> { Ok(()) }
    async fn get_peer(&self, _id: &NodeId) -> Result<Option<Peer>, StorageError> { Ok(None) }
    async fn list_peers(&self) -> Result<Vec<Peer>, StorageError> { Ok(vec![]) }
    async fn delete_peer(&self, _id: &NodeId) -> Result<bool, StorageError> { Ok(false) }
    async fn store_nonce(&self, _n: &Nonce, _s: &NodeId) -> Result<bool, StorageError> { Ok(true) }
    async fn has_nonce(&self, _n: &Nonce) -> Result<bool, StorageError> { Ok(false) }
    async fn cleanup_expired_nonces(&self, _a: u64) -> Result<u64, StorageError> { Ok(0) }
    async fn store_session(&self, _p: &NodeId, _b: &[u8]) -> Result<(), StorageError> { Ok(()) }
    async fn load_session(&self, _p: &NodeId) -> Result<Option<Vec<u8>>, StorageError> { Ok(None) }
    async fn delete_session(&self, _p: &NodeId) -> Result<bool, StorageError> { Ok(false) }
    async fn list_sessions(&self) -> Result<Vec<NodeId>, StorageError> { Ok(vec![]) }
    async fn queue_pending_delivery(&self, _m: &MessageId, _r: &NodeId) -> Result<(), StorageError> { Ok(()) }
    async fn get_pending_for_peer(&self, _r: &NodeId) -> Result<Vec<(MessageId, u32)>, StorageError> { Ok(vec![]) }
    async fn remove_pending_delivery(&self, _m: &MessageId, _r: &NodeId) -> Result<(), StorageError> { Ok(()) }
    async fn increment_pending_attempts(&self, _m: &MessageId, _r: &NodeId) -> Result<(), StorageError> { Ok(()) }
    async fn get_pending_peers(&self) -> Result<Vec<NodeId>, StorageError> { Ok(vec![]) }
    async fn count_pending_deliveries(&self) -> Result<u64, StorageError> { Ok(0) }
    async fn clear_pending_for_peer(&self, _r: &NodeId) -> Result<u64, StorageError> { Ok(0) }
    async fn cleanup_stale_pending(&self, _m: u32) -> Result<u64, StorageError> { Ok(0) }
    async fn store_file(&self, file: &FileRecord) -> Result<(), StorageError> {
        self.files.lock().unwrap().insert(file.id.clone(), file.clone());
        Ok(())
    }
    async fn get_file(&self, id: &str) -> Result<Option<FileRecord>, StorageError> {
        Ok(self.files.lock().unwrap().get(id).cloned())
    }
    async fn get_file_metadata(&self, _id: &str) -> Result<Option<FileMetadata>, StorageError> { Ok(None) }
    async fn list_files(&self, _l: u32) -> Result<Vec<FileMetadata>, StorageError> { Ok(vec![]) }
    async fn delete_file(&self, _id: &str) -> Result<bool, StorageError> { Ok(false) }
    async fn store_message_plaintext(&self, id: &MessageId, data: &[u8]) -> Result<(), StorageError> {
        self.plaintexts.lock().unwrap().insert(id.to_hex(), data.to_vec());
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

fn make_envelope(sender: &NodeIdentity, recipient: NodeId, kind: u16, ciphertext: Vec<u8>) -> konsensus_core::UkmEnvelope {
    let proof = make_valid_proof(100);
    let mut env = UkmEnvelopeBuilder::new(kind, *sender.node_id(), Recipient::Node(recipient), ciphertext, proof).build();
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
    Arc::new(konsensus_message::NoiseTransport::new(Arc::clone(identity), cfg))
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

    let envelope = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_FILE_REF, b"encrypted".to_vec());
    let sender = *alice.node_id();

    let result = process_file_message(&bytes, &sender, &envelope, &storage, &audit).await;

    assert_eq!(result, Some("[file: test.txt]".to_string()));
}

#[tokio::test]
async fn process_file_hash_mismatch_discards_data() {
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

    let envelope = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_FILE_REF, b"encrypted".to_vec());
    let sender = *alice.node_id();

    let result = process_file_message(&bytes, &sender, &envelope, &storage, &audit).await;

    // Returns filename (for display) but does NOT store the file (hash mismatch)
    assert_eq!(result, Some("[file: corrupt.txt]".to_string()));
}

#[tokio::test]
async fn process_file_invalid_json_returns_none() {
    let alice = alice_identity();
    let bob = bob_identity();
    let storage: Arc<dyn Storage> = Arc::new(TestStorage::new());
    let audit = make_audit_log();

    let bytes = b"not json";
    let envelope = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_FILE_REF, b"enc".to_vec());
    let sender = *alice.node_id();

    let result = process_file_message(bytes, &sender, &envelope, &storage, &audit).await;
    assert_eq!(result, None);
}

#[tokio::test]
async fn process_file_invalid_base64_returns_filename() {
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

    let envelope = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_FILE_REF, b"enc".to_vec());
    let sender = *alice.node_id();

    let result = process_file_message(&bytes, &sender, &envelope, &storage, &audit).await;

    // Invalid base64 returns filename (graceful degradation)
    assert_eq!(result, Some("[file: broken.bin]".to_string()));
}

// ── decrypt_and_process tests ───────────────────────────────────────

#[tokio::test]
async fn decrypt_no_session_returns_none() {
    let alice = alice_identity();
    let bob = bob_identity();
    let session_mgr = SessionManager::new(Arc::clone(&bob));
    let plaintext_cipher = PlaintextCacheCipher::new(bob.aes_key());
    let storage: Arc<dyn Storage> = Arc::new(TestStorage::new());
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    let envelope = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_CHAT, b"encrypted".to_vec());
    let sender = *alice.node_id();

    let result = decrypt_and_process(
        &envelope,
        &sender,
        &session_mgr,
        &plaintext_cipher,
        &storage,
        &None,
        &(Arc::new(konsensus_chain::MockChainProvider::new()) as Arc<dyn ChainProvider>),
        &(Arc::new(konsensus_pricing::StaticPricingEngine::new(Default::default())) as Arc<dyn konsensus_core::traits::pricing::PricingEngine>),
        &bob,
        &transport,
        &audit,
    )
    .await;

    assert!(result.is_none(), "no session should return None");
}

#[tokio::test]
async fn decrypt_invalid_ratchet_message_returns_none() {
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
    let envelope = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_CHAT, b"not-a-ratchet-msg".to_vec());
    let sender = *alice.node_id();

    let result = decrypt_and_process(
        &envelope,
        &sender,
        &bob_mgr,
        &plaintext_cipher,
        &storage,
        &None,
        &(Arc::new(konsensus_chain::MockChainProvider::new()) as Arc<dyn ChainProvider>),
        &(Arc::new(konsensus_pricing::StaticPricingEngine::new(Default::default())) as Arc<dyn konsensus_core::traits::pricing::PricingEngine>),
        &bob,
        &transport,
        &audit,
    )
    .await;

    assert!(result.is_none(), "invalid ratchet message should return None");
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
    let ratchet_msg = alice_mgr.encrypt(bob.node_id(), b"Hello from Alice!").await.unwrap();
    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(&ratchet_msg);

    let envelope = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_CHAT, ciphertext);
    let sender = *alice.node_id();
    let storage_dyn: Arc<dyn Storage> = Arc::clone(&storage) as _;

    let result = decrypt_and_process(
        &envelope,
        &sender,
        &bob_mgr,
        &plaintext_cipher,
        &storage_dyn,
        &None,
        &(Arc::new(konsensus_chain::MockChainProvider::new()) as Arc<dyn ChainProvider>),
        &(Arc::new(konsensus_pricing::StaticPricingEngine::new(Default::default())) as Arc<dyn konsensus_core::traits::pricing::PricingEngine>),
        &bob,
        &transport,
        &audit,
    )
    .await;

    assert_eq!(result, Some("Hello from Alice!".to_string()));
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

    let ratchet_msg = alice_mgr.encrypt(bob.node_id(), &payload_bytes).await.unwrap();
    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(&ratchet_msg);

    let envelope = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_FILE_REF, ciphertext);
    let sender = *alice.node_id();
    let storage_dyn: Arc<dyn Storage> = Arc::clone(&storage) as _;

    let result = decrypt_and_process(
        &envelope,
        &sender,
        &bob_mgr,
        &plaintext_cipher,
        &storage_dyn,
        &None,
        &(Arc::new(konsensus_chain::MockChainProvider::new()) as Arc<dyn ChainProvider>),
        &(Arc::new(konsensus_pricing::StaticPricingEngine::new(Default::default())) as Arc<dyn konsensus_core::traits::pricing::PricingEngine>),
        &bob,
        &transport,
        &audit,
    )
    .await;

    assert_eq!(result, Some("[file: report.pdf]".to_string()));
    assert_eq!(storage.file_count(), 1);
}

// ── process_web_manifest tests ──────────────────────────────────────

#[tokio::test]
async fn web_manifest_no_content_server_returns_label() {
    let alice = alice_identity();
    let bob = bob_identity();
    let session_mgr = SessionManager::new(Arc::clone(&bob));
    let chain: Arc<dyn ChainProvider> = Arc::new(konsensus_chain::MockChainProvider::new());
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> =
        Arc::new(konsensus_pricing::StaticPricingEngine::new(Default::default()));
    let transport = make_transport(&bob);

    let sender = *alice.node_id();

    let result = process_web_manifest(
        &sender,
        &None,
        &chain,
        &pricing,
        &bob,
        &session_mgr,
        &transport,
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
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> =
        Arc::new(konsensus_pricing::StaticPricingEngine::new(Default::default()));
    let transport = make_transport(&bob);

    let tmp_dir = tempfile::tempdir().unwrap();
    let cs = Arc::new(ContentServer::new(crate::content_server::ContentServerConfig {
        content_dir: tmp_dir.path().to_path_buf(),
        max_file_size: 4 * 1024 * 1024,
        cache_seconds: 3600,
        site_name: "Test Node".to_string(),
    }).unwrap());

    let sender = *alice.node_id();

    let result = process_web_manifest(
        &sender,
        &Some(cs),
        &chain,
        &pricing,
        &bob,
        &session_mgr,
        &transport,
    )
    .await;

    assert_eq!(result, Some("[web manifest request]".to_string()));
}

// ── process_page_request tests ──────────────────────────────────────

#[tokio::test]
async fn page_request_invalid_json_returns_none() {
    let alice = alice_identity();
    let bob = bob_identity();
    let session_mgr = SessionManager::new(Arc::clone(&bob));
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> =
        Arc::new(konsensus_pricing::StaticPricingEngine::new(Default::default()));
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    let envelope = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_PAGE_REQUEST, b"enc".to_vec());
    let sender = *alice.node_id();

    let result = process_page_request(
        b"not json",
        &sender,
        &envelope,
        &None,
        &pricing,
        &bob,
        &session_mgr,
        &transport,
        &audit,
    )
    .await;

    assert!(result.is_none());
}

#[tokio::test]
async fn page_request_no_content_server_returns_label() {
    let alice = alice_identity();
    let bob = bob_identity();
    let session_mgr = SessionManager::new(Arc::clone(&bob));
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> =
        Arc::new(konsensus_pricing::StaticPricingEngine::new(Default::default()));
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    let envelope = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_PAGE_REQUEST, b"enc".to_vec());
    let sender = *alice.node_id();

    let page_req = konsensus_core::payloads::content::PageRequest {
        request_id: "req-1".to_string(),
        path: "/index.md".to_string(),
        method: "GET".to_string(),
        accept: vec!["text/html".to_string()],
    };
    let bytes = serde_json::to_vec(&page_req).unwrap();

    let result = process_page_request(
        &bytes, &sender, &envelope, &None, &pricing, &bob, &session_mgr, &transport, &audit,
    )
    .await;

    assert_eq!(result, Some("[page request: /index.md]".to_string()));
}

#[tokio::test]
async fn page_request_with_content_server_serves_page() {
    let alice = alice_identity();
    let bob = bob_identity();
    let session_mgr = SessionManager::new(Arc::clone(&bob));
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> =
        Arc::new(konsensus_pricing::StaticPricingEngine::new(Default::default()));
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    let tmp_dir = tempfile::tempdir().unwrap();
    std::fs::write(tmp_dir.path().join("hello.md"), "# Hello World\nTest page.").unwrap();
    let cs = Arc::new(ContentServer::new(crate::content_server::ContentServerConfig {
        content_dir: tmp_dir.path().to_path_buf(),
        max_file_size: 4 * 1024 * 1024,
        cache_seconds: 3600,
        site_name: "Test Node".to_string(),
    }).unwrap());

    let envelope = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_PAGE_REQUEST, b"enc".to_vec());
    let sender = *alice.node_id();

    let page_req = konsensus_core::payloads::content::PageRequest {
        request_id: "req-2".to_string(),
        path: "/hello.md".to_string(),
        method: "GET".to_string(),
        accept: vec!["text/html".to_string()],
    };
    let bytes = serde_json::to_vec(&page_req).unwrap();

    let result = process_page_request(
        &bytes, &sender, &envelope, &Some(cs), &pricing, &bob, &session_mgr, &transport, &audit,
    )
    .await;

    assert_eq!(result, Some("[page request: /hello.md]".to_string()));
}

#[tokio::test]
async fn page_request_nonexistent_path_returns_label() {
    let alice = alice_identity();
    let bob = bob_identity();
    let session_mgr = SessionManager::new(Arc::clone(&bob));
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> =
        Arc::new(konsensus_pricing::StaticPricingEngine::new(Default::default()));
    let audit = make_audit_log();
    let transport = make_transport(&bob);

    let tmp_dir = tempfile::tempdir().unwrap();
    let cs = Arc::new(ContentServer::new(crate::content_server::ContentServerConfig {
        content_dir: tmp_dir.path().to_path_buf(),
        max_file_size: 4 * 1024 * 1024,
        cache_seconds: 3600,
        site_name: "Test Node".to_string(),
    }).unwrap());

    let envelope = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_PAGE_REQUEST, b"enc".to_vec());
    let sender = *alice.node_id();

    let page_req = konsensus_core::payloads::content::PageRequest {
        request_id: "req-3".to_string(),
        path: "/nonexistent.md".to_string(),
        method: "GET".to_string(),
        accept: vec!["text/html".to_string()],
    };
    let bytes = serde_json::to_vec(&page_req).unwrap();

    let result = process_page_request(
        &bytes, &sender, &envelope, &Some(cs), &pricing, &bob, &session_mgr, &transport, &audit,
    )
    .await;

    assert_eq!(result, Some("[page request: /nonexistent.md]".to_string()));
}

// ── decrypt_and_process with stale session ──────────────────────────

#[tokio::test]
async fn decrypt_stale_session_removes_and_triggers_renegotiation() {
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
    let ratchet_msg = alice_mgr2.encrypt(bob.node_id(), b"stale message").await.unwrap();
    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(&ratchet_msg);

    let envelope = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_CHAT, ciphertext);
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
        &(Arc::new(konsensus_chain::MockChainProvider::new()) as Arc<dyn ChainProvider>),
        &(Arc::new(konsensus_pricing::StaticPricingEngine::new(Default::default())) as Arc<dyn konsensus_core::traits::pricing::PricingEngine>),
        &bob,
        &transport,
        &audit,
    )
    .await;

    // Decryption failed → returns None
    assert!(result.is_none());
    // Session should be removed for re-negotiation
    assert!(!bob_mgr.has_session(alice.node_id()).await);
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
    let ratchet_msg = alice_mgr.encrypt(bob.node_id(), invalid_utf8).await.unwrap();
    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(&ratchet_msg);

    let envelope = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_CHAT, ciphertext);
    let sender = *alice.node_id();

    let result = decrypt_and_process(
        &envelope,
        &sender,
        &bob_mgr,
        &plaintext_cipher,
        &storage,
        &None,
        &(Arc::new(konsensus_chain::MockChainProvider::new()) as Arc<dyn ChainProvider>),
        &(Arc::new(konsensus_pricing::StaticPricingEngine::new(Default::default())) as Arc<dyn konsensus_core::traits::pricing::PricingEngine>),
        &bob,
        &transport,
        &audit,
    )
    .await;

    // Non-UTF8 for a chat message returns None
    assert!(result.is_none());
}
