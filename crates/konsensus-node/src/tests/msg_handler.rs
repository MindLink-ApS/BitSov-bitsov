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
    // This general route fixture accepts replay keys; the real SQLite and gate
    // suites exercise atomic replay rejection and rollback.
    async fn store_paid_nonce(&self, _nonce: &Nonce, _hash: &[u8; 32], _sender: &NodeId, _message: &MessageId)
        -> Result<konsensus_core::gate::PaidReplay, StorageError> {
        Ok(konsensus_core::gate::PaidReplay::Accepted)
    }

    async fn store_nonce(&self, _n: &Nonce, _s: &NodeId) -> Result<bool, StorageError> { Ok(true) }
    async fn has_nonce(&self, _n: &Nonce) -> Result<bool, StorageError> { Ok(false) }
    // HARD-5 (#237) made the Storage `store_payment_receipt` default fail-closed.
    // This in-memory test stub accepts fresh payment hashes (mirrors MemStorage +
    // store_nonce above) so a covering proof verifies; replay coverage lives in the
    // konsensus-storage backend suites.
    async fn store_payment_receipt(&self, _h: &[u8; 32], _s: &NodeId, _m: &MessageId) -> Result<bool, StorageError> { Ok(true) }
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
        &Default::default(),
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
        &Default::default(),
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
        &Default::default(),
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
        &Default::default(),
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

    let request = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_WEB_MANIFEST, b"enc".to_vec());
    let result = process_web_manifest(
        &sender,
        &request,
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
    let request = make_envelope(alice.as_ref(), *bob.node_id(), konsensus_core::kind::KIND_WEB_MANIFEST, b"enc".to_vec());

    let result = process_web_manifest(
        &sender,
        &request,
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
    assert_ne!(reply.payment_proof.amount_msat, request.payment_proof.amount_msat);
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
        &Default::default(),
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
        &bytes, &sender, &envelope, &None, &Default::default(), &pricing, &bob, &session_mgr, &transport, &audit,
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
        &bytes, &sender, &envelope, &Some(cs), &Default::default(), &pricing, &bob, &session_mgr, &transport, &audit,
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
        &bytes, &sender, &envelope, &Some(cs), &Default::default(), &pricing, &bob, &session_mgr, &transport, &audit,
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
        &Default::default(),
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
        &Default::default(),
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

// ── HARD-11: registry read guard released before the gate await ──────
//
// Codex objection on #230: the code shape scopes the read guard before
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
        Ok(1) // 1 msat required; the 100-msat proof covers it.
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
    let nonce_adapter =
        Arc::new(konsensus_storage::StorageNonceAdapter::new(Arc::clone(&storage)));
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
            konsensus_message::ReachabilityMode::Whitelist, true)
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
        fn as_any(&self) -> &dyn std::any::Any { self }
        async fn get_price_msat(&self, _: u16) -> Result<u64, PricingError> {
            self.0.notify_one();
            Ok(2000)
        }
        async fn get_category_price_msat(&self, _: konsensus_core::kind::KindCategory) -> Result<u64, PricingError> {
            Ok(2000)
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let alice = alice_identity();
    let bob = bob_identity();
    let make_open_transport = |id: Arc<NodeIdentity>| Arc::new(NoiseTransport::new(id, TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        admission_mode: ReachabilityMode::PriceOpen,
        whitelist: if privileged { vec![*alice.node_id(), *bob.node_id()] } else { vec![] },
        ..Default::default()
    }));
    let source = make_open_transport(alice.clone());
    let target = make_open_transport(bob.clone());
    target.start_listener().await.unwrap();
    let storage: Arc<dyn Storage> = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let sessions = Arc::new(SessionManager::new(bob.clone()));
    let registry = Arc::new(tokio::sync::RwLock::new(PeerRegistry::new()));
    let audit_path = dir.path().join("audit.jsonl");
    let checked_price = Arc::new(tokio::sync::Notify::new());
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (ws_tx, _ws_rx) = broadcast::channel(8);
    let worker = tokio::spawn(run(MsgHandlerDeps {
        transport: target.clone(), transport_ack: target.clone(), storage: storage.clone(),
        gate: Arc::new(PaymentGate::with_config(konsensus_core::gate::GateConfig {
            verify_lightning_settlement: true, ..Default::default()
        })),
        pricing: Arc::new(ObservedPricing(checked_price.clone())),
        lightning: Arc::new(konsensus_lightning::MockLightningProvider::new()),
        chain: Arc::new(konsensus_chain::MockChainProvider::new()),
        peer_registry: registry.clone(), session_manager: sessions.clone(),
        nonce_adapter: Arc::new(konsensus_storage::StorageNonceAdapter::new(storage.clone())),
        content_server: None, front_door: Default::default(), routing: Arc::new(RoutingTable::new(Default::default())),
        identity: bob.clone(), plaintext_cipher: Arc::new(PlaintextCacheCipher::new(bob.aes_key())),
        ws_tx, audit_log: Arc::new(AuditLog::open(&audit_path).unwrap()),
        admission_mode: ReachabilityMode::PriceOpen, relay_engine: None, shutdown_rx,
    }));
    source.connect(bob.node_id(), &target.listen_addr().unwrap().to_string()).await.unwrap();
    assert!(matches!(source.recv_control().await.unwrap(), ControlEvent::PeerConnected { privileged: actual, .. } if actual == privileged));
    // A correctly signed envelope with a self-generated hash/preimage is not
    // evidence of payment. File kind also probes the arbitrary-kind price leak.
    let envelope = make_envelope(&alice, *bob.node_id(), 200, b"unpaid".to_vec());
    source.send_frame(bob.node_id(), &Frame::Message(Box::new(envelope.clone()))).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), checked_price.notified()).await.unwrap();
    let response = tokio::time::timeout(Duration::from_millis(200), source.recv_control()).await;
    shutdown.send(true).unwrap();
    worker.await.unwrap();
    source.shutdown();
    target.shutdown();
    if privileged {
        assert!(matches!(response, Ok(Some(ControlEvent::MessageRejected { .. }))), "privileged peer lost detailed rejection: {response:?}");
        assert!(!std::fs::read(&audit_path).unwrap().is_empty());
    } else {
        assert!(response.is_err(), "unpaid stranger received a response: {response:?}");
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
        konsensus_message::ReachabilityMode::PriceOpen, true)
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
        konsensus_message::ReachabilityMode::PriceOpen, true)
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
        konsensus_message::ReachabilityMode::PriceOpen, true)
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
            min_admission_cost_msat: if case == "insufficient" { 200 } else { 0 },
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
            &env, &membrane, &registry, &gate, &nonce, &pricing, None, 0.0, None, mode, true)
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
    fn category_price_overrides(&self) -> Option<Vec<u16>> { Some(Vec::new()) }
    fn as_any(&self) -> &dyn std::any::Any { self }
    async fn get_price_msat(&self, _: u16) -> Result<u64, konsensus_core::traits::pricing::PricingError> {
        Ok(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
    async fn get_category_price_msat(&self, _: konsensus_core::kind::KindCategory) -> Result<u64, konsensus_core::traits::pricing::PricingError> { self.get_price_msat(0).await }
}

#[tokio::test]
async fn quoted_payment_delayed_until_price_rise_is_accepted_once_over_noise() {
    paid_acceptance_retry_case(false, false, false, true).await;
}

async fn paid_acceptance_retry_case(legacy: bool, retained: bool, price_rise: bool, queued_price_rise: bool) {
    use konsensus_message::{ControlEvent, ReachabilityMode, TransportConfig};
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let alice = alice_identity();
    let bob = bob_identity();
    let transport = |id| Arc::new(NoiseTransport::new(id, TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        admission_mode: ReachabilityMode::PriceOpen, ..Default::default()
    }));
    let source = transport(alice.clone());
    let target = transport(bob.clone());
    target.start_listener().await.unwrap();
    let db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let storage: Arc<dyn Storage> = db.clone();
    source.connect(bob.node_id(), &target.listen_addr().unwrap().to_string()).await.unwrap();
    assert!(matches!(source.recv_control().await.unwrap(), ControlEvent::PeerConnected { privileged: false, .. }));
    if queued_price_rise {
        while !matches!(target.recv_control().await.unwrap(), ControlEvent::PeerConnected { .. }) {}
        crate::delivery_prices::send_price_frame(&target, db.as_ref(), alice.node_id(), &Frame::PriceTable {
            prices: std::collections::HashMap::from([("communication".into(), 100)]),
            block_height: 1, valid_blocks: 10, trust_discount: 0.0,
        }, &MutableDeliveryPrice(std::sync::atomic::AtomicU64::new(100))).await.unwrap();
        assert!(matches!(source.recv_control().await.unwrap(), ControlEvent::PriceTableReceived { .. }));
    }
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let hash = wallet.inject_inbound_keysend(100, None).await;
    let payment = wallet.get_payment_status(&hash).await.unwrap();
    let proof = PaymentProof::new(hex::decode(&hash).unwrap().try_into().unwrap(),
        hex::decode(payment.preimage.unwrap()).unwrap().try_into().unwrap(), 100);
    let sessions_a = SessionManager::new(alice.clone());
    let sessions_b = Arc::new(SessionManager::new(bob.clone()));
    establish_sessions(&sessions_a, &sessions_b, &alice, &bob).await;
    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(
        &sessions_a.encrypt(bob.node_id(), b"paid exactly once").await.unwrap());
    let mut env = UkmEnvelopeBuilder::new(konsensus_core::kind::KIND_CHAT, *alice.node_id(), Recipient::Node(*bob.node_id()), ciphertext, proof).build();
    env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
    let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (ws_tx, mut ws_rx) = broadcast::channel(8);
    let pricing = Arc::new(MutableDeliveryPrice(std::sync::atomic::AtomicU64::new(100)));
    let worker = tokio::spawn(run(MsgHandlerDeps {
        transport: target.clone(), transport_ack: target.clone(), storage: storage.clone(),
        gate: Arc::new(PaymentGate::with_config(konsensus_core::gate::GateConfig {
            verify_lightning_settlement: true, ..Default::default()
        })),
        pricing: pricing.clone(),
        lightning: wallet, chain: Arc::new(konsensus_chain::MockChainProvider::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        session_manager: sessions_b, nonce_adapter: Arc::new(konsensus_storage::StorageNonceAdapter::new(storage)),
        content_server: None, front_door: Default::default(), routing: Arc::new(RoutingTable::new(Default::default())),
        identity: bob.clone(), plaintext_cipher: Arc::new(PlaintextCacheCipher::new(bob.aes_key())),
        ws_tx, audit_log: audit.clone(), admission_mode: ReachabilityMode::PriceOpen,
        relay_engine: None, shutdown_rx,
    }));
    if queued_price_rise { pricing.0.store(1000, std::sync::atomic::Ordering::SeqCst); }
    if legacy {
        db.store_payment_receipt(&env.payment_proof.payment_hash, &env.sender, &env.id).await.unwrap();
        db.store_nonce(&env.nonce, &env.sender).await.unwrap();
        let mut forged = env.clone(); forged.signature = Signature::from_bytes([0; 64]);
        source.send(bob.node_id(), &forged).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while audit.membrane().read(None, 100).0.first().is_none_or(|e| e.code != konsensus_api::membrane::Code::BadSignature) {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert!(db.get_message(&env.id).await.unwrap().is_none());
        assert!(!target.connected_privileged_peers().await.contains(alice.node_id()));
    }
    sqlx::query("CREATE TRIGGER fail_message BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
        .execute(db.pool()).await.unwrap();
    source.send(bob.node_id(), &env).await.unwrap();
    let rejected = tokio::time::timeout(Duration::from_secs(5), source.recv_control()).await.unwrap().unwrap();
    assert!(matches!(rejected, ControlEvent::MessageRejected { reason, .. } if reason == "storage error"));
    assert_eq!(db.has_nonce(&env.nonce).await.unwrap(), legacy);
    assert_eq!(audit.membrane().read(None, 100).1.admitted, 0);
    assert!(!target.connected_privileged_peers().await.contains(alice.node_id()));
    sqlx::query("DROP TRIGGER fail_message").execute(db.pool()).await.unwrap();
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
    }).await.unwrap();
    assert!(matches!(ack, ControlEvent::MessageAcked { duplicate: false, .. }));
    let message = tokio::time::timeout(Duration::from_secs(5), ws_rx.recv()).await.unwrap().unwrap();
    assert_eq!(message.plaintext.as_deref(), Some("paid exactly once"));
    assert_eq!(audit.membrane().read(None, 100).1.admitted, 1);
    assert!(target.connected_privileged_peers().await.contains(alice.node_id()));
    if retained {
        assert_eq!(db.delete_messages_older_than(env.timestamp + 1).await.unwrap(), 1);
        let path = dir.path().join("sender.sqlite");
        let sender_db = konsensus_storage::SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
        sender_db.store_message(&env).await.unwrap();
        sender_db.prepare_delivery(&env.id, bob.node_id()).await.unwrap();
        sender_db.pool().close().await;
        let reopened = konsensus_storage::SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
        env = reopened.get_message(&env.id).await.unwrap().unwrap();
        env.timestamp += 1;
        env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
        reopened.update_message_wrapper(&env).await.unwrap();
        assert_eq!(reopened.get_pending_for_peer(bob.node_id()).await.unwrap().len(), 1);
    }
    if price_rise { pricing.0.store(1000, std::sync::atomic::Ordering::SeqCst); }
    // Treat the first ACK as dropped. Reconnect so a second promotion would be observable.
    source.disconnect(bob.node_id()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while target.is_connected(alice.node_id()).await { tokio::task::yield_now().await; }
    }).await.unwrap();
    source.connect(bob.node_id(), &target.listen_addr().unwrap().to_string()).await.unwrap();
    while !matches!(source.recv_control().await.unwrap(), ControlEvent::PeerConnected { .. }) {}
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
    }).await.unwrap();
    assert!(matches!(ack, ControlEvent::MessageAcked { duplicate: true, .. }));
    assert!(!target.connected_privileged_peers().await.contains(alice.node_id()));
    assert!(ws_rx.try_recv().is_err());
    assert_eq!(audit.membrane().read(None, 100).1.admitted, 1);
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM messages").fetch_one(db.pool()).await.unwrap(), if retained { 0 } else { 1 });
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM payment_receipts").fetch_one(db.pool()).await.unwrap(), 1);
    // Even a previously accepted id must still pass full signature validation.
    let mut tampered = env.clone(); tampered.signature = Signature::from_bytes([0; 64]);
    source.send(bob.node_id(), &tampered).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while audit.membrane().read(None, 100).0.first().unwrap().code != konsensus_api::membrane::Code::BadSignature { tokio::task::yield_now().await; }
    }).await.unwrap();
    assert!(!target.connected_privileged_peers().await.contains(alice.node_id()));
    assert!(ws_rx.try_recv().is_err());
    pricing.0.store(100, std::sync::atomic::Ordering::SeqCst);
    // A different valid id cannot reuse that payment or be promoted.
    let mut reused = UkmEnvelopeBuilder::new(env.kind, env.sender, env.recipient, vec![8], env.payment_proof.clone()).build();
    reused.signature = Signature::from_ed25519(&alice.sign(&reused.signable_bytes()));
    source.send(bob.node_id(), &reused).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while audit.membrane().read(None, 100).0.first().unwrap().code != konsensus_api::membrane::Code::ProofReused { tokio::task::yield_now().await; }
    }).await.unwrap();
    assert!(!target.connected_privileged_peers().await.contains(alice.node_id()));
    shutdown.send(true).unwrap(); worker.await.unwrap(); source.shutdown(); target.shutdown();
}

/// An offered price is a recipient-side contract, not an arbitrary claim in a
/// refreshed envelope. A fresh inbound settlement binds its time and amount.
#[tokio::test]
async fn queued_paid_proof_honours_offered_price_before_acceptance() {
    use konsensus_core::gate::GateConfig;
    let alice = alice_identity(); let bob = bob_identity();
    let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("quotes.sqlite");
    let db = Arc::new(konsensus_storage::SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
    let wallet = konsensus_lightning::MockLightningProvider::new();
    let hash = wallet.inject_inbound_keysend(100, None).await;
    let paid = wallet.get_payment_status(&hash).await.unwrap();
    db.record_delivery_prices(alice.node_id(), &[("category:communication".into(), 100)], &[1], paid.timestamp.saturating_sub(1), paid.timestamp + 3599).await.unwrap();
    db.pool().close().await;
    let db = Arc::new(konsensus_storage::SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
    let proof = PaymentProof::new(hex::decode(hash).unwrap().try_into().unwrap(), hex::decode(paid.preimage.unwrap()).unwrap().try_into().unwrap(), 100);
    let mut env = UkmEnvelopeBuilder::new(0, *alice.node_id(), Recipient::Node(*bob.node_id()), vec![1], proof).build();
    env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
    let gate = PaymentGate::with_config(GateConfig { verify_lightning_settlement: true, ..Default::default() });
    let nonce = konsensus_storage::StorageNonceAdapter::new(db.clone());
    let pricing = MutableDeliveryPrice(std::sync::atomic::AtomicU64::new(1000));
    let registry = tokio::sync::RwLock::new(PeerRegistry::new());
    let membrane = konsensus_api::membrane::Membrane::default();
    let result = whitelist_then_verify(&env, &membrane, &registry, &gate, &nonce, &pricing,
        Some(&wallet), 0.0, Some(bob.node_id()), konsensus_message::ReachabilityMode::PriceOpen, false).await;
    assert!(result.is_ok(), "a queued paid proof retains the recipient's unexpired offered price: {result:?}");
    assert!(db.get_message(&env.id).await.unwrap().is_none(), "validation must not consume the paid identity");
    assert!(!db.has_nonce(&env.nonce).await.unwrap());
    for case in ["underpaid", "wrong_kind", "wrong_sender", "wrong_recipient", "unknown_proof"] {
        let mut invalid = env.clone();
        match case {
            "underpaid" => invalid.payment_proof.amount_msat = 1,
            "wrong_kind" => invalid.kind = 200,
            "wrong_sender" => invalid.sender = *bob.node_id(),
            "wrong_recipient" => invalid.recipient = Recipient::Node(*alice.node_id()),
            _ => invalid.payment_proof = make_valid_proof(100),
        }
        let signer = if case == "wrong_sender" { &bob } else { &alice };
        invalid.signature = Signature::from_ed25519(&signer.sign(&invalid.signable_bytes()));
        assert!(whitelist_then_verify(&invalid, &membrane, &registry, &gate, &nonce, &pricing,
            Some(&wallet), 0.0, Some(bob.node_id()), konsensus_message::ReachabilityMode::PriceOpen, false).await.is_err(), "{case}");
    }
    sqlx::query("UPDATE delivery_price_quotes SET expires_at = issued_at").execute(db.pool()).await.unwrap();
    env.timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
    assert!(whitelist_then_verify(&env, &membrane, &registry, &gate, &nonce, &pricing,
        Some(&wallet), 0.0, Some(bob.node_id()), konsensus_message::ReachabilityMode::PriceOpen, false).await.is_err(), "renewing the wrapper cannot renew an expired offer");
}

#[tokio::test]
async fn category_offer_binds_original_kind_exclusion_after_tariffs_converge() {
    category_offer_kind_transition(2000, 3000, 3000, false).await;
}

#[tokio::test]
async fn category_offer_binds_original_kind_inclusion_after_tariffs_diverge() {
    category_offer_kind_transition(1000, 2000, 3000, true).await;
}

async fn category_offer_kind_transition(old_longform: u64, new_chat: u64, new_longform: u64, allowed: bool) {
    use konsensus_core::traits::pricing::PricingEngine;
    let alice = alice_identity(); let bob = bob_identity();
    let db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let transport = |id| Arc::new(NoiseTransport::new(id, konsensus_message::TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(), admission_mode: konsensus_message::ReachabilityMode::PriceOpen, ..Default::default()
    }));
    let payer = transport(alice.clone()); let payee = transport(bob.clone());
    payee.start_listener().await.unwrap();
    payer.connect(bob.node_id(), &payee.listen_addr().unwrap().to_string()).await.unwrap();
    payer.recv_control().await.unwrap(); payee.recv_control().await.unwrap();
    let old = konsensus_pricing::StaticPricingEngine::new(konsensus_pricing::StaticPricingConfig { chat_msat: 1000, longform_msat: old_longform, ..Default::default() });
    assert_eq!(old.get_price_msat(konsensus_core::kind::KIND_LONGFORM).await.unwrap(), old_longform);
    let frame = Frame::PriceTable { prices: konsensus_pricing::peer_prices::build_price_table(&old).await, block_height: 1, valid_blocks: 10, trust_discount: 0.0 };
    crate::delivery_prices::send_price_frame(&payee, db.as_ref(), alice.node_id(), &frame, &old).await.unwrap();
    assert!(matches!(payer.recv_control().await.unwrap(), konsensus_message::ControlEvent::PriceTableReceived { .. }));
    let wallet = konsensus_lightning::MockLightningProvider::new();
    let hash = wallet.inject_inbound_keysend(1000, None).await;
    let details = wallet.get_payment_status(&hash).await.unwrap();
    let proof = PaymentProof::new(hex::decode(hash).unwrap().try_into().unwrap(), hex::decode(details.preimage.unwrap()).unwrap().try_into().unwrap(), 1000);
    let mut env = UkmEnvelopeBuilder::new(konsensus_core::kind::KIND_LONGFORM, *alice.node_id(), Recipient::Node(*bob.node_id()), vec![1], proof).build();
    env.signature = Signature::from_ed25519(&alice.sign(&env.signable_bytes()));
    let new = konsensus_pricing::StaticPricingEngine::new(konsensus_pricing::StaticPricingConfig { chat_msat: new_chat, longform_msat: new_longform, ..Default::default() });
    let gate = PaymentGate::with_config(konsensus_core::gate::GateConfig { verify_lightning_settlement: true, ..Default::default() });
    let nonce = konsensus_storage::StorageNonceAdapter::new(db);
    let result = gate.validate_received_paid_envelope(&env, &nonce, &new, None, Some(&wallet), 0.0, Some(bob.node_id())).await;
    payer.shutdown(); payee.shutdown();
    assert_eq!(result.is_ok(), allowed, "the original offer's kind eligibility is immutable: {result:?}");
}

#[tokio::test]
async fn discounted_kind_offer_survives_price_rise() {
    for (raw_price, discount, expected) in [(2000, 0.5, 1000), (2001, 0.25, 1501)] {
        discounted_kind_offer_case(raw_price, discount, expected).await;
    }
}

async fn discounted_kind_offer_case(raw_price: u64, discount: f64, expected: u64) {
    use konsensus_core::gate::GateConfig;
    use konsensus_core::kind::KIND_LONGFORM;
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
    let raw_kind_price = old.get_price_msat(KIND_LONGFORM).await.unwrap();
    crate::delivery_prices::send_price_frame(
        &target,
        db.as_ref(),
        alice.node_id(),
        &Frame::PriceResponse {
            kind: KIND_LONGFORM,
            price_msat: raw_kind_price,
            block_height: 1,
        },
        &old,
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
    let offered = cache
        .get_fresh_discounted_peer_price(
            bob.node_id(),
            KIND_LONGFORM,
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
    let hash = wallet.inject_inbound_keysend(offered, None).await;
    let settled = wallet.get_payment_status(&hash).await.unwrap();
    let proof = PaymentProof::new(
        hex::decode(hash).unwrap().try_into().unwrap(),
        hex::decode(settled.preimage.unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        offered,
    );
    let mut env = UkmEnvelopeBuilder::new(
        KIND_LONGFORM,
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
    let transport = |id| Arc::new(NoiseTransport::new(id, TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        admission_mode: ReachabilityMode::PriceOpen, ..Default::default()
    }));
    let source = transport(alice.clone());
    let target = transport(bob.clone());
    target.start_listener().await.unwrap();
    let db = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let storage: Arc<dyn Storage> = db.clone();
    source.connect(bob.node_id(), &target.listen_addr().unwrap().to_string()).await.unwrap();
    while !matches!(source.recv_control().await.unwrap(), ControlEvent::PeerConnected { .. }) {}
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let sessions_a = SessionManager::new(alice.clone());
    let sessions_b = Arc::new(SessionManager::new(bob.clone()));
    establish_sessions(&sessions_a, &sessions_b, &alice, &bob).await;
    let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (ws_tx, mut ws_rx) = broadcast::channel(16);
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> =
        Arc::new(konsensus_pricing::StaticPricingEngine::new(Default::default()));
    let worker = tokio::spawn(run(MsgHandlerDeps {
        transport: target.clone(), transport_ack: target.clone(), storage: storage.clone(),
        gate: Arc::new(PaymentGate::with_config(konsensus_core::gate::GateConfig {
            verify_lightning_settlement: true, ..Default::default()
        })),
        pricing,
        lightning: wallet.clone(), chain: Arc::new(konsensus_chain::MockChainProvider::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        session_manager: sessions_b, nonce_adapter: Arc::new(konsensus_storage::StorageNonceAdapter::new(storage)),
        content_server: None, front_door: Default::default(), routing: Arc::new(RoutingTable::new(Default::default())),
        identity: bob.clone(), plaintext_cipher: Arc::new(PlaintextCacheCipher::new(bob.aes_key())),
        ws_tx, audit_log: audit, admission_mode: ReachabilityMode::PriceOpen,
        relay_engine: None, shutdown_rx,
    }));

    // Alice pays `msat` to Bob and sends one signal of `kind`.
    let signal = |kind: u16, msat: u64, body: String| {
        let (wallet, sessions_a, alice, bob) = (wallet.clone(), &sessions_a, alice.clone(), bob.clone());
        async move {
            let hash = wallet.inject_inbound_keysend(msat, None).await;
            let payment = wallet.get_payment_status(&hash).await.unwrap();
            let proof = PaymentProof::new(hex::decode(&hash).unwrap().try_into().unwrap(),
                hex::decode(payment.preimage.unwrap()).unwrap().try_into().unwrap(), msat);
            let ciphertext = konsensus_crypto::ratchet_message_to_bytes(
                &sessions_a.encrypt(bob.node_id(), body.as_bytes()).await.unwrap());
            let mut env = UkmEnvelopeBuilder::new(kind, *alice.node_id(), Recipient::Node(*bob.node_id()), ciphertext, proof).build();
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
        }).await.unwrap()
    };
    let id = format!("{:032x}", rand::random::<u128>());
    let offer = format!(r#"{{"v":1,"call_id":"{id}","media":"audio","sdp":"v=0\r\no=- 1 1 IN IP4 127.0.0.1"}}"#);

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
    let rung = tokio::time::timeout(Duration::from_secs(5), ws_rx.recv()).await.unwrap().unwrap();
    assert_eq!((rung.envelope.kind, rung.plaintext.as_deref()), (400, Some(offer.as_str())));
    // Now a paid peer: an underpaid offer for another call is refused openly.
    let under = format!(r#"{{"v":1,"call_id":"{:032x}","media":"video","sdp":"v=0"}}"#, rand::random::<u128>());
    let env_under = signal(400, 9_999, under).await;
    source.send(bob.node_id(), &env_under).await.unwrap();
    assert!(outcome(source.clone()).await.unwrap_err().to_lowercase().contains("insufficient"));
    assert!(ws_rx.try_recv().is_err());
    // The same envelope again is a duplicate: acked, never forwarded twice.
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Ok(true));
    // A freshly paid offer reusing the call id is a replay: refused.
    let env = signal(400, 10_000, offer.clone()).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert!(outcome(source.clone()).await.unwrap_err().contains("replayed"));
    assert!(ws_rx.try_recv().is_err());
    // Codex P1: the refused signal is withdrawn (no history/resync), and a
    // resend of the very same paid envelope is refused, not duplicate-ACKed.
    assert!(db.get_message(&env.id).await.unwrap().is_none());
    assert!(!db.is_paid_envelope_accepted(&env).await.unwrap());
    source.send(bob.node_id(), &env).await.unwrap();
    assert!(outcome(source.clone()).await.is_err());
    assert!(ws_rx.try_recv().is_err());

    // Alice made the offer, so an answer from Alice is from the wrong side.
    let env = signal(401, 50, format!(r#"{{"v":1,"call_id":"{id}","sdp":"v=0"}}"#)).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert!(outcome(source.clone()).await.is_err());
    // ICE for this live call reaches the app; ICE for an unknown call does not.
    let ice = |call: &str| format!(r#"{{"v":1,"call_id":"{call}","candidate":"candidate:1 1 udp 2130706431 127.0.0.1 9 typ host","sdp_mid":"0","sdp_mline_index":0}}"#);
    let env = signal(402, 50, ice(&id)).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Ok(false));
    assert_eq!(tokio::time::timeout(Duration::from_secs(5), ws_rx.recv()).await.unwrap().unwrap().envelope.kind, 402);
    let other = format!("{:032x}", rand::random::<u128>());
    let env = signal(402, 50, ice(&other)).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert!(outcome(source.clone()).await.unwrap_err().contains("no live call"));
    // Hangup ends it; later ICE for that call is refused.
    let env = signal(403, 50, format!(r#"{{"v":1,"call_id":"{id}","reason":"hangup"}}"#)).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert_eq!(outcome(source.clone()).await, Ok(false));
    assert_eq!(tokio::time::timeout(Duration::from_secs(5), ws_rx.recv()).await.unwrap().unwrap().envelope.kind, 403);
    let env = signal(402, 50, ice(&id)).await;
    source.send(bob.node_id(), &env).await.unwrap();
    assert!(outcome(source.clone()).await.is_err());
    assert!(ws_rx.try_recv().is_err());
    shutdown.send(true).unwrap(); worker.await.unwrap(); source.shutdown(); target.shutdown();
}
