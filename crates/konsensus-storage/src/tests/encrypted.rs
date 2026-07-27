use super::*;
use crate::sqlite::SqliteStorage;
use crate::InviteState;
use konsensus_core::kind::KIND_CHAT;
use konsensus_core::PaymentProof;
use sha2::{Digest, Sha256};

fn make_proof() -> PaymentProof {
    let preimage = [42u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    PaymentProof::new(hash, preimage, 10)
}

#[tokio::test]
async fn encrypt_decrypt_roundtrip() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let original_ct = b"secret message content".to_vec();

    let envelope = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        sender,
        recipient,
        original_ct.clone(),
        make_proof(),
    )
    .timestamp(1_700_000_000_000)
    .build();

    let msg_id = envelope.id;

    store.store_message(&envelope).await.unwrap();

    // Retrieve through encrypted layer — should get original ciphertext back
    let retrieved = store.get_message(&msg_id).await.unwrap().unwrap();
    assert_eq!(retrieved.ciphertext, original_ct);
    assert_eq!(retrieved.id, msg_id);
    assert_eq!(retrieved.sender, sender);

    // Verify the raw storage has encrypted (different) ciphertext
    let raw = store.inner().get_message(&msg_id).await.unwrap().unwrap();
    assert_ne!(raw.ciphertext, original_ct);
    assert!(raw.ciphertext.len() > original_ct.len()); // nonce + tag overhead
}

#[tokio::test]
async fn encrypted_pagination() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));

    for i in 0..3u64 {
        let ct = format!("message {i}").into_bytes();
        let env =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, ct, make_proof())
                .timestamp(1_700_000_000_000 + i * 1000)
                .build();
        store.store_message(&env).await.unwrap();
    }

    let msgs = store
        .get_messages_for_recipient(&recipient, 10, None)
        .await
        .unwrap();
    assert_eq!(msgs.len(), 3);
    // Should be decrypted properly
    assert!(msgs[0].ciphertext.starts_with(b"message"));
}

#[tokio::test]
async fn wrong_key_fails_to_decrypt() {
    // Store with key A, then try to read with key B
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key_a = [7u8; 32];
    let store_a = EncryptedStorage::new(sqlite, &key_a);

    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let original_ct = b"secret data".to_vec();

    let envelope = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        sender,
        recipient,
        original_ct,
        make_proof(),
    )
    .timestamp(1_700_000_000_000)
    .build();

    let msg_id = envelope.id;
    store_a.store_message(&envelope).await.unwrap();

    // Destructure to get the inner SQLite storage back
    let sqlite_inner = store_a.inner;

    // Wrap with a different key
    let key_b = [8u8; 32];
    let store_b = EncryptedStorage::new(sqlite_inner, &key_b);
    let result = store_b.get_message(&msg_id).await;
    // Decryption must fail with wrong key
    assert!(result.is_err(), "wrong key should fail to decrypt");
}

#[tokio::test]
async fn encrypted_delete() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [9u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));

    let envelope = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        sender,
        recipient,
        b"to be deleted".to_vec(),
        make_proof(),
    )
    .timestamp(1_700_000_000_000)
    .build();

    let msg_id = envelope.id;
    store.store_message(&envelope).await.unwrap();
    assert!(store.get_message(&msg_id).await.unwrap().is_some());

    let deleted = store.delete_message(&msg_id).await.unwrap();
    assert!(deleted);
    assert!(store.get_message(&msg_id).await.unwrap().is_none());
}

#[test]
fn encrypt_decrypt_raw() {
    let key = [42u8; 32];
    let sqlite_dummy_key = key;
    // Direct test of encrypt/decrypt without storage
    let cipher =
        Aes256Gcm::new_from_slice(&sqlite_dummy_key).unwrap();
    let wrapper = EncryptedStorage {
        inner: (), // won't be used
        cipher,
        peer_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let plaintext = b"Principle 4: no plaintext at any layer";
    let encrypted = wrapper.encrypt(plaintext).unwrap();
    assert_ne!(&encrypted[12..], plaintext); // ciphertext differs
    let decrypted = wrapper.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ── Edge case tests ───────────────────────────────────────────────

#[test]
fn decrypt_truncated_data_too_short() {
    // Data shorter than 12 bytes (nonce size) — should fail
    let key = [42u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let wrapper = EncryptedStorage {
        inner: (),
        cipher,
        peer_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let result = wrapper.decrypt(&[1, 2, 3, 4, 5]);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("too short"), "got: {err}");
}

#[test]
fn decrypt_exactly_12_bytes_nonce_only() {
    // Exactly 12 bytes = nonce but zero ciphertext — AEAD decryption fails
    let key = [42u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let wrapper = EncryptedStorage {
        inner: (),
        cipher,
        peer_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let result = wrapper.decrypt(&[0u8; 12]);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("decrypt"), "got: {err}");
}

#[test]
fn decrypt_corrupted_aead_tag() {
    // Encrypt valid data, then corrupt the AEAD tag
    let key = [42u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let wrapper = EncryptedStorage {
        inner: (),
        cipher,
        peer_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let plaintext = b"sensitive data";
    let mut encrypted = wrapper.encrypt(plaintext).unwrap();

    // Flip last byte (part of the AEAD tag)
    let last = encrypted.len() - 1;
    encrypted[last] ^= 0xFF;

    let result = wrapper.decrypt(&encrypted);
    assert!(result.is_err(), "corrupted AEAD tag should fail decryption");
}

#[test]
fn decrypt_corrupted_nonce() {
    // Encrypt valid data, then corrupt the nonce
    let key = [42u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let wrapper = EncryptedStorage {
        inner: (),
        cipher,
        peer_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let plaintext = b"sensitive data";
    let mut encrypted = wrapper.encrypt(plaintext).unwrap();

    // Flip first byte of nonce
    encrypted[0] ^= 0xFF;

    let result = wrapper.decrypt(&encrypted);
    assert!(result.is_err(), "corrupted nonce should fail decryption");
}

#[test]
fn encrypt_empty_plaintext() {
    // Empty plaintext should still encrypt/decrypt successfully
    let key = [42u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let wrapper = EncryptedStorage {
        inner: (),
        cipher,
        peer_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let encrypted = wrapper.encrypt(b"").unwrap();
    // Should be 12 (nonce) + 16 (AEAD tag) = 28 bytes minimum
    assert_eq!(encrypted.len(), 28);

    let decrypted = wrapper.decrypt(&encrypted).unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn encrypt_produces_different_ciphertext_each_time() {
    // Random nonce means same plaintext produces different ciphertext
    let key = [42u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let wrapper = EncryptedStorage {
        inner: (),
        cipher,
        peer_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let plaintext = b"same plaintext";
    let enc1 = wrapper.encrypt(plaintext).unwrap();
    let enc2 = wrapper.encrypt(plaintext).unwrap();

    // Nonces should differ (random), so ciphertexts differ
    assert_ne!(enc1, enc2);

    // But both decrypt to the same plaintext
    let dec1 = wrapper.decrypt(&enc1).unwrap();
    let dec2 = wrapper.decrypt(&enc2).unwrap();
    assert_eq!(dec1, dec2);
    assert_eq!(dec1, plaintext);
}

#[tokio::test]
async fn onboarding_state_encrypted_wrapper_passthrough() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [21u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let expected = OnboardingStateRecord {
        invite_id: None,
        inviter_pubkey: Some([7u8; 32]),
        inviter_ln_pubkey: Some("02abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678ab".into()),
        current_step: "funding".into(),
        tier: Some("full".into()),
        funding_address: Some("bcrt1qexample".into()),
        funding_amount_sats_required: Some(42_000),
        funding_amount_sats_received: 1_000,
        last_poll_at: Some(1_700_000_123),
        funding_evidence: Some("wallet_balance_observed".into()),
    };

    store.upsert_onboarding_state(&expected).await.unwrap();
    let got = store.get_onboarding_state().await.unwrap().unwrap();
    assert_eq!(got, expected);
}

#[test]
fn decrypt_empty_data() {
    // Completely empty data — too short for nonce
    let key = [42u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let wrapper = EncryptedStorage {
        inner: (),
        cipher,
        peer_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let result = wrapper.decrypt(&[]);
    assert!(result.is_err());
}

// ── Metadata encryption tests ──────────────────────────────────────

#[test]
fn encrypt_decrypt_string_roundtrip() {
    let key = [42u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let wrapper = EncryptedStorage {
        inner: (),
        cipher,
        peer_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let original = "192.0.2.11:9736";
    let encrypted = wrapper.encrypt_string(original).unwrap();
    // Encrypted should be a hex string, not the original
    assert_ne!(encrypted, original);
    assert!(encrypted.len() > original.len());
    let decrypted = wrapper.decrypt_string(&encrypted).unwrap();
    assert_eq!(decrypted, original);
}

#[test]
fn encrypt_opt_string_none_stays_none() {
    let key = [42u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let wrapper = EncryptedStorage {
        inner: (),
        cipher,
        peer_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let result = wrapper.encrypt_opt_string(&None).unwrap();
    assert!(result.is_none());
    let result = wrapper.decrypt_opt_string(&None).unwrap();
    assert!(result.is_none());
}

#[test]
fn encrypt_opt_string_some_roundtrips() {
    let key = [42u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let wrapper = EncryptedStorage {
        inner: (),
        cipher,
        peer_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let original = Some("Alice".to_string());
    let encrypted = wrapper.encrypt_opt_string(&original).unwrap();
    assert!(encrypted.is_some());
    assert_ne!(encrypted.as_deref(), Some("Alice"));
    let decrypted = wrapper.decrypt_opt_string(&encrypted).unwrap();
    assert_eq!(decrypted, original);
}

#[test]
fn encrypt_json_roundtrip() {
    let key = [42u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let wrapper = EncryptedStorage {
        inner: (),
        cipher,
        peer_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let original = serde_json::json!({"role": "admin", "notes": "trusted peer"});
    let encrypted = wrapper.encrypt_json(&original).unwrap();
    // Encrypted should be a JSON string containing hex
    assert!(encrypted.is_string());
    let decrypted = wrapper.decrypt_json(&encrypted).unwrap();
    assert_eq!(decrypted, original);
}

#[test]
fn encrypt_json_empty_object() {
    let key = [42u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let wrapper = EncryptedStorage {
        inner: (),
        cipher,
        peer_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let original = serde_json::json!({});
    let encrypted = wrapper.encrypt_json(&original).unwrap();
    let decrypted = wrapper.decrypt_json(&encrypted).unwrap();
    assert_eq!(decrypted, original);
}

#[test]
fn decrypt_json_unencrypted_passthrough() {
    // Non-string JSON values pass through as-is (backward compat)
    let key = [42u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let wrapper = EncryptedStorage {
        inner: (),
        cipher,
        peer_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let original = serde_json::json!({"key": "value"});
    let result = wrapper.decrypt_json(&original).unwrap();
    assert_eq!(result, original);
}

#[tokio::test]
async fn peer_metadata_encrypted_at_rest() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let node_id = NodeId::from_bytes([1u8; 32]);
    let mut peer = Peer::new(node_id);
    peer.address = Some("192.0.2.11:9736".to_string());
    peer.display_name = Some("Alpha Node".to_string());
    peer.metadata = serde_json::json!({"tier": "full"});

    store.upsert_peer(&peer).await.unwrap();

    // Read through encrypted layer — should get original values
    let retrieved = store.get_peer(&node_id).await.unwrap().unwrap();
    assert_eq!(retrieved.address.as_deref(), Some("192.0.2.11:9736"));
    assert_eq!(retrieved.display_name.as_deref(), Some("Alpha Node"));
    assert_eq!(retrieved.metadata, serde_json::json!({"tier": "full"}));

    // Read raw — should be encrypted (not plaintext)
    let raw = store.inner().get_peer(&node_id).await.unwrap().unwrap();
    assert_ne!(raw.address.as_deref(), Some("192.0.2.11:9736"));
    assert_ne!(raw.display_name.as_deref(), Some("Alpha Node"));
    // Raw metadata should be a string (hex-encoded encrypted), not an object
    assert!(raw.metadata.is_string());
}

#[tokio::test]
async fn peer_list_decrypted() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    for i in 0..3u8 {
        let mut peer = Peer::new(NodeId::from_bytes([i + 1; 32]));
        peer.display_name = Some(format!("Node {i}"));
        store.upsert_peer(&peer).await.unwrap();
    }

    let peers = store.list_peers().await.unwrap();
    assert_eq!(peers.len(), 3);
    for (i, p) in peers.iter().enumerate() {
        assert_eq!(
            p.display_name.as_deref(),
            Some(format!("Node {i}").as_str())
        );
    }
}

#[tokio::test]
async fn room_metadata_encrypted_at_rest() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let creator = NodeId::from_bytes([1u8; 32]);
    let mut room = Room::new("Engineering Team".to_string(), creator);
    room.metadata = serde_json::json!({"description": "Private engineering channel"});

    store.create_room(&room).await.unwrap();

    // Read through encrypted layer
    let retrieved = store.get_room(&room.id).await.unwrap().unwrap();
    assert_eq!(retrieved.name, "Engineering Team");
    assert_eq!(
        retrieved.metadata,
        serde_json::json!({"description": "Private engineering channel"})
    );

    // Read raw — should be encrypted
    let raw = store.inner().get_room(&room.id).await.unwrap().unwrap();
    assert_ne!(raw.name, "Engineering Team");
    assert!(raw.metadata.is_string());
}

#[tokio::test]
async fn room_list_decrypted() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let creator = NodeId::from_bytes([1u8; 32]);
    for name in ["Alpha", "Beta", "Gamma"] {
        let room = Room::new(name.to_string(), creator);
        store.create_room(&room).await.unwrap();
    }

    let rooms = store.list_rooms().await.unwrap();
    assert_eq!(rooms.len(), 3);
    let names: Vec<&str> = rooms.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"Alpha"));
    assert!(names.contains(&"Beta"));
    assert!(names.contains(&"Gamma"));
}

#[tokio::test]
async fn file_metadata_encrypted_at_rest() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let file = FileRecord {
        id: "file-001".into(),
        filename: "confidential_report.pdf".into(),
        mime_type: "application/pdf".into(),
        size_bytes: 12345,
        blake3_hash: "ab".repeat(32),
        sender: "cc".repeat(32),
        message_id: None,
        data: vec![1, 2, 3, 4, 5],
        created_at: "2026-03-31T00:00:00Z".into(),
    };

    store.store_file(&file).await.unwrap();

    // Read through encrypted layer — original values
    let retrieved = store.get_file("file-001").await.unwrap().unwrap();
    assert_eq!(retrieved.filename, "confidential_report.pdf");
    assert_eq!(retrieved.mime_type, "application/pdf");
    assert_eq!(retrieved.data, vec![1, 2, 3, 4, 5]);

    // Read raw — filename, mime_type, and bytes encrypted
    let raw = store.inner().get_file("file-001").await.unwrap().unwrap();
    assert_ne!(raw.filename, "confidential_report.pdf");
    assert_ne!(raw.mime_type, "application/pdf");
    assert_ne!(raw.data, vec![1, 2, 3, 4, 5]);
    assert!(
        raw.data.len() > 5,
        "encrypted file bytes should include nonce + authentication tag"
    );
}

#[tokio::test]
async fn file_metadata_list_decrypted() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let file = FileRecord {
        id: "file-002".into(),
        filename: "photo.jpg".into(),
        mime_type: "image/jpeg".into(),
        size_bytes: 5000,
        blake3_hash: "dd".repeat(32),
        sender: "ee".repeat(32),
        message_id: None,
        data: vec![0xFF, 0xD8],
        created_at: "2026-03-31T01:00:00Z".into(),
    };

    store.store_file(&file).await.unwrap();

    // list_files returns FileMetadata (no data)
    let files = store.list_files(10).await.unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].filename, "photo.jpg");
    assert_eq!(files[0].mime_type, "image/jpeg");

    // get_file_metadata also decrypts
    let meta = store.get_file_metadata("file-002").await.unwrap().unwrap();
    assert_eq!(meta.filename, "photo.jpg");
    assert_eq!(meta.mime_type, "image/jpeg");
}

#[tokio::test]
async fn wrong_key_fails_peer_decrypt() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key_a = [7u8; 32];
    let store_a = EncryptedStorage::new(sqlite, &key_a);

    let node_id = NodeId::from_bytes([1u8; 32]);
    let mut peer = Peer::new(node_id);
    peer.display_name = Some("Secret Name".to_string());
    store_a.upsert_peer(&peer).await.unwrap();

    // Get the inner storage and wrap with different key
    let sqlite_inner = store_a.inner;
    let key_b = [8u8; 32];
    let store_b = EncryptedStorage::new(sqlite_inner, &key_b);

    let result = store_b.get_peer(&node_id).await;
    assert!(result.is_err(), "wrong key should fail to decrypt peer metadata");
}

// Dummy impl so we can test encrypt/decrypt without a real Storage
// ── Delete operations through encryption layer ──────────────────

#[tokio::test]
async fn encrypted_delete_room() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let creator = NodeId::from_bytes([1u8; 32]);
    let room = Room::new("Secret Room".to_string(), creator);
    let room_id = room.id;

    store.create_room(&room).await.unwrap();
    assert!(store.get_room(&room_id).await.unwrap().is_some());

    let deleted = store.delete_room(&room_id).await.unwrap();
    assert!(deleted);
    assert!(store.get_room(&room_id).await.unwrap().is_none());

    // Deleting again returns false
    let deleted_again = store.delete_room(&room_id).await.unwrap();
    assert!(!deleted_again);
}

#[tokio::test]
async fn encrypted_delete_peer() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let node_id = NodeId::from_bytes([5u8; 32]);
    let mut peer = Peer::new(node_id);
    peer.display_name = Some("Deletable Peer".to_string());
    peer.address = Some("10.0.0.1:9736".to_string());

    store.upsert_peer(&peer).await.unwrap();
    assert!(store.get_peer(&node_id).await.unwrap().is_some());

    let deleted = store.delete_peer(&node_id).await.unwrap();
    assert!(deleted);
    assert!(store.get_peer(&node_id).await.unwrap().is_none());

    // Verify it's gone from list too
    let peers = store.list_peers().await.unwrap();
    assert!(peers.is_empty());
}

#[tokio::test]
async fn encrypted_delete_file() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let file = FileRecord {
        id: "file-del-001".into(),
        filename: "secret_doc.pdf".into(),
        mime_type: "application/pdf".into(),
        size_bytes: 1024,
        blake3_hash: "ab".repeat(32),
        sender: "cc".repeat(32),
        message_id: None,
        data: vec![0xDE, 0xAD],
        created_at: "2026-04-01T00:00:00Z".into(),
    };

    store.store_file(&file).await.unwrap();
    assert!(store.get_file("file-del-001").await.unwrap().is_some());

    let deleted = store.delete_file("file-del-001").await.unwrap();
    assert!(deleted);
    assert!(store.get_file("file-del-001").await.unwrap().is_none());

    // Metadata also gone
    assert!(store.get_file_metadata("file-del-001").await.unwrap().is_none());
}

#[tokio::test]
async fn encrypted_delete_messages_older_than() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));

    // Store 3 messages: old, medium, recent
    for (i, ts) in [1_000_000u64, 2_000_000, 3_000_000].iter().enumerate() {
        let env = UkmEnvelopeBuilder::new(
            KIND_CHAT,
            sender,
            recipient,
            format!("msg {i}").into_bytes(),
            make_proof(),
        )
        .timestamp(*ts)
        .build();
        store.store_message(&env).await.unwrap();
    }

    let msgs = store
        .get_messages_for_recipient(&recipient, 10, None)
        .await
        .unwrap();
    assert_eq!(msgs.len(), 3);

    // Delete messages older than 2_500_000 (should delete first 2)
    let deleted = store.delete_messages_older_than(2_500_000).await.unwrap();
    assert_eq!(deleted, 2);

    let remaining = store
        .get_messages_for_recipient(&recipient, 10, None)
        .await
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].ciphertext, b"msg 2");
}

// ── Room membership through encryption layer ──────────────────────

#[tokio::test]
async fn encrypted_room_membership() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let creator = NodeId::from_bytes([1u8; 32]);
    let member_a = NodeId::from_bytes([2u8; 32]);
    let member_b = NodeId::from_bytes([3u8; 32]);

    let room = Room::new("Team Room".to_string(), creator);
    let room_id = room.id;
    store.create_room(&room).await.unwrap();

    // Add members
    store.add_room_member(&room_id, &member_a).await.unwrap();
    store.add_room_member(&room_id, &member_b).await.unwrap();

    // Verify members
    let members = store.get_room_members(&room_id).await.unwrap();
    assert_eq!(members.len(), 2);
    assert!(members.contains(&member_a));
    assert!(members.contains(&member_b));

    // Remove one member
    store.remove_room_member(&room_id, &member_a).await.unwrap();
    let members = store.get_room_members(&room_id).await.unwrap();
    assert_eq!(members.len(), 1);
    assert!(members.contains(&member_b));
    assert!(!members.contains(&member_a));
}

#[tokio::test]
async fn encrypted_room_members_empty_by_default() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let creator = NodeId::from_bytes([1u8; 32]);
    let room = Room::new("Empty Room".to_string(), creator);
    let room_id = room.id;
    store.create_room(&room).await.unwrap();

    let members = store.get_room_members(&room_id).await.unwrap();
    assert!(members.is_empty());
}

// ── File get through encryption layer ─────────────────────────────

#[tokio::test]
async fn encrypted_get_file_decrypts_metadata() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let file = FileRecord {
        id: "file-get-001".into(),
        filename: "contract.docx".into(),
        mime_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            .into(),
        size_bytes: 50_000,
        blake3_hash: "ff".repeat(32),
        sender: "aa".repeat(32),
        message_id: Some("msg-ref-001".into()),
        data: vec![0x50, 0x4B, 0x03, 0x04], // PK header
        created_at: "2026-04-01T12:00:00Z".into(),
    };

    store.store_file(&file).await.unwrap();

    // get_file returns full FileRecord with decrypted metadata
    let retrieved = store.get_file("file-get-001").await.unwrap().unwrap();
    assert_eq!(retrieved.filename, "contract.docx");
    assert_eq!(
        retrieved.mime_type,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    );
    assert_eq!(retrieved.data, vec![0x50, 0x4B, 0x03, 0x04]);
    assert_eq!(retrieved.size_bytes, 50_000);
    assert_eq!(retrieved.message_id.as_deref(), Some("msg-ref-001"));

    // get_file for nonexistent returns None
    assert!(store.get_file("no-such-file").await.unwrap().is_none());
}

// ── inner() accessor test ─────────────────────────────────────────

#[tokio::test]
async fn inner_accessor_returns_underlying_storage() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    // Store a peer through the encrypted layer
    let node_id = NodeId::from_bytes([9u8; 32]);
    let mut peer = Peer::new(node_id);
    peer.display_name = Some("Test Node".to_string());
    store.upsert_peer(&peer).await.unwrap();

    // inner() should give us access to the raw storage
    let raw_peer = store.inner().get_peer(&node_id).await.unwrap().unwrap();
    // Raw display_name should be encrypted (not plaintext)
    assert_ne!(raw_peer.display_name.as_deref(), Some("Test Node"));
}

#[tokio::test]
async fn encrypted_atomic_invite_and_whitelist() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let invitee_pubkey = [0xABu8; 32];
    let invitee = NodeId::from_bytes(invitee_pubkey);
    let invite_id = uuid::Uuid::new_v4();
    let invite = InviteIssuedRecord {
        id: invite_id,
        invitee_pubkey,
        expiry_unix: 1_900_000_000,
        channel_size_hint_sats: Some(25_000),
        addr: "127.0.0.1:9735".to_string(),
        max_fee_rate_sat_per_vb: Some(25),
        channel_open_intent_expiry_unix: Some(1_900_000_000),
        nonce: [8u8; 16],
        state: InviteState::Pending,
        created_at: 1_800_000_000,
        accepted_at: None,
        revoked_at: None,
    };

    store
        .add_invite_and_whitelist(&invite, invitee_pubkey)
        .await
        .unwrap();

    assert_eq!(store.find_invite_issued(&invite_id).await.unwrap(), Some(invite));
    let peer = store.get_peer(&invitee).await.unwrap().unwrap();
    assert_eq!(peer.metadata["invite_ref"], invite_id.to_string());
    assert_eq!(peer.metadata["whitelist_source"], "invite");
}

#[tokio::test]
async fn encrypted_upsert_peer_preserves_invite_ref_metadata() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let invitee_pubkey = [0xACu8; 32];
    let invitee = NodeId::from_bytes(invitee_pubkey);
    let invite_id = uuid::Uuid::new_v4();

    store
        .add_whitelisted_peer_with_invite_ref(invitee_pubkey, invite_id)
        .await
        .unwrap();

    let mut manual_update = Peer::new(invitee);
    manual_update.address = Some("127.0.0.1:9735".to_string());
    manual_update.metadata = serde_json::json!({"source": "manual"});
    store.upsert_peer(&manual_update).await.unwrap();

    let peer = store.get_peer(&invitee).await.unwrap().unwrap();
    assert_eq!(peer.address.as_deref(), Some("127.0.0.1:9735"));
    assert_eq!(peer.metadata["source"], "manual");
    assert_eq!(peer.metadata["invite_ref"], invite_id.to_string());
    assert_eq!(peer.metadata["whitelist_source"], "invite");
}

/// HARD-3 regression: many concurrent `upsert_peer` calls on the same peer must
/// never lose the `invite_ref` / `whitelist_source` metadata set by an earlier
/// whitelist write. The pre-fix read-decrypt-merge-encrypt-write was not atomic,
/// so two writers racing on the same node could each read the same "before"
/// state and the loser's write would clobber the winner's preserved invite_ref.
#[tokio::test]
async fn encrypted_upsert_peer_concurrent_preserves_invite_ref() {
    use std::sync::Arc;

    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = Arc::new(EncryptedStorage::new(sqlite, &key));

    let invitee_pubkey = [0xADu8; 32];
    let invitee = NodeId::from_bytes(invitee_pubkey);
    let invite_id = uuid::Uuid::new_v4();

    // Seed the invite_ref / whitelist_source metadata.
    store
        .add_whitelisted_peer_with_invite_ref(invitee_pubkey, invite_id)
        .await
        .unwrap();

    // Fire many concurrent updates, each carrying metadata that does NOT
    // include invite_ref. Every one of them must preserve it.
    let mut handles = Vec::new();
    for i in 0..32u32 {
        let store = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            let mut peer = Peer::new(invitee);
            peer.display_name = Some(format!("name-{i}"));
            peer.metadata = serde_json::json!({ "round": i });
            store.upsert_peer(&peer).await.unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    let peer = store.get_peer(&invitee).await.unwrap().unwrap();
    assert_eq!(
        peer.metadata["invite_ref"],
        invite_id.to_string(),
        "invite_ref must survive concurrent upserts"
    );
    assert_eq!(peer.metadata["whitelist_source"], "invite");
    // The last writer wins on the non-preserved keys, so exactly one `round`
    // value remains — proving updates were serialised rather than torn.
    assert!(peer.metadata["round"].is_u64());
}

/// HARD-3 regression: a whitelist write racing concurrent `upsert_peer` calls on
/// the encrypted layer must still land the `invite_ref`. The pre-fix code let an
/// `upsert_peer` that read the peer *before* the whitelist write commit, then
/// wrote *after* it, silently drop the invite_ref from the encrypted blob.
#[tokio::test]
async fn encrypted_whitelist_write_races_upsert_keeps_invite_ref() {
    use std::sync::Arc;

    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [9u8; 32];
    let store = Arc::new(EncryptedStorage::new(sqlite, &key));

    let invitee_pubkey = [0xAEu8; 32];
    let invitee = NodeId::from_bytes(invitee_pubkey);
    let invite_id = uuid::Uuid::new_v4();

    // Pre-create the peer row (no invite_ref yet).
    let mut seed = Peer::new(invitee);
    seed.display_name = Some("seed".into());
    store.upsert_peer(&seed).await.unwrap();

    // Race the whitelist write against a barrage of plain upserts.
    let mut handles = Vec::new();
    {
        let store = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            store
                .add_whitelisted_peer_with_invite_ref(invitee_pubkey, invite_id)
                .await
                .unwrap();
        }));
    }
    for i in 0..16u32 {
        let store = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            let mut peer = Peer::new(invitee);
            peer.metadata = serde_json::json!({ "round": i });
            store.upsert_peer(&peer).await.unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    let peer = store.get_peer(&invitee).await.unwrap().unwrap();
    assert_eq!(
        peer.metadata["invite_ref"],
        invite_id.to_string(),
        "invite_ref must survive the whitelist-write / upsert race"
    );
    assert_eq!(peer.metadata["whitelist_source"], "invite");
}

/// Principle 4 (P4) regression: after `add_invite_and_whitelist`, the invite tag
/// (`invite_ref` / `whitelist_source`) must be CIPHERTEXT at rest in the inner
/// backend — never plaintext JSON. The pre-fix wrapper delegated the peer write
/// straight to the inner backend, which built and stored the metadata as
/// plaintext JSON, leaving the invite reference readable on the operator's disk
/// until a later `upsert_peer` happened to re-encrypt it.
#[tokio::test]
async fn encrypted_add_invite_and_whitelist_metadata_is_ciphertext_at_rest() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [7u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let invitee_pubkey = [0xB1u8; 32];
    let invitee = NodeId::from_bytes(invitee_pubkey);
    let invite_id = uuid::Uuid::new_v4();
    let invite = InviteIssuedRecord {
        id: invite_id,
        invitee_pubkey,
        expiry_unix: 1_900_000_000,
        channel_size_hint_sats: Some(25_000),
        addr: "127.0.0.1:9735".to_string(),
        max_fee_rate_sat_per_vb: Some(25),
        channel_open_intent_expiry_unix: Some(1_900_000_000),
        nonce: [8u8; 16],
        state: InviteState::Pending,
        created_at: 1_800_000_000,
        accepted_at: None,
        revoked_at: None,
    };

    store
        .add_invite_and_whitelist(&invite, invitee_pubkey)
        .await
        .unwrap();

    // Through the wrapper: plaintext is recoverable (decrypts correctly).
    let peer = store.get_peer(&invitee).await.unwrap().unwrap();
    assert_eq!(peer.metadata["invite_ref"], invite_id.to_string());
    assert_eq!(peer.metadata["whitelist_source"], "invite");

    // At rest in the inner backend: the metadata is an opaque ciphertext string,
    // NOT a JSON object, and does NOT leak the invite reference or marker.
    let raw = store.inner().get_peer(&invitee).await.unwrap().unwrap();
    let raw_blob = raw.metadata.as_str().expect(
        "inner peer metadata must be an encrypted string scalar, not a plaintext JSON object",
    );
    let invite_id_str = invite_id.to_string();
    assert!(
        !raw_blob.contains(&invite_id_str),
        "invite_ref leaked as plaintext at rest: {raw_blob}"
    );
    assert!(
        !raw_blob.contains("invite_ref"),
        "invite_ref key leaked as plaintext at rest: {raw_blob}"
    );
    assert!(
        !raw_blob.contains("whitelist_source"),
        "whitelist_source key leaked as plaintext at rest: {raw_blob}"
    );
    // Decrypting the blob with the storage key yields the real plaintext object.
    let decrypted = store
        .decrypt_json(&raw.metadata)
        .expect("ciphertext blob must decrypt with the storage key");
    assert_eq!(decrypted["invite_ref"], invite_id_str);
    assert_eq!(decrypted["whitelist_source"], "invite");
}

/// P4 regression for the standalone whitelist write path. Same invariant as
/// `encrypted_add_invite_and_whitelist_metadata_is_ciphertext_at_rest`, exercised
/// through `add_whitelisted_peer_with_invite_ref`, including the case where an
/// encrypted peer row already exists (its prior metadata must survive and stay
/// encrypted alongside the new invite tag).
#[tokio::test]
async fn encrypted_add_whitelisted_peer_metadata_is_ciphertext_at_rest() {
    let sqlite = SqliteStorage::in_memory().await.unwrap();
    let key = [5u8; 32];
    let store = EncryptedStorage::new(sqlite, &key);

    let invitee_pubkey = [0xB2u8; 32];
    let invitee = NodeId::from_bytes(invitee_pubkey);
    let invite_id = uuid::Uuid::new_v4();

    // Pre-existing encrypted peer with prior metadata that must be preserved.
    let mut seed = Peer::new(invitee);
    seed.display_name = Some("seed-name".to_string());
    seed.metadata = serde_json::json!({ "note": "prior-secret" });
    store.upsert_peer(&seed).await.unwrap();

    store
        .add_whitelisted_peer_with_invite_ref(invitee_pubkey, invite_id)
        .await
        .unwrap();

    // Through the wrapper: invite tag landed AND the prior metadata survived.
    let peer = store.get_peer(&invitee).await.unwrap().unwrap();
    assert_eq!(peer.metadata["invite_ref"], invite_id.to_string());
    assert_eq!(peer.metadata["whitelist_source"], "invite");
    assert_eq!(peer.metadata["note"], "prior-secret");
    assert_eq!(peer.display_name.as_deref(), Some("seed-name"));

    // At rest: ciphertext string, no plaintext leakage of the tag or the prior
    // secret.
    let raw = store.inner().get_peer(&invitee).await.unwrap().unwrap();
    let raw_blob = raw
        .metadata
        .as_str()
        .expect("inner peer metadata must be an encrypted string scalar");
    assert!(
        !raw_blob.contains("invite_ref")
            && !raw_blob.contains("whitelist_source")
            && !raw_blob.contains(&invite_id.to_string())
            && !raw_blob.contains("prior-secret"),
        "invite tag or prior metadata leaked as plaintext at rest: {raw_blob}"
    );
    let decrypted = store.decrypt_json(&raw.metadata).unwrap();
    assert_eq!(decrypted["invite_ref"], invite_id.to_string());
    assert_eq!(decrypted["whitelist_source"], "invite");
    assert_eq!(decrypted["note"], "prior-secret");
}

#[async_trait]
impl Storage for () {
    async fn store_message(&self, _: &UkmEnvelope) -> Result<(), StorageError> {
        Ok(())
    }
    async fn get_message(&self, _: &MessageId) -> Result<Option<UkmEnvelope>, StorageError> {
        Ok(None)
    }
    async fn get_messages_for_recipient(
        &self,
        _: &Recipient,
        _: u32,
        _: Option<u64>,
    ) -> Result<Vec<UkmEnvelope>, StorageError> {
        Ok(vec![])
    }
    async fn get_conversation_messages(
        &self,
        _: &str,
        _: &str,
        _: bool,
        _: u32,
        _: Option<u64>,
    ) -> Result<Vec<UkmEnvelope>, StorageError> {
        Ok(vec![])
    }
    async fn delete_message(&self, _: &MessageId) -> Result<bool, StorageError> {
        Ok(false)
    }
    async fn delete_messages_older_than(&self, _: u64) -> Result<u64, StorageError> {
        Ok(0)
    }
    async fn create_room(&self, _: &Room) -> Result<(), StorageError> {
        Ok(())
    }
    async fn get_room(&self, _: &RoomId) -> Result<Option<Room>, StorageError> {
        Ok(None)
    }
    async fn list_rooms(&self) -> Result<Vec<Room>, StorageError> {
        Ok(vec![])
    }
    async fn delete_room(&self, _: &RoomId) -> Result<bool, StorageError> {
        Ok(false)
    }
    async fn add_room_member(&self, _: &RoomId, _: &NodeId) -> Result<(), StorageError> {
        Ok(())
    }
    async fn remove_room_member(&self, _: &RoomId, _: &NodeId) -> Result<(), StorageError> {
        Ok(())
    }
    async fn get_room_members(&self, _: &RoomId) -> Result<Vec<NodeId>, StorageError> {
        Ok(vec![])
    }
    async fn upsert_peer(&self, _: &Peer) -> Result<(), StorageError> {
        Ok(())
    }
    async fn get_peer(&self, _: &NodeId) -> Result<Option<Peer>, StorageError> {
        Ok(None)
    }
    async fn list_peers(&self) -> Result<Vec<Peer>, StorageError> {
        Ok(vec![])
    }
    async fn delete_peer(&self, _: &NodeId) -> Result<bool, StorageError> {
        Ok(false)
    }
    async fn store_nonce(&self, _: &Nonce, _: &NodeId) -> Result<bool, StorageError> {
        Ok(true)
    }
    async fn has_nonce(&self, _: &Nonce) -> Result<bool, StorageError> {
        Ok(false)
    }
    async fn cleanup_expired_nonces(&self, _: u64) -> Result<u64, StorageError> {
        Ok(0)
    }
    async fn store_session(&self, _: &NodeId, _: &[u8]) -> Result<(), StorageError> {
        Ok(())
    }
    async fn load_session(&self, _: &NodeId) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }
    async fn delete_session(&self, _: &NodeId) -> Result<bool, StorageError> {
        Ok(false)
    }
    async fn list_sessions(&self) -> Result<Vec<NodeId>, StorageError> {
        Ok(vec![])
    }
    async fn queue_pending_delivery(&self, _: &MessageId, _: &NodeId) -> Result<(), StorageError> {
        Ok(())
    }
    async fn get_pending_for_peer(&self, _: &NodeId) -> Result<Vec<(MessageId, u32)>, StorageError> {
        Ok(vec![])
    }
    async fn remove_pending_delivery(&self, _: &MessageId, _: &NodeId) -> Result<(), StorageError> {
        Ok(())
    }
    async fn increment_pending_attempts(&self, _: &MessageId, _: &NodeId) -> Result<(), StorageError> {
        Ok(())
    }
    async fn get_pending_peers(&self) -> Result<Vec<NodeId>, StorageError> {
        Ok(vec![])
    }
    async fn count_pending_deliveries(&self) -> Result<u64, StorageError> {
        Ok(0)
    }
    async fn clear_pending_for_peer(&self, _: &NodeId) -> Result<u64, StorageError> {
        Ok(0)
    }
    async fn cleanup_stale_pending(&self, _: u32) -> Result<u64, StorageError> {
        Ok(0)
    }
    async fn store_file(&self, _: &FileRecord) -> Result<(), StorageError> {
        Ok(())
    }
    async fn get_file(&self, _: &str) -> Result<Option<FileRecord>, StorageError> {
        Ok(None)
    }
    async fn get_file_metadata(&self, _: &str) -> Result<Option<FileMetadata>, StorageError> {
        Ok(None)
    }
    async fn list_files(&self, _: u32) -> Result<Vec<FileMetadata>, StorageError> {
        Ok(vec![])
    }
    async fn delete_file(&self, _: &str) -> Result<bool, StorageError> {
        Ok(false)
    }
    async fn store_message_plaintext(
        &self,
        _: &MessageId,
        _: &[u8],
    ) -> Result<(), StorageError> {
        Ok(())
    }
    async fn get_message_plaintext(
        &self,
        _: &MessageId,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }
}
