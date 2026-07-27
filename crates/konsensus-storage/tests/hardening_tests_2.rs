//! Hardening tests part 2 — SQLite edge cases: room-recipient messages,
//! message references, StorageNonceAdapter, plaintext cache edge cases,
//! upsert peer COALESCE semantics, concurrent operations, room deletion cascade,
//! and empty-database boundary conditions.

use std::sync::Arc;

use konsensus_core::UkmEnvelopeBuilder;
use konsensus_core::gate::NonceStore;
use konsensus_core::types::{MessageId, NodeId, Nonce, PaymentProof, Recipient, RoomId, Signature};
use konsensus_storage::models::{FileRecord, Peer, Room};
use konsensus_storage::{EncryptedStorage, SqliteStorage, Storage, StorageNonceAdapter};
use sha2::{Digest, Sha256};

fn make_node_id(seed: u8) -> NodeId {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    NodeId::from_verifying_key(&signing.verifying_key())
}

fn make_proof(amount_msat: u64) -> PaymentProof {
    let preimage = [42u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    PaymentProof::new(hash, preimage, amount_msat)
}

fn make_envelope_for_node(
    kind: u16,
    sender_seed: u8,
    recipient_seed: u8,
    ts: u64,
) -> konsensus_core::UkmEnvelope {
    let sender = make_node_id(sender_seed);
    let recipient = Recipient::Node(make_node_id(recipient_seed));
    let proof = make_proof(100);
    let ciphertext = format!("encrypted-{kind}-{ts}").into_bytes();
    UkmEnvelopeBuilder::new(kind, sender, recipient, ciphertext, proof)
        .timestamp(ts)
        .signature(Signature::from_bytes([0u8; 64]))
        .nonce(Nonce::from_bytes([ts as u8; 24]))
        .build()
}

fn make_envelope_for_room(
    kind: u16,
    sender_seed: u8,
    room_id: RoomId,
    ts: u64,
) -> konsensus_core::UkmEnvelope {
    let sender = make_node_id(sender_seed);
    let recipient = Recipient::Room(room_id);
    let proof = make_proof(100);
    let ciphertext = format!("room-encrypted-{kind}-{ts}").into_bytes();
    UkmEnvelopeBuilder::new(kind, sender, recipient, ciphertext, proof)
        .timestamp(ts)
        .signature(Signature::from_bytes([0u8; 64]))
        .nonce(Nonce::from_bytes([ts as u8; 24]))
        .build()
}

fn make_envelope_with_refs(
    sender_seed: u8,
    recipient_seed: u8,
    ts: u64,
    refs: Vec<MessageId>,
) -> konsensus_core::UkmEnvelope {
    let sender = make_node_id(sender_seed);
    let recipient = Recipient::Node(make_node_id(recipient_seed));
    let proof = make_proof(100);
    let ciphertext = b"ref-msg".to_vec();
    UkmEnvelopeBuilder::new(0, sender, recipient, ciphertext, proof)
        .timestamp(ts)
        .signature(Signature::from_bytes([0u8; 64]))
        .nonce(Nonce::from_bytes([ts as u8; 24]))
        .references(refs)
        .build()
}

fn make_file_record(id: &str, filename: &str, data: &[u8]) -> FileRecord {
    let hash = blake3::hash(data);
    FileRecord {
        id: id.to_string(),
        filename: filename.to_string(),
        mime_type: "application/octet-stream".to_string(),
        size_bytes: data.len() as u64,
        blake3_hash: hash.to_hex().to_string(),
        sender: hex::encode([1u8; 32]),
        message_id: None,
        data: data.to_vec(),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

async fn setup() -> SqliteStorage {
    SqliteStorage::in_memory().await.unwrap()
}

async fn setup_encrypted() -> EncryptedStorage<SqliteStorage> {
    let sqlite = setup().await;
    let key = [7u8; 32];
    EncryptedStorage::new(sqlite, &key)
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROOM-RECIPIENT MESSAGES
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn store_and_retrieve_room_recipient_message() {
    let db = setup().await;
    let room_id = RoomId::new();
    let env = make_envelope_for_room(0, 1, room_id, 1_000);

    db.store_message(&env).await.unwrap();

    let loaded = db.get_message(&env.id).await.unwrap().unwrap();
    assert_eq!(loaded.id, env.id);
    assert_eq!(loaded.recipient, Recipient::Room(room_id));
    assert_eq!(loaded.sender, env.sender);
}

#[tokio::test]
async fn query_messages_for_room_recipient() {
    let db = setup().await;
    let room_id = RoomId::new();

    for ts in [1_000u64, 2_000, 3_000] {
        let env = make_envelope_for_room(0, 1, room_id, ts);
        db.store_message(&env).await.unwrap();
    }

    let msgs = db
        .get_messages_for_recipient(&Recipient::Room(room_id), 10, None)
        .await
        .unwrap();
    assert_eq!(msgs.len(), 3);
    // Newest first
    assert!(msgs[0].timestamp >= msgs[1].timestamp);
    assert!(msgs[1].timestamp >= msgs[2].timestamp);
}

#[tokio::test]
async fn room_messages_dont_mix_with_node_messages() {
    let db = setup().await;
    let room_id = RoomId::new();

    // Store 2 room messages
    for ts in [1_000u64, 2_000] {
        let env = make_envelope_for_room(0, 1, room_id, ts);
        db.store_message(&env).await.unwrap();
    }
    // Store 3 node messages
    for ts in [3_000u64, 4_000, 5_000] {
        let env = make_envelope_for_node(0, 1, 2, ts);
        db.store_message(&env).await.unwrap();
    }

    let room_msgs = db
        .get_messages_for_recipient(&Recipient::Room(room_id), 10, None)
        .await
        .unwrap();
    assert_eq!(room_msgs.len(), 2);

    let node_msgs = db
        .get_messages_for_recipient(&Recipient::Node(make_node_id(2)), 10, None)
        .await
        .unwrap();
    assert_eq!(node_msgs.len(), 3);
}

#[tokio::test]
async fn room_messages_pagination() {
    let db = setup().await;
    let room_id = RoomId::new();

    for ts in [1_000u64, 2_000, 3_000, 4_000, 5_000] {
        let env = make_envelope_for_room(0, 1, room_id, ts);
        db.store_message(&env).await.unwrap();
    }

    // Get messages before ts=3000
    let msgs = db
        .get_messages_for_recipient(&Recipient::Room(room_id), 10, Some(3_000))
        .await
        .unwrap();
    assert_eq!(msgs.len(), 2);
    for msg in &msgs {
        assert!(msg.timestamp < 3_000);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MESSAGE REFERENCES
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn message_with_references_roundtrips() {
    let db = setup().await;

    // Create two base messages to reference
    let base1 = make_envelope_for_node(0, 1, 2, 1_000);
    let base2 = make_envelope_for_node(0, 1, 2, 2_000);
    db.store_message(&base1).await.unwrap();
    db.store_message(&base2).await.unwrap();

    // Create a reply referencing both
    let reply = make_envelope_with_refs(1, 2, 3_000, vec![base1.id, base2.id]);
    db.store_message(&reply).await.unwrap();

    let loaded = db.get_message(&reply.id).await.unwrap().unwrap();
    assert_eq!(loaded.references.len(), 2);
    assert!(loaded.references.contains(&base1.id));
    assert!(loaded.references.contains(&base2.id));
}

#[tokio::test]
async fn message_with_empty_references() {
    let db = setup().await;
    let env = make_envelope_with_refs(1, 2, 1_000, vec![]);
    db.store_message(&env).await.unwrap();

    let loaded = db.get_message(&env.id).await.unwrap().unwrap();
    assert!(loaded.references.is_empty());
}

#[tokio::test]
async fn message_with_single_reference() {
    let db = setup().await;
    let base = make_envelope_for_node(0, 1, 2, 1_000);
    db.store_message(&base).await.unwrap();

    let reply = make_envelope_with_refs(1, 2, 2_000, vec![base.id]);
    db.store_message(&reply).await.unwrap();

    let loaded = db.get_message(&reply.id).await.unwrap().unwrap();
    assert_eq!(loaded.references.len(), 1);
    assert_eq!(loaded.references[0], base.id);
}

// ═══════════════════════════════════════════════════════════════════════════════
// STORAGE NONCE ADAPTER (bridges Storage → NonceStore for PaymentGate)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn nonce_adapter_check_and_store_new_returns_true() {
    let db = Arc::new(setup().await);
    let adapter = StorageNonceAdapter::new(db);
    let nonce = Nonce::generate();
    let sender = make_node_id(1);

    let result = adapter.check_and_store(&nonce, &sender).await.unwrap();
    assert!(result, "new nonce should return true");
}

#[tokio::test]
async fn nonce_adapter_check_and_store_duplicate_returns_false() {
    let db = Arc::new(setup().await);
    let adapter = StorageNonceAdapter::new(db);
    let nonce = Nonce::generate();
    let sender = make_node_id(1);

    assert!(adapter.check_and_store(&nonce, &sender).await.unwrap());
    assert!(
        !adapter.check_and_store(&nonce, &sender).await.unwrap(),
        "duplicate nonce should return false (replay detected)"
    );
}

#[tokio::test]
async fn nonce_adapter_multiple_unique_nonces() {
    let db = Arc::new(setup().await);
    let adapter = StorageNonceAdapter::new(db);
    let sender = make_node_id(1);

    for _ in 0..10 {
        let nonce = Nonce::generate();
        assert!(adapter.check_and_store(&nonce, &sender).await.unwrap());
    }
}

#[tokio::test]
async fn nonce_adapter_payment_hash_reuse_returns_false() {
    let db = Arc::new(setup().await);
    let adapter = StorageNonceAdapter::new(db);
    let sender = make_node_id(1);
    let message_a = MessageId::from_bytes([1u8; 32]);
    let message_b = MessageId::from_bytes([2u8; 32]);
    let payment_hash = [9u8; 32];

    assert!(
        adapter
            .check_and_store_payment_hash(&payment_hash, &sender, &message_a)
            .await
            .unwrap()
    );
    assert!(
        !adapter
            .check_and_store_payment_hash(&payment_hash, &sender, &message_b)
            .await
            .unwrap(),
        "reused Lightning payment hash should be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PLAINTEXT CACHE EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn plaintext_cache_overwrite() {
    let db = setup().await;
    let env = make_envelope_for_node(0, 1, 2, 1_000);
    db.store_message(&env).await.unwrap();

    db.store_message_plaintext(&env.id, b"version1")
        .await
        .unwrap();
    db.store_message_plaintext(&env.id, b"version2")
        .await
        .unwrap();

    let loaded = db.get_message_plaintext(&env.id).await.unwrap().unwrap();
    assert_eq!(loaded, b"version2");
}

#[tokio::test]
async fn plaintext_cache_empty_blob() {
    let db = setup().await;
    let env = make_envelope_for_node(0, 1, 2, 1_000);
    db.store_message(&env).await.unwrap();

    db.store_message_plaintext(&env.id, b"").await.unwrap();
    let loaded = db.get_message_plaintext(&env.id).await.unwrap().unwrap();
    assert!(loaded.is_empty());
}

#[tokio::test]
async fn plaintext_cache_large_blob() {
    let db = setup().await;
    let env = make_envelope_for_node(0, 1, 2, 1_000);
    db.store_message(&env).await.unwrap();

    let large = vec![0xAB; 512 * 1024]; // 512 KB
    db.store_message_plaintext(&env.id, &large).await.unwrap();
    let loaded = db.get_message_plaintext(&env.id).await.unwrap().unwrap();
    assert_eq!(loaded.len(), 512 * 1024);
}

#[tokio::test]
async fn plaintext_for_message_without_plaintext_returns_none() {
    let db = setup().await;
    let env = make_envelope_for_node(0, 1, 2, 1_000);
    db.store_message(&env).await.unwrap();
    // Don't store plaintext
    assert!(db.get_message_plaintext(&env.id).await.unwrap().is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// UPSERT PEER COALESCE SEMANTICS
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn upsert_peer_preserves_existing_address_when_new_is_none() {
    let db = setup().await;
    let nid = make_node_id(5);

    // First insert with address
    let mut peer1 = Peer::new(nid);
    peer1.address = Some("10.0.0.1:9735".to_string());
    peer1.display_name = Some("Alice".to_string());
    db.upsert_peer(&peer1).await.unwrap();

    // Second upsert with None address — should preserve existing
    let mut peer2 = Peer::new(nid);
    peer2.address = None; // Don't overwrite
    peer2.display_name = Some("Alice Updated".to_string());
    db.upsert_peer(&peer2).await.unwrap();

    let loaded = db.get_peer(&nid).await.unwrap().unwrap();
    assert_eq!(
        loaded.address.as_deref(),
        Some("10.0.0.1:9735"),
        "address should be preserved by COALESCE"
    );
    assert_eq!(loaded.display_name.as_deref(), Some("Alice Updated"));
}

#[tokio::test]
async fn upsert_peer_overwrites_address_when_new_is_some() {
    let db = setup().await;
    let nid = make_node_id(5);

    let mut peer1 = Peer::new(nid);
    peer1.address = Some("10.0.0.1:9735".to_string());
    db.upsert_peer(&peer1).await.unwrap();

    let mut peer2 = Peer::new(nid);
    peer2.address = Some("10.0.0.2:9735".to_string());
    db.upsert_peer(&peer2).await.unwrap();

    let loaded = db.get_peer(&nid).await.unwrap().unwrap();
    assert_eq!(loaded.address.as_deref(), Some("10.0.0.2:9735"));
}

#[tokio::test]
async fn upsert_peer_metadata_always_overwrites() {
    let db = setup().await;
    let nid = make_node_id(5);

    let mut peer1 = Peer::new(nid);
    peer1.metadata = serde_json::json!({"version": 1});
    db.upsert_peer(&peer1).await.unwrap();

    let mut peer2 = Peer::new(nid);
    peer2.metadata = serde_json::json!({"version": 2, "extra": true});
    db.upsert_peer(&peer2).await.unwrap();

    let loaded = db.get_peer(&nid).await.unwrap().unwrap();
    assert_eq!(loaded.metadata["version"], 2);
    assert_eq!(loaded.metadata["extra"], true);
}

async fn assert_upsert_peer_preserves_invite_ref_metadata<S: Storage>(db: S) {
    let nid = make_node_id(5);
    let invite_id = uuid::Uuid::new_v4();

    db.add_whitelisted_peer_with_invite_ref(*nid.as_bytes(), invite_id)
        .await
        .unwrap();

    let mut manual_update = Peer::new(nid);
    manual_update.address = Some("10.0.0.3:9735".to_string());
    manual_update.metadata = serde_json::json!({"source": "manual"});
    db.upsert_peer(&manual_update).await.unwrap();

    let loaded = db.get_peer(&nid).await.unwrap().unwrap();
    assert_eq!(loaded.address.as_deref(), Some("10.0.0.3:9735"));
    assert_eq!(loaded.metadata["source"], "manual");
    assert_eq!(loaded.metadata["invite_ref"], invite_id.to_string());
    assert_eq!(loaded.metadata["whitelist_source"], "invite");
}

#[tokio::test]
async fn upsert_peer_preserves_invite_ref_metadata() {
    assert_upsert_peer_preserves_invite_ref_metadata(setup().await).await;
}

#[tokio::test]
async fn encrypted_upsert_peer_preserves_invite_ref_metadata() {
    assert_upsert_peer_preserves_invite_ref_metadata(setup_encrypted().await).await;
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROOM DELETION CASCADE
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn delete_room_also_removes_memberships() {
    let db = setup().await;
    let room = Room::new("Cascade Test".to_string(), make_node_id(1));
    let room_id = room.id;
    db.create_room(&room).await.unwrap();

    // Add members
    db.add_room_member(&room_id, &make_node_id(10))
        .await
        .unwrap();
    db.add_room_member(&room_id, &make_node_id(11))
        .await
        .unwrap();
    db.add_room_member(&room_id, &make_node_id(12))
        .await
        .unwrap();
    assert_eq!(db.get_room_members(&room_id).await.unwrap().len(), 3);

    // Delete room — should cascade to memberships
    assert!(db.delete_room(&room_id).await.unwrap());
    assert!(db.get_room(&room_id).await.unwrap().is_none());
    assert!(db.get_room_members(&room_id).await.unwrap().is_empty());
}

#[tokio::test]
async fn delete_room_doesnt_affect_other_rooms() {
    let db = setup().await;
    let room_a = Room::new("Room A".to_string(), make_node_id(1));
    let room_b = Room::new("Room B".to_string(), make_node_id(1));
    let room_a_id = room_a.id;
    let room_b_id = room_b.id;

    db.create_room(&room_a).await.unwrap();
    db.create_room(&room_b).await.unwrap();

    db.add_room_member(&room_a_id, &make_node_id(10))
        .await
        .unwrap();
    db.add_room_member(&room_b_id, &make_node_id(10))
        .await
        .unwrap();

    db.delete_room(&room_a_id).await.unwrap();

    // Room B and its memberships should be unaffected
    assert!(db.get_room(&room_b_id).await.unwrap().is_some());
    assert_eq!(db.get_room_members(&room_b_id).await.unwrap().len(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE WITH MESSAGE ID
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn file_with_message_id_set() {
    let db = setup().await;
    let hash = blake3::hash(b"test");
    let file = FileRecord {
        id: "linked-file".to_string(),
        filename: "doc.pdf".to_string(),
        mime_type: "application/pdf".to_string(),
        size_bytes: 1000,
        blake3_hash: hash.to_hex().to_string(),
        sender: hex::encode([1u8; 32]),
        message_id: Some(hex::encode([0xAA; 32])),
        data: b"pdf data".to_vec(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    db.store_file(&file).await.unwrap();

    let loaded = db.get_file("linked-file").await.unwrap().unwrap();
    assert_eq!(
        loaded.message_id.as_deref(),
        Some(&hex::encode([0xAA; 32])[..])
    );

    let meta = db.get_file_metadata("linked-file").await.unwrap().unwrap();
    assert_eq!(
        meta.message_id.as_deref(),
        Some(&hex::encode([0xAA; 32])[..])
    );
}

#[tokio::test]
async fn file_metadata_matches_file_record() {
    let db = setup().await;
    let file = make_file_record("meta-check", "test.bin", b"binary data here");
    db.store_file(&file).await.unwrap();

    let full = db.get_file("meta-check").await.unwrap().unwrap();
    let meta = db.get_file_metadata("meta-check").await.unwrap().unwrap();

    assert_eq!(meta.id, full.id);
    assert_eq!(meta.filename, full.filename);
    assert_eq!(meta.mime_type, full.mime_type);
    assert_eq!(meta.size_bytes, full.size_bytes);
    assert_eq!(meta.blake3_hash, full.blake3_hash);
    assert_eq!(meta.sender, full.sender);
    assert_eq!(meta.message_id, full.message_id);
}

// ═══════════════════════════════════════════════════════════════════════════════
// EMPTY DATABASE BOUNDARY CONDITIONS
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn empty_db_list_rooms_returns_empty() {
    let db = setup().await;
    assert!(db.list_rooms().await.unwrap().is_empty());
}

#[tokio::test]
async fn empty_db_list_peers_returns_empty() {
    let db = setup().await;
    assert!(db.list_peers().await.unwrap().is_empty());
}

#[tokio::test]
async fn empty_db_list_sessions_returns_empty() {
    let db = setup().await;
    assert!(db.list_sessions().await.unwrap().is_empty());
}

#[tokio::test]
async fn empty_db_list_files_returns_empty() {
    let db = setup().await;
    assert!(db.list_files(10).await.unwrap().is_empty());
}

#[tokio::test]
async fn empty_db_count_pending_returns_zero() {
    let db = setup().await;
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 0);
}

#[tokio::test]
async fn empty_db_get_pending_peers_returns_empty() {
    let db = setup().await;
    assert!(db.get_pending_peers().await.unwrap().is_empty());
}

#[tokio::test]
async fn empty_db_cleanup_nonces_returns_zero() {
    let db = setup().await;
    assert_eq!(db.cleanup_expired_nonces(0).await.unwrap(), 0);
}

#[tokio::test]
async fn empty_db_cleanup_stale_pending_returns_zero() {
    let db = setup().await;
    assert_eq!(db.cleanup_stale_pending(0).await.unwrap(), 0);
}

#[tokio::test]
async fn empty_db_messages_for_recipient_returns_empty() {
    let db = setup().await;
    let msgs = db
        .get_messages_for_recipient(&Recipient::Node(make_node_id(1)), 10, None)
        .await
        .unwrap();
    assert!(msgs.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONCURRENT / INTERLEAVED OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn interleaved_nonce_and_message_operations() {
    let db = setup().await;
    let sender = make_node_id(1);

    // Interleave nonce stores with message stores
    for i in 0..5u8 {
        let nonce = Nonce::from_bytes([i; 24]);
        assert!(db.store_nonce(&nonce, &sender).await.unwrap());

        let env = make_envelope_for_node(0, 1, 2, (i as u64) * 1000);
        db.store_message(&env).await.unwrap();
    }

    // All nonces should be stored
    for i in 0..5u8 {
        assert!(db.has_nonce(&Nonce::from_bytes([i; 24])).await.unwrap());
    }

    // All messages should be retrievable
    let msgs = db
        .get_messages_for_recipient(&Recipient::Node(make_node_id(2)), 10, None)
        .await
        .unwrap();
    assert_eq!(msgs.len(), 5);
}

#[tokio::test]
async fn many_rooms_with_members() {
    let db = setup().await;
    let creator = make_node_id(1);

    // Create 10 rooms with 3 members each
    for room_idx in 0..10u8 {
        let room = Room::new(format!("Room {room_idx}"), creator);
        db.create_room(&room).await.unwrap();

        for member_idx in 0..3u8 {
            db.add_room_member(&room.id, &make_node_id(100 + room_idx * 10 + member_idx))
                .await
                .unwrap();
        }
    }

    let rooms = db.list_rooms().await.unwrap();
    assert_eq!(rooms.len(), 10);

    // Verify each room has 3 members
    for room in &rooms {
        let members = db.get_room_members(&room.id).await.unwrap();
        assert_eq!(members.len(), 3, "Room {} should have 3 members", room.name);
    }
}

#[tokio::test]
async fn many_peers() {
    let db = setup().await;

    // Store 50 peers
    for i in 0..50u8 {
        let mut peer = Peer::new(make_node_id(i));
        peer.display_name = Some(format!("Peer {i}"));
        peer.address = Some(format!("10.0.0.{i}:9735"));
        db.upsert_peer(&peer).await.unwrap();
    }

    let peers = db.list_peers().await.unwrap();
    assert_eq!(peers.len(), 50);
}

#[tokio::test]
async fn session_for_multiple_peers() {
    let db = setup().await;

    // Store sessions for 10 different peers
    for i in 0..10u8 {
        let peer = make_node_id(i);
        let blob = vec![i; 64]; // Each peer gets unique session data
        db.store_session(&peer, &blob).await.unwrap();
    }

    let sessions = db.list_sessions().await.unwrap();
    assert_eq!(sessions.len(), 10);

    // Verify each session has correct data
    for i in 0..10u8 {
        let loaded = db.load_session(&make_node_id(i)).await.unwrap().unwrap();
        assert_eq!(loaded, vec![i; 64]);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MESSAGE KIND AND CIPHERTEXT ROUNDTRIP
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn different_message_kinds_store_and_retrieve() {
    let db = setup().await;
    let kinds = [0u16, 100, 200, 300, 500, 900, 1000];

    for &kind in &kinds {
        let env = make_envelope_for_node(kind, 1, 2, kind as u64 * 1000);
        db.store_message(&env).await.unwrap();

        let loaded = db.get_message(&env.id).await.unwrap().unwrap();
        assert_eq!(loaded.kind, kind, "kind mismatch for {kind}");
    }
}

#[tokio::test]
async fn ciphertext_binary_data_roundtrips() {
    let db = setup().await;
    let sender = make_node_id(1);
    let recipient = Recipient::Node(make_node_id(2));

    // Use binary ciphertext with all byte values 0-255
    let ciphertext: Vec<u8> = (0..=255).collect();
    let proof = make_proof(100);
    let env = UkmEnvelopeBuilder::new(0, sender, recipient, ciphertext.clone(), proof)
        .timestamp(1_000)
        .signature(Signature::from_bytes([0u8; 64]))
        .nonce(Nonce::from_bytes([1u8; 24]))
        .build();

    db.store_message(&env).await.unwrap();
    let loaded = db.get_message(&env.id).await.unwrap().unwrap();
    assert_eq!(loaded.ciphertext, ciphertext);
}

#[tokio::test]
async fn payment_proof_fields_roundtrip() {
    let db = setup().await;
    let sender = make_node_id(1);
    let recipient = Recipient::Node(make_node_id(2));

    let preimage = [0xBB; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, 25_000);

    let env = UkmEnvelopeBuilder::new(0, sender, recipient, b"test".to_vec(), proof)
        .timestamp(1_000)
        .signature(Signature::from_bytes([0xCC; 64]))
        .nonce(Nonce::from_bytes([0xDD; 24]))
        .build();

    db.store_message(&env).await.unwrap();
    let loaded = db.get_message(&env.id).await.unwrap().unwrap();

    assert_eq!(loaded.payment_proof.payment_hash, hash);
    assert_eq!(loaded.payment_proof.preimage, preimage);
    assert_eq!(loaded.payment_proof.amount_msat, 25_000);
    assert_eq!(loaded.signature.as_bytes(), &[0xCC; 64]);
    assert_eq!(loaded.nonce.as_bytes(), &[0xDD; 24]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// END-TO-END PAYMENT-HASH REPLAY REJECTION THROUGH THE PAYMENT GATE
//
// HARD-5 regression: proves economic replay protection is NOT a no-op on the
// production money-path. Two fully-signed, fresh-nonce envelopes that reuse the
// SAME settled Lightning payment hash are run through `PaymentGate::verify` using
// the *production* `StorageNonceAdapter` over a real SQLite store. The first must
// be accepted; the second must be rejected with `PaymentProofReused`. Before the
// fix, the permissive `Ok(true)` defaults on `NonceStore::check_and_store_payment_hash`
// and `Storage::store_payment_receipt` could silently turn this into a no-op for
// any backend that forgot to override them.
// ═══════════════════════════════════════════════════════════════════════════════

mod replay_e2e {
    use super::*;
    use konsensus_core::gate::{GateRejection, PaymentGate};
    use konsensus_core::identity::NodeIdentity;
    use konsensus_core::kind::{KIND_CHAT, KindCategory};
    use konsensus_core::traits::pricing::{PricingEngine, PricingError};

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon art";

    struct FixedPricing {
        price_msat: u64,
    }

    #[async_trait::async_trait]
    impl PricingEngine for FixedPricing {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        async fn get_price_msat(&self, _kind: u16) -> Result<u64, PricingError> {
            Ok(self.price_msat)
        }

        async fn get_category_price_msat(
            &self,
            _category: KindCategory,
        ) -> Result<u64, PricingError> {
            Ok(self.price_msat)
        }
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// Build a fully-signed chat envelope. The payment proof is deterministic
    /// (fixed preimage), so two envelopes built by this helper share the same
    /// `payment_hash` while getting distinct fresh nonces from the builder.
    fn signed_chat_envelope(identity: &NodeIdentity, amount_msat: u64) -> konsensus_core::UkmEnvelope {
        let sender = *identity.node_id();
        let recipient = Recipient::Node(make_node_id(2));
        let preimage = [42u8; 32];
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        let proof = PaymentProof::new(hash, preimage, amount_msat);

        let mut envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"encrypted content".to_vec(), proof)
                .timestamp(now_ms())
                .build();

        let signable = envelope.signable_bytes();
        let sig = identity.sign(&signable);
        envelope.signature = Signature::from_ed25519(&sig);
        envelope
    }

    /// A settled Lightning payment proof buys exactly ONE message. Replaying the
    /// same payment hash under a fresh nonce + fresh signed envelope must be
    /// rejected end-to-end through the production gate + SqliteStorage adapter.
    #[tokio::test]
    async fn replayed_payment_hash_rejected_through_gate_and_sqlite() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();

        let first = signed_chat_envelope(&identity, 100);
        let second = signed_chat_envelope(&identity, 100);

        // Sanity: fresh nonce, but identical economic proof (payment hash).
        assert_ne!(first.nonce, second.nonce, "envelopes must have distinct nonces");
        assert_eq!(
            first.payment_proof.payment_hash, second.payment_proof.payment_hash,
            "envelopes must reuse the same payment hash for this test to mean anything"
        );

        // Production wiring: gate + StorageNonceAdapter over a REAL SQLite store.
        let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
        let nonce_store = StorageNonceAdapter::new(Arc::clone(&db));
        let gate = PaymentGate::new();
        let pricing = FixedPricing { price_msat: 10 };

        // First envelope: accepted (new nonce + new payment hash).
        gate.verify(&first, &nonce_store, &pricing, None, None, 0.0, None)
            .await
            .expect("first paid envelope should be accepted");

        // Second envelope: fresh nonce passes the nonce check, but the reused
        // payment hash must be rejected at Step 7 (economic replay).
        let result = gate
            .verify(&second, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            matches!(result, Err(GateRejection::PaymentProofReused { .. })),
            "replayed payment hash must be rejected end-to-end, got: {result:?}"
        );

        // And the receipt is durably persisted: a direct re-check returns false.
        assert!(
            !db.store_payment_receipt(
                &second.payment_proof.payment_hash,
                &second.sender,
                &second.id,
            )
            .await
            .unwrap(),
            "payment receipt must be durably stored and reject reuse"
        );
    }
}
