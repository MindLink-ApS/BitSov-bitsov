//! Hardening tests for konsensus-storage — SQLite backend CRUD operations,
//! pending delivery queue, nonce replay protection, session persistence,
//! file storage, room management, and cross-method interaction edge cases.

use konsensus_core::types::{MessageId, NodeId, Nonce, PaymentProof, Recipient, Signature};
use konsensus_core::UkmEnvelopeBuilder;
use konsensus_storage::models::{FileRecord, Peer, Room};
use konsensus_storage::{SqliteStorage, Storage};
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

fn make_envelope(kind: u16, sender_seed: u8, recipient_seed: u8, ts: u64) -> konsensus_core::UkmEnvelope {
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

// ═══════════════════════════════════════════════════════════════════════════════
// MESSAGE STORAGE
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn store_and_retrieve_message() {
    let db = setup().await;
    let env = make_envelope(0, 1, 2, 1_700_000_000_000);
    db.store_message(&env).await.unwrap();

    let loaded = db.get_message(&env.id).await.unwrap();
    assert!(loaded.is_some());
    let loaded = loaded.unwrap();
    assert_eq!(loaded.id, env.id);
    assert_eq!(loaded.kind, env.kind);
    assert_eq!(loaded.sender, env.sender);
    assert_eq!(loaded.timestamp, env.timestamp);
}

#[tokio::test]
async fn get_nonexistent_message_returns_none() {
    let db = setup().await;
    let fake_id = MessageId::compute(b"nonexistent", &Nonce::generate());
    assert!(db.get_message(&fake_id).await.unwrap().is_none());
}

#[tokio::test]
async fn delete_message_returns_true_when_exists() {
    let db = setup().await;
    let env = make_envelope(0, 1, 2, 1_700_000_000_000);
    db.store_message(&env).await.unwrap();
    assert!(db.delete_message(&env.id).await.unwrap());
    assert!(db.get_message(&env.id).await.unwrap().is_none());
}

#[tokio::test]
async fn delete_nonexistent_message_returns_false() {
    let db = setup().await;
    let fake_id = MessageId::compute(b"none", &Nonce::generate());
    assert!(!db.delete_message(&fake_id).await.unwrap());
}

#[tokio::test]
async fn messages_for_recipient_ordered_newest_first() {
    let db = setup().await;
    let recipient = make_node_id(2);

    for ts in [1_000, 3_000, 2_000u64] {
        let env = make_envelope(0, 1, 2, ts);
        db.store_message(&env).await.unwrap();
    }

    let msgs = db
        .get_messages_for_recipient(&Recipient::Node(recipient), 10, None)
        .await
        .unwrap();
    assert_eq!(msgs.len(), 3);
    assert!(msgs[0].timestamp >= msgs[1].timestamp);
    assert!(msgs[1].timestamp >= msgs[2].timestamp);
}

#[tokio::test]
async fn messages_pagination_with_before_timestamp() {
    let db = setup().await;

    for ts in [1_000u64, 2_000, 3_000, 4_000, 5_000] {
        let env = make_envelope(0, 1, 2, ts);
        db.store_message(&env).await.unwrap();
    }

    let recipient = Recipient::Node(make_node_id(2));

    // Get messages before ts=4000
    let msgs = db
        .get_messages_for_recipient(&recipient, 10, Some(4_000))
        .await
        .unwrap();

    for msg in &msgs {
        assert!(msg.timestamp < 4_000, "Expected all messages before 4000");
    }
}

#[tokio::test]
async fn messages_limit_respected() {
    let db = setup().await;

    for ts in 1..=10u64 {
        let env = make_envelope(0, 1, 2, ts * 1_000);
        db.store_message(&env).await.unwrap();
    }

    let recipient = Recipient::Node(make_node_id(2));
    let msgs = db
        .get_messages_for_recipient(&recipient, 3, None)
        .await
        .unwrap();
    assert_eq!(msgs.len(), 3);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROOM MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn create_and_get_room() {
    let db = setup().await;
    let room = Room::new("Test Room".to_string(), make_node_id(1));
    db.create_room(&room).await.unwrap();

    let loaded = db.get_room(&room.id).await.unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().name, "Test Room");
}

#[tokio::test]
async fn list_rooms_returns_all() {
    let db = setup().await;
    for i in 0..5u8 {
        let room = Room::new(format!("Room {i}"), make_node_id(i));
        db.create_room(&room).await.unwrap();
    }
    assert_eq!(db.list_rooms().await.unwrap().len(), 5);
}

#[tokio::test]
async fn delete_room_removes_it() {
    let db = setup().await;
    let room = Room::new("Doomed".to_string(), make_node_id(1));
    db.create_room(&room).await.unwrap();
    assert!(db.delete_room(&room.id).await.unwrap());
    assert!(db.get_room(&room.id).await.unwrap().is_none());
}

#[tokio::test]
async fn delete_nonexistent_room_returns_false() {
    let db = setup().await;
    let fake_id = konsensus_core::RoomId::new();
    assert!(!db.delete_room(&fake_id).await.unwrap());
}

#[tokio::test]
async fn room_member_management() {
    let db = setup().await;
    let room = Room::new("Members Test".to_string(), make_node_id(1));
    db.create_room(&room).await.unwrap();

    let member_a = make_node_id(10);
    let member_b = make_node_id(11);

    db.add_room_member(&room.id, &member_a).await.unwrap();
    db.add_room_member(&room.id, &member_b).await.unwrap();

    let members = db.get_room_members(&room.id).await.unwrap();
    assert_eq!(members.len(), 2);

    // Remove one member
    db.remove_room_member(&room.id, &member_a).await.unwrap();
    let members = db.get_room_members(&room.id).await.unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0], member_b);
}

#[tokio::test]
async fn add_duplicate_room_member_is_idempotent() {
    let db = setup().await;
    let room = Room::new("Dup Test".to_string(), make_node_id(1));
    db.create_room(&room).await.unwrap();

    let member = make_node_id(10);
    db.add_room_member(&room.id, &member).await.unwrap();
    db.add_room_member(&room.id, &member).await.unwrap(); // Should not error
    assert_eq!(db.get_room_members(&room.id).await.unwrap().len(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════════
// PEER MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn upsert_and_get_peer() {
    let db = setup().await;
    let node_id = make_node_id(5);
    let mut peer = Peer::new(node_id);
    peer.display_name = Some("Alice".to_string());
    peer.address = Some("10.0.0.1:9735".to_string());

    db.upsert_peer(&peer).await.unwrap();

    let loaded = db.get_peer(&node_id).await.unwrap().unwrap();
    assert_eq!(loaded.display_name.as_deref(), Some("Alice"));
    assert_eq!(loaded.address.as_deref(), Some("10.0.0.1:9735"));
}

#[tokio::test]
async fn upsert_peer_updates_existing() {
    let db = setup().await;
    let node_id = make_node_id(5);

    let mut peer = Peer::new(node_id);
    peer.display_name = Some("Alice".to_string());
    db.upsert_peer(&peer).await.unwrap();

    // Update the name
    peer.display_name = Some("Alice Updated".to_string());
    db.upsert_peer(&peer).await.unwrap();

    let loaded = db.get_peer(&node_id).await.unwrap().unwrap();
    assert_eq!(loaded.display_name.as_deref(), Some("Alice Updated"));
}

#[tokio::test]
async fn list_peers_returns_all() {
    let db = setup().await;
    for i in 0..4u8 {
        db.upsert_peer(&Peer::new(make_node_id(i))).await.unwrap();
    }
    assert_eq!(db.list_peers().await.unwrap().len(), 4);
}

#[tokio::test]
async fn delete_peer_returns_true_when_exists() {
    let db = setup().await;
    let id = make_node_id(5);
    db.upsert_peer(&Peer::new(id)).await.unwrap();
    assert!(db.delete_peer(&id).await.unwrap());
    assert!(db.get_peer(&id).await.unwrap().is_none());
}

#[tokio::test]
async fn delete_nonexistent_peer_returns_false() {
    let db = setup().await;
    assert!(!db.delete_peer(&make_node_id(99)).await.unwrap());
}

#[tokio::test]
async fn peer_with_all_optional_fields_none() {
    let db = setup().await;
    let peer = Peer::new(make_node_id(50));
    db.upsert_peer(&peer).await.unwrap();
    let loaded = db.get_peer(&make_node_id(50)).await.unwrap().unwrap();
    assert!(loaded.address.is_none());
    assert!(loaded.last_seen.is_none());
    assert!(loaded.display_name.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// NONCE REPLAY PROTECTION
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn store_nonce_returns_true_for_new() {
    let db = setup().await;
    let nonce = Nonce::generate();
    let sender = make_node_id(1);
    assert!(db.store_nonce(&nonce, &sender).await.unwrap());
}

#[tokio::test]
async fn store_nonce_returns_false_for_duplicate() {
    let db = setup().await;
    let nonce = Nonce::generate();
    let sender = make_node_id(1);
    assert!(db.store_nonce(&nonce, &sender).await.unwrap());
    assert!(!db.store_nonce(&nonce, &sender).await.unwrap());
}

#[tokio::test]
async fn same_nonce_different_senders_still_replay() {
    let db = setup().await;
    let nonce = Nonce::generate();
    // Nonce is globally unique — same nonce from different senders is still a replay
    assert!(db.store_nonce(&nonce, &make_node_id(1)).await.unwrap());
    assert!(!db.store_nonce(&nonce, &make_node_id(2)).await.unwrap());
}

#[tokio::test]
async fn has_nonce_true_after_store() {
    let db = setup().await;
    let nonce = Nonce::generate();
    db.store_nonce(&nonce, &make_node_id(1)).await.unwrap();
    assert!(db.has_nonce(&nonce).await.unwrap());
}

#[tokio::test]
async fn has_nonce_false_for_unseen() {
    let db = setup().await;
    assert!(!db.has_nonce(&Nonce::generate()).await.unwrap());
}

#[tokio::test]
async fn cleanup_expired_nonces_removes_old() {
    let db = setup().await;
    // Store some nonces (they get current timestamps)
    for i in 0..5u8 {
        db.store_nonce(&Nonce::from_bytes([i; 24]), &make_node_id(1))
            .await
            .unwrap();
    }
    // Wait 1 second so all nonces are at least 1 second old
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // Cleanup with 0 age should remove all
    let removed = db.cleanup_expired_nonces(0).await.unwrap();
    assert_eq!(removed, 5);
}

#[tokio::test]
async fn cleanup_expired_nonces_keeps_recent() {
    let db = setup().await;
    for i in 0..3u8 {
        db.store_nonce(&Nonce::from_bytes([i; 24]), &make_node_id(1))
            .await
            .unwrap();
    }
    // Cleanup with very large age should keep all
    let removed = db.cleanup_expired_nonces(3600).await.unwrap();
    assert_eq!(removed, 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// E2EE SESSION PERSISTENCE
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn store_and_load_session() {
    let db = setup().await;
    let peer_id = make_node_id(10);
    let blob = b"encrypted-session-state-json".to_vec();
    db.store_session(&peer_id, &blob).await.unwrap();

    let loaded = db.load_session(&peer_id).await.unwrap();
    assert_eq!(loaded, Some(blob));
}

#[tokio::test]
async fn load_nonexistent_session_returns_none() {
    let db = setup().await;
    assert!(db.load_session(&make_node_id(99)).await.unwrap().is_none());
}

#[tokio::test]
async fn store_session_overwrites_existing() {
    let db = setup().await;
    let peer_id = make_node_id(10);
    db.store_session(&peer_id, b"v1").await.unwrap();
    db.store_session(&peer_id, b"v2").await.unwrap();

    let loaded = db.load_session(&peer_id).await.unwrap().unwrap();
    assert_eq!(loaded, b"v2");
}

#[tokio::test]
async fn delete_session_returns_true() {
    let db = setup().await;
    let peer_id = make_node_id(10);
    db.store_session(&peer_id, b"blob").await.unwrap();
    assert!(db.delete_session(&peer_id).await.unwrap());
    assert!(db.load_session(&peer_id).await.unwrap().is_none());
}

#[tokio::test]
async fn delete_nonexistent_session_returns_false() {
    let db = setup().await;
    assert!(!db.delete_session(&make_node_id(99)).await.unwrap());
}

#[tokio::test]
async fn list_sessions_returns_all_peer_ids() {
    let db = setup().await;
    for i in 0..3u8 {
        db.store_session(&make_node_id(i), &[i; 16])
            .await
            .unwrap();
    }
    let sessions = db.list_sessions().await.unwrap();
    assert_eq!(sessions.len(), 3);
}

#[tokio::test]
async fn session_with_empty_blob() {
    let db = setup().await;
    let peer = make_node_id(10);
    db.store_session(&peer, b"").await.unwrap();
    let loaded = db.load_session(&peer).await.unwrap().unwrap();
    assert!(loaded.is_empty());
}

#[tokio::test]
async fn session_with_large_blob() {
    let db = setup().await;
    let peer = make_node_id(10);
    let blob = vec![0xAB; 256 * 1024]; // 256 KB
    db.store_session(&peer, &blob).await.unwrap();
    let loaded = db.load_session(&peer).await.unwrap().unwrap();
    assert_eq!(loaded.len(), 256 * 1024);
}

// ═══════════════════════════════════════════════════════════════════════════════
// PENDING DELIVERY QUEUE
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn queue_and_get_pending_delivery() {
    let db = setup().await;
    let env = make_envelope(0, 1, 2, 1_000);
    db.store_message(&env).await.unwrap();

    let recipient = make_node_id(2);
    db.queue_pending_delivery(&env.id, &recipient)
        .await
        .unwrap();

    let pending = db.get_pending_for_peer(&recipient).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, env.id);
    assert_eq!(pending[0].1, 0); // zero attempts
}

#[tokio::test]
async fn queue_pending_is_idempotent() {
    let db = setup().await;
    let env = make_envelope(0, 1, 2, 1_000);
    db.store_message(&env).await.unwrap();
    let recipient = make_node_id(2);

    db.queue_pending_delivery(&env.id, &recipient).await.unwrap();
    db.queue_pending_delivery(&env.id, &recipient).await.unwrap(); // no error
    assert_eq!(db.get_pending_for_peer(&recipient).await.unwrap().len(), 1);
}

#[tokio::test]
async fn remove_pending_delivery_works() {
    let db = setup().await;
    let env = make_envelope(0, 1, 2, 1_000);
    db.store_message(&env).await.unwrap();
    let recipient = make_node_id(2);

    db.queue_pending_delivery(&env.id, &recipient).await.unwrap();
    db.remove_pending_delivery(&env.id, &recipient).await.unwrap();
    assert!(db.get_pending_for_peer(&recipient).await.unwrap().is_empty());
}

#[tokio::test]
async fn increment_pending_attempts() {
    let db = setup().await;
    let env = make_envelope(0, 1, 2, 1_000);
    db.store_message(&env).await.unwrap();
    let recipient = make_node_id(2);

    db.queue_pending_delivery(&env.id, &recipient).await.unwrap();
    db.increment_pending_attempts(&env.id, &recipient).await.unwrap();
    db.increment_pending_attempts(&env.id, &recipient).await.unwrap();

    let pending = db.get_pending_for_peer(&recipient).await.unwrap();
    assert_eq!(pending[0].1, 2); // 2 attempts
}

#[tokio::test]
async fn count_pending_deliveries_across_peers() {
    let db = setup().await;

    for i in 0..3u64 {
        let env = make_envelope(0, 1, (i as u8) + 10, i + 1_000);
        db.store_message(&env).await.unwrap();
        db.queue_pending_delivery(&env.id, &make_node_id((i as u8) + 10))
            .await
            .unwrap();
    }

    assert_eq!(db.count_pending_deliveries().await.unwrap(), 3);
}

#[tokio::test]
async fn get_pending_peers_returns_distinct() {
    let db = setup().await;

    // Queue 2 messages for peer 10, 1 for peer 11
    let env1 = make_envelope(0, 1, 10, 1_000);
    let env2 = make_envelope(0, 1, 10, 2_000);
    let env3 = make_envelope(0, 1, 11, 3_000);

    for env in [&env1, &env2, &env3] {
        db.store_message(env).await.unwrap();
    }
    db.queue_pending_delivery(&env1.id, &make_node_id(10)).await.unwrap();
    db.queue_pending_delivery(&env2.id, &make_node_id(10)).await.unwrap();
    db.queue_pending_delivery(&env3.id, &make_node_id(11)).await.unwrap();

    let peers = db.get_pending_peers().await.unwrap();
    assert_eq!(peers.len(), 2);
}

#[tokio::test]
async fn clear_pending_for_peer_removes_all() {
    let db = setup().await;
    let recipient = make_node_id(10);

    for ts in [1_000u64, 2_000, 3_000] {
        let env = make_envelope(0, 1, 10, ts);
        db.store_message(&env).await.unwrap();
        db.queue_pending_delivery(&env.id, &recipient).await.unwrap();
    }

    let cleared = db.clear_pending_for_peer(&recipient).await.unwrap();
    assert_eq!(cleared, 3);
    assert!(db.get_pending_for_peer(&recipient).await.unwrap().is_empty());
}

#[tokio::test]
async fn cleanup_stale_pending_removes_high_attempt_entries() {
    let db = setup().await;
    let env = make_envelope(0, 1, 2, 1_000);
    db.store_message(&env).await.unwrap();
    let recipient = make_node_id(2);

    db.queue_pending_delivery(&env.id, &recipient).await.unwrap();

    // Increment to 5 attempts
    for _ in 0..5 {
        db.increment_pending_attempts(&env.id, &recipient).await.unwrap();
    }

    // Cleanup with max_attempts=3 should remove this entry
    let removed = db.cleanup_stale_pending(3).await.unwrap();
    assert_eq!(removed, 1);
    assert!(db.get_pending_for_peer(&recipient).await.unwrap().is_empty());
}

#[tokio::test]
async fn cleanup_stale_pending_keeps_low_attempt_entries() {
    let db = setup().await;
    let env = make_envelope(0, 1, 2, 1_000);
    db.store_message(&env).await.unwrap();
    let recipient = make_node_id(2);

    db.queue_pending_delivery(&env.id, &recipient).await.unwrap();
    db.increment_pending_attempts(&env.id, &recipient).await.unwrap();

    // Cleanup with max_attempts=5 should keep this (only 1 attempt)
    let removed = db.cleanup_stale_pending(5).await.unwrap();
    assert_eq!(removed, 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE STORAGE
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn store_and_get_file() {
    let db = setup().await;
    let file = make_file_record("file-001", "readme.md", b"# Hello");
    db.store_file(&file).await.unwrap();

    let loaded = db.get_file("file-001").await.unwrap().unwrap();
    assert_eq!(loaded.filename, "readme.md");
    assert_eq!(loaded.data, b"# Hello");
    assert_eq!(loaded.size_bytes, 7);
}

#[tokio::test]
async fn get_file_metadata_excludes_data() {
    let db = setup().await;
    let file = make_file_record("file-002", "big.bin", &[0xFF; 1024]);
    db.store_file(&file).await.unwrap();

    let meta = db.get_file_metadata("file-002").await.unwrap().unwrap();
    assert_eq!(meta.filename, "big.bin");
    assert_eq!(meta.size_bytes, 1024);
    // FileMetadata doesn't have a data field, so this just confirms it compiles/loads
}

#[tokio::test]
async fn list_files_returns_correct_count() {
    let db = setup().await;

    // Store files sequentially — SQLite uses datetime('now') for created_at
    // so ordering within a single test may be insertion order. Just verify
    // the correct count is returned and all IDs are present.
    for id in ["a", "b", "c"] {
        let file = make_file_record(id, &format!("{id}.txt"), b"data");
        db.store_file(&file).await.unwrap();
    }

    let files = db.list_files(10).await.unwrap();
    assert_eq!(files.len(), 3);

    let ids: Vec<&str> = files.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"a"));
    assert!(ids.contains(&"b"));
    assert!(ids.contains(&"c"));
}

#[tokio::test]
async fn list_files_respects_limit() {
    let db = setup().await;
    for i in 0..10 {
        let file = make_file_record(&format!("f-{i}"), "x.txt", b"x");
        db.store_file(&file).await.unwrap();
    }
    assert_eq!(db.list_files(3).await.unwrap().len(), 3);
}

#[tokio::test]
async fn delete_file_returns_true_when_exists() {
    let db = setup().await;
    let file = make_file_record("del-me", "temp.txt", b"temp");
    db.store_file(&file).await.unwrap();
    assert!(db.delete_file("del-me").await.unwrap());
    assert!(db.get_file("del-me").await.unwrap().is_none());
}

#[tokio::test]
async fn delete_nonexistent_file_returns_false() {
    let db = setup().await;
    assert!(!db.delete_file("nope").await.unwrap());
}

#[tokio::test]
async fn file_with_empty_data() {
    let db = setup().await;
    let file = make_file_record("empty", "empty.bin", b"");
    db.store_file(&file).await.unwrap();
    let loaded = db.get_file("empty").await.unwrap().unwrap();
    assert!(loaded.data.is_empty());
    assert_eq!(loaded.size_bytes, 0);
}

#[tokio::test]
async fn file_with_large_data() {
    let db = setup().await;
    let data = vec![0xAB; 1024 * 1024]; // 1 MB
    let file = make_file_record("big", "big.bin", &data);
    db.store_file(&file).await.unwrap();
    let loaded = db.get_file("big").await.unwrap().unwrap();
    assert_eq!(loaded.data.len(), 1024 * 1024);
}

// ═══════════════════════════════════════════════════════════════════════════════
// PLAINTEXT CACHE
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn store_and_get_message_plaintext() {
    let db = setup().await;
    let env = make_envelope(0, 1, 2, 1_000);
    db.store_message(&env).await.unwrap();

    let encrypted_pt = b"aes-gcm-encrypted-plaintext".to_vec();
    db.store_message_plaintext(&env.id, &encrypted_pt).await.unwrap();

    let loaded = db.get_message_plaintext(&env.id).await.unwrap().unwrap();
    assert_eq!(loaded, encrypted_pt);
}

#[tokio::test]
async fn get_plaintext_for_uncached_message_returns_none() {
    let db = setup().await;
    let fake_id = MessageId::compute(b"no-cache", &Nonce::generate());
    assert!(db.get_message_plaintext(&fake_id).await.unwrap().is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// CROSS-METHOD INTERACTIONS
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn deleting_message_does_not_affect_other_messages() {
    let db = setup().await;
    let env1 = make_envelope(0, 1, 2, 1_000);
    let env2 = make_envelope(0, 1, 2, 2_000);

    db.store_message(&env1).await.unwrap();
    db.store_message(&env2).await.unwrap();

    db.delete_message(&env1.id).await.unwrap();
    assert!(db.get_message(&env1.id).await.unwrap().is_none());
    assert!(db.get_message(&env2.id).await.unwrap().is_some());
}

#[tokio::test]
async fn multiple_nonces_from_same_sender_all_unique() {
    let db = setup().await;
    let sender = make_node_id(1);

    for i in 0..10u8 {
        let nonce = Nonce::from_bytes([i; 24]);
        assert!(db.store_nonce(&nonce, &sender).await.unwrap());
    }
    // All 10 should be stored
    for i in 0..10u8 {
        assert!(db.has_nonce(&Nonce::from_bytes([i; 24])).await.unwrap());
    }
}

#[tokio::test]
async fn pending_delivery_survives_message_retrieval() {
    let db = setup().await;
    let env = make_envelope(0, 1, 2, 1_000);
    db.store_message(&env).await.unwrap();
    let recipient = make_node_id(2);
    db.queue_pending_delivery(&env.id, &recipient).await.unwrap();

    // Reading the message should not affect pending queue
    let _ = db.get_message(&env.id).await.unwrap();
    assert_eq!(db.get_pending_for_peer(&recipient).await.unwrap().len(), 1);
}

#[tokio::test]
async fn concurrent_session_stores_last_write_wins() {
    let db = setup().await;
    let peer = make_node_id(10);

    // Simulate rapid overwrites
    for i in 0..20u8 {
        db.store_session(&peer, &[i; 32]).await.unwrap();
    }

    let loaded = db.load_session(&peer).await.unwrap().unwrap();
    assert_eq!(loaded, vec![19u8; 32]); // last write wins
}

// ── QA-L7: FK cascade — deleting a message removes its pending deliveries ──

#[tokio::test]
async fn delete_message_cascades_to_pending_deliveries() {
    let db = setup().await;
    let env = make_envelope(0, 1, 2, 1_000);
    db.store_message(&env).await.unwrap();
    let recipient = make_node_id(2);

    db.queue_pending_delivery(&env.id, &recipient).await.unwrap();
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 1);

    // Deleting the message should also remove the pending delivery
    assert!(db.delete_message(&env.id).await.unwrap());
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 0);
}

#[tokio::test]
async fn delete_messages_older_than_cascades_to_pending_deliveries() {
    let db = setup().await;

    // Store 3 messages: two old (ts=1000, 2000) and one new (ts=100_000)
    let old1 = make_envelope(0, 1, 2, 1_000);
    let old2 = make_envelope(0, 1, 3, 2_000);
    let new1 = make_envelope(0, 1, 4, 100_000);
    db.store_message(&old1).await.unwrap();
    db.store_message(&old2).await.unwrap();
    db.store_message(&new1).await.unwrap();

    let peer2 = make_node_id(2);
    let peer3 = make_node_id(3);
    let peer4 = make_node_id(4);
    db.queue_pending_delivery(&old1.id, &peer2).await.unwrap();
    db.queue_pending_delivery(&old2.id, &peer3).await.unwrap();
    db.queue_pending_delivery(&new1.id, &peer4).await.unwrap();
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 3);

    // Delete messages older than ts=50_000 — should remove old1, old2 and their deliveries
    let deleted = db.delete_messages_older_than(50_000).await.unwrap();
    assert_eq!(deleted, 2);
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 1);

    // The remaining delivery should be for the new message
    let remaining = db.get_pending_for_peer(&peer4).await.unwrap();
    assert_eq!(remaining.len(), 1);
}
