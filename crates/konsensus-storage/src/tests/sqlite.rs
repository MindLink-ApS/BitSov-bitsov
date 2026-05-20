use super::*;
use konsensus_core::kind::KIND_CHAT;
use konsensus_core::UkmEnvelopeBuilder;
use sha2::{Digest, Sha256};

fn make_proof() -> PaymentProof {
    let preimage = [42u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    PaymentProof::new(hash, preimage, 10)
}

fn make_envelope(sender: NodeId, recipient: Recipient) -> UkmEnvelope {
    UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"test ciphertext".to_vec(), make_proof())
        .timestamp(1_700_000_000_000)
        .build()
}

#[tokio::test]
async fn sqlite_invite_schema_capabilities_reports_v2_columns(
) -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let caps = db.invite_schema_capabilities().await?;

    assert!(caps.addr_column);
    assert!(caps.max_fee_rate_sat_per_vb_column);
    assert!(caps.channel_open_intent_expiry_unix_column);
    assert!(caps.v2_ready());
    Ok(())
}

#[tokio::test]
async fn message_store_and_retrieve() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let envelope = make_envelope(sender, recipient);

    db.store_message(&envelope).await?;
    let retrieved = db.get_message(&envelope.id).await?.expect("value should exist");

    assert_eq!(retrieved.id, envelope.id);
    assert_eq!(retrieved.kind, envelope.kind);
    assert_eq!(retrieved.sender, envelope.sender);
    assert_eq!(retrieved.recipient, envelope.recipient);
    assert_eq!(retrieved.timestamp, envelope.timestamp);
    assert_eq!(retrieved.ciphertext, envelope.ciphertext);
    Ok(())
}

#[tokio::test]
async fn message_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let id = MessageId::from_bytes([0u8; 32]);
    assert!(db.get_message(&id).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn message_delete() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let envelope = make_envelope(sender, recipient);

    db.store_message(&envelope).await?;
    assert!(db.delete_message(&envelope.id).await?);
    assert!(db.get_message(&envelope.id).await?.is_none());
    // Second delete returns false
    assert!(!db.delete_message(&envelope.id).await?);
    Ok(())
}

#[tokio::test]
async fn messages_for_recipient_pagination() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let node2 = NodeId::from_bytes([2u8; 32]);
    let recipient = Recipient::Node(node2);

    // Insert 3 messages with different timestamps
    for i in 0..3u64 {
        let proof = make_proof();
        let ct = format!("msg {i}").into_bytes();
        let env = UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, ct, proof)
            .timestamp(1_700_000_000_000 + i * 1000)
            .build();
        db.store_message(&env).await?;
    }

    // Get all — should return 3, newest first
    let msgs = db
        .get_messages_for_recipient(&recipient, 10, None)
        .await?;
    assert_eq!(msgs.len(), 3);
    assert!(msgs[0].timestamp > msgs[1].timestamp);

    // Paginate — get only before the newest
    let msgs = db
        .get_messages_for_recipient(&recipient, 10, Some(msgs[0].timestamp))
        .await?;
    assert_eq!(msgs.len(), 2);
    Ok(())
}

#[tokio::test]
async fn conversation_messages_includes_both_directions() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let alice = NodeId::from_bytes([1u8; 32]);
    let bob = NodeId::from_bytes([2u8; 32]);

    // Alice sends to Bob (outgoing from Alice's perspective)
    let env1 = UkmEnvelopeBuilder::new(
        KIND_CHAT, alice, Recipient::Node(bob), b"hello bob".to_vec(), make_proof(),
    ).timestamp(1_700_000_000_000).build();
    db.store_message(&env1).await?;

    // Bob sends to Alice (incoming from Alice's perspective)
    let env2 = UkmEnvelopeBuilder::new(
        KIND_CHAT, bob, Recipient::Node(alice), b"hello alice".to_vec(), make_proof(),
    ).timestamp(1_700_000_001_000).build();
    db.store_message(&env2).await?;

    // Conversation from Alice's POV should include both
    let msgs = db
        .get_conversation_messages(&alice.to_hex(), &bob.to_hex(), false, 10, None)
        .await?;
    assert_eq!(msgs.len(), 2);
    // Newest first
    assert_eq!(msgs[0].id, env2.id);
    assert_eq!(msgs[1].id, env1.id);

    // get_messages_for_recipient only returns incoming (recipient = alice)
    let incoming_only = db
        .get_messages_for_recipient(&Recipient::Node(alice), 10, None)
        .await?;
    assert_eq!(incoming_only.len(), 1);
    assert_eq!(incoming_only[0].sender, bob);
    Ok(())
}

#[tokio::test]
async fn conversation_messages_pagination() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let alice = NodeId::from_bytes([1u8; 32]);
    let bob = NodeId::from_bytes([2u8; 32]);

    for i in 0..5u64 {
        let sender = if i % 2 == 0 { alice } else { bob };
        let recipient = if i % 2 == 0 { Recipient::Node(bob) } else { Recipient::Node(alice) };
        let env = UkmEnvelopeBuilder::new(
            KIND_CHAT, sender, recipient, format!("msg {i}").into_bytes(), make_proof(),
        ).timestamp(1_700_000_000_000 + i * 1000).build();
        db.store_message(&env).await?;
    }

    // Get all 5
    let all = db
        .get_conversation_messages(&alice.to_hex(), &bob.to_hex(), false, 10, None)
        .await?;
    assert_eq!(all.len(), 5);

    // Get before the middle message (timestamp of msg 2 = base + 2000)
    let older = db
        .get_conversation_messages(
            &alice.to_hex(), &bob.to_hex(), false, 10,
            Some(1_700_000_002_000),
        )
        .await?;
    assert_eq!(older.len(), 2); // msg 0 and msg 1

    // Limit works
    let limited = db
        .get_conversation_messages(&alice.to_hex(), &bob.to_hex(), false, 2, None)
        .await?;
    assert_eq!(limited.len(), 2);
    Ok(())
}

#[tokio::test]
async fn conversation_messages_room() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let alice = NodeId::from_bytes([1u8; 32]);
    let bob = NodeId::from_bytes([2u8; 32]);
    let room_id = RoomId::new();

    // Two messages in the same room from different senders
    let env1 = UkmEnvelopeBuilder::new(
        KIND_CHAT, alice, Recipient::Room(room_id), b"alice msg".to_vec(), make_proof(),
    ).timestamp(1_700_000_000_000).build();
    let env2 = UkmEnvelopeBuilder::new(
        KIND_CHAT, bob, Recipient::Room(room_id), b"bob msg".to_vec(), make_proof(),
    ).timestamp(1_700_000_001_000).build();
    db.store_message(&env1).await?;
    db.store_message(&env2).await?;

    let msgs = db
        .get_conversation_messages(
            &alice.to_hex(), &room_id.to_string(), true, 10, None,
        )
        .await?;
    assert_eq!(msgs.len(), 2);
    Ok(())
}

#[tokio::test]
async fn conversation_messages_excludes_other_peers() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let alice = NodeId::from_bytes([1u8; 32]);
    let bob = NodeId::from_bytes([2u8; 32]);
    let charlie = NodeId::from_bytes([3u8; 32]);

    // Alice <-> Bob
    let env1 = UkmEnvelopeBuilder::new(
        KIND_CHAT, alice, Recipient::Node(bob), b"to bob".to_vec(), make_proof(),
    ).timestamp(1_700_000_000_000).build();
    // Alice <-> Charlie
    let env2 = UkmEnvelopeBuilder::new(
        KIND_CHAT, alice, Recipient::Node(charlie), b"to charlie".to_vec(), make_proof(),
    ).timestamp(1_700_000_001_000).build();
    db.store_message(&env1).await?;
    db.store_message(&env2).await?;

    // Conversation with Bob should only have 1 message
    let msgs = db
        .get_conversation_messages(&alice.to_hex(), &bob.to_hex(), false, 10, None)
        .await?;
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].id, env1.id);
    Ok(())
}

#[tokio::test]
async fn room_crud() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let creator = NodeId::from_bytes([1u8; 32]);

    let room = Room::new("Test Room".into(), creator);
    let room_id = room.id;

    db.create_room(&room).await?;

    let retrieved = db.get_room(&room_id).await?.expect("value should exist");
    assert_eq!(retrieved.name, "Test Room");
    assert_eq!(retrieved.created_by, creator);

    let rooms = db.list_rooms().await?;
    assert_eq!(rooms.len(), 1);
    Ok(())
}

#[tokio::test]
async fn room_members() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let creator = NodeId::from_bytes([1u8; 32]);
    let member1 = NodeId::from_bytes([2u8; 32]);
    let member2 = NodeId::from_bytes([3u8; 32]);

    let room = Room::new("Group".into(), creator);
    let room_id = room.id;
    db.create_room(&room).await?;

    db.add_room_member(&room_id, &member1).await?;
    db.add_room_member(&room_id, &member2).await?;

    let members = db.get_room_members(&room_id).await?;
    assert_eq!(members.len(), 2);

    db.remove_room_member(&room_id, &member1).await?;
    let members = db.get_room_members(&room_id).await?;
    assert_eq!(members.len(), 1);
    assert_eq!(members[0], member2);
    Ok(())
}

#[tokio::test]
async fn peer_crud() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let nid = NodeId::from_bytes([1u8; 32]);

    let mut peer = Peer::new(nid);
    peer.address = Some("127.0.0.1:9735".into());
    peer.display_name = Some("Alice".into());

    db.upsert_peer(&peer).await?;

    let retrieved = db.get_peer(&nid).await?.expect("value should exist");
    assert_eq!(retrieved.address.as_deref(), Some("127.0.0.1:9735"));
    assert_eq!(retrieved.display_name.as_deref(), Some("Alice"));

    // Update
    peer.display_name = Some("Alice Node".into());
    db.upsert_peer(&peer).await?;
    let updated = db.get_peer(&nid).await?.expect("value should exist");
    assert_eq!(updated.display_name.as_deref(), Some("Alice Node"));

    let peers = db.list_peers().await?;
    assert_eq!(peers.len(), 1);

    assert!(db.delete_peer(&nid).await?);
    assert!(db.get_peer(&nid).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn add_whitelisted_peer_with_invite_ref() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let invitee_bytes = [0xABu8; 32];
    let invitee = NodeId::from_bytes(invitee_bytes);
    let invite_id = uuid::Uuid::new_v4();

    db.add_whitelisted_peer_with_invite_ref(invitee_bytes, invite_id)
        .await?;

    let created = db
        .get_peer(&invitee)
        .await?
        .expect("invite-derived whitelist row should exist");
    assert_eq!(created.node_id, invitee);
    assert_eq!(created.metadata["invite_ref"], invite_id.to_string());
    assert_eq!(created.metadata["whitelist_source"], "invite");

    // Preserve existing peer fields while updating invite_ref metadata.
    let mut existing = Peer::new(invitee);
    existing.address = Some("127.0.0.1:9735".to_string());
    db.upsert_peer(&existing).await?;

    let invite_id_2 = uuid::Uuid::new_v4();
    db.add_whitelisted_peer_with_invite_ref(invitee_bytes, invite_id_2)
        .await?;
    let updated = db.get_peer(&invitee).await?.expect("peer should still exist");
    assert_eq!(updated.address.as_deref(), Some("127.0.0.1:9735"));
    assert_eq!(updated.metadata["invite_ref"], invite_id_2.to_string());
    assert_eq!(updated.metadata["whitelist_source"], "invite");

    Ok(())
}

#[tokio::test]
async fn atomic_invite_and_whitelist() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let invitee_pubkey = [0xABu8; 32];
    let invitee = NodeId::from_bytes(invitee_pubkey);
    let invite_id = uuid::Uuid::new_v4();
    let invite = InviteIssuedRecord {
        id: invite_id,
        invitee_pubkey,
        expiry_unix: 1_900_000_000,
        channel_size_hint_sats: Some(50_000),
        addr: "127.0.0.1:9735".to_string(),
        max_fee_rate_sat_per_vb: Some(42),
        channel_open_intent_expiry_unix: Some(1_900_000_000),
        nonce: [7u8; 16],
        state: InviteState::Pending,
        created_at: 1_800_000_000,
        accepted_at: None,
        revoked_at: None,
    };

    db.add_invite_and_whitelist(&invite, invitee_pubkey).await?;

    let persisted = db.find_invite_issued(&invite_id).await?;
    assert_eq!(persisted, Some(invite.clone()));

    let peer = db.get_peer(&invitee).await?.expect("peer should exist");
    assert_eq!(peer.metadata["invite_ref"], invite_id.to_string());
    assert_eq!(peer.metadata["whitelist_source"], "invite");
    Ok(())
}

#[tokio::test]
async fn session_store_load_delete() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let peer = NodeId::from_bytes([1u8; 32]);

    // No session initially
    assert!(db.load_session(&peer).await?.is_none());
    assert!(db.list_sessions().await?.is_empty());

    // Store session
    let blob = b"serialized ratchet state";
    db.store_session(&peer, blob).await?;

    // Load session
    let loaded = db.load_session(&peer).await?.expect("value should exist");
    assert_eq!(loaded, blob);

    // List sessions
    let sessions = db.list_sessions().await?;
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0], peer);

    // Update session (upsert)
    let blob2 = b"updated ratchet state";
    db.store_session(&peer, blob2).await?;
    let loaded2 = db.load_session(&peer).await?.expect("value should exist");
    assert_eq!(loaded2, blob2);

    // Still only one session
    assert_eq!(db.list_sessions().await?.len(), 1);

    // Delete
    assert!(db.delete_session(&peer).await?);
    assert!(db.load_session(&peer).await?.is_none());
    assert!(!db.delete_session(&peer).await?); // second delete returns false
    Ok(())
}

#[tokio::test]
async fn pending_delivery_queue_and_flush() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let peer = NodeId::from_bytes([2u8; 32]);
    let recipient = Recipient::Node(peer);

    // Store a message first (foreign key reference)
    let envelope = make_envelope(sender, recipient);
    db.store_message(&envelope).await?;

    // Queue pending delivery
    db.queue_pending_delivery(&envelope.id, &peer).await?;

    // Check pending count
    assert_eq!(db.count_pending_deliveries().await?, 1);

    // Get pending for peer
    let pending = db.get_pending_for_peer(&peer).await?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, envelope.id);
    assert_eq!(pending[0].1, 0); // zero attempts

    // Increment attempts
    db.increment_pending_attempts(&envelope.id, &peer).await?;
    let pending = db.get_pending_for_peer(&peer).await?;
    assert_eq!(pending[0].1, 1);

    // Get pending peers
    let peers = db.get_pending_peers().await?;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0], peer);

    // Remove pending delivery (simulating successful delivery)
    db.remove_pending_delivery(&envelope.id, &peer).await?;
    assert_eq!(db.count_pending_deliveries().await?, 0);
    assert!(db.get_pending_for_peer(&peer).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn pending_delivery_idempotent_queue() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let peer = NodeId::from_bytes([2u8; 32]);
    let recipient = Recipient::Node(peer);

    let envelope = make_envelope(sender, recipient);
    db.store_message(&envelope).await?;

    // Queue twice — should not fail (INSERT OR IGNORE)
    db.queue_pending_delivery(&envelope.id, &peer).await?;
    db.queue_pending_delivery(&envelope.id, &peer).await?;

    // Still only one entry
    assert_eq!(db.count_pending_deliveries().await?, 1);
    Ok(())
}

#[tokio::test]
async fn pending_delivery_multiple_peers() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let peer_a = NodeId::from_bytes([2u8; 32]);
    let peer_b = NodeId::from_bytes([3u8; 32]);

    // One message queued for two peers (e.g., room delivery)
    let envelope = make_envelope(sender, Recipient::Node(peer_a));
    db.store_message(&envelope).await?;

    db.queue_pending_delivery(&envelope.id, &peer_a).await?;
    db.queue_pending_delivery(&envelope.id, &peer_b).await?;

    assert_eq!(db.count_pending_deliveries().await?, 2);
    assert_eq!(db.get_pending_peers().await?.len(), 2);

    // Remove for peer_a only
    db.remove_pending_delivery(&envelope.id, &peer_a).await?;
    assert_eq!(db.count_pending_deliveries().await?, 1);
    assert_eq!(db.get_pending_for_peer(&peer_b).await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn clear_pending_for_peer_removes_all() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let peer_a = NodeId::from_bytes([2u8; 32]);
    let peer_b = NodeId::from_bytes([3u8; 32]);

    // Create two messages queued for peer_a and one for peer_b
    let env1 = make_envelope(sender, Recipient::Node(peer_a));
    let env2 = make_envelope(sender, Recipient::Node(peer_a));
    let env3 = make_envelope(sender, Recipient::Node(peer_b));
    db.store_message(&env1).await?;
    db.store_message(&env2).await?;
    db.store_message(&env3).await?;

    db.queue_pending_delivery(&env1.id, &peer_a).await?;
    db.queue_pending_delivery(&env2.id, &peer_a).await?;
    db.queue_pending_delivery(&env3.id, &peer_b).await?;
    assert_eq!(db.count_pending_deliveries().await?, 3);

    // Clear all pending for peer_a
    let cleared = db.clear_pending_for_peer(&peer_a).await?;
    assert_eq!(cleared, 2);
    assert_eq!(db.count_pending_deliveries().await?, 1);
    assert!(db.get_pending_for_peer(&peer_a).await?.is_empty());
    assert_eq!(db.get_pending_for_peer(&peer_b).await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn cleanup_stale_pending_removes_high_attempt_entries() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let peer = NodeId::from_bytes([2u8; 32]);

    let env1 = make_envelope(sender, Recipient::Node(peer));
    let env2 = make_envelope(sender, Recipient::Node(peer));
    let env3 = make_envelope(sender, Recipient::Node(peer));
    db.store_message(&env1).await?;
    db.store_message(&env2).await?;
    db.store_message(&env3).await?;

    db.queue_pending_delivery(&env1.id, &peer).await?;
    db.queue_pending_delivery(&env2.id, &peer).await?;
    db.queue_pending_delivery(&env3.id, &peer).await?;

    // Increment env1 to 10 attempts, env2 to 5 attempts, env3 stays at 0
    for _ in 0..10 {
        db.increment_pending_attempts(&env1.id, &peer).await?;
    }
    for _ in 0..5 {
        db.increment_pending_attempts(&env2.id, &peer).await?;
    }

    // Cleanup with max_attempts=10 should only remove env1
    let removed = db.cleanup_stale_pending(10).await?;
    assert_eq!(removed, 1);
    assert_eq!(db.count_pending_deliveries().await?, 2);

    // Cleanup with max_attempts=5 should remove env2
    let removed = db.cleanup_stale_pending(5).await?;
    assert_eq!(removed, 1);
    assert_eq!(db.count_pending_deliveries().await?, 1);

    // env3 (0 attempts) should still be there
    let pending = db.get_pending_for_peer(&peer).await?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, env3.id);
    Ok(())
}

/// remove_pending_delivery on nonexistent entry does not error.
#[tokio::test]
async fn remove_pending_delivery_nonexistent_is_noop() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let peer = NodeId::from_bytes([2u8; 32]);
    let fake_id = MessageId::from_bytes(rand::random::<[u8; 32]>());

    // Should succeed silently (DELETE WHERE ... matches nothing)
    db.remove_pending_delivery(&fake_id, &peer).await?;
    assert_eq!(db.count_pending_deliveries().await?, 0);
    Ok(())
}

/// increment_pending_attempts on nonexistent entry does not error.
#[tokio::test]
async fn increment_pending_attempts_nonexistent_is_noop() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let peer = NodeId::from_bytes([2u8; 32]);
    let fake_id = MessageId::from_bytes(rand::random::<[u8; 32]>());

    // Should succeed silently (UPDATE WHERE ... matches nothing)
    db.increment_pending_attempts(&fake_id, &peer).await?;
    Ok(())
}

/// clear_pending_for_peer on a peer with no pending deliveries returns 0.
#[tokio::test]
async fn clear_pending_for_peer_empty_returns_zero() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let peer = NodeId::from_bytes([2u8; 32]);

    let cleared = db.clear_pending_for_peer(&peer).await?;
    assert_eq!(cleared, 0);
    Ok(())
}

/// get_pending_for_peer returns entries in queued_at ASC order.
#[tokio::test]
async fn get_pending_for_peer_ordered_by_queue_time() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let peer = NodeId::from_bytes([2u8; 32]);

    // Queue 3 messages in order
    let env1 = make_envelope(sender, Recipient::Node(peer));
    let env2 = make_envelope(sender, Recipient::Node(peer));
    let env3 = make_envelope(sender, Recipient::Node(peer));
    db.store_message(&env1).await?;
    db.store_message(&env2).await?;
    db.store_message(&env3).await?;

    db.queue_pending_delivery(&env1.id, &peer).await?;
    db.queue_pending_delivery(&env2.id, &peer).await?;
    db.queue_pending_delivery(&env3.id, &peer).await?;

    let pending = db.get_pending_for_peer(&peer).await?;
    assert_eq!(pending.len(), 3);
    // Order should match insertion order (queued_at ASC)
    assert_eq!(pending[0].0, env1.id);
    assert_eq!(pending[1].0, env2.id);
    assert_eq!(pending[2].0, env3.id);
    Ok(())
}

/// increment_pending_attempts correctly tracks count across multiple increments.
#[tokio::test]
async fn increment_pending_attempts_tracks_count() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let peer = NodeId::from_bytes([2u8; 32]);

    let env = make_envelope(sender, Recipient::Node(peer));
    db.store_message(&env).await?;
    db.queue_pending_delivery(&env.id, &peer).await?;

    for expected in 1..=5 {
        db.increment_pending_attempts(&env.id, &peer).await?;
        let pending = db.get_pending_for_peer(&peer).await?;
        assert_eq!(pending[0].1, expected, "attempts should be {expected}");
    }
    Ok(())
}

#[tokio::test]
async fn file_store_and_retrieve() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let data = b"hello sovereign world".to_vec();
    let hash = blake3::hash(&data).to_hex().to_string();

    let file = crate::models::FileRecord {
        id: "file-001".into(),
        filename: "document.txt".into(),
        mime_type: "text/plain".into(),
        size_bytes: data.len() as u64,
        blake3_hash: hash.clone(),
        sender: "aa".repeat(32),
        message_id: None,
        data: data.clone(),
        created_at: String::new(), // default from DB
    };

    db.store_file(&file).await?;

    // Retrieve with data
    let retrieved = db.get_file("file-001").await?.expect("value should exist");
    assert_eq!(retrieved.filename, "document.txt");
    assert_eq!(retrieved.data, data);
    assert_eq!(retrieved.blake3_hash, hash);

    // Retrieve metadata only
    let meta = db.get_file_metadata("file-001").await?.expect("value should exist");
    assert_eq!(meta.filename, "document.txt");
    assert_eq!(meta.size_bytes, data.len() as u64);

    // List files
    let files = db.list_files(10).await?;
    assert_eq!(files.len(), 1);

    // Delete
    assert!(db.delete_file("file-001").await?);
    assert!(db.get_file("file-001").await?.is_none());
    assert!(!db.delete_file("file-001").await?);
    Ok(())
}

#[tokio::test]
async fn file_list_ordering_and_limit() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;

    for i in 0..5 {
        let file = crate::models::FileRecord {
            id: format!("file-{i:03}"),
            filename: format!("doc_{i}.txt"),
            mime_type: "text/plain".into(),
            size_bytes: 100,
            blake3_hash: format!("{i:064x}"),
            sender: "aa".repeat(32),
            message_id: None,
            data: vec![i as u8; 100],
            created_at: String::new(),
        };
        db.store_file(&file).await?;
    }

    // List with limit
    let files = db.list_files(3).await?;
    assert_eq!(files.len(), 3);

    // List all
    let all = db.list_files(100).await?;
    assert_eq!(all.len(), 5);
    Ok(())
}

#[tokio::test]
async fn nonce_replay_protection() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let nonce = Nonce::from_bytes([42u8; 24]);

    // First store succeeds
    assert!(db.store_nonce(&nonce, &sender).await?);
    assert!(db.has_nonce(&nonce).await?);

    // Second store returns false (replay detected)
    assert!(!db.store_nonce(&nonce, &sender).await?);

    // Different nonce succeeds
    let nonce2 = Nonce::from_bytes([99u8; 24]);
    assert!(db.store_nonce(&nonce2, &sender).await?);
    Ok(())
}

// ── Plaintext Cache Tests ───────────────────────────────────────────

#[tokio::test]
async fn plaintext_cache_store_and_retrieve() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let envelope = make_envelope(sender, recipient);

    // Store the message first (plaintext_enc column is on messages table)
    db.store_message(&envelope).await?;

    // Store plaintext cache
    let plaintext = b"encrypted-at-rest plaintext data";
    db.store_message_plaintext(&envelope.id, plaintext)
        .await?;

    // Retrieve it
    let retrieved = db
        .get_message_plaintext(&envelope.id)
        .await?
        .expect("value should exist");
    assert_eq!(retrieved, plaintext);
    Ok(())
}

#[tokio::test]
async fn plaintext_cache_returns_none_for_uncached() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let envelope = make_envelope(sender, recipient);

    // Store the message but don't set plaintext
    db.store_message(&envelope).await?;

    // Should be None
    let result = db.get_message_plaintext(&envelope.id).await?;
    assert!(result.is_none());
    Ok(())
}

#[tokio::test]
async fn plaintext_cache_returns_none_for_nonexistent_message() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let id = MessageId::from_bytes([0u8; 32]);

    // Message doesn't exist at all
    let result = db.get_message_plaintext(&id).await?;
    assert!(result.is_none());
    Ok(())
}

#[tokio::test]
async fn plaintext_cache_update_overwrites() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let envelope = make_envelope(sender, recipient);

    db.store_message(&envelope).await?;

    // Store initial plaintext
    db.store_message_plaintext(&envelope.id, b"version 1")
        .await?;

    // Overwrite with new plaintext
    db.store_message_plaintext(&envelope.id, b"version 2")
        .await?;

    let retrieved = db
        .get_message_plaintext(&envelope.id)
        .await?
        .expect("value should exist");
    assert_eq!(retrieved, b"version 2");
    Ok(())
}

#[tokio::test]
async fn plaintext_cache_empty_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let envelope = make_envelope(sender, recipient);

    db.store_message(&envelope).await?;

    // Store empty bytes
    db.store_message_plaintext(&envelope.id, b"")
        .await?;

    let retrieved = db
        .get_message_plaintext(&envelope.id)
        .await?
        .expect("value should exist");
    assert!(retrieved.is_empty());
    Ok(())
}

#[tokio::test]
async fn plaintext_cache_deleted_with_message() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let envelope = make_envelope(sender, recipient);

    db.store_message(&envelope).await?;
    db.store_message_plaintext(&envelope.id, b"cached plaintext")
        .await?;

    // Delete the message
    db.delete_message(&envelope.id).await?;

    // Plaintext should be gone too (it's a column on the messages table)
    let result = db.get_message_plaintext(&envelope.id).await?;
    assert!(result.is_none());
    Ok(())
}

// ── Boundary Condition Tests ─────────────────────────────────────────

#[tokio::test]
async fn messages_for_recipient_empty_result() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let node = NodeId::from_bytes([99u8; 32]);
    let recipient = Recipient::Node(node);

    let msgs = db
        .get_messages_for_recipient(&recipient, 10, None)
        .await?;
    assert!(msgs.is_empty());
    Ok(())
}

#[tokio::test]
async fn messages_for_recipient_limit_zero() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let envelope = make_envelope(sender, recipient);
    db.store_message(&envelope).await?;

    let msgs = db
        .get_messages_for_recipient(&recipient, 0, None)
        .await?;
    assert!(msgs.is_empty());
    Ok(())
}

#[tokio::test]
async fn room_member_idempotent_add() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let creator = NodeId::from_bytes([1u8; 32]);
    let member = NodeId::from_bytes([2u8; 32]);

    let room = Room::new("Test".into(), creator);
    db.create_room(&room).await?;

    // Add same member twice — should not error (INSERT OR IGNORE)
    db.add_room_member(&room.id, &member).await?;
    db.add_room_member(&room.id, &member).await?;

    let members = db.get_room_members(&room.id).await?;
    assert_eq!(members.len(), 1);
    Ok(())
}

#[tokio::test]
async fn remove_room_member_removes_single_member() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let creator = NodeId::from_bytes([1u8; 32]);
    let member_a = NodeId::from_bytes([2u8; 32]);
    let member_b = NodeId::from_bytes([3u8; 32]);

    let room = Room::new("Test".into(), creator);
    db.create_room(&room).await?;

    db.add_room_member(&room.id, &member_a).await?;
    db.add_room_member(&room.id, &member_b).await?;
    assert_eq!(db.get_room_members(&room.id).await?.len(), 2);

    // Remove member_a — member_b should remain
    db.remove_room_member(&room.id, &member_a).await?;
    let members = db.get_room_members(&room.id).await?;
    assert_eq!(members.len(), 1);
    assert_eq!(members[0], member_b);

    // Removing a non-member is a no-op (no error)
    db.remove_room_member(&room.id, &member_a).await?;
    assert_eq!(db.get_room_members(&room.id).await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn room_delete_cascades_members() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let creator = NodeId::from_bytes([1u8; 32]);
    let member = NodeId::from_bytes([2u8; 32]);

    let room = Room::new("Cascade Test".into(), creator);
    let room_id = room.id;
    db.create_room(&room).await?;
    db.add_room_member(&room_id, &member).await?;

    assert!(db.delete_room(&room_id).await?);

    // Members should be cascaded
    let members = db.get_room_members(&room_id).await?;
    assert!(members.is_empty());
    Ok(())
}

#[tokio::test]
async fn room_messages_with_room_recipient() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let creator = NodeId::from_bytes([2u8; 32]);

    let room = Room::new("Chat Room".into(), creator);
    db.create_room(&room).await?;

    let recipient = Recipient::Room(room.id);
    let envelope = make_envelope(sender, recipient);
    db.store_message(&envelope).await?;

    let msgs = db
        .get_messages_for_recipient(&recipient, 10, None)
        .await?;
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].id, envelope.id);
    Ok(())
}

#[tokio::test]
async fn file_delete_nonexistent() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    assert!(!db.delete_file("nonexistent-id").await?);
    Ok(())
}

#[tokio::test]
async fn file_metadata_nonexistent() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    assert!(db.get_file_metadata("nonexistent-id").await?.is_none());
    Ok(())
}

#[tokio::test]
async fn session_list_multiple_peers() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let peer1 = NodeId::from_bytes([1u8; 32]);
    let peer2 = NodeId::from_bytes([2u8; 32]);
    let peer3 = NodeId::from_bytes([3u8; 32]);

    db.store_session(&peer1, b"state1").await?;
    db.store_session(&peer2, b"state2").await?;
    db.store_session(&peer3, b"state3").await?;

    let sessions = db.list_sessions().await?;
    assert_eq!(sessions.len(), 3);

    // Delete one and verify
    db.delete_session(&peer2).await?;
    let sessions = db.list_sessions().await?;
    assert_eq!(sessions.len(), 2);
    assert!(!sessions.contains(&peer2));
    Ok(())
}

#[tokio::test]
async fn peer_delete_nonexistent() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let nid = NodeId::from_bytes([99u8; 32]);
    assert!(!db.delete_peer(&nid).await?);
    Ok(())
}

#[tokio::test]
async fn pending_remove_nonexistent() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let msg_id = MessageId::from_bytes([1u8; 32]);
    let peer = NodeId::from_bytes([2u8; 32]);

    // Should not error — just affects 0 rows
    db.remove_pending_delivery(&msg_id, &peer).await?;
    Ok(())
}

#[tokio::test]
async fn cleanup_stale_pending_zero_max() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let peer = NodeId::from_bytes([2u8; 32]);
    let envelope = make_envelope(sender, Recipient::Node(peer));
    db.store_message(&envelope).await?;
    db.queue_pending_delivery(&envelope.id, &peer).await?;

    // max_attempts=0 should remove entries with attempts >= 0
    // (i.e., everything)
    let removed = db.cleanup_stale_pending(0).await?;
    assert_eq!(removed, 1);
    Ok(())
}

// ── Recipient Conversion Tests ───────────────────────────────────────

#[test]
fn recipient_roundtrip_node() -> Result<(), Box<dyn std::error::Error>> {
    let nid = NodeId::from_bytes([42u8; 32]);
    let r = Recipient::Node(nid);
    let (rtype, rid) = recipient_to_parts(&r);
    let recovered = recipient_from_parts(rtype, &rid)?;
    assert_eq!(r, recovered);
    Ok(())
}

#[test]
fn recipient_roundtrip_room() -> Result<(), Box<dyn std::error::Error>> {
    let room_id = RoomId::new();
    let r = Recipient::Room(room_id);
    let (rtype, rid) = recipient_to_parts(&r);
    let recovered = recipient_from_parts(rtype, &rid)?;
    assert_eq!(r, recovered);
    Ok(())
}

#[test]
fn recipient_from_unknown_type_errors() {
    let result = recipient_from_parts("channel", "abc123");
    assert!(result.is_err());
    match result.unwrap_err() {
        StorageError::Conversion(msg) => {
            assert!(msg.contains("unknown recipient type"));
        }
        other => panic!("expected Conversion error, got {other:?}"),
    }
}

#[test]
fn recipient_from_invalid_node_id_errors() {
    let result = recipient_from_parts("node", "not-hex");
    assert!(result.is_err());
}

// ── Nonce Edge Case Tests ────────────────────────────────────────────

#[tokio::test]
async fn nonce_global_uniqueness_across_senders() -> Result<(), Box<dyn std::error::Error>> {
    // The same nonce value from different senders should be treated as replay.
    // The nonces table uses nonce_hex as PRIMARY KEY (not composite with sender).
    let db = SqliteStorage::in_memory().await?;
    let sender_a = NodeId::from_bytes([1u8; 32]);
    let sender_b = NodeId::from_bytes([2u8; 32]);
    let nonce = Nonce::from_bytes([42u8; 24]);

    // First store succeeds
    assert!(db.store_nonce(&nonce, &sender_a).await?);

    // Same nonce from different sender — should be rejected (global uniqueness)
    assert!(!db.store_nonce(&nonce, &sender_b).await?);

    // has_nonce only checks by nonce value, not sender
    assert!(db.has_nonce(&nonce).await?);
    Ok(())
}

#[tokio::test]
async fn nonce_different_values_same_sender() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let n1 = Nonce::from_bytes([1u8; 24]);
    let n2 = Nonce::from_bytes([2u8; 24]);

    assert!(db.store_nonce(&n1, &sender).await?);
    assert!(db.store_nonce(&n2, &sender).await?);
    assert!(db.has_nonce(&n1).await?);
    assert!(db.has_nonce(&n2).await?);
    Ok(())
}

#[tokio::test]
async fn nonce_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let nonce = Nonce::from_bytes([0u8; 24]);

    assert!(db.store_nonce(&nonce, &sender).await?);
    assert!(db.has_nonce(&nonce).await?);
    // Replay detected
    assert!(!db.store_nonce(&nonce, &sender).await?);
    Ok(())
}

#[tokio::test]
async fn nonce_has_nonce_nonexistent() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let nonce = Nonce::from_bytes([99u8; 24]);
    assert!(!db.has_nonce(&nonce).await?);
    Ok(())
}

// ── Duplicate Message Store Tests ────────────────────────────────────

#[tokio::test]
async fn message_store_duplicate_id_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    // Storing the same envelope twice should fail with UNIQUE constraint.
    // This is correct — message IDs are blake3(ciphertext||nonce) and
    // must be globally unique. A duplicate ID means either a replay or
    // a programming error in the caller.
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let envelope = make_envelope(sender, recipient);

    db.store_message(&envelope).await?;
    // Second store with same ID — should error
    let result = db.store_message(&envelope).await;
    assert!(result.is_err(), "duplicate message store should fail");
    Ok(())
}

// ── Session Large Blob Tests ─────────────────────────────────────────

#[tokio::test]
async fn session_store_large_blob() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let peer = NodeId::from_bytes([1u8; 32]);

    // 256 KB session blob (realistic for sessions with many skipped keys)
    let large_blob = vec![0xAB; 256 * 1024];
    db.store_session(&peer, &large_blob).await?;

    let loaded = db.load_session(&peer).await?.expect("value should exist");
    assert_eq!(loaded.len(), 256 * 1024);
    assert_eq!(loaded, large_blob);
    Ok(())
}

#[tokio::test]
async fn session_store_empty_blob() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let peer = NodeId::from_bytes([1u8; 32]);

    db.store_session(&peer, b"").await?;
    let loaded = db.load_session(&peer).await?.expect("value should exist");
    assert!(loaded.is_empty());
    Ok(())
}

// ── Pending Delivery Edge Cases ──────────────────────────────────────

#[tokio::test]
async fn pending_delivery_increment_multiple_times() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let peer = NodeId::from_bytes([2u8; 32]);
    let envelope = make_envelope(sender, Recipient::Node(peer));
    db.store_message(&envelope).await?;
    db.queue_pending_delivery(&envelope.id, &peer).await?;

    // Increment 100 times
    for _ in 0..100 {
        db.increment_pending_attempts(&envelope.id, &peer).await?;
    }

    let pending = db.get_pending_for_peer(&peer).await?;
    assert_eq!(pending[0].1, 100);
    Ok(())
}

#[tokio::test]
async fn pending_peers_empty_when_no_pending() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let peers = db.get_pending_peers().await?;
    assert!(peers.is_empty());
    Ok(())
}

#[tokio::test]
async fn count_pending_deliveries_empty() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    assert_eq!(db.count_pending_deliveries().await?, 0);
    Ok(())
}

// ── File Edge Cases ──────────────────────────────────────────────────

#[tokio::test]
async fn file_list_empty() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let files = db.list_files(100).await?;
    assert!(files.is_empty());
    Ok(())
}

#[tokio::test]
async fn file_store_large_data() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    // 1 MB file
    let data = vec![0xFFu8; 1024 * 1024];
    let hash = blake3::hash(&data).to_hex().to_string();

    let file = crate::models::FileRecord {
        id: "big-file".into(),
        filename: "large.bin".into(),
        mime_type: "application/octet-stream".into(),
        size_bytes: data.len() as u64,
        blake3_hash: hash,
        sender: "aa".repeat(32),
        message_id: None,
        data: data.clone(),
        created_at: String::new(),
    };

    db.store_file(&file).await?;
    let retrieved = db.get_file("big-file").await?.expect("value should exist");
    assert_eq!(retrieved.data.len(), 1024 * 1024);
    assert_eq!(retrieved.data, data);
    Ok(())
}

// ── Room Edge Cases ──────────────────────────────────────────────────

#[tokio::test]
async fn room_delete_nonexistent() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let fake_id = RoomId::new();
    assert!(!db.delete_room(&fake_id).await?);
    Ok(())
}

#[tokio::test]
async fn room_get_members_nonexistent_room() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let fake_id = RoomId::new();
    let members = db.get_room_members(&fake_id).await?;
    assert!(members.is_empty());
    Ok(())
}

#[tokio::test]
async fn room_list_empty() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let rooms = db.list_rooms().await?;
    assert!(rooms.is_empty());
    Ok(())
}

#[tokio::test]
async fn nonce_cleanup_removes_old_entries() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);

    // Store some nonces (they get current timestamps)
    let n1 = Nonce::from_bytes([1u8; 24]);
    let n2 = Nonce::from_bytes([2u8; 24]);
    db.store_nonce(&n1, &sender).await?;
    db.store_nonce(&n2, &sender).await?;

    // Cleanup with max_age=0 (delete everything older than now)
    // Since nonces were just inserted, they're essentially age 0.
    // Use max_age=3600 (1 hour) — nothing should be deleted since nonces are fresh.
    let deleted = db.cleanup_expired_nonces(3600).await?;
    assert_eq!(deleted, 0);
    assert!(db.has_nonce(&n1).await?);
    assert!(db.has_nonce(&n2).await?);

    // Now manually backdate a nonce and clean up
    sqlx::query(
        "UPDATE nonces SET received_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-7200 seconds') WHERE nonce_hex = ?",
    )
    .bind(hex::encode(n1.as_bytes()))
    .execute(&db.pool)
    .await?;

    // Cleanup with 1 hour TTL — the backdated nonce should be deleted
    let deleted = db.cleanup_expired_nonces(3600).await?;
    assert_eq!(deleted, 1);
    assert!(!db.has_nonce(&n1).await?); // deleted
    assert!(db.has_nonce(&n2).await?); // still fresh
    Ok(())
}

// ── Message Retention ────────────────────────────────────────────

#[tokio::test]
async fn retention_deletes_old_messages_keeps_new() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));

    // Store an old message (timestamp 1000ms)
    let old = UkmEnvelopeBuilder::new(
        KIND_CHAT, sender, recipient.clone(), b"old".to_vec(), make_proof(),
    )
    .timestamp(1000)
    .build();
    db.store_message(&old).await?;

    // Store a new message (timestamp 5000ms)
    let new = UkmEnvelopeBuilder::new(
        KIND_CHAT, sender, recipient, b"new".to_vec(), make_proof(),
    )
    .timestamp(5000)
    .build();
    db.store_message(&new).await?;

    // Delete messages older than 3000ms
    let deleted = db.delete_messages_older_than(3000).await?;
    assert_eq!(deleted, 1);

    // Old message gone, new message retained
    assert!(db.get_message(&old.id).await?.is_none());
    assert!(db.get_message(&new.id).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn retention_zero_cutoff_deletes_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));

    let msg = make_envelope(sender, recipient);
    db.store_message(&msg).await?;

    // Cutoff at 0 means "delete messages before epoch" — should delete nothing
    let deleted = db.delete_messages_older_than(0).await?;
    assert_eq!(deleted, 0);
    assert!(db.get_message(&msg.id).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn retention_deletes_all_when_cutoff_in_future() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));

    let msg = make_envelope(sender, recipient); // timestamp 1_700_000_000_000
    db.store_message(&msg).await?;

    // Cutoff far in the future — should delete everything
    let deleted = db
        .delete_messages_older_than(2_000_000_000_000)
        .await?;
    assert_eq!(deleted, 1);
    assert!(db.get_message(&msg.id).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn retention_empty_table_returns_zero() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let deleted = db.delete_messages_older_than(u64::MAX).await?;
    assert_eq!(deleted, 0);
    Ok(())
}

#[tokio::test]
async fn retention_also_removes_plaintext_cache() -> Result<(), Box<dyn std::error::Error>> {
    let db = SqliteStorage::in_memory().await?;
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));

    let msg = UkmEnvelopeBuilder::new(
        KIND_CHAT, sender, recipient, b"ciphertext".to_vec(), make_proof(),
    )
    .timestamp(1000)
    .build();
    db.store_message(&msg).await?;
    db.store_message_plaintext(&msg.id, b"encrypted-plaintext").await?;

    // Verify plaintext cache is stored
    let pt = db.get_message_plaintext(&msg.id).await?;
    assert!(pt.is_some());

    // Delete via retention (the plaintext_enc column is on the same row)
    let deleted = db.delete_messages_older_than(2000).await?;
    assert_eq!(deleted, 1);

    // Both message and plaintext cache gone
    assert!(db.get_message(&msg.id).await?.is_none());
    assert!(db.get_message_plaintext(&msg.id).await?.is_none());
    Ok(())
}
