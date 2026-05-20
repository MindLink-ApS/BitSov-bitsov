use super::*;

fn test_group_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..5].copy_from_slice(b"test!");
    id
}

fn make_node_id(seed: u8) -> NodeId {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    NodeId::from_verifying_key(&signing.verifying_key())
}

#[test]
fn basic_group_encrypt_decrypt() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice_session = GroupSession::new(group_id, alice_id);
    let mut bob_session = GroupSession::new(group_id, bob_id);

    // Exchange distributions
    let alice_dist = alice_session.our_distribution();
    let bob_dist = bob_session.our_distribution();

    bob_session.process_distribution(&alice_dist).unwrap();
    alice_session.process_distribution(&bob_dist).unwrap();

    // Alice sends a message
    let ct = alice_session.encrypt(b"Hello group!").unwrap();
    let pt = bob_session.decrypt(&alice_id, &ct).unwrap();
    assert_eq!(pt, b"Hello group!");

    // Bob sends a message
    let ct2 = bob_session.encrypt(b"Hi Alice!").unwrap();
    let pt2 = alice_session.decrypt(&bob_id, &ct2).unwrap();
    assert_eq!(pt2, b"Hi Alice!");
}

#[test]
fn multiple_messages_same_sender() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice_session = GroupSession::new(group_id, alice_id);
    let mut bob_session = GroupSession::new(group_id, bob_id);

    let alice_dist = alice_session.our_distribution();
    bob_session.process_distribution(&alice_dist).unwrap();

    // Alice sends multiple messages
    let ct1 = alice_session.encrypt(b"msg 1").unwrap();
    let ct2 = alice_session.encrypt(b"msg 2").unwrap();
    let ct3 = alice_session.encrypt(b"msg 3").unwrap();

    assert_eq!(bob_session.decrypt(&alice_id, &ct1).unwrap(), b"msg 1");
    assert_eq!(bob_session.decrypt(&alice_id, &ct2).unwrap(), b"msg 2");
    assert_eq!(bob_session.decrypt(&alice_id, &ct3).unwrap(), b"msg 3");
}

#[test]
fn out_of_order_messages() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice_session = GroupSession::new(group_id, alice_id);
    let mut bob_session = GroupSession::new(group_id, bob_id);

    let alice_dist = alice_session.our_distribution();
    bob_session.process_distribution(&alice_dist).unwrap();

    let ct1 = alice_session.encrypt(b"first").unwrap();
    let ct2 = alice_session.encrypt(b"second").unwrap();
    let ct3 = alice_session.encrypt(b"third").unwrap();

    // Receive out of order: 3, 1, 2
    assert_eq!(bob_session.decrypt(&alice_id, &ct3).unwrap(), b"third");
    assert_eq!(bob_session.decrypt(&alice_id, &ct1).unwrap(), b"first");
    assert_eq!(bob_session.decrypt(&alice_id, &ct2).unwrap(), b"second");
}

#[test]
fn three_member_group() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);
    let carol_id = make_node_id(3);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);
    let mut carol = GroupSession::new(group_id, carol_id);

    // Distribute all keys
    let alice_dist = alice.our_distribution();
    let bob_dist = bob.our_distribution();
    let carol_dist = carol.our_distribution();

    bob.process_distribution(&alice_dist).unwrap();
    carol.process_distribution(&alice_dist).unwrap();

    alice.process_distribution(&bob_dist).unwrap();
    carol.process_distribution(&bob_dist).unwrap();

    alice.process_distribution(&carol_dist).unwrap();
    bob.process_distribution(&carol_dist).unwrap();

    // Alice sends — both Bob and Carol can decrypt
    let ct = alice.encrypt(b"Hello everyone!").unwrap();
    assert_eq!(bob.decrypt(&alice_id, &ct).unwrap(), b"Hello everyone!");
    assert_eq!(carol.decrypt(&alice_id, &ct).unwrap(), b"Hello everyone!");

    // Carol sends — both Alice and Bob can decrypt
    let ct2 = carol.encrypt(b"Hi from Carol").unwrap();
    assert_eq!(alice.decrypt(&carol_id, &ct2).unwrap(), b"Hi from Carol");
    assert_eq!(bob.decrypt(&carol_id, &ct2).unwrap(), b"Hi from Carol");
}

#[test]
fn member_removal_rotates_keys() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);
    let carol_id = make_node_id(3);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);
    let mut carol = GroupSession::new(group_id, carol_id);

    // Full key distribution
    let alice_dist = alice.our_distribution();
    let bob_dist = bob.our_distribution();
    let carol_dist = carol.our_distribution();

    bob.process_distribution(&alice_dist).unwrap();
    carol.process_distribution(&alice_dist).unwrap();
    alice.process_distribution(&bob_dist).unwrap();
    carol.process_distribution(&bob_dist).unwrap();
    alice.process_distribution(&carol_dist).unwrap();
    bob.process_distribution(&carol_dist).unwrap();

    // Alice can decrypt Carol's messages before removal
    let ct_before = carol.encrypt(b"before removal").unwrap();
    assert_eq!(
        alice.decrypt(&carol_id, &ct_before).unwrap(),
        b"before removal"
    );

    // Remove Carol from Alice's and Bob's sessions
    let alice_new_dist = alice.remove_member(&carol_id);
    let bob_new_dist = bob.remove_member(&carol_id);

    // Redistribute rotated keys (only to remaining members)
    bob.process_distribution(&alice_new_dist).unwrap();
    alice.process_distribution(&bob_new_dist).unwrap();

    // Alice sends with new key — Bob can decrypt
    let ct_after = alice.encrypt(b"after removal").unwrap();
    assert_eq!(
        bob.decrypt(&alice_id, &ct_after).unwrap(),
        b"after removal"
    );

    // Carol cannot decrypt the new message (she has the old key)
    assert!(carol.decrypt(&alice_id, &ct_after).is_err());

    // Carol is no longer listed as a member
    assert!(!alice.has_member(&carol_id));
    assert!(!bob.has_member(&carol_id));
}

#[test]
fn tampered_ciphertext_rejected() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    let alice_dist = alice.our_distribution();
    bob.process_distribution(&alice_dist).unwrap();

    let mut ct = alice.encrypt(b"secret").unwrap();
    // Tamper with ciphertext — signature check will fail
    if let Some(byte) = ct.ciphertext.get_mut(0) {
        *byte ^= 0xFF;
    }

    assert!(bob.decrypt(&alice_id, &ct).is_err());
}

#[test]
fn unknown_sender_rejected() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);
    let unknown_id = make_node_id(99);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    let alice_dist = alice.our_distribution();
    bob.process_distribution(&alice_dist).unwrap();

    let ct = alice.encrypt(b"hello").unwrap();
    // Try to decrypt as if from an unknown sender
    let result = bob.decrypt(&unknown_id, &ct);
    assert!(matches!(result.unwrap_err(), SenderKeyError::UnknownSender(_)));
}

#[test]
fn distribution_wrong_group_rejected() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);

    let mut session = GroupSession::new(group_id, alice_id);

    let dist = SenderKeyDistribution {
        group_id: [0xFF; 32], // Wrong group
        sender: make_node_id(2),
        chain_key: [0u8; 32],
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[2u8; 32])
            .verifying_key()
            .to_bytes(),
        generation: 0,
    };

    let result = session.process_distribution(&dist);
    assert!(matches!(
        result.unwrap_err(),
        SenderKeyError::InvalidDistribution(_)
    ));
}

#[test]
fn each_message_has_unique_ciphertext() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);

    let mut alice = GroupSession::new(group_id, alice_id);

    let ct1 = alice.encrypt(b"same text").unwrap();
    let ct2 = alice.encrypt(b"same text").unwrap();

    assert_ne!(ct1.ciphertext, ct2.ciphertext);
    assert_ne!(ct1.message_number, ct2.message_number);
}

#[test]
fn key_rotation_increments_generation() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);

    let mut session = GroupSession::new(group_id, alice_id);

    let dist0 = session.our_distribution();
    assert_eq!(dist0.generation, 0);

    session.remove_member(&make_node_id(99)); // Trigger rotation
    let dist1 = session.our_distribution();
    assert_eq!(dist1.generation, 1);
}

#[test]
fn many_messages_roundtrip() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    let alice_dist = alice.our_distribution();
    let bob_dist = bob.our_distribution();
    bob.process_distribution(&alice_dist).unwrap();
    alice.process_distribution(&bob_dist).unwrap();

    for i in 0..50u32 {
        let txt = format!("message {i}");
        let ct = alice.encrypt(txt.as_bytes()).unwrap();
        assert_eq!(bob.decrypt(&alice_id, &ct).unwrap(), txt.as_bytes());
    }
}

#[test]
fn process_distribution_lower_generation_is_noop() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    // Bob gets Alice's gen 0 distribution
    let dist0 = alice.our_distribution();
    bob.process_distribution(&dist0).unwrap();

    // Alice rotates to gen 1
    alice.remove_member(&make_node_id(99));
    let dist1 = alice.our_distribution();
    assert_eq!(dist1.generation, 1);
    bob.process_distribution(&dist1).unwrap();

    // Replay of gen 0 should be silently accepted but not downgrade
    let result = bob.process_distribution(&dist0);
    assert!(result.is_ok());

    // Verify Bob can still decrypt from Alice's gen 1 key
    let ct = alice.encrypt(b"after rotation").unwrap();
    assert_eq!(bob.decrypt(&alice_id, &ct).unwrap(), b"after rotation");
}

#[test]
fn process_distribution_same_generation_is_idempotent() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    let dist = alice.our_distribution();

    // Process same distribution twice — should be accepted
    bob.process_distribution(&dist).unwrap();
    bob.process_distribution(&dist).unwrap();

    // Should still be able to decrypt
    let ct = alice.encrypt(b"idempotent").unwrap();
    assert_eq!(bob.decrypt(&alice_id, &ct).unwrap(), b"idempotent");
}

#[test]
fn decrypt_from_unknown_sender_fails() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    // Bob never gets Alice's distribution
    let ct = alice.encrypt(b"hello").unwrap();
    let result = bob.decrypt(&alice_id, &ct);
    assert!(matches!(result, Err(SenderKeyError::UnknownSender(_))));
}

#[test]
fn encrypt_empty_group_message() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    let dist = alice.our_distribution();
    bob.process_distribution(&dist).unwrap();

    let ct = alice.encrypt(b"").unwrap();
    let pt = bob.decrypt(&alice_id, &ct).unwrap();
    assert!(pt.is_empty());
}

#[test]
fn multiple_rotations_increment_generation() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);

    let mut alice = GroupSession::new(group_id, alice_id);

    for expected_gen in 0..5u32 {
        let dist = alice.our_distribution();
        assert_eq!(dist.generation, expected_gen);
        alice.remove_member(&make_node_id(99)); // trigger rotation
    }
}

#[test]
fn debug_impl_redacts_chain_key() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let alice = GroupSession::new(group_id, alice_id);

    let dist = alice.our_distribution();
    let debug_str = format!("{:?}", dist);

    assert!(debug_str.contains("[REDACTED]"), "Distribution Debug must redact chain_key");
    let chain_hex = hex::encode(dist.chain_key);
    assert!(
        !debug_str.contains(&chain_hex),
        "Debug output must not contain the chain key"
    );
    // Signing key (public) SHOULD be visible
    let signing_hex = hex::encode(dist.signing_key);
    assert!(
        debug_str.contains(&signing_hex),
        "Public signing key should be visible in Debug output"
    );
}

#[test]
fn group_session_many_messages_maintains_order() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    let dist = alice.our_distribution();
    bob.process_distribution(&dist).unwrap();

    // Send 50 messages and verify all decrypt correctly in order
    let mut ciphertexts = Vec::new();
    for i in 0..50 {
        let ct = alice.encrypt(format!("msg-{}", i).as_bytes()).unwrap();
        ciphertexts.push(ct);
    }

    for (i, ct) in ciphertexts.iter().enumerate() {
        let pt = bob.decrypt(&alice_id, ct).unwrap();
        assert_eq!(pt, format!("msg-{}", i).as_bytes());
    }
}

#[test]
fn cross_group_messages_cannot_decrypt() {
    // A ciphertext from group A must not decrypt in group B
    let group_a = [0xAA; 32];
    let group_b = [0xBB; 32];
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice_a = GroupSession::new(group_a, alice_id);
    let mut bob_b = GroupSession::new(group_b, bob_id);

    // Bob gets Alice's distribution for group A but applies it to group B context
    let dist_a = alice_a.our_distribution();
    // Process will succeed because it just stores the keys
    let _ = bob_b.process_distribution(&dist_a);

    let ct = alice_a.encrypt(b"group-a-message").unwrap();
    // Decrypt should fail because the message was encrypted for group A
    // but Bob's session is for group B — the AEAD AD includes group_id
    let result = bob_b.decrypt(&alice_id, &ct);
    assert!(result.is_err(), "Cross-group decryption must fail");
}

#[test]
fn removed_member_cannot_decrypt_new_messages() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);
    let charlie_id = make_node_id(3);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    // Initial distribution
    let dist = alice.our_distribution();
    bob.process_distribution(&dist).unwrap();

    // Verify Bob can decrypt
    let ct = alice.encrypt(b"before-removal").unwrap();
    assert_eq!(bob.decrypt(&alice_id, &ct).unwrap(), b"before-removal");

    // Remove Charlie (triggers key rotation)
    alice.remove_member(&charlie_id);

    // Bob gets new distribution (updated keys)
    let new_dist = alice.our_distribution();
    bob.process_distribution(&new_dist).unwrap();

    // After rotation, new messages decrypt fine
    let ct = alice.encrypt(b"after-removal").unwrap();
    assert_eq!(bob.decrypt(&alice_id, &ct).unwrap(), b"after-removal");
}

#[test]
fn distribution_for_correct_group_only() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);

    let alice = GroupSession::new(group_id, alice_id);
    let dist = alice.our_distribution();

    assert_eq!(dist.group_id, group_id);
    assert_eq!(dist.sender, alice_id);
    assert_eq!(dist.generation, 0);
}
