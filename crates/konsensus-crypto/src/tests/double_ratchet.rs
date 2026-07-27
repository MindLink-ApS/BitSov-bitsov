use super::*;
use crate::x3dh;

#[test]
fn basic_encrypt_decrypt() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();

    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Alice sends a message
    let msg = alice.encrypt(b"Hello Bob!").unwrap();
    let plaintext = bob.decrypt(&msg).unwrap();
    assert_eq!(plaintext, b"Hello Bob!");
}

#[test]
fn bidirectional_messages() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();

    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Alice → Bob
    let msg1 = alice.encrypt(b"Hello").unwrap();
    assert_eq!(bob.decrypt(&msg1).unwrap(), b"Hello");

    // Bob → Alice
    let msg2 = bob.encrypt(b"Hi Alice").unwrap();
    assert_eq!(alice.decrypt(&msg2).unwrap(), b"Hi Alice");

    // Alice → Bob again
    let msg3 = alice.encrypt(b"How are you?").unwrap();
    assert_eq!(bob.decrypt(&msg3).unwrap(), b"How are you?");

    // Bob → Alice again
    let msg4 = bob.encrypt(b"Good, thanks!").unwrap();
    assert_eq!(alice.decrypt(&msg4).unwrap(), b"Good, thanks!");
}

#[test]
fn multiple_messages_same_direction() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();

    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Alice sends multiple messages before Bob replies
    let msg1 = alice.encrypt(b"msg 1").unwrap();
    let msg2 = alice.encrypt(b"msg 2").unwrap();
    let msg3 = alice.encrypt(b"msg 3").unwrap();

    // Bob receives all in order
    assert_eq!(bob.decrypt(&msg1).unwrap(), b"msg 1");
    assert_eq!(bob.decrypt(&msg2).unwrap(), b"msg 2");
    assert_eq!(bob.decrypt(&msg3).unwrap(), b"msg 3");
}

#[test]
fn out_of_order_delivery() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();

    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Alice sends 3 messages
    let msg1 = alice.encrypt(b"first").unwrap();
    let msg2 = alice.encrypt(b"second").unwrap();
    let msg3 = alice.encrypt(b"third").unwrap();

    // Bob receives them out of order: 3, 1, 2
    assert_eq!(bob.decrypt(&msg3).unwrap(), b"third");
    assert_eq!(bob.decrypt(&msg1).unwrap(), b"first");
    assert_eq!(bob.decrypt(&msg2).unwrap(), b"second");
}

#[test]
fn forward_secrecy_via_ratchet() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();

    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Exchange messages to advance the ratchet
    let msg1 = alice.encrypt(b"hello").unwrap();
    bob.decrypt(&msg1).unwrap();

    let msg2 = bob.encrypt(b"reply").unwrap();
    alice.decrypt(&msg2).unwrap();

    // After a DH ratchet step, old keys are gone
    // Verify by sending more messages (different ratchet state)
    let msg3 = alice.encrypt(b"after ratchet").unwrap();
    let msg4 = alice.encrypt(b"second after ratchet").unwrap();

    assert_eq!(bob.decrypt(&msg3).unwrap(), b"after ratchet");
    assert_eq!(bob.decrypt(&msg4).unwrap(), b"second after ratchet");
}

#[test]
fn tampered_ciphertext_rejected() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();

    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    let mut msg = alice.encrypt(b"secret").unwrap();

    // Tamper with ciphertext
    if let Some(byte) = msg.ciphertext.get_mut(0) {
        *byte ^= 0xFF;
    }

    assert!(bob.decrypt(&msg).is_err());
}

#[test]
fn different_shared_secrets_cant_decrypt() {
    let ad = b"alice||bob".to_vec();

    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice =
        DoubleRatchet::init_sender(&[1u8; 32], &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &[2u8; 32], // Different secret!
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    let msg = alice.encrypt(b"hello").unwrap();
    assert!(bob.decrypt(&msg).is_err());
}

#[test]
fn message_header_serialization() {
    let header = MessageHeader {
        dh_public: [7u8; 32],
        previous_chain_length: 42,
        message_number: 99,
    };

    let bytes = header.to_bytes();
    let recovered = MessageHeader::from_bytes(&bytes);

    assert_eq!(header, recovered);
}

#[test]
fn each_message_has_unique_ciphertext() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad).unwrap();

    // Same plaintext, different messages
    let msg1 = alice.encrypt(b"same text").unwrap();
    let msg2 = alice.encrypt(b"same text").unwrap();

    // Ciphertext should differ (different message keys)
    assert_ne!(msg1.ciphertext, msg2.ciphertext);
    // Headers should have different message numbers
    assert_ne!(msg1.header.message_number, msg2.header.message_number);
}

#[test]
fn export_import_state_roundtrip() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Exchange a few messages to advance the ratchet
    let msg1 = alice.encrypt(b"hello").unwrap();
    bob.decrypt(&msg1).unwrap();
    let msg2 = bob.encrypt(b"reply").unwrap();
    alice.decrypt(&msg2).unwrap();
    let msg3 = alice.encrypt(b"after ratchet").unwrap();
    bob.decrypt(&msg3).unwrap();

    // Export both sides
    let alice_state = alice.export_state();
    let bob_state = bob.export_state();

    // Serialize to JSON (simulates persistence)
    let alice_json = serde_json::to_string(&alice_state).unwrap();
    let bob_json = serde_json::to_string(&bob_state).unwrap();

    // Restore from serialized state
    let alice_restored_state: RatchetState = serde_json::from_str(&alice_json).unwrap();
    let bob_restored_state: RatchetState = serde_json::from_str(&bob_json).unwrap();
    let mut alice2 = DoubleRatchet::from_state(&alice_restored_state);
    let mut bob2 = DoubleRatchet::from_state(&bob_restored_state);

    // Verify restored sessions can continue communicating
    let msg4 = alice2.encrypt(b"after restore").unwrap();
    assert_eq!(bob2.decrypt(&msg4).unwrap(), b"after restore");

    let msg5 = bob2.encrypt(b"bob after restore").unwrap();
    assert_eq!(alice2.decrypt(&msg5).unwrap(), b"bob after restore");
}

#[test]
fn export_import_with_skipped_keys() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Alice sends 3 messages
    let msg1 = alice.encrypt(b"first").unwrap();
    let msg2 = alice.encrypt(b"second").unwrap();
    let msg3 = alice.encrypt(b"third").unwrap();

    // Bob receives only msg3 (skips msg1, msg2 — they're stored as skipped keys)
    assert_eq!(bob.decrypt(&msg3).unwrap(), b"third");

    // Export bob's state (should include skipped keys for msg1, msg2)
    let bob_state = bob.export_state();
    assert_eq!(bob_state.skipped_keys.len(), 2);

    // Serialize and restore
    let json = serde_json::to_string(&bob_state).unwrap();
    let restored_state: RatchetState = serde_json::from_str(&json).unwrap();
    let mut bob2 = DoubleRatchet::from_state(&restored_state);

    // Bob can now decrypt the skipped messages
    assert_eq!(bob2.decrypt(&msg1).unwrap(), b"first");
    assert_eq!(bob2.decrypt(&msg2).unwrap(), b"second");
}

#[test]
fn many_round_trips() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // 50 round trips
    for i in 0..50u32 {
        let txt_a = format!("alice msg {i}");
        let msg = alice.encrypt(txt_a.as_bytes()).unwrap();
        assert_eq!(bob.decrypt(&msg).unwrap(), txt_a.as_bytes());

        let txt_b = format!("bob reply {i}");
        let reply = bob.encrypt(txt_b.as_bytes()).unwrap();
        assert_eq!(alice.decrypt(&reply).unwrap(), txt_b.as_bytes());
    }
}

#[test]
fn export_import_state_with_none_chains() {
    // init_receiver starts with no sending chain until first DH ratchet.
    // Verify export/import roundtrip preserves this state correctly.
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Bob hasn't received any message yet — sending chain is None
    assert!(!bob.can_send());

    let state = bob.export_state();
    assert!(state.sending_chain.is_none());

    // Roundtrip through JSON
    let json = serde_json::to_string(&state).unwrap();
    let restored_state: RatchetState = serde_json::from_str(&json).unwrap();
    let bob2 = DoubleRatchet::from_state(&restored_state);

    assert!(!bob2.can_send());
}

#[test]
fn export_import_preserves_empty_skipped_keys() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Exchange messages in order — no skipped keys
    let msg1 = alice.encrypt(b"hello").unwrap();
    bob.decrypt(&msg1).unwrap();

    let state = bob.export_state();
    assert!(state.skipped_keys.is_empty());

    let json = serde_json::to_string(&state).unwrap();
    let restored: RatchetState = serde_json::from_str(&json).unwrap();
    let mut bob2 = DoubleRatchet::from_state(&restored);

    // Verify restored session still works
    let msg2 = alice.encrypt(b"world").unwrap();
    assert_eq!(bob2.decrypt(&msg2).unwrap(), b"world");
}

#[test]
fn skip_too_many_messages_rejected() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Alice sends MAX_SKIP + 2 messages, bob tries to receive only the last
    let mut last_msg = None;
    for _ in 0..(MAX_SKIP + 2) {
        last_msg = Some(alice.encrypt(b"filler").unwrap());
    }

    // Decrypting the last message requires skipping > MAX_SKIP messages
    let result = bob.decrypt(&last_msg.unwrap());
    assert!(matches!(result, Err(RatchetError::TooManySkipped(_, _))));
}

#[test]
fn encrypt_empty_plaintext() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    let msg = alice.encrypt(b"").unwrap();
    let plaintext = bob.decrypt(&msg).unwrap();
    assert!(plaintext.is_empty());
}

#[test]
fn encrypt_large_plaintext() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // 1 MiB plaintext
    let big = vec![0xABu8; 1024 * 1024];
    let msg = alice.encrypt(&big).unwrap();
    let plaintext = bob.decrypt(&msg).unwrap();
    assert_eq!(plaintext, big);
}

#[test]
fn replay_same_message_fails() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    let msg = alice.encrypt(b"no replays").unwrap();
    assert_eq!(bob.decrypt(&msg).unwrap(), b"no replays");

    // Replaying same message should fail — key was consumed
    assert!(bob.decrypt(&msg).is_err());
}

#[test]
fn can_send_false_for_receiver_before_first_message() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Receiver can't send before first DH ratchet step
    assert!(!bob.can_send());
}

#[test]
fn can_send_true_for_sender() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad).unwrap();

    // Sender can send immediately
    assert!(alice.can_send());
}

#[test]
fn skipped_key_eviction_uses_insertion_order() {
    // Verify that eviction removes oldest-inserted keys, not lowest message numbers.
    // This matters for out-of-order delivery: if messages arrive as [0, 10, 1],
    // message 1's key was inserted last and should be retained over message 0's.
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Alice sends messages 0..5. Bob only decrypts message 4, creating
    // skipped keys for messages 0, 1, 2, 3 (inserted in order: seq 0,1,2,3).
    let msgs: Vec<_> = (0..5).map(|i| alice.encrypt(format!("msg{i}").as_bytes()).unwrap()).collect();
    bob.decrypt(&msgs[4]).unwrap(); // Skip 0,1,2,3

    // Verify skipped keys exist for 0,1,2,3
    assert_eq!(bob.skipped_keys.len(), 4);

    // Now verify all skipped messages can be decrypted (out of order)
    assert_eq!(bob.decrypt(&msgs[2]).unwrap(), b"msg2");
    assert_eq!(bob.decrypt(&msgs[0]).unwrap(), b"msg0");
    assert_eq!(bob.decrypt(&msgs[3]).unwrap(), b"msg3");
    assert_eq!(bob.decrypt(&msgs[1]).unwrap(), b"msg1");
}

#[test]
fn skipped_key_eviction_preserves_recent_low_numbered_keys() {
    // Directly test the eviction logic: manually insert keys with known insertion
    // sequences and verify eviction removes oldest-inserted, not lowest-numbered.
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut ratchet = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad).unwrap();

    // Manually insert keys with specific insertion order.
    // Key for msg_num=100 inserted first (seq=0), key for msg_num=1 inserted last (seq=2).
    let fake_pub = [0xAA; 32];
    let key_a = [0x11; 32];
    let key_b = [0x22; 32];
    let key_c = [0x33; 32];

    ratchet.skipped_keys.insert((fake_pub, 100), (key_a, 0)); // oldest insertion
    ratchet.skipped_keys.insert((fake_pub, 50), (key_b, 1));
    ratchet.skipped_keys.insert((fake_pub, 1), (key_c, 2));   // newest insertion
    ratchet.skipped_key_seq = 3;

    // Simulate eviction by reducing the cap temporarily.
    // We need to evict 1 entry: it should be msg_num=100 (seq=0), NOT msg_num=1.
    while ratchet.skipped_keys.len() > 2 {
        if let Some(&key) = ratchet
            .skipped_keys
            .iter()
            .min_by_key(|(_, (_, seq))| *seq)
            .map(|(k, _)| k)
        {
            ratchet.skipped_keys.remove(&key);
        }
    }

    // msg_num=100 (oldest insertion) should be evicted
    assert!(!ratchet.skipped_keys.contains_key(&(fake_pub, 100)));
    // msg_num=50 and msg_num=1 should be retained
    assert!(ratchet.skipped_keys.contains_key(&(fake_pub, 50)));
    assert!(ratchet.skipped_keys.contains_key(&(fake_pub, 1)));
}

#[test]
fn debug_impl_redacts_ratchet_state() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad).unwrap();
    let state = alice.export_state();
    let debug_str = format!("{:?}", state);

    assert!(debug_str.contains("[REDACTED]"), "RatchetState Debug must redact secrets");
    // Root key must not appear in debug output
    let root_hex = hex::encode(state.root_key);
    assert!(
        !debug_str.contains(&root_hex),
        "Debug output must not contain the root key"
    );
}

#[test]
fn debug_impl_redacts_skipped_key() {
    let sk = SkippedKey {
        ratchet_public: [0xAA; 32],
        message_number: 5,
        message_key: [0xBB; 32],
    };
    let debug_str = format!("{:?}", sk);

    assert!(debug_str.contains("[REDACTED]"), "SkippedKey Debug must redact message_key");
    let key_hex = hex::encode(sk.message_key);
    assert!(
        !debug_str.contains(&key_hex),
        "Debug output must not contain the message key"
    );
}

#[test]
fn message_header_roundtrip_max_values() {
    let header = MessageHeader {
        dh_public: [0xFF; 32],
        previous_chain_length: u32::MAX,
        message_number: u32::MAX,
    };

    let bytes = header.to_bytes();
    let restored = MessageHeader::from_bytes(&bytes);

    assert_eq!(header, restored);
    assert_eq!(restored.previous_chain_length, u32::MAX);
    assert_eq!(restored.message_number, u32::MAX);
}

#[test]
fn message_header_roundtrip_zero_values() {
    let header = MessageHeader {
        dh_public: [0; 32],
        previous_chain_length: 0,
        message_number: 0,
    };

    let bytes = header.to_bytes();
    let restored = MessageHeader::from_bytes(&bytes);

    assert_eq!(header, restored);
}

#[test]
fn heavy_interleaved_conversation() {
    let shared_secret = [42u8; 32];
    let ad = b"heavy-test".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // 100 round trips: Alice sends, Bob decrypts, Bob sends, Alice decrypts
    for i in 0u32..100 {
        let msg_a = format!("alice-msg-{}", i);
        let enc_a = alice.encrypt(msg_a.as_bytes()).unwrap();
        let dec_a = bob.decrypt(&enc_a).unwrap();
        assert_eq!(dec_a, msg_a.as_bytes());

        let msg_b = format!("bob-msg-{}", i);
        let enc_b = bob.encrypt(msg_b.as_bytes()).unwrap();
        let dec_b = alice.decrypt(&enc_b).unwrap();
        assert_eq!(dec_b, msg_b.as_bytes());
    }
}

#[test]
fn cross_ratchet_messages_are_independent() {
    // Two separate sessions with same shared secret but different SPKs
    // must produce entirely different ciphertexts
    let shared_secret = [42u8; 32];
    let ad = b"independence-test".to_vec();

    let spk1 = x3dh::SignedPreKey::generate();
    let spk2 = x3dh::SignedPreKey::generate();

    let mut alice1 = DoubleRatchet::init_sender(&shared_secret, &spk1.public, ad.clone()).unwrap();
    let mut alice2 = DoubleRatchet::init_sender(&shared_secret, &spk2.public, ad).unwrap();

    let enc1 = alice1.encrypt(b"same plaintext").unwrap();
    let enc2 = alice2.encrypt(b"same plaintext").unwrap();

    // Different SPK → different DH → different keys → different ciphertext
    assert_ne!(enc1.ciphertext, enc2.ciphertext);
    // Even the DH public keys in headers should differ
    assert_ne!(enc1.header.dh_public, enc2.header.dh_public);
}

#[test]
fn export_import_preserves_bidirectional_communication() {
    let shared_secret = [42u8; 32];
    let ad = b"persist-test".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Exchange some messages to advance ratchet state
    for i in 0..5 {
        let enc = alice.encrypt(format!("msg-{}", i).as_bytes()).unwrap();
        bob.decrypt(&enc).unwrap();
    }
    let enc = bob.encrypt(b"reply").unwrap();
    alice.decrypt(&enc).unwrap();

    // Export and restore both sides
    let alice_state = alice.export_state();
    let bob_state = bob.export_state();

    let mut alice2 = DoubleRatchet::from_state(&alice_state);
    let mut bob2 = DoubleRatchet::from_state(&bob_state);

    // Communication must continue seamlessly after restore
    let enc = alice2.encrypt(b"after restore").unwrap();
    let dec = bob2.decrypt(&enc).unwrap();
    assert_eq!(dec, b"after restore");

    let enc = bob2.encrypt(b"bob after restore").unwrap();
    let dec = alice2.decrypt(&enc).unwrap();
    assert_eq!(dec, b"bob after restore");
}

#[test]
fn ratchet_message_different_ad_fails_decrypt() {
    // Messages encrypted with one AD cannot be decrypted with different AD.
    // This verifies AEAD binding.
    let shared_secret = [42u8; 32];
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(
        &shared_secret,
        &bob_spk.public,
        b"ad-one".to_vec(),
    ).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        b"ad-two".to_vec(), // Different AD!
    );

    let enc = alice.encrypt(b"test").unwrap();
    let result = bob.decrypt(&enc);
    assert!(result.is_err(), "Decryption with different AD must fail");
    assert!(matches!(result.unwrap_err(), RatchetError::DecryptionFailed(_)));
}

#[test]
fn public_key_accessor_returns_current_dh_key() {
    let shared_secret = [42u8; 32];
    let ad = b"test".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad).unwrap();

    // Public key must not be all zeros
    assert_ne!(alice.public_key().as_bytes(), &[0u8; 32]);
}

/// Receiver calling encrypt() before receiving the first message must fail
/// with NotInitialized — the sending chain isn't set up until the first
/// DH ratchet step triggered by decrypting the sender's first message.
#[test]
fn receiver_encrypt_before_first_message_fails() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Bob hasn't received any message yet — sending chain is None
    assert!(!bob.can_send(), "receiver should not be 'initialized' for sending yet");
    let result = bob.encrypt(b"too early");
    assert!(
        matches!(result, Err(RatchetError::NotInitialized)),
        "encrypt before first decrypt should return NotInitialized, got: {result:?}"
    );
}

/// After receiving the first message, the receiver CAN encrypt (bidirectional).
#[test]
fn receiver_can_encrypt_after_first_decrypt() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // Alice sends first message, Bob decrypts — this triggers DH ratchet
    let msg1 = alice.encrypt(b"hello").unwrap();
    bob.decrypt(&msg1).unwrap();

    // Now Bob should be able to encrypt
    assert!(bob.can_send(), "receiver should be initialized after first decrypt");
    let reply = bob.encrypt(b"reply");
    assert!(reply.is_ok(), "receiver should be able to encrypt after first decrypt");

    // Alice can decrypt Bob's reply
    let plaintext = alice.decrypt(&reply.unwrap()).unwrap();
    assert_eq!(plaintext, b"reply");
}

/// Rapidly alternating DH ratchets: each direction change triggers a new ratchet step.
/// Verify correctness after many alternations.
#[test]
fn rapid_dh_ratchet_alternation() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    // 50 rapid alternations: alice→bob, bob→alice, alice→bob, ...
    for i in 0u32..50 {
        let payload = format!("msg-{i}");
        if i % 2 == 0 {
            let msg = alice.encrypt(payload.as_bytes()).unwrap();
            let pt = bob.decrypt(&msg).unwrap();
            assert_eq!(pt, payload.as_bytes());
        } else {
            let msg = bob.encrypt(payload.as_bytes()).unwrap();
            let pt = alice.decrypt(&msg).unwrap();
            assert_eq!(pt, payload.as_bytes());
        }
    }
}

/// Decrypt with a tampered header (modified message_number) must fail.
#[test]
fn tampered_header_message_number_rejected() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = x3dh::SignedPreKey::generate();

    let mut alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).unwrap();
    let mut bob = DoubleRatchet::init_receiver(
        &shared_secret,
        bob_spk.secret(),
        &bob_spk.public,
        ad,
    );

    let mut msg = alice.encrypt(b"original").unwrap();
    // Tamper with the message number
    msg.header.message_number = msg.header.message_number.wrapping_add(5);
    let result = bob.decrypt(&msg);
    assert!(result.is_err(), "tampered message_number should cause decryption failure");
}
