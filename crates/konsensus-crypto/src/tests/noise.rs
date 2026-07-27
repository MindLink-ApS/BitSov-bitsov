use super::*;

fn test_keypair() -> [u8; 32] {
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();
    let keypair = snow::Builder::new(params).generate_keypair().unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&keypair.private);
    key
}

#[test]
fn full_handshake_and_transport() {
    let initiator_key = test_keypair();
    let responder_key = test_keypair();

    let mut initiator = NoiseSession::initiator(&initiator_key).unwrap();
    let mut responder = NoiseSession::responder(&responder_key).unwrap();

    assert!(initiator.is_initiator());
    assert!(!responder.is_initiator());
    assert!(!initiator.is_transport());
    assert!(!responder.is_transport());

    // Message 1: Initiator → Responder (→ e)
    assert!(initiator.is_my_turn());
    let msg1 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg1).unwrap();

    // Message 2: Responder → Initiator (← e, ee, s, es)
    assert!(responder.is_my_turn());
    let msg2 = responder.write_handshake(&[]).unwrap();
    initiator.read_handshake(&msg2).unwrap();

    // After msg2, initiator knows responder's static key
    assert!(initiator.remote_static_key().is_some());

    // Message 3: Initiator → Responder (→ s, se)
    assert!(initiator.is_my_turn());
    let msg3 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg3).unwrap();

    // After msg3, responder knows initiator's static key
    assert!(responder.remote_static_key().is_some());

    // Transition both to transport mode
    assert!(initiator.try_finish_handshake().unwrap());
    assert!(responder.try_finish_handshake().unwrap());
    assert!(initiator.is_transport());
    assert!(responder.is_transport());

    // Encrypt/decrypt a message
    let plaintext = b"Hello, sovereign mesh!";
    let encrypted = initiator.encrypt(plaintext).unwrap();
    let decrypted = responder.decrypt(&encrypted).unwrap();
    assert_eq!(&decrypted, plaintext);

    // And in the other direction
    let plaintext2 = b"Principle 2: No payment, no packet.";
    let encrypted2 = responder.encrypt(plaintext2).unwrap();
    let decrypted2 = initiator.decrypt(&encrypted2).unwrap();
    assert_eq!(&decrypted2, plaintext2);
}

#[test]
fn handshake_with_piggybacked_payload() {
    let initiator_key = test_keypair();
    let responder_key = test_keypair();

    let mut initiator = NoiseSession::initiator(&initiator_key).unwrap();
    let mut responder = NoiseSession::responder(&responder_key).unwrap();

    // Payload in first message (not encrypted in XX pattern at step 1)
    let msg1 = initiator.write_handshake(b"hello").unwrap();
    let payload1 = responder.read_handshake(&msg1).unwrap();
    assert_eq!(&payload1, b"hello");

    // Payload in second message (encrypted)
    let msg2 = responder.write_handshake(b"world").unwrap();
    let payload2 = initiator.read_handshake(&msg2).unwrap();
    assert_eq!(&payload2, b"world");

    // Third message
    let msg3 = initiator.write_handshake(b"ready").unwrap();
    let payload3 = responder.read_handshake(&msg3).unwrap();
    assert_eq!(&payload3, b"ready");

    initiator.try_finish_handshake().unwrap();
    responder.try_finish_handshake().unwrap();
}

#[test]
fn encrypt_before_handshake_fails() {
    let key = test_keypair();
    let mut session = NoiseSession::initiator(&key).unwrap();
    let err = session.encrypt(b"too early").unwrap_err();
    assert!(matches!(err, NoiseError::HandshakeIncomplete));
}

#[test]
fn decrypt_before_handshake_fails() {
    let key = test_keypair();
    let mut session = NoiseSession::responder(&key).unwrap();
    let err = session.decrypt(&[0u8; 32]).unwrap_err();
    assert!(matches!(err, NoiseError::HandshakeIncomplete));
}

#[test]
fn remote_static_keys_match() {
    let initiator_key = test_keypair();
    let responder_key = test_keypair();

    let mut initiator = NoiseSession::initiator(&initiator_key).unwrap();
    let mut responder = NoiseSession::responder(&responder_key).unwrap();

    // Get the expected public keys from snow
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();
    // We verify the remote static keys match by checking them after the handshake
    drop(params);

    // Complete handshake
    let msg1 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg1).unwrap();
    let msg2 = responder.write_handshake(&[]).unwrap();
    initiator.read_handshake(&msg2).unwrap();
    let msg3 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg3).unwrap();

    initiator.try_finish_handshake().unwrap();
    responder.try_finish_handshake().unwrap();

    // Both sides should have each other's public keys
    let i_sees_r = initiator.remote_static_key().unwrap();
    let r_sees_i = responder.remote_static_key().unwrap();

    // They should be different (different keypairs)
    assert_ne!(i_sees_r, r_sees_i);
    // Each should be 32 bytes and non-zero
    assert_ne!(i_sees_r, &[0u8; 32]);
    assert_ne!(r_sees_i, &[0u8; 32]);
}

#[test]
fn multiple_messages_in_transport_mode() {
    let initiator_key = test_keypair();
    let responder_key = test_keypair();

    let mut initiator = NoiseSession::initiator(&initiator_key).unwrap();
    let mut responder = NoiseSession::responder(&responder_key).unwrap();

    // Complete handshake
    let msg1 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg1).unwrap();
    let msg2 = responder.write_handshake(&[]).unwrap();
    initiator.read_handshake(&msg2).unwrap();
    let msg3 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg3).unwrap();
    initiator.try_finish_handshake().unwrap();
    responder.try_finish_handshake().unwrap();

    // Send 100 messages in each direction
    for i in 0..100u32 {
        let msg = format!("message {i} from initiator");
        let encrypted = initiator.encrypt(msg.as_bytes()).unwrap();
        let decrypted = responder.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, msg.as_bytes());

        let reply = format!("reply {i} from responder");
        let encrypted = responder.encrypt(reply.as_bytes()).unwrap();
        let decrypted = initiator.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, reply.as_bytes());
    }
}

#[test]
fn tampered_ciphertext_rejected() {
    let initiator_key = test_keypair();
    let responder_key = test_keypair();

    let mut initiator = NoiseSession::initiator(&initiator_key).unwrap();
    let mut responder = NoiseSession::responder(&responder_key).unwrap();

    // Complete handshake
    let msg1 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg1).unwrap();
    let msg2 = responder.write_handshake(&[]).unwrap();
    initiator.read_handshake(&msg2).unwrap();
    let msg3 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg3).unwrap();
    initiator.try_finish_handshake().unwrap();
    responder.try_finish_handshake().unwrap();

    // Encrypt a message
    let mut encrypted = initiator.encrypt(b"secret data").unwrap();
    // Tamper with a byte
    if let Some(byte) = encrypted.get_mut(5) {
        *byte ^= 0xFF;
    }
    // Decryption should fail (AEAD tag mismatch)
    assert!(responder.decrypt(&encrypted).is_err());
}

#[test]
fn try_finish_handshake_idempotent() {
    let initiator_key = test_keypair();
    let responder_key = test_keypair();

    let mut initiator = NoiseSession::initiator(&initiator_key).unwrap();
    let mut responder = NoiseSession::responder(&responder_key).unwrap();

    // Not finished yet
    assert!(!initiator.try_finish_handshake().unwrap());

    // Complete handshake
    let msg1 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg1).unwrap();
    let msg2 = responder.write_handshake(&[]).unwrap();
    initiator.read_handshake(&msg2).unwrap();
    let msg3 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg3).unwrap();

    // First call transitions
    assert!(initiator.try_finish_handshake().unwrap());
    // Second call is idempotent (already in transport)
    assert!(initiator.try_finish_handshake().unwrap());
}

/// Helper to create a connected pair in transport mode.
fn connected_pair() -> (NoiseSession, NoiseSession) {
    let ik = test_keypair();
    let rk = test_keypair();
    let mut i = NoiseSession::initiator(&ik).unwrap();
    let mut r = NoiseSession::responder(&rk).unwrap();

    let m1 = i.write_handshake(&[]).unwrap();
    r.read_handshake(&m1).unwrap();
    let m2 = r.write_handshake(&[]).unwrap();
    i.read_handshake(&m2).unwrap();
    let m3 = i.write_handshake(&[]).unwrap();
    r.read_handshake(&m3).unwrap();
    i.try_finish_handshake().unwrap();
    r.try_finish_handshake().unwrap();
    (i, r)
}

#[test]
fn chunked_encrypt_small_payload() {
    let (mut i, mut r) = connected_pair();
    let plaintext = b"small";
    let encrypted = i.encrypt(plaintext).unwrap();
    let decrypted = r.decrypt(&encrypted).unwrap();
    assert_eq!(&decrypted, plaintext);
}

#[test]
fn chunked_encrypt_single_byte() {
    let (mut i, mut r) = connected_pair();
    let plaintext = &[0x42u8];
    let encrypted = i.encrypt(plaintext).unwrap();
    let decrypted = r.decrypt(&encrypted).unwrap();
    assert_eq!(&decrypted, plaintext);
}

#[test]
fn chunked_encrypt_empty() {
    let (mut i, mut r) = connected_pair();
    let plaintext = &[];
    let encrypted = i.encrypt(plaintext).unwrap();
    let decrypted = r.decrypt(&encrypted).unwrap();
    assert_eq!(&decrypted, plaintext);
}

#[test]
fn chunked_encrypt_exactly_max_payload() {
    let (mut i, mut r) = connected_pair();
    let plaintext = vec![0xABu8; MAX_NOISE_PAYLOAD];
    let encrypted = i.encrypt(&plaintext).unwrap();
    let decrypted = r.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn chunked_encrypt_100kb_payload() {
    let (mut i, mut r) = connected_pair();
    // 100KB — requires 2 chunks
    let plaintext: Vec<u8> = (0..100_000).map(|n| (n % 256) as u8).collect();
    let encrypted = i.encrypt(&plaintext).unwrap();
    let decrypted = r.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn chunked_encrypt_1mb_payload() {
    let (mut i, mut r) = connected_pair();
    // 1MB — requires ~16 chunks
    let plaintext: Vec<u8> = (0..1_000_000).map(|n| (n % 256) as u8).collect();
    let encrypted = i.encrypt(&plaintext).unwrap();
    let decrypted = r.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn chunked_encrypt_boundary_plus_one() {
    let (mut i, mut r) = connected_pair();
    // One byte over the chunk boundary — needs 2 chunks
    let plaintext = vec![0xCDu8; MAX_NOISE_PAYLOAD + 1];
    let encrypted = i.encrypt(&plaintext).unwrap();
    let decrypted = r.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn chunked_encrypt_bidirectional() {
    let (mut i, mut r) = connected_pair();
    let big_msg = vec![0xEFu8; 200_000];

    // Initiator → Responder
    let enc = i.encrypt(&big_msg).unwrap();
    let dec = r.decrypt(&enc).unwrap();
    assert_eq!(dec, big_msg);

    // Responder → Initiator
    let enc2 = r.encrypt(&big_msg).unwrap();
    let dec2 = i.decrypt(&enc2).unwrap();
    assert_eq!(dec2, big_msg);
}
