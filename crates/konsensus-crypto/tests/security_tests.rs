//! Security tests for E2EE primitives.
//!
//! Tests for:
//! - Double Ratchet: forward secrecy, replay resistance, tamper detection
//! - X3DH: signature verification, ephemeral key uniqueness
//! - Sender Keys: removed member can't decrypt, signature forgery
//! - Noise_XX: tampered handshake, identity verification

use konsensus_crypto::double_ratchet::DoubleRatchet;
use konsensus_crypto::sender_keys::{GroupSession, SenderKeyDistribution, SenderKeyError};
use konsensus_crypto::x3dh::{self, PrekeyBundle, SignedPreKey};

use ed25519_dalek::Signer;
use konsensus_core::types::NodeId;
use x25519_dalek::{PublicKey, StaticSecret};

// ═════════════════════════════════════════════════════════════════════════════
// DOUBLE RATCHET — SECURITY PROPERTIES
// ═════════════════════════════════════════════════════════════════════════════

fn make_ratchet_pair() -> (DoubleRatchet, DoubleRatchet) {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = SignedPreKey::generate();

    let alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).expect("test setup");
    let bob = DoubleRatchet::init_receiver(&shared_secret, bob_spk.secret(), &bob_spk.public, ad);
    (alice, bob)
}

#[test]
fn ratchet_replay_same_message_fails() {
    let (mut alice, mut bob) = make_ratchet_pair();

    let msg = alice.encrypt(b"hello").unwrap();

    // First decrypt succeeds
    assert_eq!(bob.decrypt(&msg).unwrap(), b"hello");

    // Replaying the same message must fail (key consumed)
    assert!(bob.decrypt(&msg).is_err());
}

#[test]
fn ratchet_tampered_header_fails() {
    let (mut alice, mut bob) = make_ratchet_pair();

    let mut msg = alice.encrypt(b"secret").unwrap();

    // Tamper with message number in header
    msg.header.message_number = 999;

    // Decryption must fail (AEAD includes header in AD)
    assert!(bob.decrypt(&msg).is_err());
}

#[test]
fn ratchet_cross_session_decryption_fails() {
    // Two completely separate sessions — ciphertext from one cannot decrypt in the other
    let (mut alice1, _bob1) = make_ratchet_pair();

    let shared_secret2 = [99u8; 32];
    let ad2 = b"carol||dave".to_vec();
    let dave_spk = SignedPreKey::generate();
    let mut dave =
        DoubleRatchet::init_receiver(&shared_secret2, dave_spk.secret(), &dave_spk.public, ad2);

    let msg = alice1.encrypt(b"hello").unwrap();

    // Dave cannot decrypt Alice's message (different shared secret)
    assert!(dave.decrypt(&msg).is_err());
}

#[test]
fn ratchet_forward_secrecy_after_dh_step() {
    let (mut alice, mut bob) = make_ratchet_pair();

    // Alice's initial DH public key
    let alice_pk_v1 = *alice.public_key();

    // Alice sends a message — no DH ratchet yet on Alice's side
    let msg1 = alice.encrypt(b"msg1").unwrap();
    bob.decrypt(&msg1).unwrap();

    // Bob replies — triggers DH ratchet on Alice when she decrypts
    let reply1 = bob.encrypt(b"reply1").unwrap();
    alice.decrypt(&reply1).unwrap();

    // Alice's DH key should have changed after processing Bob's reply
    let alice_pk_v2 = *alice.public_key();
    assert_ne!(alice_pk_v1.as_bytes(), alice_pk_v2.as_bytes());

    // Another round trip changes it again
    let msg2 = alice.encrypt(b"msg2").unwrap();
    bob.decrypt(&msg2).unwrap();
    let reply2 = bob.encrypt(b"reply2").unwrap();
    alice.decrypt(&reply2).unwrap();

    let alice_pk_v3 = *alice.public_key();
    assert_ne!(alice_pk_v2.as_bytes(), alice_pk_v3.as_bytes());
}

#[test]
fn ratchet_skip_limit_enforced() {
    let (mut alice, mut bob) = make_ratchet_pair();

    // Encrypt 1002 messages without decrypting any
    // MAX_SKIP = 1000, so trying to decrypt message #1001 requires
    // skipping 1001 messages which exceeds the limit.
    let mut messages = Vec::new();
    for _ in 0..1002 {
        messages.push(alice.encrypt(b"x").unwrap());
    }

    // Decrypting message at index 1001 requires skipping 1001 messages > MAX_SKIP
    let result = bob.decrypt(&messages[1001]);
    assert!(result.is_err(), "should reject when skip count exceeds MAX_SKIP");
}

// ═════════════════════════════════════════════════════════════════════════════
// X3DH — SECURITY PROPERTIES
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn x3dh_ephemeral_key_is_unique_per_initiation() {
    let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_signing = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let bob_public = PublicKey::from(&bob_secret);
    let spk = SignedPreKey::generate();
    let sig = bob_signing.sign(spk.public.as_bytes());

    let bundle = PrekeyBundle {
        identity_key: bob_public,
        signed_prekey: spk.public,
        signed_prekey_sig: sig,
        identity_verifying_key: bob_signing.verifying_key(),
        one_time_prekey: None,
        one_time_prekey_id: None,
    };

    let init1 = x3dh::initiate(&alice_secret, &alice_public, &bundle).unwrap();
    let init2 = x3dh::initiate(&alice_secret, &alice_public, &bundle).unwrap();

    // Ephemeral keys must differ across initiations
    assert_ne!(init1.ephemeral_key.as_bytes(), init2.ephemeral_key.as_bytes());

    // Shared secrets must also differ (due to different ephemeral keys)
    assert_ne!(init1.shared_secret.as_bytes(), init2.shared_secret.as_bytes());
}

#[test]
fn x3dh_tampered_signed_prekey_rejected() {
    let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_signing = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let bob_public = PublicKey::from(&bob_secret);
    let spk = SignedPreKey::generate();
    let sig = bob_signing.sign(spk.public.as_bytes());

    // Replace the signed prekey with a different one (attacker's key)
    let attacker_spk = SignedPreKey::generate();

    let bundle = PrekeyBundle {
        identity_key: bob_public,
        signed_prekey: attacker_spk.public, // TAMPERED
        signed_prekey_sig: sig,             // Signature doesn't match
        identity_verifying_key: bob_signing.verifying_key(),
        one_time_prekey: None,
        one_time_prekey_id: None,
    };

    let result = x3dh::initiate(&alice_secret, &alice_public, &bundle);
    assert!(result.is_err());
}

#[test]
fn x3dh_man_in_the_middle_detected() {
    // If an attacker substitutes their own identity key, the shared secret
    // won't match, preventing MITM attacks.
    let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_signing = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);

    let spk = SignedPreKey::generate();
    let sig = bob_signing.sign(spk.public.as_bytes());

    // Attacker creates their own identity key
    let attacker_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let attacker_public = PublicKey::from(&attacker_secret);

    let bundle = PrekeyBundle {
        identity_key: attacker_public, // Attacker's key, not Bob's
        signed_prekey: spk.public,
        signed_prekey_sig: sig,
        identity_verifying_key: bob_signing.verifying_key(),
        one_time_prekey: None,
        one_time_prekey_id: None,
    };

    let initiation = x3dh::initiate(&alice_secret, &alice_public, &bundle).unwrap();

    // Bob tries to derive with his real identity key
    let bob_secret_result = x3dh::respond(
        &bob_secret,
        &PublicKey::from(&bob_secret),
        &spk,
        None,
        &initiation.identity_key,
        &initiation.ephemeral_key,
    )
    .unwrap();

    // Shared secrets won't match (MITM detected at application layer)
    assert_ne!(
        initiation.shared_secret.as_bytes(),
        bob_secret_result.as_bytes()
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// SENDER KEYS — SECURITY PROPERTIES
// ═════════════════════════════════════════════════════════════════════════════

fn make_node_id(seed: u8) -> NodeId {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    NodeId::from_verifying_key(&signing.verifying_key())
}

#[test]
fn sender_keys_removed_member_cannot_decrypt_new_messages() {
    let group_id = [0u8; 32];
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

    // Carol can decrypt before removal
    let ct1 = alice.encrypt(b"before").unwrap();
    assert_eq!(carol.decrypt(&alice_id, &ct1).unwrap(), b"before");

    // Remove Carol — Alice rotates keys
    let new_alice_dist = alice.remove_member(&carol_id);
    bob.process_distribution(&new_alice_dist).unwrap();
    // Carol does NOT get the new distribution

    // Post-removal messages: Bob can decrypt, Carol cannot
    let ct2 = alice.encrypt(b"after removal").unwrap();
    assert_eq!(bob.decrypt(&alice_id, &ct2).unwrap(), b"after removal");
    assert!(carol.decrypt(&alice_id, &ct2).is_err());
}

#[test]
fn sender_keys_forged_signature_rejected() {
    let group_id = [0u8; 32];
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    let alice_dist = alice.our_distribution();
    bob.process_distribution(&alice_dist).unwrap();

    let mut ct = alice.encrypt(b"hello").unwrap();

    // Forge the signature
    ct.signature = [0xAA; 64];

    let result = bob.decrypt(&alice_id, &ct);
    assert!(matches!(result, Err(SenderKeyError::InvalidSignature(_))));
}

#[test]
fn sender_keys_wrong_group_distribution_rejected() {
    let group_id = [0u8; 32];
    let alice_id = make_node_id(1);

    let mut session = GroupSession::new(group_id, alice_id);

    let bad_dist = SenderKeyDistribution {
        group_id: [0xFF; 32], // Wrong group ID
        sender: make_node_id(2),
        chain_key: [0u8; 32],
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[2u8; 32])
            .verifying_key()
            .to_bytes(),
        generation: 0,
    };

    let result = session.process_distribution(&bad_dist);
    assert!(matches!(
        result,
        Err(SenderKeyError::InvalidDistribution(_))
    ));
}

#[test]
fn sender_keys_generation_mismatch_rejected() {
    let group_id = [0u8; 32];
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    let alice_dist = alice.our_distribution();
    bob.process_distribution(&alice_dist).unwrap();

    let ct = alice.encrypt(b"hello").unwrap();

    // Manually tamper with the generation field
    let mut tampered = ct.clone();
    tampered.generation = 999;

    let result = bob.decrypt(&alice_id, &tampered);
    assert!(result.is_err());
}

// ═════════════════════════════════════════════════════════════════════════════
// NOISE_XX — TRANSPORT SECURITY
// ═════════════════════════════════════════════════════════════════════════════

/// Complete a Noise_XX handshake between two sessions.
fn complete_noise_handshake(
    initiator: &mut konsensus_crypto::NoiseSession,
    responder: &mut konsensus_crypto::NoiseSession,
) {
    let msg1 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg1).unwrap();
    let msg2 = responder.write_handshake(&[]).unwrap();
    initiator.read_handshake(&msg2).unwrap();
    let msg3 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg3).unwrap();
    initiator.try_finish_handshake().unwrap();
    responder.try_finish_handshake().unwrap();
}

fn noise_keypair() -> [u8; 32] {
    let params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let keypair = snow::Builder::new(params).generate_keypair().unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&keypair.private);
    key
}

#[test]
fn noise_tampered_ciphertext_decryption_fails() {
    use konsensus_crypto::NoiseSession;

    let ik = noise_keypair();
    let rk = noise_keypair();
    let mut initiator = NoiseSession::initiator(&ik).unwrap();
    let mut responder = NoiseSession::responder(&rk).unwrap();
    complete_noise_handshake(&mut initiator, &mut responder);

    let plaintext = b"test message";
    let mut ciphertext = initiator.encrypt(plaintext).unwrap();

    // Tamper with ciphertext
    if let Some(byte) = ciphertext.get_mut(0) {
        *byte ^= 0xFF;
    }

    // Decryption must fail
    assert!(responder.decrypt(&ciphertext).is_err());
}

#[test]
fn noise_message_from_wrong_session_fails() {
    use konsensus_crypto::NoiseSession;

    let ik1 = noise_keypair();
    let rk1 = noise_keypair();
    let mut initiator1 = NoiseSession::initiator(&ik1).unwrap();
    let mut responder1 = NoiseSession::responder(&rk1).unwrap();
    complete_noise_handshake(&mut initiator1, &mut responder1);

    let ik2 = noise_keypair();
    let rk2 = noise_keypair();
    let mut _initiator2 = NoiseSession::initiator(&ik2).unwrap();
    let mut responder2 = NoiseSession::responder(&rk2).unwrap();
    complete_noise_handshake(&mut _initiator2, &mut responder2);

    let ciphertext = initiator1.encrypt(b"hello").unwrap();

    // Different session cannot decrypt
    assert!(responder2.decrypt(&ciphertext).is_err());
}
