//! Identity and MITM tests for the federation handshake.
//!
//! Covers four attack vectors against the BitSov node-to-node handshake:
//!
//! 1. Noise_XX wrong static key - an impostor completes the Noise handshake
//!    with a different X25519 key; the application layer must verify the
//!    authenticated remote static key matches the expected peer identity.
//!
//! 2. Ed25519 signature forgery - tampered or cross-key signatures on
//!    SignedMessage federation messages must be rejected.
//!
//! 3. Handshake replay - a captured Noise ciphertext replayed to the
//!    same session must fail due to stateful AEAD nonce advancement.
//!
//! 4. MITM on prekey bundle - an attacker substituting a different
//!    signed_prekey in Bob's X3DH bundle must be caught by Ed25519
//!    signature verification before the DH exchange proceeds.

use ed25519_dalek::Signer;
use konsensus_core::federation::SignedMessage;
use konsensus_core::identity::NodeIdentity;
use konsensus_core::types::Signature;
use konsensus_crypto::x3dh::{self, PrekeyBundle, SignedPreKey, X3dhError};
use konsensus_crypto::NoiseSession;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

// ---------------------------------------------------------------------------
// Deterministic test identities.
// One valid BIP-39 mnemonic; passphrase differentiates node identities.
// ---------------------------------------------------------------------------

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art";

fn alice() -> NodeIdentity {
    NodeIdentity::from_mnemonic(TEST_MNEMONIC, "alice").unwrap()
}

fn bob() -> NodeIdentity {
    NodeIdentity::from_mnemonic(TEST_MNEMONIC, "bob").unwrap()
}

fn impostor() -> NodeIdentity {
    NodeIdentity::from_mnemonic(TEST_MNEMONIC, "impostor").unwrap()
}

// ---------------------------------------------------------------------------
// Helper: run the Noise_XX three-message handshake to completion.
// ---------------------------------------------------------------------------

fn complete_noise_handshake(i: &mut NoiseSession, r: &mut NoiseSession) {
    let m1 = i.write_handshake(&[]).unwrap();
    r.read_handshake(&m1).unwrap();
    let m2 = r.write_handshake(&[]).unwrap();
    i.read_handshake(&m2).unwrap();
    let m3 = i.write_handshake(&[]).unwrap();
    r.read_handshake(&m3).unwrap();
    i.try_finish_handshake().unwrap();
    r.try_finish_handshake().unwrap();
}

// =============================================================================
// TEST 1 - Noise_XX: wrong static key rejected by application
// =============================================================================

/// An impostor using a different X25519 static key completes Noise_XX, but the
/// application layer detects the key mismatch against the expected peer identity.
///
/// Noise_XX provides mutual authentication of static keys via DH; the authenticated
/// key is available via remote_static_key(). The application must compare that
/// key against the expected identity - a mismatch means the connection is from
/// an impostor and must be rejected.
#[test]
fn noise_xx_wrong_static_key_rejected_by_application() {
    let alice = alice();
    let bob = bob();
    let impostor = impostor();

    // Alice knows Bob's expected X25519 public key (from his node manifest /
    // Bitcoin-anchored identity, established out-of-band).
    let bob_expected_x25519: [u8; 32] = *bob.x25519_public().as_bytes();

    // -- Happy path: Alice connects to the REAL Bob --
    {
        let mut alice_session = NoiseSession::initiator(alice.x25519_secret_bytes()).unwrap();
        let mut bob_session = NoiseSession::responder(bob.x25519_secret_bytes()).unwrap();
        complete_noise_handshake(&mut alice_session, &mut bob_session);

        let remote = alice_session.remote_static_key().unwrap();
        assert_eq!(
            remote, &bob_expected_x25519,
            "happy path: authenticated remote key must match Bob's real X25519 public key"
        );
    }

    // -- Attack path: Alice is tricked into connecting to an IMPOSTOR --
    {
        let mut alice_session = NoiseSession::initiator(alice.x25519_secret_bytes()).unwrap();
        let mut impostor_session =
            NoiseSession::responder(impostor.x25519_secret_bytes()).unwrap();
        complete_noise_handshake(&mut alice_session, &mut impostor_session);

        let remote = alice_session.remote_static_key().unwrap();

        // The authenticated key does NOT match Bob's expected key.
        assert_ne!(
            remote, &bob_expected_x25519,
            "impostor's X25519 key must differ from Bob's expected key"
        );

        // Application layer decision: reject the connection.
        let accepted = remote == &bob_expected_x25519;
        assert!(
            !accepted,
            "application must reject a connection whose authenticated static key \
             does not match the expected peer"
        );
    }
}

// =============================================================================
// TEST 2 - Ed25519 signature forgery rejected
// =============================================================================

/// Replacing the 64-byte signature with arbitrary bytes must fail verification.
#[test]
fn ed25519_forged_signature_bytes_rejected() {
    let alice = alice();
    let now_ms = 1_700_000_000_000u64;

    let mut msg = SignedMessage::sign(&alice, b"federation-hello".to_vec(), now_ms);

    // Overwrite all 64 signature bytes with a forged value.
    msg.signature = Signature::from_bytes([0xDE; 64]);

    assert!(
        msg.verify_signature().is_err(),
        "forged signature bytes must be rejected"
    );
}

/// Signing a message with Alice's key but claiming to be Bob must fail.
///
/// verify_signature derives the verifying key from sender (Bob's NodeId),
/// which won't verify a signature produced by Alice's key.
#[test]
fn ed25519_cross_identity_signature_rejected() {
    let alice = alice();
    let bob = bob();
    let now_ms = 1_700_000_000_000u64;

    let mut msg = SignedMessage::sign(&alice, b"federation-hello".to_vec(), now_ms);

    // Attacker replaces sender with Bob's NodeId - the signature was made by
    // Alice's key, which cannot verify against Bob's public key.
    msg.sender = *bob.node_id();

    assert!(
        msg.verify_signature().is_err(),
        "a message signed by Alice but claiming Bob as sender must be rejected"
    );
}

/// Attacker produces a structurally valid Ed25519 signature with their own key
/// but claims the victim's NodeId as the sender.
///
/// verify_signature uses the public key embedded in sender (Alice's NodeId);
/// the attacker's signature won't verify against Alice's authentic public key.
#[test]
fn ed25519_attacker_own_key_claiming_victim_identity_rejected() {
    let alice = alice();
    let now_ms = 1_700_000_000_000u64;

    // Attacker generates an ephemeral Ed25519 signing key.
    let attacker_signing = ed25519_dalek::SigningKey::from_bytes(&[0xAA; 32]);

    let payload = b"federation-hello FAKE".to_vec();
    let alice_node_id = *alice.node_id();
    let nonce = konsensus_core::types::Nonce::generate();

    // Build the signable bytes exactly as SignedMessage::sign does internally.
    let mut signable = Vec::new();
    signable.extend_from_slice(&payload);
    signable.extend_from_slice(alice_node_id.as_bytes());
    signable.extend_from_slice(nonce.as_bytes());
    signable.extend_from_slice(&now_ms.to_be_bytes());

    // Attacker signs with their own key, not Alice's.
    let attacker_sig = attacker_signing.sign(&signable);

    let msg = SignedMessage {
        payload,
        sender: alice_node_id,
        nonce,
        timestamp: now_ms,
        signature: Signature::from_ed25519(&attacker_sig),
    };

    // Alice's public key (derived from her NodeId) cannot verify this signature.
    assert!(
        msg.verify_signature().is_err(),
        "attacker's Ed25519 signature must not verify against Alice's public key"
    );
}

// =============================================================================
// TEST 3 - Handshake replay rejected
// =============================================================================

/// A ciphertext from an established Noise session cannot be replayed.
///
/// Noise transport uses a stateful nonce counter (ChaCha20-Poly1305).
/// After Bob decrypts nonce=0, his counter advances to 1. Replaying the same
/// ciphertext (still bound to nonce=0) fails AEAD authentication.
#[test]
fn noise_transport_replay_rejected() {
    let alice = alice();
    let bob = bob();

    let mut alice_session = NoiseSession::initiator(alice.x25519_secret_bytes()).unwrap();
    let mut bob_session = NoiseSession::responder(bob.x25519_secret_bytes()).unwrap();
    complete_noise_handshake(&mut alice_session, &mut bob_session);

    // Alice sends the first encrypted message.
    let plaintext = b"federation payload - sovereign mesh";
    let ciphertext = alice_session.encrypt(plaintext).unwrap();

    // Bob decrypts successfully (nonce counter: 0 -> 1).
    let decrypted = bob_session.decrypt(&ciphertext).unwrap();
    assert_eq!(&decrypted, plaintext, "first decryption must succeed");

    // Attacker replays the exact same ciphertext.
    // Bob's receive counter is now 1; the replayed ciphertext targets nonce 0
    // -> AEAD authentication fails.
    let replay_result = bob_session.decrypt(&ciphertext);
    assert!(
        replay_result.is_err(),
        "replayed Noise ciphertext must be rejected (stateful nonce counter prevents reuse)"
    );
}

/// Federation-layer replay is detectable via unique per-message nonces.
///
/// Every SignedMessage carries a random 24-byte nonce. A node tracking seen
/// nonces can detect and reject any replayed message.
#[test]
fn federation_signed_message_nonce_enables_replay_detection() {
    let alice = alice();
    let now_ms = 1_700_000_000_000u64;

    let msg1 = SignedMessage::sign(&alice, b"connect-request".to_vec(), now_ms);
    let msg2 = SignedMessage::sign(&alice, b"connect-request".to_vec(), now_ms);

    // Identical payload and timestamp -> each message still has a unique nonce.
    assert_ne!(
        msg1.nonce, msg2.nonce,
        "each SignedMessage must carry a unique nonce"
    );

    // Simulate a node's nonce store: track seen nonces, reject duplicates.
    let mut seen_nonces = std::collections::HashSet::new();

    // First occurrence: fresh nonce accepted.
    assert!(!seen_nonces.contains(&msg1.nonce), "nonce should not yet be in store");
    seen_nonces.insert(msg1.nonce);

    // Replay: same nonce detected.
    assert!(
        seen_nonces.contains(&msg1.nonce),
        "replayed nonce must be detected as already seen"
    );

    // Second distinct message: not a replay.
    assert!(!seen_nonces.contains(&msg2.nonce), "different message nonce must not be flagged");
}

// =============================================================================
// TEST 4 - MITM on prekey bundle: X3DH sig verify fails
// =============================================================================

/// An attacker substituting a different signed_prekey in Bob's X3DH prekey bundle
/// is caught immediately by Ed25519 signature verification in x3dh::initiate.
///
/// Bob publishes a bundle where signed_prekey is signed with his Ed25519 key.
/// A MITM swapping that key for their own cannot produce a valid signature
/// (they don't have Bob's signing key). x3dh::initiate verifies before any DH.
#[test]
fn x3dh_mitm_on_signed_prekey_rejected() {
    let bob = bob();

    // Bob generates and signs his pre-key.
    let bob_spk = SignedPreKey::generate();
    let bob_spk_sig = bob.ed25519_signing_key().sign(bob_spk.public.as_bytes());

    // -- Happy path: authentic bundle --
    {
        let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let alice_public = X25519PublicKey::from(&alice_secret);

        let authentic_bundle = PrekeyBundle {
            identity_key: *bob.x25519_public(),
            signed_prekey: bob_spk.public,
            signed_prekey_sig: bob_spk_sig,
            identity_verifying_key: *bob.ed25519_verifying_key(),
            one_time_prekey: None,
            one_time_prekey_id: None,
        };

        let result = x3dh::initiate(&alice_secret, &alice_public, &authentic_bundle);
        assert!(result.is_ok(), "authentic bundle must succeed X3DH initiation");
    }

    // -- Attack path: MITM substitutes attacker's signed_prekey --
    {
        let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let alice_public = X25519PublicKey::from(&alice_secret);

        // Attacker generates their own SPK; they cannot sign it with Bob's key.
        let attacker_spk = SignedPreKey::generate();

        let tampered_bundle = PrekeyBundle {
            identity_key: *bob.x25519_public(),
            signed_prekey: attacker_spk.public, // MITM substitution
            signed_prekey_sig: bob_spk_sig,      // Bob's sig over a *different* key
            identity_verifying_key: *bob.ed25519_verifying_key(),
            one_time_prekey: None,
            one_time_prekey_id: None,
        };

        let result = x3dh::initiate(&alice_secret, &alice_public, &tampered_bundle);
        assert!(
            matches!(result, Err(X3dhError::InvalidSignature(_))),
            "tampered prekey bundle must be rejected with X3dhError::InvalidSignature"
        );
    }
}

/// Stronger MITM attempt: attacker provides their OWN signature over their own
/// SPK while keeping Bob's identity_verifying_key in the bundle.
///
/// x3dh::initiate verifies the signature against identity_verifying_key
/// (Bob's authentic Ed25519 pubkey). The attacker's key != Bob's key
/// -> verification fails with InvalidSignature.
#[test]
fn x3dh_mitm_with_attacker_self_signed_prekey_rejected() {
    let bob = bob();

    let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_public = X25519PublicKey::from(&alice_secret);

    // Attacker generates their own Ed25519 key and SPK.
    let attacker_signing = ed25519_dalek::SigningKey::from_bytes(&[0xBB; 32]);
    let attacker_spk = SignedPreKey::generate();
    // Attacker signs their SPK with their own key (not Bob's).
    let attacker_sig = attacker_signing.sign(attacker_spk.public.as_bytes());

    let tampered_bundle = PrekeyBundle {
        identity_key: *bob.x25519_public(),               // Bob's real identity key
        signed_prekey: attacker_spk.public,                // Attacker's SPK
        signed_prekey_sig: attacker_sig,                   // Attacker's own signature
        identity_verifying_key: *bob.ed25519_verifying_key(), // Bob's real Ed25519 pubkey
        one_time_prekey: None,
        one_time_prekey_id: None,
    };

    // initiate verifies against identity_verifying_key (Bob's pubkey).
    // Attacker's signature won't verify -> rejected.
    let result = x3dh::initiate(&alice_secret, &alice_public, &tampered_bundle);
    assert!(
        matches!(result, Err(X3dhError::InvalidSignature(_))),
        "attacker's self-signed prekey bundle must be rejected with X3dhError::InvalidSignature"
    );
}
