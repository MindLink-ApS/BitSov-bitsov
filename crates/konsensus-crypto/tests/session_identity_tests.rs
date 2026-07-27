//! Hardening tests for session manager lifecycle, identity edge cases,
//! prekey bundle serialization, ratchet message boundaries, and session
//! store interaction patterns.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use konsensus_core::identity::{IdentityError, NodeIdentity};
use konsensus_core::types::NodeId;
use konsensus_crypto::double_ratchet::{DoubleRatchet, RatchetMessage};
use konsensus_crypto::session::{
    ratchet_message_from_bytes, ratchet_message_to_bytes, SessionError, SessionManager,
    SessionStore,
};
use konsensus_crypto::x3dh::SignedPreKey;
use tokio::sync::Mutex;

const MNEMONIC_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon art";

const MNEMONIC_B: &str = "zoo zoo zoo zoo zoo zoo zoo zoo \
    zoo zoo zoo zoo zoo zoo zoo zoo \
    zoo zoo zoo zoo zoo zoo zoo vote";

fn make_identity(mnemonic: &str) -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(mnemonic, "").unwrap())
}

// ── In-Memory Session Store ──────────────────────────────────────────────────

struct InMemorySessionStore {
    data: Mutex<HashMap<NodeId, Vec<u8>>>,
}

impl InMemorySessionStore {
    fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn save_session(
        &self,
        peer_id: &NodeId,
        state_json: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.data.lock().await.insert(*peer_id, state_json.to_vec());
        Ok(())
    }

    async fn load_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.data.lock().await.get(peer_id).cloned())
    }

    async fn delete_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.data.lock().await.remove(peer_id);
        Ok(())
    }

    async fn list_sessions(
        &self,
    ) -> Result<Vec<NodeId>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.data.lock().await.keys().copied().collect())
    }
}

/// Session store that always fails
struct FailingSessionStore;

#[async_trait]
impl SessionStore for FailingSessionStore {
    async fn save_session(
        &self,
        _peer_id: &NodeId,
        _state_json: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("save failed".into())
    }

    async fn load_session(
        &self,
        _peer_id: &NodeId,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        Err("load failed".into())
    }

    async fn delete_session(
        &self,
        _peer_id: &NodeId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("delete failed".into())
    }

    async fn list_sessions(
        &self,
    ) -> Result<Vec<NodeId>, Box<dyn std::error::Error + Send + Sync>> {
        Err("list failed".into())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// IDENTITY EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn twelve_word_mnemonic_accepted() {
    // bip39 supports 12, 15, 18, 21, 24 word mnemonics
    let mnemonic_12 = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
    let result = NodeIdentity::from_mnemonic(mnemonic_12, "");
    assert!(result.is_ok(), "12-word mnemonic should be valid");
}

#[test]
fn empty_string_mnemonic_rejected() {
    let result = NodeIdentity::from_mnemonic("", "");
    assert!(matches!(result, Err(IdentityError::InvalidMnemonic(_))));
}

#[test]
fn whitespace_only_mnemonic_rejected() {
    let result = NodeIdentity::from_mnemonic("   \t\n  ", "");
    assert!(matches!(result, Err(IdentityError::InvalidMnemonic(_))));
}

#[test]
fn mnemonic_with_extra_whitespace_handled() {
    // Extra spaces between words should still parse
    let mnemonic = "abandon  abandon  abandon  abandon  abandon  abandon \
                     abandon  abandon  abandon  abandon  abandon  about";
    // bip39 crate may or may not normalize — test what happens
    let _result = NodeIdentity::from_mnemonic(mnemonic, "");
    // Not asserting success/failure — just no panic
}

#[test]
fn wrong_checksum_mnemonic_rejected() {
    // Last word is wrong checksum
    let bad = "abandon abandon abandon abandon abandon abandon \
               abandon abandon abandon abandon abandon abandon";
    let result = NodeIdentity::from_mnemonic(bad, "");
    assert!(result.is_err());
}

#[test]
fn seed_with_all_zeros_produces_valid_identity() {
    // All-zero 64-byte seed is degenerate but should still derive valid keys
    let seed = [0u8; 64];
    let id = NodeIdentity::from_seed(&seed).expect("all-zero seed must produce valid identity");
    // Verify identity can sign and verify (keys are functional)
    let sig = id.sign(b"test");
    id.verify(b"test", &sig).expect("zero-seed identity must produce valid signatures");
}

#[test]
fn seed_with_all_ones_produces_valid_identity() {
    let seed_zeros = [0u8; 64];
    let seed_ones = [0xFF; 64];
    let id_zeros = NodeIdentity::from_seed(&seed_zeros).unwrap();
    let id_ones = NodeIdentity::from_seed(&seed_ones).expect("all-ones seed must produce valid identity");
    // Different seeds must produce different node IDs
    assert_ne!(id_zeros.node_id(), id_ones.node_id());
}

#[test]
fn seed_length_63_rejected() {
    let result = NodeIdentity::from_seed(&[0u8; 63]);
    assert!(matches!(result, Err(IdentityError::InvalidSeedLength(63))));
}

#[test]
fn seed_length_65_rejected() {
    let result = NodeIdentity::from_seed(&[0u8; 65]);
    assert!(matches!(result, Err(IdentityError::InvalidSeedLength(65))));
}

#[test]
fn seed_length_0_rejected() {
    let result = NodeIdentity::from_seed(&[]);
    assert!(matches!(result, Err(IdentityError::InvalidSeedLength(0))));
}

#[test]
fn sign_empty_message() {
    let id = NodeIdentity::from_mnemonic(MNEMONIC_A, "").unwrap();
    let sig = id.sign(b"");
    id.verify(b"", &sig).expect("empty message signature must verify");
    // Signature for empty message must NOT verify against non-empty message
    assert!(id.verify(b"x", &sig).is_err());
}

#[test]
fn sign_large_message() {
    let id = NodeIdentity::from_mnemonic(MNEMONIC_A, "").unwrap();
    let large = vec![0x42; 1024 * 1024]; // 1 MB
    let sig = id.sign(&large);
    id.verify(&large, &sig).expect("large message signature must verify");
    // Verify the signature is deterministic (Ed25519 is deterministic)
    let sig2 = id.sign(&large);
    assert_eq!(sig.to_bytes(), sig2.to_bytes());
}

#[test]
fn verify_with_corrupted_signature() {
    let id = NodeIdentity::from_mnemonic(MNEMONIC_A, "").unwrap();
    let sig = id.sign(b"test message");

    let mut sig_bytes = sig.to_bytes();
    sig_bytes[0] ^= 0xFF; // flip first byte
    let corrupted = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    let err = id.verify(b"test message", &corrupted);
    assert!(err.is_err(), "corrupted signature must fail verification");
    // Original signature must still verify
    id.verify(b"test message", &sig).expect("original signature must still verify");
}

#[test]
fn verify_with_flipped_last_byte_signature() {
    let id = NodeIdentity::from_mnemonic(MNEMONIC_A, "").unwrap();
    let sig = id.sign(b"test");

    // Flip the last byte of the signature — still 64 bytes but invalid
    let mut sig_bytes = sig.to_bytes();
    sig_bytes[63] ^= 0xFF;
    let bad_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    let err = id.verify(b"test", &bad_sig);
    assert!(err.is_err(), "flipped-last-byte signature must fail verification");
    // Different message must also fail with the original good signature
    assert!(id.verify(b"wrong", &sig).is_err());
}

#[test]
fn jwt_secret_deterministic() {
    let id1 = NodeIdentity::from_mnemonic(MNEMONIC_A, "").unwrap();
    let id2 = NodeIdentity::from_mnemonic(MNEMONIC_A, "").unwrap();
    assert_eq!(id1.derive_jwt_secret(), id2.derive_jwt_secret());
}

#[test]
fn jwt_secret_differs_between_identities() {
    let id1 = NodeIdentity::from_mnemonic(MNEMONIC_A, "").unwrap();
    let id2 = NodeIdentity::from_mnemonic(MNEMONIC_B, "").unwrap();
    assert_ne!(id1.derive_jwt_secret(), id2.derive_jwt_secret());
}

#[test]
fn x25519_shared_secret_symmetric() {
    let id1 = NodeIdentity::from_mnemonic(MNEMONIC_A, "alice").unwrap();
    let id2 = NodeIdentity::from_mnemonic(MNEMONIC_A, "bob").unwrap();

    let shared_ab = id1.x25519_secret().diffie_hellman(id2.x25519_public());
    let shared_ba = id2.x25519_secret().diffie_hellman(id1.x25519_public());
    assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());
}

#[test]
fn different_passphrases_produce_different_shared_secrets() {
    let id1 = NodeIdentity::from_mnemonic(MNEMONIC_A, "pass1").unwrap();
    let id2 = NodeIdentity::from_mnemonic(MNEMONIC_A, "pass2").unwrap();
    let id3 = NodeIdentity::from_mnemonic(MNEMONIC_A, "pass1").unwrap();

    // Same passphrase → same identity
    assert_eq!(id1.node_id(), id3.node_id());
    // Different passphrase → different identity
    assert_ne!(id1.node_id(), id2.node_id());
}

#[test]
fn generate_produces_unique_identities() {
    let (m1, id1) = NodeIdentity::generate().unwrap();
    let (m2, id2) = NodeIdentity::generate().unwrap();
    assert_ne!(m1, m2);
    assert_ne!(id1.node_id(), id2.node_id());
}

// ═══════════════════════════════════════════════════════════════════════════════
// SESSION MANAGER LIFECYCLE
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn full_session_lifecycle_with_store() {
    let store = Arc::new(InMemorySessionStore::new());
    let alice_id = make_identity(MNEMONIC_A);
    let bob_id = make_identity(MNEMONIC_B);

    let alice = SessionManager::with_store(alice_id.clone(), store.clone());
    let bob = SessionManager::with_store(bob_id.clone(), store.clone());

    // Get Bob's prekey bundle
    let bob_bundle = bob.prekey_bundle().await;

    // Alice initiates session with Bob
    let init_data = alice
        .initiate_session(bob_id.node_id(), &bob_bundle)
        .await
        .unwrap();

    // Bob accepts session from Alice
    bob.accept_session(alice_id.node_id(), &init_data)
        .await
        .unwrap();

    // Alice can encrypt (initiator has sending chain immediately)
    assert!(alice.can_send(bob_id.node_id()).await);

    // Bob cannot send yet (acceptor needs first decrypt to init sending chain)
    assert!(!bob.can_send(alice_id.node_id()).await);

    // Alice sends first message
    let msg = alice.encrypt(bob_id.node_id(), b"hello bob").await.unwrap();
    let decrypted = bob.decrypt(alice_id.node_id(), &msg).await.unwrap();
    assert_eq!(decrypted, b"hello bob");

    // Now Bob can send
    assert!(bob.can_send(alice_id.node_id()).await);

    // Bidirectional messaging
    let msg = bob.encrypt(alice_id.node_id(), b"hello alice").await.unwrap();
    let decrypted = alice.decrypt(bob_id.node_id(), &msg).await.unwrap();
    assert_eq!(decrypted, b"hello alice");

    // Session count
    assert_eq!(alice.session_count().await, 1);
    assert_eq!(bob.session_count().await, 1);

    // Verify store was written
    assert!(!store.data.lock().await.is_empty());
}

#[tokio::test]
async fn encrypt_without_session_fails() {
    let alice_id = make_identity(MNEMONIC_A);
    let bob_id = make_identity(MNEMONIC_B);
    let alice = SessionManager::new(alice_id);

    let result = alice.encrypt(bob_id.node_id(), b"no session").await;
    assert!(matches!(result, Err(SessionError::NoSession(_))));
}

#[tokio::test]
async fn decrypt_without_session_fails() {
    let alice_id = make_identity(MNEMONIC_A);
    let bob_id = make_identity(MNEMONIC_B);
    let alice = SessionManager::new(alice_id);

    let dummy_msg = RatchetMessage {
        header: konsensus_crypto::double_ratchet::MessageHeader {
            dh_public: [0u8; 32],
            previous_chain_length: 0,
            message_number: 0,
        },
        ciphertext: vec![0u8; 64],
    };

    let result = alice.decrypt(bob_id.node_id(), &dummy_msg).await;
    assert!(matches!(result, Err(SessionError::NoSession(_))));
}

#[tokio::test]
async fn duplicate_session_initiation_rejected() {
    let alice_id = make_identity(MNEMONIC_A);
    let bob_id = make_identity(MNEMONIC_B);

    let alice = SessionManager::new(alice_id.clone());
    let bob = SessionManager::new(bob_id.clone());

    let bob_bundle = bob.prekey_bundle().await;

    // First initiation succeeds
    alice
        .initiate_session(bob_id.node_id(), &bob_bundle)
        .await
        .unwrap();

    // Second initiation fails — session already exists
    let result = alice
        .initiate_session(bob_id.node_id(), &bob_bundle)
        .await;
    assert!(matches!(result, Err(SessionError::SessionExists(_))));
}

#[tokio::test]
async fn remove_session_and_reinitiate() {
    let alice_id = make_identity(MNEMONIC_A);
    let bob_id = make_identity(MNEMONIC_B);

    let alice = SessionManager::new(alice_id.clone());
    let bob = SessionManager::new(bob_id.clone());

    let bob_bundle = bob.prekey_bundle().await;

    // Create and remove session
    alice
        .initiate_session(bob_id.node_id(), &bob_bundle)
        .await
        .unwrap();
    assert!(alice.remove_session(bob_id.node_id()).await);

    // Can re-initiate after removal
    alice
        .initiate_session(bob_id.node_id(), &bob_bundle)
        .await
        .unwrap();
    assert!(alice.has_session(bob_id.node_id()).await);
}

#[tokio::test]
async fn remove_nonexistent_session_returns_false() {
    let alice_id = make_identity(MNEMONIC_A);
    let alice = SessionManager::new(alice_id);

    let fake_id = NodeId::from_bytes([99u8; 32]);
    assert!(!alice.remove_session(&fake_id).await);
}

#[tokio::test]
async fn has_session_false_for_no_session() {
    let alice_id = make_identity(MNEMONIC_A);
    let alice = SessionManager::new(alice_id);
    assert!(!alice.has_session(&NodeId::from_bytes([99u8; 32])).await);
}

#[tokio::test]
async fn active_sessions_returns_peer_ids() {
    let alice_id = make_identity(MNEMONIC_A);
    let bob_id = make_identity(MNEMONIC_B);

    let alice = SessionManager::new(alice_id.clone());
    let bob = SessionManager::new(bob_id.clone());

    assert!(alice.active_sessions().await.is_empty());

    let bob_bundle = bob.prekey_bundle().await;
    alice
        .initiate_session(bob_id.node_id(), &bob_bundle)
        .await
        .unwrap();

    let sessions = alice.active_sessions().await;
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0], *bob_id.node_id());
}

#[tokio::test]
async fn prekey_bundle_has_one_time_prekey() {
    let alice_id = make_identity(MNEMONIC_A);
    let alice = SessionManager::new(alice_id);
    let bundle = alice.prekey_bundle().await;

    assert!(bundle.one_time_prekey.is_some());
    assert!(bundle.one_time_prekey_id.is_some());
    assert!(!bundle.identity_key.is_empty());
    assert!(!bundle.signed_prekey.is_empty());
    assert!(!bundle.signed_prekey_sig.is_empty());
    assert!(!bundle.node_id.is_empty());
}

#[tokio::test]
async fn multiple_sessions_to_different_peers() {
    let alice_id = make_identity(MNEMONIC_A);
    let alice = SessionManager::new(alice_id.clone());

    // Create sessions with 5 different peers
    for pass in ["peer1", "peer2", "peer3", "peer4", "peer5"] {
        let peer_id = Arc::new(NodeIdentity::from_mnemonic(MNEMONIC_B, pass).unwrap());
        let peer_mgr = SessionManager::new(peer_id.clone());
        let bundle = peer_mgr.prekey_bundle().await;
        alice
            .initiate_session(peer_id.node_id(), &bundle)
            .await
            .unwrap();
    }

    assert_eq!(alice.session_count().await, 5);
}

// ═══════════════════════════════════════════════════════════════════════════════
// RATCHET MESSAGE SERIALIZATION EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ratchet_message_roundtrip() {
    let msg = RatchetMessage {
        header: konsensus_crypto::double_ratchet::MessageHeader {
            dh_public: [0xAB; 32],
            previous_chain_length: 42,
            message_number: 99,
        },
        ciphertext: vec![1, 2, 3, 4, 5],
    };

    let bytes = ratchet_message_to_bytes(&msg);
    let decoded = ratchet_message_from_bytes(&bytes).unwrap();

    assert_eq!(decoded.header.dh_public, [0xAB; 32]);
    assert_eq!(decoded.header.previous_chain_length, 42);
    assert_eq!(decoded.header.message_number, 99);
    assert_eq!(decoded.ciphertext, vec![1, 2, 3, 4, 5]);
}

#[test]
fn ratchet_message_with_empty_ciphertext() {
    let msg = RatchetMessage {
        header: konsensus_crypto::double_ratchet::MessageHeader {
            dh_public: [0; 32],
            previous_chain_length: 0,
            message_number: 0,
        },
        ciphertext: vec![],
    };

    let bytes = ratchet_message_to_bytes(&msg);
    assert_eq!(bytes.len(), 40); // 32 (dh) + 4 (pn) + 4 (n) + 0 (ct)

    let decoded = ratchet_message_from_bytes(&bytes).unwrap();
    assert!(decoded.ciphertext.is_empty());
}

#[test]
fn ratchet_message_from_39_bytes_fails() {
    let short = vec![0u8; 39]; // one byte less than header
    assert!(ratchet_message_from_bytes(&short).is_err());
}

#[test]
fn ratchet_message_from_exactly_40_bytes_succeeds() {
    let exact = vec![0u8; 40]; // exactly header, empty ciphertext
    let msg = ratchet_message_from_bytes(&exact).unwrap();
    assert!(msg.ciphertext.is_empty());
}

#[test]
fn ratchet_message_with_large_ciphertext() {
    let msg = RatchetMessage {
        header: konsensus_crypto::double_ratchet::MessageHeader {
            dh_public: [0xFF; 32],
            previous_chain_length: u32::MAX,
            message_number: u32::MAX,
        },
        ciphertext: vec![0xCC; 1024 * 1024], // 1 MB
    };

    let bytes = ratchet_message_to_bytes(&msg);
    let decoded = ratchet_message_from_bytes(&bytes).unwrap();
    assert_eq!(decoded.ciphertext.len(), 1024 * 1024);
    assert_eq!(decoded.header.previous_chain_length, u32::MAX);
    assert_eq!(decoded.header.message_number, u32::MAX);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SESSION STORE INTERACTION PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn restore_from_empty_store_returns_zero() {
    let store = Arc::new(InMemorySessionStore::new());
    let alice = SessionManager::with_store(make_identity(MNEMONIC_A), store);
    assert_eq!(alice.restore_sessions().await, 0);
}

#[tokio::test]
async fn failing_store_does_not_crash_on_restore() {
    let store = Arc::new(FailingSessionStore);
    let alice = SessionManager::with_store(make_identity(MNEMONIC_A), store);
    // Should return 0, not panic
    assert_eq!(alice.restore_sessions().await, 0);
}

#[tokio::test]
async fn session_without_store_works_in_memory() {
    let alice_id = make_identity(MNEMONIC_A);
    let bob_id = make_identity(MNEMONIC_B);

    let alice = SessionManager::new(alice_id.clone());
    let bob = SessionManager::new(bob_id.clone());

    let bob_bundle = bob.prekey_bundle().await;
    let init = alice
        .initiate_session(bob_id.node_id(), &bob_bundle)
        .await
        .unwrap();
    bob.accept_session(alice_id.node_id(), &init).await.unwrap();

    let msg = alice.encrypt(bob_id.node_id(), b"test").await.unwrap();
    let pt = bob.decrypt(alice_id.node_id(), &msg).await.unwrap();
    assert_eq!(pt, b"test");
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOUBLE RATCHET EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

fn make_ratchet_pair() -> (DoubleRatchet, DoubleRatchet) {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = SignedPreKey::generate();
    let alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).expect("test setup");
    let bob = DoubleRatchet::init_receiver(&shared_secret, bob_spk.secret(), &bob_spk.public, ad);
    (alice, bob)
}

#[test]
fn out_of_order_messages_within_skip_limit() {
    let (mut alice, mut bob) = make_ratchet_pair();

    // Alice sends 5 messages
    let mut messages = Vec::new();
    for i in 0..5u8 {
        let msg = alice.encrypt(&[i]).unwrap();
        messages.push(msg);
    }

    // Bob decrypts in reverse order (out-of-order delivery)
    for i in (0..5u8).rev() {
        let pt = bob.decrypt(&messages[i as usize]).unwrap();
        assert_eq!(pt, vec![i]);
    }
}

#[test]
fn bidirectional_ratchet_ping_pong() {
    let (mut alice, mut bob) = make_ratchet_pair();

    // Alice→Bob, Bob→Alice, back and forth
    for round in 0..10u8 {
        let msg = alice.encrypt(&[round]).unwrap();
        let pt = bob.decrypt(&msg).unwrap();
        assert_eq!(pt, vec![round]);

        let msg = bob.encrypt(&[round + 100]).unwrap();
        let pt = alice.decrypt(&msg).unwrap();
        assert_eq!(pt, vec![round + 100]);
    }
}

#[test]
fn double_decrypt_same_message_fails() {
    let (mut alice, mut bob) = make_ratchet_pair();

    let msg = alice.encrypt(b"single use").unwrap();
    let plaintext = bob.decrypt(&msg).expect("first decrypt must succeed");
    assert_eq!(plaintext, b"single use");

    // Second decrypt should fail (message key consumed)
    let err = bob.decrypt(&msg).unwrap_err();
    assert!(matches!(err, konsensus_crypto::double_ratchet::RatchetError::DecryptionFailed(_)));
}

#[test]
fn encrypt_empty_plaintext() {
    let (mut alice, mut bob) = make_ratchet_pair();
    let msg = alice.encrypt(b"").unwrap();
    let pt = bob.decrypt(&msg).unwrap();
    assert!(pt.is_empty());
}

#[test]
fn encrypt_large_plaintext() {
    let (mut alice, mut bob) = make_ratchet_pair();
    let large = vec![0x42; 64 * 1024]; // 64 KB
    let msg = alice.encrypt(&large).unwrap();
    let pt = bob.decrypt(&msg).unwrap();
    assert_eq!(pt.len(), 64 * 1024);
}

#[test]
fn many_sequential_messages_without_response() {
    let (mut alice, mut bob) = make_ratchet_pair();

    // Alice sends 100 messages without Bob responding
    let mut messages = Vec::new();
    for i in 0..100u32 {
        let msg = alice.encrypt(&i.to_be_bytes()).unwrap();
        messages.push(msg);
    }

    // Bob decrypts all in order
    for (i, msg) in messages.iter().enumerate() {
        let pt = bob.decrypt(msg).unwrap();
        assert_eq!(pt, (i as u32).to_be_bytes());
    }
}
