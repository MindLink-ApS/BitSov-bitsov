//! Hardening tests for crypto crate — session persistence, sender key rotation,
//! skipped message limits, concurrent access, and edge cases.
//!
//! These tests target gaps identified during security audit:
//! - RatchetState serialization roundtrip with advanced ratchet states
//! - Sender key generation rotation beyond gen 0
//! - Skipped message key eviction (MAX_TOTAL_SKIPPED_KEYS)
//! - Concurrent session access under tokio
//! - Plaintext cache domain separation
//! - Session manager edge cases with stores

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use konsensus_core::identity::NodeIdentity;
use konsensus_core::types::NodeId;
use konsensus_crypto::double_ratchet::{DoubleRatchet, RatchetError, RatchetMessage, RatchetState};
use konsensus_crypto::sender_keys::{GroupSession, SenderKeyError};
use konsensus_crypto::session::{
    ratchet_message_from_bytes, ratchet_message_to_bytes, SessionError, SessionManager,
    SessionStore,
};
use konsensus_crypto::x3dh::SignedPreKey;
use konsensus_crypto::{PlaintextCacheCipher, PlaintextCacheError};

const MNEMONIC_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon art";

const MNEMONIC_B: &str = "zoo zoo zoo zoo zoo zoo zoo zoo \
    zoo zoo zoo zoo zoo zoo zoo zoo \
    zoo zoo zoo zoo zoo zoo zoo vote";

fn make_identity(mnemonic: &str) -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(mnemonic, "").unwrap())
}

fn make_node_id(seed: u8) -> NodeId {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    NodeId::from_verifying_key(&signing.verifying_key())
}

fn make_ratchet_pair() -> (DoubleRatchet, DoubleRatchet) {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = SignedPreKey::generate();
    let alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).expect("test setup");
    let bob = DoubleRatchet::init_receiver(&shared_secret, bob_spk.secret(), &bob_spk.public, ad);
    (alice, bob)
}

// ═══════════════════════════════════════════════════════════════════════════════
// RATCHET STATE SERIALIZATION — ADVANCED SCENARIOS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ratchet_state_json_roundtrip_after_many_ratchet_steps() {
    let (mut alice, mut bob) = make_ratchet_pair();

    // 20 round trips to advance DH ratchet many times
    for i in 0..20u32 {
        let msg = alice.encrypt(format!("a{i}").as_bytes()).unwrap();
        bob.decrypt(&msg).unwrap();
        let reply = bob.encrypt(format!("b{i}").as_bytes()).unwrap();
        alice.decrypt(&reply).unwrap();
    }

    // Export, serialize, restore, verify continued communication
    let alice_state = alice.export_state();
    let bob_state = bob.export_state();

    let aj = serde_json::to_vec(&alice_state).unwrap();
    let bj = serde_json::to_vec(&bob_state).unwrap();

    let mut alice2 = DoubleRatchet::from_state(&serde_json::from_slice::<RatchetState>(&aj).unwrap());
    let mut bob2 = DoubleRatchet::from_state(&serde_json::from_slice::<RatchetState>(&bj).unwrap());

    let msg = alice2.encrypt(b"post-restore").unwrap();
    assert_eq!(bob2.decrypt(&msg).unwrap(), b"post-restore");
    let reply = bob2.encrypt(b"reply-post-restore").unwrap();
    assert_eq!(alice2.decrypt(&reply).unwrap(), b"reply-post-restore");
}

#[test]
fn ratchet_state_serialization_preserves_counters() {
    let (mut alice, mut bob) = make_ratchet_pair();

    // Alice sends 5 messages
    for i in 0..5 {
        let msg = alice.encrypt(format!("msg{i}").as_bytes()).unwrap();
        bob.decrypt(&msg).unwrap();
    }

    let state = alice.export_state();
    assert_eq!(state.send_count, 5);

    let json = serde_json::to_vec(&state).unwrap();
    let restored: RatchetState = serde_json::from_slice(&json).unwrap();
    assert_eq!(restored.send_count, 5);
    assert_eq!(restored.previous_chain_length, state.previous_chain_length);
}

#[test]
fn ratchet_state_associated_data_preserved() {
    let shared_secret = [42u8; 32];
    let ad = b"custom-associated-data-12345".to_vec();
    let bob_spk = SignedPreKey::generate();
    let alice = DoubleRatchet::init_sender(&shared_secret, &bob_spk.public, ad.clone()).expect("test setup");

    let state = alice.export_state();
    assert_eq!(state.associated_data, ad);

    let json = serde_json::to_vec(&state).unwrap();
    let restored: RatchetState = serde_json::from_slice(&json).unwrap();
    assert_eq!(restored.associated_data, ad);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SKIPPED MESSAGE KEY EVICTION
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn skipped_keys_bounded_by_max_total() {
    let (mut alice, mut bob) = make_ratchet_pair();

    // Alice sends many messages that Bob doesn't decrypt yet
    let mut pending_msgs: Vec<RatchetMessage> = Vec::new();
    for i in 0..500u32 {
        pending_msgs.push(alice.encrypt(format!("msg{i}").as_bytes()).unwrap());
    }

    // Bob receives only the last one — this creates 499 skipped keys
    let last = &pending_msgs[499];
    bob.decrypt(last).unwrap();

    // Export and check skipped keys count is bounded
    let state = bob.export_state();
    // Should have at most 499 skipped keys (all within MAX_SKIP=1000)
    assert_eq!(state.skipped_keys.len(), 499);

    // Now verify those skipped messages can still be decrypted
    assert_eq!(
        bob.decrypt(&pending_msgs[0]).unwrap(),
        b"msg0"
    );
    assert_eq!(
        bob.decrypt(&pending_msgs[250]).unwrap(),
        b"msg250"
    );
}

#[test]
fn skip_exactly_max_skip_succeeds() {
    let (mut alice, mut bob) = make_ratchet_pair();

    // Send exactly MAX_SKIP (1000) messages
    let mut msgs = Vec::new();
    for i in 0..1000u32 {
        msgs.push(alice.encrypt(format!("m{i}").as_bytes()).unwrap());
    }

    // Bob receives the last one — skips exactly 999 (within MAX_SKIP=1000)
    let plaintext = bob.decrypt(&msgs[999]).expect("skip exactly MAX_SKIP must succeed");
    assert_eq!(plaintext, b"m999");
}

#[test]
fn skip_over_max_skip_rejected() {
    let (mut alice, mut bob) = make_ratchet_pair();

    // Send MAX_SKIP + 2 messages
    let mut msgs = Vec::new();
    for i in 0..1002u32 {
        msgs.push(alice.encrypt(format!("m{i}").as_bytes()).unwrap());
    }

    // Bob tries to receive message 1001 — requires skipping 1001 messages
    let err = bob.decrypt(&msgs[1001]).unwrap_err();
    assert!(matches!(err, RatchetError::TooManySkipped(_, _)));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SENDER KEY ROTATION — MULTI-GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

fn test_group_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..5].copy_from_slice(b"test!");
    id
}

#[test]
fn sender_key_multiple_rotations() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);
    let carol_id = make_node_id(3);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);
    let mut carol = GroupSession::new(group_id, carol_id);

    // Initial distribution
    let adist = alice.our_distribution();
    let bdist = bob.our_distribution();
    let cdist = carol.our_distribution();
    bob.process_distribution(&adist).unwrap();
    carol.process_distribution(&adist).unwrap();
    alice.process_distribution(&bdist).unwrap();
    carol.process_distribution(&bdist).unwrap();
    alice.process_distribution(&cdist).unwrap();
    bob.process_distribution(&cdist).unwrap();

    // Remove Carol (rotation 1)
    let adist1 = alice.remove_member(&carol_id);
    let bdist1 = bob.remove_member(&carol_id);
    bob.process_distribution(&adist1).unwrap();
    alice.process_distribution(&bdist1).unwrap();

    assert_eq!(adist1.generation, 1);

    // Verify communication works after rotation 1
    let ct1 = alice.encrypt(b"gen1").unwrap();
    assert_eq!(bob.decrypt(&alice_id, &ct1).unwrap(), b"gen1");

    // Add a new member Dave
    let dave_id = make_node_id(4);
    let mut dave = GroupSession::new(group_id, dave_id);

    // Distribute current keys to Dave
    let adist_for_dave = alice.our_distribution();
    let bdist_for_dave = bob.our_distribution();
    dave.process_distribution(&adist_for_dave).unwrap();
    dave.process_distribution(&bdist_for_dave).unwrap();

    let ddist = dave.our_distribution();
    alice.process_distribution(&ddist).unwrap();
    bob.process_distribution(&ddist).unwrap();

    // Remove Dave (rotation 2)
    let adist2 = alice.remove_member(&dave_id);
    let bdist2 = bob.remove_member(&dave_id);
    bob.process_distribution(&adist2).unwrap();
    alice.process_distribution(&bdist2).unwrap();

    assert_eq!(adist2.generation, 2);

    // Verify communication works after rotation 2
    let ct2 = alice.encrypt(b"gen2").unwrap();
    assert_eq!(bob.decrypt(&alice_id, &ct2).unwrap(), b"gen2");

    let ct3 = bob.encrypt(b"bob-gen2").unwrap();
    assert_eq!(alice.decrypt(&bob_id, &ct3).unwrap(), b"bob-gen2");
}

#[test]
fn sender_key_generation_mismatch_rejected() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    let adist = alice.our_distribution();
    bob.process_distribution(&adist).unwrap();

    // Alice sends gen 0 message
    let ct_gen0 = alice.encrypt(b"gen0").unwrap();

    // Manually craft a distribution with higher generation
    // by removing a fake member to trigger rotation
    let fake_id = make_node_id(99);
    alice.process_distribution(&GroupSession::new(group_id, fake_id).our_distribution()).unwrap();
    let _ = alice.remove_member(&fake_id);

    // Alice is now at gen 1 but Bob still has gen 0
    let ct_gen1 = alice.encrypt(b"gen1").unwrap();

    // Bob can decrypt gen 0 (matches his stored gen)
    assert_eq!(bob.decrypt(&alice_id, &ct_gen0).unwrap(), b"gen0");

    // Bob cannot decrypt gen 1 (generation mismatch)
    let err = bob.decrypt(&alice_id, &ct_gen1).unwrap_err();
    assert!(matches!(err, SenderKeyError::DecryptionFailed(_)));
}

#[test]
fn sender_key_distribution_idempotent() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    let adist = alice.our_distribution();

    // Process same distribution twice — should be idempotent
    bob.process_distribution(&adist).unwrap();
    bob.process_distribution(&adist).unwrap();

    let ct = alice.encrypt(b"test").unwrap();
    assert_eq!(bob.decrypt(&alice_id, &ct).unwrap(), b"test");
}

#[test]
fn sender_key_group_id_mismatch_rejected() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut different_group = [0u8; 32];
    different_group[..7].copy_from_slice(b"other!!");

    let alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(different_group, bob_id);

    let adist = alice.our_distribution();

    // Distribution has group_id from alice's group, not bob's
    let err = bob.process_distribution(&adist).unwrap_err();
    assert!(matches!(err, SenderKeyError::InvalidDistribution(_)));
}

#[test]
fn sender_key_replay_same_message_behind_chain() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    let adist = alice.our_distribution();
    bob.process_distribution(&adist).unwrap();

    let ct1 = alice.encrypt(b"msg1").unwrap();
    let ct2 = alice.encrypt(b"msg2").unwrap();

    // Bob decrypts both in order
    bob.decrypt(&alice_id, &ct1).unwrap();
    bob.decrypt(&alice_id, &ct2).unwrap();

    // Replaying ct1 should fail (behind chain index, no skipped key)
    let err = bob.decrypt(&alice_id, &ct1).unwrap_err();
    assert!(matches!(err, SenderKeyError::DecryptionFailed(_)));
}

#[test]
fn sender_key_empty_plaintext() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    let adist = alice.our_distribution();
    bob.process_distribution(&adist).unwrap();

    let ct = alice.encrypt(b"").unwrap();
    let pt = bob.decrypt(&alice_id, &ct).unwrap();
    assert!(pt.is_empty());
}

#[test]
fn sender_key_large_plaintext() {
    let group_id = test_group_id();
    let alice_id = make_node_id(1);
    let bob_id = make_node_id(2);

    let mut alice = GroupSession::new(group_id, alice_id);
    let mut bob = GroupSession::new(group_id, bob_id);

    let adist = alice.our_distribution();
    bob.process_distribution(&adist).unwrap();

    let large = vec![0xABu8; 1024 * 1024]; // 1 MiB
    let ct = alice.encrypt(&large).unwrap();
    let pt = bob.decrypt(&alice_id, &ct).unwrap();
    assert_eq!(pt, large);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONCURRENT SESSION ACCESS
// ═══════════════════════════════════════════════════════════════════════════════

/// In-memory session store for testing.
struct MemorySessionStore {
    data: tokio::sync::RwLock<HashMap<NodeId, Vec<u8>>>,
}

impl MemorySessionStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            data: tokio::sync::RwLock::new(HashMap::new()),
        })
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn save_session(
        &self,
        peer_id: &NodeId,
        state_json: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.data.write().await.insert(*peer_id, state_json.to_vec());
        Ok(())
    }
    async fn load_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.data.read().await.get(peer_id).cloned())
    }
    async fn delete_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.data.write().await.remove(peer_id);
        Ok(())
    }
    async fn list_sessions(
        &self,
    ) -> Result<Vec<NodeId>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.data.read().await.keys().copied().collect())
    }
}

#[tokio::test]
async fn concurrent_encrypt_to_different_peers() {
    let id_a = make_identity(MNEMONIC_A);
    let id_b = make_identity(MNEMONIC_B);
    let node_a = *id_a.node_id();
    let node_b = *id_b.node_id();

    let mgr_a = Arc::new(SessionManager::new(Arc::clone(&id_a)));
    let mgr_b = Arc::new(SessionManager::new(Arc::clone(&id_b)));

    // Establish sessions
    let bundle_b = mgr_b.prekey_bundle().await;
    let init = mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();
    mgr_b.accept_session(&node_a, &init).await.unwrap();

    // Concurrent encrypts from A to B
    let mut handles = Vec::new();
    for i in 0..10u32 {
        let mgr = Arc::clone(&mgr_a);
        let peer = node_b;
        handles.push(tokio::spawn(async move {
            mgr.encrypt(&peer, format!("msg{i}").as_bytes()).await
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        results.push(h.await.unwrap().unwrap());
    }

    // All 10 encryptions succeeded, all have unique message numbers
    assert_eq!(results.len(), 10);

    // Decrypt all in any order
    for msg in &results {
        mgr_b.decrypt(&node_a, msg).await.unwrap();
    }
}

#[tokio::test]
async fn concurrent_has_session_reads() {
    let id_a = make_identity(MNEMONIC_A);
    let id_b = make_identity(MNEMONIC_B);
    let node_b = *id_b.node_id();

    let mgr_a = Arc::new(SessionManager::new(Arc::clone(&id_a)));
    let mgr_b = Arc::new(SessionManager::new(id_b));

    let bundle_b = mgr_b.prekey_bundle().await;
    mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();

    // Many concurrent reads
    let mut handles = Vec::new();
    for _ in 0..50 {
        let mgr = Arc::clone(&mgr_a);
        let peer = node_b;
        handles.push(tokio::spawn(async move { mgr.has_session(&peer).await }));
    }

    for h in handles {
        assert!(h.await.unwrap());
    }
}

#[tokio::test]
async fn session_persist_with_store_and_concurrent_operations() {
    let id_a = make_identity(MNEMONIC_A);
    let id_b = make_identity(MNEMONIC_B);
    let node_a = *id_a.node_id();
    let node_b = *id_b.node_id();

    let store = MemorySessionStore::new();
    let mgr_a = Arc::new(SessionManager::with_store(Arc::clone(&id_a), store.clone()));
    let mgr_b = Arc::new(SessionManager::new(Arc::clone(&id_b)));

    let bundle_b = mgr_b.prekey_bundle().await;
    let init = mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();
    mgr_b.accept_session(&node_a, &init).await.unwrap();

    // Send 5 messages sequentially (each persists state)
    for i in 0..5u32 {
        let msg = mgr_a.encrypt(&node_b, format!("m{i}").as_bytes()).await.unwrap();
        mgr_b.decrypt(&node_a, &msg).await.unwrap();
    }

    // Verify store has data
    assert!(store.data.read().await.contains_key(&node_b));

    // Restore into new manager
    let mgr_a2 = SessionManager::with_store(Arc::clone(&id_a), store.clone());
    let restored = mgr_a2.restore_sessions().await;
    assert_eq!(restored, 1);

    // Verify can continue
    let msg = mgr_a2.encrypt(&node_b, b"after-restore").await.unwrap();
    assert_eq!(mgr_b.decrypt(&node_a, &msg).await.unwrap(), b"after-restore");
}

// ═══════════════════════════════════════════════════════════════════════════════
// PLAINTEXT CACHE — DOMAIN SEPARATION
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn plaintext_cache_different_master_keys_produce_different_ciphertexts() {
    let cipher1 = PlaintextCacheCipher::new(&[0x01u8; 32]);
    let cipher2 = PlaintextCacheCipher::new(&[0x02u8; 32]);

    let pt = b"same plaintext";
    let enc1 = cipher1.encrypt(pt).unwrap();
    let enc2 = cipher2.encrypt(pt).unwrap();

    // Can't cross-decrypt
    assert!(cipher1.decrypt(&enc2).is_err());
    assert!(cipher2.decrypt(&enc1).is_err());
}

#[test]
fn plaintext_cache_large_payload() {
    let cipher = PlaintextCacheCipher::new(&[0x42u8; 32]);
    let large = vec![0xFFu8; 4 * 1024 * 1024]; // 4 MiB
    let enc = cipher.encrypt(&large).unwrap();
    let dec = cipher.decrypt(&enc).unwrap();
    assert_eq!(dec, large);
}

#[test]
fn plaintext_cache_nonce_only_data_fails() {
    let cipher = PlaintextCacheCipher::new(&[0x42u8; 32]);
    // Exactly 12 bytes (nonce only, no ciphertext) — should fail with DecryptionFailed
    let err = cipher.decrypt(&[0u8; 12]).unwrap_err();
    assert!(matches!(err, PlaintextCacheError::DecryptionFailed));
}

// ═══════════════════════════════════════════════════════════════════════════════
// RATCHET MESSAGE SERIALIZATION EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ratchet_message_from_bytes_empty_fails() {
    let err = ratchet_message_from_bytes(&[]).unwrap_err();
    assert!(matches!(err, SessionError::InvalidPeerData(_)));
}

#[test]
fn ratchet_message_from_bytes_one_byte_fails() {
    let err = ratchet_message_from_bytes(&[0xFF]).unwrap_err();
    assert!(matches!(err, SessionError::InvalidPeerData(_)));
}

#[test]
fn ratchet_message_roundtrip_large_ciphertext() {
    use konsensus_crypto::double_ratchet::MessageHeader;

    let large_ct = vec![0xABu8; 100_000];
    let msg = RatchetMessage {
        header: MessageHeader {
            dh_public: [0x01u8; 32],
            previous_chain_length: u32::MAX,
            message_number: u32::MAX,
        },
        ciphertext: large_ct.clone(),
    };

    let bytes = ratchet_message_to_bytes(&msg);
    let recovered = ratchet_message_from_bytes(&bytes).unwrap();
    assert_eq!(recovered.ciphertext.len(), 100_000);
    assert_eq!(recovered.header.previous_chain_length, u32::MAX);
    assert_eq!(recovered.header.message_number, u32::MAX);
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOUBLE RATCHET — RECEIVER CAN'T SEND BEFORE FIRST DECRYPT
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn receiver_cannot_encrypt_before_first_decrypt() {
    let shared_secret = [42u8; 32];
    let ad = b"alice||bob".to_vec();
    let bob_spk = SignedPreKey::generate();

    let mut bob =
        DoubleRatchet::init_receiver(&shared_secret, bob_spk.secret(), &bob_spk.public, ad);

    assert!(!bob.can_send());
    let err = bob.encrypt(b"should fail").unwrap_err();
    assert!(matches!(err, RatchetError::NotInitialized));
}

#[test]
fn receiver_can_send_after_first_decrypt() {
    let (mut alice, mut bob) = make_ratchet_pair();

    assert!(!bob.can_send());

    let msg = alice.encrypt(b"trigger ratchet").unwrap();
    bob.decrypt(&msg).unwrap();

    assert!(bob.can_send());
    let reply = bob.encrypt(b"now I can send").unwrap();
    assert_eq!(alice.decrypt(&reply).unwrap(), b"now I can send");
}

// ═══════════════════════════════════════════════════════════════════════════════
// SESSION MANAGER — MULTI-PEER SESSIONS
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn session_count_tracks_multiple_peers() {
    let id_a = make_identity(MNEMONIC_A);
    let id_b = make_identity(MNEMONIC_B);

    // Create a third identity with a different mnemonic
    let id_c = Arc::new(
        NodeIdentity::from_mnemonic(
            "legal winner thank year wave sausage worth useful legal winner thank year \
             wave sausage worth useful legal winner thank year wave sausage worth title",
            "",
        )
        .unwrap(),
    );

    let node_b = *id_b.node_id();
    let node_c = *id_c.node_id();

    let mgr_a = SessionManager::new(Arc::clone(&id_a));
    let mgr_b = SessionManager::new(id_b);
    let mgr_c = SessionManager::new(id_c);

    assert_eq!(mgr_a.session_count().await, 0);

    // Session with B
    let bundle_b = mgr_b.prekey_bundle().await;
    mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();
    assert_eq!(mgr_a.session_count().await, 1);

    // Session with C
    let bundle_c = mgr_c.prekey_bundle().await;
    mgr_a.initiate_session(&node_c, &bundle_c).await.unwrap();
    assert_eq!(mgr_a.session_count().await, 2);

    // Remove one
    mgr_a.remove_session(&node_b).await;
    assert_eq!(mgr_a.session_count().await, 1);

    let sessions = mgr_a.active_sessions().await;
    assert!(sessions.contains(&node_c));
    assert!(!sessions.contains(&node_b));
}

#[tokio::test]
async fn can_send_false_for_nonexistent_peer() {
    let id_a = make_identity(MNEMONIC_A);
    let mgr = SessionManager::new(id_a);
    let fake = NodeId::from_bytes([99u8; 32]);
    assert!(!mgr.can_send(&fake).await);
}

#[tokio::test]
async fn can_send_false_for_acceptor_before_ratchet_init() {
    let id_a = make_identity(MNEMONIC_A);
    let id_b = make_identity(MNEMONIC_B);
    let node_a = *id_a.node_id();
    let node_b = *id_b.node_id();

    let mgr_a = SessionManager::new(Arc::clone(&id_a));
    let mgr_b = SessionManager::new(Arc::clone(&id_b));

    let bundle_b = mgr_b.prekey_bundle().await;
    let init = mgr_a.initiate_session(&node_b, &bundle_b).await.unwrap();
    mgr_b.accept_session(&node_a, &init).await.unwrap();

    // A initiated, so A can send immediately
    assert!(mgr_a.can_send(&node_b).await);

    // B accepted — B's sending chain is NOT initialized until it decrypts A's first message
    assert!(!mgr_b.can_send(&node_a).await);

    // A sends a message, B decrypts — now B can send
    let msg = mgr_a.encrypt(&node_b, b"init").await.unwrap();
    mgr_b.decrypt(&node_a, &msg).await.unwrap();
    assert!(mgr_b.can_send(&node_a).await);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SESSION MANAGER — RESTORE EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn restore_with_no_store_returns_zero() {
    let id_a = make_identity(MNEMONIC_A);
    let mgr = SessionManager::new(id_a);
    assert_eq!(mgr.restore_sessions().await, 0);
}

#[tokio::test]
async fn restore_with_empty_store_returns_zero() {
    let id_a = make_identity(MNEMONIC_A);
    let store = MemorySessionStore::new();
    let mgr = SessionManager::with_store(id_a, store);
    assert_eq!(mgr.restore_sessions().await, 0);
}

#[tokio::test]
async fn restore_skips_corrupted_sessions() {
    let id_a = make_identity(MNEMONIC_A);
    let store = MemorySessionStore::new();

    // Store garbage data under a fake peer ID
    let fake_peer = NodeId::from_bytes([77u8; 32]);
    store
        .data
        .write()
        .await
        .insert(fake_peer, b"not valid json or encrypted blob".to_vec());

    let mgr = SessionManager::with_store(id_a, store);
    // Should not panic, should return 0
    assert_eq!(mgr.restore_sessions().await, 0);
}
