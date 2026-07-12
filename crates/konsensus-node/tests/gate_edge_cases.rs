//! Integration tests for payment gate edge cases.
//!
//! Tests attack scenarios against the full BitSov message pipeline:
//! - Tampered signatures
//! - Nonce replay attacks
//! - Tampered ciphertext (invalidates envelope ID)
//! - Invalid payment proofs (wrong preimage)
//! - Future-timestamped messages
//! - Expired messages
//! - Zero-payment messages
//! - Non-whitelisted senders
//!
//! Each test verifies the specific `GateRejection` variant returned.

use std::collections::HashSet;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::gate::{GateConfig, GateRejection, PaymentGate};
use konsensus_core::identity::NodeIdentity;
use konsensus_core::types::{NodeId, Nonce, PaymentProof, Recipient, Signature};
use konsensus_pricing::StaticPricingConfig;

const MNEMONIC_ALICE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEMONIC_BOB: &str =
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
const MNEMONIC_CAROL: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn make_identity(mnemonic: &str) -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(mnemonic, "").expect("valid mnemonic"))
}

/// Build and sign a valid UKM envelope with correct payment proof.
fn make_valid_envelope(
    identity: &NodeIdentity,
    recipient: NodeId,
    ciphertext: Vec<u8>,
    amount_msat: u64,
) -> UkmEnvelope {
    let preimage = rand::random::<[u8; 32]>();
    let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(payment_hash, preimage, amount_msat);

    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        0, // KIND_CHAT
        *identity.node_id(),
        Recipient::Node(recipient),
        ciphertext,
        proof,
    )
    .timestamp(chrono::Utc::now().timestamp_millis() as u64)
    .build();

    let sig = identity.sign(&envelope.signable_bytes());
    envelope.signature = Signature::from_ed25519(&sig);
    envelope
}

fn default_pricing() -> konsensus_pricing::StaticPricingEngine {
    konsensus_pricing::StaticPricingEngine::new(StaticPricingConfig::default())
}

// ═══════════════════════════════════════════════════════════════════════════════
// NONCE REPLAY PROTECTION
// ═══════════════════════════════════════════════════════════════════════════════

/// In-memory nonce store for testing.
struct InMemoryNonceStore {
    seen: tokio::sync::Mutex<HashSet<Vec<u8>>>,
    seen_payment_hashes: tokio::sync::Mutex<HashSet<[u8; 32]>>,
}

impl InMemoryNonceStore {
    fn new() -> Self {
        Self {
            seen: tokio::sync::Mutex::new(HashSet::new()),
            seen_payment_hashes: tokio::sync::Mutex::new(HashSet::new()),
        }
    }
}

#[async_trait::async_trait]
impl konsensus_core::gate::NonceStore for InMemoryNonceStore {
    async fn check_and_store(
        &self,
        nonce: &Nonce,
        _sender: &NodeId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let mut seen = self.seen.lock().await;
        Ok(seen.insert(nonce.as_bytes().to_vec()))
    }

    async fn check_and_store_payment_hash(
        &self,
        payment_hash: &[u8; 32],
        _sender: &NodeId,
        _message_id: &konsensus_core::MessageId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let mut seen = self.seen_payment_hashes.lock().await;
        Ok(seen.insert(*payment_hash))
    }
}

#[tokio::test]
async fn replay_attack_rejected_on_second_submission() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let bob_id = *id_bob.node_id();
    let alice_id = *id_alice.node_id();

    let envelope = make_valid_envelope(&id_alice, bob_id, b"hello".to_vec(), 100);
    let gate = PaymentGate::new();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = default_pricing();
    let whitelist: HashSet<NodeId> = [alice_id].into_iter().collect();

    // First submission passes
    gate.verify(
        &envelope,
        &nonce_store,
        &pricing,
        Some(&whitelist),
        None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
        None,
    )
    .await
    .expect("first submission should pass");

    // Second submission (replay) must be rejected
    let result = gate
        .verify(
            &envelope,
            &nonce_store,
            &pricing,
            Some(&whitelist),
            None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
            None,
        )
        .await;

    assert!(
        matches!(result, Err(GateRejection::ReplayDetected)),
        "replay should be rejected with ReplayDetected, got: {result:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// TAMPERED SIGNATURE
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tampered_signature_rejected() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let bob_id = *id_bob.node_id();
    let alice_id = *id_alice.node_id();

    let mut envelope = make_valid_envelope(&id_alice, bob_id, b"hello".to_vec(), 100);

    // Tamper: sign with Bob's key instead of Alice's (sender mismatch)
    let wrong_sig = id_bob.sign(&envelope.signable_bytes());
    envelope.signature = Signature::from_ed25519(&wrong_sig);

    let gate = PaymentGate::new();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = default_pricing();
    let whitelist: HashSet<NodeId> = [alice_id].into_iter().collect();

    let result = gate
        .verify(
            &envelope,
            &nonce_store,
            &pricing,
            Some(&whitelist),
            None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
            None,
        )
        .await;

    assert!(
        matches!(result, Err(GateRejection::InvalidSignature(_))),
        "tampered signature should be rejected with InvalidSignature, got: {result:?}"
    );
}

#[tokio::test]
async fn zeroed_signature_rejected() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let bob_id = *id_bob.node_id();
    let alice_id = *id_alice.node_id();

    let mut envelope = make_valid_envelope(&id_alice, bob_id, b"hello".to_vec(), 100);

    // Tamper: zero out the signature
    envelope.signature = Signature::from_ed25519(&ed25519_dalek::Signature::from_bytes(
        &[0u8; 64],
    ));

    let gate = PaymentGate::new();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = default_pricing();
    let whitelist: HashSet<NodeId> = [alice_id].into_iter().collect();

    let result = gate
        .verify(
            &envelope,
            &nonce_store,
            &pricing,
            Some(&whitelist),
            None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
            None,
        )
        .await;

    assert!(
        matches!(result, Err(GateRejection::InvalidSignature(_))),
        "zeroed signature should be rejected, got: {result:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// TAMPERED CIPHERTEXT (invalidates envelope ID)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tampered_ciphertext_rejected() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let bob_id = *id_bob.node_id();
    let alice_id = *id_alice.node_id();

    let mut envelope = make_valid_envelope(&id_alice, bob_id, b"hello".to_vec(), 100);

    // Tamper: modify ciphertext after signing (ID won't match)
    envelope.ciphertext = b"tampered data".to_vec();

    let gate = PaymentGate::new();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = default_pricing();
    let whitelist: HashSet<NodeId> = [alice_id].into_iter().collect();

    let result = gate
        .verify(
            &envelope,
            &nonce_store,
            &pricing,
            Some(&whitelist),
            None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
            None,
        )
        .await;

    // Ciphertext change invalidates the envelope ID (blake3 hash mismatch)
    assert!(
        matches!(result, Err(GateRejection::InvalidEnvelope(_))),
        "tampered ciphertext should be rejected with InvalidEnvelope, got: {result:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// INVALID PAYMENT PROOF
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn wrong_preimage_rejected() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let bob_id = *id_bob.node_id();
    let alice_id = *id_alice.node_id();

    // Build envelope with mismatched preimage and payment_hash
    let real_preimage = rand::random::<[u8; 32]>();
    let real_hash: [u8; 32] = Sha256::digest(real_preimage).into();
    let fake_preimage = rand::random::<[u8; 32]>(); // Different preimage
    let proof = PaymentProof::new(real_hash, fake_preimage, 100);

    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        0,
        *id_alice.node_id(),
        Recipient::Node(bob_id),
        b"hello".to_vec(),
        proof,
    )
    .timestamp(chrono::Utc::now().timestamp_millis() as u64)
    .build();

    let sig = id_alice.sign(&envelope.signable_bytes());
    envelope.signature = Signature::from_ed25519(&sig);

    let gate = PaymentGate::new();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = default_pricing();
    let whitelist: HashSet<NodeId> = [alice_id].into_iter().collect();

    let result = gate
        .verify(
            &envelope,
            &nonce_store,
            &pricing,
            Some(&whitelist),
            None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
            None,
        )
        .await;

    assert!(
        matches!(result, Err(GateRejection::InvalidEnvelope(_))),
        "wrong preimage should be rejected with InvalidEnvelope, got: {result:?}"
    );
}

#[tokio::test]
async fn zero_payment_rejected() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let bob_id = *id_bob.node_id();
    let alice_id = *id_alice.node_id();

    // Build envelope with 0 msat payment (gate requires > 0 for KIND_CHAT)
    let envelope = make_valid_envelope(&id_alice, bob_id, b"hello".to_vec(), 0);

    let gate = PaymentGate::new();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = default_pricing();
    let whitelist: HashSet<NodeId> = [alice_id].into_iter().collect();

    let result = gate
        .verify(
            &envelope,
            &nonce_store,
            &pricing,
            Some(&whitelist),
            None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
            None,
        )
        .await;

    assert!(
        matches!(result, Err(GateRejection::InsufficientPayment { .. })),
        "zero payment should be rejected with InsufficientPayment, got: {result:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// TIMESTAMP ATTACKS
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn far_future_timestamp_rejected() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let bob_id = *id_bob.node_id();
    let alice_id = *id_alice.node_id();

    let preimage = rand::random::<[u8; 32]>();
    let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(payment_hash, preimage, 100);

    // Timestamp 1 hour in the future (gate allows max 5 minutes)
    let future_ts = (chrono::Utc::now().timestamp_millis() as u64) + 3_600_000;

    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        0,
        *id_alice.node_id(),
        Recipient::Node(bob_id),
        b"hello".to_vec(),
        proof,
    )
    .timestamp(future_ts)
    .build();

    let sig = id_alice.sign(&envelope.signable_bytes());
    envelope.signature = Signature::from_ed25519(&sig);

    let gate = PaymentGate::new();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = default_pricing();
    let whitelist: HashSet<NodeId> = [alice_id].into_iter().collect();

    let result = gate
        .verify(
            &envelope,
            &nonce_store,
            &pricing,
            Some(&whitelist),
            None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
            None,
        )
        .await;

    assert!(
        matches!(result, Err(GateRejection::MessageFromFuture { .. })),
        "far-future timestamp should be rejected with MessageFromFuture, got: {result:?}"
    );
}

#[tokio::test]
async fn expired_message_rejected() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let bob_id = *id_bob.node_id();
    let alice_id = *id_alice.node_id();

    let preimage = rand::random::<[u8; 32]>();
    let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(payment_hash, preimage, 100);

    // Timestamp 1 hour in the past (gate allows max 5 minutes)
    let past_ts = (chrono::Utc::now().timestamp_millis() as u64) - 3_600_000;

    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        0,
        *id_alice.node_id(),
        Recipient::Node(bob_id),
        b"hello".to_vec(),
        proof,
    )
    .timestamp(past_ts)
    .build();

    let sig = id_alice.sign(&envelope.signable_bytes());
    envelope.signature = Signature::from_ed25519(&sig);

    let gate = PaymentGate::new();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = default_pricing();
    let whitelist: HashSet<NodeId> = [alice_id].into_iter().collect();

    let result = gate
        .verify(
            &envelope,
            &nonce_store,
            &pricing,
            Some(&whitelist),
            None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
            None,
        )
        .await;

    assert!(
        matches!(result, Err(GateRejection::MessageTooOld { .. })),
        "expired message should be rejected with MessageTooOld, got: {result:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WHITELIST ENFORCEMENT
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn non_whitelisted_sender_rejected() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let id_carol = make_identity(MNEMONIC_CAROL);
    let bob_id = *id_bob.node_id();
    let carol_id = *id_carol.node_id();

    // Alice sends to Bob, but Bob's whitelist only has Carol
    let envelope = make_valid_envelope(&id_alice, bob_id, b"hello".to_vec(), 100);

    let gate = PaymentGate::new();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = default_pricing();
    let whitelist: HashSet<NodeId> = [carol_id].into_iter().collect(); // No Alice

    let result = gate
        .verify(
            &envelope,
            &nonce_store,
            &pricing,
            Some(&whitelist),
            None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
            None,
        )
        .await;

    assert!(
        matches!(result, Err(GateRejection::NotWhitelisted(_))),
        "non-whitelisted sender should be rejected with NotWhitelisted, got: {result:?}"
    );
}

#[tokio::test]
async fn empty_whitelist_rejects_all() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let bob_id = *id_bob.node_id();

    let envelope = make_valid_envelope(&id_alice, bob_id, b"hello".to_vec(), 100);

    let gate = PaymentGate::new();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = default_pricing();
    let whitelist: HashSet<NodeId> = HashSet::new(); // Empty = nobody allowed

    let result = gate
        .verify(
            &envelope,
            &nonce_store,
            &pricing,
            Some(&whitelist),
            None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
            None,
        )
        .await;

    assert!(
        matches!(result, Err(GateRejection::NotWhitelisted(_))),
        "empty whitelist should reject all senders, got: {result:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// REALTIME SIGNALING
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn realtime_signaling_kind_uses_payment_gate() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let bob_id = *id_bob.node_id();
    let alice_id = *id_alice.node_id();

    let preimage = rand::random::<[u8; 32]>();
    let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(payment_hash, preimage, 100);

    // Kind 400 = realtime signaling and must be priceable, not a free lane.
    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        400,
        *id_alice.node_id(),
        Recipient::Node(bob_id),
        b"signal".to_vec(),
        proof,
    )
    .timestamp(chrono::Utc::now().timestamp_millis() as u64)
    .build();

    let sig = id_alice.sign(&envelope.signable_bytes());
    envelope.signature = Signature::from_ed25519(&sig);

    let gate = PaymentGate::new();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = default_pricing();
    let whitelist: HashSet<NodeId> = [alice_id].into_iter().collect();

    let result = gate
        .verify(
            &envelope,
            &nonce_store,
            &pricing,
            Some(&whitelist),
            None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
            None,
        )
        .await;

    assert!(
        result.is_ok(),
        "paid realtime signaling kind should pass the payment gate, got: {result:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// TIGHT GATE CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tight_max_age_rejects_slightly_old_message() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let bob_id = *id_bob.node_id();
    let alice_id = *id_alice.node_id();

    let preimage = rand::random::<[u8; 32]>();
    let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(payment_hash, preimage, 100);

    // Timestamp 10 seconds in the past
    let past_ts = (chrono::Utc::now().timestamp_millis() as u64) - 10_000;

    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        0,
        *id_alice.node_id(),
        Recipient::Node(bob_id),
        b"hello".to_vec(),
        proof,
    )
    .timestamp(past_ts)
    .build();

    let sig = id_alice.sign(&envelope.signable_bytes());
    envelope.signature = Signature::from_ed25519(&sig);

    // Gate with 5-second max age (tighter than default)
    let config = GateConfig {
        max_message_age_ms: 5_000,
        max_future_ms: 5_000,
        verify_lightning_settlement: false,
        min_admission_cost_msat: 0,
    };
    let gate = PaymentGate::with_config(config);
    let nonce_store = InMemoryNonceStore::new();
    let pricing = default_pricing();
    let whitelist: HashSet<NodeId> = [alice_id].into_iter().collect();

    let result = gate
        .verify(
            &envelope,
            &nonce_store,
            &pricing,
            Some(&whitelist),
            None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
            None,
        )
        .await;

    assert!(
        matches!(result, Err(GateRejection::MessageTooOld { .. })),
        "10s old message with 5s max age should be rejected, got: {result:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// VALID ENVELOPE BASELINE (positive test)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn valid_envelope_passes_all_checks() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let bob_id = *id_bob.node_id();
    let alice_id = *id_alice.node_id();

    let envelope = make_valid_envelope(&id_alice, bob_id, b"hello".to_vec(), 100);

    let gate = PaymentGate::new();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = default_pricing();
    let whitelist: HashSet<NodeId> = [alice_id].into_iter().collect();

    gate.verify(
        &envelope,
        &nonce_store,
        &pricing,
        Some(&whitelist),
        None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
        None,
    )
    .await
    .expect("valid envelope should pass all gate checks");
}

#[tokio::test]
async fn valid_envelope_with_no_whitelist_passes() {
    let id_alice = make_identity(MNEMONIC_ALICE);
    let id_bob = make_identity(MNEMONIC_BOB);
    let bob_id = *id_bob.node_id();

    let envelope = make_valid_envelope(&id_alice, bob_id, b"hello".to_vec(), 100);

    let gate = PaymentGate::new();
    let nonce_store = InMemoryNonceStore::new();
    let pricing = default_pricing();

    // No whitelist = whitelist check skipped
    gate.verify(
        &envelope,
        &nonce_store,
        &pricing,
        None,
        None::<&dyn konsensus_core::traits::lightning::LightningProvider>, 0.0,
        None,
    )
    .await
    .expect("envelope without whitelist enforcement should pass");
}
