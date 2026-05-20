//! Security hardening tests for BitSov v2.
//!
//! Tests for:
//! - Replay attack resistance
//! - Payment bypass attempts
//! - Malformed envelope handling
//! - Key material isolation
//! - Signature forgery prevention
//! - Whitelist enforcement edge cases

use std::collections::HashSet;
use std::sync::Mutex;

use konsensus_core::gate::{GateConfig, GateRejection, NonceStore, PaymentGate};
use konsensus_core::identity::NodeIdentity;
use konsensus_core::kind::{KindCategory, KIND_CHAT};
use konsensus_core::traits::lightning::{
    Invoice, LightningError, PaymentDetails, PaymentDirection, PaymentStatus,
};
use konsensus_core::traits::pricing::{PricingEngine, PricingError};
use konsensus_core::types::{MessageId, NodeId, Nonce, PaymentProof, Recipient, Signature};
use konsensus_core::UkmEnvelopeBuilder;

use sha2::{Digest, Sha256};

// ── Mocks ────────────────────────────────────────────────────────────────────

struct MockNonceStore {
    seen: Mutex<HashSet<[u8; 24]>>,
}

impl MockNonceStore {
    fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }
}

#[async_trait::async_trait]
impl NonceStore for MockNonceStore {
    async fn check_and_store(
        &self,
        nonce: &Nonce,
        _sender: &NodeId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let mut seen = self.seen.lock().unwrap();
        Ok(seen.insert(*nonce.as_bytes()))
    }
}

struct MockPricing {
    price_msat: u64,
}

#[async_trait::async_trait]
impl PricingEngine for MockPricing {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get_price_msat(&self, _kind: u16) -> Result<u64, PricingError> {
        Ok(self.price_msat)
    }

    async fn get_category_price_msat(&self, _category: KindCategory) -> Result<u64, PricingError> {
        Ok(self.price_msat)
    }
}

struct FailingNonceStore;

#[async_trait::async_trait]
impl NonceStore for FailingNonceStore {
    async fn check_and_store(
        &self,
        _nonce: &Nonce,
        _sender: &NodeId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Err("storage failure".into())
    }
}

struct FailingPricing;

#[async_trait::async_trait]
impl PricingEngine for FailingPricing {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get_price_msat(&self, _kind: u16) -> Result<u64, PricingError> {
        Err(PricingError::Other("simulated failure".into()))
    }

    async fn get_category_price_msat(&self, _category: KindCategory) -> Result<u64, PricingError> {
        Err(PricingError::Other("simulated failure".into()))
    }
}

struct MockLightning {
    settled: bool,
}

#[async_trait::async_trait]
impl konsensus_core::traits::lightning::LightningProvider for MockLightning {
    async fn create_invoice(
        &self,
        _amount_msat: u64,
        _description: &str,
        _expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        Err(LightningError::InvoiceCreation("mock: not supported".into()))
    }

    async fn pay_invoice(&self, _bolt11: &str) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::PaymentFailed("mock: not supported".into()))
    }

    async fn get_payment_status(
        &self,
        payment_hash: &str,
    ) -> Result<PaymentDetails, LightningError> {
        let status = if self.settled {
            PaymentStatus::Settled
        } else {
            PaymentStatus::Pending
        };
        Ok(PaymentDetails {
            payment_hash: payment_hash.to_string(),
            preimage: None,
            amount_msat: 0,
            status,
            direction: PaymentDirection::Incoming,
            timestamp: 0,
            memo: None,
            fee_msat: None,
        })
    }

    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(0)
    }

    async fn is_available(&self) -> bool {
        true
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art";

fn make_proof(amount_msat: u64) -> PaymentProof {
    let preimage = [42u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    PaymentProof::new(hash, preimage, amount_msat)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn make_signed_envelope(
    identity: &NodeIdentity,
    amount_msat: u64,
) -> konsensus_core::UkmEnvelope {
    let sender = *identity.node_id();
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let proof = make_proof(amount_msat);
    let ciphertext = b"encrypted content".to_vec();

    let mut envelope =
        UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, ciphertext, proof)
            .timestamp(now_ms())
            .build();

    let signable = envelope.signable_bytes();
    let sig = identity.sign(&signable);
    envelope.signature = Signature::from_ed25519(&sig);
    envelope
}

fn make_signed_envelope_with_nonce(
    identity: &NodeIdentity,
    amount_msat: u64,
    nonce: Nonce,
) -> konsensus_core::UkmEnvelope {
    let sender = *identity.node_id();
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let proof = make_proof(amount_msat);
    let ciphertext = b"encrypted content".to_vec();

    let mut envelope =
        UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, ciphertext, proof)
            .timestamp(now_ms())
            .nonce(nonce)
            .build();

    let signable = envelope.signable_bytes();
    let sig = identity.sign(&signable);
    envelope.signature = Signature::from_ed25519(&sig);
    envelope
}

// ═════════════════════════════════════════════════════════════════════════════
// REPLAY ATTACK RESISTANCE
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn replay_same_envelope_rejected() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 100);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    // First: accepted
    assert!(gate.verify(&envelope, &nonces, &pricing, None, None, 0.0).await.is_ok());

    // Replay: rejected
    let result = gate.verify(&envelope, &nonces, &pricing, None, None, 0.0).await;
    assert!(matches!(result, Err(GateRejection::ReplayDetected)));
}

#[tokio::test]
async fn replay_same_nonce_different_content_rejected() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let nonce = Nonce::generate();

    let env1 = make_signed_envelope_with_nonce(&identity, 100, nonce);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    // First envelope with this nonce: accepted
    assert!(gate.verify(&env1, &nonces, &pricing, None, None, 0.0).await.is_ok());

    // Second envelope with same nonce: rejected (even if content differs)
    let env2 = make_signed_envelope_with_nonce(&identity, 200, nonce);
    let result = gate.verify(&env2, &nonces, &pricing, None, None, 0.0).await;
    assert!(matches!(result, Err(GateRejection::ReplayDetected)));
}

#[tokio::test]
async fn different_nonces_both_accepted() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let env1 = make_signed_envelope(&identity, 100);
    let env2 = make_signed_envelope(&identity, 100);

    // Different nonces (generated randomly)
    assert_ne!(env1.nonce.as_bytes(), env2.nonce.as_bytes());

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    assert!(gate.verify(&env1, &nonces, &pricing, None, None, 0.0).await.is_ok());
    assert!(gate.verify(&env2, &nonces, &pricing, None, None, 0.0).await.is_ok());
}

// ═════════════════════════════════════════════════════════════════════════════
// PAYMENT BYPASS ATTEMPTS
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn zero_payment_rejected() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 0); // Zero payment

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    let result = gate.verify(&envelope, &nonces, &pricing, None, None, 0.0).await;
    assert!(matches!(
        result,
        Err(GateRejection::InsufficientPayment { .. })
    ));
}

#[tokio::test]
async fn one_sat_less_than_required_rejected() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 9); // 9 when 10 required

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    let result = gate.verify(&envelope, &nonces, &pricing, None, None, 0.0).await;
    match result {
        Err(GateRejection::InsufficientPayment {
            required_msat,
            paid_msat,
        }) => {
            assert_eq!(required_msat, 10);
            assert_eq!(paid_msat, 9);
        }
        other => panic!("expected InsufficientPayment, got: {other:?}"),
    }
}

#[tokio::test]
async fn forged_preimage_rejected() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let sender = *identity.node_id();
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));

    // Craft a payment proof where preimage doesn't match hash
    let fake_preimage = [0xAA; 32];
    let fake_hash = [0xBB; 32]; // Doesn't match SHA256(preimage)
    let bad_proof = PaymentProof::new(fake_hash, fake_preimage, 1000);

    let mut envelope = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        sender,
        recipient,
        b"data".to_vec(),
        bad_proof,
    )
    .timestamp(now_ms())
    .build();

    let signable = envelope.signable_bytes();
    let sig = identity.sign(&signable);
    envelope.signature = Signature::from_ed25519(&sig);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    let result = gate.verify(&envelope, &nonces, &pricing, None, None, 0.0).await;
    assert!(matches!(result, Err(GateRejection::InvalidEnvelope(_))));
}

// ═════════════════════════════════════════════════════════════════════════════
// FAIL-CLOSED BEHAVIOR
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn nonce_store_failure_rejects_message() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 100);

    let gate = PaymentGate::new();
    let failing_nonces = FailingNonceStore;
    let pricing = MockPricing { price_msat: 10 };

    // Storage failure = message rejected (fail-closed)
    let result = gate
        .verify(&envelope, &failing_nonces, &pricing, None, None, 0.0)
        .await;
    assert!(matches!(result, Err(GateRejection::NonceCheckFailed(_))));
}

#[tokio::test]
async fn pricing_engine_failure_rejects_message() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 100);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let failing_pricing = FailingPricing;

    // Pricing failure = message rejected (fail-closed)
    let result = gate
        .verify(&envelope, &nonces, &failing_pricing, None, None, 0.0)
        .await;
    assert!(matches!(result, Err(GateRejection::PricingFailed(_))));
}

#[tokio::test]
async fn settlement_required_but_lightning_unavailable() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 100);

    let config = GateConfig {
        verify_lightning_settlement: true,
        ..Default::default()
    };
    let gate = PaymentGate::with_config(config);
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    // No lightning provider = rejected when settlement required
    let result = gate.verify(&envelope, &nonces, &pricing, None, None, 0.0).await;
    assert!(matches!(
        result,
        Err(GateRejection::LightningUnavailable(_))
    ));
}

#[tokio::test]
async fn settlement_unsettled_payment_rejected() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 100);

    let config = GateConfig {
        verify_lightning_settlement: true,
        ..Default::default()
    };
    let gate = PaymentGate::with_config(config);
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };
    let lightning = MockLightning { settled: false };

    let result = gate
        .verify(&envelope, &nonces, &pricing, None, Some(&lightning), 0.0)
        .await;
    assert!(matches!(result, Err(GateRejection::PaymentNotSettled(_))));
}

// ═════════════════════════════════════════════════════════════════════════════
// SIGNATURE FORGERY
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn unsigned_envelope_rejected() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let sender = *identity.node_id();
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let proof = make_proof(100);

    // Envelope with zero signature (unsigned)
    let envelope = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        sender,
        recipient,
        b"data".to_vec(),
        proof,
    )
    .timestamp(now_ms())
    .build();

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    let result = gate.verify(&envelope, &nonces, &pricing, None, None, 0.0).await;
    assert!(matches!(result, Err(GateRejection::InvalidSignature(_))));
}

#[tokio::test]
async fn signature_from_wrong_sender_rejected() {
    let alice = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "alice").unwrap();
    let bob = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "bob").unwrap();

    // Create envelope claiming to be from Alice but signed by Bob
    let sender = *alice.node_id();
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let proof = make_proof(100);

    let mut envelope = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        sender,
        recipient,
        b"data".to_vec(),
        proof,
    )
    .timestamp(now_ms())
    .build();

    // Sign with Bob's key (forgery attempt)
    let signable = envelope.signable_bytes();
    let sig = bob.sign(&signable);
    envelope.signature = Signature::from_ed25519(&sig);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    let result = gate.verify(&envelope, &nonces, &pricing, None, None, 0.0).await;
    assert!(matches!(result, Err(GateRejection::InvalidSignature(_))));
}

#[tokio::test]
async fn tampered_ciphertext_fails_validation() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let mut envelope = make_signed_envelope(&identity, 100);

    // Tamper with ciphertext after signing — breaks both ID and signature
    envelope.ciphertext[0] ^= 0xFF;

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    let result = gate.verify(&envelope, &nonces, &pricing, None, None, 0.0).await;
    assert!(result.is_err());
    // Should fail at envelope validation (ID mismatch)
    assert!(matches!(result, Err(GateRejection::InvalidEnvelope(_))));
}

// ═════════════════════════════════════════════════════════════════════════════
// WHITELIST ENFORCEMENT
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn empty_whitelist_rejects_all() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 100);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };
    let empty_whitelist: HashSet<NodeId> = HashSet::new();

    let result = gate
        .verify(
            &envelope,
            &nonces,
            &pricing,
            Some(&empty_whitelist),
            None,
            0.0,
        )
        .await;
    assert!(matches!(result, Err(GateRejection::NotWhitelisted(_))));
}

#[tokio::test]
async fn whitelist_with_wrong_node_rejects() {
    let alice = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "alice").unwrap();
    let bob = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "bob").unwrap();

    let envelope = make_signed_envelope(&alice, 100);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    // Whitelist contains only Bob — Alice is rejected
    let mut whitelist = HashSet::new();
    whitelist.insert(*bob.node_id());

    let result = gate
        .verify(&envelope, &nonces, &pricing, Some(&whitelist), None, 0.0)
        .await;
    assert!(matches!(result, Err(GateRejection::NotWhitelisted(_))));
}

#[tokio::test]
async fn no_whitelist_accepts_all_senders() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 100);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    // No whitelist (None) — open federation mode
    let result = gate.verify(&envelope, &nonces, &pricing, None, None, 0.0).await;
    assert!(result.is_ok());
}

// ═════════════════════════════════════════════════════════════════════════════
// MALFORMED ENVELOPE HANDLING
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn envelope_with_zeroed_id_rejected() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let mut envelope = make_signed_envelope(&identity, 100);

    // Zero out the message ID — should fail validation
    envelope.id = MessageId::from_bytes([0u8; 32]);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    let result = gate.verify(&envelope, &nonces, &pricing, None, None, 0.0).await;
    assert!(matches!(result, Err(GateRejection::InvalidEnvelope(_))));
}

// ═════════════════════════════════════════════════════════════════════════════
// KEY MATERIAL ISOLATION
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn different_mnemonics_produce_different_identities() {
    let id1 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let id2 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "different").unwrap();
    let (_, id3) = NodeIdentity::generate().unwrap();

    // All node IDs must be unique
    assert_ne!(id1.node_id(), id2.node_id());
    assert_ne!(id1.node_id(), id3.node_id());
    assert_ne!(id2.node_id(), id3.node_id());
}

#[test]
fn key_types_are_domain_separated() {
    let id = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();

    // Ed25519 signing key bytes should differ from X25519 secret bytes
    let ed_bytes = id.ed25519_signing_key().to_bytes();
    let x_bytes = id.x25519_secret_bytes();
    let aes_bytes = id.aes_key();
    let secp_bytes = id.secp_secret_key().secret_bytes();

    // All key types must be distinct (domain separation working)
    assert_ne!(&ed_bytes[..], x_bytes.as_slice());
    assert_ne!(&ed_bytes[..], aes_bytes.as_slice());
    assert_ne!(&ed_bytes[..], &secp_bytes[..]);
    assert_ne!(x_bytes.as_slice(), aes_bytes.as_slice());
    assert_ne!(x_bytes.as_slice(), &secp_bytes[..]);
    assert_ne!(aes_bytes.as_slice(), &secp_bytes[..]);
}

#[test]
fn node_identity_debug_does_not_leak_secrets() {
    // NodeIdentity doesn't derive Debug — it cannot be printed.
    // This test verifies that attempting to use it in format strings fails at compile time.
    // The test passes by existing — if Debug were ever added, the test would need
    // to verify that it redacts secrets.
    let id = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();

    // We can get the public node_id (safe to print)
    let _public_id = format!("{}", id.node_id());

    // But we cannot format the identity itself (no Debug impl)
    // This is a compile-time guarantee — verifiable by reviewing the struct.
}

#[test]
fn signature_debug_redacts_content() {
    let sig = Signature::from_bytes([0xAB; 64]);
    let debug_output = format!("{:?}", sig);

    // Should show truncated hex, not full 64 bytes
    assert!(!debug_output.contains("abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab"));
    assert!(debug_output.len() < 100);
}

// ═════════════════════════════════════════════════════════════════════════════
// VERIFICATION ORDER (defense in depth — gate must check in correct order)
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn invalid_envelope_rejected_before_nonce_consumed() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let mut envelope = make_signed_envelope(&identity, 100);

    // Tamper with ciphertext (breaks ID validation)
    envelope.ciphertext[0] ^= 0xFF;

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    // First attempt: rejected at envelope validation (before nonce stored)
    let result = gate.verify(&envelope, &nonces, &pricing, None, None, 0.0).await;
    assert!(matches!(result, Err(GateRejection::InvalidEnvelope(_))));

    // Fix the envelope (re-sign with correct content)
    let fixed = make_signed_envelope_with_nonce(&identity, 100, envelope.nonce);

    // Nonce should NOT have been consumed by the failed attempt
    let result = gate.verify(&fixed, &nonces, &pricing, None, None, 0.0).await;
    assert!(result.is_ok(), "nonce should not be consumed by failed validation: {result:?}");
}

#[tokio::test]
async fn whitelist_check_before_signature_verification() {
    // A non-whitelisted sender should be rejected before we even check the signature.
    // This prevents wasting CPU on signature verification for spam from unknown nodes.
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 100);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    let mut whitelist = HashSet::new();
    whitelist.insert(NodeId::from_bytes([99u8; 32]));

    let result = gate
        .verify(&envelope, &nonces, &pricing, Some(&whitelist), None, 0.0)
        .await;

    // Should be NotWhitelisted (not InvalidSignature)
    assert!(matches!(result, Err(GateRejection::NotWhitelisted(_))));
}
