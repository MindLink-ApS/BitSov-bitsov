//! Payment gate boundary condition tests — timestamp freshness edges,
//! exact payment matching, custom max_message_age, settlement success path,
//! overpayment acceptance, and multi-message flows with whitelist variations.

use std::collections::HashSet;
use std::sync::Mutex;

use konsensus_core::UkmEnvelopeBuilder;
use konsensus_core::gate::{GateConfig, GateRejection, NonceStore, PaymentGate};
use konsensus_core::identity::NodeIdentity;
use konsensus_core::kind::{KIND_CHAT, KIND_FILE_REF, KIND_LONGFORM, KindCategory};
use konsensus_core::traits::lightning::{
    Invoice, LightningError, PaymentDetails, PaymentDirection, PaymentStatus,
};
use konsensus_core::traits::pricing::{PricingEngine, PricingError};
use konsensus_core::types::{NodeId, Nonce, PaymentProof, Recipient, Signature};

use sha2::{Digest, Sha256};

// ── Mocks ────────────────────────────────────────────────────────────────────

struct MockNonceStore {
    seen: Mutex<HashSet<[u8; 24]>>,
    seen_payment_hashes: Mutex<HashSet<[u8; 32]>>,
}

impl MockNonceStore {
    fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
            seen_payment_hashes: Mutex::new(HashSet::new()),
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

    async fn check_and_store_payment_hash(
        &self,
        payment_hash: &[u8; 32],
        _sender: &NodeId,
        _message_id: &konsensus_core::MessageId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let mut seen = self.seen_payment_hashes.lock().unwrap();
        Ok(seen.insert(*payment_hash))
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

/// Pricing that returns different prices per kind
struct KindAwarePricing;

#[async_trait::async_trait]
impl PricingEngine for KindAwarePricing {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get_price_msat(&self, kind: u16) -> Result<u64, PricingError> {
        match kind {
            0 => Ok(10),    // KIND_CHAT
            1 => Ok(50),    // KIND_LONGFORM
            200 => Ok(100), // KIND_FILE_REF
            _ => Ok(25),
        }
    }

    async fn get_category_price_msat(&self, _category: KindCategory) -> Result<u64, PricingError> {
        Ok(25)
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
        Err(LightningError::InvoiceCreation("mock".into()))
    }

    async fn pay_invoice(&self, _bolt11: &str) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::PaymentFailed("mock".into()))
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
            preimage: Some(hex::encode([42u8; 32])),
            amount_msat: 100,
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

// ── Helpers ──────────────────────────────────────────────────────────────────

const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn make_proof(amount_msat: u64) -> PaymentProof {
    let preimage = [42u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    PaymentProof::new(hash, preimage, amount_msat)
}

fn make_signed_envelope_with_kind_and_ts(
    identity: &NodeIdentity,
    kind: u16,
    amount_msat: u64,
    timestamp: u64,
) -> konsensus_core::UkmEnvelope {
    let sender = *identity.node_id();
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let proof = make_proof(amount_msat);
    let ciphertext = b"encrypted content".to_vec();

    let mut envelope = UkmEnvelopeBuilder::new(kind, sender, recipient, ciphertext, proof)
        .timestamp(timestamp)
        .build();

    let signable = envelope.signable_bytes();
    let sig = identity.sign(&signable);
    envelope.signature = Signature::from_ed25519(&sig);
    envelope
}

fn make_signed_envelope(identity: &NodeIdentity, amount_msat: u64) -> konsensus_core::UkmEnvelope {
    make_signed_envelope_with_kind_and_ts(identity, KIND_CHAT, amount_msat, now_ms())
}

/// Like `make_signed_envelope` but derives a UNIQUE payment proof per `seed`.
///
/// Each real message is paid with its own Lightning invoice, so distinct
/// messages carry distinct payment hashes. The shared-preimage `make_proof`
/// helper would (correctly) trip the gate's economic-replay protection when
/// reused across messages, so multi-message flow tests use this instead.
fn make_signed_envelope_unique_proof(
    identity: &NodeIdentity,
    amount_msat: u64,
    seed: u8,
) -> konsensus_core::UkmEnvelope {
    let sender = *identity.node_id();
    let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let preimage = [seed; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, amount_msat);

    let mut envelope =
        UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"encrypted content".to_vec(), proof)
            .timestamp(now_ms())
            .build();

    let signable = envelope.signable_bytes();
    let sig = identity.sign(&signable);
    envelope.signature = Signature::from_ed25519(&sig);
    envelope
}

// ═══════════════════════════════════════════════════════════════════════════════
// TIMESTAMP FRESHNESS BOUNDARY CONDITIONS
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn message_just_within_max_age_accepted() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let max_age_ms = 5 * 60 * 1000; // 5 minutes (default)

    // Timestamp is exactly (max_age - 1000ms) old — safely within window
    let ts = now_ms() - (max_age_ms - 1_000);
    let envelope = make_signed_envelope_with_kind_and_ts(&identity, KIND_CHAT, 100, ts);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    assert!(
        gate.verify(&envelope, &nonces, &pricing, None, None, 0.0, None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn message_well_beyond_max_age_rejected() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();

    // Timestamp is 10 minutes old (well beyond default 5-minute window)
    let ts = now_ms() - (10 * 60 * 1000);
    let envelope = make_signed_envelope_with_kind_and_ts(&identity, KIND_CHAT, 100, ts);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    let result = gate
        .verify(&envelope, &nonces, &pricing, None, None, 0.0, None)
        .await;
    assert!(matches!(result, Err(GateRejection::MessageTooOld { .. })));
}

#[tokio::test]
async fn custom_max_age_1_second_rejects_old_messages() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();

    let config = GateConfig {
        max_message_age_ms: 1_000, // 1 second
        ..Default::default()
    };
    let gate = PaymentGate::with_config(config);
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    // Message 2 seconds old — rejected with 1s max age
    let ts = now_ms() - 2_000;
    let envelope = make_signed_envelope_with_kind_and_ts(&identity, KIND_CHAT, 100, ts);

    let result = gate
        .verify(&envelope, &nonces, &pricing, None, None, 0.0, None)
        .await;
    assert!(matches!(result, Err(GateRejection::MessageTooOld { .. })));
}

#[tokio::test]
async fn custom_max_age_1_hour_accepts_recent_messages() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();

    let config = GateConfig {
        max_message_age_ms: 60 * 60 * 1000, // 1 hour
        ..Default::default()
    };
    let gate = PaymentGate::with_config(config);
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    // Message 10 minutes old — accepted with 1h max age
    let ts = now_ms() - (10 * 60 * 1000);
    let envelope = make_signed_envelope_with_kind_and_ts(&identity, KIND_CHAT, 100, ts);

    assert!(
        gate.verify(&envelope, &nonces, &pricing, None, None, 0.0, None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn zero_timestamp_rejected_as_too_old() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();

    // Timestamp = 0 (epoch) — extremely old
    let envelope = make_signed_envelope_with_kind_and_ts(&identity, KIND_CHAT, 100, 0);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    let result = gate
        .verify(&envelope, &nonces, &pricing, None, None, 0.0, None)
        .await;
    assert!(matches!(result, Err(GateRejection::MessageTooOld { .. })));
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAYMENT AMOUNT BOUNDARY CONDITIONS
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn exact_payment_amount_accepted() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 10); // exactly 10 msat

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    assert!(
        gate.verify(&envelope, &nonces, &pricing, None, None, 0.0, None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn overpayment_accepted() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 1_000_000); // 1M msat overpayment

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    assert!(
        gate.verify(&envelope, &nonces, &pricing, None, None, 0.0, None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn zero_price_accepts_zero_payment() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 0);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 0 }; // free messages

    assert!(
        gate.verify(&envelope, &nonces, &pricing, None, None, 0.0, None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn large_payment_amount_no_overflow() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, u64::MAX);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing {
        price_msat: u64::MAX,
    };

    // u64::MAX >= u64::MAX — should pass price check
    assert!(
        gate.verify(&envelope, &nonces, &pricing, None, None, 0.0, None)
            .await
            .is_ok()
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// KIND-AWARE PRICING
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn different_kinds_require_different_payments() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let gate = PaymentGate::new();
    let pricing = KindAwarePricing;

    // KIND_CHAT costs 10 — paying 10 should pass
    let env = make_signed_envelope_with_kind_and_ts(&identity, KIND_CHAT, 10, now_ms());
    let nonces = MockNonceStore::new();
    assert!(
        gate.verify(&env, &nonces, &pricing, None, None, 0.0, None)
            .await
            .is_ok()
    );

    // KIND_LONGFORM costs 50 — paying 10 should fail
    let env = make_signed_envelope_with_kind_and_ts(&identity, KIND_LONGFORM, 10, now_ms());
    let nonces = MockNonceStore::new();
    let result = gate.verify(&env, &nonces, &pricing, None, None, 0.0, None).await;
    assert!(matches!(
        result,
        Err(GateRejection::InsufficientPayment {
            required_msat: 50,
            paid_msat: 10
        })
    ));

    // KIND_FILE_REF costs 100 — paying 100 should pass
    let env = make_signed_envelope_with_kind_and_ts(&identity, KIND_FILE_REF, 100, now_ms());
    let nonces = MockNonceStore::new();
    assert!(
        gate.verify(&env, &nonces, &pricing, None, None, 0.0, None)
            .await
            .is_ok()
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// LIGHTNING SETTLEMENT SUCCESS PATH
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn settled_payment_passes_settlement_check() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 100);

    let config = GateConfig {
        verify_lightning_settlement: true,
        ..Default::default()
    };
    let gate = PaymentGate::with_config(config);
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };
    let lightning = MockLightning { settled: true };

    assert!(
        gate.verify(&envelope, &nonces, &pricing, None, Some(&lightning), 0.0, None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn settlement_not_required_by_default() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 100);

    // Default config: settlement not required
    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };
    let lightning = MockLightning { settled: false };

    // Even with unsettled Lightning, should pass (settlement not checked)
    assert!(
        gate.verify(&envelope, &nonces, &pricing, None, Some(&lightning), 0.0, None)
            .await
            .is_ok()
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WHITELIST VARIATIONS
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn sender_in_whitelist_accepted() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 100);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    let mut whitelist = HashSet::new();
    whitelist.insert(*identity.node_id());

    assert!(
        gate.verify(&envelope, &nonces, &pricing, Some(&whitelist), None, 0.0, None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn large_whitelist_with_sender_accepted() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let envelope = make_signed_envelope(&identity, 100);

    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    // Whitelist with 100 random nodes plus the sender
    let mut whitelist = HashSet::new();
    for i in 0..100u8 {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[i; 32]);
        whitelist.insert(NodeId::from_verifying_key(&signing.verifying_key()));
    }
    whitelist.insert(*identity.node_id());

    assert!(
        gate.verify(&envelope, &nonces, &pricing, Some(&whitelist), None, 0.0, None)
            .await
            .is_ok()
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MULTI-MESSAGE SEQUENTIAL FLOWS
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn multiple_valid_messages_all_accepted() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    for seed in 0..20u8 {
        // Each message is paid with its own Lightning proof → unique payment hash.
        let envelope = make_signed_envelope_unique_proof(&identity, 100, seed);
        assert!(
            gate.verify(&envelope, &nonces, &pricing, None, None, 0.0, None)
                .await
                .is_ok()
        );
    }
}

#[tokio::test]
async fn messages_from_multiple_senders_accepted() {
    let gate = PaymentGate::new();
    let nonces = MockNonceStore::new();
    let pricing = MockPricing { price_msat: 10 };

    let mut whitelist = HashSet::new();

    for (seed, pass) in ["alice", "bob", "charlie", "dave", "eve"].iter().enumerate() {
        let id = NodeIdentity::from_mnemonic(TEST_MNEMONIC, pass).unwrap();
        whitelist.insert(*id.node_id());
        // Distinct senders pay with distinct Lightning proofs → unique hashes.
        let envelope = make_signed_envelope_unique_proof(&id, 100, seed as u8);
        assert!(
            gate.verify(&envelope, &nonces, &pricing, Some(&whitelist), None, 0.0, None)
                .await
                .is_ok(),
            "message from {pass} should be accepted"
        );
    }
}

#[tokio::test]
async fn gate_config_default_values() {
    let config = GateConfig::default();
    assert_eq!(config.max_message_age_ms, 5 * 60 * 1000);
    assert!(!config.verify_lightning_settlement);
}
