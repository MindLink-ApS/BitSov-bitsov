//! Phase 2 acceptance — path-2 covenant send/receive (mock RPC).

use async_trait::async_trait;
use konsensus_blvm_payment::{
    BlvmCovenantPaymentProvider, BlvmGateVerifier, BlvmNodeRpc, CreatedPaymentRequest,
    OnChainVerification, PaymentRequestOutput, PaymentStateSnapshot, RpcBlvmError,
};
use konsensus_core::gate::{BlvmChatPolicy, GateRejection, NonceStore, PaymentGate};
use konsensus_core::gate_payment::{GatePaymentProof, PaymentPath};
use konsensus_core::traits::blvm_payment::{SessionDebitError, SessionDebitStore};
use konsensus_core::identity::NodeIdentity;
use konsensus_core::kind::KIND_CHAT;
use konsensus_core::traits::pricing::{PricingEngine, PricingError};
use konsensus_core::types::{NodeId, Recipient};
use konsensus_core::UkmEnvelopeBuilder;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const PRICE_MSAT: u64 = 5_000;
const AMOUNT_SATS: u64 = 5;

struct MemoryNonces(Mutex<HashSet<[u8; 24]>>);

#[async_trait]
impl NonceStore for MemoryNonces {
    async fn check_and_store(
        &self,
        nonce: &konsensus_core::types::Nonce,
        _sender: &NodeId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.0.lock().unwrap().insert(*nonce.as_bytes()))
    }
}

struct FixedPricing {
    price_msat: u64,
}

struct MemoryDebits(Mutex<HashSet<[u8; 32]>>);

#[async_trait]
impl SessionDebitStore for MemoryDebits {
    async fn record_inbound_debit(
        &self,
        _payment_request_id: &str,
        tx_hash: &[u8; 32],
        _session_debit_seq: u64,
        _debit_msat: u64,
    ) -> Result<(), SessionDebitError> {
        if !self.0.lock().unwrap().insert(*tx_hash) {
            return Err(SessionDebitError::Replay);
        }
        Ok(())
    }
}

fn blvm_gate(verifier: BlvmGateVerifier<MockRpc>) -> PaymentGate {
    PaymentGate::new().with_blvm_chat(
        BlvmChatPolicy::lightning_only()
            .enabled(true)
            .allow_path(PaymentPath::BlvmCovenant),
        Arc::new(verifier),
        Arc::new(MemoryDebits(Mutex::new(HashSet::new()))),
    )
}

#[async_trait]
impl PricingEngine for FixedPricing {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get_price_msat(&self, _kind: u16) -> Result<u64, PricingError> {
        Ok(self.price_msat)
    }

    async fn get_category_price_msat(
        &self,
        _category: konsensus_core::kind::KindCategory,
    ) -> Result<u64, PricingError> {
        Ok(self.price_msat)
    }
}

#[derive(Clone)]
struct MockRpc {
    covenant_bytes: Vec<u8>,
    covenant_ok: bool,
}

#[async_trait]
impl BlvmNodeRpc for MockRpc {
    async fn verify_on_chain_payment(
        &self,
        _: &str,
        _: &str,
    ) -> Result<OnChainVerification, RpcBlvmError> {
        Err(RpcBlvmError::CallFailed("unused".into()))
    }

    async fn verify_covenant_proof(
        &self,
        proof: &[u8],
        output_index: u32,
        amount_sats: u64,
    ) -> Result<bool, RpcBlvmError> {
        if !self.covenant_ok {
            return Ok(false);
        }
        Ok(proof == self.covenant_bytes && output_index == 0 && amount_sats == AMOUNT_SATS)
    }

    async fn create_payment_request(
        &self,
        _: &[PaymentRequestOutput],
        _: Option<&[u8]>,
        create_covenant: bool,
    ) -> Result<CreatedPaymentRequest, RpcBlvmError> {
        Ok(CreatedPaymentRequest {
            payment_id: "req-cov".into(),
            covenant_proof: create_covenant.then(|| self.covenant_bytes.clone()),
        })
    }

    async fn get_payment_state(&self, _: &str) -> Result<PaymentStateSnapshot, RpcBlvmError> {
        Ok(PaymentStateSnapshot {
            state: "proof_created".into(),
            tx_hash: None,
        })
    }

    async fn create_covenant_proof(&self, _: &str) -> Result<Vec<u8>, RpcBlvmError> {
        Ok(self.covenant_bytes.clone())
    }
}

fn alice() -> NodeIdentity {
    NodeIdentity::from_mnemonic(TEST_MNEMONIC, "alice").unwrap()
}

fn bob_id() -> NodeId {
    *NodeIdentity::from_mnemonic(TEST_MNEMONIC, "bob")
        .unwrap()
        .node_id()
}

fn sample_covenant_bytes() -> Vec<u8> {
    let template_hash = [0xBE; 32];
    serde_json::to_vec(&serde_json::json!({
        "template_hash": template_hash,
        "payment_request_id": "req-cov",
        "created_at": 1,
    }))
    .expect("json")
}

fn sign_envelope(
    sender: &NodeIdentity,
    recipient: NodeId,
    proof: GatePaymentProof,
) -> konsensus_core::UkmEnvelope {
    let mut envelope = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        *sender.node_id(),
        Recipient::Node(recipient),
        b"phase2 covenant acceptance".to_vec(),
        proof,
    )
    .timestamp(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
    )
    .build();
    let sig = sender.sign(&envelope.signable_bytes());
    envelope.signature = konsensus_core::types::Signature::from_ed25519(&sig);
    envelope
}

#[tokio::test]
async fn phase2_create_and_finalize_builds_verified_proof() {
    let bytes = sample_covenant_bytes();
    let rpc: Arc<dyn BlvmNodeRpc> = Arc::new(MockRpc {
        covenant_bytes: bytes.clone(),
        covenant_ok: true,
    });
    let provider = BlvmCovenantPaymentProvider::new(rpc);

    let proof = provider
        .create_and_finalize(AMOUNT_SATS, "0014deadbeef", 0)
        .await
        .expect("covenant proof");

    assert_eq!(proof.path(), PaymentPath::BlvmCovenant);
    assert_eq!(proof.amount_msat(), AMOUNT_SATS * 1000);
    if let GatePaymentProof::BlvmCovenant {
        covenant_proof,
        amount_sats,
        output_index,
        ..
    } = proof
    {
        assert_eq!(covenant_proof, bytes);
        assert_eq!(amount_sats, AMOUNT_SATS);
        assert_eq!(output_index, 0);
    } else {
        panic!("expected BlvmCovenant proof");
    }
}

#[tokio::test]
async fn phase2_receiver_gate_accepts_covenant_message() {
    let bytes = sample_covenant_bytes();
    let rpc: Arc<dyn BlvmNodeRpc> = Arc::new(MockRpc {
        covenant_bytes: bytes.clone(),
        covenant_ok: true,
    });
    let provider = BlvmCovenantPaymentProvider::new(Arc::clone(&rpc));
    let verifier = BlvmGateVerifier::new(MockRpc {
        covenant_bytes: bytes,
        covenant_ok: true,
    });

    let proof = provider
        .create_and_finalize(AMOUNT_SATS, "0014aa", 0)
        .await
        .expect("proof");

    let alice = alice();
    let bob = bob_id();
    let envelope = sign_envelope(&alice, bob, proof);

    let gate = blvm_gate(verifier);
    gate.verify(
        &envelope,
        &MemoryNonces(Mutex::new(HashSet::new())),
        &FixedPricing {
            price_msat: PRICE_MSAT,
        },
        None,
        None,
        0.0,
        None,
    )
    .await
    .expect("gate accepts covenant proof");
}

#[tokio::test]
async fn phase2_underpaid_covenant_rejected_at_gate() {
    let bytes = sample_covenant_bytes();
    let verifier = BlvmGateVerifier::new(MockRpc {
        covenant_bytes: bytes.clone(),
        covenant_ok: true,
    });

    let proof = GatePaymentProof::BlvmCovenant {
        covenant_proof: bytes,
        output_index: 0,
        amount_sats: 1,
        timestamp: 1,
    };

    let envelope = sign_envelope(&alice(), bob_id(), proof);
    let err = blvm_gate(verifier)
        .verify(
            &envelope,
            &MemoryNonces(Mutex::new(HashSet::new())),
            &FixedPricing {
                price_msat: PRICE_MSAT,
            },
            None,
            None,
            0.0,
            None,
        )
        .await
        .expect_err("underpaid covenant must fail");

    assert!(matches!(err, GateRejection::InsufficientPayment { .. }));
}
