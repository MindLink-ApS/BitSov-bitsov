//! BlvmGateVerifier + on-chain session provider tests.

use async_trait::async_trait;
use konsensus_blvm_payment::providers::on_chain::open_session_from_rpc;
use konsensus_blvm_payment::{
    BlvmGateVerifier, BlvmNodeRpc, CreatedPaymentRequest, OnChainVerification,
    PaymentRequestOutput, PaymentStateSnapshot, RpcBlvmError,
};
use konsensus_core::gate::{BlvmChatPolicy, GateRejection, NonceStore, PaymentGate};
use konsensus_core::gate_payment::{GatePaymentProof, PaymentPath};
use konsensus_core::traits::blvm_payment::{SessionDebitError, SessionDebitStore};
use konsensus_core::identity::NodeIdentity;
use konsensus_core::kind::{KindCategory, KIND_CHAT};
use konsensus_core::traits::pricing::{PricingEngine, PricingError};
use konsensus_core::types::{NodeId, Recipient};
use konsensus_core::UkmEnvelopeBuilder;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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

struct MemorySessionDebits {
    inner: Mutex<MemorySessionDebitsState>,
}

struct MemorySessionDebitsState {
    seen: HashSet<(String, u64)>,
}

impl MemorySessionDebits {
    fn new() -> Self {
        Self {
            inner: Mutex::new(MemorySessionDebitsState {
                seen: HashSet::new(),
            }),
        }
    }
}

#[async_trait]
impl SessionDebitStore for MemorySessionDebits {
    async fn record_inbound_debit(
        &self,
        _payment_request_id: &str,
        tx_hash: &[u8; 32],
        session_debit_seq: u64,
        _debit_msat: u64,
    ) -> Result<(), SessionDebitError> {
        let mut state = self.inner.lock().unwrap();
        let key = (hex::encode(tx_hash), session_debit_seq);
        if !state.seen.insert(key) {
            return Err(SessionDebitError::Replay);
        }
        Ok(())
    }
}

fn blvm_gate<R: BlvmNodeRpc + 'static>(
    verifier: BlvmGateVerifier<R>,
    debits: Arc<MemorySessionDebits>,
) -> PaymentGate {
    PaymentGate::new().with_blvm_chat(
        BlvmChatPolicy::lightning_only()
            .enabled(true)
            .allow_path(PaymentPath::BlvmOnChainSession)
            .allow_path(PaymentPath::BlvmCovenant),
        Arc::new(verifier),
        debits,
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

    async fn get_category_price_msat(&self, _category: KindCategory) -> Result<u64, PricingError> {
        Ok(self.price_msat)
    }
}

#[derive(Clone)]
struct MockRpc {
    on_chain: OnChainVerification,
    covenant_ok: bool,
}

#[async_trait]
impl BlvmNodeRpc for MockRpc {
    async fn verify_on_chain_payment(
        &self,
        _payment_request_id: &str,
        _tx_hash_hex: &str,
    ) -> Result<OnChainVerification, RpcBlvmError> {
        Ok(self.on_chain.clone())
    }

    async fn verify_covenant_proof(
        &self,
        _covenant_proof: &[u8],
        _output_index: u32,
        _amount_sats: u64,
    ) -> Result<bool, RpcBlvmError> {
        Ok(self.covenant_ok)
    }

    async fn create_payment_request(
        &self,
        _outputs: &[PaymentRequestOutput],
        _merchant_data: Option<&[u8]>,
        _create_covenant: bool,
    ) -> Result<CreatedPaymentRequest, RpcBlvmError> {
        Ok(CreatedPaymentRequest {
            payment_id: "req-mock".into(),
            covenant_proof: None,
        })
    }

    async fn get_payment_state(
        &self,
        _payment_request_id: &str,
    ) -> Result<PaymentStateSnapshot, RpcBlvmError> {
        Ok(PaymentStateSnapshot {
            state: "in_mempool".into(),
            tx_hash: None,
        })
    }

    async fn create_covenant_proof(
        &self,
        _payment_request_id: &str,
    ) -> Result<Vec<u8>, RpcBlvmError> {
        Ok(vec![0xAB])
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn sign_with_proof(
    identity: &NodeIdentity,
    proof: GatePaymentProof,
) -> konsensus_core::UkmEnvelope {
    let mut envelope = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        *identity.node_id(),
        Recipient::Node(NodeId::from_bytes([2u8; 32])),
        b"data".to_vec(),
        proof,
    )
    .timestamp(now_ms())
    .build();
    let signable = envelope.signable_bytes();
    let sig = identity.sign(&signable);
    envelope.signature = konsensus_core::types::Signature::from_ed25519(&sig);
    envelope
}

#[tokio::test]
async fn gate_accepts_on_chain_session_via_blvm_gate_verifier() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let rpc = MockRpc {
        on_chain: OnChainVerification {
            verified: true,
            state: "settled".into(),
            amount_sats: Some(100_000),
            tx_hash: Some(hex::encode([0x11; 32])),
            reason: None,
        },
        covenant_ok: true,
    };

    let session = open_session_from_rpc(&rpc, "req-1".into(), [0x11; 32])
        .await
        .expect("session");
    let proof = session.gate_proof_for_debit();
    let envelope = sign_with_proof(&identity, proof);
    let verifier = BlvmGateVerifier::new(rpc);
    let debits = Arc::new(MemorySessionDebits::new());
    let gate = blvm_gate(verifier, Arc::clone(&debits));
    let nonces = MemoryNonces(Mutex::new(HashSet::new()));
    let pricing = FixedPricing { price_msat: 100 };

    gate.verify(&envelope, &nonces, &pricing, None, None, 0.0, None)
        .await
        .expect("gate accepts RPC-verified on-chain session");
}

#[tokio::test]
async fn gate_rejects_on_chain_when_rpc_not_verified() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let rpc = MockRpc {
        on_chain: OnChainVerification {
            verified: false,
            state: "pending".into(),
            amount_sats: Some(100_000),
            tx_hash: None,
            reason: Some("not in mempool".into()),
        },
        covenant_ok: true,
    };
    let verifier = BlvmGateVerifier::new(rpc);

    let proof = GatePaymentProof::BlvmOnChainSession {
        payment_request_id: "req-x".into(),
        tx_hash: [0x22; 32],
        amount_sats: 100_000,
        timestamp: 1,
        session_debit_seq: Some(1),
    };
    let envelope = sign_with_proof(&identity, proof);

    let gate = blvm_gate(verifier, Arc::new(MemorySessionDebits::new()));
    let err = gate
        .verify(
            &envelope,
            &MemoryNonces(Mutex::new(HashSet::new())),
            &FixedPricing { price_msat: 100 },
            None,
            None,
            0.0,
            None,
        )
        .await
        .expect_err("must reject");

    assert!(matches!(err, GateRejection::BlvmRejected(_)));
}

#[tokio::test]
async fn gate_rejects_on_chain_when_rpc_amount_below_proof() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let rpc = MockRpc {
        on_chain: OnChainVerification {
            verified: true,
            state: "settled".into(),
            amount_sats: Some(50),
            tx_hash: Some(hex::encode([0x33; 32])),
            reason: None,
        },
        covenant_ok: true,
    };
    let verifier = BlvmGateVerifier::new(rpc);

    let proof = GatePaymentProof::BlvmOnChainSession {
        payment_request_id: "req-underpay".into(),
        tx_hash: [0x33; 32],
        amount_sats: 100,
        timestamp: 1,
        session_debit_seq: Some(1),
    };
    let envelope = sign_with_proof(&identity, proof);

    let gate = blvm_gate(verifier, Arc::new(MemorySessionDebits::new()));
    let err = gate
        .verify(
            &envelope,
            &MemoryNonces(Mutex::new(HashSet::new())),
            &FixedPricing { price_msat: 100 },
            None,
            None,
            0.0,
            None,
        )
        .await
        .expect_err("must reject underpaid rpc amount");

    assert!(matches!(err, GateRejection::BlvmRejected(_)));
}

#[derive(Clone)]
struct TwoTierMockRpc {
    chain: OnChainVerification,
}

#[async_trait]
impl BlvmNodeRpc for TwoTierMockRpc {
    async fn verify_on_chain_payment(
        &self,
        _payment_request_id: &str,
        _tx_hash_hex: &str,
    ) -> Result<OnChainVerification, RpcBlvmError> {
        Ok(OnChainVerification {
            verified: false,
            state: "unknown".into(),
            amount_sats: None,
            tx_hash: None,
            reason: Some("payment request not found".into()),
        })
    }

    async fn verify_on_chain_payment_by_tx(
        &self,
        _payment_request_id: &str,
        _tx_hash_hex: &str,
        _min_amount_sats: u64,
    ) -> Result<OnChainVerification, RpcBlvmError> {
        Ok(self.chain.clone())
    }

    async fn verify_covenant_proof(&self, _: &[u8], _: u32, _: u64) -> Result<bool, RpcBlvmError> {
        Ok(true)
    }

    async fn create_payment_request(
        &self,
        _: &[PaymentRequestOutput],
        _: Option<&[u8]>,
        _: bool,
    ) -> Result<CreatedPaymentRequest, RpcBlvmError> {
        Ok(CreatedPaymentRequest {
            payment_id: "req-chain".into(),
            covenant_proof: None,
        })
    }

    async fn get_payment_state(&self, _: &str) -> Result<PaymentStateSnapshot, RpcBlvmError> {
        Ok(PaymentStateSnapshot {
            state: "settled".into(),
            tx_hash: Some(hex::encode([0x11; 32])),
        })
    }

    async fn create_covenant_proof(&self, _: &str) -> Result<Vec<u8>, RpcBlvmError> {
        Ok(vec![])
    }
}

#[tokio::test]
async fn gate_rejects_when_payment_request_is_not_on_this_node() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let verifier = BlvmGateVerifier::new(TwoTierMockRpc {
        chain: OnChainVerification {
            verified: true,
            state: "settled".into(),
            amount_sats: Some(100_000),
            tx_hash: Some(hex::encode([0x11; 32])),
            reason: None,
        },
    });
    let proof = GatePaymentProof::BlvmOnChainSession {
        payment_request_id: "req-remote".into(),
        tx_hash: [0x11; 32],
        amount_sats: 100_000,
        timestamp: 1,
        session_debit_seq: Some(0),
    };
    let envelope = sign_with_proof(&identity, proof);
    let gate = blvm_gate(verifier, Arc::new(MemorySessionDebits::new()));
    let err = gate
        .verify(
            &envelope,
            &MemoryNonces(Mutex::new(HashSet::new())),
            &FixedPricing { price_msat: 100 },
            None,
            None,
            0.0,
            None,
        )
        .await
        .expect_err("a request that is not stored on this node is terminal");
    assert!(matches!(err, GateRejection::BlvmRejected(ref msg) if msg.contains("not found")), "{err:?}");
}
