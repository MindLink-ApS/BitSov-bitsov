//! Phase 1 acceptance — path-3 session prepay send/receive behavior.

use async_trait::async_trait;
use konsensus_blvm_payment::{
    mem_try_debit_record, BlvmGateVerifier, BlvmNodeRpc, BlvmOnChainSessionManager,
    CreatedPaymentRequest, OnChainSessionDebit, OnChainSessionRecord, OnChainSessionStore,
    OnChainVerification, PaymentRequestOutput, PaymentStateSnapshot, RpcBlvmError,
    SessionManagerError, SessionStoreError,
};
use konsensus_core::gate::{BlvmChatPolicy, GateRejection, NonceStore, PaymentGate};
use konsensus_core::traits::blvm_payment::{SessionDebitError, SessionDebitStore};
use konsensus_core::gate_payment::{GatePaymentProof, PaymentPath};
use konsensus_core::identity::NodeIdentity;
use konsensus_core::kind::{KindCategory, KIND_CHAT};
use konsensus_core::traits::pricing::{PricingEngine, PricingError};
use konsensus_core::types::{NodeId, Recipient};
use konsensus_core::UkmEnvelopeBuilder;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const PRICE_MSAT: u64 = 1_000;
const SESSION_SATS: u64 = 10;
const MESSAGE_COUNT: usize = 10;

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
        if !state.seen.insert((hex::encode(tx_hash), session_debit_seq)) {
            return Err(SessionDebitError::Replay);
        }
        Ok(())
    }
}

fn blvm_gate(verifier: BlvmGateVerifier<MockRpc>, debits: Arc<MemorySessionDebits>) -> PaymentGate {
    PaymentGate::new().with_blvm_chat(
        BlvmChatPolicy::lightning_only()
            .enabled(true)
            .allow_path(PaymentPath::BlvmOnChainSession),
        Arc::new(verifier),
        debits,
    )
}

async fn verify_and_record(
    gate: &PaymentGate,
    envelope: &konsensus_core::UkmEnvelope,
    nonces: &MemoryNonces,
    pricing: &FixedPricing,
) -> Result<(), GateRejection> {
    gate.verify(envelope, nonces, pricing, None, None, 0.0, None)
        .await
}

struct MemSessionStore {
    sessions: Mutex<HashMap<String, OnChainSessionRecord>>,
}

impl MemSessionStore {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl OnChainSessionStore for MemSessionStore {
    async fn get_for_recipient(
        &self,
        recipient: &NodeId,
    ) -> Result<Option<OnChainSessionRecord>, SessionStoreError> {
        Ok(self
            .sessions
            .lock()
            .unwrap()
            .get(&recipient.to_hex())
            .cloned())
    }

    async fn upsert(&self, record: &OnChainSessionRecord) -> Result<(), SessionStoreError> {
        self.sessions
            .lock()
            .unwrap()
            .insert(record.recipient.to_hex(), record.clone());
        Ok(())
    }

    async fn delete_for_recipient(&self, recipient: &NodeId) -> Result<bool, SessionStoreError> {
        Ok(self
            .sessions
            .lock()
            .unwrap()
            .remove(&recipient.to_hex())
            .is_some())
    }

    async fn try_debit_for_recipient(
        &self,
        recipient: &NodeId,
        debit_msat: u64,
    ) -> Result<OnChainSessionDebit, SessionStoreError> {
        let mut sessions = self.sessions.lock().unwrap();
        let record = sessions
            .get_mut(&recipient.to_hex())
            .ok_or_else(|| SessionStoreError::NoSession(recipient.to_hex()))?;
        let seq = mem_try_debit_record(record, debit_msat)?;
        Ok(OnChainSessionDebit {
            payment_request_id: record.payment_request_id.clone(),
            tx_hash: record.tx_hash,
            amount_sats: record.amount_sats,
            session_debit_seq: seq,
        })
    }

    async fn try_reserve_debit_for_recipient(
        &self,
        recipient: &NodeId,
        _message_id: &konsensus_core::types::MessageId,
        debit_msat: u64,
    ) -> Result<OnChainSessionDebit, SessionStoreError> {
        self.try_debit_for_recipient(recipient, debit_msat).await
    }

    async fn commit_debit(
        &self,
        _message_id: &konsensus_core::types::MessageId,
    ) -> Result<(), SessionStoreError> {
        Ok(())
    }

    async fn rollback_debit(
        &self,
        _message_id: &konsensus_core::types::MessageId,
    ) -> Result<bool, SessionStoreError> {
        Ok(false)
    }
}

#[derive(Clone)]
struct MockRpc {
    amount_sats: u64,
}

#[async_trait]
impl BlvmNodeRpc for MockRpc {
    async fn verify_on_chain_payment(
        &self,
        _payment_request_id: &str,
        _tx_hash_hex: &str,
    ) -> Result<OnChainVerification, RpcBlvmError> {
        Ok(OnChainVerification {
            verified: true,
            state: "in_mempool".into(),
            amount_sats: Some(self.amount_sats),
            tx_hash: Some(hex::encode([0x77; 32])),
            reason: None,
        })
    }

    async fn verify_covenant_proof(
        &self,
        _covenant_proof: &[u8],
        _output_index: u32,
        _amount_sats: u64,
    ) -> Result<bool, RpcBlvmError> {
        Ok(true)
    }

    async fn create_payment_request(
        &self,
        _outputs: &[PaymentRequestOutput],
        _merchant_data: Option<&[u8]>,
        _create_covenant: bool,
    ) -> Result<CreatedPaymentRequest, RpcBlvmError> {
        Ok(CreatedPaymentRequest {
            payment_id: "req-phase1".into(),
            covenant_proof: None,
        })
    }

    async fn get_payment_state(
        &self,
        _payment_request_id: &str,
    ) -> Result<PaymentStateSnapshot, RpcBlvmError> {
        Ok(PaymentStateSnapshot {
            state: "in_mempool".into(),
            tx_hash: Some(hex::encode([0x77; 32])),
        })
    }

    async fn create_covenant_proof(
        &self,
        _payment_request_id: &str,
    ) -> Result<Vec<u8>, RpcBlvmError> {
        Ok(vec![0xAB])
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

fn setup_alice_session_manager() -> BlvmOnChainSessionManager {
    let rpc: Arc<dyn BlvmNodeRpc> = Arc::new(MockRpc {
        amount_sats: SESSION_SATS,
    });
    let store: Arc<dyn OnChainSessionStore> = Arc::new(MemSessionStore::new());
    BlvmOnChainSessionManager::new(rpc, store)
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
        b"phase1 acceptance".to_vec(),
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
async fn phase1_sender_debits_ten_then_eleventh_rejected() {
    let mgr = setup_alice_session_manager();
    let bob = bob_id();

    mgr.open_verified(&bob, "req-phase1".into(), &hex::encode([0x77; 32]))
        .await
        .expect("session opens");

    for i in 0..MESSAGE_COUNT {
        mgr.debit_for_message(&bob, PRICE_MSAT)
            .await
            .unwrap_or_else(|e| panic!("debit {i} should succeed: {e:?}"));
    }

    let err = mgr
        .debit_for_message(&bob, PRICE_MSAT)
        .await
        .expect_err("11th debit must fail");
    assert!(matches!(
        err,
        SessionManagerError::Store(SessionStoreError::BalanceExhausted { .. })
    ));
}

#[tokio::test]
async fn phase1_receiver_accepts_ten_messages() {
    let mgr = setup_alice_session_manager();
    let alice = alice();
    let bob = bob_id();

    mgr.open_verified(&bob, "req-phase1".into(), &hex::encode([0x77; 32]))
        .await
        .expect("session opens");

    let verifier = BlvmGateVerifier::new(MockRpc {
        amount_sats: SESSION_SATS,
    });
    let debits = Arc::new(MemorySessionDebits::new());
    let gate = blvm_gate(verifier, Arc::clone(&debits));
    let nonces = MemoryNonces(Mutex::new(HashSet::new()));
    let pricing = FixedPricing {
        price_msat: PRICE_MSAT,
    };

    for i in 0..MESSAGE_COUNT {
        let proof = mgr
            .debit_for_message(&bob, PRICE_MSAT)
            .await
            .unwrap_or_else(|e| panic!("debit {i}: {e:?}"));
        let envelope = sign_envelope(&alice, bob, proof);

        verify_and_record(&gate, &envelope, &nonces, &pricing)
            .await
            .unwrap_or_else(|e| panic!("gate accept {i}: {e:?}"));
    }

    // The sender's session manager refuses an 11th debit. The receiver's
    // anti-replay is the sequence: reusing sequence 0 fails and does not debit again.
    let proof = GatePaymentProof::BlvmOnChainSession {
        payment_request_id: "req-phase1".into(),
        tx_hash: [0x77; 32],
        amount_sats: SESSION_SATS,
        timestamp: 1,
        session_debit_seq: Some(0),
    };
    let envelope = sign_envelope(&alice, bob, proof);
    let err = gate
        .verify(&envelope, &nonces, &pricing, None, None, 0.0, None)
        .await
        .expect_err("replayed debit sequence");
    assert!(
        matches!(err, GateRejection::BlvmRejected(ref msg) if msg.contains("replayed")),
        "{err:?}"
    );
}

#[tokio::test]
async fn phase1_replay_of_debit_seq_rejected_at_gate() {
    let alice = alice();
    let bob = bob_id();

    let proof = GatePaymentProof::BlvmOnChainSession {
        payment_request_id: "req-phase1".into(),
        tx_hash: [0x77; 32],
        amount_sats: SESSION_SATS,
        timestamp: 1,
        session_debit_seq: Some(0),
    };

    let verifier = BlvmGateVerifier::new(MockRpc {
        amount_sats: SESSION_SATS,
    });
    let debits = Arc::new(MemorySessionDebits::new());
    let gate = blvm_gate(verifier, debits);
    let nonces = MemoryNonces(Mutex::new(HashSet::new()));
    let pricing = FixedPricing {
        price_msat: PRICE_MSAT,
    };

    let env1 = sign_envelope(&alice, bob, proof.clone());
    verify_and_record(&gate, &env1, &nonces, &pricing)
        .await
        .expect("first delivery");

    assert_eq!(proof.path(), PaymentPath::BlvmOnChainSession);

    let env2 = sign_envelope(&alice, bob, proof);
    let err = gate
        .verify(&env2, &nonces, &pricing, None, None, 0.0, None)
        .await
        .expect_err("replay same session_debit_seq");

    assert!(
        matches!(err, GateRejection::BlvmRejected(ref msg) if msg.contains("replayed")),
        "{err:?}"
    );
}
