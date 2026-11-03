//! The inbound gate over the production wrappers, on a backend whose chain sync
//! has lapsed: a settlement already in the local store counts, nothing else does.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use konsensus_core::gate::{GateConfig, GateRejection, PaymentGate};
use konsensus_core::identity::NodeIdentity;
use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails, PaymentDirection, PaymentStatus,
};
use konsensus_core::types::Recipient;
use konsensus_core::{PaymentProof, UkmEnvelope, UkmEnvelopeBuilder};
use konsensus_lightning::{CircuitBreakerLightning, RecoveringLightning};
use konsensus_storage::{PaidAcceptance, SqliteStorage, Storage, StorageNonceAdapter};
use sha2::{Digest, Sha256};

const AMOUNT: u64 = 10_000;
const PREIMAGE: [u8; 32] = [7; 32];

struct Store {
    ready: AtomicBool,
    funding: AtomicBool,
    record: Mutex<Option<PaymentDetails>>,
}

impl Store {
    fn read(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        self.record
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| LightningError::PaymentNotFound(hash.into()))
    }
}

#[async_trait::async_trait]
impl LightningProvider for Store {
    async fn money_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }
    async fn is_available(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }
    async fn is_funding_payment(&self, hash: &str) -> Result<bool, LightningError> {
        self.read(hash).map(|_| self.funding.load(Ordering::SeqCst))
    }
    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        self.read(hash)
    }
    async fn create_invoice(&self, amount_msat: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
        Ok(Invoice {
            bolt11: "lnbcrt1".into(),
            payment_hash: hex::encode(hash()),
            amount_msat,
            description: String::new(),
            expiry_secs: 60,
            created_at: 0,
        })
    }
    async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::Backend("unused".into()))
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(0)
    }
}

fn hash() -> [u8; 32] {
    Sha256::digest(PREIMAGE).into()
}

fn record(status: PaymentStatus, direction: PaymentDirection) -> PaymentDetails {
    PaymentDetails {
        payment_hash: hex::encode(hash()),
        preimage: (status == PaymentStatus::Settled).then(|| hex::encode(PREIMAGE)),
        amount_msat: AMOUNT,
        status,
        direction,
        timestamp: 0,
        memo: None,
        fee_msat: None,
    }
}

/// `CircuitBreaker(Guarded(Recovering(store)))`, as the node builds it.
struct Node {
    store: Arc<Store>,
    money: Arc<dyn LightningProvider>,
    verifier: CircuitBreakerLightning,
    identity: NodeIdentity,
    db: Arc<SqliteStorage>,
    _dir: tempfile::TempDir,
}

impl Node {
    async fn start(ready: bool, stored: Option<PaymentDetails>) -> Self {
        let store = Arc::new(Store {
            ready: ready.into(),
            funding: false.into(),
            record: stored.into(),
        });
        let backend = store.clone() as Arc<dyn LightningProvider>;
        let recovering = RecoveringLightning::new(
            move || {
                let backend = backend.clone();
                async move { Ok(backend) }
            },
            Default::default(),
        )
        .await
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let money: Arc<dyn LightningProvider> = Arc::new(crate::guarded_lightning::GuardedLightning {
            inner: Arc::new(recovering),
            disk: Arc::new(crate::safety::DiskGuard::new(dir.path().to_path_buf(), 0)),
            channel_peers: Default::default(),
            _state_guard: Arc::new(std::fs::File::open(dir.path()).unwrap()),
        });
        let verifier = CircuitBreakerLightning::with_defaults(money.clone());
        Self {
            store,
            money,
            verifier,
            identity: NodeIdentity::generate().unwrap().1,
            db: Arc::new(SqliteStorage::in_memory().await.unwrap()),
            _dir: dir,
        }
    }

    fn envelope(&self, sender: &NodeIdentity, proof: PaymentProof) -> UkmEnvelope {
        let now = chrono::Utc::now().timestamp_millis().try_into().unwrap();
        let mut envelope = UkmEnvelopeBuilder::new(
            konsensus_core::kind::KIND_CHAT,
            *sender.node_id(),
            Recipient::Node(*self.identity.node_id()),
            b"ciphertext".to_vec(),
            proof,
        )
        .timestamp(now)
        .build();
        let signature = sender.sign(&envelope.signable_bytes());
        envelope.signature = konsensus_core::types::Signature::from_ed25519(&signature);
        envelope
    }

    /// The handler's order: gate first, then the atomic replay-store acceptance.
    async fn gate(&self, envelope: &UkmEnvelope) -> Result<bool, GateRejection> {
        let gate = PaymentGate::with_config(GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        });
        let receipts = StorageNonceAdapter::new(self.db.clone() as Arc<dyn Storage>);
        let pricing = konsensus_pricing::StaticPricingEngine::new(Default::default());
        gate.validate_received_paid_envelope(
            envelope,
            &receipts,
            &pricing,
            None,
            Some(&self.verifier),
            0.0,
            Some(self.identity.node_id()),
        )
        .await
    }

    async fn wait_money_ready(&self, ready: bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.money.money_ready().await != ready {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}

fn proof() -> PaymentProof {
    PaymentProof::new(hash(), PREIMAGE, AMOUNT)
}

fn sender() -> NodeIdentity {
    NodeIdentity::generate().unwrap().1
}

#[tokio::test]
async fn settled_payment_is_admitted_while_not_ready() {
    let node = Node::start(false, Some(record(PaymentStatus::Settled, PaymentDirection::Incoming))).await;
    let envelope = node.envelope(&sender(), proof());
    assert!(!node.gate(&envelope).await.unwrap());
    assert!(!node.money.money_ready().await);
    node.money.shutdown().await.unwrap();
}

/// The order that lost a paid block: invoice while ready, settlement, then chain
/// sync lapses before the envelope carrying the proof reaches the gate.
#[tokio::test]
async fn block_settled_before_readiness_lapses_still_counts() {
    let node = Node::start(true, None).await;
    node.wait_money_ready(true).await;
    node.money.create_invoice(AMOUNT, "call block", 60).await.unwrap();
    *node.store.record.lock().unwrap() = Some(record(PaymentStatus::Settled, PaymentDirection::Incoming));
    node.store.ready.store(false, Ordering::SeqCst);
    node.wait_money_ready(false).await;

    let envelope = node.envelope(&sender(), proof());
    assert!(!node.gate(&envelope).await.unwrap());
    // The next minute is still refused before anything is paid.
    assert!(matches!(
        node.money.create_invoice(AMOUNT, "call block", 60).await,
        Err(LightningError::NotReady)
    ));
    node.money.shutdown().await.unwrap();
}

#[tokio::test]
async fn nothing_else_is_admitted_while_not_ready() {
    for stored in [
        Some(record(PaymentStatus::Pending, PaymentDirection::Incoming)),
        Some(record(PaymentStatus::InFlight, PaymentDirection::Incoming)),
        Some(record(PaymentStatus::Failed, PaymentDirection::Incoming)),
        Some(record(PaymentStatus::Expired, PaymentDirection::Incoming)),
        Some(record(PaymentStatus::Settled, PaymentDirection::Outgoing)),
        None,
    ] {
        let label = format!("{stored:?}");
        let node = Node::start(false, stored).await;
        let envelope = node.envelope(&sender(), proof());
        let refusal = node.gate(&envelope).await.expect_err(&label);
        assert!(
            matches!(&refusal, GateRejection::LightningUnavailable(reason) if reason.contains("not_ready")),
            "{label}: {refusal:?}"
        );
        node.money.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn every_gate_check_still_runs_while_not_ready() {
    let settled = record(PaymentStatus::Settled, PaymentDirection::Incoming);

    let node = Node::start(false, Some(settled.clone())).await;
    node.store.funding.store(true, Ordering::SeqCst);
    let refusal = node.gate(&node.envelope(&sender(), proof())).await.unwrap_err();
    assert!(matches!(refusal, GateRejection::PaymentSettlementMismatch(_)), "funding: {refusal:?}");
    node.money.shutdown().await.unwrap();

    // Claims more than was settled.
    let node = Node::start(false, Some(settled.clone())).await;
    let inflated = PaymentProof::new(hash(), PREIMAGE, AMOUNT + 1);
    let refusal = node.gate(&node.envelope(&sender(), inflated)).await.unwrap_err();
    assert!(matches!(refusal, GateRejection::PaymentSettlementMismatch(_)), "amount: {refusal:?}");
    node.money.shutdown().await.unwrap();

    // Settled below the price of the kind.
    let mut small = settled.clone();
    small.amount_msat = 1;
    let node = Node::start(false, Some(small)).await;
    let underpaid = PaymentProof::new(hash(), PREIMAGE, 1);
    let refusal = node.gate(&node.envelope(&sender(), underpaid)).await.unwrap_err();
    assert!(matches!(refusal, GateRejection::InsufficientPayment { .. }), "price: {refusal:?}");
    node.money.shutdown().await.unwrap();

    // The stored preimage differs from the proof's.
    let mut other = settled.clone();
    other.preimage = Some(hex::encode([9u8; 32]));
    let node = Node::start(false, Some(other)).await;
    let refusal = node.gate(&node.envelope(&sender(), proof())).await.unwrap_err();
    assert!(matches!(refusal, GateRejection::PaymentSettlementMismatch(_)), "preimage: {refusal:?}");
    node.money.shutdown().await.unwrap();

    // Addressed to another node.
    let node = Node::start(false, Some(settled)).await;
    let elsewhere = Node::start(false, None).await;
    let refusal = node.gate(&elsewhere.envelope(&sender(), proof())).await.unwrap_err();
    assert!(matches!(refusal, GateRejection::RecipientMismatch { .. }), "recipient: {refusal:?}");
    node.money.shutdown().await.unwrap();
    elsewhere.money.shutdown().await.unwrap();
}

#[tokio::test]
async fn replay_store_still_holds_while_not_ready() {
    let node = Node::start(false, Some(record(PaymentStatus::Settled, PaymentDirection::Incoming))).await;
    let payer = sender();
    let envelope = node.envelope(&payer, proof());
    assert!(!node.gate(&envelope).await.unwrap());
    assert_eq!(node.db.accept_paid_envelope(&envelope).await.unwrap(), PaidAcceptance::Accepted);

    // A retransmission is a duplicate, never a second admission.
    assert!(node.gate(&envelope).await.unwrap(), "duplicate needs no new payment");
    assert_eq!(node.db.accept_paid_envelope(&envelope).await.unwrap(), PaidAcceptance::AlreadyAccepted);

    // The same payment cannot pay for another act, by this sender or another.
    for other in [&payer, &sender()] {
        let second = UkmEnvelopeBuilder::new(
            konsensus_core::kind::KIND_CHAT,
            *other.node_id(),
            Recipient::Node(*node.identity.node_id()),
            b"a different act".to_vec(),
            proof(),
        )
        .timestamp(envelope.timestamp)
        .build();
        assert_eq!(node.db.accept_paid_envelope(&second).await.unwrap(), PaidAcceptance::PaymentReused);
    }
    node.money.shutdown().await.unwrap();
}

/// Other readers of the same record keep the refusal they have today.
#[tokio::test]
async fn ordinary_status_reads_stay_refused_while_not_ready() {
    let node = Node::start(false, Some(record(PaymentStatus::Settled, PaymentDirection::Incoming))).await;
    let hash = hex::encode(hash());
    assert!(matches!(node.money.get_payment_status(&hash).await, Err(LightningError::NotReady)));
    assert!(matches!(node.money.verify_payment(&hash).await, Err(LightningError::NotReady)));
    assert!(matches!(node.verifier.get_payment_status(&hash).await, Err(LightningError::NotReady)));
    assert!(node.money.gate_payment_status(&hash).await.is_ok());
    node.money.shutdown().await.unwrap();
}
