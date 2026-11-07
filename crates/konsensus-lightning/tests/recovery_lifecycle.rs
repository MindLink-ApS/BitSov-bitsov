use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails, PaymentDirection, PaymentStatus,
};
use konsensus_lightning::{MockLightningProvider, RecoveringLightning};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

fn offline() -> LightningError {
    LightningError::ChainSourceUnavailable {
        network: "bitcoin".into(),
        service: "localhost".into(),
        attempts: 5,
        elapsed_ms: 60_000,
        cause: "unavailable".into(),
    }
}

#[tokio::test(start_paused = true)]
async fn backoff_has_one_owner_and_shutdown_cancels_retries() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = attempts.clone();
    let provider = Arc::new(
        RecoveringLightning::new(
            move || {
                count.fetch_add(1, Ordering::SeqCst);
                async { Err(offline()) }
            },
            Default::default(),
        )
        .await
        .unwrap(),
    );
    tokio::task::yield_now().await;
    for (elapsed, expected) in [(4, 1), (1, 2), (9, 2), (1, 3), (19, 3), (1, 4)] {
        // Many concurrent readers may never create their own retry work.
        let readers: Vec<_> = (0..30)
            .map(|_| {
                let p = provider.clone();
                tokio::spawn(async move { p.readiness().await })
            })
            .collect();
        for reader in readers {
            assert!(!reader.await.unwrap().money_ready);
        }
        tokio::time::advance(Duration::from_secs(elapsed)).await;
        tokio::task::yield_now().await;
        assert_eq!(attempts.load(Ordering::SeqCst), expected);
    }
    provider.shutdown().await.unwrap();
    tokio::time::advance(Duration::from_secs(600)).await;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 4);
    assert_eq!(provider.readiness().await.state, "stopped");
}

#[tokio::test(start_paused = true)]
async fn recovery_starts_once_and_every_offline_money_method_fails_closed() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let provider = RecoveringLightning::new(
        move || {
            let first = count.fetch_add(1, Ordering::SeqCst) == 0;
            async move {
                if first {
                    Err(offline())
                } else {
                    Ok(Arc::new(MockLightningProvider::new()) as Arc<dyn LightningProvider>)
                }
            }
        },
        Default::default(),
    )
    .await
    .unwrap();
    macro_rules! refused {
        ($call:expr) => {
            assert!(matches!($call.await, Err(LightningError::NotReady)));
        };
    }
    refused!(provider.create_invoice(1000, "x", 60));
    refused!(provider.create_stateless_invoice(1000, "x", 60));
    refused!(provider.pay_invoice("x"));
    refused!(provider.pay_invoice_with_fee_limit("x", 100));
    refused!(provider.keysend("x", 1000, None));
    refused!(provider.keysend_with_fee_limit("x", 1000, None, 100));
    refused!(provider.keysend_with_binding("x", 1000, b"x"));
    refused!(provider.open_channel("x", "x", 1000, false, None));
    refused!(provider.close_channel("x", false));
    refused!(provider.send_onchain("x", 1000, None));
    refused!(provider.create_hodl_invoice("x", 1000, "x", 60));
    refused!(provider.settle_hodl_invoice("x"));
    refused!(provider.cancel_hodl_invoice("x"));
    refused!(provider.quote_liquidity("x", 1000, 100));
    refused!(provider.accept_liquidity("x", "x"));
    assert!(matches!(
        provider.liquidity_quote("x", "x"),
        Err(LightningError::NotReady)
    ));
    assert_eq!(
        provider.wallet_sync().await,
        konsensus_core::traits::lightning::WalletSync::NeverSynced
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    assert!(provider.money_ready().await);
    assert!(!provider
        .create_invoice(1000, "online", 60)
        .await
        .unwrap()
        .bolt11
        .is_empty());
    tokio::time::advance(Duration::from_secs(600)).await;
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    provider.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn drop_cancels_pending_retry_factory() {
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    let provider = RecoveringLightning::new(
        move || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    return Err(offline());
                }
                futures::future::pending().await
            }
        },
        Default::default(),
    )
    .await
    .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    assert_eq!(count.load(Ordering::SeqCst), 2);
    // shutdown joins the pending worker, so cancellation is observable, not detached.
    provider.shutdown().await.unwrap();
    assert_eq!(provider.readiness().await.state, "stopped");
}

#[tokio::test]
async fn permanent_local_errors_are_not_retried() {
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    let result = RecoveringLightning::new(
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err(LightningError::InvalidStartupConfig("bad key".into())) }
        },
        Default::default(),
    )
    .await;
    assert!(matches!(
        result,
        Err(LightningError::InvalidStartupConfig(_))
    ));
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

struct SlowShutdown {
    entered: Arc<AtomicUsize>,
    release: Arc<tokio::sync::Notify>,
}
#[async_trait::async_trait]
impl LightningProvider for SlowShutdown {
    async fn create_invoice(
        &self,
        _: u64,
        _: &str,
        _: u32,
    ) -> Result<konsensus_core::traits::lightning::Invoice, LightningError> {
        unreachable!()
    }
    async fn pay_invoice(
        &self,
        _: &str,
    ) -> Result<konsensus_core::traits::lightning::PaymentDetails, LightningError> {
        unreachable!()
    }
    async fn get_payment_status(
        &self,
        _: &str,
    ) -> Result<konsensus_core::traits::lightning::PaymentDetails, LightningError> {
        unreachable!()
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(0)
    }
    async fn is_available(&self) -> bool {
        true
    }
    async fn shutdown(&self) -> Result<(), LightningError> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.release.notified().await;
        Ok(())
    }
}

#[tokio::test]
async fn cancelled_shutdown_does_not_detach_persistence_or_report_ready() {
    let entered = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    let backend = Arc::new(SlowShutdown {
        entered: entered.clone(),
        release: release.clone(),
    });
    let provider = Arc::new(
        RecoveringLightning::new(
            move || {
                let p = backend.clone();
                async { Ok(p as Arc<dyn LightningProvider>) }
            },
            Default::default(),
        )
        .await
        .unwrap(),
    );
    tokio::task::yield_now().await;
    let p = provider.clone();
    let first = tokio::spawn(async move { p.shutdown().await });
    while entered.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    first.abort();
    let _ = first.await;
    let p = provider.clone();
    let second = tokio::spawn(async move { p.shutdown().await });
    tokio::task::yield_now().await;
    assert!(
        !second.is_finished(),
        "shutdown must still await backend persistence"
    );
    release.notify_one();
    second.await.unwrap().unwrap();
    assert_eq!(entered.load(Ordering::SeqCst), 1);
    assert!(!provider.money_ready().await);
    assert_eq!(provider.readiness().await.state, "stopped");
}

struct FailingSync(std::sync::atomic::AtomicBool);
#[async_trait::async_trait]
impl LightningProvider for FailingSync {
    fn chain_sync_status(&self) -> Option<konsensus_core::traits::lightning::ChainSyncStatus> {
        self.0.load(Ordering::SeqCst).then_some(
            konsensus_core::traits::lightning::ChainSyncStatus::Stalled {
                since: 123,
                last_error_kind: konsensus_core::traits::lightning::ChainSyncErrorKind::SyncFailed,
            },
        )
    }
    async fn money_ready(&self) -> bool { true }
    async fn is_available(&self) -> bool { true }
    async fn create_invoice(&self, amount: u64, description: &str, expiry: u32)
        -> Result<konsensus_core::traits::lightning::Invoice, LightningError> {
        MockLightningProvider::new().create_invoice(amount, description, expiry).await
    }
    async fn pay_invoice(&self, _: &str)
        -> Result<konsensus_core::traits::lightning::PaymentDetails, LightningError> { unreachable!() }
    async fn get_payment_status(&self, _: &str)
        -> Result<konsensus_core::traits::lightning::PaymentDetails, LightningError> { unreachable!() }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> { Ok(1) }
}

#[tokio::test(start_paused = true)]
async fn sync_failure_is_diagnostic_only_before_and_after_next_poll() {
    let backend = Arc::new(FailingSync(std::sync::atomic::AtomicBool::new(false)));
    let factory_backend = backend.clone();
    let provider = RecoveringLightning::new(move || {
        let backend = factory_backend.clone();
        async { Ok(backend as Arc<dyn LightningProvider>) }
    }, Default::default()).await.unwrap();
    tokio::task::yield_now().await;
    assert!(provider.money_ready().await);
    assert!(provider.readiness().await.money_ready);
    backend.0.store(true, Ordering::SeqCst);
    // No clock advance / monitor tick between a live failure and these calls.
    for _ in 0..2 {
        assert!(provider.chain_sync_status().is_some());
        assert!(provider.money_ready().await);
        let readiness = provider.readiness().await;
        assert!(readiness.money_ready);
        assert_eq!(readiness.state, "ready");
        assert_eq!(readiness.events.last().unwrap().state, "ready");
        assert!(readiness.events.last().unwrap().money_ready);
        assert!(provider.is_payment_capable().await);
        assert_eq!(provider.wallet_sync().await, konsensus_core::traits::lightning::WalletSync::Live);
        assert!(provider.create_invoice(1, "x", 60).await.is_ok());
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
    }
    provider.shutdown().await.unwrap();
}

const SYNCED: u64 = 1_700_000_000;

/// A local payment store with a chain-sync flag, like the embedded backend: its
/// reads need no chain, and an unknown hash is `PaymentNotFound`.
struct Store {
    ready: std::sync::atomic::AtomicBool,
    funding: bool,
    cutoff: std::sync::Mutex<Option<u64>>,
    record: std::sync::Mutex<Option<PaymentDetails>>,
}

impl Store {
    fn new(ready: bool, record: Option<PaymentDetails>) -> Arc<Self> {
        Arc::new(Self {
            ready: ready.into(),
            funding: false,
            cutoff: Some(SYNCED).into(),
            record: record.into(),
        })
    }
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
    fn gate_settlement_cutoff(&self) -> Option<u64> {
        *self.cutoff.lock().unwrap()
    }
    async fn money_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }
    async fn is_available(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }
    async fn is_funding_payment(&self, hash: &str) -> Result<bool, LightningError> {
        self.read(hash).map(|_| self.funding)
    }
    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        self.read(hash)
    }
    async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
        Ok(Invoice {
            bolt11: "lnbcrt1".into(),
            payment_hash: "aa".into(),
            amount_msat: 1,
            description: String::new(),
            expiry_secs: 60,
            created_at: 0,
        })
    }
    async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        self.read("aa")
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(0)
    }
}

fn record(status: PaymentStatus, direction: PaymentDirection) -> PaymentDetails {
    PaymentDetails {
        payment_hash: "aa".into(),
        preimage: (status == PaymentStatus::Settled).then(|| "bb".into()),
        amount_msat: 10_000,
        status,
        direction,
        timestamp: SYNCED,
        memo: None,
        fee_msat: None,
    }
}

async fn over(store: Arc<Store>) -> RecoveringLightning {
    RecoveringLightning::new(
        move || {
            let backend = store.clone() as Arc<dyn LightningProvider>;
            async move { Ok(backend) }
        },
        Default::default(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn not_ready_gate_read_confirms_only_a_stored_inbound_settlement() {
    let settled = record(PaymentStatus::Settled, PaymentDirection::Incoming);
    let provider = over(Store::new(false, Some(settled))).await;
    assert_eq!(provider.gate_payment_status("aa").await.unwrap().status, PaymentStatus::Settled);
    assert!(!provider.is_funding_payment("aa").await.unwrap());
    // Everything else on the money path stays closed for the same record.
    assert!(matches!(provider.get_payment_status("aa").await, Err(LightningError::NotReady)));
    assert!(matches!(provider.verify_payment("aa").await, Err(LightningError::NotReady)));
    assert!(matches!(provider.create_invoice(1, "", 60).await, Err(LightningError::NotReady)));
    assert!(matches!(provider.pay_invoice("lnbcrt1").await, Err(LightningError::NotReady)));
    provider.shutdown().await.unwrap();
}

#[tokio::test]
async fn not_ready_gate_read_refuses_anything_but_a_stored_inbound_settlement() {
    for stored in [
        record(PaymentStatus::Pending, PaymentDirection::Incoming),
        record(PaymentStatus::InFlight, PaymentDirection::Incoming),
        record(PaymentStatus::Failed, PaymentDirection::Incoming),
        record(PaymentStatus::Expired, PaymentDirection::Incoming),
        record(PaymentStatus::Settled, PaymentDirection::Outgoing),
    ] {
        let label = format!("{:?} {:?}", stored.status, stored.direction);
        let provider = over(Store::new(false, Some(stored))).await;
        assert!(
            matches!(provider.gate_payment_status("aa").await, Err(LightningError::NotReady)),
            "{label}"
        );
        provider.shutdown().await.unwrap();
    }
    // An unknown hash reads as not ready, as it always has here, on both reads.
    let provider = over(Store::new(false, None)).await;
    assert!(matches!(provider.gate_payment_status("aa").await, Err(LightningError::NotReady)));
    assert!(matches!(provider.is_funding_payment("aa").await, Err(LightningError::NotReady)));
    provider.shutdown().await.unwrap();
}

#[tokio::test]
async fn not_ready_gate_read_refuses_a_settlement_past_the_cutoff() {
    let at_cutoff = record(PaymentStatus::Settled, PaymentDirection::Incoming);
    let mut past_cutoff = at_cutoff.clone();
    past_cutoff.timestamp = SYNCED + 1;

    let provider = over(Store::new(false, Some(at_cutoff.clone()))).await;
    assert!(provider.gate_payment_status("aa").await.is_ok(), "the last second still counts");
    provider.shutdown().await.unwrap();

    let provider = over(Store::new(false, Some(past_cutoff))).await;
    assert!(matches!(provider.gate_payment_status("aa").await, Err(LightningError::NotReady)));
    provider.shutdown().await.unwrap();

    // A backend with no good sync on record confirms nothing.
    let store = Store::new(false, Some(at_cutoff));
    *store.cutoff.lock().unwrap() = None;
    let provider = over(store).await;
    assert!(matches!(provider.gate_payment_status("aa").await, Err(LightningError::NotReady)));
    provider.shutdown().await.unwrap();
}

#[tokio::test]
async fn gate_read_stays_refused_without_a_backend_or_when_stopping() {
    let offline = RecoveringLightning::new(|| async { Err(offline()) }, Default::default())
        .await
        .unwrap();
    assert!(matches!(offline.gate_payment_status("aa").await, Err(LightningError::NotReady)));
    assert!(matches!(offline.is_funding_payment("aa").await, Err(LightningError::NotReady)));
    offline.shutdown().await.unwrap();

    let settled = record(PaymentStatus::Settled, PaymentDirection::Incoming);
    let stopped = over(Store::new(false, Some(settled))).await;
    stopped.shutdown().await.unwrap();
    assert!(matches!(stopped.gate_payment_status("aa").await, Err(LightningError::NotReady)));
    assert!(matches!(stopped.is_funding_payment("aa").await, Err(LightningError::NotReady)));
}

#[tokio::test]
async fn ready_gate_read_answers_exactly_like_the_ordinary_read() {
    // Ready: the cutoff plays no part, even with no good sync on record.
    let store = Store::new(true, Some(record(PaymentStatus::Settled, PaymentDirection::Incoming)));
    *store.cutoff.lock().unwrap() = None;
    let provider = over(store).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !provider.money_ready().await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(provider.gate_payment_status("aa").await.is_ok());
    provider.shutdown().await.unwrap();

    let store = Store::new(true, Some(record(PaymentStatus::Failed, PaymentDirection::Incoming)));
    let provider = over(store).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !provider.money_ready().await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(provider.gate_payment_status("aa").await.unwrap().status, PaymentStatus::Failed);
    assert_eq!(provider.get_payment_status("aa").await.unwrap().status, PaymentStatus::Failed);
    provider.shutdown().await.unwrap();

    let provider = over(Store::new(true, None)).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !provider.money_ready().await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        provider.gate_payment_status("aa").await,
        Err(LightningError::PaymentNotFound(_))
    ));
    provider.shutdown().await.unwrap();
}
