use konsensus_core::traits::lightning::{LightningError, LightningProvider};
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
    async fn money_ready(&self) -> bool { !self.0.load(Ordering::SeqCst) }
    async fn is_available(&self) -> bool { true }
    async fn create_invoice(&self, _: u64, _: &str, _: u32)
        -> Result<konsensus_core::traits::lightning::Invoice, LightningError> { unreachable!() }
    async fn pay_invoice(&self, _: &str)
        -> Result<konsensus_core::traits::lightning::PaymentDetails, LightningError> { unreachable!() }
    async fn get_payment_status(&self, _: &str)
        -> Result<konsensus_core::traits::lightning::PaymentDetails, LightningError> { unreachable!() }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> { Ok(1) }
}

#[tokio::test(start_paused = true)]
async fn sync_failure_revokes_cached_readiness_and_money_dispatch_before_next_poll() {
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
    assert!(!provider.money_ready().await);
    let readiness = provider.readiness().await;
    assert!(!readiness.money_ready);
    assert_eq!(readiness.state, "synchronizing");
    assert!(matches!(provider.create_invoice(1, "x", 60).await, Err(LightningError::NotReady)));
    provider.shutdown().await.unwrap();
}
