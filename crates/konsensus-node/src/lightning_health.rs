//! The Lightning check at startup.
//!
//! On every normal start the wallet is still synchronizing, and Lightning
//! refuses money work with `NotReady` until it is done. That is expected, so it
//! is said at INFO. A warning is kept for a real failure, and for a wallet that
//! is still not ready once the sync window has passed. This only reports; the
//! money-ready gate itself is unchanged.

use std::sync::{Arc, Weak};
use std::time::Duration;

use konsensus_core::traits::lightning::{LightningError, LightningProvider};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::NodeTier;

/// How long a start may synchronize before the node warns that payments are
/// still off: the age at which the API marks a wallet sync stale.
pub(crate) const SYNC_WINDOW: Duration = konsensus_api::freshness::WALLET_SYNC_STALE_AFTER;

/// What the startup check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupCheck {
    Ready,
    Syncing,
    Failed,
}

fn fix_hint(tier: NodeTier) -> &'static str {
    match tier {
        NodeTier::Cloud => {
            "Cloud tier: check your hosted node URL and ensure the service is running."
        }
        NodeTier::Light => {
            "Light tier: check your LDK or LND settings in konsensus.toml.\n  \
             If using hosted Lightning, ensure your configured provider is reachable.\n  \
             You can switch to mock Lightning for testing: set [lightning] backend = \"mock\"."
        }
        NodeTier::Full => {
            "Full tier: LDK embedded Lightning is enabled by default. Your node IS its own Lightning node.\n  \
             Keys are derived from your mnemonic. Fund the on-chain wallet to open channels.\n  \
             To use your own LND instead, set [lightning] backend = \"lnd\" and configure its REST credentials."
        }
    }
}

/// Read the balance once and say what it means. Never aborts startup: the
/// node can still work for non-payment tasks, and the payment gate refuses
/// money work until Lightning is ready.
pub(crate) async fn check_at_startup(
    lightning: &dyn LightningProvider,
    backend: &str,
    tier: NodeTier,
    is_mock: bool,
) -> StartupCheck {
    match lightning.get_balance_msat().await {
        Ok(balance_msat) => {
            info!(backend, balance_msat, "lightning health check passed");
            StartupCheck::Ready
        }
        Err(LightningError::NotReady) if !is_mock => {
            info!(
                backend,
                "lightning wallet is syncing; payments start when it is ready"
            );
            StartupCheck::Syncing
        }
        Err(e) if is_mock => {
            // Mock should never fail, but log just in case.
            warn!(error = %e, "mock lightning health check failed (unexpected)");
            StartupCheck::Failed
        }
        Err(e) => {
            warn!(
                backend,
                error = %e,
                "lightning health check FAILED — payments will not work"
            );
            warn!("Fix: {}", fix_hint(tier));
            StartupCheck::Failed
        }
    }
}

/// After `window`, warn once if payments are still not ready. Returns whether
/// it warned. Stops quietly on shutdown or when the provider is gone.
pub(crate) async fn warn_if_still_syncing(
    lightning: Weak<dyn LightningProvider>,
    window: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        biased;
        _ = shutdown_rx.changed() => return false,
        _ = tokio::time::sleep(window) => {}
    }
    if *shutdown_rx.borrow() {
        return false;
    }
    let Some(lightning) = lightning.upgrade() else {
        return false;
    };
    if lightning.money_ready().await {
        return false;
    }
    let state = lightning.readiness().await.state;
    warn!(
        state = %state,
        window_secs = window.as_secs(),
        "lightning wallet is still not ready after the sync window; payments stay off until it is. Check that the chain source is reachable"
    );
    true
}

/// Start-up entry point: check once, and if the wallet is syncing, watch the
/// sync window in the background.
pub(crate) async fn check_and_watch(
    lightning: &Arc<dyn LightningProvider>,
    backend: &str,
    tier: NodeTier,
    is_mock: bool,
    shutdown_rx: watch::Receiver<bool>,
) {
    if check_at_startup(lightning.as_ref(), backend, tier, is_mock).await == StartupCheck::Syncing {
        tokio::spawn(warn_if_still_syncing(
            Arc::downgrade(lightning),
            SYNC_WINDOW,
            shutdown_rx,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use konsensus_core::traits::lightning::{Invoice, PaymentDetails};
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A provider whose balance read and readiness the test sets.
    struct Stub {
        balance: fn() -> Result<u64, LightningError>,
        ready: AtomicBool,
    }

    #[async_trait]
    impl LightningProvider for Stub {
        async fn money_ready(&self) -> bool {
            self.ready.load(Ordering::SeqCst)
        }
        async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
            Err(LightningError::Backend("unused".into()))
        }
        async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::Backend("unused".into()))
        }
        async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::PaymentNotFound("missing".into()))
        }
        async fn get_balance_msat(&self) -> Result<u64, LightningError> {
            (self.balance)()
        }
        async fn is_available(&self) -> bool {
            self.ready.load(Ordering::SeqCst)
        }
    }

    fn stub(
        balance: fn() -> Result<u64, LightningError>,
        ready: bool,
    ) -> Arc<dyn LightningProvider> {
        Arc::new(Stub {
            balance,
            ready: AtomicBool::new(ready),
        })
    }

    /// Run `f` with a plain-text subscriber on this thread; return what it logged.
    async fn logged<F: std::future::Future<Output = T>, T>(f: F) -> (T, String) {
        let log = tempfile::tempfile().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(log.try_clone().unwrap())
            .finish();
        let out = {
            let _guard = tracing::subscriber::set_default(subscriber);
            f.await
        };
        let mut log = log;
        log.seek(SeekFrom::Start(0)).unwrap();
        let mut output = String::new();
        log.read_to_string(&mut output).unwrap();
        (out, output)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn syncing_at_startup_is_info_with_no_fix_hint() {
        for tier in [NodeTier::Full, NodeTier::Light, NodeTier::Cloud] {
            let lightning = stub(|| Err(LightningError::NotReady), false);
            let (check, output) =
                logged(check_at_startup(lightning.as_ref(), "ldk", tier, false)).await;
            assert_eq!(check, StartupCheck::Syncing);
            assert!(
                output.contains("INFO")
                    && output
                        .contains("lightning wallet is syncing; payments start when it is ready"),
                "{output}"
            );
            assert!(!output.contains("WARN"), "{output}");
            assert!(!output.contains("FAILED"), "{output}");
            assert!(!output.contains("Fix:"), "{output}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_real_failure_still_warns_with_the_fix() {
        let lightning = stub(|| Err(LightningError::Backend("refused".into())), false);
        let (check, output) = logged(check_at_startup(
            lightning.as_ref(),
            "lnd",
            NodeTier::Light,
            false,
        ))
        .await;
        assert_eq!(check, StartupCheck::Failed);
        assert!(
            output.contains("WARN") && output.contains("lightning health check FAILED"),
            "{output}"
        );
        assert!(output.contains("Fix: Light tier"), "{output}");
        assert!(!output.contains("is syncing"), "{output}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_ready_wallet_passes() {
        let lightning = stub(|| Ok(5_000), true);
        let (check, output) = logged(check_at_startup(
            lightning.as_ref(),
            "ldk",
            NodeTier::Full,
            false,
        ))
        .await;
        assert_eq!(check, StartupCheck::Ready);
        assert!(output.contains("lightning health check passed"), "{output}");
        assert!(!output.contains("WARN"), "{output}");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn still_not_ready_after_the_window_warns_once() {
        let lightning = stub(|| Err(LightningError::NotReady), false);
        let (_tx, rx) = watch::channel(false);
        let (warned, output) = logged(warn_if_still_syncing(
            Arc::downgrade(&lightning),
            SYNC_WINDOW,
            rx,
        ))
        .await;
        assert!(warned);
        assert!(
            output.contains("WARN")
                && output.contains("lightning wallet is still not ready after the sync window"),
            "{output}"
        );
        assert_eq!(output.matches("WARN").count(), 1, "{output}");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ready_within_the_window_says_nothing() {
        let lightning = stub(|| Ok(0), true);
        let (_tx, rx) = watch::channel(false);
        let (warned, output) = logged(warn_if_still_syncing(
            Arc::downgrade(&lightning),
            SYNC_WINDOW,
            rx,
        ))
        .await;
        assert!(!warned);
        assert!(output.is_empty(), "{output}");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn shutdown_or_a_dropped_provider_says_nothing() {
        let lightning = stub(|| Err(LightningError::NotReady), false);
        let (tx, rx) = watch::channel(false);
        tx.send(true).unwrap();
        let (warned, output) = logged(warn_if_still_syncing(
            Arc::downgrade(&lightning),
            SYNC_WINDOW,
            rx,
        ))
        .await;
        assert!(!warned && output.is_empty(), "{output}");

        let weak = Arc::downgrade(&lightning);
        drop(lightning);
        let (_tx, rx) = watch::channel(false);
        let (warned, output) = logged(warn_if_still_syncing(weak, SYNC_WINDOW, rx)).await;
        assert!(!warned && output.is_empty(), "{output}");
    }
}
