//! The Lightning check at startup, and what the node says until payments are on.
//!
//! Before Lightning is money-ready, every balance read is refused with
//! `NotReady`, whatever the reason. So the check reads the readiness phase:
//!
//! - `synchronizing`: normal on every start, said at INFO;
//! - `offline` or `retrying`: the chain service is unreachable, said at WARN
//!   once, in the same words as the boot retry line;
//! - `failed` or `stopped`: Lightning gave up, said at WARN with the tier hint.
//!
//! A background watcher then says each of those once as the phase changes,
//! warns once if a sync is still running after the sync window, and says at
//! INFO when payments are on. This only reports; the money-ready gate itself
//! is unchanged.

use std::sync::{Arc, Weak};
use std::time::Duration;

use konsensus_core::traits::lightning::{LightningError, LightningProvider};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::NodeTier;

/// How long a start may synchronize before the node warns that payments are
/// still off: the age at which the API marks a wallet sync stale.
pub(crate) const SYNC_WINDOW: Duration = konsensus_api::freshness::WALLET_SYNC_STALE_AFTER;

/// How often the watcher reads the readiness phase.
const POLL: Duration = Duration::from_secs(5);

/// What the node knows about where it runs, for the log lines.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Context {
    /// Lightning backend name, such as `ldk`.
    pub backend: &'static str,
    /// Chain service kind, such as `esplora`. Never its URL.
    pub chain_source: &'static str,
    pub tier: NodeTier,
    pub is_mock: bool,
}

/// What the startup check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupCheck {
    Ready,
    Syncing,
    Offline,
    Failed,
}

/// The readiness phase, as `RecoveringLightning` names it. A provider without
/// phases reports `offline` while not ready, so an unknown phase is not a
/// sync: only the named sync phase is treated as normal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Ready,
    Synchronizing,
    Offline,
    Failed,
}

fn phase(state: &str) -> Phase {
    match state {
        "ready" => Phase::Ready,
        "synchronizing" => Phase::Synchronizing,
        "failed" | "stopped" => Phase::Failed,
        _ => Phase::Offline,
    }
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

fn log_syncing(ctx: &Context) {
    info!(
        backend = ctx.backend,
        "lightning wallet is syncing; payments start when it is ready"
    );
}

fn log_offline(ctx: &Context, state: &str) {
    warn!(
        code = "LIGHTNING_CHAIN_SOURCE_UNAVAILABLE",
        backend = ctx.backend,
        chain_source = ctx.chain_source,
        state,
        "Bitcoin chain service unavailable; node remains not ready and payments stay off. It retries in the background; check that the chain service is reachable"
    );
}

fn log_failed(ctx: &Context, error: &dyn std::fmt::Display) {
    warn!(
        backend = ctx.backend,
        error = %error,
        "lightning health check FAILED — payments will not work"
    );
    warn!("Fix: {}", fix_hint(ctx.tier));
}

/// Read the balance once and say what it means. Never aborts startup: the
/// node can still work for non-payment tasks, and the payment gate refuses
/// money work until Lightning is ready.
pub(crate) async fn check_at_startup(
    lightning: &dyn LightningProvider,
    ctx: &Context,
) -> StartupCheck {
    match lightning.get_balance_msat().await {
        Ok(balance_msat) => {
            info!(
                backend = ctx.backend,
                balance_msat, "lightning health check passed"
            );
            StartupCheck::Ready
        }
        Err(e) if ctx.is_mock => {
            // Mock should never fail, but log just in case.
            warn!(error = %e, "mock lightning health check failed (unexpected)");
            StartupCheck::Failed
        }
        Err(LightningError::NotReady) => {
            let state = lightning.readiness().await.state;
            match phase(&state) {
                // Ready between the two reads: the sync just finished.
                Phase::Ready | Phase::Synchronizing => {
                    log_syncing(ctx);
                    StartupCheck::Syncing
                }
                Phase::Offline => {
                    log_offline(ctx, &state);
                    StartupCheck::Offline
                }
                Phase::Failed => {
                    log_failed(ctx, &format_args!("lightning {state}"));
                    StartupCheck::Failed
                }
            }
        }
        Err(e) => {
            log_failed(ctx, &e);
            StartupCheck::Failed
        }
    }
}

/// Until payments are on: say `offline` once and `failed` once as the phase
/// reaches them, warn once if a sync is still running after `window`, and say
/// when payments are on. `already` is what the startup check already said.
/// Stops on shutdown, when the provider is gone, on `failed` (the retry
/// worker has stopped), or once money-ready.
pub(crate) async fn watch_until_ready(
    lightning: Weak<dyn LightningProvider>,
    ctx: Context,
    already: StartupCheck,
    window: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let started = tokio::time::Instant::now();
    let mut said_offline = already == StartupCheck::Offline;
    let mut said_window = false;
    let mut tick = tokio::time::interval(POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => return,
            _ = tick.tick() => {}
        }
        if *shutdown_rx.borrow() {
            return;
        }
        let Some(lightning) = lightning.upgrade() else {
            return;
        };
        if lightning.money_ready().await {
            info!(
                backend = ctx.backend,
                "lightning wallet is ready; payments are on"
            );
            return;
        }
        let state = lightning.readiness().await.state;
        drop(lightning);
        match phase(&state) {
            Phase::Failed => {
                log_failed(&ctx, &format_args!("lightning {state}"));
                return;
            }
            Phase::Offline => {
                if !said_offline {
                    log_offline(&ctx, &state);
                    said_offline = true;
                }
            }
            Phase::Ready | Phase::Synchronizing => {
                if !said_window && started.elapsed() >= window {
                    warn!(
                        backend = ctx.backend,
                        chain_source = ctx.chain_source,
                        window_secs = window.as_secs(),
                        "lightning wallet is still syncing after the sync window; payments stay off until it is ready. Check that the chain service is reachable"
                    );
                    said_window = true;
                }
            }
        }
    }
}

/// Start-up entry point: check once, then watch in the background until
/// payments are on, unless the check found them on or found a final failure.
pub(crate) async fn check_and_watch(
    lightning: &Arc<dyn LightningProvider>,
    ctx: Context,
    shutdown_rx: watch::Receiver<bool>,
) {
    let found = check_at_startup(lightning.as_ref(), &ctx).await;
    if matches!(found, StartupCheck::Syncing | StartupCheck::Offline) {
        tokio::spawn(watch_until_ready(
            Arc::downgrade(lightning),
            ctx,
            found,
            SYNC_WINDOW,
            shutdown_rx,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use konsensus_core::traits::lightning::{Invoice, LightningReadiness, PaymentDetails};
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::Mutex;

    /// A provider whose balance read is fixed and whose readiness follows a
    /// script: each read takes the next phase, then the last one repeats.
    struct Stub {
        balance: fn() -> Result<u64, LightningError>,
        script: Mutex<Vec<&'static str>>,
    }

    impl Stub {
        fn current(&self) -> &'static str {
            let script = self.script.lock().unwrap();
            script[0]
        }
        fn advance(&self) -> &'static str {
            let mut script = self.script.lock().unwrap();
            if script.len() > 1 {
                script.remove(0)
            } else {
                script[0]
            }
        }
    }

    #[async_trait]
    impl LightningProvider for Stub {
        async fn money_ready(&self) -> bool {
            self.current() == "ready"
        }
        async fn readiness(&self) -> LightningReadiness {
            let state = self.advance();
            LightningReadiness {
                money_ready: state == "ready",
                state: state.into(),
                retry_attempt: 0,
                retry_after_secs: None,
                events: Vec::new(),
            }
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
            self.current() == "ready"
        }
    }

    fn stub(
        balance: fn() -> Result<u64, LightningError>,
        script: &[&'static str],
    ) -> Arc<dyn LightningProvider> {
        Arc::new(Stub {
            balance,
            script: Mutex::new(script.to_vec()),
        })
    }

    fn not_ready() -> Result<u64, LightningError> {
        Err(LightningError::NotReady)
    }

    fn ctx(tier: NodeTier) -> Context {
        Context {
            backend: "ldk",
            chain_source: "esplora",
            tier,
            is_mock: false,
        }
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

    const SYNCING: &str = "lightning wallet is syncing; payments start when it is ready";
    const OFFLINE: &str = "Bitcoin chain service unavailable; node remains not ready";
    const FAILED: &str = "lightning health check FAILED";
    const WINDOW: &str = "still syncing after the sync window";
    const READY: &str = "lightning wallet is ready; payments are on";

    async fn startup(script: &[&'static str], tier: NodeTier) -> (StartupCheck, String) {
        let lightning = stub(not_ready, script);
        logged(check_at_startup(lightning.as_ref(), &ctx(tier))).await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn synchronizing_at_startup_is_info_with_no_fix_hint() {
        for tier in [NodeTier::Full, NodeTier::Light, NodeTier::Cloud] {
            let (check, output) = startup(&["synchronizing"], tier).await;
            assert_eq!(check, StartupCheck::Syncing);
            assert!(
                output.contains("INFO") && output.contains(SYNCING),
                "{output}"
            );
            assert!(!output.contains("WARN"), "{output}");
            assert!(!output.contains("Fix:"), "{output}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn offline_at_startup_warns_naming_the_chain_service() {
        for state in ["offline", "retrying"] {
            let (check, output) = startup(&[state], NodeTier::Full).await;
            assert_eq!(check, StartupCheck::Offline);
            assert!(
                output.contains("WARN") && output.contains(OFFLINE),
                "{output}"
            );
            assert!(output.contains("chain_source=\"esplora\""), "{output}");
            assert!(
                output.contains("code=\"LIGHTNING_CHAIN_SOURCE_UNAVAILABLE\""),
                "{output}"
            );
            assert!(!output.contains(SYNCING), "{output}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_unknown_phase_is_not_called_a_sync() {
        let (check, output) = startup(&[""], NodeTier::Full).await;
        assert_eq!(check, StartupCheck::Offline);
        assert!(!output.contains(SYNCING), "{output}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_at_startup_warns_with_the_fix() {
        for state in ["failed", "stopped"] {
            let (check, output) = startup(&[state], NodeTier::Full).await;
            assert_eq!(check, StartupCheck::Failed);
            assert!(
                output.contains("WARN") && output.contains(FAILED),
                "{output}"
            );
            assert!(output.contains("Fix: Full tier"), "{output}");
            assert!(!output.contains(SYNCING), "{output}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_backend_error_still_warns_with_the_fix() {
        let lightning = stub(
            || Err(LightningError::Backend("refused".into())),
            &["offline"],
        );
        let (check, output) =
            logged(check_at_startup(lightning.as_ref(), &ctx(NodeTier::Light))).await;
        assert_eq!(check, StartupCheck::Failed);
        assert!(
            output.contains("WARN") && output.contains(FAILED),
            "{output}"
        );
        assert!(output.contains("Fix: Light tier"), "{output}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_ready_wallet_passes() {
        let lightning = stub(|| Ok(5_000), &["ready"]);
        let (check, output) =
            logged(check_at_startup(lightning.as_ref(), &ctx(NodeTier::Full))).await;
        assert_eq!(check, StartupCheck::Ready);
        assert!(output.contains("lightning health check passed"), "{output}");
        assert!(!output.contains("WARN"), "{output}");
    }

    async fn watched(script: &[&'static str], already: StartupCheck, window: Duration) -> String {
        let lightning = stub(not_ready, script);
        let (_tx, rx) = watch::channel(false);
        // Every script ends in `ready` or `failed`, so the watch must end. The
        // clock is paused: a watch that never ends fails here, not by hanging.
        let (ended, output) = logged(tokio::time::timeout(
            WATCH_BOUND,
            watch_until_ready(
                Arc::downgrade(&lightning),
                ctx(NodeTier::Full),
                already,
                window,
                rx,
            ),
        ))
        .await;
        assert!(ended.is_ok(), "the watch did not end: {output}");
        output
    }

    /// Far past every script and window in these tests, in paused time.
    const WATCH_BOUND: Duration = Duration::from_secs(24 * 3600);

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn offline_is_said_once_across_retries() {
        let mut script = Vec::new();
        for _ in 0..5 {
            script.extend(["offline", "retrying"]);
        }
        script.extend(["synchronizing", "ready"]);
        let output = watched(&script, StartupCheck::Syncing, SYNC_WINDOW).await;
        assert_eq!(output.matches(OFFLINE).count(), 1, "{output}");
        assert_eq!(output.matches(READY).count(), 1, "{output}");
        assert!(!output.contains(FAILED), "{output}");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn offline_said_at_startup_is_not_said_again() {
        let output = watched(
            &["offline", "retrying", "offline", "ready"],
            StartupCheck::Offline,
            SYNC_WINDOW,
        )
        .await;
        assert!(!output.contains(OFFLINE), "{output}");
        assert!(output.contains(READY), "{output}");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn failed_is_said_at_once_with_the_fix_and_ends_the_watch() {
        let output = watched(
            &["offline", "retrying", "failed"],
            StartupCheck::Offline,
            SYNC_WINDOW,
        )
        .await;
        assert_eq!(output.matches(FAILED).count(), 1, "{output}");
        assert_eq!(output.matches("Fix: Full tier").count(), 1, "{output}");
        assert!(!output.contains(WINDOW), "{output}");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn failed_is_said_without_waiting_for_the_window() {
        let started = tokio::time::Instant::now();
        let output = watched(&["failed"], StartupCheck::Syncing, SYNC_WINDOW).await;
        assert!(output.contains(FAILED), "{output}");
        assert!(started.elapsed() < SYNC_WINDOW, "{:?}", started.elapsed());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_long_sync_warns_once_after_the_window() {
        // Synchronizing for 3 polls past the window, then ready.
        let window = POLL * 4;
        let mut script = vec!["synchronizing"; 8];
        script.push("ready");
        let output = watched(&script, StartupCheck::Syncing, window).await;
        assert_eq!(output.matches(WINDOW).count(), 1, "{output}");
        assert!(output.contains(READY), "{output}");
        assert!(!output.contains(OFFLINE), "{output}");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_sync_inside_the_window_says_only_ready() {
        let output = watched(
            &["synchronizing", "synchronizing", "ready"],
            StartupCheck::Syncing,
            SYNC_WINDOW,
        )
        .await;
        assert!(output.contains(READY), "{output}");
        assert!(!output.contains("WARN"), "{output}");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn shutdown_or_a_dropped_provider_says_nothing() {
        let lightning = stub(not_ready, &["offline"]);
        let (tx, rx) = watch::channel(false);
        tx.send(true).unwrap();
        let (_, output) = logged(watch_until_ready(
            Arc::downgrade(&lightning),
            ctx(NodeTier::Full),
            StartupCheck::Syncing,
            SYNC_WINDOW,
            rx,
        ))
        .await;
        assert!(output.is_empty(), "{output}");

        let weak = Arc::downgrade(&lightning);
        drop(lightning);
        let (_tx, rx) = watch::channel(false);
        let (_, output) = logged(watch_until_ready(
            weak,
            ctx(NodeTier::Full),
            StartupCheck::Syncing,
            SYNC_WINDOW,
            rx,
        ))
        .await;
        assert!(output.is_empty(), "{output}");
    }
}
