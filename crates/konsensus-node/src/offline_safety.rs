//! Node-local offline breach-window diagnostics and durable heartbeat.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use konsensus_core::offline_safety::{
    ChannelAlert, ChannelWindow, OfflineReport, OfflineSafetyStatus, Severity,
    SyncedBlock as Heartbeat,
};
use konsensus_core::{ChainProvider, LightningProvider};
use tokio::sync::watch;

const HEARTBEAT_FILE: &str = "offline-heartbeat.json";
const WINDOWS_FILE: &str = "offline-channel-windows.json";
const SECONDS_PER_BLOCK: u64 = 600;

fn severity(blocks: u64, window: u16) -> Option<Severity> {
    if window == 0 {
        None
    } else if u128::from(blocks) * 100 >= u128::from(window) * 80 {
        Some(Severity::Critical)
    } else if u128::from(blocks) * 100 >= u128::from(window) * 50 {
        Some(Severity::Warning)
    } else {
        None
    }
}

fn evaluate(blocks: Option<u64>, estimated: bool, windows: &[ChannelWindow]) -> OfflineReport {
    let channels: Vec<_> = windows
        .iter()
        .map(|channel| {
            let window = channel.window_blocks.filter(|w| *w > 0);
            ChannelAlert {
                channel_id: channel.channel_id.clone(),
                window_blocks: window,
                percentage: blocks
                    .zip(window)
                    .map(|(b, w)| b as f64 * 100.0 / f64::from(w)),
                severity: blocks.zip(window).and_then(|(b, w)| severity(b, w)),
            }
        })
        .collect();
    let smallest = channels.iter().filter_map(|c| c.window_blocks).min();
    OfflineReport {
        blocks_offline: blocks,
        smallest_window_blocks: smallest,
        percentage: blocks
            .zip(smallest)
            .map(|(b, w)| b as f64 * 100.0 / f64::from(w)),
        severity: blocks.zip(smallest).and_then(|(b, w)| severity(b, w)),
        estimated,
        coverage_complete: channels.is_empty()
            || (blocks.is_some() && channels.iter().all(|c| c.window_blocks.is_some())),
        channels,
    }
}

/// Wall time is only an estimate, never a claim about the actual chain height.
fn lag(heartbeat: Option<Heartbeat>, tip: Option<u64>, now: u64) -> (Option<u64>, bool) {
    let Some(last) = heartbeat else {
        return (None, false);
    };
    let observed = tip.map(|h| h.saturating_sub(last.height));
    let elapsed_blocks = now.saturating_sub(last.unix_secs) / SECONDS_PER_BLOCK;
    let estimated = observed.is_none_or(|blocks| elapsed_blocks > blocks);
    (Some(observed.unwrap_or(0).max(elapsed_blocks)), estimated)
}

struct OfflineTracker {
    directory: PathBuf,
    heartbeat: Option<Heartbeat>,
    cached_channels: Option<Vec<ChannelWindow>>,
    startup_heartbeat: Option<Heartbeat>,
    startup_checked: bool,
    status: OfflineSafetyStatus,
}

impl OfflineTracker {
    fn load(directory: &Path) -> Self {
        fn read<T: serde::de::DeserializeOwned>(path: PathBuf) -> io::Result<Option<T>> {
            match std::fs::read(path) {
                Ok(bytes) => serde_json::from_slice(&bytes)
                    .map(Some)
                    .map_err(io::Error::other),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }
        let heartbeat = read(directory.join(HEARTBEAT_FILE));
        let windows = read(directory.join(WINDOWS_FILE));
        // Files are independent: a bad cache must not erase known offline history,
        // and a bad heartbeat must not hide the known channel windows.
        let error = match (heartbeat.is_err(), windows.is_err()) {
            (true, true) => Some("previous heartbeat and channel cache unreadable"),
            (true, false) => Some("previous heartbeat unreadable"),
            (false, true) => Some("previous channel cache unreadable"),
            (false, false) => None,
        };
        let mut tracker = Self::new(directory, heartbeat.ok().flatten());
        tracker.cached_channels = windows.ok().flatten();
        tracker.status.heartbeat_error = error.map(str::to_owned);
        tracker
    }

    fn new(directory: &Path, heartbeat: Option<Heartbeat>) -> Self {
        Self {
            directory: directory.to_path_buf(),
            heartbeat,
            cached_channels: None,
            startup_heartbeat: heartbeat,
            startup_checked: heartbeat.is_none(),
            status: OfflineSafetyStatus {
                history_available_on_start: heartbeat.is_some(),
                ..Default::default()
            },
        }
    }

    fn observe(
        &mut self,
        channels: &[ChannelWindow],
        last_sync: Option<Heartbeat>,
        tip: Option<u64>,
        now: u64,
    ) -> io::Result<OfflineSafetyStatus> {
        // A newly synced height is itself evidence of chain progress if the separate
        // tip query is down or lagging. Evaluate BEFORE replacing the old heartbeat.
        let tip = tip.into_iter().chain(last_sync.map(|s| s.height)).max();
        self.update_report(channels, tip, now);
        let mut windows = channels.to_vec();
        windows.sort_by(|a, b| a.channel_id.cmp(&b.channel_id));
        if self.cached_channels.as_ref() != Some(&windows) {
            self.persist_json(WINDOWS_FILE, &windows)?;
            self.cached_channels = Some(windows);
        }
        if let Some(heartbeat) = last_sync {
            // Never refresh the timestamp on the same block or roll height backwards.
            if self
                .heartbeat
                .is_none_or(|last| heartbeat.height > last.height)
            {
                self.persist_json(HEARTBEAT_FILE, &heartbeat)?;
                self.heartbeat = Some(heartbeat);
            }
        }
        Ok(self.status.clone())
    }

    fn update_report(&mut self, channels: &[ChannelWindow], tip: Option<u64>, now: u64) {
        let (blocks, estimated) = lag(self.heartbeat, tip, now);
        self.status.current = evaluate(blocks, estimated, channels);
        if !self.startup_checked {
            let (blocks, estimated) = lag(self.startup_heartbeat, tip, now);
            let report = evaluate(blocks, estimated, channels);
            if report.severity.is_some() {
                self.status.startup_alert = Some(report);
            }
            self.startup_checked = tip.is_some();
        }
    }

    fn observe_cached(&mut self, tip: Option<u64>, now: u64) -> OfflineSafetyStatus {
        let channels = self.cached_channels.clone().unwrap_or_default();
        let startup_checked = self.startup_checked;
        self.update_report(&channels, tip, now);
        // Re-evaluate startup against live channels when backend recovery succeeds.
        self.startup_checked = startup_checked;
        self.status.current.coverage_complete = false;
        if let Some(alert) = self.status.startup_alert.as_mut() {
            alert.coverage_complete = false;
        }
        self.status.clone()
    }

    fn persist_json(&self, name: &str, value: &impl serde::Serialize) -> io::Result<()> {
        let temporary = self.directory.join(format!(
            ".offline-heartbeat-{:016x}.tmp",
            rand::random::<u64>()
        ));
        let result = (|| {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&serde_json::to_vec(value).map_err(io::Error::other)?)?;
            file.sync_all()?;
            std::fs::rename(&temporary, self.directory.join(name))?;
            konsensus_api::pairing::fsync_dir_strict(&self.directory)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }
}

/// Starts only after unlock. It never contacts the hub; only the configured chain
/// backend is queried, with a timeout. Provider diagnostics bypass money admission.
pub async fn run(
    lightning: Arc<dyn LightningProvider>,
    chain: Arc<dyn ChainProvider>,
    directory: PathBuf,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut tracker = OfflineTracker::load(&directory);
    if let Some(error) = &tracker.status.heartbeat_error {
        tracing::error!(%error, "offline safety: saved diagnostics incomplete");
    }
    let mut logged = false;
    let mut write_error_logged = false;
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = interval.tick() => {},
        }
        if *shutdown.borrow() {
            break;
        }
        let Some(shared) = lightning.offline_safety() else {
            continue;
        };
        let source = lightning.offline_chain_state();
        let tip = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            result = tokio::time::timeout(Duration::from_secs(5), chain.get_block_height()) => {
                result.ok().and_then(Result::ok)
            },
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Durable writes (including fsync) stay off the async runtime workers.
        let updated = tokio::task::spawn_blocking(move || {
            let result = match source {
                Some(source) => tracker.observe(&source.channels, source.last_sync, tip, now),
                None => Ok(tracker.observe_cached(tip, now)),
            };
            (tracker, result)
        })
        .await;
        let Ok((next, result)) = updated else {
            tracing::error!("offline safety heartbeat worker panicked");
            break;
        };
        tracker = next;
        if let Err(error) = result {
            tracker.status.heartbeat_error = Some("heartbeat persistence failed".into());
            if !write_error_logged {
                tracing::error!(%error, "offline safety: heartbeat persistence failed");
                write_error_logged = true;
            }
        } else if write_error_logged {
            tracker.status.heartbeat_error = None;
            write_error_logged = false;
        }
        if !logged {
            let report = tracker
                .status
                .startup_alert
                .as_ref()
                .unwrap_or(&tracker.status.current);
            match report.severity {
                Some(Severity::Critical) => {
                    tracing::error!(blocks_offline = ?report.blocks_offline, window_blocks = ?report.smallest_window_blocks, percentage = ?report.percentage, estimated = report.estimated,
                        "OFFLINE SAFETY CRITICAL: >=80% of a channel breach window; unlock now, synchronize, then check channels");
                    logged = true;
                }
                Some(Severity::Warning) => {
                    tracing::warn!(blocks_offline = ?report.blocks_offline, window_blocks = ?report.smallest_window_blocks, percentage = ?report.percentage, estimated = report.estimated,
                        "OFFLINE SAFETY WARNING: >=50% of a channel breach window; unlock now, synchronize, then check channels");
                    logged = true;
                }
                None => {}
            }
        }
        *shared.write().unwrap() = tracker.status.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channels() -> Vec<ChannelWindow> {
        vec![ChannelWindow {
            channel_id: "a".into(),
            window_blocks: Some(200),
        }]
    }

    #[test]
    fn offline_thresholds_and_rounding() {
        for (blocks, expected) in [
            (80, None),
            (110, Some(Severity::Warning)),
            (170, Some(Severity::Critical)),
            (100, Some(Severity::Warning)),
            (160, Some(Severity::Critical)),
        ] {
            let report = evaluate(Some(blocks), false, &channels());
            assert_eq!(report.severity, expected);
            assert_eq!(report.percentage, Some(blocks as f64 / 2.0));
        }
        assert_eq!(severity(100, 201), None);
        assert_eq!(severity(101, 201), Some(Severity::Warning));
        assert_eq!(severity(160, 201), Some(Severity::Warning));
        assert_eq!(severity(161, 201), Some(Severity::Critical));
        assert_eq!(severity(u64::MAX, 2016), Some(Severity::Critical));
        assert_eq!(severity(100, 0), None);
    }

    #[test]
    fn offline_no_channels_never_alerts_and_smallest_window_wins() {
        assert_eq!(evaluate(Some(10_000), true, &[]).severity, None);
        let mut windows = channels();
        windows.push(ChannelWindow {
            channel_id: "b".into(),
            window_blocks: Some(100),
        });
        let report = evaluate(Some(85), false, &windows);
        assert_eq!(report.smallest_window_blocks, Some(100));
        assert_eq!(report.severity, Some(Severity::Critical));
        assert_eq!(report.channels[0].severity, None);
        assert_eq!(report.channels[1].severity, Some(Severity::Critical));
        windows.push(ChannelWindow {
            channel_id: "unknown".into(),
            window_blocks: None,
        });
        assert!(!evaluate(Some(85), false, &windows).coverage_complete);
        assert_eq!(evaluate(None, false, &windows).severity, None);
    }

    #[test]
    fn offline_heartbeat_survives_restart_and_startup_alert_stays_visible() {
        let dir = tempfile::tempdir().unwrap();
        let mut tracker = OfflineTracker::load(dir.path());
        tracker
            .observe(
                &channels(),
                Some(Heartbeat {
                    height: 1000,
                    unix_secs: 600,
                }),
                Some(1000),
                600,
            )
            .unwrap();
        let bytes = std::fs::read(dir.path().join(HEARTBEAT_FILE)).unwrap();
        tracker
            .observe(
                &channels(),
                Some(Heartbeat {
                    height: 1000,
                    unix_secs: 1200,
                }),
                Some(1000),
                1200,
            )
            .unwrap();
        assert_eq!(
            bytes,
            std::fs::read(dir.path().join(HEARTBEAT_FILE)).unwrap()
        );
        drop(tracker);
        let mut restarted = OfflineTracker::load(dir.path());
        let alert = restarted
            .observe(
                &channels(),
                Some(Heartbeat {
                    height: 1170,
                    unix_secs: 1300,
                }),
                Some(1170),
                1300,
            )
            .unwrap();
        assert_eq!(
            alert.startup_alert.as_ref().unwrap().blocks_offline,
            Some(170)
        );
        assert_eq!(
            alert.startup_alert.as_ref().unwrap().severity,
            Some(Severity::Critical)
        );
        let caught_up = restarted
            .observe(
                &channels(),
                Some(Heartbeat {
                    height: 1170,
                    unix_secs: 1301,
                }),
                Some(1170),
                1301,
            )
            .unwrap();
        assert_eq!(caught_up.current.severity, None);
        assert_eq!(
            caught_up.startup_alert.unwrap().severity,
            Some(Severity::Critical)
        );
        assert_eq!(
            OfflineTracker::load(dir.path()).heartbeat.unwrap(),
            Heartbeat {
                height: 1170,
                unix_secs: 1300
            }
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn offline_stalled_sync_uses_height_or_explicit_time_estimate() {
        let dir = tempfile::tempdir().unwrap();
        let mut tracker = OfflineTracker::load(dir.path());
        tracker
            .observe(
                &channels(),
                Some(Heartbeat {
                    height: 1000,
                    unix_secs: 100,
                }),
                Some(1000),
                100,
            )
            .unwrap();
        let stalled = tracker.observe(&channels(), None, Some(1110), 200).unwrap();
        assert_eq!(stalled.current.blocks_offline, Some(110));
        assert_eq!(stalled.current.severity, Some(Severity::Warning));
        assert!(!stalled.current.estimated);
        let disconnected = tracker
            .observe(&channels(), None, None, 100 + 170 * 600)
            .unwrap();
        assert_eq!(disconnected.current.severity, Some(Severity::Critical));
        assert!(disconnected.current.estimated);
        assert_eq!(tracker.heartbeat.unwrap().height, 1000);
    }

    #[test]
    fn offline_unknown_history_reorg_and_clock_rollback_are_safe() {
        let dir = tempfile::tempdir().unwrap();
        let mut tracker = OfflineTracker::load(dir.path());
        let unknown = tracker.observe(&channels(), None, Some(1000), 100).unwrap();
        assert_eq!(unknown.current.blocks_offline, None);
        assert!(!unknown.current.coverage_complete);
        tracker
            .observe(
                &channels(),
                Some(Heartbeat {
                    height: 1000,
                    unix_secs: 100,
                }),
                Some(1000),
                100,
            )
            .unwrap();
        let rollback = tracker
            .observe(
                &channels(),
                Some(Heartbeat {
                    height: 999,
                    unix_secs: 50,
                }),
                Some(999),
                50,
            )
            .unwrap();
        assert_eq!(rollback.current.blocks_offline, Some(0));
        assert_eq!(rollback.current.severity, None);
        assert_eq!(tracker.heartbeat.unwrap().height, 1000);
        std::fs::write(dir.path().join(HEARTBEAT_FILE), b"truncated").unwrap();
        let corrupted = OfflineTracker::load(dir.path());
        assert!(corrupted.heartbeat.is_none());
        assert!(corrupted.cached_channels.is_some());
        assert!(corrupted.status.heartbeat_error.is_some());
    }

    #[test]
    fn offline_failed_write_does_not_advance_heartbeat() {
        let dir = tempfile::tempdir().unwrap();
        let mut tracker = OfflineTracker::load(dir.path());
        tracker
            .observe(
                &channels(),
                Some(Heartbeat {
                    height: 1000,
                    unix_secs: 100,
                }),
                Some(1000),
                100,
            )
            .unwrap();
        // A destination obstruction makes atomic rename fail after the temp was synced.
        std::fs::remove_file(dir.path().join(HEARTBEAT_FILE)).unwrap();
        std::fs::create_dir(dir.path().join(HEARTBEAT_FILE)).unwrap();
        assert!(tracker
            .observe(
                &channels(),
                Some(Heartbeat {
                    height: 1170,
                    unix_secs: 200
                }),
                Some(1170),
                200
            )
            .is_err());
        assert_eq!(tracker.heartbeat.unwrap().height, 1000);
        assert_eq!(tracker.status.current.severity, Some(Severity::Critical));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    struct StalledSource(konsensus_core::offline_safety::SharedOfflineSafety);

    #[async_trait::async_trait]
    impl LightningProvider for StalledSource {
        fn offline_safety(&self) -> Option<konsensus_core::offline_safety::SharedOfflineSafety> {
            Some(self.0.clone())
        }
        fn offline_chain_state(&self) -> Option<konsensus_core::offline_safety::OfflineChainState> {
            Some(konsensus_core::offline_safety::OfflineChainState {
                last_sync: None,
                channels: channels(),
            })
        }
        async fn is_available(&self) -> bool {
            false
        }
        async fn create_invoice(
            &self,
            _: u64,
            _: &str,
            _: u32,
        ) -> Result<
            konsensus_core::traits::lightning::Invoice,
            konsensus_core::traits::lightning::LightningError,
        > {
            unreachable!()
        }
        async fn pay_invoice(
            &self,
            _: &str,
        ) -> Result<
            konsensus_core::traits::lightning::PaymentDetails,
            konsensus_core::traits::lightning::LightningError,
        > {
            unreachable!()
        }
        async fn get_payment_status(
            &self,
            _: &str,
        ) -> Result<
            konsensus_core::traits::lightning::PaymentDetails,
            konsensus_core::traits::lightning::LightningError,
        > {
            unreachable!()
        }
        async fn get_balance_msat(
            &self,
        ) -> Result<u64, konsensus_core::traits::lightning::LightningError> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn offline_worker_publishes_through_all_admission_wrappers_while_stalled() {
        use konsensus_lightning::circuit_breaker::{CircuitBreakerConfig, CircuitBreakerLightning};
        use konsensus_lightning::recovering::RecoveringLightning;
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut tracker = OfflineTracker::load(dir.path());
        tracker
            .observe(
                &channels(),
                Some(Heartbeat {
                    height: 1000,
                    unix_secs: now,
                }),
                Some(1000),
                now,
            )
            .unwrap();
        let saved = std::fs::read(dir.path().join(HEARTBEAT_FILE)).unwrap();
        let shared: konsensus_core::offline_safety::SharedOfflineSafety = Default::default();
        let backend: Arc<dyn LightningProvider> = Arc::new(StalledSource(shared.clone()));
        let recovering = RecoveringLightning::new(
            move || {
                let backend = backend.clone();
                async move { Ok(backend) }
            },
            Default::default(),
        )
        .await
        .unwrap();
        let breaker =
            CircuitBreakerLightning::new(Arc::new(recovering), CircuitBreakerConfig::default());
        let lightning: Arc<dyn LightningProvider> =
            Arc::new(crate::guarded_lightning::GuardedLightning {
                inner: Arc::new(breaker),
                disk: Arc::new(crate::safety::DiskGuard::new(
                    dir.path().to_path_buf(),
                    u64::MAX,
                )),
                channel_peers: Default::default(),
                _state_guard: Arc::new(std::fs::File::open(dir.path()).unwrap()),
            });
        assert!(!lightning.money_ready().await);
        let chain = Arc::new(konsensus_chain::mock::MockChainProvider::with_config(
            konsensus_chain::mock::MockChainConfig {
                initial_height: 1170,
                ..Default::default()
            },
        ));
        let (stop, rx) = watch::channel(false);
        let worker = tokio::spawn(run(lightning.clone(), chain, dir.path().to_path_buf(), rx));
        tokio::time::timeout(Duration::from_secs(5), async {
            while shared.read().unwrap().startup_alert.is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        stop.send(true).unwrap();
        worker.await.unwrap();
        lightning.shutdown().await.unwrap();
        let report = shared.read().unwrap();
        assert_eq!(report.current.blocks_offline, Some(170));
        assert_eq!(report.current.severity, Some(Severity::Critical));
        assert_eq!(
            saved,
            std::fs::read(dir.path().join(HEARTBEAT_FILE)).unwrap()
        );
    }

    #[tokio::test]
    async fn offline_start_without_backend_uses_persisted_channel_windows() {
        use konsensus_core::traits::lightning::LightningError;
        use konsensus_lightning::recovering::RecoveringLightning;
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut tracker = OfflineTracker::load(dir.path());
        tracker
            .observe(
                &channels(),
                Some(Heartbeat {
                    height: 1000,
                    unix_secs: now - 170 * 600,
                }),
                Some(1000),
                now - 170 * 600,
            )
            .unwrap();
        drop(tracker);
        let lightning = Arc::new(
            RecoveringLightning::new(
                || async {
                    Err(LightningError::ChainSourceUnavailable {
                        network: "test".into(),
                        service: "offline.invalid".into(),
                        attempts: 1,
                        elapsed_ms: 0,
                        cause: "offline fixture".into(),
                    })
                },
                Default::default(),
            )
            .await
            .unwrap(),
        );
        let shared = lightning
            .offline_safety()
            .expect("status must survive offline startup");
        assert!(lightning.offline_chain_state().is_none());
        let chain = Arc::new(konsensus_chain::mock::MockChainProvider::with_config(
            konsensus_chain::mock::MockChainConfig {
                initial_height: 1000,
                ..Default::default()
            },
        ));
        let (stop, rx) = watch::channel(false);
        let worker = tokio::spawn(run(lightning.clone(), chain, dir.path().to_path_buf(), rx));
        tokio::time::timeout(Duration::from_secs(5), async {
            while shared.read().unwrap().startup_alert.is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        stop.send(true).unwrap();
        worker.await.unwrap();
        lightning.shutdown().await.unwrap();
        let report = shared.read().unwrap();
        assert_eq!(report.current.blocks_offline, Some(170));
        assert_eq!(report.current.severity, Some(Severity::Critical));
        assert!(report.current.estimated);
        assert!(
            !report.current.coverage_complete,
            "cached channels must not claim live coverage"
        );
        assert_eq!(report.current.channels[0].window_blocks, Some(200));
    }

    #[test]
    fn offline_corrupt_window_cache_does_not_discard_valid_heartbeat() {
        let dir = tempfile::tempdir().unwrap();
        let mut previous = OfflineTracker::load(dir.path());
        previous
            .observe(
                &channels(),
                Some(Heartbeat {
                    height: 1000,
                    unix_secs: 100,
                }),
                Some(1000),
                100,
            )
            .unwrap();
        std::fs::write(dir.path().join(WINDOWS_FILE), b"truncated").unwrap();
        let mut restarted = OfflineTracker::load(dir.path());
        assert!(restarted.status.heartbeat_error.is_some());
        let report = restarted
            .observe(
                &channels(),
                Some(Heartbeat {
                    height: 1170,
                    unix_secs: 200,
                }),
                Some(1170),
                200,
            )
            .unwrap();
        assert!(report.history_available_on_start);
        assert_eq!(
            report.startup_alert.unwrap().severity,
            Some(Severity::Critical)
        );
    }
}
