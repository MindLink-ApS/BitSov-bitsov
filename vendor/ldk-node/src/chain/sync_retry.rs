//! Bounded, process-local retries. Never log remote error text or chain identifiers.
use std::future::Future;
use std::time::Duration;

use crate::config::WALLET_SYNC_INTERVAL_MINIMUM_SECS;
use crate::Error;

const RETRY_MIN_SECS: u64 = 10;
const RETRY_MAX_SECS: u64 = 300;

pub(super) async fn run<F, Fut>(
	mut stop: tokio::sync::watch::Receiver<()>,
	operation: &'static str,
	interval_secs: u64,
	immediate: bool,
	mut sync: F,
) where
	F: FnMut() -> Fut,
	Fut: Future<Output = Result<(), Error>>,
{
	let interval = Duration::from_secs(interval_secs.max(WALLET_SYNC_INTERVAL_MINIMUM_SECS));
	let mut delay = if immediate { Duration::ZERO } else { interval };
	let mut retry_secs = RETRY_MIN_SECS;
	loop {
		tokio::select! {
			biased;
			_ = stop.changed() => return,
			_ = tokio::time::sleep(delay) => {},
		}
		// Let the source's bounded attempt finish before stopping. In particular,
		// Electrum's blocking worker must not be detached by a shutdown select.
		match sync().await {
			Ok(()) => {
				delay = interval;
				retry_secs = RETRY_MIN_SECS;
			}
			Err(error) => {
				delay = Duration::from_secs(retry_secs);
				// This deliberately uses the application log facade, even if LDK's
				// detailed logger writes to a file. One line per failed attempt;
				// the retry delay bounds log rate to at most once/10s per worker.
				let kind = match error {
					Error::WalletOperationTimeout
					| Error::TxSyncTimeout
					| Error::FeerateEstimationUpdateTimeout => "timeout",
					_ => "sync_failed",
				};
				log::error!(target: "ldk_node::chain_sync",
					"chain_sync_failed operation={} kind={} retry_in_secs={}",
					operation, kind, retry_secs);
				retry_secs = retry_secs.saturating_mul(2).min(RETRY_MAX_SECS);
			}
		}
	}
}

#[cfg(test)]
mod bitsov_retry_tests {
	use super::*;
	use crate::chain::{sync_health::SyncHealth, WalletSyncStatus};
	use std::sync::{Arc, Mutex};

	#[derive(Default)]
	struct Capture(Mutex<Vec<String>>);
	impl log::Log for Capture {
		fn enabled(&self, metadata: &log::Metadata) -> bool {
			metadata.target() == "ldk_node::chain_sync"
		}
		fn log(&self, record: &log::Record) {
			if self.enabled(record.metadata()) {
				self.0.lock().unwrap().push(record.args().to_string());
			}
		}
		fn flush(&self) {}
	}
	static LOG: Capture = Capture(Mutex::new(Vec::new()));

	#[tokio::test(start_paused = true)]
	async fn errors_back_off_cap_recover_and_log_without_busy_loop() {
		log::set_logger(&LOG).unwrap();
		log::set_max_level(log::LevelFilter::Error);
		let (stop, receiver) = tokio::sync::watch::channel(());
		let times = Arc::new(Mutex::new(Vec::new()));
		let health = Arc::new(Mutex::new(SyncHealth::default()));
		let started = tokio::time::Instant::now();
		let observed = times.clone();
		let recorded = health.clone();
		let task = tokio::spawn(run(receiver, "onchain", 80, true, move || {
			let mut times = observed.lock().unwrap();
			times.push(started.elapsed().as_secs());
			let succeeded = times.len() == 8;
			recorded.lock().unwrap().record(0, succeeded);
			async move {
				if succeeded {
					Ok(())
				} else {
					Err(Error::WalletOperationFailed)
				}
			}
		}));
		// Virtual time: wait for each actual attempt, keeping the task alive after errors.
		for expected in [0, 10, 30, 70, 150, 310, 610, 910, 990, 1000] {
			while times.lock().unwrap().last().copied() != Some(expected) {
				tokio::time::sleep(Duration::from_secs(1)).await;
				assert!(
					started.elapsed().as_secs() <= expected + 2,
					"retry stalled or ran early"
				);
			}
			assert_eq!(health.lock().unwrap().failure().is_none(), expected == 910);
		}
		stop.send(()).unwrap();
		task.await.unwrap();
		assert_eq!(
			*times.lock().unwrap(),
			[0, 10, 30, 70, 150, 310, 610, 910, 990, 1000]
		);
		let all_logs = LOG.0.lock().unwrap();
		let logs: Vec<_> = all_logs
			.iter()
			.filter(|line| line.contains("operation=onchain "))
			.collect();
		assert_eq!(logs.len(), 9);
		assert!(logs.iter().all(|line| line
			.starts_with("chain_sync_failed operation=onchain kind=sync_failed retry_in_secs=")));
	}

	#[tokio::test(start_paused = true)]
	async fn hanging_work_times_out_releases_waiters_and_recovers() {
		let status = Arc::new(Mutex::new(WalletSyncStatus::Completed));
		let owner_status = status.clone();
		let owner = tokio::spawn(async move {
			WalletSyncStatus::run(
				&owner_status,
				Duration::from_secs(10),
				Error::TxSyncTimeout,
				std::future::pending(),
			)
			.await
		});
		tokio::task::yield_now().await;
		let mut waiter = status
			.lock()
			.unwrap()
			.register_or_subscribe_pending_sync()
			.unwrap();
		assert_eq!(owner.await.unwrap(), Err(Error::TxSyncTimeout));
		assert_eq!(waiter.recv().await.unwrap(), Err(Error::TxSyncTimeout));
		assert_eq!(
			WalletSyncStatus::run(
				&status,
				Duration::from_secs(10),
				Error::TxSyncTimeout,
				async { Ok(()) }
			)
			.await,
			Ok(())
		);
	}

	#[tokio::test(start_paused = true)]
	async fn abandoned_subscriber_is_bounded_without_stealing_ownership() {
		let status = Mutex::new(WalletSyncStatus::Completed);
		assert!(status
			.lock()
			.unwrap()
			.register_or_subscribe_pending_sync()
			.is_none());
		assert_eq!(
			WalletSyncStatus::run(
				&status,
				Duration::from_secs(10),
				Error::TxSyncTimeout,
				async { panic!("subscriber must not start another sync") }
			)
			.await,
			Err(Error::TxSyncTimeout)
		);
		assert!(matches!(
			*status.lock().unwrap(),
			WalletSyncStatus::InProgress { .. }
		));
		// An owner completing after every subscriber has timed out must not panic.
		status
			.lock()
			.unwrap()
			.propagate_result_to_subscribers(Ok(()));
		assert_eq!(
			WalletSyncStatus::run(
				&status,
				Duration::from_secs(10),
				Error::TxSyncTimeout,
				async { Ok(()) }
			)
			.await,
			Ok(())
		);
	}

	#[tokio::test(start_paused = true)]
	async fn delayed_fees_and_shutdown_do_not_start_unwanted_work() {
		let (stop, receiver) = tokio::sync::watch::channel(());
		let task = tokio::spawn(run(receiver, "fees", 600, false, || async {
			panic!("startup already refreshed fees")
		}));
		tokio::task::yield_now().await;
		tokio::time::advance(Duration::from_secs(599)).await;
		stop.send(()).unwrap();
		task.await.unwrap();
	}
	#[tokio::test(start_paused = true)]
	async fn stalled_wallet_does_not_starve_other_retries_or_fees() {
		let (stop, receiver) = tokio::sync::watch::channel(());
		let counts = Arc::new(Mutex::new([0; 3]));
		let observed = counts.clone();
		let task = tokio::spawn(async move {
			let status = Mutex::new(WalletSyncStatus::Completed);
			tokio::join!(
				run(receiver.clone(), "test_stalled", 80, true, || {
					observed.lock().unwrap()[0] += 1;
					WalletSyncStatus::run(
						&status,
						Duration::from_secs(10),
						Error::WalletOperationTimeout,
						std::future::pending(),
					)
				}),
				run(receiver.clone(), "test_recovering", 30, true, || {
					let mut counts = observed.lock().unwrap();
					counts[1] += 1;
					let result = if counts[1] == 1 {
						Err(Error::TxSyncFailed)
					} else {
						Ok(())
					};
					async move { result }
				}),
				run(receiver, "test_fees", 10, false, || {
					observed.lock().unwrap()[2] += 1;
					async { Ok(()) }
				}),
			);
			assert!(matches!(
				*status.lock().unwrap(),
				WalletSyncStatus::Completed
			));
		});
		// Small advances allow every intermediate deadline to run before shutdown.
		for _ in 0..25 {
			tokio::time::sleep(Duration::from_secs(1)).await;
		}
		assert_eq!(*counts.lock().unwrap(), [2, 2, 2]);
		stop.send(()).unwrap();
		// The active attempt finishes at its deadline, then stops without another retry.
		task.await.unwrap();
		assert_eq!(*counts.lock().unwrap(), [2, 2, 2]);
	}
}
