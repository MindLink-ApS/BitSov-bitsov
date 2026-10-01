use std::time::{SystemTime, UNIX_EPOCH};

/// A process-local wallet sync failure. No remote error text is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainSyncFailure {
	/// Unix seconds when the currently failing wallet first failed to sync.
	pub since: u64,
}

/// Separate slots prevent a successful wallet sync from hiding the other failure.
#[derive(Default)]
pub(super) struct SyncHealth {
	failures: [Option<ChainSyncFailure>; 2],
}

impl SyncHealth {
	pub(super) fn record(&mut self, wallet: usize, succeeded: bool) {
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
		self.record_at(wallet, succeeded, now);
	}

	fn record_at(&mut self, wallet: usize, succeeded: bool, now: u64) {
		if succeeded {
			self.failures[wallet] = None;
		} else {
			self.failures[wallet].get_or_insert(ChainSyncFailure { since: now });
		}
	}

	pub(super) fn failure(&self) -> Option<ChainSyncFailure> {
		self.failures.iter().flatten().min_by_key(|failure| failure.since).copied()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn failure_since_survives_retries_and_other_wallet_success() {
		let mut health = SyncHealth::default();
		assert_eq!(health.failure(), None);
		health.record_at(0, false, 100);
		health.record_at(0, false, 110);
		health.record_at(1, true, 120);
		assert_eq!(health.failure().unwrap().since, 100);
		health.record_at(1, false, 130);
		health.record_at(0, true, 140);
		assert_eq!(health.failure().unwrap().since, 130);
		health.record_at(1, true, 150);
		assert_eq!(health.failure(), None);
		health.record_at(0, false, 160);
		assert_eq!(health.failure().unwrap().since, 160);
	}
}
