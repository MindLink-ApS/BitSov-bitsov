use std::time::{SystemTime, UNIX_EPOCH};

/// A process-local wallet sync failure. No remote error text is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainSyncFailure {
	/// Unix seconds when the currently failing wallet first failed to sync.
	pub since: u64,
	/// Whether the latest observed failure was an HTTP 429.
	pub rate_limited: bool,
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

    pub(super) fn record_result(&mut self, wallet: usize, result: &Result<(), crate::Error>) {
        self.record(wallet, result.is_ok());
        if let Some(failure) = &mut self.failures[wallet] {
            failure.rate_limited = matches!(result, Err(crate::Error::ChainRateLimited));
        }
    }

	fn record_at(&mut self, wallet: usize, succeeded: bool, now: u64) {
		if succeeded {
			self.failures[wallet] = None;
		} else {
			self.failures[wallet].get_or_insert(ChainSyncFailure { since: now, rate_limited: false });
		}
	}

	pub(super) fn failure(&self) -> Option<ChainSyncFailure> {
		self.failures.iter().flatten().min_by_key(|failure| failure.since).copied().map(|mut failure| {
            // Keep the oldest onset, but do not hide another wallet's outstanding 429.
            failure.rate_limited = self.failures.iter().flatten().any(|failure| failure.rate_limited);
            failure
        })
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

#[cfg(test)]
mod bitsov_rate_health_tests {
    use super::*;
    #[test]
    fn rate_limit_kind_preserves_since_and_clears_on_recovery() {
        let mut health = SyncHealth::default();
        health.record_result(0, &Err(crate::Error::WalletOperationFailed));
        let since = health.failure().unwrap().since;
        health.record_result(0, &Err(crate::Error::ChainRateLimited));
        assert_eq!(health.failure(), Some(ChainSyncFailure { since, rate_limited: true }));
        health.record_result(1, &Ok(()));
        assert!(health.failure().unwrap().rate_limited);
        health.record_result(0, &Ok(()));
        assert!(health.failure().is_none());
    }
    #[test]
    fn other_wallet_rate_limit_is_not_hidden_by_older_generic_failure() {
        let mut health = SyncHealth::default();
        health.record_at(0, false, 100);
        health.record_result(1, &Err(crate::Error::ChainRateLimited));
        assert_eq!(health.failure(), Some(ChainSyncFailure { since: 100, rate_limited: true }));
        health.record_result(1, &Ok(()));
        assert_eq!(health.failure(), Some(ChainSyncFailure { since: 100, rate_limited: false }));
    }

}
