//! Atomic channel-capacity admission shared by manual, inbound and JIT opens.

use crate::Error;
use std::sync::{Arc, Mutex, MutexGuard};

/// Capacity ceilings for new channels. Zero refuses new positive capacity.
/// Clones share one admission lock; snapshots must be taken while holding it.
#[derive(Clone, Debug)]
pub struct ChannelLimits {
	/// Inclusive capacity ceiling for each newly admitted channel.
	pub max_channel_capacity_sats: u64,
	/// Inclusive sum of full capacities of all manager-listed channels.
	pub max_total_channel_capacity_sats: u64,
	admission: Arc<Mutex<()>>,
}

impl ChannelLimits {
	/// Create finite ceilings with a shared admission lock.
	pub fn new(max_channel_capacity_sats: u64, max_total_channel_capacity_sats: u64) -> Self {
		Self {
			max_channel_capacity_sats,
			max_total_channel_capacity_sats,
			admission: Arc::new(Mutex::new(())),
		}
	}

	pub(crate) fn lock(&self) -> Result<MutexGuard<'_, ()>, Error> {
		// A poisoned admission boundary has unknown state. Never recover by admitting work.
		self.admission
			.lock()
			.map_err(|_| Error::TotalChannelCapacityExceeded)
	}

	pub(crate) fn check(
		&self,
		requested: u64,
		mut capacities: impl Iterator<Item = u64>,
	) -> Result<(), Error> {
		if requested > self.max_channel_capacity_sats {
			return Err(Error::ChannelCapacityExceeded);
		}
		let projected = capacities
			.try_fold(requested, u64::checked_add)
			.ok_or(Error::TotalChannelCapacityExceeded)?;
		if projected > self.max_total_channel_capacity_sats {
			return Err(Error::TotalChannelCapacityExceeded);
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn inclusive_edges_zero_and_overflow_fail_closed() {
		let caps = ChannelLimits::new(100, 150);
		assert_eq!(caps.check(100, [].into_iter()), Ok(()));
		assert_eq!(
			caps.check(101, [].into_iter()),
			Err(crate::Error::ChannelCapacityExceeded)
		);
		assert_eq!(caps.check(50, [100].into_iter()), Ok(()));
		assert_eq!(
			caps.check(51, [100].into_iter()),
			Err(crate::Error::TotalChannelCapacityExceeded)
		);
		assert_eq!(
			caps.check(1, [151].into_iter()),
			Err(crate::Error::TotalChannelCapacityExceeded)
		);
		assert_eq!(
			ChannelLimits::new(0, 0).check(1, [].into_iter()),
			Err(crate::Error::ChannelCapacityExceeded)
		);
		let huge = ChannelLimits::new(u64::MAX, u64::MAX);
		assert_eq!(
			huge.check(1, [u64::MAX].into_iter()),
			Err(crate::Error::TotalChannelCapacityExceeded)
		);
		assert_eq!(
			huge.check(1, [u64::MAX, 1].into_iter()),
			Err(crate::Error::TotalChannelCapacityExceeded)
		);
	}

	#[test]
	fn poisoned_admission_lock_refuses_new_work() {
		let limits = ChannelLimits::new(100, 100);
		let other = limits.clone();
		assert!(std::thread::spawn(move || {
			let _guard = other.lock().unwrap();
			panic!("interrupted admission");
		})
		.join()
		.is_err());
		assert_eq!(
			limits.lock().unwrap_err(),
			Error::TotalChannelCapacityExceeded
		);
	}

	#[test]
	fn cloned_limits_serialize_snapshot_and_admission() {
		let caps = ChannelLimits::new(100, 100);
		let channels = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
		let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
		let jobs: Vec<_> = (0..8)
			.map(|_| {
				let caps = caps.clone();
				let channels = channels.clone();
				let barrier = barrier.clone();
				std::thread::spawn(move || {
					barrier.wait();
					let _guard = caps.lock().unwrap();
					let snapshot = channels.lock().unwrap().clone();
					if caps.check(100, snapshot.into_iter()).is_ok() {
						channels.lock().unwrap().push(100);
					}
				})
			})
			.collect();
		for job in jobs {
			job.join().unwrap();
		}
		assert_eq!(*channels.lock().unwrap(), vec![100]);
	}
}
