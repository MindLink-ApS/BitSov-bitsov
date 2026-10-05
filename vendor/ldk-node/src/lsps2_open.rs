//! BITSOV-PATCH: bounded, durable LSPS2 open reservations and retry journal.
//! Dispatch is fenced before calling LDK. An uncertain outcome is never retried.
use crate::{types::DynStore, Error};
use lightning::util::persist::KVStoreSync;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const NAMESPACE: &str = "bitsov_lsps2";
const MAX_ATTEMPTS: u32 = 5;
const LIFETIME_SECS: u64 = 60;
// Pilot journal keeps tombstones to reject replay without growing without bound.
const MAX_RECORDS: usize = 4096;

/// Durable hub totals and current conservative exposure. No peer labels.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LSPS2ServiceMetrics {
	/// Channels observed ready (once per JIT request).
	pub opens: u64,
	/// Observed settled opening skim, bounded by the quote (at-least-once telemetry).
	pub opening_fees_earned_msat: u64,
	/// Full reserved allocation, including anchors and funding fee ceilings.
	pub capital_locked_sats: u64,
	/// Reserved opens not yet ready; includes uncertain dispatch outcomes.
	pub pending_opens: u64,
	/// Failed attempts, including capacity refusals.
	pub failed_opens: u64,
	/// Attempts after the first one, including across restarts.
	pub open_retries: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Phase {
	Waiting,
	Dispatching,
	Ready,
	Closed,
	Failed,
	Released,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Open {
	pub peer: String,
	pub amount_sats: u64,
	pub opening_fee_msat: u64,
	pub funding_fee_cap_sats: u64,
	pub reserved_sats: u64,
	pub expires_at: u64,
	pub next_attempt: u64,
	pub attempts: u32,
	pub phase: Phase,
	pub channel_id: Option<String>,
	pub earned_msat: u64,
	pub failure_notified: bool,
	pub policy_saved: bool,
	pub closed: bool,
	pub cleanup_attempts: u32,
}

impl Open {
	// A configuration increase cannot widen a previously reserved fee budget.
	pub fn funding_cap(&self, configured_cap: u64) -> u64 {
		self.funding_fee_cap_sats.min(configured_cap)
	}
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Journal {
	version: u8,
	pub opens: BTreeMap<String, Open>,
	totals: LSPS2ServiceMetrics,
}

pub(crate) struct OpenRequest {
	pub id: u128,
	pub peer: String,
	pub amount_sats: u64,
	pub opening_fee_msat: u64,
	pub funding_fee_cap_sats: u64,
	pub reserve: u64,
}

impl Journal {
	pub fn load(store: &DynStore) -> Result<Self, Error> {
		match KVStoreSync::read(store, NAMESPACE, "", "opens") {
			Ok(bytes) => {
				let state: Self =
					serde_json::from_slice(&bytes).map_err(|_| Error::PersistenceFailed)?;
				if state.version != 1
					|| state.opens.len() > MAX_RECORDS
					|| state.opens.iter().any(|(id, r)| {
						id.parse::<u128>().map_or(true, |n| n.to_string() != *id)
							|| r.peer.parse::<bitcoin::secp256k1::PublicKey>().is_err()
							|| r.attempts > MAX_ATTEMPTS
							|| r.cleanup_attempts > MAX_ATTEMPTS
							|| r.earned_msat > r.opening_fee_msat
							|| r.channel_id.as_ref().is_some_and(|id| {
								id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit())
							})
					}) {
					return Err(Error::PersistenceFailed);
				}
				Ok(state)
			}
			Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => Ok(Self {
				version: 1,
				opens: BTreeMap::new(),
				totals: LSPS2ServiceMetrics::default(),
			}),
			Err(_) => Err(Error::PersistenceFailed),
		}
	}

	// Copy-on-write: a failed write must never release a reservation in memory.
	pub fn update<T>(
		&mut self,
		store: &DynStore,
		change: impl FnOnce(&mut Self) -> T,
	) -> Result<T, Error> {
		let mut next = self.clone();
		let result = change(&mut next);
		let bytes = serde_json::to_vec(&next).map_err(|_| Error::PersistenceFailed)?;
		KVStoreSync::write(store, NAMESPACE, "", "opens", bytes)
			.map_err(|_| Error::PersistenceFailed)?;
		*self = next;
		Ok(result)
	}

	pub fn metrics(&self) -> LSPS2ServiceMetrics {
		let mut metrics = self.totals;
		for open in self.opens.values() {
			metrics.capital_locked_sats = metrics
				.capital_locked_sats
				.saturating_add(open.reserved_sats);
			if matches!(open.phase, Phase::Waiting | Phase::Dispatching) {
				metrics.pending_opens += 1;
			}
		}
		metrics
	}

	pub fn insert(
		&mut self,
		request: OpenRequest,
		now: u64,
		limits: (u32, u64),
		external: (u64, u64),
	) -> Result<(), Error> {
		let OpenRequest {
			id,
			peer,
			amount_sats,
			opening_fee_msat,
			funding_fee_cap_sats,
			reserve,
		} = request;
		let (max_pending, max_capital) = limits;
		let (external_capital, external_pending) = external;
		if self.opens.contains_key(&id.to_string()) {
			return Ok(());
		}
		if self.opens.len() >= MAX_RECORDS {
			self.totals.failed_opens = self.totals.failed_opens.saturating_add(1);
			return Err(Error::ChannelCreationFailed);
		}
		let metrics = self.metrics();
		let admitted = metrics.pending_opens.saturating_add(external_pending)
			< u64::from(max_pending)
			&& metrics
				.capital_locked_sats
				.checked_add(external_capital)
				.and_then(|s| s.checked_add(reserve))
				.is_some_and(|total| total <= max_capital);
		if !admitted {
			self.totals.failed_opens = self.totals.failed_opens.saturating_add(1);
		}
		self.opens.insert(
			id.to_string(),
			Open {
				peer,
				amount_sats,
				opening_fee_msat,
				funding_fee_cap_sats,
				reserved_sats: if admitted { reserve } else { 0 },
				expires_at: now.saturating_add(LIFETIME_SECS),
				next_attempt: now,
				attempts: 0,
				phase: if admitted {
					Phase::Waiting
				} else {
					Phase::Failed
				},
				channel_id: None,
				earned_msat: 0,
				failure_notified: false,
				policy_saved: false,
				closed: false,
				cleanup_attempts: 0,
			},
		);
		Ok(())
	}

	pub fn due(&self, now: u64) -> Vec<u128> {
		self.opens
			.iter()
			.filter(|(_, r)| r.phase == Phase::Waiting && now >= r.next_attempt)
			.map(|(id, _)| id.parse().expect("validated journal id"))
			.collect()
	}

	pub fn begin(&mut self, id: u128, now: u64) -> bool {
		let r = self
			.opens
			.get_mut(&id.to_string())
			.expect("reserved request");
		if r.phase != Phase::Waiting || now < r.next_attempt {
			return false;
		}
		if now >= r.expires_at || r.attempts >= MAX_ATTEMPTS {
			r.phase = Phase::Failed;
			r.reserved_sats = 0;
			self.totals.failed_opens = self.totals.failed_opens.saturating_add(1);
			return false;
		}
		if r.attempts > 0 {
			self.totals.open_retries = self.totals.open_retries.saturating_add(1);
		}
		r.attempts += 1;
		r.phase = Phase::Dispatching;
		true
	}

	// Only call when create_channel definitely returned Err, or before it was called.
	pub fn failed(&mut self, id: u128, now: u64) {
		let r = self
			.opens
			.get_mut(&id.to_string())
			.expect("reserved request");
		self.totals.failed_opens = self.totals.failed_opens.saturating_add(1);
		if r.attempts >= MAX_ATTEMPTS || now >= r.expires_at {
			r.phase = Phase::Failed;
			r.reserved_sats = 0;
		} else {
			r.phase = Phase::Waiting;
			r.next_attempt = now.saturating_add(1 << r.attempts.min(3));
		}
	}

	pub fn observe(&mut self, id: u128, channel_id: String, ready: bool) {
		if let Some(r) = self.opens.get_mut(&id.to_string()) {
			r.channel_id = Some(channel_id);
			if ready && r.phase == Phase::Dispatching {
				r.phase = Phase::Ready;
				self.totals.opens = self.totals.opens.saturating_add(1);
			}
		}
	}

	pub fn closed(&mut self, id: u128) {
		if let Some(r) = self.opens.get_mut(&id.to_string()) {
			if r.closed {
				return;
			}
			r.closed = true;
			if r.phase == Phase::Dispatching {
				self.totals.failed_opens = self.totals.failed_opens.saturating_add(1);
			}
			if r.phase == Phase::Dispatching {
				r.phase = Phase::Closed;
			}
		}
	}

	pub fn forwarded(&mut self, channel_id: &str, skim_msat: u64) {
		if let Some(r) = self
			.opens
			.values_mut()
			.find(|r| r.channel_id.as_deref() == Some(channel_id))
		{
			// MPP can split skim across forwards. LDK provides no per-HTLC ID
			// here: replay can advance telemetry early, but never above the quote.
			let earned = r
				.earned_msat
				.saturating_add(skim_msat)
				.min(r.opening_fee_msat);
			if earned > r.earned_msat {
				self.totals.opening_fees_earned_msat = self
					.totals
					.opening_fees_earned_msat
					.saturating_add(earned - r.earned_msat);
				r.earned_msat = earned;
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	fn node() -> (tempfile::TempDir, crate::Node) {
		let dir = tempfile::tempdir().unwrap();
		let mut builder = crate::Builder::new();
		builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
		builder.set_entropy_seed_bytes([72; 64]);
		let node = builder.build_with_fs_store().unwrap();
		(dir, node)
	}
	fn add(j: &mut Journal, id: u128, peer: &str, now: u64) {
		j.insert(
			OpenRequest {
				id,
				peer: peer.into(),
				amount_sats: 198000,
				opening_fee_msat: 1000000,
				funding_fee_cap_sats: 2000,
				reserve: 233000,
			},
			now,
			(2, 466000),
			(0, 0),
		)
		.unwrap();
	}
	#[test]
	fn bitsov_jit_caps_and_retry_budget_survive_reload() {
		let (_dir, node) = node();
		let store = node.kv_store.as_ref();
		let peer = node.node_id().to_string();
		let mut j = Journal::load(store).unwrap();
		j.update(store, |j| {
			add(j, 1, &peer, 100);
			add(j, 2, &peer, 100);
			add(j, 3, &peer, 100);
		})
		.unwrap();
		assert_eq!(j.metrics().capital_locked_sats, 466000);
		let reloaded = Journal::load(store).unwrap();
		assert_eq!(reloaded.opens["1"].funding_cap(10000), 2000);
		assert_eq!(reloaded.opens["1"].funding_cap(1000), 1000);
		assert_eq!(j.metrics().pending_opens, 2);
		assert_eq!(j.opens["3"].phase, Phase::Failed);
		for now in [100, 102, 106, 114, 122] {
			j = Journal::load(store).unwrap();
			assert!(j.update(store, |j| j.begin(1, now)).unwrap());
			// Once dispatched, reload must NEVER expose it as due for retry.
			assert!(!Journal::load(store).unwrap().due(now + 1).contains(&1));
			j.update(store, |j| j.failed(1, now)).unwrap();
			assert!(!j.due(now + 1).contains(&1));
		}
		j = Journal::load(store).unwrap();
		assert_eq!(j.opens["1"].phase, Phase::Failed);
		assert_eq!(j.metrics().open_retries, 4);
		assert_eq!(j.metrics().failed_opens, 6);
		assert_eq!(j.metrics().capital_locked_sats, 233000);
		j.update(store, |j| add(j, 1, &peer, 1000)).unwrap();
		assert!(
			!j.due(1000).contains(&1),
			"replay cannot refresh exhausted budget"
		);
	}
	#[test]
	fn bitsov_jit_deadline_duplicates_and_earned_fees() {
		let (_dir, node) = node();
		let store = node.kv_store.as_ref();
		let mut j = Journal::load(store).unwrap();
		let peer = node.node_id().to_string();
		j.update(store, |j| {
			add(j, 1, &peer, 100);
			add(j, 1, &peer, 110);
		})
		.unwrap();
		assert_eq!(j.metrics().capital_locked_sats, 233000);
		assert!(!j.update(store, |j| j.begin(1, 160)).unwrap());
		assert_eq!(j.metrics().capital_locked_sats, 0);
		j.update(store, |j| {
			add(j, 2, &peer, 200);
			assert!(j.begin(2, 200));
			j.observe(2, "00".repeat(32), true);
			j.observe(2, "00".repeat(32), true);
			j.forwarded(&"00".repeat(32), 1000000);
			j.forwarded(&"00".repeat(32), 1000000);
		})
		.unwrap();
		let m = Journal::load(store).unwrap().metrics();
		assert_eq!(m.opens, 1);
		assert_eq!(m.opening_fees_earned_msat, 1000000);
		assert_eq!(m.pending_opens, 0);
		assert_eq!(m.capital_locked_sats, 233000);
	}
	#[test]
	fn bitsov_jit_write_failure_does_not_release_or_dispatch() {
		let (dir, node) = node();
		let store = node.kv_store.as_ref();
		let peer = node.node_id().to_string();
		let mut j = Journal::load(store).unwrap();
		j.update(store, |j| add(j, 1, &peer, 100)).unwrap();
		let path = dir.path().join("fs_store").join(NAMESPACE);
		let backup = dir.path().join("saved-journal");
		std::fs::rename(&path, &backup).unwrap();
		std::fs::write(&path, b"force namespace write failure").unwrap();
		assert!(j.update(store, |j| j.begin(1, 100)).is_err());
		assert_eq!(j.opens["1"].phase, Phase::Waiting);
		assert_eq!(j.opens["1"].attempts, 0);
		assert_eq!(j.metrics().capital_locked_sats, 233000);
		std::fs::remove_file(&path).unwrap();
		std::fs::rename(backup, path).unwrap();
		assert_eq!(Journal::load(store).unwrap().opens["1"].attempts, 0);
	}

	#[test]
	fn bitsov_jit_mpp_skim_accumulates_without_exceeding_quote() {
		let (_dir, node) = node();
		let store = node.kv_store.as_ref();
		let mut j = Journal::load(store).unwrap();
		j.update(store, |j| {
			add(j, 1, &node.node_id().to_string(), 100);
			j.observe(1, "11".repeat(32), false);
			j.forwarded(&"11".repeat(32), 400000);
		})
		.unwrap();
		assert_eq!(j.metrics().opening_fees_earned_msat, 400000);
		j = Journal::load(store).unwrap();
		j.update(store, |j| j.forwarded(&"11".repeat(32), 600000))
			.unwrap();
		assert_eq!(j.metrics().opening_fees_earned_msat, 1000000);
		j.update(store, |j| j.forwarded(&"11".repeat(32), 600000))
			.unwrap();
		assert_eq!(j.metrics().opening_fees_earned_msat, 1000000);
	}

	#[test]
	fn bitsov_jit_capital_limit_is_independent_of_slots_and_checked_for_overflow() {
		let (_dir, node) = node();
		let store = node.kv_store.as_ref();
		let mut j = Journal::load(store).unwrap();
		let peer = node.node_id().to_string();
		j.insert(
			OpenRequest {
				id: 1,
				peer: peer.clone(),
				amount_sats: 198000,
				opening_fee_msat: 1000000,
				funding_fee_cap_sats: 2000,
				reserve: 233000,
			},
			100,
			(10, 233000),
			(0, 0),
		)
		.unwrap();
		assert_eq!(j.metrics().capital_locked_sats, 233000);
		j.insert(
			OpenRequest {
				id: 2,
				peer: peer.clone(),
				amount_sats: 1,
				opening_fee_msat: 1,
				funding_fee_cap_sats: 1,
				reserve: 1,
			},
			100,
			(10, 233000),
			(0, 0),
		)
		.unwrap();
		assert_eq!(j.opens["2"].phase, Phase::Failed);
		j.insert(
			OpenRequest {
				id: 3,
				peer,
				amount_sats: 1,
				opening_fee_msat: 1,
				funding_fee_cap_sats: 1,
				reserve: 1,
			},
			100,
			(10, u64::MAX),
			(u64::MAX, 0),
		)
		.unwrap();
		assert_eq!(j.opens["3"].phase, Phase::Failed);
	}

	#[test]
	fn bitsov_jit_close_before_ready_counts_failure_once_and_retains_capital() {
		let (_dir, node) = node();
		let store = node.kv_store.as_ref();
		let mut j = Journal::load(store).unwrap();
		j.update(store, |j| {
			add(j, 1, &node.node_id().to_string(), 100);
			assert!(j.begin(1, 100));
			j.closed(1);
			j.closed(1);
		})
		.unwrap();
		let m = Journal::load(store).unwrap().metrics();
		assert_eq!(m.failed_opens, 1);
		assert_eq!(m.opens, 0);
		assert_eq!(m.pending_opens, 0);
		assert_eq!(m.capital_locked_sats, 233000);
	}

	#[test]
	fn bitsov_jit_corrupt_journal_refuses_startup() {
		let (_dir, node) = node();
		KVStoreSync::write(
			node.kv_store.as_ref(),
			NAMESPACE,
			"",
			"opens",
			b"{}".to_vec(),
		)
		.unwrap();
		assert!(Journal::load(node.kv_store.as_ref()).is_err());
	}
}
