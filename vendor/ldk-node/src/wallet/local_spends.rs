//! Durable local spend ownership, independent of a chain source's mempool view.
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bitcoin::{OutPoint, Transaction, Txid};
use lightning::util::persist::KVStoreSync;

use crate::{types::DynStore, Error};

const NAMESPACE: &str = "bitsov_local_spends";
pub(super) const ABSENCE_WINDOW_SECS: u64 = 24 * 60 * 60;

pub(crate) fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}

/// Durable reservation metadata; timestamps are Unix seconds.
#[derive(Clone, Debug)]
pub struct LocalSpendReservation {
	/// Transaction owning the inputs.
	pub txid: Txid,
	/// Time the signed spend was first reserved.
	pub created_at: u64,
	/// Most recent successful chain-source sighting.
	pub last_seen_at: Option<u64>,
}

struct Spend {
	tx: Transaction,
	bump: bool,
	verified: bool,
	created_at: u64,
	last_seen_at: Option<u64>,
}

pub(super) struct LocalSpends {
	store: Arc<DynStore>,
	spends: HashMap<Txid, Spend>,
	pub(super) unreadable_rows: u64,
}

impl LocalSpends {
	pub(super) fn load(store: Arc<DynStore>) -> Result<Self, Error> {
		let mut result = Self {
			store,
			spends: HashMap::new(),
			unreadable_rows: 0,
		};
		for key in KVStoreSync::list(&*result.store, NAMESPACE, "")
			.map_err(|_| Error::PersistenceFailed)?
		{
			let bytes = KVStoreSync::read(&*result.store, NAMESPACE, "", &key).ok();
			let legacy = bytes.as_ref().map_or(false, |b| b.first() != Some(&2));
			let decoded = bytes.as_ref().and_then(|bytes| Self::decode(bytes));
			match decoded {
				Some(spend) if spend.tx.compute_txid().to_string() == key => {
					let txid = spend.tx.compute_txid();
					result.spends.insert(txid, spend);
					// Migrate legacy rows once so restarting cannot reset their age.
					if legacy {
						result.persist(txid)?;
					}
				}
				_ => result.unreadable_rows += 1,
			}
		}
		Ok(result)
	}

	fn decode(bytes: &[u8]) -> Option<Spend> {
		let (flags, created_at, last_seen_at, tx_bytes) = if bytes.first() == Some(&2) {
			if bytes.len() < 20 {
				return None;
			}
			let created = u64::from_le_bytes(bytes[3..11].try_into().ok()?);
			let seen = u64::from_le_bytes(bytes[11..19].try_into().ok()?);
			(
				&bytes[1..3],
				created,
				(seen != 0).then_some(seen),
				&bytes[19..],
			)
		} else {
			if bytes.len() < 3 {
				return None;
			}
			(&bytes[..2], now(), None, &bytes[2..])
		};
		if flags[0] > 1 || flags[1] > 1 {
			return None;
		}
		Some(Spend {
			tx: bitcoin::consensus::deserialize(tx_bytes).ok()?,
			bump: flags[0] == 1,
			verified: flags[1] == 1,
			created_at,
			last_seen_at,
		})
	}

	pub(super) fn reservations(&self) -> Vec<LocalSpendReservation> {
		self.spends
			.iter()
			.map(|(txid, s)| LocalSpendReservation {
				txid: *txid,
				created_at: s.created_at,
				last_seen_at: s.last_seen_at,
			})
			.collect()
	}

	pub(super) fn expired(&self, txid: Txid, at: u64) -> bool {
		self.spends.get(&txid).map_or(false, |s| {
			at.saturating_sub(s.last_seen_at.unwrap_or(s.created_at).max(s.created_at))
				>= ABSENCE_WINDOW_SECS
		})
	}

	fn persist(&self, txid: Txid) -> Result<(), Error> {
		let spend = &self.spends[&txid];
		let mut bytes = vec![2, u8::from(spend.bump), u8::from(spend.verified)];
		bytes.extend(spend.created_at.to_le_bytes());
		bytes.extend(spend.last_seen_at.unwrap_or(0).to_le_bytes());
		bytes.extend(bitcoin::consensus::serialize(&spend.tx));
		KVStoreSync::write(&*self.store, NAMESPACE, "", &txid.to_string(), bytes)
			.map_err(|_| Error::PersistenceFailed)
	}

	pub(super) fn record(&mut self, tx: &Transaction, bump: bool) -> Result<(), Error> {
		let txid = tx.compute_txid();
		self.spends.entry(txid).or_insert_with(|| Spend {
			tx: tx.clone(),
			bump,
			verified: false,
			created_at: now(),
			last_seen_at: None,
		});
		// Keep the in-memory reservation even on a failed write. No broadcast is
		// allowed until this and BDK persistence both succeed.
		self.persist(txid)
	}

	pub(super) fn verified(&mut self, txid: Txid) -> Result<(), Error> {
		if let Some(spend) = self.spends.get_mut(&txid) {
			spend.verified = true;
			spend.last_seen_at = Some(now());
			self.persist(txid)?;
		}
		Ok(())
	}

	pub(super) fn transaction(&self, txid: Txid) -> Option<Transaction> {
		self.spends.get(&txid).map(|spend| spend.tx.clone())
	}

	pub(super) fn abandon(&mut self, txid: Txid) -> Result<(), Error> {
		KVStoreSync::remove(&*self.store, NAMESPACE, "", &txid.to_string(), false)
			.map_err(|_| Error::PersistenceFailed)?;
		self.spends.remove(&txid);
		Ok(())
	}

	pub(super) fn confirmed(&mut self, tx: &Transaction) -> Result<(), Error> {
		let txid = tx.compute_txid();
		if self.spends.contains_key(&txid) {
			self.abandon(txid)?;
		}
		// A confirmed replacement definitively spends the shared claim/input.
		// Its abandoned variants must not strand their additional fee inputs.
		let superseded: Vec<_> = self
			.spends
			.iter()
			.filter_map(|(id, spend)| {
				(*id != txid
					&& spend.tx.input.iter().any(|old| {
						tx.input
							.iter()
							.any(|new| old.previous_output == new.previous_output)
					}))
				.then_some(*id)
			})
			.collect();
		for id in superseded {
			self.abandon(id)?;
		}
		Ok(())
	}

	pub(super) fn bump_inputs(
		&self,
		confirmed: &HashSet<Txid>,
		claim: Option<OutPoint>,
		allow_other_bumps: bool,
	) -> HashSet<OutPoint> {
		self.spends
			.iter()
			.filter(|(txid, spend)| {
				spend.bump
					&& !confirmed.contains(*txid)
					&& (allow_other_bumps
						|| (claim.is_some()
							&& spend.tx.input.first().map(|i| i.previous_output) == claim))
			})
			.flat_map(|(_, spend)| spend.tx.input.iter().map(|i| i.previous_output))
			.filter(|point| {
				!self.spends.values().any(|owner| {
					!owner.bump
						&& owner
							.tx
							.input
							.iter()
							.any(|input| input.previous_output == *point)
				})
			})
			.collect()
	}

	pub(super) fn unavailable(&self) -> Vec<OutPoint> {
		self.spends
			.values()
			.flat_map(|spend| {
				let mut points: Vec<_> = spend.tx.input.iter().map(|i| i.previous_output).collect();
				if !spend.verified {
					let txid = spend.tx.compute_txid();
					points.extend((0..spend.tx.output.len()).map(|vout| OutPoint {
						txid,
						vout: vout as u32,
					}));
				}
				points
			})
			.collect()
	}

	/// LDK selects bump inputs before asking us to sign. Recheck under the wallet
	/// lock so a stale selection can never conflict with a funding/payment spend.
	/// LDK's deliberate bump-vs-bump replacements remain valid; ordinary spends never do.
	pub(super) fn check_bump(&self, tx: &Transaction) -> Result<(), ()> {
		for spend in self.spends.values() {
			if !spend.bump
				&& tx.input.iter().any(|input| {
					spend
						.tx
						.input
						.iter()
						.any(|previous| previous.previous_output == input.previous_output)
				}) {
				return Err(());
			}
		}
		Ok(())
	}
}
