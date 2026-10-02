//! Durable local spend ownership, independent of a chain source's mempool view.
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bitcoin::{OutPoint, Transaction, Txid};
use lightning::util::persist::KVStoreSync;

use crate::{types::DynStore, Error};

const NAMESPACE: &str = "bitsov_local_spends";

struct Spend {
	tx: Transaction,
	bump: bool,
	verified: bool,
}

pub(super) struct LocalSpends {
	store: Arc<DynStore>,
	spends: HashMap<Txid, Spend>,
}

impl LocalSpends {
	pub(super) fn load(store: Arc<DynStore>) -> Result<Self, Error> {
		let mut spends = HashMap::new();
		for key in
			KVStoreSync::list(&*store, NAMESPACE, "").map_err(|_| Error::PersistenceFailed)?
		{
			let bytes = KVStoreSync::read(&*store, NAMESPACE, "", &key)
				.map_err(|_| Error::PersistenceFailed)?;
			if bytes.len() < 3 || bytes[0] > 1 || bytes[1] > 1 {
				return Err(Error::PersistenceFailed);
			}
			let tx: Transaction = bitcoin::consensus::deserialize(&bytes[2..])
				.map_err(|_| Error::PersistenceFailed)?;
			if tx.compute_txid().to_string() != key {
				return Err(Error::PersistenceFailed);
			}
			spends.insert(
				tx.compute_txid(),
				Spend { tx, bump: bytes[0] == 1, verified: bytes[1] == 1 },
			);
		}
		Ok(Self { store, spends })
	}

	fn persist(&self, txid: Txid) -> Result<(), Error> {
		let spend = &self.spends[&txid];
		let mut bytes = vec![u8::from(spend.bump), u8::from(spend.verified)];
		bytes.extend(bitcoin::consensus::serialize(&spend.tx));
		KVStoreSync::write(&*self.store, NAMESPACE, "", &txid.to_string(), bytes)
			.map_err(|_| Error::PersistenceFailed)
	}

	pub(super) fn record(&mut self, tx: &Transaction, bump: bool) -> Result<(), Error> {
		let txid = tx.compute_txid();
		self.spends.entry(txid).or_insert_with(|| Spend { tx: tx.clone(), bump, verified: false });
		// Keep the in-memory reservation even on a failed write. No broadcast is
		// allowed until this and BDK persistence both succeed.
		self.persist(txid)
	}

	pub(super) fn verified(&mut self, txid: Txid) -> Result<(), Error> {
		if let Some(spend) = self.spends.get_mut(&txid) {
			if !spend.verified {
				spend.verified = true;
				self.persist(txid)?;
			}
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
		self.verified(txid)?;
		// A confirmed replacement definitively spends the shared claim/input.
		// Its abandoned variants must not strand their additional fee inputs.
		let superseded: Vec<_> = self
			.spends
			.iter()
			.filter_map(|(id, spend)| {
				(*id != txid
					&& spend.tx.input.iter().any(|old| {
						tx.input.iter().any(|new| old.previous_output == new.previous_output)
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
						&& owner.tx.input.iter().any(|input| input.previous_output == *point)
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
					points.extend(
						(0..spend.tx.output.len()).map(|vout| OutPoint { txid, vout: vout as u32 }),
					);
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
