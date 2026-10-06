//! Narrow prepare/replay boundary for owner-authorized migration.
use super::*;

impl Wallet {
	/// Pure with respect to coins: do not register a local spend or broadcast.
	/// The caller holds the exclusive node lease and persists owner consent and
	/// these exact signed bytes before calling replay_move_home.
	#[allow(deprecated)]
	pub(crate) fn prepare_move_home(
		&self,
		address: &Address,
		fee_rate: FeeRate,
	) -> Result<(Transaction, u64), Error> {
		self.parse_and_validate_address(address)?;
		let mut wallet = self.inner.lock().unwrap();
		if wallet.is_mine(address.script_pubkey()) {
			return Err(Error::InvalidAddress);
		}
		// Refuse pre-existing outgoing ownership, including unreadable records.
		// It must be resolved using the ordinary owner's reservation workflow.
		let local = self.local_spends.lock().unwrap();
		if local.unreadable_rows != 0 || !local.reservations().is_empty() {
			return Err(Error::WalletOperationFailed);
		}
		drop(local);
		let mut builder = wallet.build_tx();
		builder
			.drain_wallet()
			.drain_to(address.script_pubkey())
			.fee_rate(fee_rate)
			.exclude_unconfirmed()
			.ordering(bdk_wallet::TxOrdering::Custom {
				input_sort: Arc::new(|a, b| a.previous_output.cmp(&b.previous_output)),
				output_sort: Arc::new(|a, b| a.script_pubkey.cmp(&b.script_pubkey)),
			});
		let mut psbt = builder.finish().map_err(|_| Error::OnchainTxCreationFailed)?;
		let fee = wallet
			.calculate_fee(&psbt.unsigned_tx)
			.map_err(|_| Error::WalletOperationFailed)?
			.to_sat();
		if !wallet
			.sign(&mut psbt, SignOptions::default())
			.map_err(|_| Error::OnchainTxSigningFailed)?
		{
			return Err(Error::OnchainTxSigningFailed);
		}
		let tx = psbt.extract_tx().map_err(|_| Error::OnchainTxCreationFailed)?;
		if tx.output.len() != 1 || tx.output[0].script_pubkey != address.script_pubkey() {
			return Err(Error::InvalidAddress);
		}
		Ok((tx, fee))
	}

	pub(crate) fn replay_move_home(
		&self,
		tx: &Transaction,
		address: &Address,
		expected_fee: u64,
	) -> Result<(), Error> {
		self.parse_and_validate_address(address)?;
		if tx.input.is_empty()
			|| tx.output.len() != 1
			|| tx.output[0].script_pubkey != address.script_pubkey()
		{
			return Err(Error::InvalidAddress);
		}
		let mut wallet = self.inner.lock().unwrap();
		if wallet.is_mine(address.script_pubkey()) {
			return Err(Error::InvalidAddress);
		}
		// Validate persisted transaction economics against our actual previous outputs.
		if wallet.calculate_fee(tx).map_err(|_| Error::WalletOperationFailed)?.to_sat()
			!= expected_fee
		{
			return Err(Error::WalletOperationFailed);
		}
		let owned =
			wallet.list_output().map(|u| u.outpoint).collect::<std::collections::HashSet<_>>();
		if tx.input.iter().any(|i| !owned.contains(&i.previous_output) || i.witness.is_empty()) {
			return Err(Error::WalletOperationFailed);
		}
		// record_outgoing_transaction is idempotent by txid; a crash here can only
		// lead to replay of the same transaction saved in the migration journal.
		self.record_outgoing_transaction(&mut wallet, tx, false)?;
		drop(wallet);
		self.broadcaster.broadcast_transactions(&[tx]);
		Ok(())
	}

	pub(crate) fn move_home_confirmations(&self, txid: Txid) -> u32 {
		let wallet = self.inner.lock().unwrap();
		let confirmations = wallet
			.transactions()
			.find_map(|tx| {
				if tx.tx_node.txid != txid {
					return None;
				}
				Some(match tx.chain_position {
					bdk_chain::ChainPosition::Confirmed { anchor, .. } => {
						wallet.latest_checkpoint().height().saturating_sub(anchor.block_id.height)
							+ 1
					}
					_ => 0,
				})
			})
			.unwrap_or(0);
		confirmations
	}
}
