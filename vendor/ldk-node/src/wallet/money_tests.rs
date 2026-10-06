use super::*;
use bitcoin::{OutPoint, Sequence, TxIn, Witness};

fn node(dir: &std::path::Path) -> crate::Node {
	let mut builder = crate::Builder::new();
	builder.set_network(bitcoin::Network::Regtest);
	builder.set_entropy_seed_bytes([73; 64]);
	builder.set_storage_dir_path(dir.to_str().unwrap().into());
	// Never start the node: real BDK signing/persistence, no network or funds.
	builder.build_with_fs_store().unwrap()
}

fn fund(wallet: &Wallet) {
	let address = wallet.get_new_address().unwrap();
	let tx = Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: LockTime::ZERO,
		input: vec![TxIn {
			previous_output: OutPoint { txid: Txid::from_byte_array([42; 32]), vout: 0 },
			script_sig: ScriptBuf::new(),
			sequence: Sequence::MAX,
			witness: Witness::new(),
		}],
		output: vec![
			TxOut {
				value: Amount::from_sat(150_000),
				script_pubkey: address.script_pubkey()
			};
			2
		],
	};
	let tip = wallet.inner.lock().unwrap().latest_checkpoint();
	let block =
		bdk_chain::BlockId { height: 1, hash: bitcoin::BlockHash::from_byte_array([1; 32]) };
	let anchor = bdk_chain::ConfirmationBlockTime { block_id: block, confirmation_time: 1 };
	let mut tx_update = bdk_chain::TxUpdate::default();
	tx_update.anchors.insert((anchor, tx.compute_txid()));
	tx_update.txs.push(Arc::new(tx));
	wallet
		.apply_update(Update {
			tx_update,
			chain: Some(tip.push(block).unwrap()),
			..Default::default()
		})
		.unwrap();
}

fn funding(wallet: &Wallet, destination: u8) -> Transaction {
	let key = bitcoin::secp256k1::PublicKey::from_secret_key(
		&Secp256k1::new(),
		&SecretKey::from_slice(&[destination; 32]).unwrap(),
	);
	let script =
		bitcoin::Address::p2wpkh(&bitcoin::CompressedPublicKey(key), bitcoin::Network::Regtest)
			.script_pubkey();
	wallet
		.create_funding_transaction(
			script,
			Amount::from_sat(80_000),
			ConfirmationTarget::ChannelFunding,
			LockTime::ZERO,
		)
		.unwrap()
}

fn assert_distinct_inputs(first: &Transaction, second: &Transaction) {
	for input in &first.input {
		assert!(
			!second.input.iter().any(|other| other.previous_output == input.previous_output),
			"two operations selected the same wallet input"
		);
	}
}

#[test]
fn concurrent_funding_transactions_do_not_reuse_inputs() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let barrier = std::sync::Barrier::new(2);
	let (first, second) = std::thread::scope(|scope| {
		let a = scope.spawn(|| {
			barrier.wait();
			funding(&node.wallet, 2)
		});
		let b = scope.spawn(|| {
			barrier.wait();
			funding(&node.wallet, 3)
		});
		(a.join().unwrap(), b.join().unwrap())
	});
	assert_distinct_inputs(&first, &second);
}

#[test]
fn funding_inputs_remain_spent_after_restart_without_chain_sync() {
	let dir = tempfile::tempdir().unwrap();
	let first = {
		let node = node(dir.path());
		fund(&node.wallet);
		funding(&node.wallet, 2)
	};
	let node = node(dir.path());
	assert_distinct_inputs(&first, &funding(&node.wallet, 3));
}

#[test]
fn onchain_send_then_funding_does_not_reuse_inputs() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let address = node.wallet.get_new_address().unwrap();
	let txid = node
		.wallet
		.send_to_address(
			&address,
			OnchainSendAmount::ExactRetainingReserve {
				amount_sats: 80_000,
				cur_anchor_reserve_sats: 0,
			},
			Some(FeeRate::from_sat_per_vb(2).unwrap()),
		)
		.unwrap();
	let first = node
		.wallet
		.get_cached_txs()
		.into_iter()
		.find(|tx| tx.compute_txid() == txid)
		.expect("signed send must be registered in BDK before returning");
	assert_distinct_inputs(&first, &funding(&node.wallet, 3));
}

#[test]
fn single_funding_keeps_amount_and_estimated_fee() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let tx = funding(&node.wallet, 2);
	assert!(tx.output.iter().any(|out| out.value == Amount::from_sat(80_000)));
	assert_eq!(tx.input.len(), 1);
	assert!(!tx.input[0].witness.is_empty());
	let fee = node.wallet.inner.lock().unwrap().calculate_fee(&tx).unwrap();
	let rate = node.wallet.fee_estimator.estimate_fee_rate(ConfirmationTarget::ChannelFunding);
	assert!(fee >= rate * tx.weight());
}

fn small_funding(wallet: &Wallet) -> Result<Transaction, Error> {
	wallet.create_funding_transaction(
		ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array([9; 32])),
		Amount::from_sat(10_000),
		ConfirmationTarget::ChannelFunding,
		LockTime::ZERO,
	)
}

#[test]
fn eviction_and_restart_do_not_release_uncertain_inputs_or_change() {
	let dir = tempfile::tempdir().unwrap();
	let (first, second) = {
		let node = node(dir.path());
		fund(&node.wallet);
		let first = funding(&node.wallet, 2);
		let second = funding(&node.wallet, 3);
		node.wallet
			.apply_mempool_txs(
				vec![],
				vec![(first.compute_txid(), u64::MAX), (second.compute_txid(), u64::MAX)],
			)
			.unwrap();
		assert!(
			small_funding(&node.wallet).is_err(),
			"chain-source absence must not release our inputs"
		);
		(first, second)
	};
	let node = node(dir.path());
	assert!(
		small_funding(&node.wallet).is_err(),
		"reservation must survive restart after eviction"
	);
	assert_distinct_inputs(&first, &second);
}

#[test]
fn unresolved_change_cannot_fund_another_transaction() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let first = funding(&node.wallet, 2);
	let _second = funding(&node.wallet, 3);
	assert!(small_funding(&node.wallet).is_err());
	node.transaction_broadcast_verified(first.compute_txid()).unwrap();
	let next = small_funding(&node.wallet).unwrap();
	assert!(next.input.iter().any(|input| input.previous_output.txid == first.compute_txid()));
	assert_distinct_inputs(&first, &next);
}

#[test]
fn definitive_funding_abandonment_recycles_inputs_without_poisoned_change() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let first = funding(&node.wallet, 2);
	let _second = funding(&node.wallet, 3);
	node.wallet.abandon_funding(&first).unwrap();
	let replacement = funding(&node.wallet, 4);
	assert_eq!(replacement.input[0].previous_output, first.input[0].previous_output);
	assert!(replacement
		.input
		.iter()
		.all(|input| input.previous_output.txid != first.compute_txid()));
}

fn bump_psbt(wallet: &Wallet) -> Psbt {
	let mut inner = wallet.inner.lock().unwrap();
	let unavailable = wallet.local_spends.lock().unwrap().unavailable();
	let mut builder = inner.build_tx();
	builder.unspendable(unavailable);
	builder
		.add_recipient(
			ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array([8; 32])),
			Amount::from_sat(80_000),
		)
		.fee_rate(FeeRate::from_sat_per_vb(2).unwrap());
	let mut psbt = builder.finish().unwrap();
	// Model the LDK-provided anchor as the first, already-signed foreign input.
	psbt.unsigned_tx.input.insert(
		0,
		TxIn {
			previous_output: OutPoint { txid: Txid::from_byte_array([88; 32]), vout: 0 },
			script_sig: ScriptBuf::new(),
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
			witness: Witness::new(),
		},
	);
	psbt.inputs.insert(
		0,
		bitcoin::psbt::Input {
			witness_utxo: Some(TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new() }),
			final_script_witness: Some(Witness::from_slice(&[&[1]])),
			..Default::default()
		},
	);
	psbt
}

#[test]
fn close_fee_spend_is_reserved_before_next_funding() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let bump = node.wallet.sign_psbt_inner(bump_psbt(&node.wallet)).unwrap();
	let funding = funding(&node.wallet, 2);
	assert_distinct_inputs(&bump, &funding);
	assert!(small_funding(&node.wallet).is_err());
}

#[test]
fn stale_close_fee_coin_selection_cannot_sign_over_a_funding_spend() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let stale_bump = bump_psbt(&node.wallet);
	let _first = funding(&node.wallet, 2);
	let _second = funding(&node.wallet, 3);
	assert!(node.wallet.sign_psbt_inner(stale_bump).is_err());
}

#[test]
fn pending_close_fee_inputs_remain_available_for_rbf_only() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let psbt = bump_psbt(&node.wallet);
	let previous_input = psbt.unsigned_tx.input[1].previous_output;
	let bump = node.wallet.sign_psbt_inner(psbt.clone()).unwrap();
	assert!(
		node.wallet
			.list_confirmed_utxos_for_claim(Some(bump.input[0].previous_output), false)
			.unwrap()
			.iter()
			.any(|utxo| utxo.outpoint == previous_input),
		"an unresolved bump must be able to replace its own fee spend"
	);
	let next = funding(&node.wallet, 2);
	assert_distinct_inputs(&bump, &next);
	let mut replacement = psbt;
	replacement.unsigned_tx.output[0].value -= Amount::from_sat(500);
	node.wallet.sign_psbt_inner(replacement).unwrap();
}

// Advance either sync path without introducing another spend.
fn advance_confirmations(wallet: &Wallet, via_blocks: bool, through: u32) {
	for height in 3..=through {
		let mut block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
		block.header.prev_blockhash = wallet.current_best_block().block_hash;
		block.header.nonce = height;
		block.txdata.clear();
		if via_blocks {
			wallet.block_connected(&block, height);
		} else {
			let tip = wallet.inner.lock().unwrap().latest_checkpoint();
			wallet
				.apply_update(Update {
					chain: Some(
						tip.push(bdk_chain::BlockId { height, hash: block.block_hash() }).unwrap(),
					),
					..Default::default()
				})
				.unwrap();
		}
	}
}

#[test]
fn shallow_reorg_retains_input_reservations_across_restart_and_eviction() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let first = funding(&node.wallet, 2);
	funding(&node.wallet, 3);
	let fork = node.wallet.current_best_block();
	let mut block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
	block.header.prev_blockhash = fork.block_hash;
	block.txdata = vec![first.clone()];
	node.wallet.block_connected(&block, 2);
	node.wallet.blocks_disconnected(fork);
	block.header.nonce += 1;
	block.txdata.clear();
	node.wallet.block_connected(&block, 2);
	node.wallet.apply_mempool_txs(vec![(first.clone(), local_spends::now())], vec![]).unwrap();
	assert!(node
		.wallet
		.inner
		.lock()
		.unwrap()
		.transactions()
		.any(|tx| tx.tx_node.txid == first.compute_txid() && !tx.chain_position.is_confirmed()));
	drop(node);
	let node = self::node(dir.path());
	// Even if the reorged mempool spend later disappears from BDK's view,
	// its input must remain unavailable to both ordinary and bump builders.
	node.wallet
		.apply_mempool_txs(vec![], vec![(first.compute_txid(), local_spends::now() + 1)])
		.unwrap();
	assert!(
		node.wallet
			.create_funding_transaction(
				ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array([9; 32])),
				Amount::from_sat(80_000),
				ConfirmationTarget::ChannelFunding,
				LockTime::ZERO,
			)
			.is_err(),
		"shallow reorg unlocked a signed spend's input"
	);
	assert!(node
		.wallet
		.list_confirmed_utxos_inner()
		.unwrap()
		.iter()
		.all(|utxo| first.input.iter().all(|i| i.previous_output != utxo.outpoint)));
	assert!(node.local_spend_reservations().iter().any(|r| r.txid == first.compute_txid()));
}

#[test]
fn source_absence_cannot_release_shallow_confirmed_spends_or_replacements() {
	for replacement in [false, true] {
		for owner_release in [false, true] {
			let dir = tempfile::tempdir().unwrap();
			let node = node(dir.path());
			fund(&node.wallet);
			let first = if replacement {
				node.wallet.sign_psbt_inner(bump_psbt(&node.wallet)).unwrap()
			} else {
				funding(&node.wallet, 2)
			};
			let confirmed = if replacement {
				node.wallet.sign_psbt_inner(bump_psbt(&node.wallet)).unwrap()
			} else {
				first.clone()
			};
			let mut block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
			block.header.prev_blockhash = node.wallet.current_best_block().block_hash;
			block.txdata = vec![confirmed];
			node.wallet.block_connected(&block, 2);
			age_reservation(&node, first.compute_txid(), 1, None);
			// Core without txindex can report not-found for a confirmed tx.
			// That source result must not override the wallet's chain evidence.
			if owner_release {
				let error = node.release_local_spend(first.compute_txid()).unwrap_err();
				assert!(error.to_string().contains("confirmed"));
			} else {
				node.reconcile_local_spend(first.compute_txid(), false).unwrap();
			}
			assert!(node.local_spend_reservations().iter().any(|r| r.txid == first.compute_txid()));
		}
	}
}

#[test]
fn reservation_cleanup_waits_for_finality_on_both_sync_paths() {
	for via_blocks in [false, true] {
		let dir = tempfile::tempdir().unwrap();
		let node = node(dir.path());
		fund(&node.wallet);
		let first = funding(&node.wallet, 2);
		let mut block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
		block.header.prev_blockhash = node.wallet.current_best_block().block_hash;
		block.txdata = vec![first.clone()];
		node.wallet.block_connected(&block, 2);
		advance_confirmations(&node.wallet, via_blocks, ANTI_REORG_DELAY);
		assert!(
			node.local_spend_reservations().iter().any(|r| r.txid == first.compute_txid()),
			"reservation removed one confirmation before finality"
		);
		drop(node);
		let node = self::node(dir.path());
		let mut block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
		block.header.prev_blockhash = node.wallet.current_best_block().block_hash;
		block.txdata.clear();
		let height = ANTI_REORG_DELAY + 1;
		if via_blocks {
			node.wallet.block_connected(&block, height);
		} else {
			let tip = node.wallet.inner.lock().unwrap().latest_checkpoint();
			node.wallet
				.apply_update(Update {
					chain: Some(
						tip.push(bdk_chain::BlockId { height, hash: block.block_hash() }).unwrap(),
					),
					..Default::default()
				})
				.unwrap();
		}
		assert!(node.local_spend_reservations().is_empty());
		drop(node);
		assert!(self::node(dir.path()).local_spend_reservations().is_empty());
	}
}

#[test]
fn core_block_confirmation_releases_change_without_mempool_observation() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let first = funding(&node.wallet, 2);
	let _second = funding(&node.wallet, 3);
	let mut block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
	block.header.prev_blockhash = node.wallet.current_best_block().block_hash;
	block.txdata = vec![first.clone()];
	node.wallet.block_connected(&block, 2);
	drop(node);
	let node = self::node(dir.path());
	let next = small_funding(&node.wallet).unwrap();
	assert!(next.input.iter().any(|input| input.previous_output.txid == first.compute_txid()));
}

#[test]
fn finalized_bump_replacement_releases_unused_fee_input() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let first = node.wallet.sign_psbt_inner(bump_psbt(&node.wallet)).unwrap();
	let second = node.wallet.sign_psbt_inner(bump_psbt(&node.wallet)).unwrap();
	let old_fee_input = first.input[1].previous_output;
	let confirmed_fee_input = second.input[1].previous_output;
	assert_ne!(old_fee_input, confirmed_fee_input);
	let mut block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
	block.header.prev_blockhash = node.wallet.current_best_block().block_hash;
	block.txdata = vec![second];
	node.wallet.block_connected(&block, 2);
	advance_confirmations(&node.wallet, true, ANTI_REORG_DELAY);
	assert_eq!(node.local_spend_reservations().len(), 2);
	assert!(
		node.wallet
			.create_funding_transaction(
				ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array([9; 32])),
				Amount::from_sat(80_000),
				ConfirmationTarget::ChannelFunding,
				LockTime::ZERO,
			)
			.is_err(),
		"replacement freed fee input before finality"
	);
	let mut final_block = block.clone();
	final_block.header.prev_blockhash = node.wallet.current_best_block().block_hash;
	final_block.txdata.clear();
	node.wallet.block_connected(&final_block, ANTI_REORG_DELAY + 1);
	assert!(node.local_spend_reservations().is_empty());
	drop(node);
	let node = self::node(dir.path());
	let next = funding(&node.wallet, 3);
	assert!(next.input.iter().any(|input| input.previous_output == old_fee_input));
	assert!(!node
		.wallet
		.list_confirmed_utxos_inner()
		.unwrap()
		.iter()
		.any(|utxo| utxo.outpoint == confirmed_fee_input));
}

#[tokio::test]
async fn restarted_ldk_selector_respects_persisted_bump_claim_ownership() {
	use lightning::events::bump_transaction::CoinSelectionSource;
	let dir = tempfile::tempdir().unwrap();
	let (original, reserved) = {
		let node = node(dir.path());
		fund(&node.wallet);
		let original = bump_psbt(&node.wallet);
		let reserved = original.unsigned_tx.input[1].previous_output;
		node.wallet.sign_psbt_inner(original.clone()).unwrap();
		(original, reserved)
	};
	let node = node(dir.path());
	let selector = super::bump::BumpWallet::new(node.wallet.clone(), node.logger.clone());
	let claim = |byte| {
		vec![Input {
			outpoint: OutPoint { txid: Txid::from_byte_array([byte; 32]), vout: 0 },
			previous_utxo: TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new() },
			satisfaction_weight: 200,
		}]
	};
	let other = selector
		.select_confirmed_utxos(lightning::chain::ClaimId([2; 32]), claim(89), &[], 2000, 400_000)
		.await
		.unwrap();
	assert!(other.confirmed_utxos.iter().all(|utxo| utxo.outpoint != reserved));
	// Consume the other coin normally; the original claim must still be able to RBF.
	let ordinary = funding(&node.wallet, 3);
	assert!(ordinary.input.iter().all(|i| i.previous_output != reserved));
	let own = selector
		.select_confirmed_utxos(lightning::chain::ClaimId([1; 32]), claim(88), &[], 3000, 400_000)
		.await
		.unwrap();
	assert!(own.confirmed_utxos.iter().any(|utxo| utxo.outpoint == reserved));
	let mut replacement = original;
	replacement.unsigned_tx.output[0].value -= Amount::from_sat(500);
	selector.sign_psbt(replacement).await.unwrap();
}

#[tokio::test]
async fn ldks_required_last_resort_conflicts_never_include_ordinary_spends() {
	use lightning::events::bump_transaction::CoinSelectionSource;
	for reserve_as_bump in [true, false] {
		let dir = tempfile::tempdir().unwrap();
		let node = node(dir.path());
		fund(&node.wallet);
		let original = bump_psbt(&node.wallet);
		if reserve_as_bump {
			node.wallet.sign_psbt_inner(original.clone()).unwrap();
		} else {
			funding(&node.wallet, 2);
		}
		funding(&node.wallet, 3);
		let selector = super::bump::BumpWallet::new(node.wallet.clone(), node.logger.clone());
		let other_claim = OutPoint { txid: Txid::from_byte_array([89; 32]), vout: 0 };
		let result = selector
			.select_confirmed_utxos(
				lightning::chain::ClaimId([2; 32]),
				vec![Input {
					outpoint: other_claim,
					previous_utxo: TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new() },
					satisfaction_weight: 200,
				}],
				&[],
				2000,
				400_000,
			)
			.await;
		if reserve_as_bump {
			let selected = result.unwrap();
			assert_eq!(
				selected.confirmed_utxos[0].outpoint,
				original.unsigned_tx.input[1].previous_output
			);
			let mut replacement = original;
			replacement.unsigned_tx.input[0].previous_output = other_claim;
			replacement.unsigned_tx.output[0].value -= Amount::from_sat(500);
			selector.sign_psbt(replacement).await.unwrap();
		} else {
			assert!(
				result.is_err(),
				"even last-resort close recovery must not double-spend an ordinary send/open"
			);
		}
	}
}

#[test]
fn manual_broadcast_outpoint_discard_releases_inputs_and_is_idempotent() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let first = funding(&node.wallet, 2);
	funding(&node.wallet, 3);
	let discard = lightning::events::FundingInfo::OutPoint {
		outpoint: lightning::chain::transaction::OutPoint { txid: first.compute_txid(), index: 0 },
	};
	node.wallet.discard_funding(discard.clone()).unwrap();
	node.wallet.discard_funding(discard).unwrap();
	let next = funding(&node.wallet, 4);
	assert_eq!(next.input[0].previous_output, first.input[0].previous_output);
}

#[test]
fn malformed_reservation_does_not_prevent_restart() {
	let dir = tempfile::tempdir().unwrap();
	let first = node(dir.path());
	let store = first.wallet.persister.lock().unwrap().kv_store.clone();
	lightning::util::persist::KVStoreSync::write(
		&*store,
		"bitsov_local_spends",
		"",
		"bad-row",
		vec![9],
	)
	.unwrap();
	drop(first);
	let restarted = node(dir.path());
	assert_eq!(restarted.local_spend_unreadable_rows(), 1);
}

#[test]
fn failed_bdk_persist_does_not_pin_prebroadcast_funding() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	// An uninitialized BDK persister fails writes, while the reservation store
	// remains writable. This reproduces KV success followed by BDK failure.
	let store = node.wallet.persister.lock().unwrap().kv_store.clone();
	let replacement = KVStoreWalletPersister::new(store.clone(), node.logger.clone());
	let original = std::mem::replace(&mut *node.wallet.persister.lock().unwrap(), replacement);
	assert!(small_funding(&node.wallet).is_err());
	assert!(lightning::util::persist::KVStoreSync::list(&*store, "bitsov_local_spends", "")
		.unwrap()
		.is_empty());
	*node.wallet.persister.lock().unwrap() = original;
	let first = funding(&node.wallet, 2);
	let second = funding(&node.wallet, 3);
	assert_distinct_inputs(&first, &second);
}

fn send(wallet: &Wallet) -> Txid {
	let address = wallet.get_new_address().unwrap();
	wallet
		.send_to_address(
			&address,
			OnchainSendAmount::ExactRetainingReserve {
				amount_sats: 80_000,
				cur_anchor_reserve_sats: 0,
			},
			Some(FeeRate::from_sat_per_vb(2).unwrap()),
		)
		.unwrap()
}

// Age the durable record, not the wall clock. Restart must use stored times.
fn age_reservation(node: &crate::Node, txid: Txid, at: u64, last_seen: Option<u64>) {
	use lightning::util::persist::KVStoreSync;
	let store = node.wallet.persister.lock().unwrap().kv_store.clone();
	let mut bytes =
		KVStoreSync::read(&*store, "bitsov_local_spends", "", &txid.to_string()).unwrap();
	bytes[3..11].copy_from_slice(&at.to_le_bytes());
	bytes[11..19].copy_from_slice(&last_seen.unwrap_or(0).to_le_bytes());
	KVStoreSync::write(&*store, "bitsov_local_spends", "", &txid.to_string(), bytes).unwrap();
	*node.wallet.local_spends.lock().unwrap() = local_spends::LocalSpends::load(store).unwrap();
}

#[test]
fn stranded_send_released_after_window_and_restart_reconciliation() {
	for restart in [false, true] {
		let dir = tempfile::tempdir().unwrap();
		let mut node = node(dir.path());
		fund(&node.wallet);
		let txid = send(&node.wallet);
		let _other = funding(&node.wallet, 3);
		let now = local_spends::now();
		age_reservation(&node, txid, now - 86_401, None);
		if restart {
			drop(node);
			node = self::node(dir.path());
		}
		// A mere restart/old age is insufficient: an actual successful absence
		// lookup is required, so source outages cannot unlock uncertain spends.
		assert!(small_funding(&node.wallet).is_err());
		node.reconcile_local_spend(txid, false).unwrap();
		assert!(node.local_spend_reservations().iter().all(|r| r.txid != txid));
		let next = funding(&node.wallet, 4);
		assert!(next.input.iter().all(|i| i.previous_output.txid != txid));
		drop(node);
		assert!(self::node(dir.path()).local_spend_reservations().iter().all(|r| r.txid != txid));
	}
}

#[test]
fn recent_sighting_extends_window_and_absence_before_window_retains_inputs() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let txid = send(&node.wallet);
	let now = local_spends::now();
	age_reservation(&node, txid, now - 172_800, Some(now - 60));
	node.reconcile_local_spend(txid, false).unwrap();
	assert!(node.local_spend_reservations().iter().any(|r| r.txid == txid));
	node.reconcile_local_spend(txid, true).unwrap();
	assert!(
		node.local_spend_reservations()
			.iter()
			.find(|r| r.txid == txid)
			.unwrap()
			.last_seen_at
			.unwrap() >= now
	);
}

#[test]
fn owner_release_recycles_only_requested_reservation_and_survives_restart() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let first = funding(&node.wallet, 2);
	let second = funding(&node.wallet, 3);
	node.release_local_spend(first.compute_txid()).unwrap();
	node.release_local_spend(first.compute_txid()).unwrap();
	drop(node);
	let node = self::node(dir.path());
	assert_eq!(node.local_spend_reservations().len(), 1);
	assert_eq!(node.local_spend_reservations()[0].txid, second.compute_txid());
	assert_eq!(funding(&node.wallet, 4).input[0].previous_output, first.input[0].previous_output);
}

#[test]
fn legacy_reservation_age_is_migrated_once_and_finality_removes_record() {
	use lightning::util::persist::KVStoreSync;
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let tx = funding(&node.wallet, 2);
	let store = node.wallet.persister.lock().unwrap().kv_store.clone();
	let mut legacy = vec![0, 0];
	legacy.extend(bitcoin::consensus::serialize(&tx));
	KVStoreSync::write(&*store, "bitsov_local_spends", "", &tx.compute_txid().to_string(), legacy)
		.unwrap();
	drop(node);
	let node = self::node(dir.path());
	let created = node.local_spend_reservations()[0].created_at;
	assert!(created > 0);
	drop(node);
	let node = self::node(dir.path());
	assert_eq!(node.local_spend_reservations()[0].created_at, created);
	let mut block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
	block.header.prev_blockhash = node.wallet.current_best_block().block_hash;
	block.txdata = vec![tx];
	node.wallet.block_connected(&block, 2);
	assert_eq!(node.local_spend_reservations().len(), 1);
	advance_confirmations(&node.wallet, true, ANTI_REORG_DELAY + 1);
	assert!(node.local_spend_reservations().is_empty());
}

#[test]
fn owner_release_keeps_retry_record_if_bdk_eviction_persist_fails() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let first = funding(&node.wallet, 2);
	funding(&node.wallet, 3);
	let store = node.wallet.persister.lock().unwrap().kv_store.clone();
	*node.wallet.persister.lock().unwrap() =
		KVStoreWalletPersister::new(store, node.logger.clone());
	assert!(node.release_local_spend(first.compute_txid()).is_err());
	drop(node);
	let node = self::node(dir.path());
	assert!(node.local_spend_reservations().iter().any(|r| r.txid == first.compute_txid()));
	assert!(small_funding(&node.wallet).is_err());
	node.release_local_spend(first.compute_txid()).unwrap();
	assert_eq!(funding(&node.wallet, 4).input[0].previous_output, first.input[0].previous_output);
}

#[tokio::test(start_paused = true)]
async fn signed_pending_funding_keeps_rebroadcasting_with_bounded_backoff() {
	use lightning::chain::chaininterface::BroadcasterInterface;
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let tx = funding(&node.wallet, 2);
	assert!(tx.input.iter().all(|input| !input.witness.is_empty()));
	let mut queue = node.tx_broadcaster.get_broadcast_queue().await;
	node.tx_broadcaster.broadcast_transactions(&[&tx]);
	assert_eq!(queue.try_recv().unwrap(), vec![tx.clone()]);
	node.tx_broadcaster.broadcast_completed(&[tx.compute_txid()]);
	for delay in [30, 60, 120, 240, 300, 300] {
		tokio::time::advance(std::time::Duration::from_secs(delay - 1)).await;
		node.tx_broadcaster.broadcast_transactions(&[&tx]);
		assert!(queue.try_recv().is_err());
		tokio::time::advance(std::time::Duration::from_secs(1)).await;
		node.tx_broadcaster.broadcast_transactions(&[&tx]);
		assert_eq!(queue.try_recv().unwrap(), vec![tx.clone()]);
		node.tx_broadcaster.broadcast_completed(&[tx.compute_txid()]);
	}
	// Scheduling never releases wallet ownership or treats a refusal as settlement.
	assert!(node
		.local_spend_reservations()
		.iter()
		.any(|reservation| reservation.txid == tx.compute_txid()));
}

#[test]
fn funding_policy_survives_restart_and_cache_increase_with_hard_cap() {
	use crate::funding::{FundingPolicy, FundingPriority};
	let dir = tempfile::tempdir().unwrap();
	let id = crate::funding::new_policy_channel_id();
	{
		let node = node(dir.path());
		fund(&node.wallet);
		let policy =
			FundingPolicy::new(FundingPriority::Fast, FeeRate::from_sat_per_kwu(1250), Some(1))
				.unwrap();
		crate::funding::save(node.kv_store.as_ref(), id, &policy).unwrap();
	}
	let node = node(dir.path());
	node.fee_estimator.set_test_fee_rate_cache(std::collections::HashMap::from([(
		ConfirmationTarget::OnchainPayment,
		FeeRate::from_sat_per_kwu(25000),
	)]));
	let script = node.wallet.get_new_address().unwrap().script_pubkey();
	let err = node
		.wallet
		.create_channel_funding_transaction(
			script.clone(),
			Amount::from_sat(80_000),
			id,
			LockTime::ZERO,
		)
		.unwrap_err();
	assert_eq!(err, Error::FundingFeeCapExceeded);
	assert!(node.wallet.local_spends.lock().unwrap().reservations().is_empty());
	let mut policy = crate::funding::load(node.kv_store.as_ref(), id).unwrap().unwrap();
	assert_eq!(policy.fee_rate.to_sat_per_kwu(), 1250);
	policy.max_fee_sats = Some(2000);
	crate::funding::save(node.kv_store.as_ref(), id, &policy).unwrap();
	let tx = node
		.wallet
		.create_channel_funding_transaction(script, Amount::from_sat(80_000), id, LockTime::ZERO)
		.unwrap();
	let wallet = node.wallet.inner.lock().unwrap();
	let fee = wallet.calculate_fee(&tx).unwrap().to_sat();
	assert!(fee <= 2000);
	assert!(fee * 4 >= tx.weight().to_wu() * 5, "fee={fee}, weight={}", tx.weight());
	assert!(fee < tx.vsize() as u64 * 6);
}

#[test]
fn missing_or_corrupt_funding_policy_never_falls_back() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let id = crate::funding::new_policy_channel_id();
	let script = node.wallet.get_new_address().unwrap().script_pubkey();
	assert!(node
		.wallet
		.create_channel_funding_transaction(
			script.clone(),
			Amount::from_sat(80_000),
			id,
			LockTime::ZERO
		)
		.is_err());
	lightning::util::persist::KVStoreSync::write(
		node.kv_store.as_ref(),
		"bitsov_funding",
		"",
		&id.to_string(),
		vec![1, 2],
	)
	.unwrap();
	assert!(node
		.wallet
		.create_channel_funding_transaction(script, Amount::from_sat(80_000), id, LockTime::ZERO)
		.is_err());
}

#[test]
fn funding_absolute_cap_accepts_exact_fee_and_refuses_one_sat_less() {
	use crate::funding::{FundingPolicy, FundingPriority};
	let build = |cap| {
		let dir = tempfile::tempdir().unwrap();
		let node = node(dir.path());
		fund(&node.wallet);
		let id = crate::funding::new_policy_channel_id();
		let policy =
			FundingPolicy::new(FundingPriority::Normal, FeeRate::from_sat_per_kwu(1250), cap)
				.unwrap();
		crate::funding::save(node.kv_store.as_ref(), id, &policy).unwrap();
		let script = node.wallet.get_new_address().unwrap().script_pubkey();
		let result = node.wallet.create_channel_funding_transaction(
			script,
			Amount::from_sat(80_000),
			id,
			LockTime::ZERO,
		);
		match result {
			Ok(tx) => Ok(node.wallet.inner.lock().unwrap().calculate_fee(&tx).unwrap().to_sat()),
			Err(error) => {
				assert!(node.wallet.local_spends.lock().unwrap().reservations().is_empty());
				Err(error)
			}
		}
	};
	let fee = build(None).unwrap();
	assert_eq!(build(Some(fee)), Ok(fee));
	assert_eq!(build(Some(fee - 1)), Err(Error::FundingFeeCapExceeded));
}

#[test]
fn funding_quotes_and_channel_policies_are_independent() {
	use crate::funding::FundingPriority;
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	node.fee_estimator.set_test_fee_rate_cache(std::collections::HashMap::from([
		(ConfirmationTarget::ChannelFunding, FeeRate::from_sat_per_kwu(1254)),
		(ConfirmationTarget::OnchainPayment, FeeRate::from_sat_per_kwu(3000)),
	]));
	let normal = node.funding_fee_quote(FundingPriority::Normal, Some(2000)).unwrap();
	let fast = node.funding_fee_quote(FundingPriority::Fast, Some(4000)).unwrap();
	assert_eq!(normal.estimated_fee_rate_sat_per_kwu(), 1254);
	assert_eq!(fast.estimated_fee_rate_sat_per_kwu(), 3000);
	let normal_id = crate::funding::new_policy_channel_id();
	let fast_id = crate::funding::new_policy_channel_id();
	crate::funding::save(node.kv_store.as_ref(), normal_id, &normal).unwrap();
	crate::funding::save(node.kv_store.as_ref(), fast_id, &fast).unwrap();
	let normal_script = node.wallet.get_new_address().unwrap().script_pubkey();
	let fast_script = node.wallet.get_new_address().unwrap().script_pubkey();
	let a = node
		.wallet
		.create_channel_funding_transaction(
			normal_script,
			Amount::from_sat(80_000),
			normal_id,
			LockTime::ZERO,
		)
		.unwrap();
	let b = node
		.wallet
		.create_channel_funding_transaction(
			fast_script,
			Amount::from_sat(80_000),
			fast_id,
			LockTime::ZERO,
		)
		.unwrap();
	assert_distinct_inputs(&a, &b);
	let wallet = node.wallet.inner.lock().unwrap();
	let a_fee = wallet.calculate_fee(&a).unwrap().to_sat();
	let b_fee = wallet.calculate_fee(&b).unwrap().to_sat();
	assert!(a_fee <= 2000 && b_fee <= 4000);
	assert!(a_fee < b_fee);
}

#[test]
fn funding_failure_reason_survives_restart() {
	let dir = tempfile::tempdir().unwrap();
	let id = crate::funding::new_policy_channel_id();
	{
		let node = node(dir.path());
		assert!(node.channel_funding_failure(crate::UserChannelId(id)).unwrap().is_none());
		node.wallet.record_funding_failure(id, Error::FundingFeeCapExceeded).unwrap();
	}
	let node = node(dir.path());
	let reason = node.channel_funding_failure(crate::UserChannelId(id)).unwrap().unwrap();
	assert!(reason.contains("max_funding_fee_sats"));
}

#[test]
fn funding_failure_is_terminal_across_restart_even_if_wallet_recovers() {
	use crate::funding::{FundingPolicy, FundingPriority};
	let dir = tempfile::tempdir().unwrap();
	let id = crate::funding::new_policy_channel_id();
	{
		let node = node(dir.path());
		let policy =
			FundingPolicy::new(FundingPriority::Normal, FeeRate::from_sat_per_kwu(1250), None)
				.unwrap();
		crate::funding::save(node.kv_store.as_ref(), id, &policy).unwrap();
		// Model a construction failure already reported to the owner. Test the
		// terminal wallet policy, not LDK event persistence (FundingGenerationReady
		// itself is not persisted by this pinned LDK version).
		node.wallet.record_funding_failure(id, Error::InsufficientFunds).unwrap();
	}
	let node = node(dir.path());
	fund(&node.wallet); // wallet can now fund, but the refused opening must not
	let script = node.wallet.get_new_address().unwrap().script_pubkey();
	let result = node.wallet.create_channel_funding_transaction(
		script,
		Amount::from_sat(80_000),
		id,
		LockTime::ZERO,
	);
	assert!(result.is_err(), "a refused opening was funded on a repeated construction attempt");
	assert!(node.wallet.local_spends.lock().unwrap().reservations().is_empty());
	node.wallet.record_funding_failure(id, Error::WalletOperationFailed).unwrap();
	let reason = node.channel_funding_failure(crate::UserChannelId(id)).unwrap().unwrap();
	assert_eq!(reason, Error::InsufficientFunds.to_string(), "retain the first refusal reason");
}

/// Exercise the real Esplora empty-response conversion and legacy BDK funding
/// construction without starting a node, binding sockets, or using real funds.
#[tokio::test]
async fn default_funding_with_empty_non_mainnet_esplora_estimates() {
	#[derive(Debug)]
	struct EmptyEstimates;
	impl esplora_client::r#async::HttpTransport for EmptyEstimates {
		fn execute(
			&self,
			request: reqwest::RequestBuilder,
		) -> std::pin::Pin<
			Box<
				dyn std::future::Future<Output = Result<reqwest::Response, esplora_client::Error>>
					+ Send
					+ '_,
			>,
		> {
			assert_eq!(request.build().unwrap().url().path(), "/fee-estimates");
			Box::pin(async { Ok(http::Response::builder().status(200).body("{}").unwrap().into()) })
		}
	}
	for network in [bitcoin::Network::Regtest, bitcoin::Network::Signet] {
		let dir = tempfile::tempdir().unwrap();
		let mut builder = crate::Builder::new();
		builder.set_network(network);
		builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
		builder.set_chain_source_esplora_with_transport(
			"http://unused.invalid".into(),
			None,
			Arc::new(EmptyEstimates),
		);
		let node = builder.build_with_fs_store().unwrap();
		node.chain_source.update_fee_rate_estimates().await.unwrap();
		assert!(node.funding_fee_quote(crate::funding::FundingPriority::Normal, None).is_err());
		fund(&node.wallet);
		let script = node.wallet.get_new_address().unwrap().script_pubkey();
		let tx = node
			.wallet
			.create_channel_funding_transaction(
				script,
				Amount::from_sat(80_000),
				42,
				LockTime::ZERO,
			)
			.unwrap();
		assert!(tx.input.iter().all(|input| !input.witness.is_empty()));
		assert!(node.local_spend_reservations().iter().any(|r| r.txid == tx.compute_txid()));
	}
}

fn move_home_destination() -> Address {
	let key = bitcoin::secp256k1::PublicKey::from_secret_key(
		&Secp256k1::new(),
		&SecretKey::from_slice(&[91; 32]).unwrap(),
	);
	Address::p2wpkh(&bitcoin::CompressedPublicKey(key), bitcoin::Network::Regtest)
}

#[test]
fn move_home_preview_is_deterministic_and_does_not_reserve_coins() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let destination = move_home_destination();
	let rate = FeeRate::from_sat_per_vb(2).unwrap();
	let (tx, fee) = node.wallet.prepare_move_home(&destination, rate).unwrap();
	let second = node.wallet.prepare_move_home(&destination, rate).unwrap();
	assert_eq!((tx.clone(), fee), second);
	assert_eq!(tx.input.len(), 2);
	assert_eq!(tx.output.len(), 1);
	assert_eq!(tx.output[0].script_pubkey, destination.script_pubkey());
	assert_eq!(tx.output[0].value.to_sat() + fee, 300_000);
	assert!(fee >= (rate * tx.weight()).to_sat());
	assert!(node.local_spend_reservations().is_empty());
	assert_eq!(node.list_balances().total_onchain_balance_sats, 300_000);
}

#[test]
fn move_home_replay_survives_wallet_restart_and_owns_same_inputs() {
	let dir = tempfile::tempdir().unwrap();
	let destination = move_home_destination();
	let (tx, fee) = {
		let node = node(dir.path());
		fund(&node.wallet);
		let (tx, fee) = node
			.wallet
			.prepare_move_home(&destination, FeeRate::from_sat_per_vb(2).unwrap())
			.unwrap();
		node.wallet.replay_move_home(&tx, &destination, fee).unwrap();
		(tx, fee)
	};
	let node = node(dir.path());
	node.wallet.replay_move_home(&tx, &destination, fee).unwrap();
	assert_eq!(node.local_spend_reservations().len(), 1);
	assert_eq!(node.local_spend_reservations()[0].txid, tx.compute_txid());
	assert!(small_funding(&node.wallet).is_err());
	assert_eq!(node.wallet.move_home_confirmations(tx.compute_txid()), 0);
}

#[test]
fn move_home_refuses_wrong_fee_address_and_self_destination() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let destination = move_home_destination();
	let rate = FeeRate::from_sat_per_vb(2).unwrap();
	let own = node.wallet.get_new_address().unwrap();
	assert!(node.wallet.prepare_move_home(&own, rate).is_err());
	let (tx, fee) = node.wallet.prepare_move_home(&destination, rate).unwrap();
	assert!(node.wallet.replay_move_home(&tx, &destination, fee + 1).is_err());
	assert!(node.wallet.replay_move_home(&tx, &own, fee).is_err());
	assert!(node.local_spend_reservations().is_empty());
}

#[test]
fn move_home_refuses_preexisting_spend_reservations() {
	let dir = tempfile::tempdir().unwrap();
	let node = node(dir.path());
	fund(&node.wallet);
	let _pending = funding(&node.wallet, 2);
	assert!(node
		.wallet
		.prepare_move_home(&move_home_destination(), FeeRate::from_sat_per_vb(2).unwrap())
		.is_err());
}
