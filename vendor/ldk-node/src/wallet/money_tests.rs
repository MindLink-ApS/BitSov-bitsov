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
fn confirmed_bump_replacement_releases_unused_fee_input() {
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
