//! Feed LDK's existing selector a claim-specific view of durable reservations.
use std::sync::Arc;

use bitcoin::{psbt::Psbt, OutPoint, ScriptBuf, Transaction, TxOut};
use lightning::chain::ClaimId;
use lightning::events::bump_transaction::{
	CoinSelection, CoinSelectionSource, Input, Utxo, Wallet as LdkWallet, WalletSource,
};
use lightning::util::async_poll::AsyncResult;

use super::Wallet;
use crate::logger::Logger;

pub(crate) struct BumpWallet {
	wallet: Arc<Wallet>,
	logger: Arc<Logger>,
}

impl BumpWallet {
	pub(crate) fn new(wallet: Arc<Wallet>, logger: Arc<Logger>) -> Self {
		Self { wallet, logger }
	}
}

struct ClaimSource<'a> {
	wallet: &'a Wallet,
	claim: Option<OutPoint>,
	allow_other_bumps: bool,
}

impl WalletSource for ClaimSource<'_> {
	fn list_confirmed_utxos<'a>(&'a self) -> AsyncResult<'a, Vec<Utxo>, ()> {
		Box::pin(async move {
			self.wallet.list_confirmed_utxos_for_claim(self.claim, self.allow_other_bumps)
		})
	}
	fn get_change_script<'a>(&'a self) -> AsyncResult<'a, ScriptBuf, ()> {
		self.wallet.get_change_script()
	}
	fn sign_psbt<'a>(&'a self, psbt: Psbt) -> AsyncResult<'a, Transaction, ()> {
		self.wallet.sign_psbt(psbt)
	}
}

impl CoinSelectionSource for BumpWallet {
	fn select_confirmed_utxos<'a>(
		&'a self,
		claim_id: ClaimId,
		must_spend: Vec<Input>,
		must_pay_to: &'a [TxOut],
		target_feerate_sat_per_1000_weight: u32,
		max_tx_weight: u64,
	) -> AsyncResult<'a, CoinSelection, ()> {
		Box::pin(async move {
			let source = ClaimSource {
				wallet: &self.wallet,
				claim: must_spend.first().map(|i| i.outpoint),
				allow_other_bumps: false,
			};
			// The shared node gate covers selection through signing. Persisted
			// ownership, not LDK's ephemeral locked_utxos map, supplies exclusions
			// after restart. Keep LDK's fee/weight/selection algorithm unchanged.
			let preferred = LdkWallet::new(&source, self.logger.as_ref())
				.select_confirmed_utxos(
					claim_id,
					must_spend.clone(),
					must_pay_to,
					target_feerate_sat_per_1000_weight,
					max_tx_weight,
				)
				.await;
			if preferred.is_ok() {
				return preferred;
			}
			// CoinSelectionSource requires deliberate bump-vs-bump conflicts as
			// a last resort when every fee UTXO belongs to another claim. Never
			// admit ordinary send/funding reservations into that fallback.
			let fallback = ClaimSource { allow_other_bumps: true, ..source };
			LdkWallet::new(&fallback, self.logger.as_ref())
				.select_confirmed_utxos(
					claim_id,
					must_spend,
					must_pay_to,
					target_feerate_sat_per_1000_weight,
					max_tx_weight,
				)
				.await
		})
	}
	fn sign_psbt<'a>(&'a self, psbt: Psbt) -> AsyncResult<'a, Transaction, ()> {
		self.wallet.sign_psbt(psbt)
	}
}
