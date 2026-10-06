// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use bitcoin::FeeRate;
use lightning::chain::chaininterface::{
	ConfirmationTarget as LdkConfirmationTarget, FeeEstimator as LdkFeeEstimator,
	FEERATE_FLOOR_SATS_PER_KW,
};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum ConfirmationTarget {
	/// The default target for onchain payments.
	OnchainPayment,
	/// The target used for funding transactions.
	ChannelFunding,
	/// Targets used by LDK.
	Lightning(LdkConfirmationTarget),
}

pub(crate) trait FeeEstimator {
	fn estimate_fee_rate(&self, confirmation_target: ConfirmationTarget) -> FeeRate;
}

impl From<LdkConfirmationTarget> for ConfirmationTarget {
	fn from(value: LdkConfirmationTarget) -> Self {
		Self::Lightning(value)
	}
}

pub(crate) struct OnchainFeeEstimator {
	funding_max_age_secs: u64,
	fee_rate_cache: RwLock<HashMap<ConfirmationTarget, FeeRate>>,
	updated_at: RwLock<Option<std::time::Instant>>,
	funding_targets: RwLock<HashSet<ConfirmationTarget>>,
}

impl OnchainFeeEstimator {
	// W1 needs the one-block estimate without LDK's fee-inflation protection margin.
	pub(crate) fn tower_justice_rate(&self) -> u32 {
		let cache = self.fee_rate_cache.read().unwrap();
		let target = LdkConfirmationTarget::MaximumFeeEstimate;
		let Some(adjusted) = cache.get(&target.into()) else {
			return get_fallback_rate_for_ldk_target(target);
		};
		// All chain sources cache apply_post_estimation_adjustments below. Invert its
		// floor(raw * 11 / 10) + 2500 exactly for integer sat/kWU, without fetching
		// another estimate or changing the fee cache / disabled-node behavior.
		let raw = (u128::from(adjusted.to_sat_per_kwu().saturating_sub(2500)) * 10).div_ceil(11);
		raw.clamp(FEERATE_FLOOR_SATS_PER_KW as u128, u32::MAX as u128) as u32
	}

	pub(crate) fn new(fee_refresh_interval_secs: u64) -> Self {
		let fee_rate_cache = RwLock::new(HashMap::new());
		Self {
			funding_max_age_secs: fee_refresh_interval_secs.saturating_mul(2).max(900),
			fee_rate_cache,
			updated_at: RwLock::new(None),
			funding_targets: RwLock::new(HashSet::new()),
		}
	}

	pub(crate) fn funding_rate(&self, target: ConfirmationTarget) -> Result<FeeRate, crate::Error> {
		let cache = self.fee_rate_cache.read().unwrap();
		if self
			.updated_at
			.read()
			.unwrap()
			.is_none_or(|time| time.elapsed().as_secs() > self.funding_max_age_secs)
		{
			return Err(crate::Error::FeerateEstimationUpdateFailed);
		}
		if !self.funding_targets.read().unwrap().contains(&target) {
			return Err(crate::Error::FeerateEstimationUpdateFailed);
		}
		let rate = cache
			.get(&target)
			.ok_or(crate::Error::FeerateEstimationUpdateFailed)?;
		Ok(FeeRate::from_sat_per_kwu(
			rate.to_sat_per_kwu().max(FEERATE_FLOOR_SATS_PER_KW as u64),
		))
	}

	#[cfg(test)]
	pub(crate) fn set_test_fee_rate_cache(
		&self,
		rates: HashMap<ConfirmationTarget, FeeRate>,
	) -> bool {
		let targets = rates.keys().copied().collect();
		self.set_fee_rate_cache(rates, targets)
	}

	// Updates the fee rate cache and returns if the new values changed.
	pub(crate) fn set_fee_rate_cache(
		&self,
		fee_rate_cache_update: HashMap<ConfirmationTarget, FeeRate>,
		funding_targets: HashSet<ConfirmationTarget>,
	) -> bool {
		let mut locked_fee_rate_cache = self.fee_rate_cache.write().unwrap();
		*self.updated_at.write().unwrap() = Some(std::time::Instant::now());
		*self.funding_targets.write().unwrap() = funding_targets;
		if fee_rate_cache_update != *locked_fee_rate_cache {
			*locked_fee_rate_cache = fee_rate_cache_update;
			true
		} else {
			false
		}
	}
}

impl FeeEstimator for OnchainFeeEstimator {
	fn estimate_fee_rate(&self, confirmation_target: ConfirmationTarget) -> FeeRate {
		let locked_fee_rate_cache = self.fee_rate_cache.read().unwrap();

		let fallback_sats_kwu = get_fallback_rate_for_target(confirmation_target);

		// We'll fall back on this, if we really don't have any other information.
		let fallback_rate = FeeRate::from_sat_per_kwu(fallback_sats_kwu as u64);

		let estimate = *locked_fee_rate_cache
			.get(&confirmation_target)
			.unwrap_or(&fallback_rate);

		// Currently we assume every transaction needs to at least be relayable, which is why we
		// enforce a lower bound of `FEERATE_FLOOR_SATS_PER_KW`.
		FeeRate::from_sat_per_kwu(
			estimate
				.to_sat_per_kwu()
				.max(FEERATE_FLOOR_SATS_PER_KW as u64),
		)
	}
}

impl LdkFeeEstimator for OnchainFeeEstimator {
	fn get_est_sat_per_1000_weight(&self, confirmation_target: LdkConfirmationTarget) -> u32 {
		self.estimate_fee_rate(confirmation_target.into())
			.to_sat_per_kwu()
			.try_into()
			.unwrap_or_else(|_| get_fallback_rate_for_ldk_target(confirmation_target))
	}
}

pub(crate) fn get_num_block_defaults_for_target(target: ConfirmationTarget) -> usize {
	match target {
		ConfirmationTarget::OnchainPayment => 6,
		ConfirmationTarget::ChannelFunding => 12,
		ConfirmationTarget::Lightning(ldk_target) => match ldk_target {
			LdkConfirmationTarget::MaximumFeeEstimate => 1,
			LdkConfirmationTarget::UrgentOnChainSweep => 6,
			LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee => 1008,
			LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => 144,
			LdkConfirmationTarget::AnchorChannelFee => 1008,
			LdkConfirmationTarget::NonAnchorChannelFee => 12,
			LdkConfirmationTarget::ChannelCloseMinimum => 144,
			LdkConfirmationTarget::OutputSpendingFee => 12,
		},
	}
}

pub(crate) fn get_fallback_rate_for_target(target: ConfirmationTarget) -> u32 {
	match target {
		ConfirmationTarget::OnchainPayment => 5000,
		ConfirmationTarget::ChannelFunding => 1000,
		ConfirmationTarget::Lightning(ldk_target) => get_fallback_rate_for_ldk_target(ldk_target),
	}
}

pub(crate) fn get_fallback_rate_for_ldk_target(target: LdkConfirmationTarget) -> u32 {
	match target {
		LdkConfirmationTarget::MaximumFeeEstimate => 8000,
		LdkConfirmationTarget::UrgentOnChainSweep => 5000,
		LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee => FEERATE_FLOOR_SATS_PER_KW,
		LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => FEERATE_FLOOR_SATS_PER_KW,
		LdkConfirmationTarget::AnchorChannelFee => 500,
		LdkConfirmationTarget::NonAnchorChannelFee => 1000,
		LdkConfirmationTarget::ChannelCloseMinimum => 500,
		LdkConfirmationTarget::OutputSpendingFee => 1000,
	}
}

pub(crate) fn get_all_conf_targets() -> [ConfirmationTarget; 10] {
	[
		ConfirmationTarget::OnchainPayment,
		ConfirmationTarget::ChannelFunding,
		LdkConfirmationTarget::MaximumFeeEstimate.into(),
		LdkConfirmationTarget::UrgentOnChainSweep.into(),
		LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee.into(),
		LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee.into(),
		LdkConfirmationTarget::AnchorChannelFee.into(),
		LdkConfirmationTarget::NonAnchorChannelFee.into(),
		LdkConfirmationTarget::ChannelCloseMinimum.into(),
		LdkConfirmationTarget::OutputSpendingFee.into(),
	]
}

pub(crate) fn apply_post_estimation_adjustments(
	target: ConfirmationTarget,
	estimated_rate: FeeRate,
) -> FeeRate {
	match target {
		ConfirmationTarget::Lightning(
			LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
		) => {
			let slightly_less_than_background = estimated_rate
				.to_sat_per_kwu()
				.saturating_sub(250)
				.max(FEERATE_FLOOR_SATS_PER_KW as u64);
			FeeRate::from_sat_per_kwu(slightly_less_than_background)
		}
		ConfirmationTarget::Lightning(LdkConfirmationTarget::MaximumFeeEstimate) => {
			// MaximumFeeEstimate is mostly used for protection against fee-inflation attacks. As
			// users were previously impacted by this limit being too restrictive (read: too low),
			// we bump it here a bit to give them some leeway.
			let slightly_bump = estimated_rate
				.to_sat_per_kwu()
				.saturating_mul(11)
				.saturating_div(10)
				.saturating_add(2500);
			FeeRate::from_sat_per_kwu(slightly_bump)
		}
		_ => estimated_rate,
	}
}

// Chain-source fallbacks remain usable by LDK, but cannot be advertised as a
// confirmation-target estimate. Reject missing, nonfinite and nonpositive data.
pub(crate) fn usable_funding_estimate(rate: Option<f64>) -> bool {
	rate.is_some_and(|value| value.is_finite() && value > 0.0)
}

#[cfg(test)]
mod funding_tests {
	use super::*;
	use crate::funding::FundingPriority;
	#[test]
	fn funding_quote_expiry_tracks_configured_refresh_interval() {
		use crate::config::{BackgroundSyncConfig, EsploraSyncConfig};
		for (interval, max_age) in [(30, 900), (600, 1200), (1800, 3600), (3600, 7200)] {
			let dir = tempfile::tempdir().unwrap();
			let mut builder = crate::Builder::new();
			builder.set_network(bitcoin::Network::Regtest);
			builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
			builder.set_chain_source_esplora(
				"http://unused.invalid".into(),
				Some(EsploraSyncConfig {
					background_sync_config: Some(BackgroundSyncConfig {
						fee_rate_cache_update_interval_secs: interval,
						..Default::default()
					}),
				}),
			);
			let node = builder.build().unwrap();
			node.fee_estimator.set_test_fee_rate_cache(HashMap::from([(
				ConfirmationTarget::ChannelFunding,
				FeeRate::from_sat_per_kwu(1234),
			)]));
			for (age, allowed) in [(max_age, true), (max_age + 1, false)] {
				*node.fee_estimator.updated_at.write().unwrap() =
					Some(std::time::Instant::now() - std::time::Duration::from_secs(age));
				assert_eq!(
					node.funding_fee_quote(FundingPriority::Normal, None)
						.is_ok(),
					allowed,
					"refresh interval {interval}, estimate age {age}"
				);
			}
		}
	}

	#[test]
	fn funding_quotes_refuse_missing_and_stale_estimates() {
		let estimator = OnchainFeeEstimator::new(crate::config::BackgroundSyncConfig::default().fee_rate_cache_update_interval_secs);
		assert!(estimator
			.funding_rate(ConfirmationTarget::ChannelFunding)
			.is_err());
		estimator.set_test_fee_rate_cache(HashMap::from([(
			ConfirmationTarget::ChannelFunding,
			FeeRate::from_sat_per_kwu(1234),
		)]));
		assert_eq!(
			estimator
				.funding_rate(ConfirmationTarget::ChannelFunding)
				.unwrap()
				.to_sat_per_kwu(),
			1234
		);
		assert!(estimator
			.funding_rate(ConfirmationTarget::OnchainPayment)
			.is_err());
		// Default refresh waits 600s then makes a bounded request. It must not
		// create a periodic refusal window while that healthy request completes.
		*estimator.updated_at.write().unwrap() =
			Some(std::time::Instant::now() - std::time::Duration::from_secs(605));
		assert!(estimator
			.funding_rate(ConfirmationTarget::ChannelFunding)
			.is_ok());
		*estimator.updated_at.write().unwrap() =
			Some(std::time::Instant::now() - std::time::Duration::from_secs(1201));
		assert!(estimator
			.funding_rate(ConfirmationTarget::ChannelFunding)
			.is_err());
	}
	#[test]
	fn unavailable_source_estimates_never_qualify_for_funding_quotes() {
		for raw in [
			serde_json::json!(-1),
			serde_json::Value::Null,
			serde_json::json!(0),
			serde_json::json!("bad"),
		] {
			assert!(!usable_funding_estimate(raw.as_f64()));
		}
		assert!(!usable_funding_estimate(None)); // Esplora target conversion missing
		assert!(!usable_funding_estimate(Some(f64::INFINITY)));
		assert!(usable_funding_estimate(Some(0.00001)));
		let estimator = OnchainFeeEstimator::new(crate::config::BackgroundSyncConfig::default().fee_rate_cache_update_interval_secs);
		estimator.set_fee_rate_cache(
			HashMap::from([(
				ConfirmationTarget::ChannelFunding,
				FeeRate::from_sat_per_kwu(250),
			)]),
			HashSet::new(),
		);
		assert!(estimator
			.funding_rate(ConfirmationTarget::ChannelFunding)
			.is_err());
		assert_eq!(
			estimator
				.estimate_fee_rate(ConfirmationTarget::ChannelFunding)
				.to_sat_per_kwu(),
			253
		);
	}
	#[test]
	fn funding_priorities_select_distinct_estimates() {
		let estimator = OnchainFeeEstimator::new(crate::config::BackgroundSyncConfig::default().fee_rate_cache_update_interval_secs);
		estimator.set_test_fee_rate_cache(HashMap::from([
			(
				ConfirmationTarget::Lightning(LdkConfirmationTarget::ChannelCloseMinimum),
				FeeRate::from_sat_per_kwu(500),
			),
			(
				ConfirmationTarget::ChannelFunding,
				FeeRate::from_sat_per_kwu(1500),
			),
			(
				ConfirmationTarget::OnchainPayment,
				FeeRate::from_sat_per_kwu(3000),
			),
		]));
		for (priority, rate) in [
			(FundingPriority::Economy, 500),
			(FundingPriority::Normal, 1500),
			(FundingPriority::Fast, 3000),
		] {
			assert_eq!(
				estimator
					.funding_rate(priority.target())
					.unwrap()
					.to_sat_per_kwu(),
				rate
			);
		}
	}
}
