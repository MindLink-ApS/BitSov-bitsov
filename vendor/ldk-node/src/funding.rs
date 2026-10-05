//! BitSov funding policy: estimator choices, never caller-supplied fee rates.
use crate::fee_estimator::ConfirmationTarget;
use crate::types::DynStore;
use crate::Error;
use bitcoin::FeeRate;
use lightning::chain::chaininterface::ConfirmationTarget as LdkTarget;

/// Funding confirmation preference. Times are targets, not guarantees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundingPriority {
	/// Use the existing 144-block ChannelCloseMinimum estimate.
	Economy,
	/// Use the existing 12-block ChannelFunding estimate.
	Normal,
	/// Use the existing 6-block OnchainPayment estimate.
	Fast,
}

impl FundingPriority {
	pub(crate) fn target(self) -> ConfirmationTarget {
		match self {
			Self::Economy => ConfirmationTarget::Lightning(LdkTarget::ChannelCloseMinimum),
			Self::Normal => ConfirmationTarget::ChannelFunding,
			Self::Fast => ConfirmationTarget::OnchainPayment,
		}
	}
	/// Estimator target in blocks; not a confirmation deadline.
	pub fn confirmation_target_blocks(self) -> u32 {
		crate::fee_estimator::get_num_block_defaults_for_target(self.target()) as u32
	}
}

/// An estimator-selected rate and optional absolute fee cap, persisted before negotiation.
/// Private fields deliberately prevent callers from supplying arbitrary funding rates.
#[derive(Clone, Debug)]
pub struct FundingPolicy {
	pub(crate) priority: FundingPriority,
	pub(crate) fee_rate: FeeRate,
	pub(crate) max_fee_sats: Option<u64>,
}
impl FundingPolicy {
	pub(crate) fn new(
		priority: FundingPriority,
		fee_rate: FeeRate,
		max_fee_sats: Option<u64>,
	) -> Result<Self, Error> {
		if fee_rate.to_sat_per_kwu() < 253 || fee_rate.to_sat_per_kwu() > 2_500_000 {
			return Err(Error::InvalidFeeRate);
		}
		if max_fee_sats.is_some_and(|cap| cap == 0 || cap > 2_100_000_000_000_000) {
			return Err(Error::InvalidAmount);
		}
		Ok(Self {
			priority,
			fee_rate,
			max_fee_sats,
		})
	}
	/// Selected confirmation preference.
	pub fn priority(&self) -> FundingPriority {
		self.priority
	}
	/// Estimator-selected rate in satoshis per 1,000 weight units.
	pub fn estimated_fee_rate_sat_per_kwu(&self) -> u64 {
		self.fee_rate.to_sat_per_kwu()
	}
	/// Optional absolute transaction fee ceiling checked before signing.
	pub fn max_fee_sats(&self) -> Option<u64> {
		self.max_fee_sats
	}
}

// Mark policy-bearing IDs so a missing row after restart MUST fail closed. Legacy
// channels retain their existing default funding behavior.
const PREFIX: u128 = 0x42534650_u128 << 96;
// BITSOV-PATCH: LSPS2 IDs carry a distinct, fail-closed funding-policy marker.
const JIT_PREFIX: u128 = 0x42534a49_u128 << 96;
pub(crate) fn new_jit_channel_id() -> u128 {
	JIT_PREFIX | (rand::random::<u128>() & !MASK)
}
pub(crate) fn is_jit_channel_id(id: u128) -> bool {
	id & MASK == JIT_PREFIX
}
fn has_policy(id: u128) -> bool {
	id & MASK == PREFIX || is_jit_channel_id(id)
}
const MASK: u128 = u128::MAX << 96;
pub(crate) fn new_policy_channel_id() -> u128 {
	PREFIX | (rand::random::<u128>() & !MASK)
}
const NAMESPACE: &str = "bitsov_funding";
pub(crate) fn save(store: &DynStore, id: u128, policy: &FundingPolicy) -> Result<(), Error> {
	let priority = match policy.priority {
		FundingPriority::Economy => 0,
		FundingPriority::Normal => 1,
		FundingPriority::Fast => 2,
	};
	let mut bytes = vec![1, priority];
	bytes.extend(policy.fee_rate.to_sat_per_kwu().to_be_bytes());
	bytes.extend(policy.max_fee_sats.unwrap_or(0).to_be_bytes());
	lightning::util::persist::KVStoreSync::write(store, NAMESPACE, "", &id.to_string(), bytes)
		.map_err(|_| Error::PersistenceFailed)
}
pub(crate) fn load(store: &DynStore, id: u128) -> Result<Option<FundingPolicy>, Error> {
	if !has_policy(id) {
		return Ok(None);
	}
	let bytes = lightning::util::persist::KVStoreSync::read(store, NAMESPACE, "", &id.to_string())
		.map_err(|_| Error::PersistenceFailed)?;
	if bytes.len() != 18 || bytes[0] != 1 {
		return Err(Error::PersistenceFailed);
	}
	let priority = match bytes[1] {
		0 => FundingPriority::Economy,
		1 => FundingPriority::Normal,
		2 => FundingPriority::Fast,
		_ => return Err(Error::PersistenceFailed),
	};
	let rate = u64::from_be_bytes(
		bytes[2..10]
			.try_into()
			.map_err(|_| Error::PersistenceFailed)?,
	);
	let cap = u64::from_be_bytes(
		bytes[10..18]
			.try_into()
			.map_err(|_| Error::PersistenceFailed)?,
	);
	FundingPolicy::new(
		priority,
		FeeRate::from_sat_per_kwu(rate),
		(cap != 0).then_some(cap),
	)
	.map(Some)
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn funding_choices_use_unadjusted_ldk_targets() {
		for (priority, blocks) in [
			(FundingPriority::Economy, 144),
			(FundingPriority::Normal, 12),
			(FundingPriority::Fast, 6),
		] {
			assert_eq!(priority.confirmation_target_blocks(), blocks);
			let rate = FeeRate::from_sat_per_kwu(1234);
			assert_eq!(
				crate::fee_estimator::apply_post_estimation_adjustments(priority.target(), rate),
				rate
			);
		}
	}
	#[test]
	fn funding_cap_and_rate_bounds() {
		for cap in [0, 2_100_000_000_000_001, u64::MAX] {
			assert!(FundingPolicy::new(
				FundingPriority::Normal,
				FeeRate::from_sat_per_kwu(500),
				Some(cap)
			)
			.is_err());
		}
		for rate in [0, 252, 2_500_001, u64::MAX] {
			assert!(FundingPolicy::new(
				FundingPriority::Normal,
				FeeRate::from_sat_per_kwu(rate),
				None
			)
			.is_err());
		}
	}
}

// Failures recorded before LDK closes the unfunded channel let the owner see the
// reason even when the asynchronous channel has already disappeared.
pub(crate) fn record_failure(store: &DynStore, id: u128, error: Error) -> Result<(), Error> {
	if !has_policy(id) || failure(store, id)?.is_some() {
		return Ok(());
	}
	lightning::util::persist::KVStoreSync::write(
		store,
		"bitsov_funding_failure",
		"",
		&id.to_string(),
		error.to_string().into_bytes(),
	)
	.map_err(|_| Error::PersistenceFailed)
}
pub(crate) fn failure(store: &DynStore, id: u128) -> Result<Option<String>, Error> {
	if !has_policy(id) {
		return Ok(None);
	}
	match lightning::util::persist::KVStoreSync::read(
		store,
		"bitsov_funding_failure",
		"",
		&id.to_string(),
	) {
		Ok(bytes) => String::from_utf8(bytes)
			.map(Some)
			.map_err(|_| Error::PersistenceFailed),
		Err(error) if error.kind() == lightning::io::ErrorKind::NotFound => Ok(None),
		Err(_) => Err(Error::PersistenceFailed),
	}
}
