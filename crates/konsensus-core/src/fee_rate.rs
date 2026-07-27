//! Shared fee-rate validator used by every code path that accepts a
//! caller-supplied `fee_rate_sat_per_vb` (Lightning trait wrappers, REST
//! handlers, future tooling).
//!
//! Track L0a (2026-04-30 review): `fee_rate_sat_per_vb: f32 as u64` truncates
//! fractional rates. `0.5 sat/vB` becomes `0`, which LDK accepts and broadcasts
//! a transaction that never propagates. `1.5 sat/vB` becomes `1`, which
//! under-pays the mempool. Both produce silent fund-loss-class incidents.
//! This validator ceil-rounds inside a known-good range so callers cannot
//! observe either failure mode.

use thiserror::Error;

/// Minimum allowed fee rate in sat/vB. Below this the network rarely
/// propagates the tx; on Lightning the channel can stall indefinitely.
pub const MIN_FEE_RATE_SAT_PER_VB: f32 = 1.0;

/// Maximum allowed fee rate in sat/vB. Sanity bound that prevents runaway
/// rates from API typos or upstream estimator glitches. ~10× the busiest
/// historical mainnet day.
pub const MAX_FEE_RATE_SAT_PER_VB: f32 = 10_000.0;

/// Reasons a caller-supplied fee rate is rejected before reaching LDK.
#[derive(Debug, Error, PartialEq)]
pub enum FeeRateError {
    /// The value is `NaN`, `+Inf`, or `-Inf`.
    #[error("fee_rate_sat_per_vb must be finite (got {0})")]
    NotFinite(String),

    /// The value is below `MIN_FEE_RATE_SAT_PER_VB`.
    #[error("fee_rate_sat_per_vb {0} is below minimum {MIN_FEE_RATE_SAT_PER_VB} sat/vB")]
    BelowMinimum(f32),

    /// The value is above `MAX_FEE_RATE_SAT_PER_VB`.
    #[error("fee_rate_sat_per_vb {0} is above maximum {MAX_FEE_RATE_SAT_PER_VB} sat/vB")]
    AboveMaximum(f32),
}

/// Validate a caller-supplied `fee_rate_sat_per_vb` and return the
/// LDK-ready integer rate.
///
/// Behavior:
/// 1. Reject `!is_finite()` (`NaN`, `±Inf`) — these would silently produce
///    `0` under `as u64` casting on most platforms and slip past naive
///    `<= 0.0` checks (`NaN` compares false everywhere).
/// 2. Reject `< MIN_FEE_RATE_SAT_PER_VB` (1.0). Fractional values like
///    `0.5` would otherwise floor to `0` and get a tx the mempool ignores.
/// 3. Reject `> MAX_FEE_RATE_SAT_PER_VB` (10_000.0). Sanity bound.
/// 4. Otherwise return `r.ceil() as u64`. The `ceil` ensures `1.5 → 2`
///    rather than `1`, and the bounds check guarantees the cast cannot
///    saturate.
///
/// # Examples
///
/// ```
/// use konsensus_core::fee_rate::validate_fee_rate_sat_per_vb;
/// assert_eq!(validate_fee_rate_sat_per_vb(1.0).unwrap(), 1);
/// assert_eq!(validate_fee_rate_sat_per_vb(1.5).unwrap(), 2);
/// assert_eq!(validate_fee_rate_sat_per_vb(50.0).unwrap(), 50);
/// assert!(validate_fee_rate_sat_per_vb(0.5).is_err());
/// assert!(validate_fee_rate_sat_per_vb(f32::NAN).is_err());
/// ```
pub fn validate_fee_rate_sat_per_vb(rate: f32) -> Result<u64, FeeRateError> {
    if !rate.is_finite() {
        return Err(FeeRateError::NotFinite(format!("{rate}")));
    }
    if rate < MIN_FEE_RATE_SAT_PER_VB {
        return Err(FeeRateError::BelowMinimum(rate));
    }
    if rate > MAX_FEE_RATE_SAT_PER_VB {
        return Err(FeeRateError::AboveMaximum(rate));
    }
    Ok(rate.ceil() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_values_pass_through() {
        assert_eq!(validate_fee_rate_sat_per_vb(1.0).unwrap(), 1);
        assert_eq!(validate_fee_rate_sat_per_vb(50.0).unwrap(), 50);
        assert_eq!(validate_fee_rate_sat_per_vb(10_000.0).unwrap(), 10_000);
    }

    #[test]
    fn fractional_rates_ceil_not_floor() {
        // The whole point of the validator: `1.5 → 2`, never `1`.
        assert_eq!(validate_fee_rate_sat_per_vb(1.5).unwrap(), 2);
        assert_eq!(validate_fee_rate_sat_per_vb(1.001).unwrap(), 2);
        assert_eq!(validate_fee_rate_sat_per_vb(9_999.9).unwrap(), 10_000);
    }

    #[test]
    fn rates_below_minimum_rejected() {
        // `0.5` previously floored to `0` → unbroadcast tx.
        match validate_fee_rate_sat_per_vb(0.5) {
            Err(FeeRateError::BelowMinimum(r)) => assert_eq!(r, 0.5),
            other => panic!("expected BelowMinimum(0.5), got {other:?}"),
        }
        assert!(matches!(
            validate_fee_rate_sat_per_vb(0.0),
            Err(FeeRateError::BelowMinimum(_))
        ));
        assert!(matches!(
            validate_fee_rate_sat_per_vb(-1.0),
            Err(FeeRateError::BelowMinimum(_))
        ));
        assert!(matches!(
            validate_fee_rate_sat_per_vb(0.999),
            Err(FeeRateError::BelowMinimum(_))
        ));
    }

    #[test]
    fn rates_above_maximum_rejected() {
        match validate_fee_rate_sat_per_vb(10_000.1) {
            Err(FeeRateError::AboveMaximum(r)) => assert_eq!(r, 10_000.1),
            other => panic!("expected AboveMaximum(10_000.1), got {other:?}"),
        }
        assert!(matches!(
            validate_fee_rate_sat_per_vb(1_000_000.0),
            Err(FeeRateError::AboveMaximum(_))
        ));
    }

    #[test]
    fn non_finite_rates_rejected() {
        // `NaN` compares false to everything — would slip past a naive
        // `rate <= 0.0` guard.
        assert!(matches!(
            validate_fee_rate_sat_per_vb(f32::NAN),
            Err(FeeRateError::NotFinite(_))
        ));
        assert!(matches!(
            validate_fee_rate_sat_per_vb(f32::INFINITY),
            Err(FeeRateError::NotFinite(_))
        ));
        assert!(matches!(
            validate_fee_rate_sat_per_vb(f32::NEG_INFINITY),
            Err(FeeRateError::NotFinite(_))
        ));
    }

    #[test]
    fn cast_cannot_saturate() {
        // The bounds check ensures the largest accepted f32 (10_000.0)
        // fits well within u64. Saturation on `as u64` is impossible to
        // observe.
        let max_ok = validate_fee_rate_sat_per_vb(MAX_FEE_RATE_SAT_PER_VB).unwrap();
        assert_eq!(max_ok, 10_000);
    }
}
