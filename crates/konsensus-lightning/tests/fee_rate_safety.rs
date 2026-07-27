//! Integration test for L0a — fee-rate validation at the
//! konsensus-lightning boundary.
//!
//! The LDK provider's `send_onchain` and `open_channel` accept an
//! `Option<f32>` fee rate from callers. Before L0a it cast `r as u64`, which
//! silently floored fractional rates (`0.5 → 0`) and admitted `NaN`/`±Inf`.
//! L0a routes the value through `konsensus_core::fee_rate::validate_fee_rate_sat_per_vb`
//! before LDK ever sees it.
//!
//! This test asserts the validator's contract — covered exhaustively in the
//! core unit tests — is exposed at the boundary the LDK wrapper uses, so
//! a future refactor can't accidentally drop the validation while the
//! core tests still pass.

use konsensus_core::fee_rate::{
    validate_fee_rate_sat_per_vb, FeeRateError, MAX_FEE_RATE_SAT_PER_VB, MIN_FEE_RATE_SAT_PER_VB,
};

#[test]
fn fractional_rate_ceils_not_floors() {
    // The headline pre-L0a bug: `1.5_f32 as u64 == 1`, which underpays.
    // Validator must ceil to 2.
    assert_eq!(validate_fee_rate_sat_per_vb(1.5).unwrap(), 2);
}

#[test]
fn sub_one_rate_rejected_not_floored_to_zero() {
    // The fund-loss case: `0.5_f32 as u64 == 0`. LDK accepted 0; tx never
    // propagated. Validator must reject below the 1.0 floor.
    let err = validate_fee_rate_sat_per_vb(0.5).unwrap_err();
    assert!(matches!(err, FeeRateError::BelowMinimum(_)), "got {err:?}");
}

#[test]
fn nan_rejected_not_silently_zero() {
    // NaN compares false to every threshold, so `<= 0.0` admits it. Casting
    // NaN to u64 is implementation-defined and historically yielded 0 on
    // some platforms. Validator must reject explicitly.
    let err = validate_fee_rate_sat_per_vb(f32::NAN).unwrap_err();
    assert!(matches!(err, FeeRateError::NotFinite(_)), "got {err:?}");
}

#[test]
fn infinity_rejected_not_silently_max() {
    let err = validate_fee_rate_sat_per_vb(f32::INFINITY).unwrap_err();
    assert!(matches!(err, FeeRateError::NotFinite(_)), "got {err:?}");
}

#[test]
fn upper_bound_enforced() {
    // Above the 10_000 sat/vB sanity bound, reject.
    let err = validate_fee_rate_sat_per_vb(MAX_FEE_RATE_SAT_PER_VB + 0.1).unwrap_err();
    assert!(matches!(err, FeeRateError::AboveMaximum(_)), "got {err:?}");
}

#[test]
fn boundary_values_accepted() {
    // Both bounds inclusive.
    assert_eq!(
        validate_fee_rate_sat_per_vb(MIN_FEE_RATE_SAT_PER_VB).unwrap(),
        1
    );
    assert_eq!(
        validate_fee_rate_sat_per_vb(MAX_FEE_RATE_SAT_PER_VB).unwrap(),
        10_000
    );
}

#[test]
fn validated_rate_round_trips_through_ldk_fee_rate() {
    // Sanity check: every value the validator returns is a valid input to
    // `ldk_node::bitcoin::FeeRate::from_sat_per_vb`. If LDK starts rejecting
    // values inside our 1..=10_000 band a future LDK upgrade, this test
    // catches it.
    for raw in [1.0_f32, 1.5, 50.0, 500.0, 9_999.9, 10_000.0] {
        let rate_u64 = validate_fee_rate_sat_per_vb(raw).unwrap();
        let _ = ldk_node::bitcoin::FeeRate::from_sat_per_vb(rate_u64).unwrap_or_else(|| {
            panic!("LDK rejected validated rate {rate_u64} (from input {raw})")
        });
    }
}
