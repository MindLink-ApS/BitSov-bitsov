//! Capped all-in debit amounts: decide once, then pay exactly the checked snapshot.
use std::collections::HashMap;
use crate::error::ApiError;

pub const CAPABILITY: &str = "paid_send_caps_v1";
pub const ROOM_CAPABILITY: &str = "room_terminal_outcomes_v1";

pub fn payable(price: u64) -> u64 { if price == 0 { 0 } else { price.max(1000) } }

pub fn check(amount: u64, cap: Option<u64>) -> Result<(), ApiError> {
    if cap.is_some_and(|max| amount > max) {
        return Err(ApiError::PriceCapExceeded(format!("required {amount} msat exceeds the confirmed cap")));
    }
    Ok(())
}

pub fn check_room(prices: &[(konsensus_core::NodeId, u64)], total: Option<u64>, per: Option<&HashMap<String, u64>>) -> Result<(), ApiError> {
    if per.is_some_and(|caps| caps.len() != prices.len()) {
        return Err(ApiError::PriceCapExceeded("room membership changed; refresh the quote".into()));
    }
    let mut sum = 0u64;
    for (peer, amount) in prices {
        sum = sum.checked_add(*amount).ok_or_else(|| ApiError::PriceCapExceeded("room total overflow".into()))?;
        if let Some(per) = per {
            let cap = per.get(&peer.to_hex()).ok_or_else(|| ApiError::PriceCapExceeded("room membership changed or recipient cap missing".into()))?;
            check(*amount, Some(*cap))?;
        }
    }
    check(sum, total)
}

/// One authorization covers both first-contact acts. Never reserve/debit them
/// as separate calls: G1 per-call limits apply to this aggregate.
pub fn first_contact_total(admission: u64, message: u64, cap: Option<u64>) -> Result<u64, ApiError> {
    let total = admission.checked_add(message).ok_or_else(|| ApiError::PriceCapExceeded("first-contact total overflow".into()))?;
    check(total, cap)?;
    Ok(total)
}

/// Snapshot principal plus the policy-approved routing fee before any dispatch.
pub fn all_in(state: &crate::state::AppState, principal: u64, caller: Option<u64>) -> Result<u64, ApiError> {
    let fee = state.lightning.routing_fee_policy().ceiling(principal, caller);
    principal.checked_add(fee).ok_or_else(|| ApiError::PriceCapExceeded(format!("all-in amount overflow; max_routing_fee_msat={fee}")))
}
pub fn check_payment(state: &crate::state::AppState, principal: u64, caller: Option<u64>, cap: Option<u64>) -> Result<u64, ApiError> {
    let total = all_in(state, principal, caller)?;
    let fee = total - principal;
    if cap.is_some_and(|cap| total > cap) {
        return Err(ApiError::PriceCapExceeded(format!("required {total} msat including max_routing_fee_msat={fee} exceeds the confirmed cap")).with_routing_fee(fee));
    }
    Ok(total)
}

#[cfg(test)]
mod first_contact_tests {
    use super::*;
    #[test]
    fn admission_and_message_share_one_cap() {
        assert_eq!(first_contact_total(2000, 2000, Some(4000)).unwrap(), 4000);
        assert!(matches!(first_contact_total(2000, 2000, Some(3999)), Err(ApiError::PriceCapExceeded(_))));
        assert!(first_contact_total(u64::MAX, 1, None).is_err());
        assert_eq!(first_contact_total(2000, 0, Some(2000)).unwrap(), 2000);
    }
}
