//! Capped principal amounts: decide once, then pay exactly the checked snapshot.
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
