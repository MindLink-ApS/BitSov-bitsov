//! Capped all-in debit amounts: decide once, then pay exactly the checked snapshot.
use std::collections::HashMap;
use crate::error::ApiError;

pub const CAPABILITY: &str = "paid_send_caps_v1";

/// A capped single-recipient chat pays a reconnect's re-admission when the
/// contact's fresh signed quote (admission + message + both routing ceilings)
/// fits the cap and any grant. A cap that does not fit is refused before any
/// payment with 409 `price_cap_exceeded`, `reason: readmission_required`; the
/// quote it fetched is then served by `POST /messages/first-contact/quote` on
/// the same connection, so the same operation can be sent again under it.
pub const QUOTED_READMISSION_CAPABILITY: &str = "quoted_readmission_v1";
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

/// One approval/reservation covers both first-contact acts. The message also
/// has its own all-in ceiling, independently of admission.
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
/// Snapshot of messaging limits used for both reservation and dispatch.
#[derive(Clone)]
pub(crate) struct MessageCaps {
    limit: u64,
    recipients: std::collections::BTreeMap<String, u64>,
}
impl Default for MessageCaps {
    fn default() -> Self { Self { limit: u64::MAX, recipients: Default::default() } }
}
impl MessageCaps {
    pub(crate) fn for_user(state: &crate::state::AppState, user: &crate::auth::AuthUser) -> Self {
        let Some(binding) = &user.pairing else { return Self::default(); };
        let view = state.pairing.as_ref().and_then(|s| s.grant_view_for(&binding.client_id));
        Self {
            limit: view.as_ref().map_or(crate::spend_budget::MESSAGING_PER_CALL_MAX_MSAT, |v| v.per_call_max_msat),
            recipients: view.map_or_else(Default::default, |v| v.per_act_max_by_recipient),
        }
    }
    pub(crate) fn for_reservation(service: &crate::pairing::PairingService, reservation: &crate::spend_budget::Reservation) -> Self {
        match service.grant_view_for(&reservation.client_id).filter(|v| v.op_id == reservation.op_id) {
            Some(view) => Self { limit: view.per_call_max_msat, recipients: view.per_act_max_by_recipient },
            None => Self { limit: 0, recipients: Default::default() },
        }
    }
    pub(crate) fn tighten(&mut self, other: Self) {
        self.limit = self.limit.min(other.limit);
        for (peer, limit) in other.recipients {
            self.recipients.entry(peer).and_modify(|current| *current = (*current).min(limit)).or_insert(limit);
        }
    }
    fn limit(&self, peer: &str) -> u64 {
        self.limit.min(self.recipients.get(peer).copied().unwrap_or(u64::MAX))
    }
    pub(crate) fn fee(&self, state: &crate::state::AppState, peer: &str, price: u64, caller: Option<u64>) -> u64 {
        state.lightning.routing_fee_policy().ceiling(price, caller)
            .min(self.limit(peer).saturating_sub(price))
    }
    pub(crate) fn all_in(&self, state: &crate::state::AppState, peer: &str, price: u64, caller: Option<u64>) -> Result<u64, ApiError> {
        let max_msat = self.limit(peer);
        if price > max_msat {
            return Err(ApiError::BudgetExceeded(crate::spend_budget::BudgetRefusal::PerCall { max_msat }));
        }
        price.checked_add(self.fee(state, peer, price, caller))
            .ok_or_else(|| ApiError::PriceCapExceeded("message total overflow".into()))
    }
}

pub(crate) const MESSAGE_ROUTE_REFUSAL: &str =
    "The route cannot fit within the approved message total. The message payment was not dispatched.";

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
