//! Metered spend: the extractor every budgeted paid path takes (G1).
//!
//! A paired client's `spend` comes only from a budget grant, so on a route that
//! moves value it must be **debited before** any invoice is requested or paid.
//! [`MeteredSpend`] is how a handler says "I debit": it requires `spend`, and
//! for a paired caller it yields a meter bound to the client and pairing epoch.
//!
//! The converse is enforced in [`crate::auth::scoped::ScopedAuth`]: a route
//! that still takes `ScopedAuth<Spend>` does not debit, so it refuses a paired
//! caller outright. A new money route therefore fails closed for paired
//! clients until it is written against this extractor.
//!
//! A caller holding the node's own key (not a pairing) is the owner and is not
//! metered; the #80 caps still bound what it asked for.

use std::future::Future;
use std::sync::Arc;
use std::task::Poll;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::auth::{AuthUser, Scope};
use crate::error::ApiError;
use crate::pairing::{FirstContactAuthorization, PairingService};
use crate::spend_budget::{BudgetRefusal, Charge, Reservation};
use crate::state::AppState;

/// An authenticated caller holding `spend`, with the meter that applies to it.
pub struct MeteredSpend {
    /// The caller.
    pub user: AuthUser,
    meter: Meter,
}

enum Meter {
    /// The owner's own key: not metered.
    Owner,
    /// A paired client: every paid call debits its grant.
    Grant { client_id: String, epoch: u64 },
}

impl std::ops::Deref for MeteredSpend {
    type Target = AuthUser;
    fn deref(&self) -> &AuthUser {
        &self.user
    }
}

#[axum::async_trait]
impl FromRequestParts<Arc<AppState>> for MeteredSpend {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if !user.has(Scope::Spend) {
            metrics::counter!(crate::metrics::AUTH_FAILURES).increment(1);
            tracing::warn!(required = "spend", "token lacks the required scope");
            return Err(
                (StatusCode::FORBIDDEN, "token lacks required scope: spend").into_response()
            );
        }
        let meter = match &user.pairing {
            Some(binding) => Meter::Grant {
                client_id: binding.client_id.clone(),
                epoch: binding.epoch,
            },
            None => Meter::Owner,
        };
        Ok(Self { user, meter })
    }
}

impl MeteredSpend {
    /// Only the owner control socket may construct authority without HTTP proof.
    #[cfg(unix)]
    pub(crate) fn owner_control(state: &AppState) -> Self {
        Self {
            user: AuthUser { node_id: state.identity.node_id().to_hex(), scopes: vec![Scope::Spend], pairing: None },
            meter: Meter::Owner,
        }
    }

    /// Whether this caller spends from a budget grant.
    pub fn is_metered(&self) -> bool {
        matches!(self.meter, Meter::Grant { .. })
    }

    /// Refuse a payment whose amount cannot be known before it is made.
    /// Only a metered caller is refused; the owner's own key is not.
    pub fn refuse_unpriced(&self, why: &str) -> Result<(), ApiError> {
        if self.is_metered() {
            return Err(ApiError::BudgetExceeded(BudgetRefusal::Unpriced(format!(
                "{why}; a budget grant only pays amounts known before dispatch — nothing was paid"
            ))));
        }
        Ok(())
    }

    /// Whether this caller may pay right now: the owner always; a paired
    /// client only while it holds a live budget grant.
    pub fn has_live_grant(&self, state: &AppState) -> bool {
        match &self.meter {
            Meter::Owner => true,
            Meter::Grant { client_id, .. } => state
                .pairing
                .as_ref()
                .and_then(|service| service.grant_view_for(client_id))
                .is_some(),
        }
    }

    /// For a first contact: the owner's approval for `recipient`, consumed
    /// once and still bound to its original budget until reservation. `Ok(None)` for the owner's own key, which is not
    /// metered. A paired client without a live matching first-contact grant is
    /// refused before anything is requested or paid.
    pub fn take_first_contact(&self, state: &AppState, recipient: &str) -> Result<Option<FirstContactAuthorization>, ApiError> {
        let Meter::Grant { client_id, epoch } = &self.meter else {
            return Ok(None);
        };
        state
            .pairing
            .as_ref()
            .and_then(|service| service.take_first_contact(client_id, *epoch, recipient))
            .map(Some)
            .ok_or_else(|| {
                ApiError::BudgetExceeded(BudgetRefusal::FirstContact(
                    "a first contact needs the owner's one-time confirmation for this contact \
                     (POST /api/v1/pair/first-contact-grant) — nothing was requested or paid"
                        .into(),
                ))
            })
    }

    pub(crate) fn debit_first_contact(&self, state: &AppState, approval: FirstContactAuthorization, cap: Option<u64>) -> Result<Debit, ApiError> {
        let service = state.pairing.as_ref().ok_or(ApiError::BudgetExceeded(BudgetRefusal::NoGrant))?;
        let reservation = service.reserve_first_contact(approval, cap).map_err(ApiError::BudgetExceeded)?;
        Ok(Debit::reserved(Arc::clone(service), reservation))
    }

    /// Debit a call's charges before anything is dispatched.
    ///
    /// Returns a [`Debit`] the handler resolves once each outcome is known.
    /// Zero amounts retain their recipient so resolution still consumes the reservation.
    pub fn debit(&self, state: &AppState, charges: Vec<Charge>) -> Result<Debit, ApiError> {
        self.debit_purpose(state, charges, false)
    }

    /// Link an operation's durable journal before committing its G1 debit.
    /// The callback is synchronous and cannot call the pairing service.
    pub(crate) fn debit_linked(
        &self, state: &AppState, charges: Vec<Charge>,
        persist_link: impl FnOnce(Option<&Reservation>) -> Result<(), BudgetRefusal>,
    ) -> Result<Debit, ApiError> {
        let Meter::Grant { client_id, epoch } = &self.meter else {
            persist_link(None).map_err(ApiError::BudgetExceeded)?;
            return Ok(Debit::unmetered());
        };
        let service = state.pairing.as_ref().ok_or(ApiError::BudgetExceeded(BudgetRefusal::NoGrant))?;
        let reservation = service.reserve_spend_linked(client_id, *epoch, charges, |r| persist_link(Some(r)))
            .map_err(ApiError::BudgetExceeded)?;
        Ok(Debit::reserved(Arc::clone(service), reservation))
    }

    /// Reserve an explicitly approved LSP fee under total/call/recipient bounds.
    pub fn debit_liquidity(&self, state: &AppState, charge: Charge) -> Result<Debit, ApiError> {
        self.debit_purpose(state, vec![charge], true)
    }

    fn debit_purpose(&self, state: &AppState, charges: Vec<Charge>, liquidity: bool) -> Result<Debit, ApiError> {
        let Meter::Grant { client_id, epoch } = &self.meter else {
            return Ok(Debit::unmetered());
        };
        let service = state
            .pairing
            .as_ref()
            .ok_or(ApiError::BudgetExceeded(BudgetRefusal::NoGrant))?;
        let reservation = if liquidity {
            service.reserve_liquidity_fee(client_id, *epoch, charges)
        } else {
            service.reserve_spend(client_id, *epoch, charges)
        }.map_err(ApiError::BudgetExceeded)?;
        tracing::debug!(
            client = %client_id,
            reserved_msat = reservation.charges.iter().map(|c| c.amount_msat).sum::<u64>(),
            "spend grant debited before dispatch"
        );
        Ok(Debit::reserved(Arc::clone(service), reservation))
    }
}

/// A reservation against a grant, waiting for its outcomes.
///
/// Dropping it without resolving keeps every charge reserved: that is the
/// "unknown" outcome, and the right answer when a handler is cancelled
/// mid-payment. Resolve explicitly to release or settle.
#[must_use = "resolve each charge once its outcome is known; dropping keeps it reserved"]
pub struct Debit {
    held: Option<(Arc<PairingService>, Reservation)>,
    max_routing_fee_msat: Option<u64>,
    // None means a settled payment's fee is still unknown. Never release that liability.
    fees: std::sync::Mutex<std::collections::BTreeMap<String, Option<u64>>>,
    // Shared by every member of a room fan-out. Reservations consume this
    // call's allowance even when a sibling finishes before another starts.
    call_reserved_msat: std::sync::Mutex<u64>,
}

impl Debit {
    pub(crate) fn with_fee_limit(mut self, limit: Option<u64>) -> Self {
        self.max_routing_fee_msat = limit;
        self
    }
    pub(crate) fn fee_limit(&self, state: &AppState, principal: u64) -> u64 {
        state.lightning.routing_fee_policy().ceiling(principal, self.max_routing_fee_msat)
    }
    pub(crate) fn record_payment(&self, recipient: &str, details: &konsensus_core::traits::lightning::PaymentDetails) {
        let mut fees = self.fees.lock().unwrap_or_else(|e| e.into_inner());
        let previous = fees.entry(recipient.to_owned()).or_insert(Some(0));
        *previous = previous.and_then(|total| details.fee_msat.and_then(|fee| total.checked_add(fee)));
    }

    /// Owner-only paths have no grant to revalidate.
    pub(crate) fn unmetered() -> Self {
        Self { max_routing_fee_msat: None, fees: Default::default(), held: None, call_reserved_msat: std::sync::Mutex::new(0) }
    }

    fn reserved(service: Arc<PairingService>, reservation: Reservation) -> Self {
        let total = reservation.charges.iter().map(|c| c.amount_msat).sum();
        Self { max_routing_fee_msat: None, fees: Default::default(), held: Some((service, reservation)), call_reserved_msat: std::sync::Mutex::new(total) }
    }

    /// Whether this debit is held against a budget grant.
    pub(crate) fn is_metered(&self) -> bool {
        self.held.is_some()
    }

    /// Whether the grant behind this debit may pay admission to `recipient`
    /// again (see [`PairingService::reserve_readmission`]). Always for the
    /// owner's own key, which is not metered. Reserves nothing.
    pub(crate) fn readmission_allowed(&self, recipient: &str) -> Result<(), ApiError> {
        let Some((service, reservation)) = &self.held else {
            return Ok(());
        };
        service
            .readmission_allowed(reservation, recipient)
            .map_err(ApiError::BudgetExceeded)
    }

    /// The contact's budget cap in the grant behind this debit, msat, if any.
    pub(crate) fn contact_budget(&self, recipient: &str) -> Option<u64> {
        let (service, reservation) = self.held.as_ref()?;
        service.reservation_contact_budget(reservation, recipient)
    }

    /// Reserve a re-admission to `recipient` of exactly `amount_msat` (the
    /// recipient's signed quote) against the same grant, as its own debit.
    /// Unmetered for the owner's own key.
    pub(crate) fn readmission(&self, recipient: &str, amount_msat: u64) -> Result<Debit, ApiError> {
        let Some((service, reservation)) = &self.held else {
            return Ok(Debit::unmetered().with_fee_limit(self.max_routing_fee_msat));
        };
        let mut call_total = self.call_reserved_msat.lock().unwrap_or_else(|e| e.into_inner());
        let readmission = service
            .reserve_readmission(reservation, recipient, amount_msat, *call_total)
            .map_err(ApiError::BudgetExceeded)?;
        *call_total += amount_msat; // checked against the grant limit under its ledger lock
        Ok(Debit::reserved(Arc::clone(service), readmission).with_fee_limit(self.max_routing_fee_msat))
    }

    /// Reconciliation reference only; never restores dispatch authority.
    pub(crate) fn reservation(&self) -> Option<Reservation> {
        self.held.as_ref().map(|(_, reservation)| reservation.clone())
    }

    /// Guard each poll of an operation that can dispatch value. A separate
    /// check followed by `.await` leaves a revocation race: the provider may
    /// suspend before it dispatches. Polling under the ledger mutex orders
    /// each dispatch step with debit/revoke/rotation without holding a lock
    /// across suspension. The provider must not spawn undispatched work that
    /// outlives its future; handing a request to a backend is dispatch.
    ///
    /// Once polled, a provider may have sent funds even if it returned Pending.
    /// Invalidation then is unknown, never a reason to release or fall back.
    pub(crate) async fn dispatch<F: Future>(&self, operation: F) -> Result<F::Output, ApiError> {
        let Some((service, reservation)) = &self.held else {
            return Ok(operation.await);
        };
        let mut operation = std::pin::pin!(operation);
        let mut polled = false;
        futures::future::poll_fn(|cx| {
            match service.with_spend_authority(reservation, || {
                polled = true;
                operation.as_mut().poll(cx)
            }) {
                Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
                Ok(Poll::Pending) => Poll::Pending,
                Err(e) if !polled => Poll::Ready(Err(ApiError::BudgetExceeded(e))),
                Err(_) => Poll::Ready(Err(ApiError::PaymentUnresolved(
                    "grant invalidated while the provider was pending; payment may have dispatched"
                        .into(),
                ))),
            }
        })
        .await
    }

    /// Authorize the start of a non-paying invoice request. Unlike a wallet
    /// operation, a started Noise frame must finish: dropping a partial write
    /// would corrupt framing or consume an unmatched encryption nonce on the
    /// shared connection. The subsequent invoice payment is separately guarded
    /// by `dispatch`, even when authority changed during this write.
    pub(crate) async fn request_invoice<F: Future>(
        &self,
        operation: F,
    ) -> Result<F::Output, ApiError> {
        let Some((service, reservation)) = &self.held else {
            return Ok(operation.await);
        };
        let mut operation = std::pin::pin!(operation);
        let first = futures::future::poll_fn(|cx| {
            Poll::Ready(service.with_spend_authority(reservation, || operation.as_mut().poll(cx)))
        })
        .await
        .map_err(ApiError::BudgetExceeded)?;
        match first {
            Poll::Ready(output) => Ok(output),
            Poll::Pending => Ok(operation.await),
        }
    }

    /// The payment to `recipient` settled for `amount_msat`.
    pub fn settled(&self, recipient: &str, amount_msat: u64) {
        if let Some((service, reservation)) = &self.held {
            let fees = self.fees.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(total) = settled_total(amount_msat, fees.get(recipient).copied()) {
                service.resolve_spend(reservation, recipient, total);
            }
        }
    }

    /// Nothing was paid to `recipient`: refused before dispatch, or the
    /// payment was confirmed failed.
    pub fn released(&self, recipient: &str) {
        if let Some((service, reservation)) = &self.held {
            service.resolve_spend(reservation, recipient, 0);
        }
    }

    /// Resolve from the result of `create_payment_proof`, using the #80
    /// classification: an unresolved payment stays reserved, a settled
    /// payment without a usable proof is settled, and anything else never
    /// moved value.
    pub fn resolve_proof<H, P>(&self, recipient: &str, result: &Result<(H, P, u64), ApiError>) {
        match result {
            Ok((_, _, amount_msat)) => self.settled(recipient, *amount_msat),
            Err(ApiError::PaymentUnresolved(_)) => {}
            Err(ApiError::PaymentProofUnavailable { amount_msat, .. }) => {
                self.settled(recipient, *amount_msat)
            }
            Err(_) => self.released(recipient),
        }
    }
}

/// No record is safe only when no principal was paid. An explicit unknown fee
/// always retains liability; absence never invents a zero fee for paid value.
fn settled_total(principal: u64, recorded_fee: Option<Option<u64>>) -> Option<u64> {
    recorded_fee.unwrap_or_else(|| (principal == 0).then_some(0))
        .and_then(|fee| principal.checked_add(fee))
}

#[cfg(test)]
mod fee_evidence_tests {
    #[test]
    fn missing_fee_evidence_holds_positive_debit_but_known_nonpayment_releases() {
        assert_eq!(super::settled_total(1000, None), None);
        assert_eq!(super::settled_total(0, None), Some(0));
        assert_eq!(super::settled_total(0, Some(None)), None);
        assert_eq!(super::settled_total(1000, Some(None)), None);
        assert_eq!(super::settled_total(1000, Some(Some(400))), Some(1400));
        assert_eq!(super::settled_total(u64::MAX, Some(Some(1))), None);
    }
}
