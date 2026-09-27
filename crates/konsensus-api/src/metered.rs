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
use crate::pairing::PairingService;
use crate::spend_budget::{BudgetRefusal, Charge, FirstContactGrant, Reservation};
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

    /// Issue the owner's one-time first-contact confirmation for `recipient`
    /// (see [`FirstContactGrant`]). Only a paired client needs one; the
    /// owner's own key is not metered and is refused here as a misuse.
    pub fn grant_first_contact(
        &self,
        state: &AppState,
        recipient: &str,
        max_total_msat: u64,
        contact_budget_msat: Option<u64>,
    ) -> Result<FirstContactGrant, ApiError> {
        let Meter::Grant { client_id, epoch } = &self.meter else {
            return Err(ApiError::BadRequest(
                "the owner's key is not metered; a first-contact grant is for a paired client".into(),
            ));
        };
        let service = state
            .pairing
            .as_ref()
            .ok_or(ApiError::BudgetExceeded(BudgetRefusal::NoGrant))?;
        service
            .grant_first_contact(client_id, *epoch, recipient, max_total_msat, contact_budget_msat)
            .map_err(ApiError::BudgetExceeded)
    }

    /// For a first contact: the amount the owner confirmed for `recipient`,
    /// consumed (single use). `Ok(None)` for the owner's own key, which is not
    /// metered. A paired client without a live matching first-contact grant is
    /// refused before anything is requested or paid.
    pub fn take_first_contact(&self, state: &AppState, recipient: &str) -> Result<Option<u64>, ApiError> {
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

    /// Debit a call's charges before anything is dispatched.
    ///
    /// Returns a [`Debit`] the handler resolves once each outcome is known.
    /// Zero-amount charges are dropped: they move nothing.
    pub fn debit(&self, state: &AppState, charges: Vec<Charge>) -> Result<Debit, ApiError> {
        let Meter::Grant { client_id, epoch } = &self.meter else {
            return Ok(Debit::unmetered());
        };
        let service = state
            .pairing
            .as_ref()
            .ok_or(ApiError::BudgetExceeded(BudgetRefusal::NoGrant))?;
        let charges: Vec<Charge> = charges.into_iter().filter(|c| c.amount_msat > 0).collect();
        let reservation = service
            .reserve_spend(client_id, *epoch, charges)
            .map_err(ApiError::BudgetExceeded)?;
        tracing::debug!(
            client = %client_id,
            reserved_msat = reservation.charges.iter().map(|c| c.amount_msat).sum::<u64>(),
            "spend grant debited before dispatch"
        );
        Ok(Debit {
            held: Some((Arc::clone(service), reservation)),
        })
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
}

impl Debit {
    /// Owner-only paths have no grant to revalidate.
    pub(crate) fn unmetered() -> Self {
        Self { held: None }
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
        service
            .grant_view_for(&reservation.client_id)?
            .per_recipient_msat
            .get(recipient)
            .copied()
    }

    /// Reserve a re-admission to `recipient` of exactly `amount_msat` (the
    /// recipient's signed quote) against the same grant, as its own debit.
    /// Unmetered for the owner's own key.
    pub(crate) fn readmission(&self, recipient: &str, amount_msat: u64) -> Result<Debit, ApiError> {
        let Some((service, reservation)) = &self.held else {
            return Ok(Debit::unmetered());
        };
        let readmission = service
            .reserve_readmission(reservation, recipient, amount_msat)
            .map_err(ApiError::BudgetExceeded)?;
        Ok(Debit {
            held: Some((Arc::clone(service), readmission)),
        })
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
            service.resolve_spend(reservation, recipient, amount_msat);
        }
    }

    /// Nothing was paid to `recipient`: refused before dispatch, or the
    /// payment was confirmed failed.
    pub fn released(&self, recipient: &str) {
        self.settled(recipient, 0);
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
