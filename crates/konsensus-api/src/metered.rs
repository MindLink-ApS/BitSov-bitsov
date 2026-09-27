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

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::auth::{AuthUser, Scope};
use crate::error::ApiError;
use crate::pairing::PairingService;
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

    /// Debit a call's charges before anything is dispatched.
    ///
    /// Returns a [`Debit`] the handler resolves once each outcome is known.
    /// Zero-amount charges are dropped: they move nothing.
    pub fn debit(&self, state: &AppState, charges: Vec<Charge>) -> Result<Debit, ApiError> {
        let Meter::Grant { client_id, epoch } = &self.meter else {
            return Ok(Debit { held: None });
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
