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
    /// Maintenance can charge only the grant that funded this call. This
    /// identity remains metered even after that grant has been removed.
    ///
    /// It carries no client id or epoch: the grant is pinned to one pairing
    /// epoch, and both the draw on its closing reserve
    /// (`PairingService::reserve_call_closing_spend`) and every dispatch poll
    /// (`PairingService::with_call_payment_authority`) take the pairing from
    /// that grant under the ledger lock and require it still current: same
    /// epoch and identity, grant not revoked. A revocation, epoch bump,
    /// pairing removal or identity change after admission therefore pays
    /// nothing.
    CallClosing { grant_op_id: Option<String>, peer: String, call_id: String },
    /// Live-call continuity only (see [`ComposeSpend`]): a paired client
    /// without `spend` paying the next minute block of the one call it owns,
    /// from that call's existing hold. Every other debit is refused.
    CallBlock { client_id: String, epoch: u64, peer: String, call_id: String },
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
    /// Internal authority only for a bounded protocol hangup after durable
    /// expiry. A grant-funded call never gains owner authority at termination.
    pub(crate) async fn call_timeout(state: &AppState, peer: &konsensus_core::NodeId, call_id: &str,
        reason: konsensus_core::payloads::call::HangupReason) -> Self {
        let grant_op_id = state.pairing.as_ref().and_then(|s| s.call_spend_grant(&peer.to_hex(), call_id));
        let meter = if reason == konsensus_core::payloads::call::HangupReason::Unpaid
            || (grant_op_id.is_none() && crate::calls::owner_funded_call(state, peer, call_id).await.unwrap_or(false)) {
            Meter::Owner
        } else { Meter::CallClosing { grant_op_id, peer: peer.to_hex(), call_id: call_id.into() } };
        Self {
            user: AuthUser { node_id: state.identity.node_id().to_hex(), scopes: vec![Scope::Spend], pairing: None },
            meter,
        }
    }

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
        !matches!(self.meter, Meter::Owner)
    }

    /// A minute-block-only caller has no other spending authority.
    fn refuse_call_block_only(&self) -> Result<(), ApiError> {
        if matches!(self.meter, Meter::CallBlock { .. }) {
            return Err(ApiError::BudgetExceeded(BudgetRefusal::NoGrant));
        }
        Ok(())
    }

    pub(crate) fn reserve_call(&self, state: &AppState, terms: crate::spend_budget::CallSpendTerms,
        capacity: u64) -> Result<(), ApiError> {
        self.refuse_call_block_only()?;
        let Meter::Grant { client_id, epoch } = &self.meter else { return Ok(()) };
        state.pairing.as_ref().ok_or(ApiError::BudgetExceeded(BudgetRefusal::NoGrant))?
            .reserve_call_spend(client_id, *epoch, terms, capacity).map_err(ApiError::BudgetExceeded)?;
        Ok(())
    }

    /// Reserve a new call's hold and debit its offer in one ledger
    /// transaction: a refusal of either keeps neither (see
    /// `PairingService::reserve_call_with_offer`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn debit_call_with_offer(&self, state: &AppState, terms: crate::spend_budget::CallSpendTerms,
        capacity: u64, charges: Vec<Charge>, cap: Option<u64>,
        operation: &crate::handlers::messages::operations::Operation) -> Result<Debit, ApiError> {
        self.refuse_call_block_only()?;
        let Meter::Grant { client_id, epoch } = &self.meter else { return Ok(Debit::unmetered()) };
        let service = state.pairing.as_ref().ok_or(ApiError::BudgetExceeded(BudgetRefusal::NoGrant))?;
        let reservation = service.reserve_call_with_offer(client_id, *epoch, terms, capacity, charges, cap,
            operation.reservation_link(false)).map_err(ApiError::BudgetExceeded)?;
        Ok(Debit::reserved(Arc::clone(service), reservation))
    }

    pub(crate) fn debit_call_block(&self, state: &AppState, signal: &konsensus_core::payloads::call::CallSignal,
        peer: &str, price: u64, fee: u64, operation: &crate::handlers::messages::operations::Operation) -> Result<Debit, ApiError> {
        let (client_id, epoch) = match &self.meter {
            Meter::Grant { client_id, epoch } => (client_id, epoch),
            // Only the call this authority was admitted for, on its hold.
            Meter::CallBlock { client_id, epoch, peer: own_peer, call_id }
                if own_peer == peer && *call_id == signal.call_id => (client_id, epoch),
            Meter::CallBlock { .. } => return Err(ApiError::BudgetExceeded(BudgetRefusal::NoGrant)),
            _ => return Ok(Debit::unmetered()),
        };
        let service = state.pairing.as_ref().ok_or(ApiError::BudgetExceeded(BudgetRefusal::NoGrant))?;
        let reservation = service.draw_call_spend(client_id, *epoch, peer, &signal.call_id,
            signal.seq.ok_or_else(|| ApiError::BadRequest("missing call block sequence".into()))?,
            price, fee, operation.reservation_link(false)).map_err(ApiError::BudgetExceeded)?;
        Ok(Debit::reserved(service.clone(), reservation))
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
            Meter::CallClosing { grant_op_id, .. } => state.pairing.as_ref().is_some_and(|s|
                s.snapshot().grants.iter().any(|g| Some(&g.op_id) == grant_op_id.as_ref())),
            Meter::Grant { client_id, .. } => state
                .pairing
                .as_ref()
                .and_then(|service| service.grant_view_for(client_id))
                .is_some(),
            Meter::CallBlock { .. } => false,
        }
    }

    /// The owner's per-payment limit on a call payment under this caller's
    /// grant, if any (see `GrantBudget::call_per_payment_max_msat`). `None`
    /// for the owner's own key. The ledger enforces it again at reservation.
    pub(crate) fn call_per_payment_max_msat(&self, state: &AppState) -> Option<u64> {
        let Meter::Grant { client_id, .. } = &self.meter else { return None };
        state.pairing.as_ref()
            .and_then(|service| service.grant_view_for(client_id))
            .and_then(|view| view.call_per_payment_max_msat)
    }

    /// For a first contact: the owner's approval for `recipient`, consumed
    /// once and still bound to its original budget until reservation. `Ok(None)` for the owner's own key, which is not
    /// metered. A paired client without a live matching first-contact grant is
    /// refused before anything is requested or paid.
    pub fn take_first_contact(&self, state: &AppState, recipient: &str) -> Result<Option<FirstContactAuthorization>, ApiError> {
        self.refuse_call_block_only()?;
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

    pub(crate) fn debit_operation(&self, state: &AppState, charges: Vec<Charge>, approval: Option<FirstContactAuthorization>, cap: Option<u64>, operation: &crate::handlers::messages::operations::Operation) -> Result<Debit, ApiError> {
        self.refuse_call_block_only()?;
        if let Meter::CallClosing { grant_op_id, peer, call_id } = &self.meter {
            let grant_op_id = grant_op_id.as_deref().ok_or(ApiError::BudgetExceeded(BudgetRefusal::NoGrant))?;
            let service = state.pairing.as_ref().ok_or(ApiError::BudgetExceeded(BudgetRefusal::NoGrant))?;
            let reservation = service.reserve_call_closing_spend(grant_op_id, peer, call_id, charges, operation.reservation_link(false))
                .map_err(ApiError::BudgetExceeded)?;
            let mut debit = Debit::reserved(Arc::clone(service), reservation);
            debit.call_spend = Some((peer.clone(), call_id.clone()));
            debit.call_payment = Some(crate::spend_budget::CallPayment::Signal);
            return Ok(debit);
        }
        let Meter::Grant { client_id, epoch } = &self.meter else { return Ok(Debit::unmetered()); };
        let service = state.pairing.as_ref().ok_or(ApiError::BudgetExceeded(BudgetRefusal::NoGrant))?;
        let link = operation.reservation_link(false);
        let reservation = match approval {
            Some(approval) => service.reserve_first_contact_operation(approval, cap, Some(link)),
            None => service.reserve_operation_spend(client_id, *epoch, charges, link),
        }.map_err(ApiError::BudgetExceeded)?;
        Ok(Debit::reserved(Arc::clone(service), reservation))
    }

    /// Debit a call offer under its call's hold, bounded by the caller's
    /// consented `cap` (or the hold's per-block ceiling) and the owner's limit.
    pub(crate) fn debit_call_offer(&self, state: &AppState, charges: Vec<Charge>, call_id: &str, cap: Option<u64>, operation: &crate::handlers::messages::operations::Operation) -> Result<Debit, ApiError> {
        self.refuse_call_block_only()?;
        let Meter::Grant { client_id, epoch } = &self.meter else { return Ok(Debit::unmetered()); };
        let service = state.pairing.as_ref().ok_or(ApiError::BudgetExceeded(BudgetRefusal::NoGrant))?;
        let reservation = service.reserve_call_offer_spend(client_id, *epoch, charges, call_id, cap, operation.reservation_link(false))
            .map_err(ApiError::BudgetExceeded)?;
        Ok(Debit::reserved(Arc::clone(service), reservation))
    }

    /// Debit a call's charges before anything is dispatched.
    ///
    /// Returns a [`Debit`] the handler resolves once each outcome is known.
    /// Zero amounts retain their recipient so resolution still consumes the reservation.
    pub fn debit(&self, state: &AppState, charges: Vec<Charge>) -> Result<Debit, ApiError> {
        self.debit_purpose(state, charges, false)
    }

    /// An identified payment may enter the backend only once per grant.
    pub(crate) fn debit_payment(
        &self,
        state: &AppState,
        charges: Vec<Charge>,
        payment_hash: Option<&str>,
        request_id: Option<&str>,
    ) -> Result<Debit, ApiError> {
        let mut ids = Vec::new();
        if let Some(id) = request_id {
            if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(ApiError::BadRequest(
                    "request_id must be 1–128 printable ASCII bytes without spaces".into(),
                ));
            }
            ids.push(format!("request:{id}"));
        }
        if let Some(hash) = payment_hash {
            ids.push(format!("hash:{hash}"));
        }
        self.refuse_call_block_only()?;
        let Meter::Grant { client_id, epoch } = &self.meter else {
            return Ok(Debit::unmetered());
        };
        let service = state
            .pairing
            .as_ref()
            .ok_or(ApiError::BudgetExceeded(BudgetRefusal::NoGrant))?;
        let reservation = service
            .reserve_payment(client_id, *epoch, charges, ids)
            .map_err(ApiError::BudgetExceeded)?;
        Ok(Debit::reserved(Arc::clone(service), reservation))
    }

    /// Link an operation's durable journal before committing its G1 debit.
    /// The callback is synchronous and cannot call the pairing service.
    pub(crate) fn debit_linked(
        &self, state: &AppState, charges: Vec<Charge>,
        persist_link: impl FnOnce(Option<&Reservation>) -> Result<(), BudgetRefusal>,
    ) -> Result<Debit, ApiError> {
        self.refuse_call_block_only()?;
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
        self.refuse_call_block_only()?;
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

/// Authority for `POST /api/v1/messages/compose`, and only there: a
/// [`MeteredSpend`] as on every other paid route, or, with live-call
/// continuity on, a paired caller whose token has no `spend` because its
/// grant ended by expiry. That caller may pay only the next minute block of
/// the one call it owns, or that call's one hangup, from that call's existing
/// hold (see [`ComposeSpend::for_request`]); every other request gets the
/// refusal [`MeteredSpend`] gave.
pub(crate) enum ComposeSpend {
    Metered(MeteredSpend),
    CallBlockOnly { user: AuthUser, refusal: Response },
}

#[axum::async_trait]
impl FromRequestParts<Arc<AppState>> for ComposeSpend {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let refusal = match MeteredSpend::from_request_parts(parts, state).await {
            Ok(auth) => return Ok(Self::Metered(auth)),
            Err(refusal) => refusal,
        };
        if !state.pairing.as_ref().is_some_and(|service| service.call_continuity_enabled()) {
            return Err(refusal);
        }
        match AuthUser::from_request_parts(parts, state).await {
            Ok(user) if user.pairing.is_some() && !user.has(Scope::Spend) => Ok(Self::CallBlockOnly { user, refusal }),
            _ => Err(refusal),
        }
    }
}

impl ComposeSpend {
    /// The authority for this request. A caller without `spend` passes only
    /// for a 1:1 minute block (kind 404), or a plain hangup (kind 403 with no
    /// reason or `hangup`), of a call its pairing owns (the binding that
    /// placed it, same epoch and identity) while that call's hold is still
    /// funded (`PairingService::call_hold_live`). A block is then drawn on
    /// that hold alone, at its pinned price, fee, minute limit and amount. A
    /// hangup is drawn on the closing reserve the hold set aside for it at
    /// admission, as the node's own closing notice would be: at most that
    /// reserve, at most once per call. Anything else gets the original refusal.
    pub(crate) fn for_request(self, state: &AppState, req: &crate::handlers::messages::ComposeRequest)
        -> Result<MeteredSpend, Box<Response>> {
        use konsensus_core::kind::{KIND_CALL_BLOCK, KIND_CALL_HANGUP};
        use konsensus_core::payloads::call::{CallSignal, HangupReason};
        let (user, refusal) = match self {
            Self::Metered(auth) => return Ok(auth),
            Self::CallBlockOnly { user, refusal } => (user, refusal),
        };
        let allowed = (|| {
            if !matches!(req.kind, KIND_CALL_BLOCK | KIND_CALL_HANGUP) || req.is_room {
                return None;
            }
            let peer = konsensus_core::NodeId::from_hex(&req.recipient).ok()?.to_hex();
            let signal = CallSignal::parse(req.kind, &req.plaintext).ok()?;
            if req.kind == KIND_CALL_HANGUP && !matches!(signal.reason, None | Some(HangupReason::Hangup)) {
                return None;
            }
            let binding = user.pairing.as_ref()?;
            let service = state.pairing.as_ref()?;
            if !(service.call_hold_live(binding, &peer, &signal.call_id)
                && service.owns_call_media(binding, &peer, &signal.call_id)) {
                return None;
            }
            if req.kind == KIND_CALL_HANGUP {
                // The grant that holds this call now; its closing reserve
                // pays the hangup, bounded as the node's own closing notice.
                //
                // Its price is not pinned here. The hangup pays the callee's
                // hangup quote as read once when this request starts (the
                // background quote loop's latest), and the payment is for
                // exactly that amount. The draw refuses it, routing ceiling
                // included, above the closing reserve pinned at admission
                // or above the grant's per-payment limit for a call signal
                // (`draw_call_spend_for_grant`). A quote that rose past the
                // reserve is refused unpaid; the reserve, not the quote,
                // bounds what this hangup can cost. One signal per call is
                // in flight at a time, and the closing sequence draws once.
                let grant_op_id = service.call_spend_grant(&peer, &signal.call_id)?;
                return Some(Meter::CallClosing { grant_op_id: Some(grant_op_id), peer, call_id: signal.call_id });
            }
            Some(Meter::CallBlock {
                client_id: binding.client_id.clone(), epoch: binding.epoch, peer, call_id: signal.call_id,
            })
        })();
        match allowed {
            Some(meter) => Ok(MeteredSpend { user, meter }),
            None => Err(Box::new(refusal)),
        }
    }
}

/// A reservation against a grant, waiting for its outcomes.
///
/// Dropping it without resolving keeps every charge reserved: that is the
/// "unknown" outcome, and the right answer when a handler is cancelled
/// mid-payment. Resolve explicitly to release or settle.
#[must_use = "resolve each charge once its outcome is known; dropping keeps it reserved"]
pub struct Debit {
    operation: Option<crate::handlers::messages::operations::Operation>,
    held: Option<(Arc<PairingService>, Reservation)>,
    max_routing_fee_msat: Option<u64>,
    /// The zero routing ceiling was pinned because the payee is a direct
    /// channel peer: every payment under it must fit that channel.
    direct: bool,
    call_block: Option<(konsensus_core::NodeId, String)>,
    call_offer: Option<(konsensus_core::NodeId, String)>,
    call_spend: Option<(String, String)>,
    /// A paid call signal: rechecked against the grant on every guarded poll.
    call_payment: Option<crate::spend_budget::CallPayment>,
    // None means a settled payment's fee is still unknown. Never release that liability.
    fees: std::sync::Mutex<std::collections::BTreeMap<String, Option<u64>>>,
    // Shared by every member of a room fan-out. Reservations consume this
    // call's allowance even when a sibling finishes before another starts.
    call_reserved_msat: std::sync::Mutex<u64>,
}

impl Debit {
    pub(crate) fn with_operation(mut self, operation: crate::handlers::messages::operations::Operation) -> Self {
        self.operation = Some(operation); self
    }
    pub(crate) fn operation(&self) -> Option<&crate::handlers::messages::operations::Operation> { self.operation.as_ref() }
    pub(crate) fn for_call_block(mut self, peer: konsensus_core::NodeId, plaintext: String) -> Self {
        self.call_spend = konsensus_core::wire_json::from_str::<konsensus_core::payloads::call::CallSignal>(&plaintext)
            .ok().map(|signal| (peer.to_hex(), signal.call_id));
        self.call_block = Some((peer, plaintext));
        self
    }

    pub(crate) fn is_call_block(&self) -> bool { self.call_block.is_some() }

    /// Mark a paid call signal of `kind` (400 to 404), whether or not it
    /// draws on a hold; any other kind is left unmarked.
    pub(crate) fn for_call_payment(mut self, kind: u16) -> Self {
        self.call_payment = crate::spend_budget::CallPayment::of_kind(kind);
        self
    }

    pub(crate) fn for_call_offer(mut self, peer: konsensus_core::NodeId, plaintext: String) -> Self {
        self.call_spend = konsensus_core::wire_json::from_str::<konsensus_core::payloads::call::CallSignal>(&plaintext)
            .ok().map(|signal| (peer.to_hex(), signal.call_id));
        self.call_offer = Some((peer, plaintext));
        self
    }

    /// Call blocks name their call and sequence; other messages name their
    /// kind so the recipient can price the invoice locally (#403).
    pub(crate) fn invoice_purpose(&self, kind: Option<u16>) -> String {
        self.call_block.as_ref().and_then(|(_, plaintext)|
            konsensus_core::payloads::call::CallSignal::parse(konsensus_core::kind::KIND_CALL_BLOCK, plaintext).ok()
        ).map(|signal| format!("{}{}:{}", konsensus_core::payloads::call::CALL_BLOCK_INVOICE_PREFIX,
            signal.call_id, signal.seq.unwrap_or_default()))
        .or_else(|| kind.map(konsensus_core::gate::service_invoice_purpose))
        .unwrap_or_else(|| "konsensus message".into())
    }

    pub(crate) async fn dispatch_message<F>(&self, state: &AppState, hash: Option<String>, amount: u64, tip: &crate::error::ObservedTip, future: F) -> Result<F::Output, ApiError>
    where F: Future<Output=Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError>> {
        match &self.operation {
            Some(op) => op.dispatch(self, hash, amount, tip, future).await,
            None => self.dispatch_message_payment(state, tip, future).await,
        }
    }

    /// Called after dispatch intent is durable. Fresh call validation and spend
    /// authority both remain serialized through the first wallet poll.
    pub(crate) async fn dispatch_message_payment<F>(&self, state: &AppState, tip: &crate::error::ObservedTip, future: F) -> Result<F::Output, ApiError>
    where F: Future<Output=Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError>> {
        let (mut call_guard, deadline) = if let Some((peer, plaintext)) = &self.call_block {
            match crate::calls::block_dispatch_guard(state, peer, plaintext).await {
                Ok((guard, deadline)) => (Some(guard), Some(deadline)),
                Err(error) => return Ok(Err(konsensus_core::traits::lightning::LightningError::PaymentNotDispatched(error.to_string()))),
            }
        } else if let Some((peer, plaintext)) = &self.call_offer {
            match crate::calls::offer_dispatch_guard(state.storage.as_ref(), peer, plaintext).await {
                Ok((guard, deadline)) => (Some(guard), Some(deadline)),
                Err(error) => return Ok(Err(konsensus_core::traits::lightning::LightningError::PaymentNotDispatched(error.to_string()))),
            }
        } else { (None, None) };
        // Journal writes and call guards can wait before the wallet is polled.
        // A refusal here proves that this payment was never submitted.
        tip.recheck(state).await?;
        let mut future = std::pin::pin!(future);
        let mut polled = false;
        let guarded = futures::future::poll_fn(|cx| {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64).unwrap_or(u64::MAX);
            // Recheck after journal awaits, immediately before the first wallet
            // poll. Once polled, money may be in flight: preserve reconciliation.
            // The caller observes the answer after the callee committed it.
            // Leave five seconds for that skew and payment/delivery latency.
            if !polled && deadline.is_some_and(|until| now.saturating_add(5_000) > until) {
                return Poll::Ready(Err(konsensus_core::traits::lightning::LightningError::PaymentNotDispatched("call block too close to expiry before payment dispatch".into())));
            }
            polled = true;
            let result = future.as_mut().poll(cx);
            drop(call_guard.take());
            result
        });
        self.dispatch(guarded).await
    }

    pub(crate) fn with_fee_limit(mut self, limit: Option<u64>) -> Self {
        self.max_routing_fee_msat = limit;
        self
    }
    pub(crate) fn with_direct_channel(mut self, direct: bool) -> Self {
        self.direct = direct;
        self
    }
    /// Whether the zero routing ceiling relies on a direct channel.
    pub(crate) fn is_direct(&self) -> bool { self.direct }
    pub(crate) fn fee_limit(&self, state: &AppState, principal: u64) -> u64 {
        state.lightning.routing_fee_policy().ceiling(principal, self.max_routing_fee_msat)
    }
    pub(crate) fn record_payment(&self, recipient: &str, details: &konsensus_core::traits::lightning::PaymentDetails) {
        let mut fees = self.fees.lock().unwrap_or_else(|e| e.into_inner());
        let previous = fees.entry(recipient.to_owned()).or_insert(Some(0));
        *previous = previous.and_then(|total| details.fee_msat.and_then(|fee| total.checked_add(fee)));
    }

    /// Reporting only. No recorded payments, unknown fees, or overflow are not zero.
    pub(crate) fn recorded_fee_paid_msat(&self) -> Option<u64> {
        let fees = self.fees.lock().unwrap_or_else(|e| e.into_inner());
        if fees.is_empty() { return None; }
        fees.values().try_fold(0u64, |sum, fee| sum.checked_add((*fee)?))
    }

    /// Owner-only paths have no grant to revalidate.
    pub(crate) fn unmetered() -> Self {
        Self { operation: None, max_routing_fee_msat: None, direct: false, call_block: None, call_offer: None, call_spend: None, call_payment: None, fees: Default::default(), held: None, call_reserved_msat: std::sync::Mutex::new(0) }
    }

    fn reserved(service: Arc<PairingService>, reservation: Reservation) -> Self {
        let total = reservation.charges.iter().map(|c| c.amount_msat).sum();
        Self { operation: None, max_routing_fee_msat: None, direct: false, call_block: None, call_offer: None, call_spend: None, call_payment: None, fees: Default::default(), held: Some((service, reservation)), call_reserved_msat: std::sync::Mutex::new(total) }
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

    /// Raise the message reservation to `quoted_message_all_in` and reserve
    /// `admission_all_in` before any re-admission payment. Refuses if the grant
    /// cannot cover both; unmetered for the owner's own key.
    pub(crate) fn reserve_quoted_readmission(
        &self,
        recipient: &str,
        quoted_message_all_in: u64,
        admission_all_in: u64,
    ) -> Result<Debit, ApiError> {
        let Some((service, reservation)) = &self.held else {
            return Ok(Debit::unmetered().with_fee_limit(self.max_routing_fee_msat).with_direct_channel(self.direct));
        };
        let mut call_total = self.call_reserved_msat.lock().unwrap_or_else(|e| e.into_inner());
        let (new_total, admission) = service
            .reserve_quoted_readmission(
                reservation,
                recipient,
                quoted_message_all_in,
                admission_all_in,
                *call_total,
                self.operation.as_ref().map(|op| op.reservation_link(true)),
            )
            .map_err(ApiError::BudgetExceeded)?;
        *call_total = new_total; // checked against the grant limit under its ledger lock
        Ok(Debit::reserved(Arc::clone(service), admission).with_fee_limit(self.max_routing_fee_msat).with_direct_channel(self.direct))
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
            match service.with_call_payment_authority(reservation, self.call_spend.as_ref().map(|(peer, id)| (peer.as_str(), id.as_str())), self.call_payment, || {
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
            Poll::Ready(service.with_call_payment_authority(reservation,
                self.call_spend.as_ref().map(|(peer, id)| (peer.as_str(), id.as_str())), self.call_payment,
                || operation.as_mut().poll(cx)))
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
        self.released_with_outcome(recipient, false);
    }

    pub(crate) fn released_with_outcome(&self, recipient: &str, payment_failed: bool) {
        if let Some((service, reservation)) = &self.held {
            if let Err(error) = service.try_resolve_spend_outcome(reservation, recipient, 0, payment_failed) {
                tracing::warn!(%error, "spend release deferred; reservation retained");
            }
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
