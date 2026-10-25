//! Direct Lightning payments: `POST /payments/pay` and `POST /payments/keysend`.
//!
//! Every request carries a client `request_id` (idempotency key). It is
//! recorded in the encrypted operation ledger before the budget is debited or
//! the backend is called (`pay:<id>` / `keysend:<id>` rows of the
//! `channel_open_operations` store, as send-onchain does), so a retry after a
//! timeout, a dropped connection or a restart answers from the record and
//! never dispatches a second payment.
//!
//! Status codes tell the truth about settlement:
//! - `200` with `status: settled` only once the backend reports the payment
//!   settled; the preimage and the actual fee are reported then.
//! - `202` with `status: in_flight` while the outcome is not final: the
//!   payment hash and operation id are returned; repeat the same request to
//!   learn the outcome, or poll `GET /payments/{hash}`.
//! - A failure returns its proper error. A positive backend failure is bound
//!   to the `request_id` and repeated on retry; a refusal before dispatch
//!   frees the id.
//!
//! Recovery only reads: a later request under the same id re-reads the
//! backend by payment hash and finalizes the record from what it reports.
//! Elapsed time or a missing backend record never counts as non-dispatch.

use super::fee_paid_msat;
use crate::handlers::messages::{SettlementPoll, SettlementUpdates};
use crate::{error::ApiError, metered::Debit, state::AppState};
use axum::{http::StatusCode, Json};
use konsensus_core::traits::lightning::{
    LightningError, PaymentDetails, PaymentDirection, PaymentStatus,
};
use konsensus_storage::{
    channel_open::{CHANNEL_OPEN_OPENED, CHANNEL_OPEN_PENDING, CHANNEL_OPEN_UNCERTAIN},
    ChannelOpenOperation,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{future::Future, sync::Arc, time::Duration};

pub(super) type Response = Result<(StatusCode, Json<Value>), ApiError>;

/// Advertised in `/api/v1/status` `api_capabilities`: `request_id` is
/// required and `202 in_flight` / `200 settled` carry settlement truth.
pub const CAPABILITY: &str = "direct_payment_operations_v1";

/// `status` once the backend reports the payment settled.
pub const STATUS_SETTLED: &str = "settled";
/// `status` while the outcome is not final (dispatched, pending, or unrecorded).
pub const STATUS_IN_FLIGHT: &str = "in_flight";

/// How long a dispatched payment is given to settle before the route answers
/// `202 in_flight`. A routed HTLC settles in a few hundred milliseconds on a
/// warm node; a longer wait would only block the client, never change truth.
const SETTLE_WAIT: Duration = Duration::from_secs(3);

const IN_FLIGHT_MESSAGE: &str = "Not settled yet. Repeat this request with the same request_id to learn the outcome, or poll GET /api/v1/payments/{payment_hash}. Nothing is dispatched again under this request_id.";

/// The response of both direct payment routes. The pre-existing fields keep
/// their names and types; `status`, `request_id`, `operation_id` and
/// `replayed` are additions.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DirectPaymentResponse {
    /// `settled` or `in_flight` (a failure is an error response).
    pub status: String,
    /// The client's idempotency key, echoed.
    pub request_id: String,
    /// The durable operation this request is bound to (`pay:<id>` / `keysend:<id>`).
    pub operation_id: String,
    /// Answered from the record of an earlier request; nothing was dispatched.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub replayed: bool,
    pub max_routing_fee_msat: u64,
    /// Actual settled LDK routing fee, including a proven zero; never the ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_paid_msat: Option<u64>,
    /// Payment hash (hex); empty only while a keysend has not reported one.
    pub payment_hash: String,
    /// Amount in millisatoshis.
    pub amount_msat: u64,
    /// Payment preimage (hex proof of payment); empty until settled.
    pub preimage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// What the ledger stores for a request id once the backend has answered.
#[derive(Serialize, Deserialize)]
enum Receipt {
    /// `opened`: final, replayed verbatim.
    Settled(DirectPaymentResponse),
    /// `uncertain`: dispatched with a hash; the backend decides on replay.
    InFlight(DirectPaymentResponse),
    /// `opened`: a positive backend failure, repeated on replay.
    Failed {
        error: String,
        max_routing_fee_msat: u64,
    },
}

/// Everything a route knows about one payment before it is dispatched.
pub(super) struct Dispatch {
    /// Canonical parameters the `request_id` binds; a change is `409 operation_mismatch`.
    pub fingerprint: Value,
    /// Known before dispatch for an invoice; a keysend learns it from the backend.
    pub payment_hash: Option<String>,
    pub amount_msat: u64,
    pub max_routing_fee_msat: u64,
    /// Budget key the debit is resolved against.
    pub recipient: String,
}

struct Ident {
    route: &'static str,
    request_id: String,
    key: String,
}

fn storage(error: impl std::fmt::Display) -> ApiError {
    tracing::warn!(%error, "direct payment operation storage failure");
    ApiError::Storage("payment operation unavailable".into())
}

/// Validate the client's idempotency key. Missing is a 400 with the remedy.
pub(super) fn required_request_id(id: Option<&str>) -> Result<String, ApiError> {
    let Some(id) = id else {
        return Err(ApiError::BadRequest(
            "request_id is required: send a client-generated idempotency key (1–128 printable \
             ASCII bytes, no spaces) and repeat it unchanged on every retry of this payment; \
             nothing was paid"
                .into(),
        ));
    };
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ApiError::BadRequest(
            "request_id must be 1–128 printable ASCII bytes without spaces".into(),
        ));
    }
    Ok(id.to_owned())
}

fn failure_text(route: &str) -> String {
    match route {
        "pay" => "invoice payment failed before settlement".into(),
        _ => format!("{route} payment failed before settlement"),
    }
}

fn is_terminal(details: &PaymentDetails) -> bool {
    matches!(
        details.status,
        PaymentStatus::Settled | PaymentStatus::Failed | PaymentStatus::Expired
    )
}

impl DirectPaymentResponse {
    fn in_flight(ident: &Ident, op: &Dispatch) -> Self {
        Self {
            status: STATUS_IN_FLIGHT.into(),
            request_id: ident.request_id.clone(),
            operation_id: ident.key.clone(),
            replayed: false,
            max_routing_fee_msat: op.max_routing_fee_msat,
            fee_paid_msat: None,
            payment_hash: op.payment_hash.clone().unwrap_or_default(),
            amount_msat: op.amount_msat,
            preimage: String::new(),
            message: Some(IN_FLIGHT_MESSAGE.into()),
        }
    }

    /// Never reports a preimage or a fee before the backend says settled.
    fn from_details(backend: &str, mut template: Self, details: &PaymentDetails) -> Self {
        let settled = details.status == PaymentStatus::Settled;
        if !details.payment_hash.is_empty() {
            template.payment_hash = details.payment_hash.clone();
        }
        template.amount_msat = details.amount_msat;
        template.fee_paid_msat = fee_paid_msat(backend, details);
        template.preimage = if settled {
            details.preimage.clone().unwrap_or_default()
        } else {
            String::new()
        };
        template.status = if settled {
            STATUS_SETTLED
        } else {
            STATUS_IN_FLIGHT
        }
        .into();
        template.message = (!settled).then(|| IN_FLIGHT_MESSAGE.into());
        template
    }
}

fn view(mut body: DirectPaymentResponse, replayed: bool) -> Result<Value, ApiError> {
    body.replayed = replayed;
    serde_json::to_value(body).map_err(storage)
}

/// Run one direct payment under its `request_id`.
///
/// `prepare` parses and validates the request (its errors are the route's
/// ordinary 400s); `debit` reserves a metered caller's budget; `send` builds
/// the backend call. Only the durable insert winner reaches `debit` and `send`.
pub(super) async fn run<Fut>(
    state: &Arc<AppState>,
    route: &'static str,
    request_id: String,
    prepare: impl FnOnce() -> Result<Dispatch, ApiError>,
    debit: impl FnOnce(&Dispatch) -> Result<Option<Debit>, ApiError>,
    send: impl FnOnce(&Dispatch) -> Fut,
) -> Response
where
    Fut: Future<Output = Result<PaymentDetails, LightningError>>,
{
    let ident = Ident {
        route,
        key: format!("{route}:{request_id}"),
        request_id,
    };
    // Saved receipts answer even while the wallet is not money-ready.
    let existing = state
        .storage
        .get_channel_open_operation(&ident.key)
        .await
        .map_err(storage)?;
    if existing.is_none() {
        crate::error::require_money_ready(state).await?;
    }
    let op = prepare()?;
    let request = serde_json::to_vec(&op.fingerprint).map_err(storage)?;
    let hash = hex::encode(Sha256::digest(&request));
    if let Some(row) = existing {
        return replay(state, row, &ident, &op, &hash).await;
    }
    let pending = ChannelOpenOperation::pending(ident.key.clone(), hash.clone(), request);
    if !state
        .storage
        .insert_channel_open_operation(&pending)
        .await
        .map_err(storage)?
    {
        let row = state
            .storage
            .get_channel_open_operation(&ident.key)
            .await
            .map_err(storage)?
            .ok_or_else(|| storage("missing operation after duplicate insert"))?;
        return replay(state, row, &ident, &op, &hash).await;
    }
    let cap = op.max_routing_fee_msat;
    // Only the durable insert winner reaches the budget and the backend. A
    // refusal before dispatch frees the id; anything after may have paid.
    let debit = match debit(&op) {
        Ok(debit) => debit,
        Err(error) => {
            release(state, &ident.key).await;
            return Err(error.with_routing_fee(cap));
        }
    };
    let unmetered = Debit::unmetered();
    let guard = debit.as_ref().unwrap_or(&unmetered);
    // Subscribed before dispatch so a hint emitted during the call is kept.
    let updates = SettlementUpdates::subscribe(state.lightning.as_ref());
    match guard.dispatch(send(&op)).await {
        Err(error @ ApiError::BudgetExceeded(_)) => {
            // Authority was lost before the backend was polled: nothing moved.
            guard.released(&op.recipient);
            release(state, &ident.key).await;
            Err(error.with_routing_fee(cap))
        }
        Err(error) => {
            // Polled, then lost authority: the backend may have sent. Unknown.
            record(
                state,
                &ident.key,
                CHANNEL_OPEN_PENDING,
                CHANNEL_OPEN_UNCERTAIN,
                None,
                Some(error.to_string()),
            )
            .await;
            Err(error.with_routing_fee(cap))
        }
        Ok(Err(error @ (LightningError::PaymentNotDispatched(_) | LightningError::NotReady))) => {
            guard.released(&op.recipient);
            release(state, &ident.key).await;
            Err(ApiError::from(error).with_routing_fee(cap))
        }
        Ok(Err(error)) => {
            let error = ApiError::from(error);
            tracing::warn!(operation_id = %ident.key, %error, "direct payment outcome uncertain; a retry will not dispatch");
            record(
                state,
                &ident.key,
                CHANNEL_OPEN_PENDING,
                CHANNEL_OPEN_UNCERTAIN,
                None,
                Some(error.to_string()),
            )
            .await;
            Err(error.with_routing_fee(cap))
        }
        Ok(Ok(details)) => {
            let details = settle_briefly(state, updates, details).await;
            super::resolve_payment(guard, &op.recipient, &Ok(details.clone()));
            conclude(state, &ident, &op, CHANNEL_OPEN_PENDING, details, false).await
        }
    }
}

/// Answer a request whose id is already recorded, without dispatching.
async fn replay(
    state: &Arc<AppState>,
    row: ChannelOpenOperation,
    ident: &Ident,
    op: &Dispatch,
    hash: &str,
) -> Response {
    if row.request_hash != hash {
        return Err(ApiError::OperationConflict("operation_mismatch"));
    }
    let receipt = row
        .result
        .as_deref()
        .map(serde_json::from_slice::<Receipt>)
        .transpose()
        .map_err(storage)?;
    let template = match (row.state.as_str(), receipt) {
        (CHANNEL_OPEN_OPENED, Some(Receipt::Settled(body))) => {
            return Ok((StatusCode::OK, Json(view(body, true)?)));
        }
        (
            CHANNEL_OPEN_OPENED,
            Some(Receipt::Failed {
                error,
                max_routing_fee_msat,
            }),
        ) => return Err(ApiError::Lightning(error).with_routing_fee(max_routing_fee_msat)),
        (CHANNEL_OPEN_OPENED, _) => return Err(storage("unreadable final payment receipt")),
        // Dispatched with a hash, or pending/ambiguous: the backend decides.
        (_, Some(Receipt::InFlight(body))) => body,
        (_, _) => DirectPaymentResponse::in_flight(ident, op),
    };
    if !template.payment_hash.is_empty() {
        if let Some(details) = terminal_outgoing(state, &template.payment_hash).await {
            return conclude(state, ident, op, &row.state, details, true).await;
        }
    }
    let mut body = template;
    body.status = STATUS_IN_FLIGHT.into();
    body.message = Some(IN_FLIGHT_MESSAGE.into());
    let mut value = view(body, true)?;
    if let Some(error) = row.last_error {
        value["last_error"] = error.into();
    }
    Ok((StatusCode::ACCEPTED, Json(value)))
}

/// Report `details` and record it. `from` is the row's current state:
/// `pending` after a fresh dispatch, `uncertain` when a replay found truth.
async fn conclude(
    state: &Arc<AppState>,
    ident: &Ident,
    op: &Dispatch,
    from: &str,
    details: PaymentDetails,
    replayed: bool,
) -> Response {
    let body = DirectPaymentResponse::from_details(
        &state.lightning_backend,
        DirectPaymentResponse::in_flight(ident, op),
        &details,
    );
    match details.status {
        PaymentStatus::Settled => {
            let receipt = serde_json::to_vec(&Receipt::Settled(body.clone())).map_err(storage)?;
            record(
                state,
                &ident.key,
                from,
                CHANNEL_OPEN_OPENED,
                Some(receipt),
                None,
            )
            .await;
            Ok((StatusCode::OK, Json(view(body, replayed)?)))
        }
        PaymentStatus::Failed | PaymentStatus::Expired => {
            let error = failure_text(ident.route);
            let receipt = serde_json::to_vec(&Receipt::Failed {
                error: error.clone(),
                max_routing_fee_msat: op.max_routing_fee_msat,
            })
            .map_err(storage)?;
            record(
                state,
                &ident.key,
                from,
                CHANNEL_OPEN_OPENED,
                Some(receipt),
                Some(error.clone()),
            )
            .await;
            Err(ApiError::Lightning(error).with_routing_fee(op.max_routing_fee_msat))
        }
        PaymentStatus::Pending | PaymentStatus::InFlight => {
            if from == CHANNEL_OPEN_PENDING {
                let receipt =
                    serde_json::to_vec(&Receipt::InFlight(body.clone())).map_err(storage)?;
                record(
                    state,
                    &ident.key,
                    from,
                    CHANNEL_OPEN_UNCERTAIN,
                    Some(receipt),
                    None,
                )
                .await;
            }
            Ok((StatusCode::ACCEPTED, Json(view(body, replayed)?)))
        }
    }
}

/// Give a dispatched payment a short window to settle. Returns the latest
/// outgoing status the backend reported; never invents one.
async fn settle_briefly(
    state: &AppState,
    updates: SettlementUpdates,
    initial: PaymentDetails,
) -> PaymentDetails {
    if is_terminal(&initial) || initial.payment_hash.is_empty() {
        return initial;
    }
    let mut poll = SettlementPoll::new(updates, &initial.payment_hash).with_deadline(SETTLE_WAIT);
    let mut latest = initial;
    loop {
        poll.wait().await;
        if let Ok(details) = state
            .lightning
            .get_payment_status(&latest.payment_hash)
            .await
        {
            if details.direction == PaymentDirection::Outgoing {
                latest = details;
            }
        }
        if is_terminal(&latest) || poll.timed_out() {
            return latest;
        }
    }
}

/// The backend's final word on an outgoing payment, if it has one. An
/// incoming record under the same hash (a self-payment's invoice, or someone
/// else paying it) is not proof that this payment settled.
async fn terminal_outgoing(state: &AppState, payment_hash: &str) -> Option<PaymentDetails> {
    let details = state
        .lightning
        .get_payment_status(payment_hash)
        .await
        .ok()?;
    (details.direction == PaymentDirection::Outgoing && is_terminal(&details)).then_some(details)
}

/// Free an id after a proven non-dispatch. Not retried: after an ambiguous
/// acknowledgement another request may already own a new pending row.
async fn release(state: &AppState, key: &str) {
    if let Err(error) = state
        .storage
        .delete_pending_channel_open_operation(key)
        .await
    {
        tracing::warn!(operation_id = %key, %error, "direct payment refusal not released");
    }
}

/// Record an outcome: `pending → to` (fresh dispatch) or `uncertain → opened`
/// (a replay found the backend's final word). Retried off the request's
/// lifetime on storage errors; a lost CAS never overwrites a final receipt.
async fn record(
    state: &Arc<AppState>,
    key: &str,
    from: &str,
    to: &'static str,
    receipt: Option<Vec<u8>>,
    last_error: Option<String>,
) {
    let from_pending = from == CHANNEL_OPEN_PENDING;
    if write(
        state,
        key,
        from_pending,
        to,
        receipt.as_deref(),
        last_error.as_deref(),
    )
    .await
    {
        return;
    }
    let state = Arc::clone(state);
    let key = key.to_owned();
    tokio::spawn(async move {
        for delay_ms in [100, 500, 1_000, 5_000, 30_000] {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            if write(
                &state,
                &key,
                from_pending,
                to,
                receipt.as_deref(),
                last_error.as_deref(),
            )
            .await
            {
                return;
            }
        }
        tracing::error!(operation_id = %key, "direct payment outcome persistence retries exhausted; the backend record stays the truth");
    });
}

// True means no further write is needed.
async fn write(
    state: &AppState,
    key: &str,
    from_pending: bool,
    to: &str,
    receipt: Option<&[u8]>,
    last_error: Option<&str>,
) -> bool {
    let result = if from_pending {
        state
            .storage
            .resolve_channel_open_operation(key, to, receipt, last_error)
            .await
    } else {
        match receipt {
            Some(receipt) => {
                state
                    .storage
                    .finalize_channel_open_operation(key, receipt, last_error)
                    .await
            }
            None => return true,
        }
    };
    match result {
        Ok(true) => true,
        Ok(false) => {
            tracing::warn!(operation_id = %key, "direct payment operation changed before outcome recording");
            true
        }
        Err(error) => {
            tracing::warn!(operation_id = %key, %error, "direct payment outcome not recorded; retrying persistence");
            false
        }
    }
}
