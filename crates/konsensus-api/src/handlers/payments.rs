//! Payment endpoints — Lightning invoices, balances, status.

use crate::auth::scoped::{Read, Receive, ScopedAuth, Spend};
use crate::metered::{Debit, MeteredSpend};
use crate::spend_budget::Charge;
use std::sync::Arc;
use std::time::SystemTime;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use konsensus_core::fee_rate::validate_fee_rate_sat_per_vb;
use konsensus_core::traits::lightning::{LightningError, WalletBalanceBreakdown};

use crate::error::ApiError;
use crate::freshness::DataFreshness;
use crate::state::AppState;

/// Reporting only: LDK's converted PaymentDetails carry the actual routing fee.
/// Never infer settlement from a fee, a preimage, or the authorized ceiling.
pub(crate) fn fee_paid_msat(
    backend: &str,
    details: &konsensus_core::traits::lightning::PaymentDetails,
) -> Option<u64> {
    use konsensus_core::traits::lightning::{PaymentDirection, PaymentStatus};
    if backend == "ldk"
        && details.status == PaymentStatus::Settled
        && details.direction == PaymentDirection::Outgoing
    {
        details.fee_msat
    } else {
        None
    }
}

/// Request to create a Lightning invoice.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInvoiceRequest {
    /// Amount in millisatoshis.
    pub amount_msat: u64,
    /// Invoice description / memo.
    #[serde(default = "default_memo")]
    pub description: String,
    /// Expiry in seconds.
    #[serde(default = "default_expiry")]
    pub expiry_secs: u32,
}

fn default_memo() -> String {
    "konsensus payment".into()
}

fn default_expiry() -> u32 {
    3600
}

/// Invoice response.
#[derive(Serialize)]
pub struct InvoiceResponse {
    /// BOLT11 payment request string.
    pub bolt11: String,
    /// Payment hash (hex).
    pub payment_hash: String,
}

/// Payment status response.
#[derive(Serialize)]
pub struct PaymentStatusResponse {
    /// Actual settled outgoing LDK routing fee; omitted when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_paid_msat: Option<u64>,
    /// Payment hash (hex).
    pub payment_hash: String,
    /// Status: "pending", "settled", "failed", "expired".
    pub status: String,
    /// Amount in millisatoshis.
    pub amount_msat: u64,
    /// Direction: "incoming" or "outgoing".
    pub direction: String,
    /// Actual JIT funding fee/net only after settlement; never a message proof.
    pub liquidity: Option<konsensus_core::traits::liquidity::LiquidityReceipt>,
}

/// Balance response.
#[derive(Serialize)]
pub struct BalanceResponse {
    /// Legacy provider aggregate in millisatoshis, unchanged for compatibility.
    /// LDK includes claimable Lightning funds plus spendable on-chain funds;
    /// this is not a spendable Lightning balance.
    pub balance_msat: u64,
    /// Known wallet categories in sats, flattened into the response. Unknown
    /// categories are omitted; confirmed zeroes are included.
    #[serde(flatten)]
    pub breakdown: WalletBalanceBreakdown,
}

/// Price check response.
#[derive(Serialize)]
pub struct PriceResponse {
    /// Message kind.
    pub kind: u16,
    /// Required price in millisatoshis.
    pub price_msat: u64,
}

/// Maximum invoice description length in bytes (BOLT11 limit).
const MAX_INVOICE_DESCRIPTION_LEN: usize = 639;

/// Maximum invoice expiry in seconds (7 days).
const MAX_INVOICE_EXPIRY_SECS: u32 = 7 * 24 * 3600;

/// Maximum invoice amount (1 BTC in millisatoshis).
const MAX_INVOICE_AMOUNT_MSAT: u64 = 100_000_000_000;

/// `POST /api/v1/payments/invoice` — create a Lightning invoice.
async fn create_invoice(
    _auth: ScopedAuth<Receive>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateInvoiceRequest>,
) -> Result<Json<InvoiceResponse>, ApiError> {
    crate::error::require_money_ready(&state).await?;
    if req.description.len() > MAX_INVOICE_DESCRIPTION_LEN {
        return Err(ApiError::BadRequest(format!(
            "description too long: {} bytes (max {MAX_INVOICE_DESCRIPTION_LEN})",
            req.description.len()
        )));
    }
    // Reject control characters (null bytes, etc.) that could confuse
    // downstream Lightning wallet implementations parsing BOLT11 strings.
    if req.description.chars().any(|c| c.is_control() && c != '\n') {
        return Err(ApiError::BadRequest(
            "description contains invalid control characters".into(),
        ));
    }
    if req.expiry_secs > MAX_INVOICE_EXPIRY_SECS {
        return Err(ApiError::BadRequest(format!(
            "expiry too large: {}s (max {MAX_INVOICE_EXPIRY_SECS}s)",
            req.expiry_secs
        )));
    }
    if req.amount_msat == 0 {
        return Err(ApiError::BadRequest(
            "amount must be greater than zero".into(),
        ));
    }
    if req.amount_msat > MAX_INVOICE_AMOUNT_MSAT {
        return Err(ApiError::BadRequest(format!(
            "amount too large: {} msat (max {MAX_INVOICE_AMOUNT_MSAT} msat)",
            req.amount_msat
        )));
    }

    let invoice = state
        .lightning
        .create_invoice(req.amount_msat, &req.description, req.expiry_secs)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(InvoiceResponse {
        bolt11: invoice.bolt11,
        payment_hash: invoice.payment_hash,
    }))
}

/// `GET /api/v1/payments/:hash` — check payment status.
async fn payment_status(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> Result<Json<PaymentStatusResponse>, ApiError> {
    let details = state
        .lightning
        .get_payment_status(&hash)
        .await
        .map_err(ApiError::from)?;

    let liquidity = state
        .lightning
        .liquidity_receipt(&hash)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(PaymentStatusResponse {
        fee_paid_msat: fee_paid_msat(&state.lightning_backend, &details),
        liquidity,
        payment_hash: details.payment_hash,
        status: format!("{:?}", details.status),
        amount_msat: details.amount_msat,
        direction: format!("{:?}", details.direction),
    }))
}

/// `GET /api/v1/payments/balance` — get wallet balance and known categories.
///
/// Carries `BitSov-Data-As-Of` / `BitSov-Data-Stale` from the wallet's sync
/// status (see [`crate::freshness`]).
async fn get_balance(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Result<(DataFreshness, Json<BalanceResponse>), ApiError> {
    // Sync status before the read: the figures are at least this current.
    let read_at = SystemTime::now();
    let sync = state.lightning.wallet_sync().await;
    let balance = state
        .lightning
        .get_balance_msat()
        .await
        .map_err(ApiError::from)?;

    let breakdown = state
        .lightning
        .get_balance_breakdown()
        .await
        .map_err(ApiError::from)?;

    Ok((
        DataFreshness::from_wallet_sync(sync, read_at),
        Json(BalanceResponse {
            balance_msat: balance,
            breakdown,
        }),
    ))
}

/// Request to pay a BOLT11 invoice.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayInvoiceRequest {
    /// Optional retry identity, consumed once within the current grant.
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub max_routing_fee_msat: Option<u64>,
    /// BOLT11 payment request string.
    pub bolt11: String,
}

/// Response after paying an invoice.
#[derive(Serialize)]
pub struct PayInvoiceResponse {
    pub max_routing_fee_msat: u64,
    /// Actual settled LDK routing fee, including a proven zero; never the ceiling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_paid_msat: Option<u64>,
    /// Payment hash (hex).
    pub payment_hash: String,
    /// Amount paid in millisatoshis.
    pub amount_msat: u64,
    /// Payment preimage (hex proof of payment).
    pub preimage: String,
}

/// Maximum BOLT11 invoice string length (generous upper bound).
const MAX_BOLT11_LEN: usize = 2048;

/// `POST /api/v1/payments/pay` — pay a BOLT11 invoice.
async fn pay_invoice(
    auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    Json(req): Json<PayInvoiceRequest>,
) -> Result<Json<PayInvoiceResponse>, ApiError> {
    crate::error::require_money_ready(&state).await?;
    if req.bolt11.is_empty() {
        return Err(ApiError::BadRequest(
            "bolt11 invoice string is required".into(),
        ));
    }
    if req.bolt11.len() > MAX_BOLT11_LEN {
        return Err(ApiError::BadRequest(format!(
            "bolt11 string too long: {} bytes (max {MAX_BOLT11_LEN})",
            req.bolt11.len()
        )));
    }

    let (principal, _) = invoice_terms(&req.bolt11).map_err(|error| {
        if !auth.is_metered() && matches!(error, ApiError::BudgetExceeded(_)) {
            ApiError::BadRequest(
                "amountless invoices are not supported; request an invoice with an amount".into(),
            )
        } else {
            error
        }
    })?;
    let max_routing_fee_msat = state
        .lightning
        .routing_fee_policy()
        .ceiling(principal, req.max_routing_fee_msat);
    // G1: a metered caller's debit needs the amount and payee before paying.
    let debit = if auth.is_metered() {
        let (amount_msat, payee) = invoice_terms(&req.bolt11)?;
        let payment_hash = req
            .bolt11
            .trim()
            .parse::<lightning_invoice::Bolt11Invoice>()
            .map_err(|e| ApiError::BadRequest(format!("invalid bolt11 invoice: {e}")))?
            .payment_hash()
            .to_string();
        Some((
            auth.debit_payment(
                &state,
                vec![Charge {
                    recipient: payee.clone(),
                    amount_msat: amount_msat
                        .checked_add(max_routing_fee_msat)
                        .ok_or_else(|| ApiError::BadRequest("payment debit overflow".into()))?,
                }],
                Some(&payment_hash),
                req.request_id.as_deref(),
            )
            .map_err(|e| e.with_routing_fee(max_routing_fee_msat))?,
            payee,
        ))
    } else {
        None
    };

    let unmetered = Debit::unmetered();
    let guard = debit.as_ref().map(|(debit, _)| debit).unwrap_or(&unmetered);
    let paid = guard
        .dispatch(
            state
                .lightning
                .pay_invoice_with_fee_limit(&req.bolt11, max_routing_fee_msat),
        )
        .await
        .map_err(|e| e.with_routing_fee(max_routing_fee_msat))?;
    if let Some((debit, payee)) = &debit {
        resolve_payment(debit, payee, &paid);
    }
    let details = paid.map_err(|e| ApiError::from(e).with_routing_fee(max_routing_fee_msat))?;

    if matches!(
        details.status,
        konsensus_core::traits::lightning::PaymentStatus::Failed
            | konsensus_core::traits::lightning::PaymentStatus::Expired
    ) {
        return Err(
            ApiError::Lightning("invoice payment failed before settlement".into())
                .with_routing_fee(max_routing_fee_msat),
        );
    }
    let fee_paid_msat = fee_paid_msat(&state.lightning_backend, &details);
    let preimage = details.preimage.unwrap_or_else(|| {
        tracing::debug!(payment_hash = %details.payment_hash, "payment pending; no preimage available yet");
        String::new()
    });

    Ok(Json(PayInvoiceResponse {
        max_routing_fee_msat,
        fee_paid_msat,
        payment_hash: details.payment_hash,
        amount_msat: details.amount_msat,
        preimage,
    }))
}

/// Request to send a keysend (spontaneous) payment.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysendRequest {
    /// Optional retry identity, consumed once within the current grant.
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub max_routing_fee_msat: Option<u64>,
    /// Destination Lightning node public key (hex, 66 chars).
    pub dest_pubkey: String,
    /// Amount in millisatoshis.
    pub amount_msat: u64,
    /// Optional memo.
    #[serde(default)]
    pub memo: Option<String>,
}

/// Response after a keysend payment.
#[derive(Serialize)]
pub struct KeysendResponse {
    pub max_routing_fee_msat: u64,
    /// Actual settled LDK routing fee; omitted while pending or unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_paid_msat: Option<u64>,
    /// Payment hash (hex).
    pub payment_hash: String,
    /// Amount paid in millisatoshis.
    pub amount_msat: u64,
    /// Payment preimage (hex proof of payment).
    pub preimage: String,
    /// Payment status.
    pub status: String,
}

/// Maximum Lightning pubkey length (compressed: 66 hex chars).
const MAX_LN_PUBKEY_LEN: usize = 70;

/// Minimum keysend amount in millisatoshis (1 sat).
const MIN_KEYSEND_AMOUNT_MSAT: u64 = 1_000;

/// Maximum keysend amount in millisatoshis (1 BTC — sanity cap).
const MAX_KEYSEND_AMOUNT_MSAT: u64 = 100_000_000_000;

/// `POST /api/v1/payments/keysend` — send a keysend (spontaneous) payment.
///
/// Pushes sats directly to a Lightning node without an invoice. The sender
/// generates the preimage and pushes it via a TLV record. Requires the
/// destination node's compressed public key.
async fn keysend(
    auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    Json(req): Json<KeysendRequest>,
) -> Result<Json<KeysendResponse>, ApiError> {
    crate::error::require_money_ready(&state).await?;
    if req.dest_pubkey.is_empty() {
        return Err(ApiError::BadRequest("dest_pubkey is required".into()));
    }
    if req.dest_pubkey.len() > MAX_LN_PUBKEY_LEN {
        return Err(ApiError::BadRequest(format!(
            "dest_pubkey too long: {} chars (max {MAX_LN_PUBKEY_LEN})",
            req.dest_pubkey.len()
        )));
    }
    if req.amount_msat < MIN_KEYSEND_AMOUNT_MSAT {
        return Err(ApiError::BadRequest(format!(
            "amount_msat must be at least {MIN_KEYSEND_AMOUNT_MSAT} (1 sat)"
        )));
    }
    if req.amount_msat > MAX_KEYSEND_AMOUNT_MSAT {
        return Err(ApiError::BadRequest(format!(
            "amount_msat exceeds maximum {MAX_KEYSEND_AMOUNT_MSAT}"
        )));
    }

    let max_routing_fee_msat = state
        .lightning
        .routing_fee_policy()
        .ceiling(req.amount_msat, req.max_routing_fee_msat);
    // G1: debit a metered caller before the keysend is dispatched.
    let dest = req.dest_pubkey.trim().to_ascii_lowercase();
    let debit = if auth.is_metered() {
        let key = crate::spend_budget::canonical_recipient(&dest)
            .filter(|k| k.len() == 66)
            .ok_or_else(|| {
                ApiError::BadRequest("dest_pubkey must be a 33-byte hex pubkey".into())
            })?;
        Some(
            auth.debit_payment(
                &state,
                vec![Charge {
                    recipient: key,
                    amount_msat: req
                        .amount_msat
                        .checked_add(max_routing_fee_msat)
                        .ok_or_else(|| ApiError::BadRequest("payment debit overflow".into()))?,
                }],
                None,
                req.request_id.as_deref(),
            )
            .map_err(|e| e.with_routing_fee(max_routing_fee_msat))?,
        )
    } else {
        None
    };

    let unmetered = Debit::unmetered();
    let guard = debit.as_ref().unwrap_or(&unmetered);
    let paid = guard
        .dispatch(state.lightning.keysend_with_fee_limit(
            &req.dest_pubkey,
            req.amount_msat,
            req.memo.as_deref(),
            max_routing_fee_msat,
        ))
        .await
        .map_err(|e| e.with_routing_fee(max_routing_fee_msat))?;
    if let Some(debit) = &debit {
        resolve_payment(debit, &dest, &paid);
    }
    let details = paid.map_err(|e| ApiError::from(e).with_routing_fee(max_routing_fee_msat))?;

    let fee_paid_msat = fee_paid_msat(&state.lightning_backend, &details);
    let preimage = details.preimage.unwrap_or_default();

    Ok(Json(KeysendResponse {
        max_routing_fee_msat,
        fee_paid_msat,
        payment_hash: details.payment_hash,
        amount_msat: details.amount_msat,
        preimage,
        status: format!("{:?}", details.status),
    }))
}

/// Amount and payee of a BOLT11 invoice, for a metered debit.
///
/// An invoice without an amount is refused for a metered caller: the amount
/// would be chosen at payment time, after the budget check.
pub(crate) fn invoice_terms(bolt11: &str) -> Result<(u64, String), ApiError> {
    let invoice = bolt11
        .trim()
        .parse::<lightning_invoice::Bolt11Invoice>()
        .map_err(|e| ApiError::BadRequest(format!("invalid bolt11 invoice: {e}")))?;
    let amount_msat = invoice.amount_milli_satoshis().ok_or_else(|| {
        ApiError::BudgetExceeded(crate::spend_budget::BudgetRefusal::Unpriced(
            "this invoice has no amount; a budget grant only pays amounts known before \
             dispatch — nothing was paid"
                .into(),
        ))
    })?;
    let payee = invoice
        .payee_pub_key()
        .copied()
        .unwrap_or_else(|| invoice.recover_payee_pub_key());
    Ok((amount_msat, hex::encode(payee.serialize())))
}

/// Resolve a pay/keysend debit from the provider's answer.
///
/// Settled → the reported amount. Failed, or rejected before dispatch → 0.
/// Anything else (pending, in flight, or an error that does not prove the
/// payment never left) stays reserved: the #80 unknown outcome.
pub(crate) fn resolve_payment(
    debit: &Debit,
    recipient: &str,
    paid: &Result<konsensus_core::traits::lightning::PaymentDetails, LightningError>,
) {
    use konsensus_core::traits::lightning::PaymentStatus;
    match paid {
        Ok(d) if d.status == PaymentStatus::Settled => {
            debit.record_payment(recipient, d);
            debit.settled(recipient, d.amount_msat);
        }
        Ok(d) if matches!(d.status, PaymentStatus::Failed | PaymentStatus::Expired) => {
            debit.released(recipient)
        }
        Ok(_) => {}
        Err(LightningError::PaymentNotDispatched(_) | LightningError::NotReady) => {
            debit.released(recipient)
        }
        Err(_) => {}
    }
}

/// Channel info response.
#[derive(Serialize)]
pub struct ChannelResponse {
    /// LDK/CLN: hex Lightning channel ID; LND: native chan_id.
    pub channel_id: String,
    /// LDK user channel ID as a decimal string, without a Display/Debug wrapper.
    pub user_channel_id: Option<String>,
    /// Funding outpoint as `txid:vout`, or null if not assigned/available.
    pub funding_txo: Option<String>,
    /// Remote peer's public key (hex).
    pub peer_pubkey: String,
    /// Total channel capacity in millisatoshis.
    pub capacity_msat: u64,
    /// Local balance in millisatoshis.
    pub local_balance_msat: u64,
    /// Remote balance in millisatoshis.
    pub remote_balance_msat: u64,
    /// Whether the channel is active.
    pub active: bool,
    /// Short channel ID (if assigned).
    pub short_channel_id: Option<String>,
}

/// `GET /api/v1/payments/channels` — list Lightning channels.
///
/// Carries `BitSov-Data-As-Of` / `BitSov-Data-Stale` from the wallet's sync
/// status (see [`crate::freshness`]).
async fn list_channels(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Result<(DataFreshness, Json<Vec<ChannelResponse>>), ApiError> {
    // Sync status before the read: the figures are at least this current.
    let read_at = SystemTime::now();
    let sync = state.lightning.wallet_sync().await;
    let channels = state
        .lightning
        .list_channels()
        .await
        .map_err(ApiError::from)?;

    Ok((
        DataFreshness::from_wallet_sync(sync, read_at),
        Json(
            channels
                .into_iter()
                .map(|ch| ChannelResponse {
                    channel_id: ch.channel_id,
                    user_channel_id: ch.user_channel_id,
                    funding_txo: ch.funding_txo,
                    peer_pubkey: ch.peer_pubkey,
                    capacity_msat: ch.capacity_msat,
                    local_balance_msat: ch.local_balance_msat,
                    remote_balance_msat: ch.remote_balance_msat,
                    active: ch.active,
                    short_channel_id: ch.short_channel_id,
                })
                .collect(),
        ),
    ))
}

/// `GET /api/v1/payments/price/:kind` — check the price for a message kind.
async fn get_price(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(kind): Path<u16>,
) -> Result<Json<PriceResponse>, ApiError> {
    let price = state
        .pricing
        .get_price_msat(kind)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    Ok(Json(PriceResponse {
        kind,
        price_msat: price,
    }))
}

/// Query params for listing payments.
#[derive(Deserialize)]
pub struct PaymentListQuery {
    /// Maximum payments to return (default 50, max 100).
    #[serde(default = "default_payment_limit")]
    pub limit: u32,
}

fn default_payment_limit() -> u32 {
    50
}

/// Payment entry in the list response.
#[derive(Serialize)]
pub struct PaymentListEntry {
    /// Payment hash (hex).
    pub payment_hash: String,
    /// Payment preimage (hex, proof of payment). `None` if pending.
    pub preimage: Option<String>,
    /// Amount in millisatoshis.
    pub amount_msat: u64,
    /// Status: "success", "failed", "expired", "pending".
    pub status: String,
    /// Direction: "incoming" or "outgoing".
    pub direction: String,
    /// Timestamp in seconds since Unix epoch.
    pub timestamp: u64,
    /// Invoice description / memo.
    pub memo: Option<String>,
    /// Routing fee in millisatoshis (outgoing payments only).
    pub fee_msat: Option<u64>,
}

/// `GET /api/v1/payments` — list recent Lightning payments.
async fn list_payments(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Query(query): Query<PaymentListQuery>,
) -> Result<Json<Vec<PaymentListEntry>>, ApiError> {
    let limit = query.limit.min(100);
    let payments = state
        .lightning
        .list_payments(limit)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(
        payments
            .into_iter()
            .map(|p| PaymentListEntry {
                payment_hash: p.payment_hash,
                preimage: p.preimage,
                amount_msat: p.amount_msat,
                status: format!("{:?}", p.status).to_lowercase(),
                direction: format!("{:?}", p.direction).to_lowercase(),
                timestamp: p.timestamp,
                memo: p.memo,
                fee_msat: p.fee_msat,
            })
            .collect(),
    ))
}

// Pairing attribution without retaining invoices, payees, memos or request IDs.
fn audit_paired_payment<T>(
    state: &AppState,
    pairing: Option<&crate::auth::PairingBinding>,
    route: &str,
    result: &Result<T, ApiError>,
) {
    let Some(pairing) = pairing else {
        return;
    };
    let mut error = result.as_ref().err();
    while let Some(
        ApiError::RoutingFee { source, .. }
        | ApiError::Operation { source, .. }
        | ApiError::Reasoned { source, .. },
    ) = error
    {
        error = Some(source);
    }
    let reason = match error {
        Some(ApiError::BudgetExceeded(refusal)) => Some(refusal.reason()),
        Some(_) => Some("payment_error"),
        None => None,
    };
    state.audit_log.record(
        "spend.payment_result",
        &pairing.client_id,
        Some(serde_json::json!({
            "client_id": pairing.client_id, "epoch": pairing.epoch,
            "route": route, "api_success": result.is_ok(), "reason": reason,
        })),
    );
}

// Budget refusals on direct payments carry no invoice, memo or Lightning key.
async fn pay_invoice_observed(
    auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    Json(req): Json<PayInvoiceRequest>,
) -> Result<Json<PayInvoiceResponse>, ApiError> {
    let pairing = auth.user.pairing.clone();
    let result = pay_invoice(auth, State(Arc::clone(&state)), Json(req)).await;
    audit_paired_payment(&state, pairing.as_ref(), "pay", &result);
    if let Err(e) = &result {
        state
            .audit_log
            .membrane()
            .outbound_refused(e, None, None, None);
    }
    result
}

async fn keysend_observed(
    auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    Json(req): Json<KeysendRequest>,
) -> Result<Json<KeysendResponse>, ApiError> {
    let pairing = auth.user.pairing.clone();
    let result = keysend(auth, State(Arc::clone(&state)), Json(req)).await;
    audit_paired_payment(&state, pairing.as_ref(), "keysend", &result);
    if let Err(e) = &result {
        state
            .audit_log
            .membrane()
            .outbound_refused(e, None, None, None);
    }
    result
}

/// Registers payment routes for invoices, payments, balance, channels, and pricing queries.
/// Open a Lightning channel to a peer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenChannelRequest {
    /// Target preference; omitted keeps the provider's default (LDK: normal).
    #[serde(default)]
    pub funding_priority: Option<konsensus_core::traits::lightning::FundingPriority>,
    /// Return a read-only estimate without connecting a peer or creating a channel.
    #[serde(default)]
    pub dry_run: bool,
    /// Hard absolute funding fee cap, checked before signing; unsupported backends refuse.
    #[serde(default)]
    pub max_funding_fee_sats: Option<u64>,

    /// Hex-encoded Lightning public key of the peer.
    pub peer_pubkey: String,
    /// Network address of the peer (host:port).
    pub peer_addr: String,
    /// Channel capacity in satoshis.
    pub amount_sats: u64,
    /// Initial gift to the counterparty, at most half the channel capacity.
    #[serde(default)]
    pub push_sats: Option<u64>,
    /// Whether to announce the channel publicly.
    #[serde(default)]
    pub announce: bool,
    /// Optional fee rate override in sat/vB for the channel funding transaction.
    /// If omitted, the backend selects a rate from its fee estimator.
    /// Unsupported overrides are refused with `not_dispatched`, never ignored.
    /// Must be finite and within 1–10,000 sat/vB if provided.
    #[serde(default)]
    pub fee_rate_sat_per_vb: Option<f32>,
    /// Optional idempotency key (UUIDv4), as for message compose (#331).
    /// Recorded before dispatch: a retry with the same id and parameters
    /// returns the recorded channel or status and never opens again; the same
    /// id with different parameters is `409 operation_mismatch`.
    #[serde(default)]
    pub operation_id: Option<String>,
}

/// Canonical digest and record of the parameters an `operation_id` binds.
fn open_channel_fingerprint(req: &OpenChannelRequest) -> Result<(String, Vec<u8>), ApiError> {
    use sha2::{Digest, Sha256};
    let request = serde_json::to_vec(&serde_json::json!({
        "peer_pubkey": req.peer_pubkey.to_ascii_lowercase(),
        "peer_addr": req.peer_addr,
        "amount_sats": req.amount_sats,
        "push_sats": req.push_sats,
        "announce": req.announce,
        "funding_priority": req.funding_priority,
        "max_funding_fee_sats": req.max_funding_fee_sats,
        "fee_rate_sat_per_vb_bits": req.fee_rate_sat_per_vb.map(f32::to_bits),
    }))
    .map_err(|e| ApiError::Internal(format!("open-channel fingerprint: {e}")))?;
    Ok((hex::encode(Sha256::digest(&request)), request))
}

fn channel_open_storage(e: impl std::fmt::Display) -> ApiError {
    ApiError::Storage(format!("channel open operation: {e}"))
}

// Like compose operation locks, weak entries are pruned and live entries are
// bounded. Scope to the shared storage instance: AppState clones and routers
// for this node must see the same active open, while independent stores do not.
fn channel_open_lock(state: &AppState, id: &str) -> Result<Arc<tokio::sync::Mutex<()>>, ApiError> {
    use std::{
        collections::HashMap,
        sync::{Mutex, OnceLock, Weak},
    };
    type Locks = HashMap<(usize, String), Weak<tokio::sync::Mutex<()>>>;
    static LOCKS: OnceLock<Mutex<Locks>> = OnceLock::new();
    let key = (
        Arc::as_ptr(&state.storage) as *const () as usize,
        id.to_owned(),
    );
    let mut locks = LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    if locks.len() >= 1024 {
        return Err(ApiError::TooManyRequests(
            "too many active channel opens".into(),
        ));
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    Ok(lock)
}

/// Answer a retry without dispatching. Only the holder of the operation lock
/// can settle a crash-left pending row; a live opener holds it through recording.
async fn replay_channel_open(
    state: &AppState,
    mut op: konsensus_storage::ChannelOpenOperation,
    request_hash: &str,
    req: &OpenChannelRequest,
    owns_operation: bool,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    use konsensus_storage::channel_open::{
        CHANNEL_OPEN_OPENED, CHANNEL_OPEN_PENDING, CHANNEL_OPEN_UNCERTAIN,
    };
    if op.request_hash != request_hash {
        return Err(ApiError::OperationConflict("operation_mismatch"));
    }
    // Best effort: an unavailable backend still answers without dispatching.
    let channels = if op.state == CHANNEL_OPEN_OPENED {
        None
    } else {
        state.lightning.list_channels().await.ok().map(|all| {
            all.into_iter()
                .filter(|c| c.peer_pubkey.eq_ignore_ascii_case(&req.peer_pubkey))
                .collect::<Vec<_>>()
        })
    };
    if owns_operation
        && op.state == CHANNEL_OPEN_PENDING
        && chrono::Utc::now()
            .timestamp_millis()
            .saturating_sub(op.created_at)
            > 10 * 60 * 1000
    {
        let matches = channels.as_ref().map(|channels| {
            channels
                .iter()
                .filter(|c| req.amount_sats.checked_mul(1000) == Some(c.capacity_msat))
                .collect::<Vec<_>>()
        });
        let recovered = match matches.as_deref() {
            Some([channel]) => Some(serde_json::json!({
                "channel_id": channel.channel_id,
                "user_channel_id": channel.user_channel_id,
                "funding_txo": channel.funding_txo,
                "funding_txid": channel.funding_txo.as_deref().and_then(|txo| txo.split_once(':').map(|(txid, _)| txid)),
                "funding_fee": null,
                "peer_pubkey": req.peer_pubkey,
                "amount_sats": req.amount_sats,
                "status": "pending_visibility",
                "recovered": true,
                "warning": "Recovered from the node's channel list by peer and capacity; original funding fee and transaction visibility are unknown. Inspect GET /payments/channels.",
            })),
            _ => None,
        };
        let result = recovered
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()
            .map_err(channel_open_storage)?;
        let (status, error) = if recovered.is_some() {
            (CHANNEL_OPEN_OPENED, None)
        } else {
            (CHANNEL_OPEN_UNCERTAIN, Some("stale pending open has no unique peer/capacity match or channels are unavailable; inspect GET /payments/channels before choosing a new operation_id"))
        };
        state
            .storage
            .resolve_channel_open_operation(&op.operation_id, status, result.as_deref(), error)
            .await
            .map_err(channel_open_storage)?;
        // The pending-only update is a CAS. Always answer from the persisted
        // winner, including if another process settled the row first.
        op = state
            .storage
            .get_channel_open_operation(&op.operation_id)
            .await
            .map_err(channel_open_storage)?
            .ok_or_else(|| ApiError::Conflict("operation changed concurrently; retry".into()))?;
    }
    if op.state == CHANNEL_OPEN_OPENED {
        let mut body: serde_json::Value =
            serde_json::from_slice(op.result.as_deref().unwrap_or_default())
                .map_err(channel_open_storage)?;
        body["operation_id"] = op.operation_id.into();
        body["replayed"] = true.into();
        return Ok((StatusCode::OK, Json(body)));
    }
    let peer_channels = channels.map(|channels| {
        channels
            .into_iter()
            .map(|c| {
                serde_json::json!({
                    "channel_id": c.channel_id,
                    "user_channel_id": c.user_channel_id,
                    "funding_txo": c.funding_txo,
                    "capacity_msat": c.capacity_msat,
                    "active": c.active,
                })
            })
            .collect::<Vec<_>>()
    });
    let status = if op.state == CHANNEL_OPEN_UNCERTAIN {
        "outcome_uncertain"
    } else {
        "pending"
    };
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status": status,
            "operation_id": op.operation_id,
            "replayed": true,
            "last_error": op.last_error,
            "peer_channels": peer_channels,
            "warning": "Not opened again. The first attempt's outcome is not recorded as final; inspect GET /payments/channels before retrying with a new operation_id.",
        })),
    ))
}

/// Largest channel size whose millisatoshi form (`amount * 1000`) fits in `u64`.
const MAX_CHANNEL_AMOUNT_SATS: u64 = u64::MAX / 1000;

/// Reject a zero or overflowing channel size before any peer is dialed.
pub(crate) fn validate_channel_amount_sats(amount_sats: u64) -> Result<(), &'static str> {
    if amount_sats == 0 || amount_sats > MAX_CHANNEL_AMOUNT_SATS {
        Err("amount_sats must be between 1 and 18446744073709551")
    } else {
        Ok(())
    }
}

/// Close a Lightning channel by a listed channel ID.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseChannelRequest {
    /// LDK: decimal user_channel_id or hex channel_id from open/list.
    /// Legacy UserChannelId(n) values are also accepted.
    pub channel_id: String,
    /// Whether to force-close the channel.
    #[serde(default)]
    pub force: bool,
}

async fn open_channel(
    State(state): State<Arc<AppState>>,
    _user: ScopedAuth<Spend>,
    Json(req): Json<OpenChannelRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if req.operation_id.is_some() && !req.dry_run {
        // Dropping a JoinHandle detaches the task. Keep insertion, dispatch AND
        // outcome recording together so an HTTP disconnect cannot strand a row
        // while LDK's blocking opener continues moving money.
        tokio::spawn(run_channel_open(state, req))
            .await
            .map_err(|e| ApiError::Internal(format!("channel open task failed: {e}")))?
    } else {
        run_channel_open(state, req).await
    }
}

async fn run_channel_open(
    state: Arc<AppState>,
    req: OpenChannelRequest,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    // Hold through dispatch and recording, including after HTTP cancellation.
    let mut operation_guard = None;
    // #331: a recorded operation answers from its record, without dispatch
    // (and without requiring Lightning to be ready again).
    let operation = match req.operation_id.as_deref() {
        Some(_) if req.dry_run => {
            return Err(ApiError::NotDispatched(
                "operation_id cannot be combined with dry_run".into(),
            ));
        }
        Some(id) => {
            let id = crate::handlers::messages::operations::operation_id(Some(id))?;
            let (hash, request) = open_channel_fingerprint(&req)?;
            operation_guard = channel_open_lock(&state, &id)?.try_lock_owned().ok();
            if let Some(op) = state
                .storage
                .get_channel_open_operation(&id)
                .await
                .map_err(channel_open_storage)?
            {
                return replay_channel_open(&state, op, &hash, &req, operation_guard.is_some())
                    .await;
            }
            if operation_guard.is_none() {
                // Another task may still be inserting (or deleting a proven
                // refusal). Do not dispatch across that gap.
                return Err(ApiError::Conflict(
                    "operation changed concurrently; retry".into(),
                ));
            }
            Some((id, hash, request))
        }
        None => None,
    };
    validate_channel_amount_sats(req.amount_sats)
        .map_err(|message| ApiError::NotDispatched(message.into()))?;
    crate::error::require_money_ready(&state).await?;
    // L0a: shared validator rejects NaN/Inf and enforces 1.0–10_000.0 sat/vB.
    // The naive `<= 0.0` check accepts NaN (NaN compares false everywhere) and
    // ignores fractional floors that would silently produce a 0-rate tx.
    if let Some(rate) = req.fee_rate_sat_per_vb {
        validate_fee_rate_sat_per_vb(rate).map_err(|e| ApiError::NotDispatched(e.to_string()))?;
    }
    if req
        .max_funding_fee_sats
        .is_some_and(|cap| cap == 0 || cap > 2_100_000_000_000_000)
    {
        return Err(ApiError::NotDispatched(
            "max_funding_fee_sats must be between 1 and 2100000000000000".into(),
        ));
    }
    let push_msat = req
        .push_sats
        .map(|push| {
            if push > req.amount_sats / 2 {
                return Err(ApiError::NotDispatched(
                    "push_sats must not exceed amount_sats / 2".into(),
                ));
            }
            push.checked_mul(1000)
                .ok_or_else(|| ApiError::NotDispatched("push_sats overflows millisatoshis".into()))
        })
        .transpose()?;
    let explicit =
        req.funding_priority.is_some() || req.max_funding_fee_sats.is_some() || push_msat.is_some();
    if req.fee_rate_sat_per_vb.is_some() && (explicit || req.dry_run) {
        return Err(ApiError::NotDispatched("exact fee_rate_sat_per_vb cannot be combined with funding priority, fee cap, push, or preview".into()));
    }
    let options = konsensus_core::traits::lightning::FundingOptions {
        priority: req.funding_priority.unwrap_or_default(),
        max_funding_fee_sats: req.max_funding_fee_sats,
    };
    if req.dry_run {
        let quote = state
            .lightning
            .funding_fee_quote(options)
            .await
            .map_err(ApiError::from)?;
        return Ok((
            StatusCode::OK,
            Json(
                serde_json::json!({"status": "preview", "funding_fee": quote,
            "warning": "Estimate only; opening obtains a fresh estimate. Confirmation and channel_ready times are not guaranteed."}),
            ),
        ));
    }
    // #331: record the operation before dispatch. Losing the insert race means
    // another request owns this id; answer from its record.
    if let Some((id, hash, request)) = &operation {
        let pending = konsensus_storage::ChannelOpenOperation::pending(
            id.clone(),
            hash.clone(),
            request.clone(),
        );
        if !state
            .storage
            .insert_channel_open_operation(&pending)
            .await
            .map_err(channel_open_storage)?
        {
            let op = state
                .storage
                .get_channel_open_operation(id)
                .await
                .map_err(channel_open_storage)?
                .ok_or_else(|| {
                    ApiError::Conflict("operation changed concurrently; retry".into())
                })?;
            return replay_channel_open(&state, op, hash, &req, operation_guard.is_some()).await;
        }
    }
    let result = if explicit {
        state
            .lightning
            .open_channel_with_funding(
                &req.peer_pubkey,
                &req.peer_addr,
                req.amount_sats,
                req.announce,
                options,
                push_msat,
            )
            .await
    } else {
        state
            .lightning
            .open_channel_with_status(
                &req.peer_pubkey,
                &req.peer_addr,
                req.amount_sats,
                req.announce,
                req.fee_rate_sat_per_vb,
            )
            .await
    };
    let result = match (result, &operation) {
        (Ok(result), _) => result,
        (Err(e), None) => return Err(ApiError::from(e)),
        (Err(e), Some((id, _, _))) => {
            use konsensus_core::traits::lightning::LightningError as E;
            // Only proven non-dispatch frees the id; anything else may have
            // opened a channel and stays recorded as uncertain.
            let recorded = if matches!(e, E::PaymentNotDispatched(_) | E::NotReady) {
                state
                    .storage
                    .delete_pending_channel_open_operation(id)
                    .await
            } else {
                state
                    .storage
                    .resolve_channel_open_operation(
                        id,
                        konsensus_storage::channel_open::CHANNEL_OPEN_UNCERTAIN,
                        None,
                        Some(&e.to_string()),
                    )
                    .await
            };
            if let Err(storage) = recorded {
                tracing::warn!(operation_id = %id, "channel open outcome not recorded: {storage}");
            }
            return Err(ApiError::from(e));
        }
    };

    let mut body = serde_json::json!({
        "channel_id": result.channel_id,
        "user_channel_id": result.user_channel_id,
        "funding_txo": result.funding_txo,
        "funding_txid": result.funding_txid,
        "funding_fee": result.funding_fee,
        "warning": "Confirmation targets are estimates, not guarantees of confirmation or channel_ready. Funding fees will not be automatically raised.",
        "peer_pubkey": req.peer_pubkey,
        "amount_sats": req.amount_sats,
        "status": result.status
    });
    if let Some((id, _, _)) = &operation {
        // A failed write leaves the record pending: a retry never reopens and
        // can reconcile against the node's channels after ten minutes.
        match serde_json::to_vec(&body) {
            Ok(bytes) => {
                if let Err(e) = state
                    .storage
                    .resolve_channel_open_operation(
                        id,
                        konsensus_storage::channel_open::CHANNEL_OPEN_OPENED,
                        Some(&bytes),
                        None,
                    )
                    .await
                {
                    tracing::warn!(operation_id = %id, "opened channel not recorded: {e}");
                }
            }
            Err(e) => tracing::warn!(operation_id = %id, "opened channel not recorded: {e}"),
        }
        body["operation_id"] = id.clone().into();
    }
    Ok((StatusCode::OK, Json(body)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseLocalSpendRequest {
    pub txid: String,
}

async fn release_local_spend(
    State(state): State<Arc<AppState>>,
    // ScopedAuth<Spend> explicitly rejects pairing-bound tokens.
    _owner: ScopedAuth<Spend>,
    Json(req): Json<ReleaseLocalSpendRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if req.txid.len() != 64 || !req.txid.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("txid must be 32 bytes of hex".into()));
    }
    state
        .lightning
        .release_local_spend(&req.txid)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({
        "txid": req.txid,
        "status": "released",
        "warning": "The signed transaction may still propagate; inspect the transaction and channel before spending released inputs."
    })))
}

async fn close_channel(
    State(state): State<Arc<AppState>>,
    _user: ScopedAuth<Spend>,
    Json(req): Json<CloseChannelRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::error::require_money_ready(&state).await?;
    if req.channel_id.trim().is_empty() {
        return Err(ApiError::BadRequest("channel_id is required".into()));
    }

    let closing_txid = state
        .lightning
        .close_channel(&req.channel_id, req.force)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(serde_json::json!({
        "channel_id": req.channel_id,
        "force": req.force,
        "closing_txid": closing_txid,
        "status": "closing"
    })))
}

/// Send on-chain Bitcoin to an address.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendOnchainRequest {
    pub address: String,
    pub amount_sats: u64,
    /// Optional fee rate override in sat/vB.
    /// If omitted, the backend selects a rate from its fee estimator.
    /// Must be > 0 if provided.
    #[serde(default)]
    pub fee_rate_sat_per_vb: Option<f32>,
}

async fn send_onchain(
    State(state): State<Arc<AppState>>,
    _user: ScopedAuth<Spend>,
    Json(req): Json<SendOnchainRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    crate::error::require_money_ready(&state).await?;
    // L0a: see open_channel above for the same validation rationale.
    if let Some(rate) = req.fee_rate_sat_per_vb {
        validate_fee_rate_sat_per_vb(rate).map_err(|e| ApiError::NotDispatched(e.to_string()))?;
    }
    // L0f: distinguish between "broadcast confirmed visible" (HTTP 200) and
    // "broadcast initiated, but the chain provider couldn't confirm
    // visibility within the verification timeout" (HTTP 202 Accepted with
    // the txid). The 202 path lets the client poll for confirmation
    // rather than treating the silent-fail as success — covers the
    // documented 2026-04-23 ba91a6ac…45ef incident class.
    match state
        .lightning
        .send_onchain(&req.address, req.amount_sats, req.fee_rate_sat_per_vb)
        .await
    {
        Ok(txid) => Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "txid": txid,
                "address": req.address,
                "amount_sats": req.amount_sats,
                "broadcast_status": "confirmed_visible",
            })),
        )),
        Err(konsensus_core::traits::lightning::LightningError::BroadcastUnconfirmed { txid }) => {
            Ok((
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "txid": txid,
                    "address": req.address,
                    "amount_sats": req.amount_sats,
                    "broadcast_status": "unconfirmed",
                    "message": "Backend returned a txid but the chain provider could not verify mempool visibility within 10s. Poll mempool.space or call /tx/<txid> to confirm; the tx may still propagate.",
                })),
            ))
        }
        Err(e) => Err(ApiError::from(e)),
    }
}

/// Get an on-chain Bitcoin funding address for this node's LDK wallet.
///
/// Only available when the Lightning backend is LDK (embedded).
/// Other backends (LNbits, LND) manage their own on-chain wallets.
async fn get_funding_address(
    State(state): State<Arc<AppState>>,
    _user: ScopedAuth<Receive>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::error::require_money_ready(&state).await?;
    match state.lightning.get_funding_address().await {
        Some(address) => Ok(Json(serde_json::json!({
            "address": address,
            "network": state.introduction.network,
            "note": "Send on-chain BTC to this address to fund the LDK wallet. Funds become available for opening Lightning channels after 1 confirmation."
        }))),
        None => Err(ApiError::BadRequest(
            "Funding address not available — this endpoint requires an embedded LDK backend."
                .into(),
        )),
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .merge(super::liquidity::routes())
        .route("/api/v1/payments", get(list_payments))
        .route("/api/v1/payments/invoice", post(create_invoice))
        .route("/api/v1/payments/pay", post(pay_invoice_observed))
        .route("/api/v1/payments/keysend", post(keysend_observed))
        .route("/api/v1/payments/balance", get(get_balance))
        .route("/api/v1/payments/channels", get(list_channels))
        .route("/api/v1/payments/price/:kind", get(get_price))
        .route("/api/v1/payments/funding-address", get(get_funding_address))
        .route("/api/v1/payments/send-onchain", post(send_onchain))
        .route("/api/v1/payments/open-channel", post(open_channel))
        .route(
            "/api/v1/payments/release-local-spend",
            post(release_local_spend),
        )
        .route("/api/v1/payments/close-channel", post(close_channel))
        .route("/api/v1/payments/:hash", get(payment_status))
}

#[cfg(test)]
mod actual_fee_tests {
    use super::*;
    use konsensus_core::traits::lightning::{PaymentDetails, PaymentDirection, PaymentStatus};

    #[test]
    fn fee_reporting_never_infers_settlement_or_zero() {
        let mut details = PaymentDetails {
            payment_hash: "ab".repeat(32),
            preimage: Some("cd".repeat(32)),
            amount_msat: 1000,
            status: PaymentStatus::Settled,
            direction: PaymentDirection::Outgoing,
            timestamp: 0,
            memo: None,
            fee_msat: None,
        };
        assert_eq!(fee_paid_msat("ldk", &details), None);
        details.fee_msat = Some(0);
        assert_eq!(fee_paid_msat("ldk", &details), Some(0));
        for status in [
            PaymentStatus::Pending,
            PaymentStatus::InFlight,
            PaymentStatus::Failed,
            PaymentStatus::Expired,
        ] {
            details.status = status;
            assert_eq!(fee_paid_msat("ldk", &details), None);
        }
        details.status = PaymentStatus::Settled;
        details.direction = PaymentDirection::Incoming;
        assert_eq!(fee_paid_msat("ldk", &details), None);
    }

    #[test]
    fn channel_amount_rejects_zero_and_msat_overflow_before_dial() {
        assert!(validate_channel_amount_sats(0).is_err());
        assert!(validate_channel_amount_sats(u64::MAX).is_err());
        assert!(validate_channel_amount_sats(1).is_ok());
        assert!(validate_channel_amount_sats(MAX_CHANNEL_AMOUNT_SATS).is_ok());
    }
}
