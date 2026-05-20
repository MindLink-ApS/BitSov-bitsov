//! Payment endpoints — Lightning invoices, balances, status.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use konsensus_core::fee_rate::validate_fee_rate_sat_per_vb;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

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
    /// Payment hash (hex).
    pub payment_hash: String,
    /// Status: "pending", "settled", "failed", "expired".
    pub status: String,
    /// Amount in millisatoshis.
    pub amount_msat: u64,
    /// Direction: "incoming" or "outgoing".
    pub direction: String,
}

/// Balance response.
#[derive(Serialize)]
pub struct BalanceResponse {
    /// Available balance in millisatoshis.
    pub balance_msat: u64,
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
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateInvoiceRequest>,
) -> Result<Json<InvoiceResponse>, ApiError> {
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
        return Err(ApiError::BadRequest("amount must be greater than zero".into()));
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
        .map_err(|e| ApiError::Lightning(e.to_string()))?;

    Ok(Json(InvoiceResponse {
        bolt11: invoice.bolt11,
        payment_hash: invoice.payment_hash,
    }))
}

/// `GET /api/v1/payments/:hash` — check payment status.
async fn payment_status(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> Result<Json<PaymentStatusResponse>, ApiError> {
    let details = state
        .lightning
        .get_payment_status(&hash)
        .await
        .map_err(|e| ApiError::Lightning(e.to_string()))?;

    Ok(Json(PaymentStatusResponse {
        payment_hash: details.payment_hash,
        status: format!("{:?}", details.status),
        amount_msat: details.amount_msat,
        direction: format!("{:?}", details.direction),
    }))
}

/// `GET /api/v1/payments/balance` — get Lightning wallet balance.
async fn get_balance(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<BalanceResponse>, ApiError> {
    let balance = state
        .lightning
        .get_balance_msat()
        .await
        .map_err(|e| ApiError::Lightning(e.to_string()))?;

    Ok(Json(BalanceResponse {
        balance_msat: balance,
    }))
}

/// Request to pay a BOLT11 invoice.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayInvoiceRequest {
    /// BOLT11 payment request string.
    pub bolt11: String,
}

/// Response after paying an invoice.
#[derive(Serialize)]
pub struct PayInvoiceResponse {
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
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<PayInvoiceRequest>,
) -> Result<Json<PayInvoiceResponse>, ApiError> {
    if req.bolt11.is_empty() {
        return Err(ApiError::BadRequest("bolt11 invoice string is required".into()));
    }
    if req.bolt11.len() > MAX_BOLT11_LEN {
        return Err(ApiError::BadRequest(format!(
            "bolt11 string too long: {} bytes (max {MAX_BOLT11_LEN})",
            req.bolt11.len()
        )));
    }

    let details = state
        .lightning
        .pay_invoice(&req.bolt11)
        .await
        .map_err(|e| ApiError::Lightning(e.to_string()))?;

    let preimage = details.preimage.unwrap_or_else(|| {
        tracing::warn!(payment_hash = %details.payment_hash, "payment succeeded but no preimage returned");
        String::new()
    });

    Ok(Json(PayInvoiceResponse {
        payment_hash: details.payment_hash,
        amount_msat: details.amount_msat,
        preimage,
    }))
}

/// Request to send a keysend (spontaneous) payment.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysendRequest {
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
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<KeysendRequest>,
) -> Result<Json<KeysendResponse>, ApiError> {
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

    let details = state
        .lightning
        .keysend(&req.dest_pubkey, req.amount_msat, req.memo.as_deref())
        .await
        .map_err(|e| ApiError::Lightning(e.to_string()))?;

    let preimage = details.preimage.unwrap_or_default();

    Ok(Json(KeysendResponse {
        payment_hash: details.payment_hash,
        amount_msat: details.amount_msat,
        preimage,
        status: format!("{:?}", details.status),
    }))
}

/// Channel info response.
#[derive(Serialize)]
pub struct ChannelResponse {
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
async fn list_channels(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ChannelResponse>>, ApiError> {
    let channels = state
        .lightning
        .list_channels()
        .await
        .map_err(|e| ApiError::Lightning(e.to_string()))?;

    Ok(Json(
        channels
            .into_iter()
            .map(|ch| ChannelResponse {
                peer_pubkey: ch.peer_pubkey,
                capacity_msat: ch.capacity_msat,
                local_balance_msat: ch.local_balance_msat,
                remote_balance_msat: ch.remote_balance_msat,
                active: ch.active,
                short_channel_id: ch.short_channel_id,
            })
            .collect(),
    ))
}

/// `GET /api/v1/payments/price/:kind` — check the price for a message kind.
async fn get_price(
    _auth: AuthUser,
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
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Query(query): Query<PaymentListQuery>,
) -> Result<Json<Vec<PaymentListEntry>>, ApiError> {
    let limit = query.limit.min(100);
    let payments = state
        .lightning
        .list_payments(limit)
        .await
        .map_err(|e| ApiError::Lightning(e.to_string()))?;

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

/// Registers payment routes for invoices, payments, balance, channels, and pricing queries.
/// Open a Lightning channel to a peer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenChannelRequest {
    /// Hex-encoded Lightning public key of the peer.
    pub peer_pubkey: String,
    /// Network address of the peer (host:port).
    pub peer_addr: String,
    /// Channel capacity in satoshis.
    pub amount_sats: u64,
    /// Whether to announce the channel publicly.
    #[serde(default)]
    pub announce: bool,
    /// Optional fee rate override in sat/vB for the channel funding transaction.
    /// If omitted, the backend selects a rate from its fee estimator.
    /// Must be > 0 if provided.
    #[serde(default)]
    pub fee_rate_sat_per_vb: Option<f32>,
}

/// Close a Lightning channel by user channel ID.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseChannelRequest {
    /// User channel ID returned by `open_channel`.
    pub channel_id: String,
    /// Whether to force-close the channel.
    #[serde(default)]
    pub force: bool,
}

async fn open_channel(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Json(req): Json<OpenChannelRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // L0a: shared validator rejects NaN/Inf and enforces 1.0–10_000.0 sat/vB.
    // The naive `<= 0.0` check accepts NaN (NaN compares false everywhere) and
    // ignores fractional floors that would silently produce a 0-rate tx.
    if let Some(rate) = req.fee_rate_sat_per_vb {
        validate_fee_rate_sat_per_vb(rate)
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    let channel_id = state
        .lightning
        .open_channel(
            &req.peer_pubkey,
            &req.peer_addr,
            req.amount_sats,
            req.announce,
            req.fee_rate_sat_per_vb,
        )
        .await
        .map_err(|e| ApiError::BadRequest(format!("open_channel failed: {e}")))?;

    Ok(Json(serde_json::json!({
        "channel_id": channel_id,
        "peer_pubkey": req.peer_pubkey,
        "amount_sats": req.amount_sats,
        "status": "opening"
    })))
}

async fn close_channel(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Json(req): Json<CloseChannelRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if req.channel_id.trim().is_empty() {
        return Err(ApiError::BadRequest("channel_id is required".into()));
    }

    let closing_txid = state
        .lightning
        .close_channel(&req.channel_id, req.force)
        .await
        .map_err(|e| ApiError::BadRequest(format!("close_channel failed: {e}")))?;

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
    _user: AuthUser,
    Json(req): Json<SendOnchainRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    // L0a: see open_channel above for the same validation rationale.
    if let Some(rate) = req.fee_rate_sat_per_vb {
        validate_fee_rate_sat_per_vb(rate)
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
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
        Err(e) => Err(ApiError::BadRequest(format!("send_onchain failed: {e}"))),
    }
}

/// Get an on-chain Bitcoin funding address for this node's LDK wallet.
///
/// Only available when the Lightning backend is LDK (embedded).
/// Other backends (LNbits, LND) manage their own on-chain wallets.
async fn get_funding_address(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    match state.lightning.get_funding_address().await {
        Some(address) => Ok(Json(serde_json::json!({
            "address": address,
            "network": "bitcoin",
            "note": "Send on-chain BTC to this address to fund the LDK wallet. Funds become available for opening Lightning channels after 1 confirmation."
        }))),
        None => Err(ApiError::BadRequest(
            "Funding address not available — this endpoint requires an embedded LDK backend.".into(),
        )),
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/payments", get(list_payments))
        .route("/api/v1/payments/invoice", post(create_invoice))
        .route("/api/v1/payments/pay", post(pay_invoice))
        .route("/api/v1/payments/keysend", post(keysend))
        .route("/api/v1/payments/balance", get(get_balance))
        .route("/api/v1/payments/channels", get(list_channels))
        .route("/api/v1/payments/price/:kind", get(get_price))
        .route("/api/v1/payments/funding-address", get(get_funding_address))
        .route("/api/v1/payments/send-onchain", post(send_onchain))
        .route("/api/v1/payments/open-channel", post(open_channel))
        .route("/api/v1/payments/close-channel", post(close_channel))
        .route("/api/v1/payments/:hash", get(payment_status))
}
