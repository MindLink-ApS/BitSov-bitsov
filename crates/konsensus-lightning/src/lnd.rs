//! LND REST provider — communicates directly with an LND node via REST API.
//!
//! This removes the LNbits middleman for Full tier nodes. The node talks
//! directly to LND using macaroon authentication and TLS.
//!
//! # LND REST API endpoints used
//!
//! - `POST /v1/invoices` — create invoice (addinvoice)
//! - `POST /v2/router/send` — pay invoice (sendpaymentv2, sync)
//! - `GET  /v1/invoice/{r_hash_str}` — lookup invoice
//! - `GET  /v2/payments?include_incomplete=true&max_payments=N` — list payments
//! - `GET  /v1/balance/channels` — channel balance
//! - `GET  /v1/channels` — list channels
//! - `GET  /v1/getinfo` — node info / health check
//!
//! Auth: `Grpc-Metadata-macaroon` header with hex-encoded macaroon.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, warn};

use konsensus_core::traits::lightning::{
    ChannelInfo, Invoice, LightningError, LightningProvider, PaymentDetails, PaymentDirection,
    PaymentStatus,
};

/// Configuration for the LND REST provider.
#[derive(Clone)]
pub struct LndConfig {
    /// Base URL of the LND REST API (e.g. `https://localhost:8080`).
    pub api_url: String,
    /// Hex-encoded macaroon for authentication.
    pub macaroon_hex: String,
    /// Optional path to TLS cert for self-signed LND certificates.
    /// If not provided, system CA roots are used.
    pub tls_cert_path: Option<String>,
}

// Keep credentials out of diagnostics, including nested and pretty Debug output.
impl std::fmt::Debug for LndConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LndConfig")
            .field(
                "api_url",
                &konsensus_core::logging::redact_url_for_debug(&self.api_url),
            )
            .field("macaroon_hex", &"<redacted>")
            .field("tls_cert_path", &self.tls_cert_path)
            .finish()
    }
}

/// LND REST provider implementing `LightningProvider`.
///
/// Talks directly to LND via its REST API, bypassing LNbits.
/// This is the most direct integration for Full tier nodes that
/// run their own LND daemon.
pub struct LndProvider {
    config: LndConfig,
    routing_fee_policy: konsensus_core::traits::lightning::RoutingFeePolicy,
    client: Client,
    invoice_attempts: tokio::sync::Mutex<std::collections::HashSet<String>>,
    invoice_expiries: Mutex<HashMap<String, u64>>,
    /// Set to `false` when a payment fails due to wallet/channel issues.
    /// Reset to `true` on successful payment.
    pub(crate) payment_capable: AtomicBool,
}

impl std::fmt::Debug for LndProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LndProvider")
            .field("config", &self.config)
            .field(
                "payment_capable",
                &self
                    .payment_capable
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

// ── LND REST API request/response types ──────────────────────────────

/// Request body for POST /v1/invoices (addinvoice).
#[derive(Serialize)]
struct AddInvoiceRequest {
    /// Invoice amount in satoshis.
    value: String,
    /// Invoice amount in millisatoshis (preferred, overrides value).
    value_msat: String,
    /// Invoice memo/description.
    memo: String,
    /// Invoice expiry in seconds.
    expiry: String,
}

/// Response from POST /v1/invoices.
#[derive(Debug, Deserialize)]
struct AddInvoiceResponse {
    /// The hex-encoded payment hash of the invoice.
    r_hash: Option<String>,
    /// The BOLT11 payment request string.
    payment_request: Option<String>,
}

/// Request body for POST /v2/router/send (sendpaymentv2 sync).
#[derive(Serialize)]
struct SendPaymentRequest {
    /// BOLT11 invoice to pay.
    payment_request: String,
    /// Timeout in seconds for finding a route.
    timeout_seconds: String,
    /// Maximum total routing fee in millisatoshis (including an explicit zero).
    fee_limit_msat: String,
}

/// Response from POST /v2/router/send (streaming, we read first line).
#[derive(Debug, Deserialize)]
struct PaymentResponse {
    result: Option<PaymentResult>,
    error: Option<LndError>,
}

/// The inner result from sendpaymentv2.
#[derive(Debug, Deserialize)]
struct PaymentResult {
    payment_hash: Option<String>,
    payment_preimage: Option<String>,
    status: Option<String>,
    /// Fee paid in millisatoshis.
    fee_msat: Option<String>,
    /// Total value sent in millisatoshis.
    value_msat: Option<String>,
}

/// Error from LND.
#[derive(Debug, Deserialize)]
struct LndError {
    message: Option<String>,
    #[allow(dead_code)]
    code: Option<i32>,
}

#[derive(Serialize)]
struct CancelInvoiceRequest {
    payment_hash: String,
}

/// Response from GET /v1/invoices.
#[derive(Debug, Deserialize)]
struct ListInvoicesResponse {
    invoices: Option<Vec<LndListedInvoice>>,
    last_index_offset: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LndListedInvoice {
    r_hash: Option<String>,
    creation_date: Option<String>,
    expiry: Option<String>,
    state: Option<String>,
}

/// Response from GET /v1/invoice/{r_hash_str} (lookupinvoice).
#[derive(Debug, Deserialize)]
struct LookupInvoiceResponse {
    #[allow(dead_code)]
    r_hash: Option<String>,
    r_preimage: Option<String>,
    /// Invoice amount in satoshis.
    value: Option<String>,
    /// Invoice amount in millisatoshis.
    value_msat: Option<String>,
    /// Invoice state: OPEN, SETTLED, CANCELED, ACCEPTED.
    state: Option<String>,
    memo: Option<String>,
    creation_date: Option<String>,
    #[allow(dead_code)]
    settle_date: Option<String>,
}

/// Response from GET /v1/balance/channels.
#[derive(Debug, Deserialize)]
struct ChannelBalanceResponse {
    /// Local balance in satoshis.
    local_balance: Option<BalanceDetail>,
    /// Remote balance in satoshis (unused but part of LND API).
    #[allow(dead_code)]
    remote_balance: Option<BalanceDetail>,
}

/// Balance detail from channel balance response.
#[derive(Debug, Deserialize)]
struct BalanceDetail {
    sat: Option<String>,
    msat: Option<String>,
}

/// Response from GET /v1/channels.
#[derive(Debug, Deserialize)]
struct ListChannelsResponse {
    channels: Option<Vec<LndChannel>>,
}

/// A single channel from list_channels.
#[derive(Debug, Deserialize)]
struct LndChannel {
    remote_pubkey: Option<String>,
    capacity: Option<String>,
    local_balance: Option<String>,
    remote_balance: Option<String>,
    active: Option<bool>,
    chan_id: Option<String>,
    local_constraints: Option<LndChannelConstraints>,
    local_chan_reserve_sat: Option<String>,
    unsettled_balance: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LndChannelConstraints {
    chan_reserve_sat: Option<String>,
}

impl LndChannel {
    fn outbound_capacity_msat(&self) -> Option<u64> {
        let local = self.local_balance.as_ref()?.parse::<u64>().ok()?;
        let reserve = self.local_constraints.as_ref().and_then(|c| c.chan_reserve_sat.as_ref())
            .or(self.local_chan_reserve_sat.as_ref())?.parse::<u64>().ok()?;
        // Conservative: retain all unsettled value, even incoming HTLCs.
        let unsettled = self.unsettled_balance.as_ref()?.parse::<u64>().ok()?;
        local.saturating_sub(reserve).saturating_sub(unsettled).checked_mul(1000)
    }
}

/// Response from GET /v1/getinfo.
#[derive(Debug, Deserialize)]
struct GetInfoResponse {
    identity_pubkey: Option<String>,
    synced_to_chain: Option<bool>,
    num_active_channels: Option<u32>,
}

/// Entry from GET /v2/payments.
#[derive(Debug, Deserialize)]
struct ListPaymentsResponse {
    payments: Option<Vec<LndPaymentEntry>>,
}

/// A single payment from list payments.
#[derive(Debug, Deserialize)]
struct LndPaymentEntry {
    payment_hash: Option<String>,
    payment_preimage: Option<String>,
    /// Value in satoshis.
    value_sat: Option<String>,
    /// Value in millisatoshis.
    value_msat: Option<String>,
    status: Option<String>,
    creation_date: Option<String>,
    fee_msat: Option<String>,
}

impl LndProvider {
    pub fn with_routing_fee_policy(
        mut self,
        policy: konsensus_core::traits::lightning::RoutingFeePolicy,
    ) -> Self {
        self.routing_fee_policy = policy;
        self
    }

    /// Track exactly this outgoing hash. Only LND's explicit NOT_FOUND permits
    /// a fresh dispatch. Read one JSON frame: tracking a live payment never ends.
    async fn require_fresh_invoice(&self, hash: &[u8]) -> Result<(), LightningError> {
        use base64::Engine;
        let hash = base64::engine::general_purpose::URL_SAFE.encode(hash);
        let mut response = self
            .client
            .get(self.api_url(&format!(
                "/v2/router/track/{hash}?no_inflight_updates=false"
            )))
            .header("Grpc-Metadata-macaroon", &self.config.macaroon_hex)
            .send()
            .await
            .map_err(|e| {
                LightningError::PaymentNotDispatched(format!("cannot verify fresh invoice: {e}"))
            })?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| LightningError::PaymentNotDispatched(e.to_string()))?
        {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > 16384 {
                break;
            }
            let first = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
            if let Ok(frame) = serde_json::from_slice::<serde_json::Value>(first) {
                let code = frame
                    .get("code")
                    .or_else(|| frame.get("error").and_then(|e| e.get("code")))
                    .and_then(|c| c.as_i64());
                if (status.is_success() || status == reqwest::StatusCode::NOT_FOUND)
                    && code == Some(5)
                {
                    return Ok(());
                }
                return Err(LightningError::PaymentNotDispatched("capped payments require a fresh invoice hash; track/reconcile existing payments".into()));
            }
        }
        Err(LightningError::PaymentNotDispatched(
            "cannot verify fresh invoice: missing or invalid LND tracking response".into(),
        ))
    }

    /// Create a new LND provider with the given configuration.
    ///
    /// If `tls_cert_path` is provided, the custom CA cert is added to the
    /// client's trust store. Otherwise, LND must use a certificate trusted
    /// by the system CA roots, or the connection will fail.
    pub fn new(config: LndConfig) -> Result<Self, LightningError> {
        let mut builder = Client::builder().timeout(std::time::Duration::from_secs(60));

        // If a TLS cert path is provided, load it as a custom CA
        if let Some(cert_path) = &config.tls_cert_path {
            let cert_pem = std::fs::read(cert_path).map_err(|e| {
                LightningError::Connection(format!("failed to read TLS cert {cert_path}: {e}"))
            })?;
            // Reject empty or non-PEM data before passing to reqwest
            if cert_pem.is_empty() || !cert_pem.windows(5).any(|w| w == b"BEGIN") {
                return Err(LightningError::Connection(
                    "invalid TLS cert: file is empty or not PEM-encoded".into(),
                ));
            }
            let cert = reqwest::Certificate::from_pem(&cert_pem)
                .map_err(|e| LightningError::Connection(format!("invalid TLS cert: {e}")))?;
            builder = builder
                .add_root_certificate(cert)
                .danger_accept_invalid_certs(false);
        }

        let client = builder
            .build()
            .map_err(|e| LightningError::Backend(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            config,
            routing_fee_policy: Default::default(),
            client,
            invoice_attempts: Default::default(),
            invoice_expiries: Mutex::new(HashMap::new()),
            payment_capable: AtomicBool::new(true),
        })
    }

    /// Create a provider with a custom reqwest Client (for testing).
    pub fn with_client(config: LndConfig, client: Client) -> Self {
        Self {
            config,
            routing_fee_policy: Default::default(),
            client,
            invoice_attempts: Default::default(),
            invoice_expiries: Mutex::new(HashMap::new()),
            payment_capable: AtomicBool::new(true),
        }
    }

    fn remember_invoice_expiry(&self, payment_hash: &str, expires_at: u64) {
        self.invoice_expiries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(payment_hash.to_string(), expires_at);
    }

    fn clear_invoice_expiry(&self, payment_hash: &str) {
        self.invoice_expiries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(payment_hash);
    }

    fn payment_hash_lnd_base64(payment_hash_hex: &str) -> Result<String, LightningError> {
        let bytes = hex::decode(payment_hash_hex)
            .map_err(|e| LightningError::Backend(format!("invalid payment hash hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(LightningError::Backend(
                "payment hash must be 32 bytes".into(),
            ));
        }
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    async fn cancel_open_invoice(&self, payment_hash: &str) -> Result<bool, LightningError> {
        let body = CancelInvoiceRequest {
            payment_hash: Self::payment_hash_lnd_base64(payment_hash)?,
        };
        let response = self
            .client
            .post(self.api_url("/v2/invoices/cancel"))
            .header("Grpc-Metadata-macaroon", &self.config.macaroon_hex)
            .json(&body)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;
        if !response.status().is_success() {
            return Err(self.handle_error(response, "cancel_invoice").await);
        }
        self.delete_canceled_invoice(payment_hash).await?;
        Ok(true)
    }

    /// DeleteCanceledInvoice. Tracking is cleared only after LND confirms the
    /// delete, so a failed delete is retried by a later sweep.
    async fn delete_canceled_invoice(&self, payment_hash: &str) -> Result<(), LightningError> {
        let delete_url = self.api_url(&format!("/v1/invoices?invoice_hash={payment_hash}"));
        let delete = self
            .client
            .delete(&delete_url)
            .header("Grpc-Metadata-macaroon", &self.config.macaroon_hex)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;
        if !delete.status().is_success() {
            return Err(self.handle_error(delete, "delete_canceled_invoice").await);
        }
        self.clear_invoice_expiry(payment_hash);
        Ok(())
    }

    async fn list_pending_invoice_expiries(&self) -> Result<Vec<(String, u64)>, LightningError> {
        let mut index_offset = "0".to_string();
        let mut pending = Vec::new();
        loop {
            let url = self.api_url(&format!(
                "/v1/invoices?pending_only=true&num_max_invoices=100&index_offset={index_offset}"
            ));
            let response = self
                .client
                .get(&url)
                .header("Grpc-Metadata-macaroon", &self.config.macaroon_hex)
                .send()
                .await
                .map_err(|e| LightningError::Connection(e.to_string()))?;
            if !response.status().is_success() {
                return Err(self.handle_error(response, "list_invoices").await);
            }
            let resp: ListInvoicesResponse = response
                .json()
                .await
                .map_err(|e| LightningError::Backend(format!("parse list invoices: {e}")))?;
            let batch = resp.invoices.unwrap_or_default();
            if batch.is_empty() {
                break;
            }
            let batch_len = batch.len();
            for invoice in batch {
                let state = invoice.state.as_deref().unwrap_or("OPEN");
                if state != "OPEN" {
                    continue;
                }
                let r_hash_raw = invoice
                    .r_hash
                    .ok_or_else(|| LightningError::Backend("LND invoice missing r_hash".into()))?;
                let payment_hash = Self::decode_r_hash(&r_hash_raw)?;
                let created = invoice
                    .creation_date
                    .as_deref()
                    .map(Self::parse_u64)
                    .unwrap_or(0);
                let expiry_secs = invoice
                    .expiry
                    .as_deref()
                    .map(Self::parse_u64)
                    .unwrap_or(3600);
                let expires_at = created.saturating_add(expiry_secs);
                pending.push((payment_hash, expires_at));
            }
            if batch_len < 100 {
                break;
            }
            let next = resp
                .last_index_offset
                .filter(|offset| *offset != index_offset);
            match next {
                Some(offset) => index_offset = offset,
                None => break,
            }
        }
        Ok(pending)
    }

    /// Probes whether LND is reachable and synced to chain.
    ///
    /// Call this at startup to get accurate health reporting.
    pub async fn probe_payment_capability(&self) {
        match self.get_info().await {
            Ok(info) => {
                if info.synced_to_chain.unwrap_or(false) {
                    debug!(
                        pubkey = info.identity_pubkey.as_deref().unwrap_or("unknown"),
                        channels = info.num_active_channels.unwrap_or(0),
                        "LND is synced and ready"
                    );
                } else {
                    warn!("LND is not synced to chain — payments may fail");
                    self.payment_capable.store(false, Ordering::Relaxed);
                }
            }
            Err(e) => {
                warn!(error = %e, "LND unreachable during capability probe");
                self.payment_capable.store(false, Ordering::Relaxed);
            }
        }
    }

    /// Build the API URL for a given path.
    fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.config.api_url.trim_end_matches('/'), path)
    }

    /// GET /v1/getinfo — node info and sync status.
    async fn get_info(&self) -> Result<GetInfoResponse, LightningError> {
        let response = self
            .client
            .get(self.api_url("/v1/getinfo"))
            .header("Grpc-Metadata-macaroon", &self.config.macaroon_hex)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;

        if !response.status().is_success() {
            return Err(self.handle_error(response, "getinfo").await);
        }

        response
            .json()
            .await
            .map_err(|e| LightningError::Backend(format!("parse getinfo response: {e}")))
    }

    /// Convert an LND API error response into a LightningError.
    async fn handle_error(&self, response: reqwest::Response, context: &str) -> LightningError {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        warn!(status = %status, body = %body, "{context} failed");

        if status.as_u16() == 401 || status.as_u16() == 403 {
            LightningError::Auth(format!("{context}: {status} — {body}"))
        } else if status.as_u16() == 404 {
            LightningError::PaymentNotFound(format!("{context}: not found"))
        } else {
            if status.as_u16() >= 500 {
                self.payment_capable.store(false, Ordering::Relaxed);
            }
            LightningError::Backend(format!("{context}: {status} — {body}"))
        }
    }

    /// Parse a string number to u64, returning 0 on failure.
    fn parse_u64(s: &str) -> u64 {
        s.parse::<u64>().unwrap_or(0)
    }

    /// A payment amount. Failure is not zero: a settled zero releases a budget grant.
    fn parse_amount_u64(raw: &str) -> Result<u64, LightningError> {
        raw.parse::<u64>().map_err(|_| {
            LightningError::Backend("unparseable integer amount; not treated as zero".into())
        })
    }

    /// Satoshis to millisatoshis. A wrapping multiply would report a small settled amount.
    fn scale_sats(sats: u64) -> Result<u64, LightningError> {
        sats.checked_mul(1_000)
            .ok_or_else(|| LightningError::Backend("satoshi amount overflows millisatoshis".into()))
    }

    /// Amount from an LND payment or invoice. A settled record with no positive
    /// amount is an error so callers cannot release a grant for funds that left.
    fn reported_amount_msat(
        status: PaymentStatus,
        value_msat: Option<&str>,
        value_sat: Option<&str>,
    ) -> Result<u64, LightningError> {
        let amount = if let Some(msat) = value_msat {
            Some(Self::parse_amount_u64(msat)?)
        } else if let Some(sat) = value_sat {
            Some(Self::scale_sats(Self::parse_amount_u64(sat)?)?)
        } else {
            None
        };
        if status == PaymentStatus::Settled && amount.unwrap_or(0) == 0 {
            return Err(LightningError::Backend(
                "settled payment has no positive amount; not reporting zero".into(),
            ));
        }
        Ok(amount.unwrap_or(0))
    }

    /// Convert LND invoice state string to PaymentStatus.
    fn invoice_state_to_status(state: &str) -> PaymentStatus {
        match state {
            "SETTLED" => PaymentStatus::Settled,
            "CANCELED" | "CANCELLED" => PaymentStatus::Failed,
            "ACCEPTED" => PaymentStatus::InFlight,
            _ => PaymentStatus::Pending, // OPEN
        }
    }

    /// Convert LND payment status string to PaymentStatus.
    fn payment_status_to_status(status: &str) -> PaymentStatus {
        match status {
            "SUCCEEDED" => PaymentStatus::Settled,
            "FAILED" => PaymentStatus::Failed,
            "IN_FLIGHT" => PaymentStatus::InFlight,
            _ => PaymentStatus::Pending, // UNKNOWN
        }
    }

    /// Decode base64-encoded r_hash to hex string.
    /// LND returns r_hash as base64 in JSON responses.
    fn decode_r_hash(r_hash: &str) -> Result<String, LightningError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(r_hash)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(r_hash))
            .map_err(|e| LightningError::Backend(format!("failed to decode r_hash base64: {e}")))?;
        Ok(hex::encode(bytes))
    }
}

#[async_trait]
impl LightningProvider for LndProvider {
    #[instrument(skip(self), fields(amount_msat, description))]
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        let body = AddInvoiceRequest {
            value: (amount_msat / 1000).to_string(),
            value_msat: amount_msat.to_string(),
            memo: description.to_string(),
            expiry: expiry_secs.to_string(),
        };

        let response = self
            .client
            .post(self.api_url("/v1/invoices"))
            .header("Grpc-Metadata-macaroon", &self.config.macaroon_hex)
            .json(&body)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;

        if !response.status().is_success() {
            return Err(self.handle_error(response, "create_invoice").await);
        }

        let resp: AddInvoiceResponse = response
            .json()
            .await
            .map_err(|e| LightningError::Backend(format!("parse addinvoice response: {e}")))?;

        let r_hash_raw = resp
            .r_hash
            .ok_or_else(|| LightningError::InvoiceCreation("no r_hash in response".into()))?;

        // LND returns r_hash as base64
        let payment_hash = Self::decode_r_hash(&r_hash_raw)?;

        let bolt11 = resp.payment_request.ok_or_else(|| {
            LightningError::InvoiceCreation("no payment_request in response".into())
        })?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expires_at = now.saturating_add(u64::from(expiry_secs));
        self.remember_invoice_expiry(&payment_hash, expires_at);

        debug!(payment_hash = %payment_hash, "LND invoice created");

        Ok(Invoice {
            bolt11,
            payment_hash,
            amount_msat,
            description: description.to_string(),
            expiry_secs,
            created_at: now,
        })
    }

    async fn forget_pending_invoice(&self, payment_hash: &str) -> Result<bool, LightningError> {
        match self.get_payment_status(payment_hash).await {
            Ok(details) if details.direction == PaymentDirection::Incoming => {
                if details.status == PaymentStatus::Pending {
                    return self.cancel_open_invoice(payment_hash).await;
                }
                // LND cancels an expired invoice by itself; it still has to be
                // deleted. A settled invoice stays in the wallet.
                if matches!(details.status, PaymentStatus::Failed | PaymentStatus::Expired) {
                    self.delete_canceled_invoice(payment_hash).await?;
                    return Ok(true);
                }
                self.clear_invoice_expiry(payment_hash);
                Ok(false)
            }
            Ok(_) => {
                self.clear_invoice_expiry(payment_hash);
                Ok(false)
            }
            Err(LightningError::PaymentNotFound(_)) => {
                self.clear_invoice_expiry(payment_hash);
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    async fn purge_expired_pending_invoices(&self, now_unix: u64) -> Result<u32, LightningError> {
        let due: Vec<String> = self
            .invoice_expiries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(_, expires_at)| **expires_at <= now_unix)
            .map(|(hash, _)| hash.clone())
            .collect();
        let mut removed = 0u32;
        for hash in due {
            if self.forget_pending_invoice(&hash).await? {
                removed += 1;
            }
        }
        Ok(removed)
    }

    async fn pending_invoice_expiries(&self) -> Result<Vec<(String, u64)>, LightningError> {
        let listed = self.list_pending_invoice_expiries().await?;
        {
            let mut map = self
                .invoice_expiries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            map.clear();
            for (hash, expires_at) in &listed {
                map.insert(hash.clone(), *expires_at);
            }
        }
        Ok(listed)
    }

    #[instrument(skip(self, bolt11))]
    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        let invoice: lightning_invoice::Bolt11Invoice = bolt11
            .parse()
            .map_err(|e| LightningError::InvalidBolt11(format!("{e}")))?;
        let amount = invoice
            .amount_milli_satoshis()
            .ok_or_else(|| LightningError::PaymentNotDispatched("amountless invoice".into()))?;
        self.pay_invoice_with_fee_limit(bolt11, self.routing_fee_policy.ceiling(amount, None))
            .await
    }

    fn routing_fee_policy(&self) -> konsensus_core::traits::lightning::RoutingFeePolicy {
        self.routing_fee_policy
    }

    async fn pay_invoice_with_fee_limit(
        &self,
        bolt11: &str,
        max_fee_msat: u64,
    ) -> Result<PaymentDetails, LightningError> {
        use bitcoin::hashes::Hash;
        let invoice: lightning_invoice::Bolt11Invoice = bolt11
            .parse()
            .map_err(|e| LightningError::InvalidBolt11(format!("{e}")))?;
        if invoice.amount_milli_satoshis().is_none() {
            return Err(LightningError::PaymentNotDispatched(
                "amountless invoice".into(),
            ));
        }
        let hash = invoice.payment_hash().to_string();
        let mut attempts = self.invoice_attempts.lock().await;
        if attempts.contains(&hash) {
            return Err(LightningError::PaymentNotDispatched(
                "capped payments require a fresh invoice hash".into(),
            ));
        }
        self.require_fresh_invoice(invoice.payment_hash().as_byte_array())
            .await?;
        // Mark BEFORE POST: cancellation or an ambiguous response cannot retry
        // while LND may still be processing the first request.
        attempts.insert(hash);
        drop(attempts); // Unrelated invoices must not wait for this payment stream.

        let body = SendPaymentRequest {
            payment_request: bolt11.to_string(),
            timeout_seconds: "60".to_string(),
            fee_limit_msat: max_fee_msat.to_string(),
        };

        // POST /v2/router/send returns a streaming response.
        // Each line is a JSON object. We read the full body and parse
        // the last complete result.
        let response = self
            .client
            .post(self.api_url("/v2/router/send"))
            .header("Grpc-Metadata-macaroon", &self.config.macaroon_hex)
            .json(&body)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;

        if !response.status().is_success() {
            let status_code = response.status().as_u16();
            let err = self.handle_error(response, "pay_invoice").await;
            if status_code >= 500 {
                self.payment_capable.store(false, Ordering::Relaxed);
            }
            return Err(err);
        }

        let body_text = response
            .text()
            .await
            .map_err(|e| LightningError::Backend(format!("read pay_invoice response: {e}")))?;

        // The streaming response contains newline-separated JSON objects.
        // Parse each line and find the terminal state.
        let mut final_result: Option<PaymentResult> = None;
        for line in body_text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(pr) = serde_json::from_str::<PaymentResponse>(line) {
                if let Some(err) = pr.error {
                    let msg = err.message.unwrap_or_else(|| "unknown error".into());
                    self.payment_capable.store(false, Ordering::Relaxed);
                    return Err(LightningError::PaymentFailed(msg));
                }
                if let Some(result) = pr.result {
                    final_result = Some(result);
                }
            }
        }

        let result = final_result
            .ok_or_else(|| LightningError::PaymentFailed("no payment result in response".into()))?;

        let status_str = result.status.as_deref().unwrap_or("UNKNOWN");
        let status = Self::payment_status_to_status(status_str);

        // Successful payment — mark as capable
        self.payment_capable.store(true, Ordering::Relaxed);

        let payment_hash = result.payment_hash.unwrap_or_default();
        let preimage = result.payment_preimage.filter(|p| {
            !p.is_empty() && p != "0000000000000000000000000000000000000000000000000000000000000000"
        });

        let invoice_msat = invoice
            .amount_milli_satoshis()
            .ok_or_else(|| LightningError::PaymentNotDispatched("amountless invoice".into()))?;
        let reported = match result.value_msat.as_deref() {
            Some(raw) => Some(Self::parse_amount_u64(raw)?),
            None => None,
        };
        // The grant is settled from this amount. It must be the invoice amount,
        // not a missing field read as zero and not a smaller figure that would
        // return the difference to the caller.
        let amount_msat = if status == PaymentStatus::Settled {
            match reported {
                Some(amount) if amount == invoice_msat => amount,
                _ => {
                    return Err(LightningError::Backend(
                        "settled value_msat missing or does not match the invoice; grant not released"
                            .into(),
                    ));
                }
            }
        } else {
            reported.unwrap_or(invoice_msat)
        };
        let fee_msat = match result.fee_msat.as_deref() {
            Some(raw) => Some(Self::parse_amount_u64(raw)?),
            None => None,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        debug!(payment_hash = %payment_hash, status = %status_str, "LND payment completed");

        Ok(PaymentDetails {
            payment_hash,
            preimage,
            amount_msat,
            status,
            direction: PaymentDirection::Outgoing,
            timestamp: now,
            memo: None,
            fee_msat,
        })
    }

    #[instrument(skip(self))]
    async fn get_payment_status(
        &self,
        payment_hash: &str,
    ) -> Result<PaymentDetails, LightningError> {
        // First try looking up as an invoice (incoming payment)
        let url = self.api_url(&format!("/v1/invoice/{payment_hash}"));

        let response = self
            .client
            .get(&url)
            .header("Grpc-Metadata-macaroon", &self.config.macaroon_hex)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;

        if response.status().is_success() {
            let resp: LookupInvoiceResponse = response
                .json()
                .await
                .map_err(|e| LightningError::Backend(format!("parse invoice response: {e}")))?;

            let state = resp.state.as_deref().unwrap_or("OPEN");
            let status = Self::invoice_state_to_status(state);

            let preimage = resp
                .r_preimage
                .and_then(|p| {
                    // LND returns r_preimage as base64
                    Self::decode_r_hash(&p).ok()
                })
                .filter(|p| {
                    !p.is_empty()
                        && p != "0000000000000000000000000000000000000000000000000000000000000000"
                });

            let amount_msat = Self::reported_amount_msat(
                status,
                resp.value_msat.as_deref(),
                resp.value.as_deref(),
            )?;

            let timestamp = resp
                .creation_date
                .as_deref()
                .map(Self::parse_u64)
                .unwrap_or(0);

            return Ok(PaymentDetails {
                payment_hash: payment_hash.to_string(),
                preimage,
                amount_msat,
                status,
                direction: PaymentDirection::Incoming,
                timestamp,
                memo: resp.memo,
                fee_msat: None,
            });
        } else if response.status().as_u16() != 404 {
            return Err(self.handle_error(response, "lookup_invoice").await);
        }

        // If not found as invoice, look up as outgoing payment
        // GET /v2/payments with payment_hash filter is not available in all LND versions,
        // so we list recent payments and filter
        let list_url = self.api_url("/v2/payments?include_incomplete=true&max_payments=100");
        let list_response = self
            .client
            .get(&list_url)
            .header("Grpc-Metadata-macaroon", &self.config.macaroon_hex)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;

        if !list_response.status().is_success() {
            return Err(self.handle_error(list_response, "list_payments").await);
        }

        let list_resp: ListPaymentsResponse = list_response
            .json()
            .await
            .map_err(|e| LightningError::Backend(format!("parse payments list: {e}")))?;

        let payments = list_resp.payments.unwrap_or_default();
        let found = payments
            .iter()
            .find(|p| p.payment_hash.as_deref() == Some(payment_hash));

        match found {
            Some(p) => {
                let status_str = p.status.as_deref().unwrap_or("UNKNOWN");
                let status = Self::payment_status_to_status(status_str);
                let preimage = p
                    .payment_preimage
                    .clone()
                    .filter(|pr| !pr.is_empty() && pr != "0000000000000000000000000000000000000000000000000000000000000000");

                let amount_msat = Self::reported_amount_msat(
                    status,
                    p.value_msat.as_deref(),
                    p.value_sat.as_deref(),
                )?;

                let timestamp = p.creation_date.as_deref().map(Self::parse_u64).unwrap_or(0);

                let fee_msat = match p.fee_msat.as_deref() {
                    Some(raw) => Some(Self::parse_amount_u64(raw)?),
                    None => None,
                };

                Ok(PaymentDetails {
                    payment_hash: payment_hash.to_string(),
                    preimage,
                    amount_msat,
                    status,
                    direction: PaymentDirection::Outgoing,
                    timestamp,
                    memo: None,
                    fee_msat,
                })
            }
            None => Err(LightningError::PaymentNotFound(payment_hash.to_string())),
        }
    }

    #[instrument(skip(self))]
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        let response = self
            .client
            .get(self.api_url("/v1/balance/channels"))
            .header("Grpc-Metadata-macaroon", &self.config.macaroon_hex)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;

        if !response.status().is_success() {
            return Err(self.handle_error(response, "get_balance").await);
        }

        let resp: ChannelBalanceResponse = response
            .json()
            .await
            .map_err(|e| LightningError::Backend(format!("parse channel balance: {e}")))?;

        // Prefer msat. The sat fallback must not wrap: a wrapped balance is a
        // small number, and a later check against it can authorize another spend.
        let balance_msat = if let Some(balance) = &resp.local_balance {
            if let Some(msat) = balance.msat.as_deref() {
                Self::parse_u64(msat)
            } else if let Some(sat) = balance.sat.as_deref() {
                Self::scale_sats(Self::parse_u64(sat))?
            } else {
                0
            }
        } else {
            0
        };

        Ok(balance_msat)
    }

    #[instrument(skip(self))]
    async fn list_payments(&self, limit: u32) -> Result<Vec<PaymentDetails>, LightningError> {
        let url = self.api_url(&format!(
            "/v2/payments?include_incomplete=true&max_payments={}",
            limit.min(100)
        ));

        let response = self
            .client
            .get(&url)
            .header("Grpc-Metadata-macaroon", &self.config.macaroon_hex)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;

        if !response.status().is_success() {
            return Err(self.handle_error(response, "list_payments").await);
        }

        let resp: ListPaymentsResponse = response
            .json()
            .await
            .map_err(|e| LightningError::Backend(format!("parse payments list: {e}")))?;

        let payments = resp
            .payments
            .unwrap_or_default()
            .into_iter()
            .map(|p| -> Result<PaymentDetails, LightningError> {
                let status_str = p.status.as_deref().unwrap_or("UNKNOWN");
                let status = Self::payment_status_to_status(status_str);
                let preimage = p
                    .payment_preimage
                    .filter(|pr| !pr.is_empty() && pr != "0000000000000000000000000000000000000000000000000000000000000000");

                let amount_msat = Self::reported_amount_msat(
                    status,
                    p.value_msat.as_deref(),
                    p.value_sat.as_deref(),
                )?;

                let timestamp = p
                    .creation_date
                    .as_deref()
                    .map(Self::parse_u64)
                    .unwrap_or(0);

                let fee_msat = match p.fee_msat.as_deref() {
                    Some(raw) => Some(Self::parse_amount_u64(raw)?),
                    None => None,
                };

                Ok(PaymentDetails {
                    payment_hash: p.payment_hash.unwrap_or_default(),
                    preimage,
                    amount_msat,
                    status,
                    direction: PaymentDirection::Outgoing,
                    timestamp,
                    memo: None,
                    fee_msat,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(payments)
    }

    #[instrument(skip(self))]
    async fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
        let response = self
            .client
            .get(self.api_url("/v1/channels"))
            .header("Grpc-Metadata-macaroon", &self.config.macaroon_hex)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;

        if !response.status().is_success() {
            return Err(self.handle_error(response, "list_channels").await);
        }

        let resp: ListChannelsResponse = response
            .json()
            .await
            .map_err(|e| LightningError::Backend(format!("parse channels list: {e}")))?;

        let channels = resp
            .channels
            .unwrap_or_default()
            .into_iter()
            .map(|ch| -> Result<ChannelInfo, LightningError> {
                let outbound_capacity_msat = ch.outbound_capacity_msat();
                let capacity_sat = ch.capacity.as_deref().map(Self::parse_u64).unwrap_or(0);
                let local_sat = ch
                    .local_balance
                    .as_deref()
                    .map(Self::parse_u64)
                    .unwrap_or(0);
                let remote_sat = ch
                    .remote_balance
                    .as_deref()
                    .map(Self::parse_u64)
                    .unwrap_or(0);

                Ok(ChannelInfo {
                    is_outbound: None,
                    is_announced: None,
                    is_channel_ready: None,
                    local_reserve_msat: None,
                    initial_push_msat: None,
                    user_channel_id: None,
                    funding_txo: None,
                    // LND identifies channels by chan_id (also surfaced as the scid).
                    channel_id: ch.chan_id.clone().unwrap_or_default(),
                    peer_pubkey: ch.remote_pubkey.unwrap_or_default(),
                    capacity_msat: Self::scale_sats(capacity_sat)?,
                    local_balance_msat: Self::scale_sats(local_sat)?,
                    outbound_capacity_msat,
                    remote_balance_msat: Self::scale_sats(remote_sat)?,
                    active: ch.active.unwrap_or(false),
                    short_channel_id: ch.chan_id,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(channels)
    }

    async fn is_available(&self) -> bool {
        self.get_info().await.is_ok()
    }

    async fn is_payment_capable(&self) -> bool {
        self.payment_capable.load(Ordering::Relaxed)
    }

    #[instrument(skip(self))]
    async fn keysend(
        &self,
        dest_pubkey: &str,
        amount_msat: u64,
        memo: Option<&str>,
    ) -> Result<PaymentDetails, LightningError> {
        self.keysend_with_fee_limit(
            dest_pubkey,
            amount_msat,
            memo,
            self.routing_fee_policy.ceiling(amount_msat, None),
        )
        .await
    }

    async fn keysend_with_fee_limit(
        &self,
        dest_pubkey: &str,
        amount_msat: u64,
        memo: Option<&str>,
        max_fee_msat: u64,
    ) -> Result<PaymentDetails, LightningError> {
        // Generate random preimage for keysend
        let preimage_bytes: [u8; 32] = rand::random();
        let preimage_hex = hex::encode(preimage_bytes);

        // Compute payment_hash = SHA-256(preimage)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(preimage_bytes);
        let hash_bytes = hasher.finalize();
        let payment_hash_hex = hex::encode(hash_bytes);

        // LND's keysend via REST uses the sendpayment endpoint with dest + keysend_preimage
        // The dest must be base64-encoded for the REST API
        let dest_bytes = hex::decode(dest_pubkey).map_err(|e| {
            LightningError::PaymentNotDispatched(format!("invalid dest_pubkey hex: {e}"))
        })?;

        use base64::Engine;
        let dest_b64 = base64::engine::general_purpose::STANDARD.encode(&dest_bytes);
        let preimage_b64 = base64::engine::general_purpose::STANDARD.encode(preimage_bytes);

        #[derive(Serialize)]
        struct KeysendPayload {
            dest: String,
            amt_msat: String,
            timeout_seconds: String,
            fee_limit_msat: String,
            payment_hash: String,
            dest_custom_records: std::collections::HashMap<String, String>,
        }

        let payment_hash_b64 =
            base64::engine::general_purpose::STANDARD.encode(hash_bytes.as_slice());

        let mut custom_records = std::collections::HashMap::new();
        // TLV type 5482373484 is the standard keysend preimage record
        custom_records.insert("5482373484".to_string(), preimage_b64);

        let body = KeysendPayload {
            dest: dest_b64,
            amt_msat: amount_msat.to_string(),
            timeout_seconds: "60".to_string(),
            fee_limit_msat: max_fee_msat.to_string(),
            payment_hash: payment_hash_b64,
            dest_custom_records: custom_records,
        };

        let response = self
            .client
            .post(self.api_url("/v2/router/send"))
            .header("Grpc-Metadata-macaroon", &self.config.macaroon_hex)
            .json(&body)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;

        if !response.status().is_success() {
            return Err(self.handle_error(response, "keysend").await);
        }

        let body_text = response
            .text()
            .await
            .map_err(|e| LightningError::Backend(format!("read keysend response: {e}")))?;

        // Parse streaming response
        let mut final_result: Option<PaymentResult> = None;
        for line in body_text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(pr) = serde_json::from_str::<PaymentResponse>(line) {
                if let Some(err) = pr.error {
                    let msg = err.message.unwrap_or_else(|| "unknown error".into());
                    return Err(LightningError::PaymentFailed(msg));
                }
                if let Some(result) = pr.result {
                    final_result = Some(result);
                }
            }
        }

        let result = final_result
            .ok_or_else(|| LightningError::PaymentFailed("no keysend result in response".into()))?;

        let status_str = result.status.as_deref().unwrap_or("UNKNOWN");
        let status = Self::payment_status_to_status(status_str);

        self.payment_capable.store(true, Ordering::Relaxed);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        debug!(
            payment_hash = %payment_hash_hex,
            dest = %dest_pubkey,
            amount_msat = amount_msat,
            memo = memo.unwrap_or(""),
            "LND keysend completed"
        );

        Ok(PaymentDetails {
            payment_hash: payment_hash_hex,
            preimage: Some(preimage_hex),
            amount_msat,
            status,
            direction: PaymentDirection::Outgoing,
            timestamp: now,
            memo: memo.map(|m| m.to_string()),
            fee_msat: match result.fee_msat.as_deref() {
                Some(raw) => Some(Self::parse_amount_u64(raw)?),
                None => None,
            },
        })
    }

    async fn get_node_pubkey(&self) -> Option<String> {
        match self.get_info().await {
            Ok(info) => info.identity_pubkey,
            Err(e) => {
                tracing::warn!("failed to get LND node pubkey: {e}");
                None
            }
        }
    }

    async fn close_channel(
        &self,
        _channel_id: &str,
        _force: bool,
    ) -> Result<Option<String>, LightningError> {
        Err(LightningError::Backend("close_channel is LDK-only".into()))
    }
}

#[cfg(test)]
#[path = "tests/lnd.rs"]
mod tests;
