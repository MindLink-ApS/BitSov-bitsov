//! LNbits HTTP provider — communicates with an LNbits instance via REST API.
//!
//! Ported from v1's `lnbits.provider.ts`. This is the fastest path to a
//! working payment gate since LNbits is widely deployed and simple to configure.
//!
//! # LNbits API endpoints used
//!
//! - `POST /api/v1/payments` (out=false) — create invoice
//! - `POST /api/v1/payments` (out=true) — pay invoice
//! - `GET  /api/v1/payments/{payment_hash}` — check payment status
//! - `GET  /api/v1/wallet` — get wallet balance
//!
//! Auth: `X-Api-Key` header with the wallet's admin key.

use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, warn};

use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails, PaymentDirection, PaymentStatus,
};

/// Configuration for the LNbits provider.
#[derive(Debug, Clone)]
pub struct LnbitsConfig {
    /// Base URL of the LNbits instance (e.g. `http://localhost:5000`).
    pub api_url: String,
    /// Admin key for the wallet (required for creating invoices and paying).
    pub admin_key: String,
}

/// LNbits HTTP provider implementing `LightningProvider`.
///
/// Tracks payment capability via an atomic flag that gets set to `false` when
/// a payment fails with a funding-source error (e.g. LND wallet locked →
/// LNbits VoidWallet). The flag is cleared on any successful payment.
/// This ensures `is_available()` reflects actual payment capability, not just
/// whether the LNbits API is reachable.
pub struct LnbitsProvider {
    config: LnbitsConfig,
    client: Client,
    /// Set to `false` when a payment fails due to a funding-source issue
    /// (VoidWallet, locked wallet, etc.). Reset to `true` on successful payment.
    pub(crate) payment_capable: AtomicBool,
}

// ── LNbits API request/response types ──────────────────────────────────

#[derive(Serialize)]
struct CreateInvoiceRequest {
    out: bool,
    amount: u64,
    memo: String,
    expiry: u32,
    unit: String,
}

#[derive(Serialize)]
struct PayInvoiceRequest {
    out: bool,
    bolt11: String,
}

#[derive(Debug, Deserialize)]
struct LnbitsInvoiceResponse {
    payment_hash: Option<String>,
    #[serde(alias = "paymentHash")]
    payment_hash_alt: Option<String>,
    bolt11: Option<String>,
    payment_request: Option<String>,
}

impl LnbitsInvoiceResponse {
    fn payment_hash(&self) -> Option<&str> {
        self.payment_hash
            .as_deref()
            .or(self.payment_hash_alt.as_deref())
    }

    fn bolt11(&self) -> Option<&str> {
        self.bolt11.as_deref().or(self.payment_request.as_deref())
    }
}

#[derive(Debug, Deserialize)]
struct LnbitsPaymentResponse {
    payment_hash: Option<String>,
    #[serde(alias = "paymentHash")]
    payment_hash_alt: Option<String>,
}

impl LnbitsPaymentResponse {
    fn payment_hash(&self) -> Option<&str> {
        self.payment_hash
            .as_deref()
            .or(self.payment_hash_alt.as_deref())
    }
}

#[derive(Debug, Deserialize)]
struct LnbitsPaymentCheckResponse {
    paid: Option<bool>,
    settled: Option<bool>,
    expired: Option<bool>,
    memo: Option<String>,
    fee: Option<i64>,
    details: Option<LnbitsPaymentDetails>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LnbitsPaymentDetails {
    payment_hash: Option<String>,
    #[serde(alias = "paymentHash")]
    payment_hash_alt: Option<String>,
    preimage: Option<String>,
    amount: Option<i64>,
    pending: Option<bool>,
    bolt11: Option<String>,
    time: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct LnbitsWalletResponse {
    balance: Option<i64>,
    #[serde(alias = "balance_msat")]
    balance_msat: Option<i64>,
}

/// Entry from `GET /api/v1/payments?limit=N`.
#[derive(Debug, Deserialize)]
struct LnbitsPaymentListEntry {
    payment_hash: Option<String>,
    #[serde(alias = "paymentHash")]
    payment_hash_alt: Option<String>,
    /// Amount in msat (negative = outgoing).
    amount: Option<i64>,
    fee: Option<i64>,
    memo: Option<String>,
    status: Option<String>,
    preimage: Option<String>,
    time: Option<f64>,
}

impl LnbitsPaymentListEntry {
    fn payment_hash(&self) -> String {
        self.payment_hash
            .as_deref()
            .or(self.payment_hash_alt.as_deref())
            .unwrap_or_default()
            .to_string()
    }
}

impl LnbitsProvider {
    /// Create a new LNbits provider with the given configuration.
    ///
    /// Returns an error if the HTTP client cannot be built (e.g. TLS
    /// backend unavailable).
    pub fn new(config: LnbitsConfig) -> Result<Self, LightningError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| LightningError::Backend(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            config,
            client,
            payment_capable: AtomicBool::new(true),
        })
    }

    /// Create a provider with a custom reqwest Client (for testing).
    pub fn with_client(config: LnbitsConfig, client: Client) -> Self {
        Self {
            config,
            client,
            payment_capable: AtomicBool::new(true),
        }
    }

    /// Probes whether the LNbits funding source can actually process payments.
    ///
    /// Creates a 1-sat invoice and attempts self-payment. If the funding source
    /// is VoidWallet (e.g. LND wallet is locked), the payment fails immediately
    /// with a distinctive error and `payment_capable` is set to `false`.
    ///
    /// Call this once at startup to get accurate health reporting from the start,
    /// rather than waiting for the first real payment to fail.
    pub async fn probe_payment_capability(&self) {
        // First check if LNbits is reachable at all
        let available = self
            .client
            .get(self.api_url("/api/v1/wallet"))
            .header("X-Api-Key", &self.config.admin_key)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);

        if !available {
            warn!("LNbits API unreachable during payment capability probe");
            self.payment_capable.store(false, Ordering::Relaxed);
            return;
        }

        // Try to create and self-pay a 1-sat invoice.
        // VoidWallet will fail the payment with "VoidWallet cannot pay invoices".
        let invoice = match LightningProvider::create_invoice(self, 1000, "capability-probe", 60).await {
            Ok(inv) => inv,
            Err(e) => {
                warn!(error = %e, "cannot create invoices — marking payment-incapable");
                self.payment_capable.store(false, Ordering::Relaxed);
                return;
            }
        };

        match LightningProvider::pay_invoice(self, &invoice.bolt11).await {
            Ok(_) => {
                debug!("payment capability probe succeeded — funding source is live");
                // payment_capable is already set to true by pay_invoice success path
            }
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("VoidWallet") || msg.contains("void wallet") {
                    warn!("LNbits funding source is VoidWallet (LND wallet likely locked) — outbound payments disabled");
                    // payment_capable already set to false by pay_invoice 5xx handler
                } else {
                    // Other errors (e.g. insufficient balance for self-pay) don't
                    // necessarily mean the funding source is broken
                    debug!(error = %e, "payment capability probe failed (non-fatal)");
                }
            }
        }
    }

    /// Build the API URL for a given path.
    fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.config.api_url.trim_end_matches('/'), path)
    }

    /// Convert an LNbits API error response into a LightningError.
    async fn handle_error(
        &self,
        response: reqwest::Response,
        context: &str,
    ) -> LightningError {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        warn!(status = %status, body = %body, "{context} failed");

        if status.as_u16() == 401 || status.as_u16() == 403 {
            LightningError::Auth(format!("{context}: {status} — {body}"))
        } else {
            LightningError::Backend(format!("{context}: {status} — {body}"))
        }
    }
}

#[async_trait]
impl LightningProvider for LnbitsProvider {
    #[instrument(skip(self), fields(amount_msat, description))]
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        // LNbits expects amount in sats for the standard unit
        let amount_sats = amount_msat / 1000;
        if amount_sats == 0 {
            return Err(LightningError::InvoiceCreation(
                "amount must be at least 1000 msat (1 sat)".into(),
            ));
        }

        let body = CreateInvoiceRequest {
            out: false,
            amount: amount_sats,
            memo: description.to_string(),
            expiry: expiry_secs,
            unit: "sat".to_string(),
        };

        let response = self
            .client
            .post(self.api_url("/api/v1/payments"))
            .header("X-Api-Key", &self.config.admin_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;

        if !response.status().is_success() {
            return Err(self.handle_error(response, "create_invoice").await);
        }

        let resp: LnbitsInvoiceResponse = response
            .json()
            .await
            .map_err(|e| LightningError::Backend(format!("parse response: {e}")))?;

        let payment_hash = resp
            .payment_hash()
            .ok_or_else(|| LightningError::InvoiceCreation("no payment_hash in response".into()))?
            .to_string();

        let bolt11 = resp
            .bolt11()
            .ok_or_else(|| LightningError::InvoiceCreation("no bolt11 in response".into()))?
            .to_string();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        debug!(payment_hash = %payment_hash, "invoice created");

        Ok(Invoice {
            bolt11,
            payment_hash,
            amount_msat,
            description: description.to_string(),
            expiry_secs,
            created_at: now,
        })
    }

    #[instrument(skip(self, bolt11))]
    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        let body = PayInvoiceRequest {
            out: true,
            bolt11: bolt11.to_string(),
        };

        let response = self
            .client
            .post(self.api_url("/api/v1/payments"))
            .header("X-Api-Key", &self.config.admin_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;

        if !response.status().is_success() {
            let status_code = response.status().as_u16();
            let err = self.handle_error(response, "pay_invoice").await;
            // Mark as payment-incapable on funding-source errors (5xx from LNbits
            // typically means VoidWallet / locked LND wallet)
            if status_code >= 500 {
                self.payment_capable.store(false, Ordering::Relaxed);
            }
            return Err(err);
        }

        // Successful payment — ensure the capability flag is set
        self.payment_capable.store(true, Ordering::Relaxed);

        let resp: LnbitsPaymentResponse = response
            .json()
            .await
            .map_err(|e| LightningError::Backend(format!("parse response: {e}")))?;

        let payment_hash = resp
            .payment_hash()
            .ok_or_else(|| LightningError::PaymentFailed("no payment_hash in response".into()))?
            .to_string();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        debug!(payment_hash = %payment_hash, "payment sent");

        // Payment is in-flight; caller should poll get_payment_status for settlement
        Ok(PaymentDetails {
            payment_hash,
            preimage: None,
            amount_msat: 0, // Amount not known until settled
            status: PaymentStatus::InFlight,
            direction: PaymentDirection::Outgoing,
            timestamp: now,
            memo: None,
            fee_msat: None,
        })
    }

    #[instrument(skip(self))]
    async fn get_payment_status(
        &self,
        payment_hash: &str,
    ) -> Result<PaymentDetails, LightningError> {
        let url = self.api_url(&format!("/api/v1/payments/{payment_hash}"));

        let response = self
            .client
            .get(url)
            .header("X-Api-Key", &self.config.admin_key)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;

        if response.status().as_u16() == 404 {
            return Err(LightningError::PaymentNotFound(payment_hash.to_string()));
        }

        if !response.status().is_success() {
            return Err(self.handle_error(response, "get_payment_status").await);
        }

        let resp: LnbitsPaymentCheckResponse = response
            .json()
            .await
            .map_err(|e| LightningError::Backend(format!("parse response: {e}")))?;

        let is_paid = resp.paid.unwrap_or(false) || resp.settled.unwrap_or(false);
        let is_expired = resp.expired.unwrap_or(false);

        let status = if is_paid {
            PaymentStatus::Settled
        } else if is_expired {
            PaymentStatus::Expired
        } else {
            PaymentStatus::Pending
        };

        let (preimage, amount_msat, timestamp) = match &resp.details {
            Some(d) => {
                let pre = d.preimage.clone();
                // LNbits amount is in msat (negative for outgoing)
                let amt = d.amount.map(|a| a.unsigned_abs()).unwrap_or_else(|| {
                    warn!(payment_hash, "LNbits payment details missing amount field, defaulting to 0");
                    0
                });
                let raw_time = d.time.unwrap_or_else(|| {
                    warn!(payment_hash, "LNbits payment details missing time field, defaulting to 0");
                    0
                });
                let ts = u64::try_from(raw_time).unwrap_or_else(|_| {
                    warn!(payment_hash, raw_time, "LNbits payment has negative timestamp, clamping to 0");
                    0
                });
                (pre, amt, ts)
            }
            None => {
                warn!(payment_hash, "LNbits payment response missing details block");
                (None, 0, 0)
            }
        };

        // Determine direction from amount sign
        let direction = match &resp.details {
            Some(d) => {
                if d.amount.unwrap_or(0) < 0 {
                    PaymentDirection::Outgoing
                } else {
                    PaymentDirection::Incoming
                }
            }
            None => PaymentDirection::Incoming,
        };

        // Fee is in msat (LNbits reports as positive msat)
        let fee_msat = resp.fee.map(|f| f.unsigned_abs());

        Ok(PaymentDetails {
            payment_hash: payment_hash.to_string(),
            preimage,
            amount_msat,
            status,
            direction,
            timestamp,
            memo: resp.memo,
            fee_msat,
        })
    }

    #[instrument(skip(self))]
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        let response = self
            .client
            .get(self.api_url("/api/v1/wallet"))
            .header("X-Api-Key", &self.config.admin_key)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;

        if !response.status().is_success() {
            return Err(self.handle_error(response, "get_balance").await);
        }

        let resp: LnbitsWalletResponse = response
            .json()
            .await
            .map_err(|e| LightningError::Backend(format!("parse response: {e}")))?;

        // LNbits returns balance in msat
        let balance = resp
            .balance_msat
            .or(resp.balance.map(|b| b * 1000))
            .unwrap_or_else(|| {
                warn!("LNbits wallet response missing both balance_msat and balance fields, defaulting to 0");
                0
            });

        // Negative balance (debt state) should not silently become a huge positive number
        if balance < 0 {
            warn!(balance, "LNbits reported negative balance (debt state), clamping to 0");
        }
        Ok(u64::try_from(balance).unwrap_or(0))
    }

    #[instrument(skip(self))]
    async fn list_payments(&self, limit: u32) -> Result<Vec<PaymentDetails>, LightningError> {
        let url = format!(
            "{}/api/v1/payments?limit={}",
            self.config.api_url.trim_end_matches('/'),
            limit.min(100) // Cap at 100 to avoid excessive responses
        );

        let response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.admin_key)
            .send()
            .await
            .map_err(|e| LightningError::Connection(e.to_string()))?;

        if !response.status().is_success() {
            return Err(self.handle_error(response, "list_payments").await);
        }

        let entries: Vec<LnbitsPaymentListEntry> = response
            .json()
            .await
            .map_err(|e| LightningError::Backend(format!("parse payments list: {e}")))?;

        let payments = entries
            .into_iter()
            .map(|e| {
                let hash_display = e.payment_hash();
                let amount_raw = e.amount.unwrap_or_else(|| {
                    warn!(payment_hash = %hash_display, "LNbits payment list entry missing amount, defaulting to 0");
                    0
                });
                let direction = if amount_raw < 0 {
                    PaymentDirection::Outgoing
                } else {
                    PaymentDirection::Incoming
                };
                let amount_msat = amount_raw.unsigned_abs();

                let status_str = e.status.as_deref().unwrap_or("pending");
                let status = match status_str {
                    "success" => PaymentStatus::Settled,
                    "failed" => PaymentStatus::Failed,
                    "expired" => PaymentStatus::Expired,
                    _ => PaymentStatus::Pending,
                };

                // LNbits `time` is a float Unix timestamp — clamp negative/NaN to 0
                let timestamp = e.time
                    .filter(|t| t.is_finite())
                    .map(|t| t.max(0.0) as u64)
                    .unwrap_or(0);
                let fee_msat = e.fee.map(|f| f.unsigned_abs());

                PaymentDetails {
                    payment_hash: hash_display,
                    preimage: e.preimage,
                    amount_msat,
                    status,
                    direction,
                    timestamp,
                    memo: e.memo,
                    fee_msat,
                }
            })
            .collect();

        Ok(payments)
    }

    async fn is_available(&self) -> bool {
        self.client
            .get(self.api_url("/api/v1/wallet"))
            .header("X-Api-Key", &self.config.admin_key)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn is_payment_capable(&self) -> bool {
        self.payment_capable.load(Ordering::Relaxed)
    }
}
