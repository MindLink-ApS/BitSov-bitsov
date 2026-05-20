//! LightningProvider trait — abstraction over Lightning Network backends.
//!
//! Implementations: LNbits (HTTP), LND (gRPC), CLN (gRPC), LDK (embedded).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Status of a Lightning payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PaymentStatus {
    /// Invoice created, awaiting payment.
    Pending,
    /// Payment is in-flight (HTLC sent but not yet settled).
    InFlight,
    /// Payment completed successfully — preimage available.
    Settled,
    /// Payment failed (expired, no route, insufficient balance, etc.).
    Failed,
    /// Invoice expired without payment.
    Expired,
}

/// Direction of a payment (from this node's perspective).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PaymentDirection {
    /// Incoming payment (we created the invoice, someone paid us).
    Incoming,
    /// Outgoing payment (we paid someone else's invoice).
    Outgoing,
}

/// Details of a Lightning invoice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    /// BOLT11 payment request string.
    pub bolt11: String,
    /// Payment hash (hex, 32 bytes).
    pub payment_hash: String,
    /// Amount in millisatoshis.
    pub amount_msat: u64,
    /// Human-readable description / memo.
    pub description: String,
    /// Expiry time in seconds from creation.
    pub expiry_secs: u32,
    /// Unix timestamp (seconds) when the invoice was created.
    pub created_at: u64,
}

/// Information about a Lightning channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    /// Remote peer's public key (hex).
    pub peer_pubkey: String,
    /// Total channel capacity in millisatoshis.
    pub capacity_msat: u64,
    /// Local balance in millisatoshis.
    pub local_balance_msat: u64,
    /// Remote balance in millisatoshis.
    pub remote_balance_msat: u64,
    /// Whether the channel is active (can route payments).
    pub active: bool,
    /// Short channel ID (if assigned).
    pub short_channel_id: Option<String>,
}

/// Details of a completed or in-progress payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentDetails {
    /// Payment hash (hex, 32 bytes).
    pub payment_hash: String,
    /// Payment preimage (hex, 32 bytes). Only present when settled.
    pub preimage: Option<String>,
    /// Amount in millisatoshis.
    pub amount_msat: u64,
    /// Current status.
    pub status: PaymentStatus,
    /// Direction (incoming/outgoing).
    pub direction: PaymentDirection,
    /// Unix timestamp (seconds) when the payment was initiated or received.
    pub timestamp: u64,
    /// Optional memo/description attached to the payment.
    #[serde(default)]
    pub memo: Option<String>,
    /// Fee paid in millisatoshis (outgoing only).
    #[serde(default)]
    pub fee_msat: Option<u64>,
}

/// Errors from Lightning operations.
#[derive(Debug, Error)]
pub enum LightningError {
    /// Invoice creation failed.
    #[error("invoice creation failed: {0}")]
    InvoiceCreation(String),

    /// Payment sending failed.
    #[error("payment failed: {0}")]
    PaymentFailed(String),

    /// Payment not found by hash.
    #[error("payment not found: {0}")]
    PaymentNotFound(String),

    /// Invalid BOLT11 string.
    #[error("invalid bolt11: {0}")]
    InvalidBolt11(String),

    /// Backend connection error.
    #[error("connection error: {0}")]
    Connection(String),

    /// Authentication / permission error.
    #[error("auth error: {0}")]
    Auth(String),

    /// General backend error.
    #[error("lightning backend error: {0}")]
    Backend(String),

    /// On-chain broadcast was initiated by the backend, but the chain
    /// provider could not verify the transaction is visible (mempool or
    /// chain) within the verification timeout.
    ///
    /// L0f (2026-04-30): added to surface the documented 2026-04-23
    /// `ba91a6ac…45ef` silent-fail incident class — LDK returned a txid
    /// from `send_to_address` that never propagated to the network. The
    /// API layer should translate this to HTTP 202 Accepted with the
    /// txid in the response body so the caller can poll until the tx is
    /// confirmed (or give up and replace it).
    #[error("on-chain broadcast unconfirmed within timeout: txid={txid}")]
    BroadcastUnconfirmed {
        /// The txid returned by the backend before the verification timeout.
        txid: String,
    },
}

/// Abstraction over Lightning Network payment backends.
///
/// This is the critical trait for Principle 2 (Lightning Clearance = Message Gate).
/// Every message must have its payment verified through this interface.
#[async_trait]
pub trait LightningProvider: Send + Sync {
    /// Create an invoice for receiving a payment.
    ///
    /// # Arguments
    /// * `amount_msat` — Amount in millisatoshis.
    /// * `description` — Human-readable description / memo.
    /// * `expiry_secs` — Invoice expiry in seconds (default: 3600).
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError>;

    /// Pay a BOLT11 invoice.
    ///
    /// Returns payment details once the payment is initiated (may still be in-flight).
    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError>;

    /// Check the status of a payment by its payment hash.
    async fn get_payment_status(
        &self,
        payment_hash: &str,
    ) -> Result<PaymentDetails, LightningError>;

    /// Verify that a payment has been settled and return the preimage.
    ///
    /// This is the core method for the payment gate: given a payment hash,
    /// confirm that it has been paid and return the preimage as proof.
    async fn verify_payment(&self, payment_hash: &str) -> Result<PaymentDetails, LightningError> {
        let details = self.get_payment_status(payment_hash).await?;
        if details.status != PaymentStatus::Settled {
            return Err(LightningError::PaymentFailed(format!(
                "payment not settled, status: {:?}",
                details.status
            )));
        }
        Ok(details)
    }

    /// Get the node's Lightning balance in millisatoshis.
    async fn get_balance_msat(&self) -> Result<u64, LightningError>;

    /// List recent payments (both incoming and outgoing).
    ///
    /// # Arguments
    /// * `limit` — Maximum number of payments to return.
    ///
    /// Default implementation returns an empty list for backends that
    /// don't support payment listing.
    async fn list_payments(&self, _limit: u32) -> Result<Vec<PaymentDetails>, LightningError> {
        Ok(Vec::new())
    }

    /// List open Lightning channels with capacity information.
    ///
    /// Default implementation returns an empty list for backends that
    /// don't support channel listing.
    async fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
        Ok(Vec::new())
    }

    /// Check whether the Lightning backend is connected and operational.
    async fn is_available(&self) -> bool;

    /// Cleanly shut down the Lightning backend.
    ///
    /// L0e (2026-04-30): explicit shutdown hook called from the node's
    /// graceful-shutdown path BEFORE the tokio runtime begins teardown.
    /// Required for LDK-backed providers because LDK queues
    /// `ChannelMonitor` updates for `Persister::persist()` on shutdown,
    /// and that persistence MUST complete before the runtime tears down
    /// — otherwise the queued updates are silently lost (real-fund-loss
    /// class on a live channel).
    ///
    /// The default implementation is a no-op for backends that don't need
    /// explicit shutdown (LND/CLN gRPC clients, mock, void). LDK overrides
    /// this to invoke `node.stop()` from a blocking-pool thread.
    ///
    /// Callers should bound this with a wall-clock timeout (15s is
    /// recommended) so a misbehaving backend cannot block process exit.
    async fn shutdown(&self) -> Result<(), LightningError> {
        Ok(())
    }

    /// Check whether the Lightning backend can currently send outbound payments.
    ///
    /// This distinguishes between "Lightning is reachable" (`is_available`) and
    /// "this node can pay invoices" — a VoidWallet or depleted channel will
    /// return `true` for availability but `false` for payment capability.
    ///
    /// Default implementation returns `true` when Lightning is available,
    /// assuming most backends that are "up" can also pay.
    async fn is_payment_capable(&self) -> bool {
        self.is_available().await
    }

    /// Send a keysend (spontaneous) payment to a node without an invoice.
    ///
    /// Keysend enables push payments and streaming (e.g., pay-per-10-seconds
    /// for VoIP, continuous micropayments). The sender generates the preimage
    /// and pushes it along with the payment via a TLV record.
    ///
    /// # Arguments
    /// * `dest_pubkey` — Destination Lightning node public key (hex).
    /// * `amount_msat` — Amount in millisatoshis.
    /// * `memo` — Optional memo attached via custom TLV.
    ///
    /// Default implementation returns `Err(Backend("keysend not supported"))`.
    async fn keysend(
        &self,
        _dest_pubkey: &str,
        _amount_msat: u64,
        _memo: Option<&str>,
    ) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::Backend(
            "keysend not supported by this provider".into(),
        ))
    }

    /// Create a HODL invoice — payment is held until the preimage is released.
    ///
    /// HODL invoices enable escrow, subscription confirmations, and conditional
    /// delivery. The payment is locked in the HTLC until `settle_hodl_invoice`
    /// is called with the preimage, or it times out and is cancelled.
    ///
    /// # Arguments
    /// * `payment_hash` — The payment hash (hex, 32 bytes). Caller generates
    ///   a random preimage and provides SHA-256(preimage) here.
    /// * `amount_msat` — Amount in millisatoshis.
    /// * `description` — Human-readable description.
    /// * `expiry_secs` — Invoice expiry in seconds.
    ///
    /// Default implementation returns `Err(Backend("HODL invoices not supported"))`.
    async fn create_hodl_invoice(
        &self,
        _payment_hash: &str,
        _amount_msat: u64,
        _description: &str,
        _expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        Err(LightningError::Backend(
            "HODL invoices not supported by this provider".into(),
        ))
    }

    /// Settle a HODL invoice by releasing the preimage.
    ///
    /// This completes the payment — the sender's funds are transferred to us.
    /// Must be called before the invoice expires, otherwise the payment is
    /// automatically cancelled.
    ///
    /// # Arguments
    /// * `preimage` — The preimage (hex, 32 bytes) that hashes to the
    ///   payment_hash used in `create_hodl_invoice`.
    ///
    /// Default implementation returns `Err(Backend("HODL invoices not supported"))`.
    async fn settle_hodl_invoice(&self, _preimage: &str) -> Result<(), LightningError> {
        Err(LightningError::Backend(
            "HODL invoices not supported by this provider".into(),
        ))
    }

    /// Cancel a HODL invoice, releasing the sender's locked funds.
    ///
    /// # Arguments
    /// * `payment_hash` — The payment hash (hex, 32 bytes) of the HODL invoice.
    ///
    /// Default implementation returns `Err(Backend("HODL invoices not supported"))`.
    async fn cancel_hodl_invoice(&self, _payment_hash: &str) -> Result<(), LightningError> {
        Err(LightningError::Backend(
            "HODL invoices not supported by this provider".into(),
        ))
    }

    /// Get this node's Lightning public key (hex-encoded compressed pubkey).
    ///
    /// Used for keysend: peers need our Lightning pubkey to push payments
    /// without an invoice. Exchanged via `Frame::LightningInfo` after the
    /// federation handshake.
    ///
    /// Returns `None` if the provider doesn't expose a node pubkey
    /// (e.g., LNbits is a wallet abstraction, not a full node).
    async fn get_node_pubkey(&self) -> Option<String> {
        None
    }

    /// Get a new on-chain Bitcoin address for funding this node's wallet.
    async fn get_funding_address(&self) -> Option<String> {
        None
    }

    /// Send on-chain Bitcoin to an address. Returns the transaction ID.
    ///
    /// # Arguments
    /// * `address` — Destination Bitcoin address.
    /// * `amount_sats` — Amount in satoshis.
    /// * `fee_rate_sat_per_vb` — Optional fee rate override in sat/vB.
    ///   If `None`, the backend selects a rate from its fee estimator.
    ///   Must be > 0 if provided.
    async fn send_onchain(
        &self,
        _address: &str,
        _amount_sats: u64,
        _fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<String, LightningError> {
        Err(LightningError::Backend("send_onchain not supported".into()))
    }

    /// Open a Lightning channel to a peer.
    ///
    /// # Arguments
    /// * `peer_pubkey` — Hex-encoded Lightning public key of the peer.
    /// * `peer_addr` — Network address of the peer (host:port).
    /// * `amount_sats` — Channel capacity in satoshis.
    /// * `announce` — Whether to announce the channel publicly.
    /// * `fee_rate_sat_per_vb` — Optional fee rate override in sat/vB for the
    ///   funding transaction. If `None`, the backend selects a rate from its
    ///   fee estimator. Must be > 0 if provided. Not all backends support this;
    ///   unsupported backends silently ignore it.
    ///
    /// Returns the temporary channel ID on success.
    async fn open_channel(
        &self,
        _peer_pubkey: &str,
        _peer_addr: &str,
        _amount_sats: u64,
        _announce: bool,
        _fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<String, LightningError> {
        Err(LightningError::Backend(
            "open_channel not supported by this provider".into(),
        ))
    }

    /// Close a Lightning channel by user channel ID.
    ///
    /// Returns `Some(txid)` when the backend can report a closing transaction
    /// immediately. LDK 0.7 initiates closure without returning a txid, so
    /// callers must poll channel/on-chain state when this returns `None`.
    async fn close_channel(
        &self,
        _channel_id: &str,
        _force: bool,
    ) -> Result<Option<String>, LightningError> {
        Err(LightningError::Backend(
            "close_channel not supported by this provider".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_status_values() {
        assert_ne!(PaymentStatus::Pending, PaymentStatus::Settled);
        assert_ne!(PaymentStatus::InFlight, PaymentStatus::Failed);
    }

    #[test]
    fn lightning_error_display() {
        let err = LightningError::PaymentFailed("no route".into());
        assert!(err.to_string().contains("no route"));
    }

    #[test]
    fn keysend_error_display() {
        let err = LightningError::Backend("keysend not supported by this provider".into());
        assert!(err.to_string().contains("keysend not supported"));
    }

    #[test]
    fn payment_direction_values() {
        assert_ne!(PaymentDirection::Incoming, PaymentDirection::Outgoing);
    }

    #[test]
    fn invoice_serialization() {
        let invoice = Invoice {
            bolt11: "lnbc1...".into(),
            payment_hash: "ab".repeat(32),
            amount_msat: 1000,
            description: "test".into(),
            expiry_secs: 3600,
            created_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&invoice).unwrap();
        let deserialized: Invoice = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.amount_msat, 1000);
    }
}
