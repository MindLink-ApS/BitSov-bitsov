//! LightningProvider trait — abstraction over Lightning Network backends.
//!
//! Implementations: LNbits (HTTP), LND (gRPC), CLN (gRPC), LDK (embedded).

use async_trait::async_trait;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};
use thiserror::Error;


/// Routing-fee authorization, independent of the recipient's principal price.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingFeePolicy {
    /// Minimum ordinary fee allowance, msat.
    pub minimum_msat: u64,
    /// Proportional allowance in parts per million (10,000 = 1%).
    pub proportional_millionths: u64,
    /// Absolute ordinary fee ceiling, msat.
    pub maximum_msat: u64,
}
impl Default for RoutingFeePolicy {
    fn default() -> Self {
        Self { minimum_msat: 5_000, proportional_millionths: 10_000, maximum_msat: 10_000 }
    }
}
impl RoutingFeePolicy {
    /// A caller may tighten, never widen, ordinary routing authority.
    pub fn ceiling(&self, principal: u64, caller: Option<u64>) -> u64 {
        if principal == 0 { return 0; }
        let proportional = (u128::from(principal) * u128::from(self.proportional_millionths) / 1_000_000)
            .min(u128::from(u64::MAX)) as u64;
        proportional.max(self.minimum_msat).min(self.maximum_msat).min(caller.unwrap_or(u64::MAX))
    }
}

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

/// Known wallet categories in satoshis; `None` means unknown, not zero.
///
/// These are estimates from the provider's last sync, not an additive accounting
/// partition: pending sweeps may already overlap the on-chain wallet balance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletBalanceBreakdown {
    /// Spendable on-chain funds, after confirmation requirements and anchor reserve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onchain_spendable_sats: Option<u64>,
    /// Total on-chain wallet funds, including unconfirmed funds and anchor reserve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onchain_total_sats: Option<u64>,
    /// On-chain funds reserved for anchor-channel closure fees; part of onchain_total_sats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_reserve_sats: Option<u64>,
    /// Usable channels' aggregate outbound capacity, rounded down to sats.
    /// Excludes channel reserves and pending HTLCs; not a guaranteed routable payment
    /// amount (route fees, per-HTLC limits, and remote liquidity still apply).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lightning_spendable_sats: Option<u64>,
    /// Known closure claims awaiting confirmation/timelocks, plus all pending sweeps.
    /// Sweep amounts are before sweep fees and may overlap on-chain wallet funds,
    /// including spendable funds while LDK retains confirmed sweeps for reorg safety.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closing_sats: Option<u64>,
    /// Contentious, conditional HTLC, and revoked-counterparty-output claims.
    /// These are potential claims, not guaranteed funds or spendable liquidity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contested_sats: Option<u64>,
}

/// Funding visibility is independent of whether channel negotiation was accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelOpenStatus {
    Opening,
    PendingVisibility,
}

/// Owner's funding preference. Confirmation times are estimates, not deadlines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingPriority {
    Economy,
    #[default]
    Normal,
    Fast,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FundingOptions {
    pub priority: FundingPriority,
    pub max_funding_fee_sats: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundingFeeEstimate {
    pub priority: FundingPriority,
    pub confirmation_target_blocks: u32,
    /// Target blocks times Bitcoin's ten-minute average; NOT time to channel_ready.
    pub expected_confirmation_minutes: u32,
    pub estimated_fee_rate_sat_per_vb: f64,
    pub max_funding_fee_sats: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelOpenResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding_fee: Option<FundingFeeEstimate>,
    pub channel_id: String,
    pub funding_txid: Option<String>,
    pub status: ChannelOpenStatus,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalSpendDiagnostics {
    pub unreadable_rows: u64,
    pub reservations: Vec<LocalSpendReservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSpendReservation {
    pub txid: String,
    pub created_at: u64,
    pub last_seen_at: Option<u64>,
}

/// Information about a Lightning channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    /// Provider-local channel identifier — the SAME string `open_channel` returns
    /// and `close_channel` accepts (LDK: the `user_channel_id`; LND: `chan_id`).
    /// Required so a client that lists channels can close/inspect one without
    /// having to remember the id from the open call. Distinct from
    /// `short_channel_id` (the routing scid, only assigned after confirmation).
    pub channel_id: String,
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

/// A single settled, INBOUND payment surfaced by
/// [`LightningProvider::watch_inbound_keysend`].
///
/// This is the receive-half of "payment is the connection": the node admits a
/// session ON this settled payment, after pairing `binding_tlv` to the matching
/// `UkmEnvelope` and routing it through the unchanged `PaymentGate`. A provider
/// MUST only surface items whose `details.status == Settled` and
/// `details.direction == Incoming`; pending/in-flight/outgoing HTLCs MUST NOT be
/// surfaced.
#[derive(Debug, Clone)]
pub struct InboundPayment {
    /// The settled inbound payment record (hash/preimage/amount, Settled+Incoming).
    /// Feeds the gate's settlement check verbatim.
    pub details: PaymentDetails,
    /// Raw bytes from the application keysend TLV record (ADR-037), if the sender
    /// pushed one; `None` for a bare keysend.
    ///
    /// HONEST FLOOR: this is a *binding* (a `payment_hash` / envelope-id pointer or
    /// digest), NOT necessarily the full `UkmEnvelope` — large payloads stay on the
    /// out-of-band transport and are linked by `payment_hash`.
    pub binding_tlv: Option<Vec<u8>>,
}

/// Node-local admission health, independent of Lightning readiness.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DiskStatus {
    pub disk_low: bool,
    /// None means the filesystem probe failed; new work is refused.
    pub disk_free_bytes: Option<u64>,
    pub disk_free_floor_bytes: u64,
}

/// [`LightningError::PaymentNotDispatched`] reason: a node started with
/// `--remote-unlock` shares new channels only with its configured hub/LSP,
/// because nothing watches its channels while it sits locked.
pub const HUB_ONLY_WHILE_LOCKABLE: &str = "HUB_ONLY_WHILE_LOCKABLE";

/// Errors from Lightning operations.
#[derive(Debug, Error)]
pub enum LightningError {
    /// No operation was dispatched: the backend has not completed safe startup.
    #[error("not_ready: Lightning is offline or synchronizing; retry when money_ready is true")]
    NotReady,

    /// The bounded startup fee barrier could not obtain usable chain data.
    #[error("BOOT_CHAIN_SOURCE_UNAVAILABLE: BitSov could not obtain usable fees from a Bitcoin chain service. Your local identity is saved. Check your connection and try again. (network={network}, service={service}, attempts={attempts}, elapsed_ms={elapsed_ms}, cause={cause})")]
    ChainSourceUnavailable {
        network: String,
        /// Host only; never an authenticated URL or response body.
        service: String,
        attempts: usize,
        elapsed_ms: u64,
        cause: String,
    },

    /// A local startup setting is invalid; retrying the network cannot fix it.
    #[error("BOOT_INVALID_CONFIG: Invalid Lightning configuration: {0}. Check konsensus.toml and try again.")]
    InvalidStartupConfig(String),

    /// This backend cannot issue a quote without retaining unpaid state.
    #[error("stateless_quote_unsupported")]
    StatelessQuoteUnsupported,

    /// Positively proven to have failed BEFORE payment or channel-open dispatch. Only this
    /// variant permits a caller to try another payment path. Never use it for
    /// a response error, timeout, or an unclassified backend/connection error.
    #[error("payment not dispatched: {0}")]
    PaymentNotDispatched(String),

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

/// How current the wallet figures (`get_balance_msat`, `list_channels`) are.
///
/// Feeds the `BitSov-Data-As-Of` / `BitSov-Data-Stale` response headers on
/// `GET /api/v1/payments/balance` and `/payments/channels`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletSync {
    /// Every call queries the backend, so the figures are current as of the
    /// call itself (LNbits, LND: remote query per request).
    Live,
    /// The figures come from a local wallet last synced to the chain tip at
    /// this Unix time in seconds (LDK: background wallet sync).
    SyncedAt(u64),
    /// The local wallet has not completed a sync yet; no time is known.
    NeverSynced,
}

/// Fixed vocabulary: never include RPC responses, credentials, URLs or paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainSyncErrorKind {
    SyncFailed,
    RateLimited,
}

/// An observed failure, not an inference from a stale timestamp or a pruned node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ChainSyncStatus {
    Stalled {
        /// Unix seconds; first failure of the currently failing wallet this run.
        since: u64,
        last_error_kind: ChainSyncErrorKind,
    },
}

/// A bounded, process-local transition history for status polling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessEvent {
    pub sequence: u64,
    pub timestamp: u64,
    pub state: String,
    pub money_ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningReadiness {
    pub money_ready: bool,
    pub state: String,
    pub retry_attempt: u64,
    pub retry_after_secs: Option<u64>,
    pub events: Vec<ReadinessEvent>,
}

/// Abstraction over Lightning Network payment backends.
///
/// This is the critical trait for Principle 2 (Lightning Clearance = Message Gate).
/// Every message must have its payment verified through this interface.
#[async_trait]
pub trait LightningProvider: Send + Sync {
    /// Owner-only cached tower diagnostics; reading never starts network work.
    fn tower_status(&self) -> crate::tower::TowerStatus {
        crate::tower::TowerStatus {
            available: true,
            ..Default::default()
        }
    }

    /// Local diagnostics only. None means no observed failure, not proof of sync.
    fn chain_sync_status(&self) -> Option<ChainSyncStatus> { None }

    /// Supplied by the node's admission wrapper; bare providers have no disk policy.
    fn disk_status(&self) -> Option<DiskStatus> { None }

    /// Safe to perform money operations, distinct from sufficient liquidity.
    async fn money_ready(&self) -> bool { self.is_available().await }

    async fn readiness(&self) -> LightningReadiness {
        let money_ready = self.money_ready().await;
        LightningReadiness { money_ready, state: if money_ready { "ready" } else { "offline" }.into(),
            retry_attempt: 0, retry_after_secs: None, events: Vec::new() }
    }

    /// Whether LSPS2 funding is explicitly enabled on this backend.
    fn liquidity_info(&self) -> super::liquidity::LiquidityInfo { Default::default() }

    /// Negotiate a private funding invoice, bounded by the caller's fee ceiling.
    async fn quote_liquidity(&self, _owner: &str, _gross_msat: u64, _max_fee_msat: u64)
        -> Result<super::liquidity::LiquidityQuote, LightningError> {
        Err(LightningError::Backend("LSPS2 liquidity disabled".into()))
    }

    /// Read immutable terms before reserving fee authority.
    fn liquidity_quote(&self, _owner: &str, _id: &str)
        -> Result<super::liquidity::LiquidityQuote, LightningError> {
        Err(LightningError::Backend("liquidity quote unavailable".into()))
    }

    /// Consume exactly once and publish the prepared invoice. Implementations
    /// must not spawn work that publishes after this future is dropped.
    async fn accept_liquidity(&self, _owner: &str, _id: &str) -> Result<Invoice, LightningError> {
        Err(LightningError::PaymentNotDispatched("liquidity quote unavailable".into()))
    }

    /// Durable funding-purpose exclusion, checked on EVERY admission attempt.
    async fn is_funding_payment(&self, _hash: &str) -> Result<bool, LightningError> { Ok(false) }

    /// Actual settled JIT net and fee, read from the backend's durable payment store.
    async fn liquidity_receipt(&self, _hash: &str)
        -> Result<Option<super::liquidity::LiquidityReceipt>, LightningError> { Ok(None) }

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

    /// Issue a signed quote without retaining any pending invoice/payment record.
    /// Unsupported backends MUST NOT fall back to create_invoice.
    async fn create_stateless_invoice(
        &self,
        _amount_msat: u64,
        _description: &str,
        _expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        Err(LightningError::StatelessQuoteUnsupported)
    }

    /// The policy used by ordinary outgoing payments and pre-dispatch budgets.
    fn routing_fee_policy(&self) -> RoutingFeePolicy { RoutingFeePolicy::default() }

    /// Send with a routing ceiling enforced before dispatch; unsupported backends refuse.
    async fn keysend_with_fee_limit(
        &self, _dest: &str, _amount: u64, _memo: Option<&str>, _max_fee_msat: u64,
    ) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::PaymentNotDispatched("backend cannot enforce keysend routing fee limit".into()))
    }

    /// Pay a BOLT11 invoice.
    ///
    /// Returns payment details once the payment is initiated (may still be in-flight).
    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError>;

    /// Pay with an exact routing-fee ceiling enforced BEFORE dispatch.
    /// This single-use operation must not retry an existing failed payment
    /// hash: callers reconcile by hash across crashes. Serialize any freshness
    /// check with dispatch so an old failure cannot stand for a new attempt.
    /// Unsupported backends fail closed; never use unbounded pay_invoice as
    /// a fallback or discover an overspend only after it has occurred.
    async fn pay_invoice_with_fee_limit(
        &self, _bolt11: &str, _max_fee_msat: u64,
    ) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::PaymentNotDispatched("backend cannot enforce routing fee limit".into()))
    }

    /// Check the status of a payment by its payment hash.
    async fn get_payment_status(
        &self,
        payment_hash: &str,
    ) -> Result<PaymentDetails, LightningError>;

    /// Wake-up hints for outgoing payments: each item is the hex payment hash
    /// of an outgoing payment that may just have reached a terminal state, or
    /// an empty string when hints were dropped (re-check every payment).
    ///
    /// A hint is never proof. Callers re-read
    /// [`get_payment_status`](LightningProvider::get_payment_status) and act
    /// only on what it returns, so a missed or spurious hint changes when they
    /// poll, never what they conclude. Subscribe before the status read the
    /// hint should shortcut. Defaults to `None`: poll on a timer.
    fn outgoing_payment_updates(&self) -> Option<BoxStream<'static, String>> {
        None
    }

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

    /// Read known wallet categories without moving funds. Providers that cannot
    /// determine a category leave it `None`; errors must not become zero balances.
    async fn get_balance_breakdown(&self) -> Result<WalletBalanceBreakdown, LightningError> {
        Ok(WalletBalanceBreakdown::default())
    }

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

    /// How current the figures from `get_balance_msat` / `list_channels` are.
    ///
    /// Default: [`WalletSync::Live`], correct for backends that query a remote
    /// node on every call. Backends that serve from a locally synced wallet
    /// (LDK) must override this.
    async fn wallet_sync(&self) -> WalletSync {
        WalletSync::Live
    }

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
    /// Only `PaymentNotDispatched` guarantees that no payment was initiated.
    /// Every other error is ambiguous: callers must not retry via an invoice.
    /// The default implementation rejects locally without dispatch.
    async fn keysend(
        &self,
        _dest_pubkey: &str,
        _amount_msat: u64,
        _memo: Option<&str>,
    ) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::PaymentNotDispatched(
            "keysend not supported by this provider".into(),
        ))
    }

    /// Send a spontaneous keysend that carries the BitSov payment→envelope
    /// *binding* as a custom keysend TLV record (ADR-037) — the send-half
    /// mirror of [`watch_inbound_keysend`](LightningProvider::watch_inbound_keysend).
    ///
    /// This is the sender's side of "payment is the connection": a node pays its
    /// way onto a counterparty by pushing a settled keysend whose binding TLV
    /// lets the recipient pair the HTLC to the out-of-band `UkmEnvelope` and
    /// route it through `PaymentGate::verify`. It is distinct from
    /// [`keysend`](LightningProvider::keysend) precisely because the caller MUST
    /// be able to supply the binding bytes; a bare keysend cannot.
    ///
    /// # Arguments
    /// * `dest_pubkey` — Destination Lightning node public key (hex).
    /// * `amount_msat` — Amount in millisatoshis (≥ the recipient's published price).
    /// * `binding_tlv` — Non-empty application binding bytes pushed in the
    ///   ADR-037 custom (odd) keysend TLV record. HONEST FLOOR: this is a
    ///   `payment_hash` / envelope-id pointer or digest, NOT necessarily the
    ///   full envelope — bulk ciphertext rides out-of-band on the transport,
    ///   linked by `payment_hash`.
    ///
    /// Default implementation returns `Err(Backend(..))` — fail **closed**. A
    /// backend that cannot attach an application TLV to a keysend MUST refuse
    /// rather than send an *unbindable* payment, which the recipient would be
    /// forced to drop (silently burning the sender's sats). This mirrors the
    /// fail-closed default of [`watch_inbound_keysend`](LightningProvider::watch_inbound_keysend):
    /// neither half of ADR-037 ever degrades to a free or lossy path. Empty
    /// bindings MUST be rejected before payment send/debit because they cannot
    /// bind a payment to an envelope.
    async fn keysend_with_binding(
        &self,
        _dest_pubkey: &str,
        _amount_msat: u64,
        _binding_tlv: &[u8],
    ) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::Backend(
            "binding-TLV keysend not supported by this provider".into(),
        ))
    }

    /// Subscribe to SETTLED, INBOUND payments as they arrive — the receive-half
    /// mirror of [`keysend`](LightningProvider::keysend).
    ///
    /// This is the "payment is the connection" primitive: the node listens for an
    /// unsolicited *settled* inbound payment and admits a session ON that payment,
    /// rather than accepting a free transport handshake and charging per message.
    /// Each yielded [`InboundPayment`] carries the settled [`PaymentDetails`]
    /// (`status == Settled`, `direction == Incoming`) plus any application binding
    /// the sender pushed in a custom keysend TLV record, so the caller can recover
    /// the matching `UkmEnvelope` and route it through `PaymentGate::verify`.
    ///
    /// The returned stream MUST only yield already-settled, incoming records;
    /// pending/in-flight HTLCs MUST NOT be surfaced. Stream-level termination
    /// (backend dropped) ends the stream and the caller re-subscribes.
    ///
    /// Provider streams may be lossy fan-out unless the implementation states a
    /// stronger guarantee. Live admission wiring MUST NOT rely on this stream
    /// alone unless it also provides durable replay/reconciliation (for example,
    /// by polling settled incoming payments) or replaces the provider fan-out
    /// with a non-lossy admission ingress. A missed stream item must fail closed,
    /// never create a free-admission fallback. Admission callers MUST explicitly
    /// inspect [`LightningProvider::inbound_keysend_stream_requires_reconciliation`]
    /// before consuming this stream.
    ///
    /// Default implementation returns `Err(Backend(..))` — a backend that cannot
    /// expose a settled-inbound signal fails **closed**, never degrading to a
    /// free-admission path.
    async fn watch_inbound_keysend(
        &self,
    ) -> Result<BoxStream<'static, InboundPayment>, LightningError> {
        Err(LightningError::Backend(
            "inbound payment subscription not supported by this provider".into(),
        ))
    }

    /// Whether [`watch_inbound_keysend`](LightningProvider::watch_inbound_keysend)
    /// is only a lossy notification stream and therefore requires durable
    /// replay/reconciliation before live admission may consume it.
    ///
    /// Defaults to `true` so new backends fail conservative: until a provider
    /// explicitly proves non-lossy admission ingress, downstream receive→admit
    /// wiring must add reconciliation or refuse to rely on the stream.
    fn inbound_keysend_stream_requires_reconciliation(&self) -> bool {
        true
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
    ///   fee estimator. A supplied rate and the announce flag must be honored.
    ///   If either cannot be enforced, return `PaymentNotDispatched` before
    ///   initiating the channel; never silently fall back to backend defaults.
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
        Err(LightningError::PaymentNotDispatched(
            "open_channel not supported by this provider".into(),
        ))
    }

    /// Detailed result for callers that need to distinguish funding visibility.
    async fn open_channel_with_status(
        &self, peer_pubkey: &str, peer_addr: &str, amount_sats: u64,
        announce: bool, fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<ChannelOpenResult, LightningError> {
        let channel_id = self.open_channel(peer_pubkey, peer_addr, amount_sats, announce, fee_rate_sat_per_vb).await?;
        Ok(ChannelOpenResult { funding_fee: None, channel_id, funding_txid: None, status: ChannelOpenStatus::Opening })
    }

    /// Read-only preview. Unsupported backends must refuse, never invent a quote.
    async fn funding_fee_quote(&self, _options: FundingOptions) -> Result<FundingFeeEstimate, LightningError> {
        Err(LightningError::PaymentNotDispatched("funding priority/fee cap not supported by this provider".into()))
    }

    /// Explicit funding preferences must survive asynchronous transaction construction.
    async fn open_channel_with_funding(
        &self, _peer_pubkey: &str, _peer_addr: &str, _amount_sats: u64,
        _announce: bool, _options: FundingOptions,
    ) -> Result<ChannelOpenResult, LightningError> {
        Err(LightningError::PaymentNotDispatched("funding priority/fee cap not supported by this provider".into()))
    }

    fn local_spend_diagnostics(&self) -> LocalSpendDiagnostics {
        LocalSpendDiagnostics::default()
    }

    /// Explicit abandonment, exposed only to an authenticated owner.
    async fn release_local_spend(&self, _txid: &str) -> Result<(), LightningError> {
        Err(LightningError::Backend("local spend release not supported".into()))
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

    struct QueryPerCall;

    #[async_trait]
    impl LightningProvider for QueryPerCall {
        async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
            Err(LightningError::Backend("unused".into()))
        }
        async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::Backend("unused".into()))
        }
        async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::Backend("unused".into()))
        }
        async fn get_balance_msat(&self) -> Result<u64, LightningError> {
            Ok(0)
        }
        async fn is_available(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn wallet_sync_defaults_to_live() {
        assert_eq!(QueryPerCall.wallet_sync().await, WalletSync::Live);
    }
}

#[cfg(test)]
mod routing_fee_policy_tests {
    use super::*;
    #[test]
    fn default_policy_bounds_small_large_and_overflowing_inputs() {
        let p = RoutingFeePolicy::default();
        for (amount, expected) in [(0,0), (1,5000), (1000,5000), (100_000,5000), (500_000,5000), (1_000_000,10000), (u64::MAX,10000)] {
            assert_eq!(p.ceiling(amount, None), expected);
            assert_eq!(p.ceiling(amount, Some(0)), 0);
            assert_eq!(p.ceiling(amount, Some(u64::MAX)), expected);
        }
        let p = RoutingFeePolicy { minimum_msat: 300, proportional_millionths: u64::MAX, maximum_msat: 700 };
        assert_eq!(p.ceiling(u64::MAX, None), 700);
        assert_eq!(p.ceiling(u64::MAX, Some(500)), 500);
    }
}

#[cfg(test)]
mod chain_rate_limit_tests {
    use super::*;
    #[test]
    fn owner_status_serializes_rate_limited_kind() {
        let status = ChainSyncStatus::Stalled { since: 123, last_error_kind: ChainSyncErrorKind::RateLimited };
        assert_eq!(serde_json::to_value(status).unwrap(), serde_json::json!({
            "state": "stalled", "since": 123, "last_error_kind": "rate_limited"
        }));
    }
}
