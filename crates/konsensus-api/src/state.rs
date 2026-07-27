//! Shared application state — passed to all handlers via Axum's state extractor.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use tokio::sync::{broadcast, oneshot, Mutex, RwLock};

use konsensus_core::gate::PaymentGate;
use konsensus_core::identity::NodeIdentity;
use konsensus_core::traits::chain::ChainProvider;
use konsensus_core::traits::lightning::LightningProvider;
use konsensus_core::traits::pricing::PricingEngine;
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::types::{MessageId, NodeId};
use konsensus_core::UkmEnvelope;
use konsensus_crypto::{PlaintextCacheCipher, SessionManager};
use konsensus_message::PeerRegistry;
use konsensus_pricing::PeerPriceCache;
use konsensus_routing::RoutingTable;
use konsensus_storage::Storage;

use crate::audit::AuditLog;
use crate::rate_limit::RateLimiter;

/// A message broadcast to WebSocket clients.
///
/// Contains the full UKM envelope (for verification/metadata) plus the
/// decrypted plaintext when available. The node decrypts incoming messages
/// using the Double Ratchet session — plaintext is only delivered over the
/// local (127.0.0.1) WebSocket connection.
#[derive(Debug, Clone, Serialize)]
pub struct WsMessage {
    /// The full UKM envelope (ciphertext, signature, payment proof, etc.).
    #[serde(flatten)]
    pub envelope: UkmEnvelope,

    /// Decrypted plaintext (UTF-8 content). `None` if the message could
    /// not be decrypted (e.g., no E2EE session established yet).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext: Option<String>,
}

/// Delivery status update broadcast to WebSocket clients.
///
/// Sent when a `MessageAck` or `MessageReject` is received from a peer,
/// allowing the frontend to update message delivery indicators in real time
/// instead of showing static/decorative checkmarks.
#[derive(Debug, Clone, Serialize)]
pub struct WsDeliveryStatus {
    /// Discriminator field so the frontend can distinguish this from messages.
    #[serde(rename = "type")]
    pub event_type: &'static str,
    /// The message ID this status update applies to (hex-encoded).
    pub message_id: String,
    /// Delivery status: `"delivered"` or `"rejected"`.
    pub status: String,
    /// Reason for rejection (only present when `status == "rejected"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Shared state for the API server.
///
/// All fields are `Arc`-wrapped so cloning is cheap (required by Axum).
#[derive(Clone)]
pub struct AppState {
    /// The node's cryptographic identity.
    pub identity: Arc<NodeIdentity>,

    /// Storage backend.
    pub storage: Arc<dyn Storage>,

    /// Lightning provider.
    pub lightning: Arc<dyn LightningProvider>,

    /// Chain data provider.
    pub chain: Arc<dyn ChainProvider>,

    /// Pricing engine.
    pub pricing: Arc<dyn PricingEngine>,

    /// Payment gate.
    pub gate: Arc<PaymentGate>,

    /// Peer registry.
    pub peer_registry: Arc<RwLock<PeerRegistry>>,

    /// P2P transport (type-erased for testability).
    pub transport: Arc<dyn MessageTransport>,

    /// E2EE session manager (X3DH + Double Ratchet per peer).
    pub session_manager: Arc<SessionManager>,

    /// JWT signing secret.
    pub jwt_secret: String,

    /// Single-use authentication challenges.
    ///
    /// `/api/v1/auth/token` must not verify a replayable static string. The
    /// challenge endpoint writes short-lived challenge strings here and token
    /// issuance consumes them exactly once.
    pub auth_challenges: Arc<Mutex<HashMap<String, Instant>>>,

    /// Whether CORS is enabled.
    pub cors_enabled: bool,

    /// Whether unauthenticated operator liveness probes are enabled.
    ///
    /// This gates cheap probe-only routes such as `/api/v1/preflight`.
    /// Full health, user state, payments, peers, and chain data remain behind
    /// their existing handlers and auth/network controls.
    pub operator_probes_enabled: bool,

    /// Whether mnemonic restore/reveal routes are mounted.
    ///
    /// These routes are valid only when the API is controlled by the same user
    /// who owns the mnemonic. Operator/relay contexts must leave them absent
    /// from the router, not merely protected by auth.
    pub sensitive_identity_routes_enabled: bool,

    /// Broadcast channel for real-time WebSocket notifications.
    /// Messages include decrypted plaintext when E2EE session is available.
    pub ws_broadcast: broadcast::Sender<Arc<WsMessage>>,

    /// Broadcast channel for delivery status updates (ack/reject).
    ///
    /// Separate from `ws_broadcast` to avoid changing the existing message
    /// format. The frontend distinguishes these events by the `type` field.
    pub ws_delivery_broadcast: broadcast::Sender<Arc<WsDeliveryStatus>>,

    /// Per-IP rate limiter.
    pub rate_limiter: Arc<RateLimiter>,

    /// Dedicated strict rate limiter for mnemonic (seed) read-back.
    ///
    /// The global `rate_limiter` is tuned for ordinary API traffic (hundreds
    /// of requests per second) and is keyed per source IP. That is far too
    /// loose to throttle attempts to exfiltrate the recovery seed. This
    /// limiter is keyed per authenticated actor and allows only a handful of
    /// reveal attempts per minute, bounding brute-force of the re-auth gate
    /// even when the caller already holds a valid JWT (HARD-9).
    pub mnemonic_reveal_limiter: Arc<RateLimiter>,

    /// Audit log for security-relevant events.
    pub audit_log: Arc<AuditLog>,

    /// Node startup time (for uptime calculation).
    pub started_at: Instant,

    /// Content directory for sovereign browser pages.
    /// `None` if the web content server is disabled.
    pub content_dir: Option<PathBuf>,

    /// Default price per page in millisatoshi for the web content server.
    /// `None` if the web content server is disabled.
    pub web_page_price_msat: Option<u64>,

    /// Cached pricing tables from connected peers.
    ///
    /// Used by the compose endpoint to pay the exact price a recipient
    /// requires, preventing pricing mismatch rejections in heterogeneous
    /// networks (Principle 5: chain-aware message pricing — see ADR-027).
    pub peer_prices: Arc<PeerPriceCache>,

    /// Synaptic routing table for adaptive routing metrics.
    pub routing: Arc<RoutingTable>,

    /// Node data directory (e.g. `~/.konsensus/`).
    ///
    /// Used by identity endpoints that need to write config/mnemonic files
    /// (e.g. the recovery/restore flow).
    pub data_dir: Option<PathBuf>,

    /// Durable-backup directory (`backup.scb_dir`) holding the rotated
    /// `scb-latest.aes` channel-state snapshot and the `whitelist-latest.aes`
    /// sidecar. Read by the one-click exit-bundle endpoint (X1) to attach the
    /// node's encrypted channel-state recovery artifact. `None` disables SCB
    /// attachment (the bundle still carries a freshly-sealed whitelist).
    pub backup_dir: Option<PathBuf>,

    /// Cipher for decrypting cached message plaintext at rest.
    ///
    /// Used by the message plaintext API endpoint to decrypt cached
    /// content that was stored by the message receive handler.
    pub plaintext_cipher: Option<Arc<PlaintextCacheCipher>>,

    /// Tracks send timestamps for outgoing messages.
    ///
    /// Used for STDP (Spike-Timing-Dependent Plasticity) latency measurement
    /// in the synaptic routing protocol. When a message is sent, its ID and
    /// the current `Instant` are recorded. When the ack arrives, the elapsed
    /// time is computed and fed into `RoutingTable::record_success()` for
    /// Hebbian learning with latency bonus.
    pub send_timestamps: Arc<tokio::sync::Mutex<HashMap<MessageId, Instant>>>,

    /// Lightning pubkeys of connected peers (for keysend payments).
    ///
    /// Populated when a peer sends a `Frame::LightningInfo` after the
    /// federation handshake. Used by `create_payment_proof()` to attempt
    /// keysend before falling back to the invoice-request round-trip.
    /// Key: peer NodeId, Value: compressed Lightning pubkey (hex, 66 chars).
    pub peer_ln_pubkeys: Arc<tokio::sync::Mutex<HashMap<NodeId, String>>>,

    /// Lightning backend name (e.g. "lnbits", "mock", "void").
    ///
    /// Used by the health endpoint to communicate the active Lightning
    /// backend to the frontend so it can show appropriate warnings for
    /// simulated wallets.
    pub lightning_backend: String,

    /// Chain backend name (e.g. "esplora", "mock").
    ///
    /// Used by the health endpoint to verify that the real Esplora chain
    /// backend is active (not mock). Critical for E7 verification.
    pub chain_backend: String,

    /// Gossip protocol validator for status/metrics queries.
    ///
    /// `None` if the gossip protocol is not initialized (e.g., in tests).
    pub gossip_validator: Option<Arc<konsensus_gossip::GossipValidator>>,

    /// Pending invoice requests — maps request_id to a oneshot sender.
    ///
    /// When the compose handler needs to pay a recipient, it:
    /// 1. Generates a unique request_id
    /// 2. Inserts a oneshot::Sender here
    /// 3. Sends Frame::RequestInvoice to the peer
    /// 4. Awaits the oneshot::Receiver (with timeout)
    ///
    /// When the node receives Frame::InvoiceResponse via ControlEvent, it
    /// removes the matching entry and sends the bolt11 string through the
    /// oneshot channel, unblocking the compose handler.
    pub invoice_requests:
        Arc<tokio::sync::Mutex<HashMap<String, oneshot::Sender<InvoiceResponseData>>>>,
}

/// Data returned via the invoice request oneshot channel.
#[derive(Debug)]
pub struct InvoiceResponseData {
    /// BOLT11 payment request string from the recipient's wallet.
    pub bolt11: String,
    /// Payment hash (hex) from the recipient's invoice.
    pub payment_hash: String,
}

impl AppState {
    /// Build the whitelist as a HashSet for the payment gate.
    ///
    /// Clones the registry's internally cached whitelist set (kept in sync on
    /// every peer add/remove) rather than rebuilding it from scratch. Callers on
    /// the per-message hot path should instead borrow the cached set directly via
    /// `PeerRegistry::whitelist_set` to avoid even this clone (see HARD-11).
    pub async fn whitelist_set(&self) -> HashSet<NodeId> {
        self.peer_registry.read().await.whitelist_set().clone()
    }
}
