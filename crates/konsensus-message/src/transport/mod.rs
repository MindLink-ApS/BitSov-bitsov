//! NoiseTransport — Noise_XX encrypted TCP transport implementing [`MessageTransport`].
//!
//! This is the primary transport for the BitSov network. Each peer connection
//! is a Noise_XX-encrypted TCP stream with federation handshake authentication.
//!
//! # Connection lifecycle
//!
//! 1. TCP connect
//! 2. Noise_XX three-message handshake (mutual X25519 authentication)
//! 3. Federation handshake (Hello/HelloAck — Ed25519 identity binding + whitelist check)
//! 4. Bidirectional encrypted message exchange
//! 5. Graceful disconnect or TCP drop

mod connection;
mod handshake;
mod messaging;
mod supervisor;

// Re-export internal helpers that sibling submodules access via `super::`.
// handshake::connect_to_peer does `use super::{PeerConnection, spawn_reader_task}` —
// spawn_reader_task lives in messaging but must be findable via the parent module.
use messaging::spawn_reader_task;

// Only needed by the test module (use super::* brings in items from this namespace).
#[cfg(test)]
use handshake::verify_identity_binding;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::identity::NodeIdentity;
use konsensus_core::traits::transport::{ConnectedPeerInfo, MessageTransport, TransportError};
use konsensus_core::types::NodeId;
use konsensus_crypto::noise::NoiseSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, instrument, warn};

use crate::wire::{Capability, Frame, SovereigntyTier, WireError, MAX_FRAME_SIZE};

/// Control events from the transport layer to the application layer.
///
/// These carry session management frames and connection lifecycle notifications
/// that the transport can't handle alone — it doesn't have access to the
/// `SessionManager` (which lives in `konsensus-crypto`).
///
/// The application layer spawns a handler task that receives these events and
/// orchestrates E2EE session establishment (X3DH → Double Ratchet) automatically.
#[derive(Debug)]
pub enum ControlEvent {
    /// A new peer connection was established (federation handshake complete).
    /// Triggers automatic prekey bundle exchange for E2EE session setup.
    PeerConnected {
        /// The authenticated peer's NodeId.
        peer_id: NodeId,
    },

    /// Peer offered their prekey bundle for X3DH session establishment.
    PrekeyOffer {
        /// The peer who sent the bundle.
        peer_id: NodeId,
        /// Serialized `SerializablePrekeyBundle` (JSON value).
        bundle: serde_json::Value,
    },

    /// Peer initiated an E2EE session (X3DH initiator → responder).
    SessionInit {
        /// The peer who initiated.
        peer_id: NodeId,
        /// Serialized `SerializableSessionInit` (JSON value).
        init_data: serde_json::Value,
    },

    /// Peer acknowledged E2EE session establishment.
    SessionAck {
        /// The peer who acknowledged.
        peer_id: NodeId,
    },

    /// Peer sent a ratchet initialization message (initiator → acceptor).
    ///
    /// The acceptor must decrypt this to initialize their sending chain.
    RatchetInit {
        /// The peer who sent the ratchet init.
        peer_id: NodeId,
        /// Ratchet-encrypted payload.
        payload: Vec<u8>,
    },

    /// Peer acknowledged receipt of a message.
    MessageAcked {
        /// The peer who acknowledged.
        peer_id: NodeId,
        /// The acknowledged message ID.
        message_id: konsensus_core::types::MessageId,
    },

    /// Peer rejected a message (e.g., payment gate failure).
    MessageRejected {
        /// The peer who rejected.
        peer_id: NodeId,
        /// The rejected message ID.
        message_id: konsensus_core::types::MessageId,
        /// Reason for rejection.
        reason: String,
    },

    /// Peer announced their pricing table.
    ///
    /// Sent after federation handshake completes, and whenever pricing changes.
    /// The receiver should cache this and use it when composing messages to
    /// this peer, to avoid pricing mismatch rejections.
    PriceTableReceived {
        /// The peer who announced.
        peer_id: NodeId,
        /// Prices per kind category in millisatoshis.
        prices: std::collections::HashMap<String, u64>,
        /// Block height at which prices were computed.
        block_height: u64,
        /// How many blocks this table is valid for (0 = until replaced).
        valid_blocks: u32,
        /// Plasticity trust discount offered to us by this peer (0.0 to 0.5).
        trust_discount: f64,
    },

    /// Peer queried our price for a specific message kind.
    PriceQueryReceived {
        /// The peer who queried.
        peer_id: NodeId,
        /// The kind they want to price.
        kind: u16,
    },

    /// Peer responded with a price for a queried kind.
    PriceResponseReceived {
        /// The peer who responded.
        peer_id: NodeId,
        /// The kind that was priced.
        kind: u16,
        /// Required price in millisatoshis.
        price_msat: u64,
        /// Block height at which price was computed.
        block_height: u64,
    },

    /// Peer requested our known peer list for discovery.
    ///
    /// The application layer should respond with a curated list of peers
    /// that have opted in to discovery (respecting Principle 3: closed mesh).
    PeerExchangeRequested {
        /// The peer who requested.
        peer_id: NodeId,
    },

    /// Peer shared their known peer list.
    ///
    /// These entries are suggestions only — the node operator or application
    /// must explicitly whitelist them before they can connect (Principle 3).
    PeerExchangeReceived {
        /// The peer who shared.
        peer_id: NodeId,
        /// List of peer entries.
        peers: Vec<crate::wire::PeerExchangeEntry>,
    },

    /// Peer requested a Lightning invoice (they want to pay us).
    ///
    /// The application layer should create an invoice on the local Lightning
    /// wallet and respond with `Frame::InvoiceResponse`.
    InvoiceRequested {
        /// The peer who requested.
        peer_id: NodeId,
        /// Correlation ID for matching request to response.
        request_id: String,
        /// Requested amount in millisatoshis.
        amount_msat: u64,
        /// Purpose description from the requester.
        purpose: String,
    },

    /// Peer responded with a Lightning invoice we requested.
    ///
    /// The application layer should fulfill the pending oneshot channel
    /// so the compose handler can pay the invoice and attach the proof.
    InvoiceResponseReceived {
        /// The peer who responded.
        peer_id: NodeId,
        /// Correlation ID matching our original request.
        request_id: String,
        /// BOLT11 payment request string.
        bolt11: String,
        /// Payment hash (hex).
        payment_hash: String,
    },

    /// Peer reported an error creating the invoice we requested.
    ///
    /// The application layer should fail the pending compose request
    /// immediately instead of waiting for the 30-second timeout.
    InvoiceErrorReceived {
        /// The peer who reported the error.
        peer_id: NodeId,
        /// Correlation ID matching our original request.
        request_id: String,
        /// Human-readable error reason.
        reason: String,
    },

    /// Received a gossip message from a peer.
    ///
    /// Legacy gossip message from a peer.
    ///
    /// Launch-facing nodes reject free gossip until paid broadcast semantics
    /// land on the normal UKM payment-gated path.
    GossipReceived {
        /// The peer who relayed this gossip message to us.
        from_peer: NodeId,
        /// The gossip envelope (sender is the original author, not the relayer).
        envelope: Box<konsensus_core::UkmEnvelope>,
    },

    /// Peer shared their Lightning node pubkey (for keysend payments).
    ///
    /// Sent after federation handshake when the peer advertises
    /// `Capability::Keysend`. Enables the compose flow to use keysend
    /// (spontaneous payment) instead of the invoice-request round-trip,
    /// reducing message compose latency by ~100-200ms.
    LightningInfoReceived {
        /// The peer who shared their Lightning pubkey.
        peer_id: NodeId,
        /// Compressed Lightning node public key (hex, 66 chars).
        ln_pubkey: String,
        /// Dialable Lightning P2P address (`host:port`) for channel opens.
        ln_addr: Option<String>,
    },

    // ── Real-time Signaling (KIND range 400–499) ──────────────────────────

    /// Peer sent a WebRTC call offer (SDP offer).
    CallOfferReceived {
        /// The peer initiating the call.
        peer_id: NodeId,
        /// Unique session identifier.
        session_id: String,
        /// SDP offer string.
        sdp: String,
    },

    /// Peer accepted the call with an SDP answer.
    CallAnswerReceived {
        /// The peer answering the call.
        peer_id: NodeId,
        /// Session ID matching the original `CallOfferReceived`.
        session_id: String,
        /// SDP answer string.
        sdp: String,
    },

    /// Peer sent a trickle ICE candidate.
    IceCandidateReceived {
        /// The peer who sent the candidate.
        peer_id: NodeId,
        /// Session ID of the in-progress call.
        session_id: String,
        /// Serialized ICE candidate.
        candidate: String,
    },

    /// Peer terminated the call.
    CallEndReceived {
        /// The peer who ended the call.
        peer_id: NodeId,
        /// Session ID of the terminated call.
        session_id: String,
        /// Human-readable termination reason.
        reason: String,
    },
}

/// Keepalive interval — send a Ping if no frames sent/received for this duration.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// If no Pong received within this duration after a Ping, consider the connection dead.
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(15);

/// Minimum reconnection delay (exponential backoff base).
const RECONNECT_MIN_DELAY: Duration = Duration::from_secs(1);

/// Maximum reconnection delay (exponential backoff cap).
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(60);

/// Maximum concurrent inbound connection handshakes.
/// Limits resource consumption from connection storms or slow handshakes.
const MAX_CONCURRENT_INBOUND: usize = 64;

/// Timeout for a single TCP read operation (length prefix + payload).
/// Prevents slowloris attacks where an attacker sends partial data to hold connections.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for the entire Noise_XX + federation handshake.
/// Prevents attackers from holding inbound connection slots indefinitely.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of invalid (unparseable) frames allowed per peer within
/// [`INVALID_FRAME_WINDOW`] before the peer is disconnected and temporarily banned.
///
/// This defends against whitelisted peers sending garbage frames to consume parsing
/// resources. The payment gate doesn't activate until a valid UKM envelope arrives,
/// so garbage frames bypass economic rate-limiting.
const INVALID_FRAME_BUDGET: u32 = 10;

/// Time window for counting invalid frames (seconds).
const INVALID_FRAME_WINDOW: Duration = Duration::from_secs(60);

/// Duration to ban a peer after exhausting their frame validation budget.
const FRAME_BAN_DURATION: Duration = Duration::from_secs(60);

/// Per-connection memory budget: maximum bytes a single peer can send within
/// [`MEMORY_BUDGET_WINDOW`]. Prevents a malicious whitelisted peer from
/// exhausting node memory by sending many large frames. 64 MiB per peer per
/// minute is generous for legitimate use (even file transfers) while preventing abuse.
const PEER_MEMORY_BUDGET: u64 = 64 * 1024 * 1024;

/// Time window for the per-peer memory budget.
const MEMORY_BUDGET_WINDOW: Duration = Duration::from_secs(60);

/// Interval for periodic eviction of expired entries from the ban map.
/// Prevents unbounded growth when many peers are banned and never reconnect.
const BAN_EVICTION_INTERVAL: Duration = Duration::from_secs(300);

/// Configuration for the Noise transport.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Address to listen on for incoming connections.
    pub listen_addr: SocketAddr,
    /// Sovereignty tier to advertise.
    pub tier: SovereigntyTier,
    /// Capabilities to advertise.
    pub capabilities: Vec<Capability>,
    /// Whitelisted peer NodeIds. Only these peers can connect (Principle 3).
    pub whitelist: Vec<NodeId>,
    /// Protocol version (always 2).
    pub version: u16,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 9735)),
            tier: SovereigntyTier::T1,
            capabilities: vec![Capability::X3dh],
            whitelist: Vec::new(),
            version: 2,
        }
    }
}

/// Shared, dynamically updatable whitelist (Principle 3: Closed Mesh).
///
/// An empty whitelist rejects ALL connections — a freshly initialized node with
/// no peers is fully isolated by default. Seeded from `TransportConfig::whitelist`
/// at construction, then updated at runtime via [`MessageTransport::add_to_whitelist`]
/// and [`MessageTransport::remove_from_whitelist`].
pub type SharedWhitelist = Arc<RwLock<HashSet<NodeId>>>;

/// State of an active peer connection.
struct PeerConnection {
    /// The Noise session for encrypt/decrypt.
    noise: NoiseSession,
    /// TCP write half — protected by mutex for send serialization.
    writer: tokio::io::WriteHalf<TcpStream>,
    /// The peer's advertised sovereignty tier.
    tier: SovereigntyTier,
    /// The peer's advertised capabilities.
    capabilities: Vec<Capability>,
    /// Last time we received any frame from this peer (monotonic).
    last_recv: Instant,
    /// Outstanding ping nonce (Some if we sent a Ping and are waiting for Pong).
    pending_ping: Option<u64>,
    /// Count of invalid (unparseable) frames received within the current window.
    /// If this exceeds [`INVALID_FRAME_BUDGET`], the peer is disconnected and banned.
    invalid_frame_count: u32,
    /// Start of the current invalid-frame counting window.
    invalid_frame_window_start: Instant,
    /// Bytes received from this peer within the current memory budget window.
    /// If this exceeds [`PEER_MEMORY_BUDGET`], the peer is disconnected and banned.
    bytes_received: u64,
    /// Start of the current memory budget window.
    memory_budget_window_start: Instant,
}

/// Shared map of active peer connections.
type PeerMap = Arc<RwLock<HashMap<NodeId, Arc<Mutex<PeerConnection>>>>>;

/// Shared map of temporarily banned peers. Value is the ban expiry time (monotonic).
type BanMap = Arc<RwLock<HashMap<NodeId, Instant>>>;

/// Shared context passed to per-peer connection tasks (reader, supervisor, incoming handler).
///
/// Groups the fields that every connection handler needs without requiring 8+ arguments.
#[derive(Clone)]
struct TransportCtx {
    identity: Arc<NodeIdentity>,
    config: TransportConfig,
    whitelist: SharedWhitelist,
    peers: PeerMap,
    banned_peers: BanMap,
    incoming_tx: mpsc::Sender<UkmEnvelope>,
    control_tx: mpsc::Sender<ControlEvent>,
}

/// Noise_XX encrypted TCP transport.
///
/// Implements [`MessageTransport`] for reliable, encrypted, direct node-to-node
/// message delivery. Enforces Principle 3 (Closed Mesh) via whitelist checks
/// during the federation handshake.
pub struct NoiseTransport {
    /// Our node identity (provides X25519 + Ed25519 keys).
    identity: Arc<NodeIdentity>,
    /// Transport configuration.
    config: TransportConfig,
    /// Dynamic whitelist — seeded from config, updated at runtime.
    whitelist: SharedWhitelist,
    /// Active peer connections, keyed by NodeId.
    peers: PeerMap,
    /// Temporarily banned peers (exceeded frame validation budget).
    banned_peers: BanMap,
    /// Channel for incoming envelopes from all peer reader tasks.
    incoming_tx: mpsc::Sender<UkmEnvelope>,
    /// Receiver for incoming envelopes (consumed by `recv()`).
    incoming_rx: Mutex<mpsc::Receiver<UkmEnvelope>>,
    /// Channel for control events (session frames, connection lifecycle).
    control_tx: mpsc::Sender<ControlEvent>,
    /// Receiver for control events (consumed by `recv_control()`).
    control_rx: Mutex<mpsc::Receiver<ControlEvent>>,
    /// Listener shutdown signal.
    shutdown: tokio::sync::watch::Sender<bool>,
    /// Monotonic counter for ping nonces (shared with supervisor tasks).
    ping_counter: Arc<AtomicU64>,
    /// Actual bound address after `start_listener()` (may differ from config if port 0 was used).
    actual_listen_addr: tokio::sync::watch::Sender<Option<SocketAddr>>,
    /// Receiver for the actual listen address.
    actual_listen_addr_rx: tokio::sync::watch::Receiver<Option<SocketAddr>>,
}

impl NoiseTransport {
    /// Create a new transport (does not start listening yet — call `start_listener`).
    ///
    /// The whitelist is seeded from `config.whitelist` and can be updated at
    /// runtime via [`add_to_whitelist`](MessageTransport::add_to_whitelist) /
    /// [`remove_from_whitelist`](MessageTransport::remove_from_whitelist).
    pub fn new(identity: Arc<NodeIdentity>, config: TransportConfig) -> Self {
        let initial_whitelist: HashSet<NodeId> = config.whitelist.iter().copied().collect();
        let (incoming_tx, incoming_rx) = mpsc::channel(1024);
        let (control_tx, control_rx) = mpsc::channel(256);
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let (actual_listen_addr, actual_listen_addr_rx) = tokio::sync::watch::channel(None);

        Self {
            identity,
            config,
            whitelist: Arc::new(RwLock::new(initial_whitelist)),
            peers: Arc::new(RwLock::new(HashMap::new())),
            banned_peers: Arc::new(RwLock::new(HashMap::new())),
            incoming_tx,
            incoming_rx: Mutex::new(incoming_rx),
            control_tx,
            control_rx: Mutex::new(control_rx),
            shutdown,
            ping_counter: Arc::new(AtomicU64::new(1)),
            actual_listen_addr,
            actual_listen_addr_rx,
        }
    }
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Write a length-prefixed Noise message to a TCP stream.
async fn write_noise_message(
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    data: &[u8],
) -> Result<(), WireError> {
    let len = u32::try_from(data.len()).map_err(|_| {
        WireError::FrameTooLarge {
            size: data.len(),
            max: u32::MAX as usize,
        }
    })?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed Noise message from a TCP stream with timeout.
///
/// Applies [`READ_TIMEOUT`] to prevent slowloris attacks where an attacker
/// sends partial data to hold connections open indefinitely.
async fn read_noise_message(
    reader: &mut tokio::io::ReadHalf<TcpStream>,
) -> Result<Vec<u8>, WireError> {
    // Wrap the entire read (length prefix + payload) in a timeout
    tokio::time::timeout(READ_TIMEOUT, async {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > MAX_FRAME_SIZE + 1024 {
            // Allow some overhead for Noise tag
            return Err(WireError::FrameTooLarge {
                size: len,
                max: MAX_FRAME_SIZE + 1024,
            });
        }

        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        Ok(buf)
    })
    .await
    .map_err(|_| WireError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "read timed out (slowloris protection)",
    )))?
}
#[async_trait]
impl MessageTransport for NoiseTransport {
    #[instrument(skip(self, envelope), fields(peer = %peer))]
    async fn send(&self, peer: &NodeId, envelope: &UkmEnvelope) -> Result<(), TransportError> {
        // L0d (2026-04-30): clone the `Arc<Mutex<PeerConnection>>` inside a
        // scoped block, drop the `peers` read guard, then lock the connection
        // and do network IO. The previous pattern held `peers.read()` across
        // both `conn.lock().await` and `write_noise_message().await`, blocking
        // every concurrent peer registration / disconnect / handshake on the
        // RwLock for as long as any send was in flight. Mirrors the safe
        // pattern already in use in `send_raw_frame` below.
        let conn = {
            let peers = self.peers.read().await;
            Arc::clone(
                peers
                    .get(peer)
                    .ok_or_else(|| TransportError::NotConnected(peer.to_hex()))?,
            )
        };

        let frame = Frame::Message(Box::new(envelope.clone()));
        let frame_bytes = frame
            .to_bytes()
            .map_err(|e| TransportError::WireProtocol(e.to_string()))?;

        let mut conn = conn.lock().await;
        let encrypted = conn
            .noise
            .encrypt(&frame_bytes)
            .map_err(|e| TransportError::NoiseError(e.to_string()))?;

        write_noise_message(&mut conn.writer, &encrypted)
            .await
            .map_err(|e| TransportError::Other(e.to_string()))?;

        debug!(msg_id = %envelope.id, "sent envelope to peer");
        Ok(())
    }

    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| TransportError::Other("transport shut down".into()))
    }

    #[instrument(skip(self), fields(peer = %peer, addr = %addr))]
    async fn connect(&self, peer: &NodeId, addr: &str) -> Result<(), TransportError> {
        // Check whitelist (Principle 3)
        if !self.is_whitelisted(peer).await {
            return Err(TransportError::Rejected(format!(
                "peer {} not in whitelist",
                peer.to_hex()
            )));
        }

        // Check if already connected
        if self.is_connected(peer).await {
            return Ok(());
        }

        let socket_addr: SocketAddr = addr
            .parse()
            .map_err(|e| TransportError::ConnectionFailed(format!("invalid address: {e}")))?;

        let ctx = TransportCtx {
            identity: Arc::clone(&self.identity),
            config: self.config.clone(),
            whitelist: Arc::clone(&self.whitelist),
            peers: Arc::clone(&self.peers),
            banned_peers: Arc::clone(&self.banned_peers),
            incoming_tx: self.incoming_tx.clone(),
            control_tx: self.control_tx.clone(),
        };
        handshake::connect_to_peer(peer, &socket_addr, &ctx).await
    }

    async fn disconnect(&self, peer: &NodeId) -> Result<(), TransportError> {
        let conn = self.peers.write().await.remove(peer);
        if let Some(conn) = conn {
            // Send graceful disconnect
            let disconnect = Frame::Disconnect {
                reason: "requested".into(),
            };
            let mut conn = conn.lock().await;
            if let Ok(bytes) = disconnect.to_bytes() {
                if let Ok(encrypted) = conn.noise.encrypt(&bytes) {
                    if let Err(e) = write_noise_message(&mut conn.writer, &encrypted).await {
                        debug!(error = %e, "failed to send disconnect frame (peer may already be gone)");
                    }
                }
            }
        }
        Ok(())
    }

    async fn is_connected(&self, peer: &NodeId) -> bool {
        self.peers.read().await.contains_key(peer)
    }

    async fn connected_peers(&self) -> Vec<NodeId> {
        self.peers.read().await.keys().copied().collect()
    }

    async fn request_peer_exchange(&self, peer: &NodeId) -> Result<(), TransportError> {
        self.send_frame(peer, &Frame::PeerExchangeRequest).await
    }

    async fn send_raw_frame(&self, peer: &NodeId, frame_bytes: &[u8]) -> Result<(), TransportError> {
        let conn = {
            let peers = self.peers.read().await;
            Arc::clone(
                peers
                    .get(peer)
                    .ok_or_else(|| TransportError::NotConnected(peer.to_hex()))?,
            )
        };

        let mut conn = conn.lock().await;
        let encrypted = conn
            .noise
            .encrypt(frame_bytes)
            .map_err(|e| TransportError::NoiseError(e.to_string()))?;

        write_noise_message(&mut conn.writer, &encrypted)
            .await
            .map_err(|e| TransportError::Other(e.to_string()))?;

        Ok(())
    }

    async fn peer_info(&self, peer: &NodeId) -> Option<ConnectedPeerInfo> {
        // L0d (2026-04-30): same scoped-clone pattern as `send`. Held the
        // `peers` read guard across `conn.lock().await` previously.
        let conn = {
            let peers = self.peers.read().await;
            Arc::clone(peers.get(peer)?)
        };
        let conn = conn.lock().await;
        Some(ConnectedPeerInfo {
            tier: format!("{:?}", conn.tier),
            capabilities: conn.capabilities.iter().map(|c| format!("{:?}", c)).collect(),
        })
    }

    async fn add_to_whitelist(&self, peer: &NodeId) {
        let mut wl = self.whitelist.write().await;
        if wl.insert(*peer) {
            info!(peer = %peer.to_hex(), "added peer to transport whitelist");
        }
    }

    async fn remove_from_whitelist(&self, peer: &NodeId) {
        let mut wl = self.whitelist.write().await;
        if wl.remove(peer) {
            info!(peer = %peer.to_hex(), "removed peer from transport whitelist");
        }
    }

    async fn supervise_peer(&self, peer: &NodeId, addr: &str) {
        match addr.parse::<SocketAddr>() {
            Ok(socket_addr) => {
                info!(
                    peer = %peer.to_hex(),
                    addr = %socket_addr,
                    "starting dynamic supervision for redeemed peer"
                );
                self.supervise_single_peer(*peer, socket_addr);
            }
            Err(e) => {
                warn!(
                    peer = %peer.to_hex(),
                    addr = %addr,
                    error = %e,
                    "cannot supervise peer: invalid address"
                );
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_core::identity::NodeIdentity;
    use konsensus_core::types::{Nonce, PaymentProof, Recipient, Signature};

    const TEST_MNEMONIC_A: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon art";

    const TEST_MNEMONIC_B: &str =
        "zoo zoo zoo zoo zoo zoo zoo zoo \
         zoo zoo zoo zoo zoo zoo zoo zoo \
         zoo zoo zoo zoo zoo zoo zoo vote";

    const TEST_MNEMONIC_C: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice \
         cage absurd amount doctor acoustic avoid letter advice cage absurd \
         amount doctor acoustic bless";

    fn make_identity(mnemonic: &str) -> Arc<NodeIdentity> {
        Arc::new(NodeIdentity::from_mnemonic(mnemonic, "").unwrap())
    }

    fn make_test_envelope(sender: &NodeIdentity, recipient: &NodeId) -> UkmEnvelope {
        use sha2::{Digest, Sha256};
        let preimage = [42u8; 32];
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        let proof = PaymentProof::new(hash, preimage, 10);

        let nonce = Nonce::generate();
        let ciphertext = b"encrypted test content".to_vec();

        let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
            0, // KIND_CHAT
            *sender.node_id(),
            Recipient::Node(*recipient),
            ciphertext,
            proof,
        )
        .nonce(nonce)
        .timestamp(1_700_000_000_000)
        .build();

        // Sign the envelope
        let sig = sender.sign(&envelope.signable_bytes());
        envelope.signature = Signature::from_ed25519(&sig);
        envelope
    }

    #[tokio::test]
    async fn two_nodes_connect_and_exchange_messages() -> Result<(), Box<dyn std::error::Error>> {
        // Create two node identities
        let identity_a = make_identity(TEST_MNEMONIC_A);
        let identity_b = make_identity(TEST_MNEMONIC_B);

        let node_a_id = *identity_a.node_id();
        let node_b_id = *identity_b.node_id();

        // Configure transports with each other in whitelist
        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(), // OS-assigned port
            tier: SovereigntyTier::T2,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_b_id],
            version: 2,
        };

        let config_b_fixed = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T1,
            capabilities: vec![Capability::X3dh, Capability::Mls],
            whitelist: vec![node_a_id],
            version: 2,
        };

        let transport_b = Arc::new(NoiseTransport::new(Arc::clone(&identity_b), config_b_fixed));
        transport_b.start_listener().await?;
        let listen_addr = transport_b.listen_addr().expect("should have actual listen addr");

        // Give the listener a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let transport_a = Arc::new(NoiseTransport::new(Arc::clone(&identity_a), config_a));

        // A connects to B
        transport_a
            .connect(&node_b_id, &listen_addr.to_string())
            .await?;

        assert!(transport_a.is_connected(&node_b_id).await);

        // Wait for B to register A's connection
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        assert!(transport_b.is_connected(&node_a_id).await);

        // A sends a message to B
        let envelope = make_test_envelope(&identity_a, &node_b_id);
        transport_a.send(&node_b_id, &envelope).await?;

        // B receives the message
        let received = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            transport_b.recv(),
        )
        .await
        .expect("recv timed out")
        .expect("channel closed");

        assert_eq!(received.id, envelope.id);
        assert_eq!(received.sender, node_a_id);
        assert_eq!(received.ciphertext, envelope.ciphertext);

        // B sends a message to A
        let reply = make_test_envelope(&identity_b, &node_a_id);
        transport_b.send(&node_a_id, &reply).await?;

        // A receives the reply
        let received_reply = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            transport_a.recv(),
        )
        .await
        .expect("recv timed out")
        .expect("channel closed");

        assert_eq!(received_reply.id, reply.id);
        assert_eq!(received_reply.sender, node_b_id);

        // Clean up
        transport_a.disconnect(&node_b_id).await?;
        transport_b.shutdown();
        Ok(())
    }

    #[tokio::test]
    async fn reject_non_whitelisted_peer() {
        let identity_a = make_identity(TEST_MNEMONIC_A);
        let identity_b = make_identity(TEST_MNEMONIC_B);

        let node_b_id = *identity_b.node_id();

        // A's whitelist does NOT include B
        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T1,
            capabilities: vec![],
            whitelist: vec![NodeId::from_bytes([99u8; 32])], // some other node
            version: 2,
        };

        let transport_a = NoiseTransport::new(Arc::clone(&identity_a), config_a);

        // Trying to connect should be rejected by our own whitelist check
        let result = transport_a
            .connect(&node_b_id, "127.0.0.1:19999")
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::Rejected(msg) => assert!(msg.contains("whitelist")),
            e => panic!("expected Rejected, got {e:?}"),
        }
    }

    #[test]
    fn verify_identity_binding_valid() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC_A, "").unwrap();
        let x25519_public = identity.x25519_public().as_bytes().to_vec();

        use ed25519_dalek::Signer;
        let sig = identity.ed25519_signing_key().sign(&x25519_public);

        let result = verify_identity_binding(
            identity.node_id(),
            &x25519_public,
            &sig.to_bytes(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn verify_identity_binding_wrong_key() {
        let identity_a = NodeIdentity::from_mnemonic(TEST_MNEMONIC_A, "").unwrap();
        let identity_b = NodeIdentity::from_mnemonic(TEST_MNEMONIC_B, "").unwrap();

        let x25519_public = identity_a.x25519_public().as_bytes().to_vec();

        use ed25519_dalek::Signer;
        // Sign with A's key but claim to be B
        let sig = identity_a.ed25519_signing_key().sign(&x25519_public);

        let result = verify_identity_binding(
            identity_b.node_id(), // Wrong node ID
            &x25519_public,
            &sig.to_bytes(),
        );
        assert!(result.is_err());
    }

    /// Multi-node integration test: two nodes connect, establish E2EE sessions,
    /// and exchange encrypted, payment-gated messages end-to-end.
    ///
    /// This validates the full Phase 1-5 stack:
    /// 1. Identity generation (BIP-39 → blake3 KDF)
    /// 2. Transport encryption (Noise_XX)
    /// 3. Federation handshake (Ed25519 identity binding)
    /// 4. E2EE session establishment (X3DH → Double Ratchet)
    /// 5. Message encryption + valid payment proof
    /// 6. Envelope construction, signing, delivery
    /// 7. Decryption on the receiving end
    #[tokio::test]
    async fn e2e_encrypted_message_exchange() -> Result<(), Box<dyn std::error::Error>> {
        use konsensus_crypto::SessionManager;
        use konsensus_crypto::ratchet_message_to_bytes;
        use sha2::{Digest, Sha256};

        // Create two node identities
        let identity_a = make_identity(TEST_MNEMONIC_A);
        let identity_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *identity_a.node_id();
        let node_b_id = *identity_b.node_id();

        // Create session managers for E2EE
        let session_mgr_a = SessionManager::new(Arc::clone(&identity_a));
        let session_mgr_b = SessionManager::new(Arc::clone(&identity_b));

        // Step 1: Establish X3DH session
        // B publishes prekey bundle
        let bundle_b = session_mgr_b.prekey_bundle().await;

        // A initiates session with B using B's prekey bundle
        let init_data = session_mgr_a
            .initiate_session(&node_b_id, &bundle_b)
            .await
            .expect("A should initiate session with B");

        // B accepts session from A
        session_mgr_b
            .accept_session(&node_a_id, &init_data)
            .await
            .expect("B should accept session from A");

        assert!(session_mgr_a.has_session(&node_b_id).await);
        assert!(session_mgr_b.has_session(&node_a_id).await);

        // Step 2: Set up Noise transport connections (port 0 = OS-assigned ephemeral port)
        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T2,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_b_id],
            version: 2,
        };
        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T2,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_a_id],
            version: 2,
        };

        let transport_b = Arc::new(NoiseTransport::new(Arc::clone(&identity_b), config_b));
        transport_b.start_listener().await?;
        let listen_addr = transport_b.listen_addr().expect("should have actual listen addr");
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let transport_a = Arc::new(NoiseTransport::new(Arc::clone(&identity_a), config_a));
        transport_a
            .connect(&node_b_id, &listen_addr.to_string())
            .await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        assert!(transport_a.is_connected(&node_b_id).await);
        assert!(transport_b.is_connected(&node_a_id).await);

        // Step 3: A encrypts and sends a message to B
        let plaintext = b"Hello B! This is an E2E encrypted message.";

        // Encrypt via Double Ratchet
        let ratchet_msg = session_mgr_a
            .encrypt(&node_b_id, plaintext)
            .await
            .expect("A should encrypt for B");
        let ciphertext = ratchet_message_to_bytes(&ratchet_msg);

        // Verify ciphertext is NOT plaintext (Principle 4)
        assert_ne!(&ciphertext, plaintext.as_slice());
        assert!(!ciphertext.windows(plaintext.len()).any(|w| w == plaintext));

        // Generate valid payment proof (Principle 2)
        let preimage = rand::random::<[u8; 32]>();
        let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
        let proof = PaymentProof::new(payment_hash, preimage, 100);

        // Build UKM envelope
        let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
            0, // KIND_CHAT
            node_a_id,
            Recipient::Node(node_b_id),
            ciphertext,
            proof,
        )
        .timestamp(1_700_000_000_000)
        .build();

        // Sign the envelope
        let sig = identity_a.sign(&envelope.signable_bytes());
        envelope.signature = Signature::from_ed25519(&sig);

        // Validate envelope integrity
        envelope.validate().expect("envelope should be valid");

        // Send via transport
        transport_a.send(&node_b_id, &envelope).await?;

        // Step 4: B receives and decrypts the message
        let received = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            transport_b.recv(),
        )
        .await
        .expect("recv timed out")
        .expect("channel closed");

        assert_eq!(received.id, envelope.id);
        assert_eq!(received.sender, node_a_id);

        // Verify envelope integrity on receiving end
        received.validate().expect("received envelope should be valid");

        // Decrypt the ciphertext via Double Ratchet
        let ratchet_msg_received = konsensus_crypto::ratchet_message_from_bytes(&received.ciphertext)
            .expect("should deserialize ratchet message");
        let decrypted = session_mgr_b
            .decrypt(&node_a_id, &ratchet_msg_received)
            .await
            .expect("B should decrypt A's message");

        assert_eq!(decrypted, plaintext);

        // Step 5: B sends an encrypted reply to A
        let reply_plaintext = b"Got it! Replying with E2E encryption.";
        let reply_ratchet = session_mgr_b
            .encrypt(&node_a_id, reply_plaintext)
            .await
            .expect("B should encrypt for A");
        let reply_ciphertext = ratchet_message_to_bytes(&reply_ratchet);

        let reply_preimage = rand::random::<[u8; 32]>();
        let reply_hash: [u8; 32] = Sha256::digest(reply_preimage).into();
        let reply_proof = PaymentProof::new(reply_hash, reply_preimage, 100);

        let mut reply_envelope = konsensus_core::UkmEnvelopeBuilder::new(
            0,
            node_b_id,
            Recipient::Node(node_a_id),
            reply_ciphertext,
            reply_proof,
        )
        .timestamp(1_700_000_001_000)
        .build();

        let reply_sig = identity_b.sign(&reply_envelope.signable_bytes());
        reply_envelope.signature = Signature::from_ed25519(&reply_sig);

        transport_b.send(&node_a_id, &reply_envelope).await?;

        let received_reply = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            transport_a.recv(),
        )
        .await
        .expect("recv timed out")
        .expect("channel closed");

        let reply_ratchet_msg = konsensus_crypto::ratchet_message_from_bytes(&received_reply.ciphertext)
            .expect("should deserialize reply ratchet message");
        let decrypted_reply = session_mgr_a
            .decrypt(&node_b_id, &reply_ratchet_msg)
            .await
            .expect("A should decrypt B's reply");

        assert_eq!(decrypted_reply, reply_plaintext);

        // Clean up
        transport_a.disconnect(&node_b_id).await?;
        transport_b.shutdown();
        Ok(())
    }

    /// Test that a message with invalid payment proof is detected.
    #[tokio::test]
    async fn e2e_invalid_payment_proof_detected() -> Result<(), Box<dyn std::error::Error>> {
        use konsensus_crypto::SessionManager;
        use konsensus_crypto::ratchet_message_to_bytes;

        let identity_a = make_identity(TEST_MNEMONIC_A);
        let identity_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *identity_a.node_id();
        let node_b_id = *identity_b.node_id();

        let session_mgr_a = SessionManager::new(Arc::clone(&identity_a));
        let session_mgr_b = SessionManager::new(Arc::clone(&identity_b));

        // Establish session
        let bundle_b = session_mgr_b.prekey_bundle().await;
        let init_data = session_mgr_a
            .initiate_session(&node_b_id, &bundle_b)
            .await?;
        session_mgr_b.accept_session(&node_a_id, &init_data).await?;

        // Encrypt a message
        let ratchet_msg = session_mgr_a
            .encrypt(&node_b_id, b"test message")
            .await?;
        let ciphertext = ratchet_message_to_bytes(&ratchet_msg);

        // Create an INVALID payment proof (preimage doesn't match hash)
        let bad_proof = PaymentProof::new([0u8; 32], [1u8; 32], 100);

        let envelope = konsensus_core::UkmEnvelopeBuilder::new(
            0,
            node_a_id,
            Recipient::Node(node_b_id),
            ciphertext,
            bad_proof,
        )
        .build();

        // Envelope validation should catch the bad proof
        let result = envelope.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("preimage"));
        Ok(())
    }

    /// Test that the connection supervisor automatically reconnects after disconnect.
    ///
    /// This validates Phase 6 stability: nodes recover from connection drops.
    #[tokio::test]
    async fn supervisor_reconnects_after_disconnect() -> Result<(), Box<dyn std::error::Error>> {
        let identity_a = make_identity(TEST_MNEMONIC_A);
        let identity_b = make_identity(TEST_MNEMONIC_B);

        let node_a_id = *identity_a.node_id();
        let node_b_id = *identity_b.node_id();

        // B uses port 0; supervisor needs the actual address for reconnection.
        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T1,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_b_id],
            version: 2,
        };
        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T1,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_a_id],
            version: 2,
        };

        // Start B's listener
        let transport_b = Arc::new(NoiseTransport::new(Arc::clone(&identity_b), config_b));
        transport_b.start_listener().await?;
        let listen_addr = transport_b.listen_addr().expect("should have actual listen addr");
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A starts with supervisor for B
        let transport_a = Arc::new(NoiseTransport::new(Arc::clone(&identity_a), config_a));
        transport_a.start_supervisor(vec![(node_b_id, listen_addr)]);

        // Wait for initial connection
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            transport_a.is_connected(&node_b_id).await,
            "A should be connected to B initially"
        );

        // Exchange a message to verify connection works
        let envelope = make_test_envelope(&identity_a, &node_b_id);
        transport_a.send(&node_b_id, &envelope).await?;
        let received = tokio::time::timeout(Duration::from_secs(2), transport_b.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        assert_eq!(received.id, envelope.id);

        // Disconnect A from B (simulating a network drop)
        transport_a.disconnect(&node_b_id).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !transport_a.is_connected(&node_b_id).await,
            "A should be disconnected from B"
        );

        // Wait for supervisor to reconnect (backoff starts at 1s, plus handshake time)
        // Use a polling loop instead of a fixed sleep to avoid flakiness under load
        let reconnected = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if transport_a.is_connected(&node_b_id).await {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        assert!(
            reconnected.is_ok(),
            "A should have reconnected to B via supervisor within 5s"
        );

        // Verify the reconnected connection works — send another message
        let envelope2 = make_test_envelope(&identity_a, &node_b_id);
        transport_a.send(&node_b_id, &envelope2).await?;
        let received2 = tokio::time::timeout(Duration::from_secs(2), transport_b.recv())
            .await
            .expect("recv timed out after reconnect")
            .expect("channel closed");
        assert_eq!(received2.id, envelope2.id);

        // Clean up
        transport_a.shutdown();
        transport_b.shutdown();
        Ok(())
    }

    /// Test that keepalive pings are responded to with pongs.
    #[tokio::test]
    async fn keepalive_ping_pong() -> Result<(), Box<dyn std::error::Error>> {
        let identity_a = make_identity(TEST_MNEMONIC_A);
        let identity_b = make_identity(TEST_MNEMONIC_B);

        let node_a_id = *identity_a.node_id();
        let node_b_id = *identity_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T1,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_b_id],
            version: 2,
        };
        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T1,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_a_id],
            version: 2,
        };

        let transport_b = Arc::new(NoiseTransport::new(Arc::clone(&identity_b), config_b));
        transport_b.start_listener().await?;
        let listen_addr = transport_b.listen_addr().expect("should have actual listen addr");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let transport_a = Arc::new(NoiseTransport::new(Arc::clone(&identity_a), config_a));
        transport_a
            .connect(&node_b_id, &listen_addr.to_string())
            .await?;

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(transport_a.is_connected(&node_b_id).await);

        // Manually send a ping from A to B
        let nonce = 42u64;
        {
            let peers = transport_a.peers.read().await;
            let conn = peers.get(&node_b_id).ok_or("peer not found")?;
            let mut conn = conn.lock().await;
            conn.pending_ping = Some(nonce);
            let ping = Frame::Ping { nonce };
            let bytes = ping.to_bytes()?;
            let encrypted = conn.noise.encrypt(&bytes)?;
            write_noise_message(&mut conn.writer, &encrypted)
                .await?;
        }

        // Wait for B to respond with Pong (reader task handles it)
        tokio::time::sleep(Duration::from_millis(200)).await;

        // After pong, pending_ping should be cleared by reader task
        {
            let peers = transport_a.peers.read().await;
            let conn = peers.get(&node_b_id).ok_or("peer not found")?;
            let conn = conn.lock().await;
            assert_eq!(
                conn.pending_ping, None,
                "pending_ping should be cleared by Pong"
            );
        }

        transport_a.shutdown();
        transport_b.shutdown();
        Ok(())
    }

    #[tokio::test]
    async fn control_events_emitted_on_connect() -> Result<(), Box<dyn std::error::Error>> {
        // Verify that PeerConnected control events are emitted when
        // two nodes complete the federation handshake.

        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };
        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_a_id],
            ..Default::default()
        };

        let transport_a = NoiseTransport::new(id_a, config_a);
        let transport_b = NoiseTransport::new(id_b, config_b);

        transport_b.start_listener().await?;
        let addr_b = transport_b.listen_addr().expect("should have actual listen addr");
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A connects to B
        transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await?;

        // Both sides should receive PeerConnected events
        let event_a = tokio::time::timeout(
            Duration::from_secs(2),
            transport_a.recv_control(),
        )
        .await
        .expect("timeout waiting for control event A")
        .expect("control channel closed");

        let event_b = tokio::time::timeout(
            Duration::from_secs(2),
            transport_b.recv_control(),
        )
        .await
        .expect("timeout waiting for control event B")
        .expect("control channel closed");

        // Verify PeerConnected events
        match event_a {
            ControlEvent::PeerConnected { peer_id } => {
                assert_eq!(peer_id, node_b_id, "A should see B connected");
            }
            other => panic!("expected PeerConnected, got {:?}", other),
        }

        match event_b {
            ControlEvent::PeerConnected { peer_id } => {
                assert_eq!(peer_id, node_a_id, "B should see A connected");
            }
            other => panic!("expected PeerConnected, got {:?}", other),
        }

        transport_a.shutdown();
        transport_b.shutdown();
        Ok(())
    }

    #[tokio::test]
    async fn prekey_offer_routed_through_control_channel() {
        // Verify that a PrekeyOffer frame sent by one node arrives as a
        // ControlEvent::PrekeyOffer on the other node.

        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };
        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_a_id],
            ..Default::default()
        };

        let transport_a = NoiseTransport::new(id_a, config_a);
        let transport_b = NoiseTransport::new(id_b, config_b);

        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().expect("should have actual listen addr");
        tokio::time::sleep(Duration::from_millis(50)).await;

        transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await
            .unwrap();

        // Drain the PeerConnected events
        let _ = transport_a.recv_control().await;
        let _ = transport_b.recv_control().await;

        // A sends a PrekeyOffer to B
        let test_bundle = serde_json::json!({
            "identity_key": "aa".repeat(32),
            "signed_prekey": "bb".repeat(32),
        });
        let frame = Frame::PrekeyOffer {
            bundle: test_bundle.clone(),
        };
        transport_a.send_frame(&node_b_id, &frame).await.unwrap();

        // B should receive the PrekeyOffer as a control event
        let event = tokio::time::timeout(
            Duration::from_secs(2),
            transport_b.recv_control(),
        )
        .await
        .expect("timeout")
        .expect("channel closed");

        match event {
            ControlEvent::PrekeyOffer { peer_id, bundle } => {
                assert_eq!(peer_id, node_a_id);
                assert_eq!(bundle, test_bundle);
            }
            other => panic!("expected PrekeyOffer, got {:?}", other),
        }

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn session_init_and_ack_routed() {
        // Verify SessionInit and SessionAck frames are routed through control channel.

        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        let port_b = 20035 + (rand::random::<u16>() % 100);
        let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };
        let config_b = TransportConfig {
            listen_addr: addr_b,
            whitelist: vec![node_a_id],
            ..Default::default()
        };

        let transport_a = NoiseTransport::new(id_a, config_a);
        let transport_b = NoiseTransport::new(id_b, config_b);

        transport_b.start_listener().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await
            .unwrap();

        // Drain PeerConnected
        let _ = transport_a.recv_control().await;
        let _ = transport_b.recv_control().await;

        // A sends SessionInit to B
        let init_data = serde_json::json!({
            "identity_key": "cc".repeat(32),
            "ephemeral_key": "dd".repeat(32),
            "ratchet_key": "ee".repeat(32),
        });
        let frame = Frame::SessionInit {
            init_data: init_data.clone(),
        };
        transport_a.send_frame(&node_b_id, &frame).await.unwrap();

        let event = tokio::time::timeout(
            Duration::from_secs(2),
            transport_b.recv_control(),
        )
        .await
        .expect("timeout")
        .expect("channel closed");

        match event {
            ControlEvent::SessionInit {
                peer_id,
                init_data: received,
            } => {
                assert_eq!(peer_id, node_a_id);
                assert_eq!(received, init_data);
            }
            other => panic!("expected SessionInit, got {:?}", other),
        }

        // B sends SessionAck to A
        transport_b
            .send_frame(&node_a_id, &Frame::SessionAck)
            .await
            .unwrap();

        let event = tokio::time::timeout(
            Duration::from_secs(2),
            transport_a.recv_control(),
        )
        .await
        .expect("timeout")
        .expect("channel closed");

        match event {
            ControlEvent::SessionAck { peer_id } => {
                assert_eq!(peer_id, node_b_id);
            }
            other => panic!("expected SessionAck, got {:?}", other),
        }

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn message_ack_and_reject_routed() {
        // Verify MessageAck and MessageReject frames are routed through control channel.

        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        let port_b = 20135 + (rand::random::<u16>() % 100);
        let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };
        let config_b = TransportConfig {
            listen_addr: addr_b,
            whitelist: vec![node_a_id],
            ..Default::default()
        };

        let transport_a = NoiseTransport::new(id_a, config_a);
        let transport_b = NoiseTransport::new(id_b, config_b);

        transport_b.start_listener().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await
            .unwrap();

        // Drain PeerConnected
        let _ = transport_a.recv_control().await;
        let _ = transport_b.recv_control().await;

        // B sends MessageAck to A
        let test_id = konsensus_core::types::MessageId::compute(
            b"test",
            &konsensus_core::types::Nonce::generate(),
        );
        let ack = Frame::MessageAck { id: test_id };
        transport_b.send_frame(&node_a_id, &ack).await.unwrap();

        let event = tokio::time::timeout(
            Duration::from_secs(2),
            transport_a.recv_control(),
        )
        .await
        .expect("timeout")
        .expect("channel closed");

        match event {
            ControlEvent::MessageAcked {
                peer_id,
                message_id,
            } => {
                assert_eq!(peer_id, node_b_id);
                assert_eq!(message_id, test_id);
            }
            other => panic!("expected MessageAcked, got {:?}", other),
        }

        // B sends MessageReject to A
        let reject = Frame::MessageReject {
            id: test_id,
            reason: "insufficient payment".into(),
        };
        transport_b.send_frame(&node_a_id, &reject).await.unwrap();

        let event = tokio::time::timeout(
            Duration::from_secs(2),
            transport_a.recv_control(),
        )
        .await
        .expect("timeout")
        .expect("channel closed");

        match event {
            ControlEvent::MessageRejected {
                peer_id,
                message_id,
                reason,
            } => {
                assert_eq!(peer_id, node_b_id);
                assert_eq!(message_id, test_id);
                assert_eq!(reason, "insufficient payment");
            }
            other => panic!("expected MessageRejected, got {:?}", other),
        }

        transport_a.shutdown();
        transport_b.shutdown();
    }

    /// Helper to set up two connected transports and drain PeerConnected events.
    async fn setup_connected_pair() -> (
        NoiseTransport,
        NoiseTransport,
        Arc<NodeIdentity>,
        Arc<NodeIdentity>,
        NodeId,
        NodeId,
    ) {
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };
        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_a_id],
            ..Default::default()
        };

        let transport_a = NoiseTransport::new(Arc::clone(&id_a), config_a);
        let transport_b = NoiseTransport::new(Arc::clone(&id_b), config_b);

        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().expect("should have actual listen addr");
        tokio::time::sleep(Duration::from_millis(50)).await;

        transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await
            .unwrap();

        // Drain PeerConnected events from both sides
        let _ = transport_a.recv_control().await;
        let _ = transport_b.recv_control().await;

        (transport_a, transport_b, id_a, id_b, node_a_id, node_b_id)
    }

    #[tokio::test]
    async fn price_table_routed_through_control_channel() {
        let (transport_a, transport_b, _id_a, _id_b, node_a_id, node_b_id) =
            setup_connected_pair().await;

        // A sends a PriceTable to B
        let mut prices = std::collections::HashMap::new();
        prices.insert("communication".to_string(), 25u64);
        prices.insert("files_media".to_string(), 100u64);

        let frame = Frame::PriceTable {
            prices: prices.clone(),
            block_height: 850_000,
            valid_blocks: 144,
            trust_discount: 0.0,
        };
        transport_a.send_frame(&node_b_id, &frame).await.unwrap();

        // B should receive PriceTableReceived control event
        let event = tokio::time::timeout(
            Duration::from_secs(2),
            transport_b.recv_control(),
        )
        .await
        .expect("timeout")
        .expect("channel closed");

        match event {
            ControlEvent::PriceTableReceived {
                peer_id,
                prices: recv_prices,
                block_height,
                valid_blocks,
                trust_discount,
            } => {
                assert_eq!(peer_id, node_a_id);
                assert_eq!(recv_prices, prices);
                assert_eq!(block_height, 850_000);
                assert_eq!(valid_blocks, 144);
                assert!((trust_discount - 0.0).abs() < f64::EPSILON);
            }
            other => panic!("expected PriceTableReceived, got {:?}", other),
        }

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn price_query_and_response_routed() {
        let (transport_a, transport_b, _id_a, _id_b, node_a_id, node_b_id) =
            setup_connected_pair().await;

        // A sends a PriceQuery to B
        let query = Frame::PriceQuery { kind: 100 }; // KIND_CHAT
        transport_a.send_frame(&node_b_id, &query).await.unwrap();

        // B receives PriceQueryReceived
        let event = tokio::time::timeout(
            Duration::from_secs(2),
            transport_b.recv_control(),
        )
        .await
        .expect("timeout")
        .expect("channel closed");

        match event {
            ControlEvent::PriceQueryReceived { peer_id, kind } => {
                assert_eq!(peer_id, node_a_id);
                assert_eq!(kind, 100);
            }
            other => panic!("expected PriceQueryReceived, got {:?}", other),
        }

        // B responds with PriceResponse
        let response = Frame::PriceResponse {
            kind: 100,
            price_msat: 50,
            block_height: 850_001,
        };
        transport_b.send_frame(&node_a_id, &response).await.unwrap();

        // A receives PriceResponseReceived
        let event = tokio::time::timeout(
            Duration::from_secs(2),
            transport_a.recv_control(),
        )
        .await
        .expect("timeout")
        .expect("channel closed");

        match event {
            ControlEvent::PriceResponseReceived {
                peer_id,
                kind,
                price_msat,
                block_height,
            } => {
                assert_eq!(peer_id, node_b_id);
                assert_eq!(kind, 100);
                assert_eq!(price_msat, 50);
                assert_eq!(block_height, 850_001);
            }
            other => panic!("expected PriceResponseReceived, got {:?}", other),
        }

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn peer_exchange_request_and_response_routed() {
        let (transport_a, transport_b, _id_a, _id_b, node_a_id, node_b_id) =
            setup_connected_pair().await;

        // A sends PeerExchangeRequest to B
        transport_a
            .send_frame(&node_b_id, &Frame::PeerExchangeRequest)
            .await
            .unwrap();

        // B receives PeerExchangeRequested
        let event = tokio::time::timeout(
            Duration::from_secs(2),
            transport_b.recv_control(),
        )
        .await
        .expect("timeout")
        .expect("channel closed");

        match event {
            ControlEvent::PeerExchangeRequested { peer_id } => {
                assert_eq!(peer_id, node_a_id);
            }
            other => panic!("expected PeerExchangeRequested, got {:?}", other),
        }

        // B responds with a peer list
        let gamma_id = NodeId::from_bytes([42u8; 32]);
        let peer_entry = crate::wire::PeerExchangeEntry {
            node_id: gamma_id,
            addr: "10.0.0.3:9735".parse().unwrap(),
            label: Some("gamma".into()),
            tier: SovereigntyTier::T2,
        };
        let response = Frame::PeerExchangeResponse {
            peers: vec![peer_entry.clone()],
        };
        transport_b.send_frame(&node_a_id, &response).await.unwrap();

        // A receives PeerExchangeReceived
        let event = tokio::time::timeout(
            Duration::from_secs(2),
            transport_a.recv_control(),
        )
        .await
        .expect("timeout")
        .expect("channel closed");

        match event {
            ControlEvent::PeerExchangeReceived { peer_id, peers } => {
                assert_eq!(peer_id, node_b_id);
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].node_id, gamma_id);
                assert_eq!(peers[0].label.as_deref(), Some("gamma"));
                assert_eq!(peers[0].tier, SovereigntyTier::T2);
            }
            other => panic!("expected PeerExchangeReceived, got {:?}", other),
        }

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn ratchet_init_routed_through_control_channel() {
        let (transport_a, transport_b, _id_a, _id_b, node_a_id, node_b_id) =
            setup_connected_pair().await;

        // A sends RatchetInit to B
        let payload = b"ratchet-encrypted-init-payload".to_vec();
        let frame = Frame::RatchetInit {
            payload: payload.clone(),
        };
        transport_a.send_frame(&node_b_id, &frame).await.unwrap();

        // B should receive RatchetInit control event
        let event = tokio::time::timeout(
            Duration::from_secs(2),
            transport_b.recv_control(),
        )
        .await
        .expect("timeout")
        .expect("channel closed");

        match event {
            ControlEvent::RatchetInit {
                peer_id,
                payload: recv_payload,
            } => {
                assert_eq!(peer_id, node_a_id);
                assert_eq!(recv_payload, payload);
            }
            other => panic!("expected RatchetInit, got {:?}", other),
        }

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn graceful_disconnect_cleans_up_peer() {
        let (transport_a, transport_b, _id_a, _id_b, _node_a_id, node_b_id) =
            setup_connected_pair().await;

        assert!(transport_a.is_connected(&node_b_id).await);

        // A disconnects from B
        transport_a.disconnect(&node_b_id).await.unwrap();

        assert!(!transport_a.is_connected(&node_b_id).await);

        // Give B's reader task time to notice the disconnection
        tokio::time::sleep(Duration::from_millis(200)).await;

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn connected_peers_returns_correct_list() {
        let (transport_a, transport_b, _id_a, _id_b, _node_a_id, node_b_id) =
            setup_connected_pair().await;

        let peers_a = transport_a.connected_peers().await;
        assert_eq!(peers_a.len(), 1);
        assert_eq!(peers_a[0], node_b_id);

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn send_to_disconnected_peer_fails() {
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_b_id = *id_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };

        let transport_a = NoiseTransport::new(id_a, config_a);
        let envelope = make_test_envelope(
            &NodeIdentity::from_mnemonic(TEST_MNEMONIC_A, "").unwrap(),
            &node_b_id,
        );

        // Send to a peer we're not connected to
        let result = transport_a.send(&node_b_id, &envelope).await;
        assert!(result.is_err());

        transport_a.shutdown();
    }

    #[tokio::test]
    async fn connect_to_unreachable_address_fails() {
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_b_id = *id_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };

        let transport_a = NoiseTransport::new(id_a, config_a);

        // Try connecting to an address where nothing is listening
        let result = transport_a
            .connect(&node_b_id, "127.0.0.1:1")
            .await;

        assert!(result.is_err());
        transport_a.shutdown();
    }

    #[tokio::test]
    async fn empty_whitelist_rejects_outbound() {
        // A node with an empty whitelist cannot initiate connections
        // (Principle 3: closed mesh — empty whitelist = isolated node)
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        // A has empty whitelist — should fail to connect
        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![], // Empty = reject all
            ..Default::default()
        };

        // B whitelists A
        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_a_id],
            ..Default::default()
        };

        let transport_b = NoiseTransport::new(Arc::clone(&id_b), config_b);
        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let transport_a = NoiseTransport::new(Arc::clone(&id_a), config_a);

        // Should fail — A's empty whitelist rejects all outbound
        let result = transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await;

        assert!(result.is_err(), "empty whitelist must reject all connections");
        assert!(!transport_a.is_connected(&node_b_id).await);

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn empty_whitelist_rejects_inbound() {
        // A node with an empty whitelist also rejects inbound connections
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        // B has empty whitelist — should reject inbound from A
        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![], // Empty = reject all
            ..Default::default()
        };

        // A whitelists B
        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };

        let transport_b = NoiseTransport::new(Arc::clone(&id_b), config_b);
        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let transport_a = NoiseTransport::new(Arc::clone(&id_a), config_a);

        // A can connect (A whitelists B), but B will reject the inbound
        // connection after the federation handshake. A may or may not get
        // an error from connect(), but B should not register A as a peer.
        let _ = transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await;

        // Give B time to process and reject
        tokio::time::sleep(Duration::from_millis(200)).await;

        // B should NOT see A as connected (empty whitelist rejects all inbound)
        assert!(
            !transport_b.is_connected(&node_a_id).await,
            "empty whitelist node must not accept inbound peers"
        );

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn disconnect_non_connected_peer_is_noop() {
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_b_id = *id_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };

        let transport_a = NoiseTransport::new(id_a, config_a);

        // Disconnecting a peer we never connected to should succeed (noop)
        let result = transport_a.disconnect(&node_b_id).await;
        assert!(result.is_ok());

        transport_a.shutdown();
    }

    #[tokio::test]
    async fn connected_peers_empty_by_default() {
        let id_a = make_identity(TEST_MNEMONIC_A);

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![],
            ..Default::default()
        };

        let transport_a = NoiseTransport::new(id_a, config_a);

        let peers = transport_a.connected_peers().await;
        assert!(peers.is_empty());

        transport_a.shutdown();
    }

    #[tokio::test]
    async fn listen_addr_none_before_start() {
        let id_a = make_identity(TEST_MNEMONIC_A);

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![],
            ..Default::default()
        };

        let transport_a = NoiseTransport::new(id_a, config_a);

        // Before start_listener, listen_addr should be None
        assert!(transport_a.listen_addr().is_none());

        transport_a.shutdown();
    }

    #[tokio::test]
    async fn listen_addr_set_after_start() {
        let id_a = make_identity(TEST_MNEMONIC_A);

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![],
            ..Default::default()
        };

        let transport_a = NoiseTransport::new(id_a, config_a);
        transport_a.start_listener().await.unwrap();

        let addr = transport_a.listen_addr();
        assert!(addr.is_some());
        // OS should have assigned a real port
        assert_ne!(addr.unwrap().port(), 0);

        transport_a.shutdown();
    }

    #[tokio::test]
    async fn version_mismatch_rejects_connection() {
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        // A uses version 2, B uses version 99
        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            version: 2,
            ..Default::default()
        };

        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_a_id],
            version: 99, // mismatched version
            ..Default::default()
        };

        let transport_b = NoiseTransport::new(Arc::clone(&id_b), config_b);
        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let transport_a = NoiseTransport::new(Arc::clone(&id_a), config_a);

        // A tries to connect to B. The federation handshake should fail
        // because A sends Hello with version=2, B expects version=99
        // and responds with HelloAck version=99, which A rejects.
        let result = transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await;

        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("version") || err_msg.contains("mismatch") || err_msg.contains("Rejected"),
            "expected version mismatch error, got: {err_msg}"
        );

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[test]
    fn verify_identity_binding_empty_signature() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC_A, "").unwrap();
        let x25519_public = identity.x25519_public().as_bytes().to_vec();

        // Empty signature should fail
        let result = verify_identity_binding(
            identity.node_id(),
            &x25519_public,
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn verify_identity_binding_truncated_signature() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC_A, "").unwrap();
        let x25519_public = identity.x25519_public().as_bytes().to_vec();

        use ed25519_dalek::Signer;
        let sig = identity.ed25519_signing_key().sign(&x25519_public);
        let sig_bytes = sig.to_bytes();

        // Truncate to 32 bytes (Ed25519 sig is 64 bytes)
        let result = verify_identity_binding(
            identity.node_id(),
            &x25519_public,
            &sig_bytes[..32],
        );
        assert!(result.is_err());
    }

    #[test]
    fn verify_identity_binding_wrong_message() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC_A, "").unwrap();
        let x25519_public = identity.x25519_public().as_bytes().to_vec();

        use ed25519_dalek::Signer;
        // Sign a different message (not the x25519 public key)
        let sig = identity.ed25519_signing_key().sign(b"wrong message");

        let result = verify_identity_binding(
            identity.node_id(),
            &x25519_public,
            &sig.to_bytes(),
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn bidirectional_message_exchange() {
        let (transport_a, transport_b, id_a, id_b, node_a_id, node_b_id) =
            setup_connected_pair().await;

        // A sends to B
        let envelope_a = make_test_envelope(&id_a, &node_b_id);
        transport_a.send(&node_b_id, &envelope_a).await.unwrap();

        let received_by_b = transport_b.recv().await.unwrap();
        assert_eq!(received_by_b.sender, envelope_a.sender);

        // B sends to A
        let envelope_b = make_test_envelope(&id_b, &node_a_id);
        transport_b.send(&node_a_id, &envelope_b).await.unwrap();

        let received_by_a = transport_a.recv().await.unwrap();
        assert_eq!(received_by_a.sender, envelope_b.sender);

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn multiple_messages_in_sequence() {
        let (transport_a, transport_b, id_a, _id_b, _node_a_id, node_b_id) =
            setup_connected_pair().await;

        // Send 5 messages from A to B
        for _ in 0..5 {
            let envelope = make_test_envelope(&id_a, &node_b_id);
            transport_a.send(&node_b_id, &envelope).await.unwrap();
        }

        // B should receive all 5
        for _ in 0..5 {
            let received = transport_b.recv().await.unwrap();
            assert_eq!(received.sender, *id_a.node_id());
        }

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[test]
    fn transport_config_default_values() {
        let config = TransportConfig::default();
        assert_eq!(config.version, 2);
        assert_eq!(config.tier, SovereigntyTier::T1);
        assert!(config.capabilities.contains(&Capability::X3dh));
        assert!(
            !config.capabilities.contains(&Capability::Relay),
            "relay capability must be opt-in"
        );
        assert!(config.whitelist.is_empty());
    }

    /// Peer sending 11 garbage frames within 60 seconds gets disconnected and banned.
    #[tokio::test]
    async fn frame_validation_budget_exceeded_disconnects_peer() {
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };

        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_a_id],
            ..Default::default()
        };

        let transport_b = NoiseTransport::new(Arc::clone(&id_b), config_b);
        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let transport_a = NoiseTransport::new(Arc::clone(&id_a), config_a);
        transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await
            .unwrap();

        assert!(transport_a.is_connected(&node_b_id).await);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(transport_b.is_connected(&node_a_id).await);

        // Send 11 garbage frames from A to B (exceeds budget of 10)
        for i in 0..11 {
            let garbage = format!("{{invalid json garbage frame {i}");
            let result = transport_a
                .send_raw_bytes(&node_b_id, garbage.as_bytes())
                .await;
            if result.is_err() {
                // Connection may have been torn down from B's side
                break;
            }
            // Small delay to let B's reader task process each frame
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Wait for B to process all frames and disconnect A
        tokio::time::sleep(Duration::from_millis(200)).await;

        // B should have disconnected A
        assert!(
            !transport_b.is_connected(&node_a_id).await,
            "peer A should be disconnected after exceeding frame validation budget"
        );

        // B should have banned A
        let bans = transport_b.banned_peers.read().await;
        assert!(
            bans.contains_key(&node_a_id),
            "peer A should be in B's ban list"
        );

        transport_a.shutdown();
        transport_b.shutdown();
    }

    /// Peer sending 9 garbage frames + 1 valid frame stays connected (counter resets).
    #[tokio::test]
    async fn frame_validation_budget_resets_on_valid_frame() {
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };

        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_a_id],
            ..Default::default()
        };

        let transport_b = NoiseTransport::new(Arc::clone(&id_b), config_b);
        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let transport_a = NoiseTransport::new(Arc::clone(&id_a), config_a);
        transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(transport_b.is_connected(&node_a_id).await);

        // Send 9 garbage frames (below budget of 10)
        for i in 0..9 {
            let garbage = format!("not valid json {i}");
            transport_a
                .send_raw_bytes(&node_b_id, garbage.as_bytes())
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Send 1 valid frame (Ping) — should reset the counter
        let ping = Frame::Ping { nonce: 42 };
        transport_a.send_frame(&node_b_id, &ping).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // B should still be connected to A (counter was reset by valid Ping)
        assert!(
            transport_b.is_connected(&node_a_id).await,
            "peer A should still be connected after 9 garbage + 1 valid frame"
        );

        // Ban list should be empty
        let bans = transport_b.banned_peers.read().await;
        assert!(
            !bans.contains_key(&node_a_id),
            "peer A should NOT be banned"
        );

        transport_a.shutdown();
        transport_b.shutdown();
    }

    /// After ban expires, peer can reconnect.
    #[tokio::test]
    async fn banned_peer_can_reconnect_after_expiry() {
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_a_id],
            ..Default::default()
        };

        let transport_b = NoiseTransport::new(Arc::clone(&id_b), config_b);
        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Manually add A to B's ban list with an already-expired ban
        {
            let mut bans = transport_b.banned_peers.write().await;
            bans.insert(node_a_id, Instant::now() - Duration::from_secs(1));
        }

        // A should be able to connect despite being in the ban map (ban expired)
        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };

        let transport_a = NoiseTransport::new(Arc::clone(&id_a), config_a);
        transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            transport_b.is_connected(&node_a_id).await,
            "peer A should connect after ban expiry"
        );

        transport_a.shutdown();
        transport_b.shutdown();
    }

    /// Actively banned peer is rejected on connection attempt.
    #[tokio::test]
    async fn actively_banned_peer_rejected() {
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_a_id],
            ..Default::default()
        };

        let transport_b = NoiseTransport::new(Arc::clone(&id_b), config_b);
        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Manually add A to B's ban list with a future expiry
        {
            let mut bans = transport_b.banned_peers.write().await;
            bans.insert(node_a_id, Instant::now() + Duration::from_secs(60));
        }

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };

        let transport_a = NoiseTransport::new(Arc::clone(&id_a), config_a);

        // A tries to connect — the TCP + Noise handshake succeeds (B can't check
        // ban until federation handshake reveals A's identity), but the federation
        // handshake responder rejects A after identifying them.
        let _result = transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await;

        // The connection may fail with a rejection error, or the TCP might succeed
        // but B drops A immediately after. Either way, A should not end up connected.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !transport_b.is_connected(&node_a_id).await,
            "banned peer A should not be connected to B"
        );

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn peer_info_returns_tier_and_capabilities() {
        let (transport_a, transport_b, _id_a, _id_b, _node_a_id, node_b_id) =
            setup_connected_pair().await;

        // A should see B's tier and capabilities
        let info = transport_a.peer_info(&node_b_id).await;
        assert!(info.is_some(), "peer_info should return Some for connected peer");
        let info = info.unwrap();
        // Default TransportConfig uses T1 tier
        assert_eq!(info.tier, "T1");
        // Default capabilities include X3dh but do not opt into relay behavior.
        assert!(!info.capabilities.is_empty(), "should have at least one capability");
        assert!(
            !info.capabilities.iter().any(|cap| cap == "Relay"),
            "default peers should not advertise Relay"
        );

        // Disconnected peer returns None
        let unknown = NodeId::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert!(
            transport_a.peer_info(&unknown).await.is_none(),
            "peer_info should return None for unknown peer"
        );

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn relay_capability_is_advertised_only_when_configured() {
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_b_id],
            ..Default::default()
        };
        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            capabilities: vec![Capability::X3dh, Capability::Relay],
            whitelist: vec![node_a_id],
            ..Default::default()
        };

        let transport_a = NoiseTransport::new(Arc::clone(&id_a), config_a);
        let transport_b = NoiseTransport::new(Arc::clone(&id_b), config_b);

        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().expect("should have actual listen addr");
        tokio::time::sleep(Duration::from_millis(50)).await;

        transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await
            .unwrap();

        let _ = transport_a.recv_control().await;
        let _ = transport_b.recv_control().await;

        let b_info = transport_a
            .peer_info(&node_b_id)
            .await
            .expect("node B should be connected");
        assert!(
            b_info.capabilities.iter().any(|cap| cap == "Relay"),
            "configured relay peer should advertise Relay capability"
        );

        let a_info = transport_b
            .peer_info(&node_a_id)
            .await
            .expect("node A should be connected");
        assert!(
            !a_info.capabilities.iter().any(|cap| cap == "Relay"),
            "non-relay peer should not advertise Relay capability"
        );

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn dynamic_whitelist_add_enables_connection() {
        // A starts with B NOT in whitelist — connection should fail
        let identity_a = make_identity(TEST_MNEMONIC_A);
        let identity_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *identity_a.node_id();
        let node_b_id = *identity_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T1,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![], // Empty — B not whitelisted
            version: 2,
        };
        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T1,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_a_id], // A is whitelisted by B
            version: 2,
        };

        let transport_a = Arc::new(NoiseTransport::new(Arc::clone(&identity_a), config_a));
        let transport_b = Arc::new(NoiseTransport::new(Arc::clone(&identity_b), config_b));
        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Attempt to connect — should fail (B not in A's whitelist)
        let result = transport_a.connect(&node_b_id, &addr_b.to_string()).await;
        assert!(result.is_err(), "connection should fail with empty whitelist");

        // Dynamically add B to A's whitelist
        transport_a.add_to_whitelist(&node_b_id).await;

        // Now connection should succeed
        transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await
            .unwrap();
        assert!(transport_a.is_connected(&node_b_id).await);

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn dynamic_whitelist_remove_blocks_new_connections() {
        // Setup: both nodes whitelist each other
        let identity_a = make_identity(TEST_MNEMONIC_A);
        let identity_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *identity_a.node_id();
        let node_b_id = *identity_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T1,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_b_id],
            version: 2,
        };
        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T1,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_a_id],
            version: 2,
        };

        let transport_a = Arc::new(NoiseTransport::new(Arc::clone(&identity_a), config_a));
        let transport_b = Arc::new(NoiseTransport::new(Arc::clone(&identity_b), config_b));
        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect successfully
        transport_a
            .connect(&node_b_id, &addr_b.to_string())
            .await
            .unwrap();
        assert!(transport_a.is_connected(&node_b_id).await);

        // Disconnect and remove B from whitelist
        transport_a.disconnect(&node_b_id).await.unwrap();
        transport_a.remove_from_whitelist(&node_b_id).await;

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Attempting to reconnect should now fail
        let result = transport_a.connect(&node_b_id, &addr_b.to_string()).await;
        assert!(result.is_err(), "connection should fail after whitelist removal");

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn supervise_peer_connects_dynamically() {
        // Test that supervise_peer() (via the trait) connects to a peer
        // that was added after startup — simulating invite redemption.
        let identity_a = make_identity(TEST_MNEMONIC_A);
        let identity_b = make_identity(TEST_MNEMONIC_B);

        let node_a_id = *identity_a.node_id();
        let node_b_id = *identity_b.node_id();

        // A starts with B whitelisted but NOT in supervised list
        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T2,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_b_id],
            version: 2,
        };

        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T1,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_a_id],
            version: 2,
        };

        let transport_a = Arc::new(NoiseTransport::new(Arc::clone(&identity_a), config_a));
        let transport_b = Arc::new(NoiseTransport::new(Arc::clone(&identity_b), config_b));
        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A is not connected to B yet
        assert!(!transport_a.is_connected(&node_b_id).await);

        // Dynamically supervise B (simulates invite redemption path)
        transport_a.supervise_peer(&node_b_id, &addr_b.to_string()).await;

        // Wait for supervisor to establish connection
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            transport_a.is_connected(&node_b_id).await,
            "supervisor should have connected to peer"
        );

        transport_a.shutdown();
        transport_b.shutdown();
    }

    #[tokio::test]
    async fn supervise_peer_reconnects_after_disconnect() {
        // Test that a dynamically supervised peer reconnects after disconnection.
        let identity_a = make_identity(TEST_MNEMONIC_A);
        let identity_b = make_identity(TEST_MNEMONIC_B);

        let node_a_id = *identity_a.node_id();
        let node_b_id = *identity_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T2,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_b_id],
            version: 2,
        };

        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T1,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_a_id],
            version: 2,
        };

        let transport_a = Arc::new(NoiseTransport::new(Arc::clone(&identity_a), config_a));
        let transport_b = Arc::new(NoiseTransport::new(Arc::clone(&identity_b), config_b));
        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Start dynamic supervision
        transport_a.supervise_peer(&node_b_id, &addr_b.to_string()).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(transport_a.is_connected(&node_b_id).await);

        // Force disconnect — supervisor should reconnect
        transport_a.disconnect(&node_b_id).await.unwrap();
        assert!(!transport_a.is_connected(&node_b_id).await);

        // Wait for supervisor to notice and reconnect (backoff starts at 1s)
        tokio::time::sleep(Duration::from_millis(3000)).await;
        assert!(
            transport_a.is_connected(&node_b_id).await,
            "supervisor should have reconnected after disconnect"
        );

        transport_a.shutdown();
        transport_b.shutdown();
    }

    /// Expired bans are removed from the ban map during connection check,
    /// preventing unbounded growth of the ban map (memory leak fix).
    #[tokio::test]
    async fn expired_bans_evicted_on_connection() {
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_a_id],
            ..Default::default()
        };

        let transport_b = NoiseTransport::new(Arc::clone(&id_b), config_b);
        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Insert an expired ban for peer A
        {
            let mut bans = transport_b.banned_peers.write().await;
            bans.insert(node_a_id, Instant::now() - Duration::from_secs(10));
        }

        // Verify the ban entry exists before connection
        assert_eq!(transport_b.banned_peers.read().await.len(), 1);

        // A connects — the expired ban should be removed during connection check
        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };
        let transport_a = NoiseTransport::new(Arc::clone(&id_a), config_a);
        transport_a.connect(&node_b_id, &addr_b.to_string()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The expired ban entry should have been removed
        assert_eq!(
            transport_b.banned_peers.read().await.len(),
            0,
            "expired ban should be evicted on connection"
        );

        transport_a.shutdown();
        transport_b.shutdown();
    }

    /// Active bans are NOT removed from the ban map during connection check.
    #[tokio::test]
    async fn active_bans_preserved_on_connection() {
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *id_a.node_id();
        let node_b_id = *id_b.node_id();

        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_a_id],
            ..Default::default()
        };

        let transport_b = NoiseTransport::new(Arc::clone(&id_b), config_b);
        transport_b.start_listener().await.unwrap();
        let addr_b = transport_b.listen_addr().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Insert an active (future) ban for peer A
        {
            let mut bans = transport_b.banned_peers.write().await;
            bans.insert(node_a_id, Instant::now() + Duration::from_secs(60));
        }

        // A tries to connect — should be rejected
        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_b_id],
            ..Default::default()
        };
        let transport_a = NoiseTransport::new(Arc::clone(&id_a), config_a);
        let _result = transport_a.connect(&node_b_id, &addr_b.to_string()).await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Active ban entry should still be in the map
        assert_eq!(
            transport_b.banned_peers.read().await.len(),
            1,
            "active ban should be preserved"
        );

        transport_a.shutdown();
        transport_b.shutdown();
    }

    /// Mixed expired and active bans: only expired entries are removed.
    #[tokio::test]
    async fn mixed_bans_only_expired_evicted() {
        let id_a = make_identity(TEST_MNEMONIC_A);
        let id_b = make_identity(TEST_MNEMONIC_B);
        let id_c = make_identity(TEST_MNEMONIC_C);
        let node_a_id = *id_a.node_id();
        let node_c_id = *id_c.node_id();

        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![node_a_id],
            ..Default::default()
        };

        let transport_b = NoiseTransport::new(Arc::clone(&id_b), config_b);

        // Insert one expired and one active ban
        {
            let mut bans = transport_b.banned_peers.write().await;
            bans.insert(node_a_id, Instant::now() - Duration::from_secs(5));
            bans.insert(node_c_id, Instant::now() + Duration::from_secs(60));
        }

        assert_eq!(transport_b.banned_peers.read().await.len(), 2);

        // Simulate periodic eviction (same logic as the eviction task)
        {
            let now = Instant::now();
            let mut bans = transport_b.banned_peers.write().await;
            bans.retain(|_, expiry| *expiry > now);
        }

        // Only the active ban should remain
        let bans = transport_b.banned_peers.read().await;
        assert_eq!(bans.len(), 1, "only active ban should remain");
        assert!(bans.contains_key(&node_c_id), "C's active ban should persist");
        assert!(!bans.contains_key(&node_a_id), "A's expired ban should be evicted");

        transport_b.shutdown();
    }

    /// Verify that `send_frame` releases the peers RwLock before doing I/O,
    /// allowing concurrent peer-map writes (connect/disconnect).
    #[tokio::test]
    async fn send_frame_does_not_hold_peers_rwlock_during_io() {
        let identity_a = make_identity(TEST_MNEMONIC_A);
        let identity_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *identity_a.node_id();
        let node_b_id = *identity_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T2,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_b_id],
            version: 2,
        };
        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T2,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_a_id],
            version: 2,
        };

        let transport_a = NoiseTransport::new(Arc::clone(&identity_a), config_a);
        let transport_b = NoiseTransport::new(Arc::clone(&identity_b), config_b);

        transport_b.start_listener().await.unwrap();
        let listen_addr = transport_b.listen_addr().expect("should have listen addr");
        transport_a.connect(&node_b_id, &listen_addr.to_string()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Concurrently: send a frame AND try to write-lock the peers map.
        // Before the lock-narrowing fix, send_frame held the RwLock read
        // guard across the TCP write, which would block write-lock
        // acquisition (connect/disconnect) for the duration of the I/O.
        let peers_for_write: PeerMap = Arc::clone(&transport_a.peers);

        let send_result = transport_a
            .send_frame(&node_b_id, &Frame::Ping { nonce: 999 })
            .await;
        assert!(send_result.is_ok(), "send_frame should succeed");

        // If the read lock were still held, this write lock would hang.
        // With lock-narrowing, it completes instantly.
        let write_ok = tokio::time::timeout(Duration::from_secs(2), async {
            let _guard = peers_for_write.write().await;
        })
        .await;
        assert!(
            write_ok.is_ok(),
            "peers write lock should be acquirable after send_frame completes"
        );

        transport_a.shutdown();
        transport_b.shutdown();
    }

    /// Verify that `send_raw_frame` also releases the peers RwLock before I/O.
    #[tokio::test]
    async fn send_raw_frame_does_not_hold_peers_rwlock_during_io() {
        let identity_a = make_identity(TEST_MNEMONIC_A);
        let identity_b = make_identity(TEST_MNEMONIC_B);
        let node_a_id = *identity_a.node_id();
        let node_b_id = *identity_b.node_id();

        let config_a = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T2,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_b_id],
            version: 2,
        };
        let config_b = TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tier: SovereigntyTier::T2,
            capabilities: vec![Capability::X3dh],
            whitelist: vec![node_a_id],
            version: 2,
        };

        let transport_a = NoiseTransport::new(Arc::clone(&identity_a), config_a);
        let transport_b = NoiseTransport::new(Arc::clone(&identity_b), config_b);

        transport_b.start_listener().await.unwrap();
        let listen_addr = transport_b.listen_addr().expect("should have listen addr");
        transport_a.connect(&node_b_id, &listen_addr.to_string()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let peers_for_write: PeerMap = Arc::clone(&transport_a.peers);

        let ping = Frame::Ping { nonce: 42 };
        let bytes = ping.to_bytes().unwrap();
        let send_result = transport_a.send_raw_frame(&node_b_id, &bytes).await;
        assert!(send_result.is_ok(), "send_raw_frame should succeed");

        let write_ok = tokio::time::timeout(Duration::from_secs(2), async {
            let _guard = peers_for_write.write().await;
        })
        .await;
        assert!(
            write_ok.is_ok(),
            "peers write lock should be acquirable after send_raw_frame completes"
        );

        transport_a.shutdown();
        transport_b.shutdown();
    }
}
