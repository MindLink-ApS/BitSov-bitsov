//! MessageTransport trait — reliable UKM delivery over Noise_XX/TCP.
//!
//! Handles peer connections, message sending/receiving, and delivery confirmation.

use async_trait::async_trait;
use thiserror::Error;

use serde::{Deserialize, Serialize};

use crate::envelope::UkmEnvelope;
use crate::types::NodeId;

/// Information about a connected peer obtained during federation handshake.
///
/// Exposes the peer's advertised sovereignty tier and capabilities as strings,
/// keeping the core trait independent of `konsensus-message` wire types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedPeerInfo {
    /// Sovereignty tier as a string (e.g. "T1", "T2", "T3", "T4").
    pub tier: String,
    /// Capabilities advertised during handshake (e.g. "X3dh", "FileTransfer").
    pub capabilities: Vec<String>,
}

/// Errors from message transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Not connected to the target peer.
    #[error("not connected to peer: {0}")]
    NotConnected(String),

    /// Connection failed (handshake, network, etc.).
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Message serialization/deserialization error.
    #[error("wire protocol error: {0}")]
    WireProtocol(String),

    /// Noise protocol handshake or encryption error.
    #[error("noise error: {0}")]
    NoiseError(String),

    /// Peer rejected the message (invalid payment, etc.).
    #[error("message rejected by peer: {0}")]
    Rejected(String),

    /// Timeout waiting for delivery or response.
    #[error("transport timeout: {0}")]
    Timeout(String),

    /// General transport error.
    #[error("transport error: {0}")]
    Other(String),
}

/// Reliable UKM transport over Noise_XX encrypted TCP connections.
///
/// Implements Principle 3 (Closed Mesh): every hop is direct node-to-node,
/// zero third-party relays.
#[async_trait]
pub trait MessageTransport: Send + Sync {
    /// Send a UKM envelope to the specified peer.
    ///
    /// Establishes a connection if one doesn't exist. The envelope's
    /// `recipient` field determines the target.
    async fn send(&self, peer: &NodeId, envelope: &UkmEnvelope) -> Result<(), TransportError>;

    /// Receive the next incoming UKM envelope.
    ///
    /// Blocks until a message is available or the transport is shut down.
    async fn recv(&self) -> Result<UkmEnvelope, TransportError>;

    /// Connect to a peer by node ID and address.
    async fn connect(&self, peer: &NodeId, addr: &str) -> Result<(), TransportError>;

    /// Disconnect from a peer.
    async fn disconnect(&self, peer: &NodeId) -> Result<(), TransportError>;

    /// Check whether we have an active connection to a peer.
    async fn is_connected(&self, peer: &NodeId) -> bool;

    /// List all currently connected peers.
    async fn connected_peers(&self) -> Vec<NodeId>;

    /// Request peer exchange from a connected peer.
    ///
    /// Sends a peer exchange request to the specified peer. The peer responds
    /// asynchronously with its known peers via a control event. Returns an
    /// error if the peer is not connected or the transport doesn't support it.
    async fn request_peer_exchange(&self, peer: &NodeId) -> Result<(), TransportError> {
        let _ = peer;
        Err(TransportError::Other("peer exchange not supported by this transport".into()))
    }

    /// Send pre-serialized frame bytes to a connected peer.
    ///
    /// Used by the API layer to send wire protocol frames (e.g., invoice
    /// request/response) without the transport trait depending on the Frame
    /// type (which lives in `konsensus-message`). The caller is responsible
    /// for serializing the frame to bytes.
    async fn send_raw_frame(&self, peer: &NodeId, frame_bytes: &[u8]) -> Result<(), TransportError> {
        let _ = (peer, frame_bytes);
        Err(TransportError::Other("send_raw_frame not supported by this transport".into()))
    }

    /// Get federation handshake info for a connected peer.
    ///
    /// Returns the peer's sovereignty tier and capabilities as advertised
    /// during the federation handshake. Returns `None` if the peer is not
    /// connected or the transport doesn't track this information.
    async fn peer_info(&self, peer: &NodeId) -> Option<ConnectedPeerInfo> {
        let _ = peer;
        None
    }

    /// Add a peer to the transport whitelist (Principle 3: Closed Mesh).
    ///
    /// Called when a peer is added via invite redemption or manual peer add.
    /// After this call, the peer can connect inbound and the node can connect
    /// outbound to them. No-op for transports that don't enforce whitelists.
    async fn add_to_whitelist(&self, _peer: &NodeId) {}

    /// Remove a peer from the transport whitelist (Principle 3: Closed Mesh).
    ///
    /// Called when a peer is removed. After this call, the peer cannot initiate
    /// new connections and the node will not connect outbound to them.
    /// Existing connections are NOT terminated — call `disconnect()` separately.
    /// No-op for transports that don't enforce whitelists.
    async fn remove_from_whitelist(&self, _peer: &NodeId) {}

    /// Start connection supervision for a single peer.
    ///
    /// Spawns a background task that monitors the connection to `peer` and
    /// automatically reconnects with exponential backoff if the connection
    /// drops. Also sends keepalive pings to detect silent failures.
    ///
    /// Called when a peer is added dynamically (e.g. via invite redemption)
    /// so that the peer gets the same reconnection resilience as peers
    /// configured at startup. No-op for transports without supervision.
    async fn supervise_peer(&self, _peer: &NodeId, _addr: &str) {}
}
