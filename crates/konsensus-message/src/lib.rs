//! konsensus-message — Noise_XX encrypted P2P transport and wire protocol.
//!
//! This crate implements the transport layer for the BitSov v2 network:
//! - **Wire protocol** — length-prefixed frame format for all communication
//! - **NoiseTransport** — Noise_XX encrypted TCP transport with federation handshake
//!
//! All connections are direct node-to-node (Principle 3: Closed Mesh).
//! All traffic is encrypted (Noise_XX + AEAD).

#![forbid(unsafe_code)]

pub mod peer;
pub mod transport;
pub mod wire;

pub use peer::{PeerConfig, PeerEntry, PeerRegistry};
pub use transport::{ControlEvent, NoiseTransport, TransportConfig};
pub use wire::{Capability, Frame, PeerExchangeEntry, SovereigntyTier, WireError};
