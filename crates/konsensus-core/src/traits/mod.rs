//! Core trait definitions for the BitSov v2 system.
//!
//! These traits define the provider interfaces that vary by sovereignty tier:
//! - [`ChainProvider`] — Bitcoin chain data (Neutrino, Electrum, Bitcoin Core)
//! - [`LightningProvider`] — Lightning payments (LNbits, LND, CLN, LDK)
//! - [`PricingEngine`] — Kind-aware message pricing
//! - [`MessageTransport`] — Noise_XX encrypted P2P messaging
//! - [`MediaTransport`] — Voice/video (WebRTC) — **deferred**

pub mod chain;
pub mod lightning;
pub mod media;
pub mod pricing;
pub mod transport;

pub use chain::{BlockHeader, ChainError, ChainProvider, FeeEstimate, TrustLevel};
pub use lightning::{
    ChannelInfo, Invoice, LightningError, LightningProvider, PaymentDetails, PaymentDirection,
    PaymentStatus,
};
pub use media::{MediaError, MediaTransport};
pub use pricing::{PricingEngine, PricingError};
pub use transport::{ConnectedPeerInfo, MessageTransport, TransportError};
