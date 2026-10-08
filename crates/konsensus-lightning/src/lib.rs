//! konsensus-lightning — Lightning Network provider implementations.
//!
//! Implements `LightningProvider` trait for:
//! - **LNbits** — HTTP REST API (fastest path to payment gate)
//! - **LND** — direct REST API to LND daemon (Full tier, no LNbits middleman)
//! - **LDK** — embedded sovereign Lightning node (no external daemon)
//! - **CLN (preview)** — pinned HTTPS connectivity/status only; no payments
//! - **Mock** — in-memory provider for testing

#![forbid(unsafe_code)]

pub mod tower;
mod balance;
pub mod circuit_breaker;
pub mod cln;
pub mod move_home;
mod onchain;
pub mod recovering;
pub use recovering::RecoveringLightning;
pub mod ldk;
mod ldk_logging;
pub mod liquidity;
pub mod lnbits;
pub mod lnd;
pub mod lsps2_service;
pub mod mock;
pub mod scb_export;
pub mod scb_restore;
pub mod scb_rotate;
pub mod shared_mock;

#[cfg(test)]
mod lnbits_tests;

pub use circuit_breaker::{CircuitBreakerConfig, CircuitBreakerLightning};
pub use cln::{ClnConfig, ClnProvider};
pub use ldk::{
    esplora_tx_visible, probe_esplora_fee_estimates, select_esplora_endpoint, LdkConfig,
    LdkProvider,
};
pub use lnbits::{LnbitsConfig, LnbitsProvider};
pub use lnd::{LndConfig, LndProvider};
pub use mock::{MockLightningConfig, MockLightningProvider};
pub use scb_restore::{
    decrypt_and_load_scb_backup, force_close_restored_channels, RestoredChannelEstimate,
    ScbRestoreError,
};
pub use scb_rotate::{decrypt_scb_backup, rotate_scb_backup, ScbBackupMetadata, ScbRotationConfig};
