//! konsensus-lightning — Lightning Network provider implementations.
//!
//! Implements `LightningProvider` trait for:
//! - **LNbits** — HTTP REST API (fastest path to payment gate)
//! - **LND** — direct REST API to LND daemon (Full tier, no LNbits middleman)
//! - **LDK** — embedded sovereign Lightning node (no external daemon)
//! - **Mock** — in-memory provider for testing

#![forbid(unsafe_code)]

pub mod circuit_breaker;
pub mod ldk;
pub mod lnd;
pub mod lnbits;
pub mod mock;
pub mod scb_export;
pub mod scb_restore;
pub mod scb_rotate;

#[cfg(test)]
mod lnbits_tests;

pub use circuit_breaker::{CircuitBreakerConfig, CircuitBreakerLightning};
pub use ldk::{
    esplora_tx_visible, probe_esplora_fee_estimates, select_esplora_endpoint, LdkConfig,
    LdkProvider,
};
pub use lnd::{LndConfig, LndProvider};
pub use lnbits::{LnbitsConfig, LnbitsProvider};
pub use mock::{MockLightningConfig, MockLightningProvider};
pub use scb_rotate::{decrypt_scb_backup, rotate_scb_backup, ScbBackupMetadata, ScbRotationConfig};
pub use scb_restore::{
    decrypt_and_load_scb_backup, force_close_restored_channels, RestoredChannelEstimate,
    ScbRestoreError,
};
