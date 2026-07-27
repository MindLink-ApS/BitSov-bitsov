//! ChainProvider trait — abstraction over Bitcoin chain data sources.
//!
//! Implementations: Neutrino (BIP 157/158), Electrum, Bitcoin Core RPC.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// How much trust we place in the chain data source.
///
/// Maps to sovereignty tiers: T1 Light uses Neutrino (SPV-level trust),
/// T2 uses Electrum (server-trusting), T3/T4 use a local Bitcoin Core
/// (full validation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    /// SPV-level: compact block filters, no full validation.
    /// Used by Neutrino (T1 Light).
    Spv,
    /// Server-trusting: relies on an external Electrum server.
    /// Used by T2 Standard.
    ServerTrust,
    /// Full validation: local Bitcoin Core with complete UTXO set.
    /// Used by T3 Full and T4 Infrastructure.
    FullValidation,
}

/// Errors from chain data operations.
#[derive(Debug, Error)]
pub enum ChainError {
    /// The chain backend is not connected or not synced.
    #[error("chain not available: {0}")]
    NotAvailable(String),

    /// Requested block not found.
    #[error("block not found at height {0}")]
    BlockNotFound(u64),

    /// Transaction not found.
    #[error("transaction not found: {0}")]
    TxNotFound(String),

    /// Fee estimation failed.
    #[error("fee estimation failed: {0}")]
    FeeEstimationFailed(String),

    /// Connection or transport error.
    #[error("connection error: {0}")]
    Connection(String),

    /// General I/O or backend error.
    #[error("chain backend error: {0}")]
    Backend(String),
}

/// Summary of a block header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height.
    pub height: u64,
    /// Block hash (hex-encoded, 32 bytes).
    pub hash: String,
    /// Unix timestamp of the block.
    pub timestamp: u64,
    /// Difficulty target (compact nBits).
    pub bits: u32,
}

/// Fee estimate for a target confirmation depth.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FeeEstimate {
    /// Target number of blocks for confirmation.
    pub target_blocks: u32,
    /// Estimated fee rate in satoshis per virtual byte (sat/vB).
    pub sat_per_vbyte: f64,
}

/// Abstraction over Bitcoin chain data sources.
///
/// Provides block data, fee estimates, and transaction verification.
/// Implementations vary by sovereignty tier.
#[async_trait]
pub trait ChainProvider: Send + Sync {
    /// The trust level of this chain data source.
    fn trust_level(&self) -> TrustLevel;

    /// Get the current best block height.
    async fn get_block_height(&self) -> Result<u64, ChainError>;

    /// Get the block header at the given height.
    async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError>;

    /// Get the best (tip) block header.
    async fn get_best_block_header(&self) -> Result<BlockHeader, ChainError> {
        let height = self.get_block_height().await?;
        self.get_block_header(height).await
    }

    /// Estimate the fee rate for a target confirmation depth.
    async fn estimate_fee(&self, target_blocks: u32) -> Result<FeeEstimate, ChainError>;

    /// Check whether a transaction is confirmed (has at least `min_confirmations`).
    async fn is_tx_confirmed(
        &self,
        txid: &str,
        min_confirmations: u32,
    ) -> Result<bool, ChainError>;

    /// Check whether the chain backend is connected and synced.
    async fn is_synced(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_level_ordering() {
        // Verify the variants exist and are distinct
        assert_ne!(TrustLevel::Spv, TrustLevel::ServerTrust);
        assert_ne!(TrustLevel::ServerTrust, TrustLevel::FullValidation);
        assert_ne!(TrustLevel::Spv, TrustLevel::FullValidation);
    }

    #[test]
    fn chain_error_display() {
        let err = ChainError::BlockNotFound(100);
        assert!(err.to_string().contains("100"));

        let err = ChainError::NotAvailable("syncing".into());
        assert!(err.to_string().contains("syncing"));
    }

    #[test]
    fn block_header_serialization() {
        let header = BlockHeader {
            height: 800_000,
            hash: "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72f8804bf".into(),
            timestamp: 1_690_000_000,
            bits: 0x1703_2e3b,
        };
        let json = serde_json::to_string(&header).unwrap();
        let deserialized: BlockHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.height, 800_000);
    }
}
