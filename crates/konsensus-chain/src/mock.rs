//! Mock chain provider — returns static block data for testnet/offline use.
//!
//! No network calls, no external dependencies. Returns plausible Bitcoin
//! mainnet-like data so the node can operate without internet access.

use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use tracing::debug;

use konsensus_core::traits::chain::{
    BlockHeader, ChainError, ChainProvider, FeeEstimate, TrustLevel,
};

/// Configuration for the mock chain provider.
#[derive(Debug, Clone)]
pub struct MockChainConfig {
    /// Starting block height (advances with each query to simulate progress).
    pub initial_height: u64,
    /// Default fee rate in sat/vB.
    pub default_fee_sat_per_vb: f64,
}

impl Default for MockChainConfig {
    fn default() -> Self {
        Self {
            initial_height: 886_000, // Plausible Bitcoin height (test fixture; see tests)
            default_fee_sat_per_vb: 5.0,
        }
    }
}

/// In-memory chain provider for testnet and development.
///
/// Returns static but plausible Bitcoin block data. Block height
/// increments slowly to simulate chain progress.
pub struct MockChainProvider {
    config: MockChainConfig,
    /// Query counter — used to slowly advance block height.
    queries: AtomicU64,
}

impl MockChainProvider {
    /// Create a new mock chain provider with default config.
    pub fn new() -> Self {
        Self::with_config(MockChainConfig::default())
    }

    /// Create a new mock chain provider with custom config.
    pub fn with_config(config: MockChainConfig) -> Self {
        Self {
            config,
            queries: AtomicU64::new(0),
        }
    }

    /// Get current simulated height (advances by 1 every 60 queries).
    fn current_height(&self) -> u64 {
        let q = self.queries.fetch_add(1, Ordering::Relaxed);
        self.config.initial_height + q / 60
    }

    /// Generate a deterministic fake block hash for a given height.
    fn fake_hash(height: u64) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(format!("konsensus-mock-block-{height}").as_bytes());
        // Prefix with zeros to look like a real Bitcoin block hash
        format!("0000000000000000000{}", &hex::encode(hash)[..45])
    }
}

impl Default for MockChainProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainProvider for MockChainProvider {
    fn trust_level(&self) -> TrustLevel {
        TrustLevel::ServerTrust
    }

    async fn get_block_height(&self) -> Result<u64, ChainError> {
        let height = self.current_height();
        debug!(height, "mock block height");
        Ok(height)
    }

    async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError> {
        // Plausible timestamp: genesis (2009-01-03) + ~10 min per block
        let timestamp = 1_231_006_505 + height * 600;

        Ok(BlockHeader {
            height,
            hash: Self::fake_hash(height),
            timestamp,
            bits: 0x1703_2e3b, // Typical recent difficulty
        })
    }

    async fn estimate_fee(&self, target_blocks: u32) -> Result<FeeEstimate, ChainError> {
        // Higher urgency = higher fee (simple linear model)
        let multiplier = match target_blocks {
            1 => 5.0,
            2..=3 => 3.0,
            4..=6 => 2.0,
            7..=12 => 1.5,
            _ => 1.0,
        };

        Ok(FeeEstimate {
            target_blocks,
            sat_per_vbyte: self.config.default_fee_sat_per_vb * multiplier,
        })
    }

    async fn is_tx_confirmed(
        &self,
        _txid: &str,
        _min_confirmations: u32,
    ) -> Result<bool, ChainError> {
        // All transactions are "confirmed" in mock mode
        Ok(true)
    }

    async fn is_synced(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[path = "tests/mock.rs"]
mod tests;
