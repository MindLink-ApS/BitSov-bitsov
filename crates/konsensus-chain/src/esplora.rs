//! Esplora HTTP ChainProvider — queries a block explorer REST API.
//!
//! Works with any Esplora-compatible API (mempool.space, self-hosted Esplora,
//! Blockstream.info). This is the simplest ChainProvider to deploy — just
//! point it at a URL.
//!
//! # Sovereignty tiers
//!
//! - **T1 Light**: Use a public Esplora instance (mempool.space)
//! - **T2 Standard**: Self-hosted Esplora behind Tor
//! - **T3+ Full**: Self-hosted Esplora connected to own Bitcoin Core
//!
//! # API endpoints used
//!
//! - `GET /api/blocks/tip/height` — current block height (plain text)
//! - `GET /api/block-height/{height}` — block hash at height (plain text)
//! - `GET /api/block/{hash}` — block metadata (JSON)
//! - `GET /api/fee-estimates` — fee rate estimates (JSON)
//! - `GET /api/tx/{txid}` — transaction details (JSON)

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use tracing::{debug, instrument};

use konsensus_core::traits::chain::{
    BlockHeader, ChainError, ChainProvider, FeeEstimate, TrustLevel,
};

/// Configuration for the Esplora provider.
#[derive(Debug, Clone)]
pub struct EsploraConfig {
    /// Base URL of the Esplora API (e.g. `https://mempool.space`).
    pub api_url: String,
    /// Trust level — controls how much we trust this data source.
    /// Typically `ServerTrust` since we rely on the Esplora server.
    pub trust_level: TrustLevel,
    /// HTTP request timeout in seconds.
    pub timeout_secs: u64,
}

impl EsploraConfig {
    /// Create config pointing at mempool.space (public, T1 default).
    pub fn mempool_space() -> Self {
        Self {
            api_url: "https://mempool.space".into(),
            trust_level: TrustLevel::ServerTrust,
            timeout_secs: 30,
        }
    }

    /// Create config for a self-hosted instance.
    pub fn custom(api_url: String, trust_level: TrustLevel) -> Self {
        Self {
            api_url,
            trust_level,
            timeout_secs: 30,
        }
    }
}

/// Esplora HTTP ChainProvider.
pub struct EsploraProvider {
    config: EsploraConfig,
    client: Client,
}

/// JSON response from `/api/block/{hash}`.
#[derive(Debug, Deserialize)]
struct EsploraBlock {
    id: String,
    height: u64,
    timestamp: u64,
    bits: u64,
    #[allow(dead_code)]
    nonce: u64,
    #[allow(dead_code)]
    difficulty: f64,
}

/// JSON response from `/api/tx/{txid}`.
#[derive(Debug, Deserialize)]
struct EsploraTx {
    status: EsploraTxStatus,
}

/// Transaction confirmation status.
#[derive(Debug, Deserialize)]
struct EsploraTxStatus {
    confirmed: bool,
    block_height: Option<u64>,
}

impl EsploraProvider {
    /// Create a new Esplora provider with the given configuration.
    ///
    /// Returns an error if the HTTP client cannot be built (e.g. TLS
    /// backend unavailable).
    pub fn new(config: EsploraConfig) -> Result<Self, ChainError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| ChainError::Connection(format!("failed to build HTTP client: {e}")))?;

        Ok(Self { config, client })
    }

    /// Create a provider with a custom reqwest Client (for testing).
    pub fn with_client(config: EsploraConfig, client: Client) -> Self {
        Self { config, client }
    }

    /// Build the API URL for a given path.
    ///
    /// Handles both `https://mempool.space` and `https://mempool.space/api`
    /// as input — strips a trailing `/api` if present to avoid double-prefixing.
    fn api_url(&self, path: &str) -> String {
        let base = self.config.api_url.trim_end_matches('/');
        let base = base.strip_suffix("/api").unwrap_or(base);
        format!("{base}/api{path}")
    }

    /// Make a GET request and return the response text.
    async fn get_text(&self, path: &str) -> Result<String, ChainError> {
        let url = self.api_url(path);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ChainError::Connection(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ChainError::Backend(format!("{path}: {status} — {body}")));
        }

        response
            .text()
            .await
            .map_err(|e| ChainError::Backend(format!("read body: {e}")))
    }

    /// Make a GET request and deserialize JSON.
    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, ChainError> {
        let url = self.api_url(path);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ChainError::Connection(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ChainError::Backend(format!("{path}: {status} — {body}")));
        }

        response
            .json()
            .await
            .map_err(|e| ChainError::Backend(format!("parse json: {e}")))
    }
}

#[async_trait]
impl ChainProvider for EsploraProvider {
    fn trust_level(&self) -> TrustLevel {
        self.config.trust_level
    }

    #[instrument(skip(self))]
    async fn get_block_height(&self) -> Result<u64, ChainError> {
        let text = self.get_text("/blocks/tip/height").await?;
        let height: u64 = text
            .trim()
            .parse()
            .map_err(|e| ChainError::Backend(format!("parse height: {e}")))?;

        debug!(height, "got block height");
        Ok(height)
    }

    #[instrument(skip(self))]
    async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError> {
        // First get the block hash at this height
        let hash = self
            .get_text(&format!("/block-height/{height}"))
            .await
            .map_err(|e| ChainError::Backend(format!("block hash at height {height}: {e}")))?;
        let hash = hash.trim().to_string();

        // Then get the full block info
        let block: EsploraBlock = self.get_json(&format!("/block/{hash}")).await?;

        Ok(BlockHeader {
            height: block.height,
            hash: block.id,
            timestamp: block.timestamp,
            bits: u32::try_from(block.bits)
                .map_err(|_| ChainError::Backend(format!("block bits overflows u32: {}", block.bits)))?,
        })
    }

    #[instrument(skip(self))]
    async fn estimate_fee(&self, target_blocks: u32) -> Result<FeeEstimate, ChainError> {
        // Esplora returns a map of confirmation target -> fee rate (sat/vB)
        let estimates: HashMap<String, f64> = self.get_json("/fee-estimates").await?;

        let target_str = target_blocks.to_string();

        // Find exact match or closest higher target
        let sat_per_vbyte = if let Some(&rate) = estimates.get(&target_str) {
            rate
        } else {
            // Find the closest available target
            let mut closest: Option<(u32, f64)> = None;
            for (key, &rate) in &estimates {
                if let Ok(t) = key.parse::<u32>() {
                    match closest {
                        None => closest = Some((t, rate)),
                        Some((prev_t, _)) => {
                            // Prefer exact match > nearest higher > nearest lower
                            let prev_dist = prev_t.abs_diff(target_blocks);
                            let curr_dist = t.abs_diff(target_blocks);
                            if curr_dist < prev_dist {
                                closest = Some((t, rate));
                            }
                        }
                    }
                }
            }

            closest
                .map(|(_, rate)| rate)
                .ok_or_else(|| {
                    ChainError::FeeEstimationFailed("no fee estimates available".into())
                })?
        };

        debug!(target_blocks, sat_per_vbyte, "fee estimate");

        Ok(FeeEstimate {
            target_blocks,
            sat_per_vbyte,
        })
    }

    #[instrument(skip(self))]
    async fn is_tx_confirmed(
        &self,
        txid: &str,
        min_confirmations: u32,
    ) -> Result<bool, ChainError> {
        let tx: EsploraTx = self
            .get_json(&format!("/tx/{txid}"))
            .await
            .map_err(|e| ChainError::Backend(format!("tx lookup {txid}: {e}")))?;

        if !tx.status.confirmed {
            return Ok(false);
        }

        // If we need to check confirmations, compare block heights
        if min_confirmations > 1 {
            if let Some(block_height) = tx.status.block_height {
                let tip_height = self.get_block_height().await?;
                let confirmations = tip_height.saturating_sub(block_height) + 1;
                return Ok(confirmations >= min_confirmations as u64);
            }
            return Ok(false);
        }

        Ok(true)
    }

    async fn is_synced(&self) -> bool {
        self.get_block_height().await.is_ok()
    }
}

#[cfg(test)]
#[path = "tests/esplora.rs"]
mod tests;
