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
use esplora_client::{r#async::HttpTransport, rate_limit::RateLimitedTransport};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::{sync::Mutex, time::Instant};
use tracing::{debug, instrument};

use konsensus_core::traits::chain::{
    BlockHeader, ChainError, ChainProvider, FeeEstimate, TrustLevel,
};

/// Maximum age of a cached tip height, shared by callers of one provider.
const TIP_HEIGHT_CACHE_TTL: Duration = Duration::from_secs(30);

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
    endpoints: Vec<(String, Arc<RateLimitedTransport>)>,
    active: AtomicUsize,
    transport: Option<Arc<dyn HttpTransport>>,
    bearer: Option<Arc<dyn HttpTransport>>,
    tip_height: Mutex<Option<(u64, Instant)>>,
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
        Self::with_fallbacks(config, Vec::new())
    }

    /// Try the primary followed by the operator's fallback endpoints.
    pub fn with_fallbacks(
        config: EsploraConfig,
        fallbacks: Vec<String>,
    ) -> Result<Self, ChainError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| ChainError::Connection(format!("failed to build HTTP client: {e}")))?;

        Ok(Self::from_parts(config, client, fallbacks))
    }

    /// Create a provider with a custom reqwest Client (for testing).
    pub fn with_client(config: EsploraConfig, client: Client) -> Self {
        Self::from_parts(config, client, Vec::new())
    }

    fn from_parts(config: EsploraConfig, client: Client, fallbacks: Vec<String>) -> Self {
        let mut endpoints: Vec<(String, Arc<RateLimitedTransport>)> = Vec::new();
        for url in std::iter::once(&config.api_url).chain(fallbacks.iter()) {
            let base = url.trim_end_matches('/');
            let base = base.strip_suffix("/api").unwrap_or(base);
            let api = format!("{base}/api");
            if !endpoints.iter().any(|(url, _)| *url == api) {
                let limiter = RateLimitedTransport::shared(&api);
                endpoints.push((api, limiter));
            }
        }
        Self {
            config,
            client,
            endpoints,
            active: AtomicUsize::new(0),
            transport: None,
            bearer: None,
            tip_height: Mutex::new(None),
        }
    }

    /// Authenticate only the primary; fallbacks retain their existing unauthenticated policy.
    pub fn with_bearer(mut self, auth: Arc<crate::bearer::BearerAuth>) -> Result<Self, ChainError> {
        self.bearer = Some(auth.transport(&self.endpoints[0].0)
            .map_err(|e| ChainError::Backend(e.to_string()))?);
        Ok(self)
    }

    /// Fall through on transport, HTTP and unusable payload errors. All chain
    /// requests share the same limiter as LDK for each configured API endpoint.
    async fn get_parsed<T>(
        &self,
        path: &str,
        parse: impl Fn(&str) -> Result<T, ChainError>,
    ) -> Result<T, ChainError> {
        let mut last_error = ChainError::NotAvailable("no usable Esplora endpoint".into());
        for (index, (base, limiter)) in self.endpoints.iter().enumerate() {
            // Admission's outer readiness deadline is five seconds. Reserve
            // four for the complete height lookup, divided across endpoints,
            // so even a blackholed primary leaves time to try every fallback.
            let timeout = if path == "/blocks/tip/height" {
                std::time::Duration::from_secs(4) / self.endpoints.len() as u32
            } else {
                std::time::Duration::from_secs(self.config.timeout_secs)
            };
            let result = tokio::time::timeout(timeout, async {
                let request = self.client.get(format!("{base}{path}")).timeout(timeout);
                let response = limiter
                    .run(false, || async {
                        match if index == 0 { self.bearer.as_ref().or(self.transport.as_ref()) } else { self.transport.as_ref() } {
                            Some(transport) => transport.execute(request).await,
                            None => Ok(request.send().await?),
                        }
                    })
                    .await
                    .map_err(|error| match error {
                        esplora_client::Error::Reqwest(_) => {
                            ChainError::Connection("Esplora connection unavailable".into())
                        }
                        _ => ChainError::NotAvailable("Esplora request unavailable".into()),
                    })?;
                if !response.status().is_success() {
                    return Err(ChainError::Backend(format!(
                        "{path}: {}",
                        response.status()
                    )));
                }
                let text = response
                    .text()
                    .await
                    .map_err(|_| ChainError::Backend("Esplora body unavailable".into()))?;
                parse(&text)
            })
            .await
            .unwrap_or_else(|_| Err(ChainError::NotAvailable("Esplora request timed out".into())));
            match result {
                Ok(value) => {
                    self.active.store(index, Ordering::Relaxed);
                    return Ok(value);
                }
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    /// Binary/block and submission requests share the existing auth, fallback,
    /// deadlines and limiter. Response allocation is bounded (a block <= 4 MB).
    async fn tower_request<T>(
        &self,
        path: &str,
        body: Option<String>,
        parse: impl Fn(&[u8]) -> Result<T, ChainError>,
    ) -> Result<T, ChainError> {
        let mut last = ChainError::NotAvailable("no usable Esplora endpoint".into());
        for (index, (base, limiter)) in self.endpoints.iter().enumerate() {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(self.config.timeout_secs),
                async {
                    let request = match &body {
                        Some(body) => self.client.post(format!("{base}{path}")).body(body.clone()),
                        None => self.client.get(format!("{base}{path}")),
                    };
                    let mut response = limiter
                        .run(body.is_some(), || async {
                            match if index == 0 {
                                self.bearer.as_ref().or(self.transport.as_ref())
                            } else {
                                self.transport.as_ref()
                            } {
                                Some(transport) => transport.execute(request).await,
                                None => Ok(request.send().await?),
                            }
                        })
                        .await
                        .map_err(|_| {
                            ChainError::Connection("tower Esplora request unavailable".into())
                        })?;
                    if !response.status().is_success() {
                        return Err(ChainError::Backend(format!(
                            "tower Esplora HTTP {}",
                            response.status()
                        )));
                    }
                    let limit = if body.is_some() { 1024 } else { 4_000_000 };
                    let mut bytes = Vec::new();
                    while let Some(chunk) = response
                        .chunk()
                        .await
                        .map_err(|_| ChainError::Backend("tower Esplora body unavailable".into()))?
                    {
                        if bytes.len() + chunk.len() > limit {
                            return Err(ChainError::Backend(
                                "tower Esplora response too large".into(),
                            ));
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    parse(&bytes)
                },
            )
            .await
            .unwrap_or_else(|_| {
                Err(ChainError::NotAvailable(
                    "tower Esplora request timed out".into(),
                ))
            });
            match result {
                Ok(bytes) => {
                    self.active.store(index, Ordering::Relaxed);
                    return Ok(bytes);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn get_text(&self, path: &str) -> Result<String, ChainError> {
        self.get_parsed(path, |text| Ok(text.to_owned())).await
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, ChainError> {
        self.get_parsed(path, |text| {
            serde_json::from_str(text)
                .map_err(|_| ChainError::Backend("invalid Esplora JSON".into()))
        })
        .await
    }
}

#[async_trait]
impl ChainProvider for EsploraProvider {
    async fn get_block(&self, height: u64) -> Result<bitcoin::Block, ChainError> {
        let hash: bitcoin::BlockHash = self
            .get_parsed(&format!("/block-height/{height}"), |text| {
                text.trim()
                    .parse()
                    .map_err(|_| ChainError::Backend("invalid tower block hash".into()))
            })
            .await?;
        self.tower_request(&format!("/block/{hash}/raw"), None, |bytes| {
            let block: bitcoin::Block = bitcoin::consensus::deserialize(bytes)
                .map_err(|_| ChainError::Backend("invalid tower block".into()))?;
            if block.block_hash() != hash || !block.check_merkle_root() {
                return Err(ChainError::Backend(
                    "tower block hash or merkle mismatch".into(),
                ));
            }
            Ok(block)
        })
        .await
    }
    async fn broadcast_transaction(&self, tx: &bitcoin::Transaction) -> Result<(), ChainError> {
        self.tower_request(
            "/tx",
            Some(hex::encode(bitcoin::consensus::serialize(tx))),
            |bytes| {
                if String::from_utf8_lossy(bytes).trim() != tx.compute_txid().to_string() {
                    return Err(ChainError::Backend("tower broadcast txid mismatch".into()));
                }
                Ok(())
            },
        )
        .await
    }

    fn chain_view(&self) -> konsensus_core::traits::chain::ChainView {
        konsensus_core::traits::chain::ChainView {
            backend: "esplora",
            trust_level: "third_party",
            host: reqwest::Url::parse(&self.endpoints[self.active.load(Ordering::Relaxed)].0)
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned)),
        }
    }

    fn trust_level(&self) -> TrustLevel {
        self.config.trust_level
    }

    #[instrument(skip(self))]
    async fn get_block_height(&self) -> Result<u64, ChainError> {
        // Hold the async lock through refresh so concurrent callers share its
        // result. Check freshness after locking; never fall back to stale data.
        let mut cached = self.tip_height.lock().await;
        if let Some((height, fetched_at)) = *cached {
            if fetched_at.elapsed() < TIP_HEIGHT_CACHE_TTL {
                return Ok(height);
            }
        }

        let height = self
            .get_parsed("/blocks/tip/height", |text| {
                let height = text
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| ChainError::Backend("invalid Esplora height".into()))?;
                if height == 0 {
                    return Err(ChainError::NotAvailable("Esplora height is zero".into()));
                }
                Ok(height)
            })
            .await?;

        *cached = Some((height, Instant::now()));
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
        if self.bearer.is_some() && hash.parse::<bitcoin::BlockHash>().is_err() {
            return Err(ChainError::Backend("invalid Esplora block hash".into()));
        }

        // Then get the full block info
        let block: EsploraBlock = self.get_json(&format!("/block/{hash}")).await?;

        Ok(BlockHeader {
            height: block.height,
            hash: block.id,
            timestamp: block.timestamp,
            bits: u32::try_from(block.bits).map_err(|_| {
                ChainError::Backend(format!("block bits overflows u32: {}", block.bits))
            })?,
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

            closest.map(|(_, rate)| rate).ok_or_else(|| {
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

    async fn is_synced_with_height(&self, _height: u64) -> bool {
        // This backend defines sync as availability of a tip. The caller's
        // successful bounded-age height read already established that.
        true
    }
}

#[cfg(test)]
#[path = "tests/esplora.rs"]
mod tests;
