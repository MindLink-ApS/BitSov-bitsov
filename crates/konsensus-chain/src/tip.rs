//! A chain tip is ready only when it is one block, recent enough.
//!
//! [`FreshTip`] wraps a real chain source. Its height read returns the height
//! of the best block header, and refuses when that header is height zero or
//! older than a per-network bound. Height and age therefore come from the
//! same block: a source that stopped following the chain, or that answers
//! with an old tip, is not ready, rather than a source of a counterfeit tip.
//!
//! The source's own sync check (`is_synced`) and every other read are passed
//! through unchanged. Which network the source is on is checked separately at
//! startup; this wrapper only bounds the tip's age.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use konsensus_core::traits::chain::{
    BlockHeader, ChainError, ChainProvider, ChainView, FeeEstimate, TrustLevel,
};
use tokio::sync::Mutex;

/// Oldest best block a mainnet source may report and still be ready.
///
/// Blocks come every ten minutes on average; a block timestamp may lag real
/// time by about an hour (it only has to exceed the median of the last eleven).
/// Three hours without a newer block is then about two hours of real silence,
/// which a live mainnet tip shows a few times a year at most.
pub const MAINNET_MAX_TIP_AGE: Duration = Duration::from_secs(3 * 60 * 60);

/// Oldest best block on test networks (testnet, signet, or a network the
/// configuration does not name). Their block production is irregular, and a
/// custom signet may mine rarely, so the bound only catches a source that is
/// a day behind.
pub const TEST_NETWORK_MAX_TIP_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// How long one header read is reused. A reused header is still judged by its
/// own timestamp, so this never hides a stale tip for longer than itself.
const TIP_CACHE_TTL: Duration = Duration::from_secs(30);

/// The tip-age bound for a configured network name (`bitcoin`, `testnet`,
/// `signet`, `regtest`, as `[lightning] network` reads them).
///
/// Regtest has none: its blocks are mined on demand. A missing or unknown
/// name gets the test-network bound, the loosest one that still applies.
pub fn max_tip_age(network: Option<&str>) -> Option<Duration> {
    match network.map(str::to_ascii_lowercase).as_deref() {
        Some("bitcoin" | "mainnet") => Some(MAINNET_MAX_TIP_AGE),
        Some("regtest") => None,
        _ => Some(TEST_NETWORK_MAX_TIP_AGE),
    }
}

/// A chain source whose height read is a recent best block, or an error.
pub struct FreshTip {
    inner: Arc<dyn ChainProvider>,
    max_age: Option<Duration>,
    cached: Mutex<Option<(BlockHeader, Instant)>>,
}

impl FreshTip {
    /// Bound `inner`'s tip by `max_age` (`None`: height zero is still refused,
    /// but any age is accepted).
    pub fn new(inner: Arc<dyn ChainProvider>, max_age: Option<Duration>) -> Self {
        Self {
            inner,
            max_age,
            cached: Mutex::new(None),
        }
    }

    /// Wrap `inner` with the bound for `network` (see [`max_tip_age`]).
    pub fn wrap(inner: Arc<dyn ChainProvider>, network: Option<&str>) -> Arc<dyn ChainProvider> {
        Arc::new(Self::new(inner, max_tip_age(network)))
    }

    /// The configured bound.
    pub fn max_age(&self) -> Option<Duration> {
        self.max_age
    }

    /// The best block header, if it is a usable tip. Only a usable header is
    /// cached; a refused one (stale or height zero) is dropped, so a source
    /// that recovers is seen on the next read.
    async fn tip(&self) -> Result<BlockHeader, ChainError> {
        let mut cached = self.cached.lock().await;
        let reused = cached
            .as_ref()
            .filter(|(_, read_at)| read_at.elapsed() < TIP_CACHE_TTL)
            .map(|(header, _)| header.clone());
        let fetched = reused.is_none();
        let header = match reused {
            Some(header) => header,
            // A failed read is not cached: the next caller asks again.
            None => self.inner.get_best_block_header().await?,
        };
        match self.usable(&header) {
            Ok(()) => {
                if fetched {
                    *cached = Some((header.clone(), Instant::now()));
                }
                Ok(header)
            }
            Err(error) => {
                *cached = None;
                Err(error)
            }
        }
    }

    fn usable(&self, header: &BlockHeader) -> Result<(), ChainError> {
        if header.height == 0 {
            return Err(ChainError::NotAvailable("chain tip is height zero".into()));
        }
        if let Some(max_age) = self.max_age {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ChainError::NotAvailable("system clock before 1970".into()))?
                .as_secs();
            // A timestamp ahead of this clock counts as age zero.
            let age = now.saturating_sub(header.timestamp);
            if age > max_age.as_secs() {
                return Err(ChainError::NotAvailable(format!(
                    "chain tip is stale: best block {} is {age} s old (limit {} s)",
                    header.height,
                    max_age.as_secs()
                )));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ChainProvider for FreshTip {
    fn chain_view(&self) -> ChainView {
        self.inner.chain_view()
    }

    fn trust_level(&self) -> TrustLevel {
        self.inner.trust_level()
    }

    async fn get_block_height(&self) -> Result<u64, ChainError> {
        Ok(self.tip().await?.height)
    }

    async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError> {
        self.inner.get_block_header(height).await
    }

    async fn get_best_block_header(&self) -> Result<BlockHeader, ChainError> {
        self.tip().await
    }

    async fn estimate_fee(&self, target_blocks: u32) -> Result<FeeEstimate, ChainError> {
        self.inner.estimate_fee(target_blocks).await
    }

    async fn is_tx_confirmed(
        &self,
        txid: &str,
        min_confirmations: u32,
    ) -> Result<bool, ChainError> {
        self.inner.is_tx_confirmed(txid, min_confirmations).await
    }

    async fn is_synced(&self) -> bool {
        self.inner.is_synced().await
    }

    async fn is_synced_with_height(&self, height: u64) -> bool {
        self.inner.is_synced_with_height(height).await
    }

    async fn tip_is_fresh(&self) -> bool {
        self.tip().await.is_ok()
    }
}

#[cfg(test)]
#[path = "tests/tip.rs"]
mod tests;
