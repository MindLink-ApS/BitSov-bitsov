//! Chain-aware pricing engine — adjusts prices based on Bitcoin fee rates
//! and halving epoch.
//!
//! Wraps [`StaticPricingEngine`] with real-time data from a
//! [`ChainProvider`]. Three timechain signals drive pricing:
//!
//! 1. **Fee rates** (short-term): mempool congestion → higher prices.
//! 2. **Halving epoch** (long-term): as block subsidy decreases, the
//!    network's security budget shifts to fees, so fee sensitivity increases.
//! 3. **Confirmation target** (per-category): different message types use
//!    different confirmation targets, reflecting their urgency. Chat uses
//!    fast targets (higher fees), files use economy targets (lower fees).
//!
//! ```text
//! sensitivity = 1.0 + halvings_completed * 0.2
//! price_msat  = base + ceil(base * fee_rate_for_category * sensitivity / 100)
//! ```
//!
//! When chain data is unavailable, falls back to static prices — the payment
//! gate (Principle 2) still enforces that *some* payment is required.
//!
//! Both fee rate and block height are cached with a configurable TTL to
//! avoid excessive chain queries. At millions of nodes, each node queries
//! its chain provider at most once per TTL interval, not once per message.
//!
//! ## EMA Persistence
//!
//! The EMA fee rate state can be saved to disk via [`FeeRateSnapshot`] and
//! restored on startup via [`ChainAwarePricingEngine::seed_ema`]. This
//! prevents cold-start pricing spikes after node restarts — without it,
//! the first fee rate fetch uses the raw value with no smoothing history.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use konsensus_core::kind::KindCategory;
use konsensus_core::traits::chain::ChainProvider;
use konsensus_core::traits::pricing::{PricingEngine, PricingError};

use crate::static_pricing::{StaticPricingConfig, StaticPricingEngine};

const DEFAULT_MAX_PRICE_MULTIPLIER: f64 = 5.0;
const DEFAULT_FEE_RATE_EMA_ALPHA: f64 = 0.3;

/// Configuration for chain-aware pricing.
#[derive(Debug, Clone)]
pub struct ChainAwarePricingConfig {
    /// Base prices (used as floor and fallback).
    pub base: StaticPricingConfig,

    /// Default fee estimation target in blocks (default: 6 — ~1 hour).
    /// Lower targets = higher fees = higher prices during congestion.
    /// Used for categories not listed in `category_fee_targets`.
    pub fee_target_blocks: u32,

    /// How long to cache the fee rate before re-querying (default: 60s).
    /// At millions of nodes, this prevents thundering-herd queries.
    pub cache_ttl: Duration,

    /// Maximum price multiplier over base price (default: 5.0).
    ///
    /// Caps the maximum chain-adjusted price to `base * max_multiplier`.
    /// Prevents runaway pricing during extreme mempool events (e.g.,
    /// Ordinal inscription storms, post-halving fee spikes).
    /// Set to 0.0 to disable the cap.
    pub max_price_multiplier: f64,

    /// EMA smoothing factor (alpha) for fee rates (default: 0.3).
    ///
    /// When a new fee rate is fetched, the smoothed rate is computed as:
    /// `ema = alpha * new_rate + (1 - alpha) * previous_ema`
    ///
    /// - alpha = 1.0: no smoothing (raw fee rates, instant reaction)
    /// - alpha = 0.5: moderate smoothing (half-life ~1 cache cycle)
    /// - alpha = 0.3: strong smoothing (half-life ~2 cache cycles)
    /// - alpha = 0.1: very strong smoothing (slow to react)
    ///
    /// Smoothing prevents pricing volatility when fee rates spike briefly
    /// between blocks. At the default 60s cache TTL, alpha=0.3 means a
    /// spike must persist for ~2 minutes before fully reflected in prices.
    pub fee_rate_ema_alpha: f64,

    /// Per-category fee confirmation targets (category name → target blocks).
    ///
    /// Categories not listed here use `fee_target_blocks` as the default.
    /// Different message types have different settlement urgency:
    /// - Chat (communication): standard target (6 blocks, ~1 hour)
    /// - Files (files_media): economy target (25 blocks, ~4 hours)
    /// - Control: deep economy target (144 blocks, ~1 day)
    ///
    /// At scale, this produces genuinely differentiated pricing: urgent
    /// chat messages cost more during congestion, while bulk file transfers
    /// and control messages use economy fee estimates and cost less.
    pub category_fee_targets: HashMap<String, u32>,
}

impl Default for ChainAwarePricingConfig {
    fn default() -> Self {
        Self {
            base: StaticPricingConfig::default(),
            fee_target_blocks: 6,
            cache_ttl: Duration::from_secs(60),
            max_price_multiplier: DEFAULT_MAX_PRICE_MULTIPLIER,
            fee_rate_ema_alpha: DEFAULT_FEE_RATE_EMA_ALPHA,
            category_fee_targets: HashMap::new(),
        }
    }
}

impl ChainAwarePricingConfig {
    /// Get the fee confirmation target for a specific category.
    ///
    /// Falls back to `fee_target_blocks` if no per-category target is configured.
    fn target_for_category(&self, category: KindCategory) -> u32 {
        let name = crate::peer_prices::category_to_string(category);
        self.category_fee_targets
            .get(&name)
            .copied()
            .unwrap_or(self.fee_target_blocks)
    }

    /// Get all unique fee targets needed (for batch fetching).
    fn unique_targets(&self) -> Vec<u32> {
        let mut targets: Vec<u32> = vec![self.fee_target_blocks];
        for &t in self.category_fee_targets.values() {
            if !targets.contains(&t) {
                targets.push(t);
            }
        }
        targets
    }
}

fn normalized_ema_alpha(alpha: f64) -> f64 {
    if alpha.is_finite() {
        alpha.clamp(0.0, 1.0)
    } else {
        DEFAULT_FEE_RATE_EMA_ALPHA
    }
}

fn normalized_fee_rate(rate: f64) -> Option<f64> {
    if rate.is_finite() && rate >= 0.0 {
        Some(rate)
    } else {
        None
    }
}

fn normalized_max_multiplier(max_multiplier: f64) -> f64 {
    if max_multiplier == 0.0 {
        0.0
    } else if max_multiplier.is_finite() && max_multiplier > 0.0 {
        max_multiplier
    } else {
        DEFAULT_MAX_PRICE_MULTIPLIER
    }
}

/// Bitcoin halving interval in blocks.
const HALVING_INTERVAL: u64 = 210_000;

/// Per-target fee rate state within the cache.
#[derive(Debug, Clone)]
struct TargetFeeState {
    /// Raw fee rate from the most recent chain query for this target.
    raw_sat_per_vbyte: f64,
    /// EMA-smoothed fee rate for this target.
    ema_sat_per_vbyte: f64,
}

/// Cached chain state with per-target fee rates and expiry.
#[derive(Debug, Clone)]
struct CachedChainState {
    /// Fee rate state keyed by confirmation target (in blocks).
    targets: HashMap<u32, TargetFeeState>,
    block_height: u64,
    fetched_at: Instant,
}

/// Serializable snapshot of EMA fee rate state for persistence across restarts.
///
/// Save this to disk periodically (e.g., every 10 minutes in the price
/// re-announcement task) and load it on startup via
/// [`ChainAwarePricingEngine::seed_ema`]. Without this, a node restart
/// resets the EMA to the raw fee rate, potentially causing a pricing spike
/// if the current rate is unusually high.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeRateSnapshot {
    /// Per-target EMA fee rates (target_blocks → EMA sat/vB).
    pub targets: HashMap<u32, f64>,
    /// Block height at the time of snapshot.
    pub block_height: u64,
    /// Unix epoch seconds when snapshot was taken.
    pub timestamp_secs: u64,
}

/// Chain-aware pricing engine implementing [`PricingEngine`].
///
/// Adjusts static base prices using three timechain signals:
///
/// 1. **Fee rate** (short-term congestion): higher mempool fees → higher prices.
/// 2. **Halving epoch** (long-term monetary policy): as block subsidy decreases,
///    fee sensitivity increases because the network's security budget shifts
///    from subsidy to fees.
/// 3. **Confirmation target** (per-category urgency): each message category can
///    use a different fee estimation target. Chat uses fast targets (6 blocks,
///    higher fees during congestion), files use economy targets (25 blocks,
///    lower fees), control uses deep economy (144 blocks, minimal fees).
///
/// The formula is:
/// ```text
/// sensitivity = 1.0 + halvings_completed * 0.2
/// price = base + ceil(base * fee_rate_for_category * sensitivity / 100)
/// ```
///
/// At halving 4 (current, blocks 840000–1049999), sensitivity = 1.8:
/// - At 1 sat/vB: prices are ~1.02x base
/// - At 10 sat/vB: prices are ~1.18x base
/// - At 50 sat/vB: prices are ~1.90x base
/// - At 100 sat/vB: prices are ~2.80x base
///
/// With per-category targets during congestion (e.g., 50 sat/vB at 6-block
/// but only 5 sat/vB at 144-block), control messages stay cheap while chat
/// messages reflect the real cost of urgent settlement.
///
/// ## EMA Persistence
///
/// Call [`ChainAwarePricingEngine::seed_ema`] on startup with a [`FeeRateSnapshot`] loaded from disk
/// to prevent cold-start pricing spikes. Call [`ChainAwarePricingEngine::snapshot`] periodically to
/// save the current state.
pub struct ChainAwarePricingEngine {
    /// Static engine for base prices and fallback.
    base_engine: StaticPricingEngine,

    /// Chain data source for fee rate and block height queries.
    chain: Arc<dyn ChainProvider>,

    /// Configuration.
    config: ChainAwarePricingConfig,

    /// Cached chain state: per-target fee rates + block height.
    cached_state: RwLock<Option<CachedChainState>>,
}

impl ChainAwarePricingEngine {
    /// Create a new chain-aware pricing engine.
    pub fn new(
        config: ChainAwarePricingConfig,
        chain: Arc<dyn ChainProvider>,
    ) -> Self {
        let base_engine = StaticPricingEngine::new(config.base.clone());
        Self {
            base_engine,
            chain,
            config,
            cached_state: RwLock::new(None),
        }
    }

    /// Seed the EMA cache from a previously saved snapshot.
    ///
    /// Call this on startup before any price queries to prevent cold-start
    /// pricing spikes. The seeded EMA values are used as the "previous" values
    /// for the first real chain query, providing smoothing continuity across
    /// restarts.
    ///
    /// Snapshots older than 1 hour are ignored (fee rates change too much
    /// over longer periods for the EMA to be meaningful).
    pub async fn seed_ema(&self, snapshot: FeeRateSnapshot) {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_else(|_| {
                warn!("system clock before UNIX epoch in seed_ema, using 0");
                0
            });

        let age_secs = now_secs.saturating_sub(snapshot.timestamp_secs);

        // Ignore snapshots older than 1 hour — fee rates change too much.
        if age_secs > 3600 {
            info!(
                age_secs,
                "ignoring stale fee rate snapshot (>1 hour old)"
            );
            return;
        }

        if snapshot.targets.is_empty() {
            debug!("empty fee rate snapshot, skipping seed");
            return;
        }

        let mut targets = HashMap::new();
        for (target_blocks, ema) in &snapshot.targets {
            if let Some(ema) = normalized_fee_rate(*ema) {
                targets.insert(
                    *target_blocks,
                    TargetFeeState {
                        raw_sat_per_vbyte: ema, // Use EMA as both raw and EMA initially
                        ema_sat_per_vbyte: ema,
                    },
                );
            } else {
                warn!(
                    target_blocks,
                    "ignoring non-finite or negative fee rate in EMA snapshot"
                );
            }
        }

        if targets.is_empty() {
            warn!("fee rate snapshot had no valid targets, skipping seed");
            return;
        }

        let targets_seeded = targets.len();
        let mut cache = self.cached_state.write().await;
        *cache = Some(CachedChainState {
            targets,
            block_height: snapshot.block_height,
            fetched_at: Instant::now()
                .checked_sub(self.config.cache_ttl)
                .unwrap_or_else(Instant::now), // Mark as expired so next query refreshes
        });

        info!(
            targets_seeded,
            block_height = snapshot.block_height,
            age_secs,
            "seeded EMA cache from snapshot"
        );
    }

    /// Take a snapshot of the current EMA state for persistence.
    ///
    /// Returns `None` if no chain state has been cached yet. Save the
    /// returned snapshot to disk (JSON) and load it on next startup via
    /// [`Self::seed_ema`].
    pub async fn snapshot(&self) -> Option<FeeRateSnapshot> {
        let cache = self.cached_state.read().await;
        let cached = cache.as_ref()?;

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_else(|_| {
                warn!("system clock before UNIX epoch in snapshot, using 0");
                0
            });

        let targets: HashMap<u32, f64> = cached
            .targets
            .iter()
            .map(|(k, v)| (*k, v.ema_sat_per_vbyte))
            .collect();

        Some(FeeRateSnapshot {
            targets,
            block_height: cached.block_height,
            timestamp_secs: now_secs,
        })
    }

    /// Refresh the chain state cache, fetching fee rates for all configured targets.
    ///
    /// Returns the block height if successful, or None if chain is unavailable.
    /// After this call, per-target fee rates are cached with EMA smoothing.
    async fn refresh_chain_state(&self) -> Option<u64> {
        // Verify chain provider is synced before trusting its data.
        if !self.chain.is_synced().await {
            warn!("chain-aware pricing: provider not synced, falling back to static prices");
            return None;
        }

        let unique_targets = self.config.unique_targets();
        let alpha = normalized_ema_alpha(self.config.fee_rate_ema_alpha);

        // Fetch block height first, then all unique fee targets.
        // Fee targets are fetched sequentially (typically 1-3 targets, each
        // is a single HTTP call with sub-second latency). The cache TTL (60s)
        // ensures this runs at most once per minute, not per message.
        let height_result = self.chain.get_block_height().await;
        let mut fee_results = Vec::with_capacity(unique_targets.len());
        for &target in &unique_targets {
            fee_results.push(self.chain.estimate_fee(target).await);
        }

        let height = match height_result {
            Ok(h) => h,
            Err(e) => {
                debug!(
                    error = %e,
                    "chain-aware pricing: block height unavailable, using base sensitivity"
                );
                0
            }
        };

        // Process fee results for each target.
        let prev_cache = self.cached_state.read().await;
        let mut new_targets = HashMap::new();
        let mut any_succeeded = false;

        for (i, result) in fee_results.into_iter().enumerate() {
            let target = unique_targets[i];
            match result {
                Ok(estimate) => {
                    let Some(raw_rate) = normalized_fee_rate(estimate.sat_per_vbyte) else {
                        warn!(
                            target_blocks = target,
                            sat_per_vbyte = estimate.sat_per_vbyte,
                            "chain-aware pricing: ignoring non-finite or negative fee rate"
                        );
                        if let Some(prev) = prev_cache
                            .as_ref()
                            .and_then(|c| c.targets.get(&target))
                            .filter(|p| normalized_fee_rate(p.ema_sat_per_vbyte).is_some())
                        {
                            new_targets.insert(target, prev.clone());
                            any_succeeded = true;
                        }
                        continue;
                    };

                    // Apply EMA smoothing using previous EMA for this target.
                    let ema_rate = match prev_cache
                        .as_ref()
                        .and_then(|c| c.targets.get(&target))
                        .and_then(|prev| normalized_fee_rate(prev.ema_sat_per_vbyte))
                    {
                        Some(prev_ema) => alpha * raw_rate + (1.0 - alpha) * prev_ema,
                        None => raw_rate, // First fetch for this target.
                    };

                    new_targets.insert(
                        target,
                        TargetFeeState {
                            raw_sat_per_vbyte: raw_rate,
                            ema_sat_per_vbyte: ema_rate,
                        },
                    );
                    any_succeeded = true;
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        target_blocks = target,
                        "chain-aware pricing: fee rate unavailable for target"
                    );
                    // Carry forward previous EMA for this target if available.
                    if let Some(prev) = prev_cache
                        .as_ref()
                        .and_then(|c| c.targets.get(&target))
                        .filter(|p| normalized_fee_rate(p.ema_sat_per_vbyte).is_some())
                    {
                        new_targets.insert(target, prev.clone());
                        any_succeeded = true;
                    }
                }
            }
        }
        drop(prev_cache);

        if !any_succeeded {
            warn!("chain-aware pricing: all fee rate queries failed, falling back to static");
            return None;
        }

        let halvings = height / HALVING_INTERVAL;
        debug!(
            block_height = height,
            halvings_completed = halvings,
            targets_fetched = new_targets.len(),
            ema_alpha = alpha,
            "chain-aware pricing: chain state updated"
        );

        // Update cache (write lock — brief, only on expiry).
        let mut cache = self.cached_state.write().await;
        *cache = Some(CachedChainState {
            targets: new_targets,
            block_height: height,
            fetched_at: Instant::now(),
        });

        Some(height)
    }

    /// Get the cached chain state for a specific category.
    ///
    /// Returns `(ema_fee_rate, block_height)` for the category's configured
    /// confirmation target. Refreshes the cache if expired.
    async fn get_chain_state_for_category(
        &self,
        category: KindCategory,
    ) -> Option<(f64, u64)> {
        let target = self.config.target_for_category(category);

        // Check cache freshness (read lock — cheap).
        {
            let cache = self.cached_state.read().await;
            if let Some(ref cached) = *cache {
                if cached.fetched_at.elapsed() < self.config.cache_ttl {
                    // Cache is fresh — look up this target's fee rate.
                    if let Some(state) = cached.targets.get(&target) {
                        return Some((state.ema_sat_per_vbyte, cached.block_height));
                    }
                    // Target not in cache (new target added to config after last fetch).
                    // Fall through to refresh.
                }
            }
        }

        // Cache expired or target missing — refresh all targets.
        let height = self.refresh_chain_state().await?;

        // Read the freshly populated cache.
        let cache = self.cached_state.read().await;
        let cached = cache.as_ref()?;
        let state = cached.targets.get(&target)?;
        Some((state.ema_sat_per_vbyte, height))
    }

    /// Get the current chain state using the default fee target.
    /// Compute the halving-adjusted fee sensitivity.
    ///
    /// As Bitcoin halvings reduce block subsidy, miners increasingly depend
    /// on transaction fees for security budget. This means the economic cost
    /// of settlement (reflected in fee rates) becomes a larger fraction of
    /// mining revenue over time. Pricing sensitivity to fees should track this.
    ///
    /// Formula: `sensitivity = 1.0 + halvings * 0.2`
    ///
    /// | Halving | Block Range         | Sensitivity | Effect at 50 sat/vB |
    /// |---------|---------------------|-------------|---------------------|
    /// | 0       | 0–209,999           | 1.0         | +50% of base        |
    /// | 1       | 210,000–419,999     | 1.2         | +60% of base        |
    /// | 2       | 420,000–629,999     | 1.4         | +70% of base        |
    /// | 3       | 630,000–839,999     | 1.6         | +80% of base        |
    /// | 4       | 840,000–1,049,999   | 1.8         | +90% of base        |
    /// | 5       | 1,050,000+          | 2.0         | +100% of base       |
    ///
    /// Capped at 4.0 (halving 15, ~year 2136) to prevent runaway pricing.
    fn halving_sensitivity(block_height: u64) -> f64 {
        let halvings = block_height / HALVING_INTERVAL;
        let sensitivity = 1.0 + (halvings as f64) * 0.2;
        // Cap at 4.0 to prevent extreme pricing in far-future halvings.
        sensitivity.min(4.0)
    }

    /// Apply the fee-rate multiplier with halving sensitivity to a base price.
    ///
    /// Formula: `base_price + ceil(base_price * fee_rate * sensitivity / 100)`
    ///
    /// The addition ensures the base price is always the floor — chain data
    /// can only increase prices, never decrease below static config.
    ///
    /// If `max_multiplier > 0`, the result is capped at `base_price * max_multiplier`.
    /// This prevents runaway pricing during extreme mempool events.
    fn apply_multiplier(
        base_price: u64,
        fee_rate: f64,
        sensitivity: f64,
        max_multiplier: f64,
    ) -> u64 {
        // Clamp fee_rate/sensitivity defensively. Chain data should be finite
        // and non-negative; NaN/negative values are treated as no fee pressure,
        // while +inf intentionally saturates into the cap below.
        let clamped_fee = if fee_rate.is_infinite() && fee_rate.is_sign_positive() {
            f64::MAX
        } else {
            normalized_fee_rate(fee_rate).unwrap_or(0.0)
        };
        let clamped_sens = if sensitivity.is_infinite() && sensitivity.is_sign_positive() {
            4.0
        } else if sensitivity.is_finite() {
            sensitivity.max(1.0)
        } else {
            1.0
        };

        // Compute the fee-rate adjustment: base_price * fee_rate * sensitivity / 100.
        // Use u128 intermediate to prevent overflow with large base prices.
        // Multiply by 1000 to preserve 3 decimal places, then divide by 100_000.
        let effective_rate = clamped_fee * clamped_sens * 1000.0;
        let effective_rate_milli = if effective_rate.is_finite() {
            effective_rate as u128
        } else {
            u128::MAX
        };
        let base = base_price as u128;

        // Ceiling division: (a + b - 1) / b, but only if remainder > 0.
        // Saturating: a compromised/buggy esplora returning an absurd fee_rate must
        // not overflow this u128 multiply (panic in debug, silent wrap -> poisoned
        // admission price in release). Saturation flows into the u64::MAX clamp and the
        // max_multiplier cap below, so an insane fee simply pins to the cap. (the-fool)
        let numerator = base.saturating_mul(effective_rate_milli);
        let adjustment = if numerator == 0 {
            0u64
        } else {
            let div = numerator / 100_000;
            let rem = numerator % 100_000;
            let ceiled = if rem > 0 { div + 1 } else { div };
            // Clamp to u64 range. Do NOT early-return here: a bare `return u64::MAX`
            // bypasses the max_multiplier cap below, letting an absurd fee produce an
            // UNCAPPED price and defeating the plasticity "bounded adaptation" invariant.
            // Yield u64::MAX as the adjustment so it flows through saturating_add and the
            // cap, which pins the final price to base*max_multiplier. (the-fool)
            if ceiled > u64::MAX as u128 {
                u64::MAX
            } else {
                ceiled as u64
            }
        };

        let result = base_price.saturating_add(adjustment);

        // Apply volatility cap: price cannot exceed base * max_multiplier.
        let max_multiplier = normalized_max_multiplier(max_multiplier);
        if max_multiplier > 0.0 {
            let cap_f64 = (base_price as f64) * max_multiplier;
            // Clamp to u64 range — f64 > u64::MAX would produce garbage via `as`
            let cap = if cap_f64 >= u64::MAX as f64 {
                u64::MAX
            } else if cap_f64 <= 0.0 {
                0
            } else {
                cap_f64 as u64
            };
            // Ensure cap is at least base_price (multiplier < 1.0 shouldn't reduce below base).
            let effective_cap = cap.max(base_price);
            result.min(effective_cap)
        } else {
            result
        }
    }

    /// Get the current block height from cache, if available.
    ///
    /// Useful for anchoring price responses to a specific block height.
    pub async fn current_block_height(&self) -> Option<u64> {
        let cache = self.cached_state.read().await;
        cache.as_ref().map(|c| c.block_height)
    }

    /// Get the current fee rate state from cache for the default target.
    ///
    /// Returns `(raw_sat_per_vbyte, ema_sat_per_vbyte)` if cached, or `None`.
    /// Uses the default `fee_target_blocks` target. For per-target
    /// observability, use [`Self::fee_rate_state_all`].
    pub async fn fee_rate_state(&self) -> Option<(f64, f64)> {
        let cache = self.cached_state.read().await;
        let cached = cache.as_ref()?;
        let state = cached.targets.get(&self.config.fee_target_blocks)?;
        Some((state.raw_sat_per_vbyte, state.ema_sat_per_vbyte))
    }

    /// Get all per-target fee rate states from cache.
    ///
    /// Returns a map of `target_blocks → (raw_sat_per_vbyte, ema_sat_per_vbyte)`.
    /// Useful for API observability of multi-target pricing.
    pub async fn fee_rate_state_all(&self) -> HashMap<u32, (f64, f64)> {
        let cache = self.cached_state.read().await;
        match cache.as_ref() {
            Some(cached) => cached
                .targets
                .iter()
                .map(|(k, v)| (*k, (v.raw_sat_per_vbyte, v.ema_sat_per_vbyte)))
                .collect(),
            None => HashMap::new(),
        }
    }

    /// Get the configured category fee targets (for API/observability).
    pub fn category_fee_targets(&self) -> &HashMap<String, u32> {
        &self.config.category_fee_targets
    }

    /// Get the configured max price multiplier (for API/observability).
    pub fn max_price_multiplier(&self) -> f64 {
        self.config.max_price_multiplier
    }
}

#[async_trait]
impl PricingEngine for ChainAwarePricingEngine {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get_price_msat(&self, kind: u16) -> Result<u64, PricingError> {
        // Get base price first — propagates NotPriceable for deferred kinds.
        let base_price = self.base_engine.get_price_msat(kind).await?;

        // Use the category-specific fee target for this kind.
        let category = KindCategory::from_kind(kind);
        match self.get_chain_state_for_category(category).await {
            Some((fee_rate, height)) => {
                let sensitivity = Self::halving_sensitivity(height);
                Ok(Self::apply_multiplier(
                    base_price,
                    fee_rate,
                    sensitivity,
                    self.config.max_price_multiplier,
                ))
            }
            None => Ok(base_price), // Fallback: static price.
        }
    }

    async fn get_category_price_msat(
        &self,
        category: KindCategory,
    ) -> Result<u64, PricingError> {
        let base_price = self.base_engine.get_category_price_msat(category).await?;

        match self.get_chain_state_for_category(category).await {
            Some((fee_rate, height)) => {
                let sensitivity = Self::halving_sensitivity(height);
                Ok(Self::apply_multiplier(
                    base_price,
                    fee_rate,
                    sensitivity,
                    self.config.max_price_multiplier,
                ))
            }
            None => Ok(base_price),
        }
    }
}

#[cfg(test)]
#[path = "tests/chain_aware.rs"]
mod tests;
