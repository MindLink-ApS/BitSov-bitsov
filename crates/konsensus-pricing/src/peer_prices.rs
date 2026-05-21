//! Peer price cache — stores pricing tables announced by connected peers.
//!
//! When a peer sends a `PriceTable` frame after federation handshake, the
//! application layer stores it here. The compose endpoint queries this cache
//! to determine how much to pay when sending messages to a specific peer.
//!
//! Without this, senders use their own pricing engine to determine payment
//! amounts. If sender and recipient have different pricing configs (different
//! base prices, chain-aware vs static, different fee rates), messages are
//! silently rejected — a critical protocol correctness issue.
//!
//! # Scale implications
//!
//! One `PeerPriceEntry` per whitelisted peer (~100 peers typical, ~1KB each).
//! Reads are non-blocking (`RwLock`, read-heavy workload). Writes happen once
//! per peer connection + once per price update (rare).

use std::collections::HashMap;
use std::time::Instant;

use konsensus_core::kind::KindCategory;
use konsensus_core::types::NodeId;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Maximum trust discount (50%) for fully trusted peers (synaptic weight = 1.0).
///
/// The plasticity pricing formula: `discounted_price = base_price * (1 - MAX_TRUST_DISCOUNT * weight)`
/// A peer with weight 1.0 pays 50% of the base price. A new peer (weight 0.0) pays full price.
/// This incentivizes reliable behavior: successful deliveries increase weight, earning discounts.
pub const MAX_TRUST_DISCOUNT: f64 = 0.5;

/// A cached price table from a peer.
#[derive(Debug, Clone)]
pub struct PeerPriceEntry {
    /// Prices per kind category name → millisatoshis.
    pub prices: HashMap<String, u64>,
    /// Block height at which these prices were computed.
    pub block_height: u64,
    /// How many blocks this table is valid for (0 = until replaced).
    pub valid_blocks: u32,
    /// When we received this table (for local staleness checks).
    pub received_at: Instant,
    /// Plasticity trust discount offered by this peer (0.0 to MAX_TRUST_DISCOUNT).
    ///
    /// Set by the peer based on our synaptic weight in their routing table.
    /// Applied to prices when composing messages to this peer.
    pub trust_discount: f64,
}

impl PeerPriceEntry {
    /// Look up the price for a specific message kind.
    ///
    /// Maps the kind to a category name and looks up the price in the table.
    /// Returns `None` if the kind's category isn't in the peer's table.
    pub fn get_price_for_kind(&self, kind: u16) -> Option<u64> {
        let category = KindCategory::from_kind(kind);
        let category_name = category_to_string(category);
        self.prices.get(&category_name).copied()
    }

    /// Look up the discounted price for a specific message kind.
    ///
    /// Applies the peer's trust discount to the base price:
    /// `discounted = base * (1 - trust_discount)`.
    /// Returns `None` if the kind's category isn't in the peer's table.
    pub fn get_discounted_price_for_kind(&self, kind: u16) -> Option<u64> {
        self.get_price_for_kind(kind)
            .map(|base| apply_trust_discount(base, self.trust_discount))
    }

    /// Check whether this price table is stale relative to a given block height.
    ///
    /// A table is stale if `valid_blocks > 0` and the current block height
    /// exceeds `block_height + valid_blocks`. A `valid_blocks` of 0 means
    /// "valid until replaced" (never stale by block count).
    ///
    /// Also considers wall-clock time: tables older than `max_age` are stale
    /// regardless of block height (guards against chain provider outages).
    pub fn is_stale(&self, current_block_height: u64, max_age: std::time::Duration) -> bool {
        // Wall-clock staleness: guard against chain provider being down
        if self.received_at.elapsed() > max_age {
            return true;
        }
        // Block-height staleness: 0 means "valid until replaced"
        if self.valid_blocks > 0 {
            let expiry_height = self.block_height.saturating_add(self.valid_blocks as u64);
            if current_block_height > expiry_height {
                return true;
            }
        }
        false
    }
}

/// Thread-safe cache of peer pricing tables.
///
/// Shared between the control event handler (writer) and the compose
/// endpoint (reader). Uses `RwLock` for read-heavy access pattern.
pub struct PeerPriceCache {
    entries: RwLock<HashMap<NodeId, PeerPriceEntry>>,
}

impl PeerPriceCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Store or update a peer's price table.
    pub async fn update(
        &self,
        peer_id: NodeId,
        prices: HashMap<String, u64>,
        block_height: u64,
        valid_blocks: u32,
        trust_discount: f64,
    ) {
        // Clamp trust_discount to valid range [0.0, MAX_TRUST_DISCOUNT]
        let clamped_discount = trust_discount.clamp(0.0, MAX_TRUST_DISCOUNT);
        let entry = PeerPriceEntry {
            prices,
            block_height,
            valid_blocks,
            received_at: Instant::now(),
            trust_discount: clamped_discount,
        };
        debug!(
            peer = %peer_id,
            block_height,
            trust_discount = clamped_discount,
            categories = entry.prices.len(),
            "cached peer price table"
        );
        self.entries.write().await.insert(peer_id, entry);
    }

    /// Get the price a specific peer requires for a message kind.
    ///
    /// Returns `None` if the peer hasn't announced pricing, or if the
    /// kind's category isn't in their table.
    pub async fn get_peer_price(&self, peer_id: &NodeId, kind: u16) -> Option<u64> {
        let entries = self.entries.read().await;
        entries
            .get(peer_id)
            .and_then(|e| e.get_price_for_kind(kind))
    }

    /// Get the discounted price a peer requires, applying plasticity trust discount.
    ///
    /// Returns the base price multiplied by `(1 - trust_discount)`. A fully
    /// trusted peer (discount 0.5) pays 50% of the base price.
    /// Returns `None` if the peer hasn't announced pricing.
    pub async fn get_discounted_peer_price(&self, peer_id: &NodeId, kind: u16) -> Option<u64> {
        let entries = self.entries.read().await;
        entries
            .get(peer_id)
            .and_then(|e| e.get_discounted_price_for_kind(kind))
    }

    /// Get the trust discount offered by a specific peer.
    ///
    /// Returns 0.0 if the peer hasn't announced pricing or doesn't support
    /// plasticity pricing.
    pub async fn get_trust_discount(&self, peer_id: &NodeId) -> f64 {
        let entries = self.entries.read().await;
        entries.get(peer_id).map_or(0.0, |e| e.trust_discount)
    }

    /// Get the price a peer requires, but only if the price table is fresh.
    ///
    /// Returns `None` if: (a) no price table cached, (b) the table is stale
    /// (block-height or wall-clock), or (c) the kind's category isn't present.
    /// When a stale table is detected, logs a warning for observability.
    pub async fn get_fresh_peer_price(
        &self,
        peer_id: &NodeId,
        kind: u16,
        current_block_height: u64,
        max_age: std::time::Duration,
    ) -> Option<u64> {
        let entries = self.entries.read().await;
        let entry = entries.get(peer_id)?;
        if entry.is_stale(current_block_height, max_age) {
            warn!(
                peer = %peer_id,
                table_height = entry.block_height,
                current_height = current_block_height,
                age_secs = entry.received_at.elapsed().as_secs(),
                "peer price table is stale, falling back to own pricing"
            );
            return None;
        }
        entry.get_price_for_kind(kind)
    }

    /// Get all cached peer price entries (for API inspection).
    pub async fn all_entries(&self) -> HashMap<NodeId, PeerPriceEntry> {
        self.entries.read().await.clone()
    }

    /// Get a peer's full price entry (for inspection / API).
    pub async fn get_peer_entry(&self, peer_id: &NodeId) -> Option<PeerPriceEntry> {
        self.entries.read().await.get(peer_id).cloned()
    }

    /// Update a single kind's price for a peer (from PriceResponse frames).
    ///
    /// If the peer already has a cached price table, this updates just the
    /// category for the given kind. If no table exists yet, creates a new
    /// entry with just this one price. This allows fine-grained price updates
    /// from PriceQuery/PriceResponse exchanges without replacing the whole table.
    pub async fn update_kind_price(
        &self,
        peer_id: NodeId,
        kind: u16,
        price_msat: u64,
        block_height: u64,
    ) {
        let category = KindCategory::from_kind(kind);
        let category_name = category_to_string(category);
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(&peer_id) {
            entry.prices.insert(category_name.clone(), price_msat);
            entry.block_height = block_height;
            entry.received_at = Instant::now();
            debug!(
                peer = %peer_id,
                category = %category_name,
                price_msat,
                block_height,
                "updated per-kind peer price"
            );
        } else {
            let mut prices = HashMap::new();
            prices.insert(category_name, price_msat);
            entries.insert(
                peer_id,
                PeerPriceEntry {
                    prices,
                    block_height,
                    valid_blocks: 0, // Unknown — will be replaced by next full PriceTable
                    received_at: Instant::now(),
                    trust_discount: 0.0, // Unknown — will be set by next full PriceTable
                },
            );
            debug!(
                peer = %peer_id,
                kind,
                price_msat,
                "created peer price entry from PriceResponse"
            );
        }
    }

    /// Remove a peer's cached pricing (e.g., on disconnect).
    pub async fn remove(&self, peer_id: &NodeId) {
        self.entries.write().await.remove(peer_id);
    }

    /// Number of cached peer price tables.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Whether the cache is empty.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}

impl Default for PeerPriceCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a `KindCategory` to its canonical string name for price table keys.
pub fn category_to_string(category: KindCategory) -> String {
    match category {
        KindCategory::Communication => "communication".to_string(),
        KindCategory::StructuredData => "structured_data".to_string(),
        KindCategory::FilesMedia => "files_media".to_string(),
        KindCategory::Collaboration => "collaboration".to_string(),
        KindCategory::RealTimeSignaling => "realtime_signaling".to_string(),
        KindCategory::WebContent => "web_content".to_string(),
        KindCategory::Storage => "storage".to_string(),
        KindCategory::Control => "control".to_string(),
        KindCategory::AppExtension => "app_extension".to_string(),
        KindCategory::Unknown => "unknown".to_string(),
    }
}

/// Apply a plasticity trust discount to a base price.
///
/// Formula: `discounted = base * (1 - discount)`, rounded up (ceil).
/// The discount is clamped to `[0.0, MAX_TRUST_DISCOUNT]` to prevent
/// underflow or negative prices.
///
/// Returns at least 1 msat — payment can never be free (Principle 2).
pub fn apply_trust_discount(base_msat: u64, discount: f64) -> u64 {
    // Fail-safe: NaN or infinite discount → no discount (full price).
    // f64::clamp passes NaN through, so we must check explicitly.
    // A NaN discount producing 1 msat would effectively bypass the payment gate.
    if !discount.is_finite() || discount.is_nan() {
        return base_msat;
    }
    let clamped = discount.clamp(0.0, MAX_TRUST_DISCOUNT);
    if clamped == 0.0 {
        return base_msat;
    }
    let discounted = (base_msat as f64) * (1.0 - clamped);
    // Ceil and enforce minimum 1 msat (payment gate is fail-closed: zero = bypass)
    let result = discounted.ceil() as u64;
    result.max(1)
}

/// Compute the trust discount for a peer based on their synaptic weight.
///
/// Formula: `discount = MAX_TRUST_DISCOUNT * weight`
/// Weight is in \[0.0, 1.0\], so discount is in \[0.0, MAX_TRUST_DISCOUNT\].
pub fn compute_trust_discount(synaptic_weight: f64) -> f64 {
    // Fail-safe: NaN or infinite weight → zero discount (full price).
    if !synaptic_weight.is_finite() {
        return 0.0;
    }
    MAX_TRUST_DISCOUNT * synaptic_weight.clamp(0.0, 1.0)
}

/// Fixed discount for resync (history restore) operations: 50%%.
///
/// Messages already paid for once get a 50%% discount when re-sent during a resync.
pub const RESYNC_DISCOUNT: f64 = 0.5;

/// Apply the resync discount to a base price.
///
/// Returns 50%% of the base price, minimum 1 msat (payment gate fail-closed).
pub fn apply_resync_discount(base_msat: u64) -> u64 {
    let discounted = (base_msat as f64) * (1.0 - RESYNC_DISCOUNT);
    (discounted.ceil() as u64).max(1)
}

/// Bitcoin difficulty adjustment interval in blocks.
const DIFFICULTY_EPOCH: u64 = 2016;

/// Compute the `valid_blocks` for a PriceTable based on position within the
/// Bitcoin difficulty adjustment epoch (2016 blocks).
///
/// The difficulty adjustment is the fundamental rhythm of Bitcoin. Prices
/// computed just after an adjustment may shift as the new epoch settles.
/// Prices mid-epoch are more stable. Prices near the end of an epoch may
/// shift soon when the next adjustment occurs.
///
/// | Epoch position | Block range | valid_blocks | Rationale                  |
/// |----------------|-------------|--------------|----------------------------|
/// | Post-adjust    | 0–100       | 72  (~12h)   | Prices settling after adj  |
/// | Mid-epoch      | 101–1915    | 144 (~24h)   | Stable pricing period      |
/// | Pre-adjust     | 1916–2015   | 36  (~6h)    | Adjustment approaching     |
///
/// When block height is unknown (0), returns a conservative 72 blocks.
pub fn compute_valid_blocks(block_height: u64) -> u32 {
    if block_height == 0 {
        return 72; // Conservative when chain data unavailable
    }

    let position_in_epoch = block_height % DIFFICULTY_EPOCH;

    if position_in_epoch <= 100 {
        72 // Post-adjustment: prices settling
    } else if position_in_epoch >= 1916 {
        36 // Pre-adjustment: adjustment approaching
    } else {
        144 // Mid-epoch: stable period
    }
}

/// Complete metadata for a PriceTable to send to peers.
///
/// Centralizes the construction of all PriceTable fields so callers don't
/// need to manually assemble block_height, valid_blocks, and trust_level.
#[derive(Debug, Clone)]
pub struct PriceTableMetadata {
    /// Prices per kind category in millisatoshis.
    pub prices: HashMap<String, u64>,
    /// Block height at which these prices were computed.
    pub block_height: u64,
    /// How many blocks this table is valid for, based on difficulty epoch.
    pub valid_blocks: u32,
    /// Trust level of the chain data source backing these prices.
    pub trust_level: konsensus_core::traits::chain::TrustLevel,
}

/// Build a price table HashMap from a `PricingEngine` for all categories.
///
/// Used to construct the `PriceTable` frame to send to peers.
pub async fn build_price_table(
    pricing: &dyn konsensus_core::traits::pricing::PricingEngine,
) -> HashMap<String, u64> {
    let mut prices = HashMap::new();

    let categories = [
        KindCategory::Communication,
        KindCategory::StructuredData,
        KindCategory::FilesMedia,
        KindCategory::Collaboration,
        KindCategory::RealTimeSignaling,
        KindCategory::WebContent,
        KindCategory::Storage,
        KindCategory::Control,
        KindCategory::AppExtension,
    ];

    for cat in categories {
        if let Ok(price) = pricing.get_category_price_msat(cat).await {
            prices.insert(category_to_string(cat), price);
        }
    }

    prices
}

/// Build a complete price table with all metadata, ready for wire transmission.
///
/// Fetches prices from the engine, block height from the chain provider,
/// computes `valid_blocks` based on difficulty epoch position, and includes
/// the chain provider's trust level. This replaces manual assembly of these
/// fields at each call site with a single authoritative function.
pub async fn build_full_price_table(
    pricing: &dyn konsensus_core::traits::pricing::PricingEngine,
    chain: &dyn konsensus_core::traits::chain::ChainProvider,
) -> PriceTableMetadata {
    let prices = build_price_table(pricing).await;
    let block_height = chain.get_block_height().await.unwrap_or_else(|e| {
        warn!(error = %e, "chain provider unavailable when building price table, using block_height=0");
        0
    });
    let valid_blocks = compute_valid_blocks(block_height);
    let trust_level = chain.trust_level();

    debug!(
        block_height,
        valid_blocks,
        trust_level = ?trust_level,
        epoch_position = block_height % DIFFICULTY_EPOCH,
        categories = prices.len(),
        "built price table metadata"
    );

    PriceTableMetadata {
        prices,
        block_height,
        valid_blocks,
        trust_level,
    }
}

#[cfg(test)]
#[path = "tests/peer_prices.rs"]
mod tests;
