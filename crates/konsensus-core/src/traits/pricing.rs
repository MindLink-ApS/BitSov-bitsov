//! PricingEngine trait — kind-aware message pricing.
//!
//! Chain-aware pricing adjusts base prices using Bitcoin fee rates, halving
//! epoch sensitivity, and per-category confirmation targets (Principle 5).

use std::any::Any;

use async_trait::async_trait;
use thiserror::Error;

use crate::kind::KindCategory;

/// Errors from pricing operations.
#[derive(Debug, Error)]
pub enum PricingError {
    /// The kind is not priceable.
    #[error("kind {0} is not priceable")]
    NotPriceable(u16),

    /// Chain data unavailable for dynamic pricing.
    #[error("chain data unavailable: {0}")]
    ChainUnavailable(String),

    /// General pricing error.
    #[error("pricing error: {0}")]
    Other(String),
}

/// Kind-aware pricing engine.
///
/// Determines the Lightning payment amount required for each UKM kind.
/// Implements Principle 5 (Chain-aware message pricing). Static mode uses
/// fixed per-kind prices; chain-aware mode adjusts prices using Bitcoin
/// fee rates and halving epoch sensitivity.
///
/// NOTE (ADR-027 · 2026-05-03): the bare term "timechain pricing" is
/// ambiguous. This trait is *chain-aware MESSAGE pricing* — per-UKM-kind
/// msat amounts. It is NOT *timechain CONTRACT pricing* (block-height
/// SaaS contracts). Contract pricing lives in the Agreements layer
/// (ADR-028), never in this trait or in `konsensus-pricing/`.
#[async_trait]
pub trait PricingEngine: Send + Sync {
    /// Get the price in millisatoshis for a message of the given kind.
    ///
    /// Returns `Err(PricingError::NotPriceable)` for unsupported/deferred kinds.
    async fn get_price_msat(&self, kind: u16) -> Result<u64, PricingError>;

    /// Price using a successful, bounded-age height observation from the same
    /// chain provider. Admission readiness can share its lookup with pricing.
    /// Preserve the original observation time when reporting data freshness.
    async fn get_price_msat_with_chain_height(
        &self,
        kind: u16,
        _height: u64,
        _observed_at: std::time::Instant,
    ) -> Result<u64, PricingError> {
        self.get_price_msat(kind).await
    }

    /// Get the price for a kind category (bulk pricing lookup).
    async fn get_category_price_msat(&self, category: KindCategory) -> Result<u64, PricingError>;

    /// Snapshot kinds with a distinct tariff at offer issuance. `Some` attests
    /// that every other priceable kind uses its category price. Engines unable
    /// to provide that guarantee must return `None` (no durable category offer).
    /// This applicability is persisted with an offer, never recomputed at redemption.
    fn category_price_overrides(&self) -> Option<Vec<u16>> { None }

    /// Downcast to concrete type for engine-specific operations.
    ///
    /// Used by the node runtime to access chain-aware features (EMA snapshot
    /// persistence, multi-target state) that aren't part of the generic trait.
    fn as_any(&self) -> &dyn Any;
}
