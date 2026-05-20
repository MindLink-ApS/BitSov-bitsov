//! konsensus-pricing — Message pricing engines for Principle 5.
//!
//! Two engines are available:
//!
//! - [`StaticPricingEngine`] — fixed msat prices per kind category, configured

#![forbid(unsafe_code)]
//!   via `konsensus.toml`. Used when `pricing.mode = "static"` (default).
//!
//! - [`ChainAwarePricingEngine`] — adjusts base prices using real-time Bitcoin
//!   fee rates AND halving epoch from a
//!   [`ChainProvider`](konsensus_core::traits::chain::ChainProvider). Higher
//!   mempool congestion → higher prices, and as halvings reduce block subsidy,
//!   fee sensitivity increases (Principle 5: chain-aware message pricing —
//!   see ADR-027 for terminology disambiguation).
//!   Used when `pricing.mode = "chain_aware"`.

pub mod chain_aware;
pub mod peer_prices;
pub mod static_pricing;

pub use chain_aware::{ChainAwarePricingConfig, ChainAwarePricingEngine, FeeRateSnapshot};
pub use peer_prices::{
    apply_resync_discount, apply_trust_discount, compute_trust_discount, PeerPriceCache,
    PeerPriceEntry, PriceTableMetadata, MAX_TRUST_DISCOUNT, RESYNC_DISCOUNT,
};
pub use static_pricing::{StaticPricingConfig, StaticPricingEngine};
