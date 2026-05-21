//! Static pricing engine — fixed msat prices per kind category.
//!
//! Reads prices from configuration. Maps each UKM kind to its category,
//! then returns the configured price for that category. Real-time signaling
//! kinds (400-499) are priceable and must use the normal payment gate.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use konsensus_core::kind::KindCategory;
use konsensus_core::traits::pricing::{PricingEngine, PricingError};

/// Static pricing configuration — fixed msat per kind category.
///
/// Matches the `[pricing]` section in `konsensus.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticPricingConfig {
    /// Price for chat messages (kinds 0-99) in millisatoshis.
    pub chat_msat: u64,
    /// Price for long-form messages (KIND_LONGFORM = 1, mail-style) in millisatoshis.
    pub longform_msat: u64,
    /// Price for calendar events (also covers structured data) in millisatoshis.
    pub calendar_msat: u64,
    /// Price for file references (kinds 200-299) in millisatoshis.
    pub file_ref_msat: u64,
    /// Price for control messages (kinds 900-999) in millisatoshis.
    pub control_msat: u64,
    /// Price for collaboration messages (kinds 300-399) in millisatoshis.
    #[serde(default = "default_collab_msat")]
    pub collaboration_msat: u64,
    /// Price for real-time signaling messages (kinds 400-499) in millisatoshis.
    #[serde(default = "default_realtime_signal_msat")]
    pub realtime_signal_msat: u64,
    /// Price for app extension messages (kinds 1000+) in millisatoshis.
    #[serde(default = "default_app_ext_msat")]
    pub app_ext_msat: u64,
    /// Price for web content messages (kinds 500-599) in millisatoshis.
    /// Used by the sovereign browser — page requests, responses, manifests.
    #[serde(default = "default_web_content_msat")]
    pub web_content_msat: u64,
}

fn default_collab_msat() -> u64 {
    25
}

fn default_realtime_signal_msat() -> u64 {
    50
}

fn default_app_ext_msat() -> u64 {
    10
}

fn default_web_content_msat() -> u64 {
    50
}

impl Default for StaticPricingConfig {
    fn default() -> Self {
        Self {
            chat_msat: 10,
            longform_msat: 50,
            calendar_msat: 25,
            file_ref_msat: 100,
            control_msat: 1,
            collaboration_msat: 25,
            realtime_signal_msat: 50,
            app_ext_msat: 10,
            web_content_msat: 50,
        }
    }
}

/// Static pricing engine implementing `PricingEngine`.
///
/// Returns fixed prices based on kind category. No chain data required.
pub struct StaticPricingEngine {
    config: StaticPricingConfig,
}

impl StaticPricingEngine {
    /// Create a new static pricing engine with the given config.
    pub fn new(config: StaticPricingConfig) -> Self {
        Self { config }
    }

    /// Get the price for a category.
    fn price_for_category(&self, category: KindCategory) -> Result<u64, PricingError> {
        match category {
            KindCategory::Communication => Ok(self.config.chat_msat),
            KindCategory::StructuredData => Ok(self.config.calendar_msat),
            KindCategory::FilesMedia => Ok(self.config.file_ref_msat),
            KindCategory::Collaboration => Ok(self.config.collaboration_msat),
            KindCategory::RealTimeSignaling => Ok(self.config.realtime_signal_msat),
            KindCategory::WebContent => Ok(self.config.web_content_msat),
            KindCategory::Control => Ok(self.config.control_msat),
            KindCategory::AppExtension => Ok(self.config.app_ext_msat),
            KindCategory::Unknown => Err(PricingError::NotPriceable(0)),
        }
    }
}

#[async_trait]
impl PricingEngine for StaticPricingEngine {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get_price_msat(&self, kind: u16) -> Result<u64, PricingError> {
        let category = KindCategory::from_kind(kind);
        if matches!(category, KindCategory::Unknown) {
            return Err(PricingError::NotPriceable(kind));
        }
        // Per-kind overrides within categories: long-form messages cost
        // more than chat because they carry more data (email-style).
        if kind == konsensus_core::kind::KIND_LONGFORM {
            return Ok(self.config.longform_msat);
        }
        self.price_for_category(category)
    }

    async fn get_category_price_msat(&self, category: KindCategory) -> Result<u64, PricingError> {
        self.price_for_category(category)
    }
}

#[cfg(test)]
#[path = "tests/static_pricing.rs"]
mod tests;
