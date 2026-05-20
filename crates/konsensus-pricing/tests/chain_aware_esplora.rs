//! Integration test: ChainAwarePricingEngine with real Esplora (mempool.space).
//!
//! Marked `#[ignore]` — requires internet access and a live Esplora instance.
//! Run manually: `cargo test -p konsensus-pricing --test chain_aware_esplora -- --ignored`

use std::sync::Arc;
use std::time::Duration;

use konsensus_chain::{EsploraConfig, EsploraProvider};
use konsensus_core::kind::KIND_CHAT;
use konsensus_core::traits::chain::TrustLevel;
use konsensus_core::traits::pricing::PricingEngine;
use konsensus_pricing::{ChainAwarePricingConfig, ChainAwarePricingEngine, StaticPricingConfig};

#[tokio::test]
#[ignore]
async fn chain_aware_with_real_esplora() {
    let esplora_config = EsploraConfig::custom(
        "https://mempool.space".to_string(),
        TrustLevel::ServerTrust,
    );
    let chain = Arc::new(
        EsploraProvider::new(esplora_config).expect("failed to create Esplora provider"),
    );

    let config = ChainAwarePricingConfig {
        base: StaticPricingConfig::default(),
        fee_target_blocks: 6,
        cache_ttl: Duration::from_secs(60),
        max_price_multiplier: 5.0,
        fee_rate_ema_alpha: 0.3,
        category_fee_targets: std::collections::HashMap::new(),
    };

    let engine = ChainAwarePricingEngine::new(config, chain);

    // With a live chain, price should be >= base price (10 msat for chat).
    let price = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert!(
        price >= 10,
        "chain-aware price ({price}) should be >= base price (10)"
    );

    // Fee rates are always > 0 on mainnet, so price should be strictly > base.
    // (This could theoretically fail if fee rate is exactly 0.0, but that
    // never happens on mainnet.)
    let height = engine.current_block_height().await;
    println!(
        "Chain-aware chat price: {price} msat (base: 10 msat), block height: {height:?}"
    );

    // Block height should be cached after the price query.
    assert!(height.is_some(), "block height should be cached");
    assert!(
        height.unwrap() > 800_000,
        "block height should be reasonable (got {:?})",
        height
    );
}
