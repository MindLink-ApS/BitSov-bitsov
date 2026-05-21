use super::*;
use konsensus_chain::MockChainConfig;
use konsensus_chain::MockChainProvider;
use konsensus_core::kind::*;

/// Create a chain-aware engine with the given base fee rate and block height.
///
/// NOTE: MockChainProvider applies its own urgency multiplier based on
/// `target_blocks`. At target_blocks=144, the multiplier is 1.0x, giving
/// us the exact base fee rate for predictable test math.
///
/// Uses alpha=1.0 (no EMA smoothing) for deterministic test math, and
/// max_multiplier=0 (no cap) unless testing those features specifically.
fn make_engine(fee_rate: f64) -> ChainAwarePricingEngine {
    make_engine_at_height(fee_rate, 886_000)
}

fn make_engine_at_height(fee_rate: f64, height: u64) -> ChainAwarePricingEngine {
    let chain = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: height,
        default_fee_sat_per_vb: fee_rate,
    }));
    let config = ChainAwarePricingConfig {
        base: StaticPricingConfig::default(),
        // target_blocks >= 13 → mock multiplier is 1.0x, so we get exact fee_rate
        fee_target_blocks: 144,
        cache_ttl: Duration::from_secs(60),
        // No cap and no smoothing for deterministic test results.
        max_price_multiplier: 0.0,
        fee_rate_ema_alpha: 1.0,
        category_fee_targets: HashMap::new(),
    };
    ChainAwarePricingEngine::new(config, chain)
}

// At height 886,000: halving 4 (886000/210000=4), sensitivity = 1.0 + 4*0.2 = 1.8

#[tokio::test]
async fn low_fee_rate_minimal_increase() {
    let engine = make_engine(1.0);
    // halving 4, sensitivity = 1.8
    // 10 + ceil(10 * 1.0 * 1.8 / 100) = 10 + ceil(0.18) = 10 + 1 = 11
    let price = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price, 11);
}

#[tokio::test]
async fn normal_fee_rate_moderate_increase() {
    let engine = make_engine(10.0);
    // halving 4, sensitivity = 1.8
    // 10 + ceil(10 * 10.0 * 1.8 / 100) = 10 + ceil(1.8) = 10 + 2 = 12
    let price = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price, 12);

    // 100 + ceil(100 * 10.0 * 1.8 / 100) = 100 + ceil(18.0) = 100 + 18 = 118
    let file_price = engine.get_price_msat(KIND_FILE_REF).await.unwrap();
    assert_eq!(file_price, 118);
}

#[tokio::test]
async fn high_fee_rate_significant_increase() {
    let engine = make_engine(50.0);
    // halving 4, sensitivity = 1.8
    // 10 + ceil(10 * 50.0 * 1.8 / 100) = 10 + ceil(9.0) = 10 + 9 = 19
    let price = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price, 19);

    // 100 + ceil(100 * 50.0 * 1.8 / 100) = 100 + 90 = 190
    let file_price = engine.get_price_msat(KIND_FILE_REF).await.unwrap();
    assert_eq!(file_price, 190);
}

#[tokio::test]
async fn extreme_fee_rate_doubles_or_more() {
    let engine = make_engine(100.0);
    // halving 4, sensitivity = 1.8
    // 10 + ceil(10 * 100 * 1.8 / 100) = 10 + 18 = 28
    let price = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price, 28);

    let engine_500 = make_engine(500.0);
    // 10 + ceil(10 * 500 * 1.8 / 100) = 10 + 90 = 100
    let price = engine_500.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price, 100);
}

#[tokio::test]
async fn zero_fee_rate_returns_base_price() {
    let engine = make_engine(0.0);
    // Multiplier = 0 adjustment, price unchanged regardless of halving.
    let price = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price, 10);

    let file_price = engine.get_price_msat(KIND_FILE_REF).await.unwrap();
    assert_eq!(file_price, 100);
}

#[tokio::test]
async fn realtime_signaling_uses_payment_gate_price() {
    let engine = make_engine(10.0);
    // Base 50 + ceil(50 * 10.0 * 1.8 / 100) = 50 + 9 = 59
    assert_eq!(engine.get_price_msat(KIND_CALL_INVITE).await.unwrap(), 59);
    assert_eq!(engine.get_price_msat(KIND_ICE_CANDIDATE).await.unwrap(), 59);
}

#[tokio::test]
async fn category_pricing_with_chain_data() {
    let engine = make_engine(50.0);
    // halving 4, sensitivity = 1.8
    // Base communication = 10, 10 + ceil(10 * 50 * 1.8 / 100) = 10 + 9 = 19
    let price = engine
        .get_category_price_msat(KindCategory::Communication)
        .await
        .unwrap();
    assert_eq!(price, 19);

    // Base files = 100, 100 + ceil(100 * 50 * 1.8 / 100) = 100 + 90 = 190
    let file_price = engine
        .get_category_price_msat(KindCategory::FilesMedia)
        .await
        .unwrap();
    assert_eq!(file_price, 190);
}

#[tokio::test]
async fn cache_prevents_repeated_queries() {
    let engine = make_engine(10.0);

    // First call fetches from chain.
    let price1 = engine.get_price_msat(KIND_CHAT).await.unwrap();
    // Second call should use cache (same result, no additional fetch).
    let price2 = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price1, price2);

    // Verify cache is populated.
    let cache = engine.cached_state.read().await;
    assert!(cache.is_some());
}

#[test]
fn multiplier_math_edge_cases() {
    // No cap (max_multiplier = 0.0) for all basic math tests.
    let no_cap = 0.0;

    // Sensitivity 1.0 (halving 0): same as previous behavior
    // Base 1 msat at low fee: 1 + ceil(1 * 1.0 * 1.0 / 100) = 1 + 1 = 2
    assert_eq!(
        ChainAwarePricingEngine::apply_multiplier(1, 1.0, 1.0, no_cap),
        2
    );

    // Base 0 stays 0 (shouldn't happen — config validation requires > 0).
    assert_eq!(
        ChainAwarePricingEngine::apply_multiplier(0, 100.0, 1.0, no_cap),
        0
    );

    // Negative fee rate clamped to 0.
    assert_eq!(
        ChainAwarePricingEngine::apply_multiplier(10, -5.0, 1.0, no_cap),
        10
    );

    // Very large fee rate doesn't overflow — saturates to u64::MAX.
    let result = ChainAwarePricingEngine::apply_multiplier(u64::MAX, 1000.0, 1.0, no_cap);
    assert_eq!(result, u64::MAX);

    // Exact integer results at sensitivity 1.0: 10 + 10 * 50 / 100 = 10 + 5 = 15
    assert_eq!(
        ChainAwarePricingEngine::apply_multiplier(10, 50.0, 1.0, no_cap),
        15
    );

    // 100 + 100 * 50 / 100 = 100 + 50 = 150
    assert_eq!(
        ChainAwarePricingEngine::apply_multiplier(100, 50.0, 1.0, no_cap),
        150
    );

    // Sensitivity 2.0 (halving 5): 10 + ceil(10 * 50 * 2.0 / 100) = 10 + 10 = 20
    assert_eq!(
        ChainAwarePricingEngine::apply_multiplier(10, 50.0, 2.0, no_cap),
        20
    );

    // Sensitivity 1.8 (halving 4): 100 + ceil(100 * 10 * 1.8 / 100) = 100 + 18 = 118
    assert_eq!(
        ChainAwarePricingEngine::apply_multiplier(100, 10.0, 1.8, no_cap),
        118
    );
}

#[test]
fn volatility_cap_limits_extreme_prices() {
    // With cap at 5.0x base:
    // Base 10, fee 500, sensitivity 1.8 → uncapped = 10 + 90 = 100
    // But cap = 10 * 5 = 50
    assert_eq!(
        ChainAwarePricingEngine::apply_multiplier(10, 500.0, 1.8, 5.0),
        50
    );

    // Base 100, fee 50, sensitivity 1.8 → uncapped = 100 + 90 = 190
    // Cap = 100 * 5 = 500 → 190 < 500, so no cap applied
    assert_eq!(
        ChainAwarePricingEngine::apply_multiplier(100, 50.0, 1.8, 5.0),
        190
    );

    // Base 10, fee 1000, sensitivity 4.0 → uncapped = 10 + 400 = 410
    // Cap = 10 * 3 = 30
    assert_eq!(
        ChainAwarePricingEngine::apply_multiplier(10, 1000.0, 4.0, 3.0),
        30
    );

    // Edge: cap = 1.0 means price equals base
    assert_eq!(
        ChainAwarePricingEngine::apply_multiplier(10, 50.0, 1.0, 1.0),
        10
    );

    // Edge: cap < 1.0 should still not go below base_price
    assert_eq!(
        ChainAwarePricingEngine::apply_multiplier(10, 50.0, 1.0, 0.5),
        10
    );
}

#[tokio::test]
async fn ema_smoothing_reduces_spike_impact() {
    // Create engine with alpha=0.3 (strong smoothing)
    let chain = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 100.0, // Spike: 100 sat/vB
    }));
    let config = ChainAwarePricingConfig {
        base: StaticPricingConfig::default(),
        fee_target_blocks: 144,
        cache_ttl: Duration::from_millis(1), // Tiny TTL so cache expires between calls
        max_price_multiplier: 0.0,
        fee_rate_ema_alpha: 0.3,
        category_fee_targets: HashMap::new(),
    };
    let engine = ChainAwarePricingEngine::new(config, chain);

    // First fetch: EMA = raw rate (no history)
    let price1 = engine.get_price_msat(KIND_CHAT).await.unwrap();

    // Wait for cache to expire
    tokio::time::sleep(Duration::from_millis(5)).await;

    // Second fetch: EMA = 0.3 * 100 + 0.7 * 100 = 100 (same rate, no change)
    let price2 = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price1, price2, "constant fee rate should produce constant prices");

    // Verify fee rate state is available
    let state = engine.fee_rate_state().await;
    assert!(state.is_some());
    let (raw, ema) = state.unwrap();
    assert!((raw - 100.0).abs() < 0.01);
    assert!((ema - 100.0).abs() < 0.01);
}

#[tokio::test]
async fn alpha_one_disables_smoothing() {
    // alpha=1.0 means EMA = raw rate (no smoothing)
    let chain = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 50.0,
    }));
    let config = ChainAwarePricingConfig {
        base: StaticPricingConfig::default(),
        fee_target_blocks: 144,
        cache_ttl: Duration::from_secs(60),
        max_price_multiplier: 0.0,
        fee_rate_ema_alpha: 1.0,
        category_fee_targets: HashMap::new(),
    };
    let engine = ChainAwarePricingEngine::new(config, chain);

    let _ = engine.get_price_msat(KIND_CHAT).await.unwrap();

    let state = engine.fee_rate_state().await.unwrap();
    assert!((state.0 - state.1).abs() < f64::EPSILON, "alpha=1.0: raw and EMA should be identical");
}

#[tokio::test]
async fn all_priceable_kinds_increase_with_fees() {
    let static_engine = StaticPricingEngine::new(StaticPricingConfig::default());
    let chain_engine = make_engine(50.0);

    for kind in [
        KIND_CHAT,
        KIND_CALENDAR_EVENT,
        KIND_FILE_REF,
        KIND_CRDT_OP,
        KIND_TYPING,
        1000u16,
    ] {
        let static_price = static_engine.get_price_msat(kind).await.unwrap();
        let chain_price = chain_engine.get_price_msat(kind).await.unwrap();
        assert!(
            chain_price >= static_price,
            "chain price {} should be >= static price {} for kind {}",
            chain_price,
            static_price,
            kind
        );
    }
}

// ── Halving-specific tests ────────────────────────────────────────

#[test]
fn halving_sensitivity_at_different_epochs() {
    // Pre-halving (genesis block)
    assert!((ChainAwarePricingEngine::halving_sensitivity(0) - 1.0).abs() < f64::EPSILON);

    // Halving 0: blocks 0–209,999
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(100_000) - 1.0).abs() < f64::EPSILON
    );

    // Halving 1: blocks 210,000–419,999
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(300_000) - 1.2).abs() < f64::EPSILON
    );

    // Halving 2: blocks 420,000–629,999
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(500_000) - 1.4).abs() < f64::EPSILON
    );

    // Halving 3: blocks 630,000–839,999
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(700_000) - 1.6).abs() < f64::EPSILON
    );

    // Halving 4 (current): blocks 840,000–1,049,999
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(886_000) - 1.8).abs() < f64::EPSILON
    );

    // Halving 5: blocks 1,050,000+
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(1_100_000) - 2.0).abs() < f64::EPSILON
    );
}

#[test]
fn halving_sensitivity_caps_at_4() {
    // Halving 15 (sensitivity = 1.0 + 15 * 0.2 = 4.0)
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(15 * HALVING_INTERVAL) - 4.0).abs()
            < f64::EPSILON
    );

    // Halving 20 would be 5.0, but capped at 4.0
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(20 * HALVING_INTERVAL) - 4.0).abs()
            < f64::EPSILON
    );
}

#[tokio::test]
async fn earlier_halving_epoch_has_lower_prices() {
    let fee_rate = 50.0;

    // Halving 0 (block 100,000): sensitivity 1.0
    let engine_h0 = make_engine_at_height(fee_rate, 100_000);
    let price_h0 = engine_h0.get_price_msat(KIND_CHAT).await.unwrap();

    // Halving 4 (block 886,000): sensitivity 1.8
    let engine_h4 = make_engine_at_height(fee_rate, 886_000);
    let price_h4 = engine_h4.get_price_msat(KIND_CHAT).await.unwrap();

    // Halving 5 (block 1,100,000): sensitivity 2.0
    let engine_h5 = make_engine_at_height(fee_rate, 1_100_000);
    let price_h5 = engine_h5.get_price_msat(KIND_CHAT).await.unwrap();

    assert!(
        price_h0 < price_h4,
        "halving 0 ({price_h0}) should be cheaper than halving 4 ({price_h4})"
    );
    assert!(
        price_h4 < price_h5,
        "halving 4 ({price_h4}) should be cheaper than halving 5 ({price_h5})"
    );
}

#[tokio::test]
async fn block_height_cached() {
    let engine = make_engine(10.0);
    // Before any query, cache is empty.
    assert!(engine.current_block_height().await.is_none());

    // Query a price to populate the cache.
    let _ = engine.get_price_msat(KIND_CHAT).await.unwrap();

    // Now block height should be cached.
    let height = engine.current_block_height().await;
    assert!(height.is_some());
    assert_eq!(height.unwrap(), 886_000);
}

#[tokio::test]
async fn zero_height_gives_base_sensitivity() {
    // Block height 0: halving 0, sensitivity 1.0
    let engine = make_engine_at_height(50.0, 0);
    // 10 + ceil(10 * 50 * 1.0 / 100) = 10 + 5 = 15
    let price = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price, 15);
}

// ── is_synced() guard tests ────────────────────────────────────────

/// Mock chain provider that reports as NOT synced.
/// Used to verify the is_synced() guard falls back to static prices.
struct UnsyncedChainProvider;

#[async_trait]
impl ChainProvider for UnsyncedChainProvider {
    fn trust_level(&self) -> konsensus_core::traits::chain::TrustLevel {
        konsensus_core::traits::chain::TrustLevel::ServerTrust
    }
    async fn get_block_height(&self) -> Result<u64, konsensus_core::traits::chain::ChainError> {
        Ok(886_000)
    }
    async fn get_block_header(
        &self,
        _height: u64,
    ) -> Result<konsensus_core::traits::chain::BlockHeader, konsensus_core::traits::chain::ChainError> {
        Err(konsensus_core::traits::chain::ChainError::NotAvailable("not synced".into()))
    }
    async fn estimate_fee(
        &self,
        _target_blocks: u32,
    ) -> Result<konsensus_core::traits::chain::FeeEstimate, konsensus_core::traits::chain::ChainError> {
        // This should never be reached if is_synced() guard works
        Ok(konsensus_core::traits::chain::FeeEstimate {
            target_blocks: 6,
            sat_per_vbyte: 999.0, // Sentinel value — if this appears, guard failed
        })
    }
    async fn is_tx_confirmed(
        &self,
        _txid: &str,
        _min_confirmations: u32,
    ) -> Result<bool, konsensus_core::traits::chain::ChainError> {
        Ok(false)
    }
    async fn is_synced(&self) -> bool {
        false // <-- The key: this provider is NOT synced
    }
}

#[tokio::test]
async fn desynced_provider_falls_back_to_static() {
    let chain = Arc::new(UnsyncedChainProvider);
    let config = ChainAwarePricingConfig {
        base: StaticPricingConfig::default(),
        fee_target_blocks: 6,
        cache_ttl: Duration::from_secs(60),
        max_price_multiplier: 0.0,
        fee_rate_ema_alpha: 1.0,
        category_fee_targets: HashMap::new(),
    };
    let engine = ChainAwarePricingEngine::new(config, chain);

    // With a desynced provider, should return base price (10 msat for chat)
    // NOT the sentinel 999.0 fee rate price
    let price = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price, 10, "desynced provider should fall back to static base price");

    let file_price = engine.get_price_msat(KIND_FILE_REF).await.unwrap();
    assert_eq!(file_price, 100, "desynced provider should fall back to static base price");
}

// ── Multi-target pricing tests ────────────────────────────────────

#[tokio::test]
async fn category_targets_differentiate_pricing() {
    // MockChainProvider applies urgency multiplier: target 1-3 → 3x, 4-6 → 2x,
    // 7-12 → 1.5x, 13+ → 1.0x. With base fee 10.0 sat/vB:
    // - target 6: 10 * 2.0 = 20 sat/vB
    // - target 144: 10 * 1.0 = 10 sat/vB
    let chain = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 10.0,
    }));
    let mut category_targets = HashMap::new();
    category_targets.insert("control".to_string(), 144u32); // Economy target
    // Communication uses default (6 blocks)

    let config = ChainAwarePricingConfig {
        base: StaticPricingConfig::default(),
        fee_target_blocks: 6, // Default: standard target
        cache_ttl: Duration::from_secs(60),
        max_price_multiplier: 0.0,
        fee_rate_ema_alpha: 1.0,
        category_fee_targets: category_targets,
    };
    let engine = ChainAwarePricingEngine::new(config, chain);

    // Chat (communication): target 6 → 20 sat/vB × sensitivity 1.8
    // 10 + ceil(10 * 20 * 1.8 / 100) = 10 + ceil(3.6) = 10 + 4 = 14
    let chat_price = engine.get_price_msat(KIND_CHAT).await.unwrap();

    // Control (typing): target 144 → 10 sat/vB × sensitivity 1.8
    // 1 + ceil(1 * 10 * 1.8 / 100) = 1 + ceil(0.18) = 1 + 1 = 2
    let control_price = engine.get_price_msat(KIND_TYPING).await.unwrap();

    assert_eq!(chat_price, 14, "chat should use standard fee target");
    assert_eq!(control_price, 2, "control should use economy fee target");

    // Control should be much cheaper per-unit than chat
    // (1 msat base + 1 msat fee vs 10 msat base + 4 msat fee)
    assert!(control_price < chat_price);
}

#[tokio::test]
async fn files_economy_target_cheaper_during_congestion() {
    // During congestion, economy targets are MUCH cheaper than standard
    let chain = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 50.0, // Congested: 50 sat/vB base
    }));
    let mut category_targets = HashMap::new();
    category_targets.insert("files_media".to_string(), 144u32); // Economy for files

    let config = ChainAwarePricingConfig {
        base: StaticPricingConfig::default(),
        fee_target_blocks: 6, // Standard for everything else
        cache_ttl: Duration::from_secs(60),
        max_price_multiplier: 0.0,
        fee_rate_ema_alpha: 1.0,
        category_fee_targets: category_targets,
    };
    let engine = ChainAwarePricingEngine::new(config, chain);

    // Chat: target 6 → 50*2.0=100 sat/vB, sensitivity 1.8
    // 10 + ceil(10 * 100 * 1.8 / 100) = 10 + 18 = 28
    let chat_price = engine.get_price_msat(KIND_CHAT).await.unwrap();

    // File: target 144 → 50*1.0=50 sat/vB, sensitivity 1.8
    // 100 + ceil(100 * 50 * 1.8 / 100) = 100 + 90 = 190
    let file_price = engine.get_price_msat(KIND_FILE_REF).await.unwrap();

    // Without economy target, file would be:
    // target 6 → 100 sat/vB, 100 + ceil(100 * 100 * 1.8 / 100) = 100 + 180 = 280
    assert_eq!(chat_price, 28);
    assert_eq!(file_price, 190);

    // File with economy target (190) is cheaper than it would be with
    // standard target (280), even though it has a higher base price
}

#[tokio::test]
async fn no_category_targets_uses_default_for_all() {
    // Empty category_fee_targets → all categories use fee_target_blocks
    let engine = make_engine(10.0); // target_blocks=144 for all

    let chat = engine.get_price_msat(KIND_CHAT).await.unwrap();
    let file = engine.get_price_msat(KIND_FILE_REF).await.unwrap();
    let control = engine.get_price_msat(KIND_TYPING).await.unwrap();

    // All use the same fee rate (target 144 → mock multiplier 1.0x → 10 sat/vB)
    // sensitivity 1.8
    // chat: 10 + ceil(10 * 10 * 1.8 / 100) = 10 + 2 = 12
    assert_eq!(chat, 12);
    // file: 100 + ceil(100 * 10 * 1.8 / 100) = 100 + 18 = 118
    assert_eq!(file, 118);
    // control: 1 + ceil(1 * 10 * 1.8 / 100) = 1 + 1 = 2
    assert_eq!(control, 2);
}

#[tokio::test]
async fn fee_rate_state_all_returns_all_targets() {
    let chain = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 10.0,
    }));
    let mut category_targets = HashMap::new();
    category_targets.insert("control".to_string(), 144u32);
    category_targets.insert("files_media".to_string(), 25u32);

    let config = ChainAwarePricingConfig {
        base: StaticPricingConfig::default(),
        fee_target_blocks: 6,
        cache_ttl: Duration::from_secs(60),
        max_price_multiplier: 0.0,
        fee_rate_ema_alpha: 1.0,
        category_fee_targets: category_targets,
    };
    let engine = ChainAwarePricingEngine::new(config, chain);

    // Trigger cache population
    let _ = engine.get_price_msat(KIND_CHAT).await.unwrap();

    let all = engine.fee_rate_state_all().await;
    // Should have 3 unique targets: 6, 25, 144
    assert_eq!(all.len(), 3, "should have 3 unique fee targets");
    assert!(all.contains_key(&6), "should have default target 6");
    assert!(all.contains_key(&25), "should have files target 25");
    assert!(all.contains_key(&144), "should have control target 144");

    // Target 6 has urgency multiplier 2.0x: raw = 20.0
    let (raw_6, ema_6) = all[&6];
    assert!((raw_6 - 20.0).abs() < 0.01);
    assert!((ema_6 - 20.0).abs() < 0.01); // alpha=1.0, no smoothing

    // Target 144 has multiplier 1.0x: raw = 10.0
    let (raw_144, _) = all[&144];
    assert!((raw_144 - 10.0).abs() < 0.01);
}

// ── EMA persistence tests ─────────────────────────────────────────

#[tokio::test]
async fn snapshot_and_seed_roundtrip() {
    let chain: Arc<dyn ChainProvider> = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 50.0,
    }));
    let config = ChainAwarePricingConfig {
        base: StaticPricingConfig::default(),
        fee_target_blocks: 144,
        cache_ttl: Duration::from_secs(60),
        max_price_multiplier: 0.0,
        fee_rate_ema_alpha: 0.3, // With smoothing
        category_fee_targets: HashMap::new(),
    };
    let engine = ChainAwarePricingEngine::new(config.clone(), Arc::clone(&chain));

    // Populate cache
    let _ = engine.get_price_msat(KIND_CHAT).await.unwrap();

    // Take snapshot
    let snapshot = engine.snapshot().await.unwrap();
    assert!(snapshot.targets.contains_key(&144));
    assert_eq!(snapshot.block_height, 886_000);

    // Verify snapshot is serializable
    let json = serde_json::to_string(&snapshot).unwrap();
    let restored: FeeRateSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.block_height, snapshot.block_height);

    // Create a new engine and seed it
    let engine2 = ChainAwarePricingEngine::new(config, chain);
    engine2.seed_ema(restored).await;

    // The seeded engine should have the EMA value from the snapshot
    // (cache is marked as expired, so next query will refresh, but
    // the EMA smoothing will use the seeded value as "previous")
    let state = engine2.fee_rate_state().await;
    assert!(state.is_some(), "seeded engine should have cached state");
}

#[tokio::test]
async fn seed_ema_stale_snapshot_ignored() {
    let chain = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 10.0,
    }));
    let config = ChainAwarePricingConfig::default();
    let engine = ChainAwarePricingEngine::new(config, chain);

    // Create a snapshot from 2 hours ago — should be ignored
    let stale_snapshot = FeeRateSnapshot {
        targets: {
            let mut m = HashMap::new();
            m.insert(6, 50.0);
            m
        },
        block_height: 885_000,
        timestamp_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 7200, // 2 hours ago
    };

    engine.seed_ema(stale_snapshot).await;

    // Cache should still be empty (stale snapshot rejected)
    assert!(
        engine.fee_rate_state().await.is_none(),
        "stale snapshot should be ignored"
    );
}

#[tokio::test]
async fn seed_ema_provides_smoothing_continuity() {
    // Scenario: fee rate was stable at 20 sat/vB, node restarts,
    // current rate is still 20. With seed, EMA should start near 20
    // (not raw). Without seed, EMA = raw on first fetch.
    let chain = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 20.0,
    }));

    let mut cat_targets = HashMap::new();
    cat_targets.insert("control".to_string(), 144u32);

    let config = ChainAwarePricingConfig {
        base: StaticPricingConfig::default(),
        fee_target_blocks: 144,
        cache_ttl: Duration::from_millis(1), // Tiny TTL for testing
        max_price_multiplier: 0.0,
        fee_rate_ema_alpha: 0.3,
        category_fee_targets: cat_targets,
    };

    let chain: Arc<dyn ChainProvider> = chain;
    let engine = ChainAwarePricingEngine::new(config, Arc::clone(&chain));

    // Seed with previous EMA of 15.0 (different from current 20.0)
    let seed = FeeRateSnapshot {
        targets: {
            let mut m = HashMap::new();
            m.insert(144, 15.0);
            m
        },
        block_height: 885_900,
        timestamp_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 300, // 5 minutes ago
    };
    engine.seed_ema(seed).await;

    // Wait for seeded cache to expire
    tokio::time::sleep(Duration::from_millis(5)).await;

    // First real fetch: EMA = 0.3 * 20.0 + 0.7 * 15.0 = 6.0 + 10.5 = 16.5
    // (smoothed using seeded previous value)
    let _ = engine.get_price_msat(KIND_CHAT).await.unwrap();
    let state = engine.fee_rate_state().await.unwrap();
    let (raw, ema) = state;
    assert!((raw - 20.0).abs() < 0.01, "raw should be 20.0, got {raw}");
    assert!(
        (ema - 16.5).abs() < 0.01,
        "EMA should be ~16.5 (smoothed with seed), got {ema}"
    );
}

// ── Halving boundary condition tests ────────────────────────────────

#[test]
fn halving_sensitivity_at_exact_boundary_blocks() {
    // Block 210000: exact first halving boundary → halving 1, sensitivity 1.2
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(210_000) - 1.2).abs() < f64::EPSILON,
        "block 210000 should be halving 1 (sensitivity 1.2)"
    );

    // Block 420000: exact second halving boundary → halving 2, sensitivity 1.4
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(420_000) - 1.4).abs() < f64::EPSILON,
        "block 420000 should be halving 2 (sensitivity 1.4)"
    );

    // Block 630000: exact third halving boundary → halving 3, sensitivity 1.6
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(630_000) - 1.6).abs() < f64::EPSILON,
        "block 630000 should be halving 3 (sensitivity 1.6)"
    );

    // Block 840000: exact fourth halving boundary → halving 4, sensitivity 1.8
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(840_000) - 1.8).abs() < f64::EPSILON,
        "block 840000 should be halving 4 (sensitivity 1.8)"
    );
}

#[test]
fn halving_sensitivity_one_block_before_boundaries() {
    // Block 209999: one block before first halving → still halving 0, sensitivity 1.0
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(209_999) - 1.0).abs() < f64::EPSILON,
        "block 209999 should still be halving 0 (sensitivity 1.0)"
    );

    // Block 419999: one block before second halving → halving 1, sensitivity 1.2
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(419_999) - 1.2).abs() < f64::EPSILON,
        "block 419999 should be halving 1 (sensitivity 1.2)"
    );

    // Block 629999: one block before third halving → halving 2, sensitivity 1.4
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(629_999) - 1.4).abs() < f64::EPSILON,
        "block 629999 should be halving 2 (sensitivity 1.4)"
    );

    // Block 839999: one block before fourth halving → halving 3, sensitivity 1.6
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(839_999) - 1.6).abs() < f64::EPSILON,
        "block 839999 should be halving 3 (sensitivity 1.6)"
    );
}

#[test]
fn halving_sensitivity_one_block_after_boundaries() {
    // Block 210001: one block after first halving → halving 1, sensitivity 1.2
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(210_001) - 1.2).abs() < f64::EPSILON,
        "block 210001 should be halving 1 (sensitivity 1.2)"
    );

    // Block 420001: one block after second halving → halving 2, sensitivity 1.4
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(420_001) - 1.4).abs() < f64::EPSILON,
        "block 420001 should be halving 2 (sensitivity 1.4)"
    );

    // Block 630001: one block after third halving → halving 3, sensitivity 1.6
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(630_001) - 1.6).abs() < f64::EPSILON,
        "block 630001 should be halving 3 (sensitivity 1.6)"
    );

    // Block 840001: one block after fourth halving → halving 4, sensitivity 1.8
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(840_001) - 1.8).abs() < f64::EPSILON,
        "block 840001 should be halving 4 (sensitivity 1.8)"
    );
}

#[test]
fn halving_sensitivity_future_halvings() {
    // Block 1050000: exact fifth halving → halving 5, sensitivity 2.0
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(1_050_000) - 2.0).abs() < f64::EPSILON,
        "block 1050000 should be halving 5 (sensitivity 2.0)"
    );

    // Block 1260000: sixth halving → sensitivity 2.2
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(1_260_000) - 2.2).abs() < f64::EPSILON,
        "block 1260000 should be halving 6 (sensitivity 2.2)"
    );

    // Block 2100000: tenth halving → sensitivity 3.0
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(2_100_000) - 3.0).abs() < f64::EPSILON,
        "block 2100000 should be halving 10 (sensitivity 3.0)"
    );

    // Block 3150000: fifteenth halving → sensitivity 4.0 (capped)
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(3_150_000) - 4.0).abs() < f64::EPSILON,
        "block 3150000 should be halving 15, capped at 4.0"
    );

    // Block 4200000: twentieth halving → still capped at 4.0
    assert!(
        (ChainAwarePricingEngine::halving_sensitivity(4_200_000) - 4.0).abs() < f64::EPSILON,
        "block 4200000 should still be capped at 4.0"
    );
}

#[tokio::test]
async fn pricing_at_exact_halving_block_heights() {
    let fee_rate = 50.0;

    // Block 210000: halving 1, sensitivity 1.2
    // Chat: 10 + ceil(10 * 50 * 1.2 / 100) = 10 + ceil(6.0) = 10 + 6 = 16
    let engine = make_engine_at_height(fee_rate, 210_000);
    let price = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price, 16, "price at block 210000 (halving 1)");

    // Block 420000: halving 2, sensitivity 1.4
    // Chat: 10 + ceil(10 * 50 * 1.4 / 100) = 10 + ceil(7.0) = 10 + 7 = 17
    let engine = make_engine_at_height(fee_rate, 420_000);
    let price = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price, 17, "price at block 420000 (halving 2)");

    // Block 630000: halving 3, sensitivity 1.6
    // Chat: 10 + ceil(10 * 50 * 1.6 / 100) = 10 + ceil(8.0) = 10 + 8 = 18
    let engine = make_engine_at_height(fee_rate, 630_000);
    let price = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price, 18, "price at block 630000 (halving 3)");

    // Block 840000: halving 4, sensitivity 1.8
    // Chat: 10 + ceil(10 * 50 * 1.8 / 100) = 10 + ceil(9.0) = 10 + 9 = 19
    let engine = make_engine_at_height(fee_rate, 840_000);
    let price = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price, 19, "price at block 840000 (halving 4)");

    // Block 1050000: halving 5, sensitivity 2.0
    // Chat: 10 + ceil(10 * 50 * 2.0 / 100) = 10 + 10 = 20
    let engine = make_engine_at_height(fee_rate, 1_050_000);
    let price = engine.get_price_msat(KIND_CHAT).await.unwrap();
    assert_eq!(price, 20, "price at block 1050000 (halving 5)");
}

#[tokio::test]
async fn snapshot_empty_cache_returns_none() {
    let engine = make_engine(10.0);
    // No price queries yet → no snapshot
    assert!(engine.snapshot().await.is_none());
}
