//! Hardening tests for konsensus-pricing — StaticPricingConfig serde,
//! FeeRateSnapshot persistence, ChainAwarePricingConfig defaults,
//! PeerPriceCache concurrent operations, build_price_table, and
//! chain-aware per-category fee targets.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use konsensus_core::kind::*;
use konsensus_core::traits::pricing::PricingEngine;
use konsensus_core::types::NodeId;
use konsensus_pricing::peer_prices::{
    build_price_table, category_to_string, compute_valid_blocks, PeerPriceCache, PeerPriceEntry,
};
use konsensus_pricing::{
    ChainAwarePricingConfig, ChainAwarePricingEngine, FeeRateSnapshot, StaticPricingConfig,
    StaticPricingEngine,
};

fn test_node_id(byte: u8) -> NodeId {
    NodeId::from_bytes([byte; 32])
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATIC PRICING CONFIG SERDE
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn static_config_default_serde_roundtrip() {
    let config = StaticPricingConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: StaticPricingConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.chat_msat, config.chat_msat);
    assert_eq!(deserialized.longform_msat, config.longform_msat);
    assert_eq!(deserialized.calendar_msat, config.calendar_msat);
    assert_eq!(deserialized.file_ref_msat, config.file_ref_msat);
    assert_eq!(deserialized.control_msat, config.control_msat);
    assert_eq!(deserialized.collaboration_msat, config.collaboration_msat);
    assert_eq!(deserialized.realtime_signal_msat, config.realtime_signal_msat);
    assert_eq!(deserialized.app_ext_msat, config.app_ext_msat);
    assert_eq!(deserialized.web_content_msat, config.web_content_msat);
}

#[test]
fn static_config_partial_json_uses_defaults() {
    // Only specify required fields — optional fields should get serde defaults
    let json = r#"{
        "chat_msat": 20,
        "longform_msat": 100,
        "calendar_msat": 50,
        "file_ref_msat": 200,
        "control_msat": 2
    }"#;

    let config: StaticPricingConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.chat_msat, 20);
    assert_eq!(config.longform_msat, 100);
    assert_eq!(config.calendar_msat, 50);
    assert_eq!(config.file_ref_msat, 200);
    assert_eq!(config.control_msat, 2);
    // These use #[serde(default)] functions
    assert_eq!(config.collaboration_msat, 25);
    assert_eq!(config.realtime_signal_msat, 50);
    assert_eq!(config.app_ext_msat, 10);
    assert_eq!(config.web_content_msat, 50);
}

#[test]
fn static_config_custom_values() {
    let config = StaticPricingConfig {
        chat_msat: 100,
        longform_msat: 500,
        calendar_msat: 250,
        file_ref_msat: 1000,
        control_msat: 5,
        collaboration_msat: 300,
        realtime_signal_msat: 40,
        app_ext_msat: 50,
        web_content_msat: 200,
    };
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: StaticPricingConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.chat_msat, 100);
    assert_eq!(deserialized.web_content_msat, 200);
}

#[test]
fn static_config_zero_prices_allowed() {
    let json = r#"{
        "chat_msat": 0,
        "longform_msat": 0,
        "calendar_msat": 0,
        "file_ref_msat": 0,
        "control_msat": 0,
        "collaboration_msat": 0,
        "realtime_signal_msat": 0,
        "app_ext_msat": 0,
        "web_content_msat": 0
    }"#;
    let config: StaticPricingConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.chat_msat, 0);
    assert_eq!(config.file_ref_msat, 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEE RATE SNAPSHOT SERDE
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn fee_rate_snapshot_serde_roundtrip() {
    let mut targets = HashMap::new();
    targets.insert(6u32, 15.5);
    targets.insert(25, 8.2);
    targets.insert(144, 2.1);

    let snapshot = FeeRateSnapshot {
        targets,
        block_height: 886_000,
        timestamp_secs: 1_711_800_000,
    };

    let json = serde_json::to_string(&snapshot).unwrap();
    let deserialized: FeeRateSnapshot = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.block_height, 886_000);
    assert_eq!(deserialized.timestamp_secs, 1_711_800_000);
    assert_eq!(deserialized.targets.len(), 3);
    assert!((deserialized.targets[&6] - 15.5).abs() < f64::EPSILON);
    assert!((deserialized.targets[&25] - 8.2).abs() < f64::EPSILON);
    assert!((deserialized.targets[&144] - 2.1).abs() < f64::EPSILON);
}

#[test]
fn fee_rate_snapshot_empty_targets() {
    let snapshot = FeeRateSnapshot {
        targets: HashMap::new(),
        block_height: 0,
        timestamp_secs: 0,
    };
    let json = serde_json::to_string(&snapshot).unwrap();
    let deserialized: FeeRateSnapshot = serde_json::from_str(&json).unwrap();
    assert!(deserialized.targets.is_empty());
}

#[test]
fn fee_rate_snapshot_from_json_string() {
    let json = r#"{"targets":{"6":25.0},"block_height":886000,"timestamp_secs":1711800000}"#;
    let snapshot: FeeRateSnapshot = serde_json::from_str(json).unwrap();
    assert_eq!(snapshot.block_height, 886_000);
    assert_eq!(snapshot.targets.len(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHAIN-AWARE CONFIG DEFAULTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn chain_aware_config_default_values() {
    let config = ChainAwarePricingConfig::default();
    assert_eq!(config.fee_target_blocks, 6);
    assert_eq!(config.cache_ttl, Duration::from_secs(60));
    assert!((config.max_price_multiplier - 5.0).abs() < f64::EPSILON);
    assert!((config.fee_rate_ema_alpha - 0.3).abs() < f64::EPSILON);
    assert!(config.category_fee_targets.is_empty());
}

#[test]
fn chain_aware_config_base_matches_static_default() {
    let config = ChainAwarePricingConfig::default();
    let static_config = StaticPricingConfig::default();
    assert_eq!(config.base.chat_msat, static_config.chat_msat);
    assert_eq!(config.base.file_ref_msat, static_config.file_ref_msat);
    assert_eq!(config.base.control_msat, static_config.control_msat);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHAIN-AWARE PER-CATEGORY FEE TARGETS
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn per_category_targets_produce_different_prices() {
    use konsensus_chain::{MockChainConfig, MockChainProvider};

    // During congestion (50 sat/vB base), different categories should get
    // different prices because they use different confirmation targets.
    let chain = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 50.0, // Congestion
    }));

    let mut category_targets = HashMap::new();
    category_targets.insert("communication".to_string(), 6u32); // Fast (expensive)
    category_targets.insert("control".to_string(), 144u32); // Economy (cheap)
    category_targets.insert("files_media".to_string(), 25u32); // Medium

    let config = ChainAwarePricingConfig {
        base: StaticPricingConfig::default(),
        fee_target_blocks: 6, // Default
        cache_ttl: Duration::from_secs(60),
        max_price_multiplier: 0.0, // No cap
        fee_rate_ema_alpha: 1.0,   // No smoothing
        category_fee_targets: category_targets,
    };

    let engine = ChainAwarePricingEngine::new(config, chain);

    let chat_price = engine.get_price_msat(KIND_CHAT).await.unwrap();
    let control_price = engine.get_price_msat(KIND_TYPING).await.unwrap();
    let file_price = engine.get_price_msat(KIND_FILE_REF).await.unwrap();

    // All should be >= base
    assert!(chat_price >= 10, "chat_price={chat_price} >= 10");
    assert!(control_price >= 1, "control_price={control_price} >= 1");
    assert!(file_price >= 100, "file_price={file_price} >= 100");

    // Chat (fast target = higher mock fee) should be more expensive per base unit
    // than control (economy target = lower mock fee)
    // Chat base is 10, control base is 1 — compare relative increase
    let chat_ratio = chat_price as f64 / 10.0;
    let control_ratio = control_price as f64 / 1.0;

    // With MockChainProvider's urgency multiplier, 6-block target gets a higher
    // fee rate than 144-block target, so chat_ratio should be >= control_ratio
    assert!(
        chat_ratio >= control_ratio,
        "fast target should produce higher ratio: chat={chat_ratio:.2} control={control_ratio:.2}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILD PRICE TABLE
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn build_price_table_includes_all_priceable_categories() {
    let engine = StaticPricingEngine::new(StaticPricingConfig::default());
    let table = build_price_table(&engine).await;

    // Should have every known priceable category except Unknown.
    assert!(table.contains_key("communication"));
    assert!(table.contains_key("structured_data"));
    assert!(table.contains_key("files_media"));
    assert!(table.contains_key("collaboration"));
    assert!(table.contains_key("realtime_signaling"));
    assert!(table.contains_key("web_content"));
    assert!(table.contains_key("control"));
    assert!(table.contains_key("app_extension"));

    // Should NOT have unknown
    assert!(!table.contains_key("unknown"));
}

#[tokio::test]
async fn build_price_table_values_match_engine() {
    let engine = StaticPricingEngine::new(StaticPricingConfig::default());
    let table = build_price_table(&engine).await;

    assert_eq!(table["communication"], 10);
    assert_eq!(table["files_media"], 100);
    assert_eq!(table["control"], 1);
    assert_eq!(table["realtime_signaling"], 50);
    assert_eq!(table["web_content"], 50);
}

#[tokio::test]
async fn build_price_table_with_custom_config() {
    let config = StaticPricingConfig {
        chat_msat: 99,
        longform_msat: 199,
        calendar_msat: 149,
        file_ref_msat: 999,
        control_msat: 5,
        collaboration_msat: 299,
        realtime_signal_msat: 59,
        app_ext_msat: 49,
        web_content_msat: 399,
    };
    let engine = StaticPricingEngine::new(config);
    let table = build_price_table(&engine).await;

    assert_eq!(table["communication"], 99);
    assert_eq!(table["files_media"], 999);
    assert_eq!(table["control"], 5);
    assert_eq!(table["realtime_signaling"], 59);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY STRING MAPPING (complete coverage)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn category_to_string_all_categories() {
    assert_eq!(category_to_string(KindCategory::Communication), "communication");
    assert_eq!(category_to_string(KindCategory::StructuredData), "structured_data");
    assert_eq!(category_to_string(KindCategory::FilesMedia), "files_media");
    assert_eq!(category_to_string(KindCategory::Collaboration), "collaboration");
    assert_eq!(category_to_string(KindCategory::RealTimeSignaling), "realtime_signaling");
    assert_eq!(category_to_string(KindCategory::WebContent), "web_content");
    assert_eq!(category_to_string(KindCategory::Control), "control");
    assert_eq!(category_to_string(KindCategory::AppExtension), "app_extension");
    assert_eq!(category_to_string(KindCategory::Unknown), "unknown");
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPUTE VALID BLOCKS (comprehensive)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn compute_valid_blocks_first_epoch() {
    // First 2016 blocks
    assert_eq!(compute_valid_blocks(0), 72); // Special case: height 0
    assert_eq!(compute_valid_blocks(1), 72); // Post-adjustment
    assert_eq!(compute_valid_blocks(100), 72);
    assert_eq!(compute_valid_blocks(101), 144); // Mid-epoch
    assert_eq!(compute_valid_blocks(1000), 144);
    assert_eq!(compute_valid_blocks(1915), 144);
    assert_eq!(compute_valid_blocks(1916), 36); // Pre-adjustment
    assert_eq!(compute_valid_blocks(2015), 36);
}

#[test]
fn compute_valid_blocks_large_heights() {
    // Height 1_000_000 — position = 1_000_000 % 2016 = 64
    // 64 is post-adjustment (0..100)
    assert_eq!(compute_valid_blocks(1_000_000), 72);

    // Height 2_016_000 — position = 0 (exact adjustment)
    assert_eq!(compute_valid_blocks(2_016_000), 72);

    // Height 1_000_101 — position = 1_000_101 % 2016 = 165
    // 165 is mid-epoch (101..1915)
    assert_eq!(compute_valid_blocks(1_000_101), 144);
}

// ═══════════════════════════════════════════════════════════════════════════════
// PEER PRICE CACHE — ADDITIONAL EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn peer_price_cache_default_is_empty() {
    let cache = PeerPriceCache::default();
    assert!(cache.is_empty().await);
    assert_eq!(cache.len().await, 0);
}

#[tokio::test]
async fn peer_price_cache_many_peers() {
    let cache = PeerPriceCache::new();

    for i in 0..50u8 {
        let mut prices = HashMap::new();
        prices.insert("communication".to_string(), i as u64 * 10);
        cache.update(test_node_id(i), prices, 886_000, 144, 0.0).await;
    }

    assert_eq!(cache.len().await, 50);

    // Verify each peer has correct price
    for i in 0..50u8 {
        assert_eq!(
            cache.get_peer_price(&test_node_id(i), KIND_CHAT).await,
            Some(i as u64 * 10)
        );
    }
}

#[tokio::test]
async fn peer_price_cache_remove_nonexistent_is_noop() {
    let cache = PeerPriceCache::new();
    cache.remove(&test_node_id(99)).await;
    assert_eq!(cache.len().await, 0);
}

#[tokio::test]
async fn peer_price_entry_get_price_all_categories() {
    let mut prices = HashMap::new();
    prices.insert("communication".to_string(), 10);
    prices.insert("structured_data".to_string(), 25);
    prices.insert("files_media".to_string(), 100);
    prices.insert("collaboration".to_string(), 25);
    prices.insert("web_content".to_string(), 50);
    prices.insert("control".to_string(), 1);
    prices.insert("app_extension".to_string(), 10);

    let entry = PeerPriceEntry {
        prices,
        block_height: 886_000,
        valid_blocks: 144,
        received_at: std::time::Instant::now(),
        trust_discount: 0.0,
    };

    // Test all priceable kinds
    assert_eq!(entry.get_price_for_kind(KIND_CHAT), Some(10));
    assert_eq!(entry.get_price_for_kind(KIND_CALENDAR_EVENT), Some(25));
    assert_eq!(entry.get_price_for_kind(KIND_FILE_REF), Some(100));
    assert_eq!(entry.get_price_for_kind(KIND_CRDT_OP), Some(25));
    assert_eq!(entry.get_price_for_kind(KIND_PAGE_REQUEST), Some(50));
    assert_eq!(entry.get_price_for_kind(KIND_TYPING), Some(1));
    assert_eq!(entry.get_price_for_kind(1000), Some(10));
}

#[tokio::test]
async fn peer_price_entry_missing_category_returns_none() {
    let mut prices = HashMap::new();
    prices.insert("communication".to_string(), 10);

    let entry = PeerPriceEntry {
        prices,
        block_height: 886_000,
        valid_blocks: 144,
        received_at: std::time::Instant::now(),
        trust_discount: 0.0,
    };

    // files_media not in table
    assert_eq!(entry.get_price_for_kind(KIND_FILE_REF), None);
}

#[test]
fn peer_price_entry_staleness_block_height_boundary() {
    let entry = PeerPriceEntry {
        prices: HashMap::new(),
        block_height: 1000,
        valid_blocks: 100,
        received_at: std::time::Instant::now(),
        trust_discount: 0.0,
    };

    let long_age = Duration::from_secs(86400);
    // At exactly block_height + valid_blocks = 1100, NOT stale (not strictly greater)
    assert!(!entry.is_stale(1100, long_age));
    // At 1101, stale
    assert!(entry.is_stale(1101, long_age));
    // At 999, not stale
    assert!(!entry.is_stale(999, long_age));
}

#[test]
fn peer_price_entry_staleness_overflow_protection() {
    let entry = PeerPriceEntry {
        prices: HashMap::new(),
        block_height: u64::MAX - 10,
        valid_blocks: 100,
        received_at: std::time::Instant::now(),
        trust_discount: 0.0,
    };

    let long_age = Duration::from_secs(86400);
    // saturating_add should prevent overflow
    assert!(!entry.is_stale(u64::MAX, long_age));
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATIC PRICING ENGINE — EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn static_engine_boundary_kinds() {
    let engine = StaticPricingEngine::new(StaticPricingConfig::default());

    // Boundary: kind 99 is still Communication
    assert_eq!(engine.get_price_msat(99).await.unwrap(), 10);
    // Boundary: kind 100 is StructuredData
    assert_eq!(engine.get_price_msat(100).await.unwrap(), 25);
    // Boundary: kind 199 is still StructuredData
    assert_eq!(engine.get_price_msat(199).await.unwrap(), 25);
    // Boundary: kind 200 is FilesMedia
    assert_eq!(engine.get_price_msat(200).await.unwrap(), 100);
    // Boundary: kind 299 is still FilesMedia
    assert_eq!(engine.get_price_msat(299).await.unwrap(), 100);
    // Boundary: kind 300 is Collaboration
    assert_eq!(engine.get_price_msat(300).await.unwrap(), 25);
    // Boundary: kind 399 is still Collaboration
    assert_eq!(engine.get_price_msat(399).await.unwrap(), 25);
    // Boundary: kind 400 is RealTimeSignaling
    assert_eq!(engine.get_price_msat(400).await.unwrap(), 50);
    // Boundary: kind 499 is still RealTimeSignaling
    assert_eq!(engine.get_price_msat(499).await.unwrap(), 50);
    // Boundary: kind 500 is WebContent
    assert_eq!(engine.get_price_msat(500).await.unwrap(), 50);
    // Boundary: kind 599 is still WebContent
    assert_eq!(engine.get_price_msat(599).await.unwrap(), 50);
    // Boundary: kind 600 is Unknown (not priceable)
    assert!(engine.get_price_msat(600).await.is_err());
    // Boundary: kind 899 is Unknown
    assert!(engine.get_price_msat(899).await.is_err());
    // Boundary: kind 900 is Control
    assert_eq!(engine.get_price_msat(900).await.unwrap(), 1);
    // Boundary: kind 999 is still Control
    assert_eq!(engine.get_price_msat(999).await.unwrap(), 1);
    // Boundary: kind 1000 is AppExtension
    assert_eq!(engine.get_price_msat(1000).await.unwrap(), 10);
    // Boundary: kind u16::MAX is still AppExtension
    assert_eq!(engine.get_price_msat(u16::MAX).await.unwrap(), 10);
}

#[tokio::test]
async fn static_engine_as_any_downcast() {
    let engine = StaticPricingEngine::new(StaticPricingConfig::default());
    let pricing: &dyn PricingEngine = &engine;
    let any = pricing.as_any();
    assert!(any.downcast_ref::<StaticPricingEngine>().is_some());
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHAIN-AWARE ENGINE — EMA SEED AND SNAPSHOT
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn chain_aware_snapshot_roundtrip() {
    use konsensus_chain::{MockChainConfig, MockChainProvider};

    let chain = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 10.0,
    }));
    let config = ChainAwarePricingConfig {
        fee_target_blocks: 144,
        fee_rate_ema_alpha: 1.0,
        ..ChainAwarePricingConfig::default()
    };
    let engine = ChainAwarePricingEngine::new(config, chain);

    // Trigger a cache fill by querying a price
    let _ = engine.get_price_msat(KIND_CHAT).await.unwrap();

    // Take snapshot
    let snapshot = engine.snapshot().await;
    assert!(snapshot.is_some());
    let snapshot = snapshot.unwrap();
    assert!(snapshot.block_height >= 886_000);
    assert!(!snapshot.targets.is_empty());
    assert!(snapshot.timestamp_secs > 0);
}

#[tokio::test]
async fn chain_aware_snapshot_none_before_first_query() {
    use konsensus_chain::{MockChainConfig, MockChainProvider};

    let chain = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 10.0,
    }));
    let engine = ChainAwarePricingEngine::new(ChainAwarePricingConfig::default(), chain);

    // No queries yet — snapshot should be None
    assert!(engine.snapshot().await.is_none());
}

#[tokio::test]
async fn chain_aware_seed_ema_skips_stale_snapshot() {
    use konsensus_chain::{MockChainConfig, MockChainProvider};

    let chain = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 10.0,
    }));
    let engine = ChainAwarePricingEngine::new(ChainAwarePricingConfig::default(), chain);

    // Snapshot from 2 hours ago — should be ignored
    let stale_snapshot = FeeRateSnapshot {
        targets: {
            let mut t = HashMap::new();
            t.insert(6, 100.0);
            t
        },
        block_height: 886_000,
        timestamp_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 7200, // 2 hours ago
    };

    engine.seed_ema(stale_snapshot).await;
    // Snapshot should still be None (stale seed was ignored)
    assert!(engine.snapshot().await.is_none());
}

#[tokio::test]
async fn chain_aware_seed_ema_skips_empty_snapshot() {
    use konsensus_chain::{MockChainConfig, MockChainProvider};

    let chain = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 10.0,
    }));
    let engine = ChainAwarePricingEngine::new(ChainAwarePricingConfig::default(), chain);

    let empty_snapshot = FeeRateSnapshot {
        targets: HashMap::new(),
        block_height: 886_000,
        timestamp_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    engine.seed_ema(empty_snapshot).await;
    assert!(engine.snapshot().await.is_none());
}

#[tokio::test]
async fn chain_aware_observability_methods() {
    use konsensus_chain::{MockChainConfig, MockChainProvider};

    let chain = Arc::new(MockChainProvider::with_config(MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 10.0,
    }));

    let mut category_targets = HashMap::new();
    category_targets.insert("control".to_string(), 144u32);

    let config = ChainAwarePricingConfig {
        fee_target_blocks: 6,
        max_price_multiplier: 3.0,
        fee_rate_ema_alpha: 1.0,
        category_fee_targets: category_targets,
        ..ChainAwarePricingConfig::default()
    };
    let engine = ChainAwarePricingEngine::new(config, chain);

    // Query to populate cache
    let _ = engine.get_price_msat(KIND_CHAT).await.unwrap();

    // Verify observability methods
    assert!((engine.max_price_multiplier() - 3.0).abs() < f64::EPSILON);
    assert_eq!(engine.category_fee_targets().len(), 1);
    assert_eq!(engine.category_fee_targets()["control"], 144);

    let height = engine.current_block_height().await;
    assert!(height.is_some());
    assert!(height.unwrap() >= 886_000);

    let fee_state = engine.fee_rate_state().await;
    assert!(fee_state.is_some());

    let all_states = engine.fee_rate_state_all().await;
    assert!(!all_states.is_empty());
}
