use super::*;

#[tokio::test]
async fn block_height_advances() {
    let provider = MockChainProvider::new();
    let h1 = provider.get_block_height().await.unwrap();
    // Height should be near initial
    assert!(h1 >= 886_000);
}

#[tokio::test]
async fn block_header_has_valid_fields() {
    let provider = MockChainProvider::new();
    let header = provider.get_block_header(800_000).await.unwrap();
    assert_eq!(header.height, 800_000);
    assert!(header.hash.starts_with("000000"));
    assert!(header.timestamp > 0);
}

#[tokio::test]
async fn fee_estimate_scales_with_urgency() {
    let provider = MockChainProvider::new();
    let fast = provider.estimate_fee(1).await.unwrap();
    let slow = provider.estimate_fee(144).await.unwrap();
    assert!(fast.sat_per_vbyte > slow.sat_per_vbyte);
}

#[tokio::test]
async fn tx_always_confirmed() {
    let provider = MockChainProvider::new();
    assert!(provider.is_tx_confirmed("abc123", 6).await.unwrap());
}

#[tokio::test]
async fn always_synced() {
    let provider = MockChainProvider::new();
    assert!(provider.is_synced().await);
}

#[tokio::test]
async fn custom_config_initial_height() {
    let config = MockChainConfig {
        initial_height: 100_000,
        default_fee_sat_per_vb: 10.0,
    };
    let provider = MockChainProvider::with_config(config);
    let h = provider.get_block_height().await.unwrap();
    assert_eq!(h, 100_000);
}

#[tokio::test]
async fn custom_config_fee_rate() {
    let config = MockChainConfig {
        initial_height: 886_000,
        default_fee_sat_per_vb: 20.0,
    };
    let provider = MockChainProvider::with_config(config);
    let slow = provider.estimate_fee(200).await.unwrap();
    assert!((slow.sat_per_vbyte - 20.0).abs() < 0.01);
}

#[tokio::test]
async fn height_advances_after_many_queries() {
    let provider = MockChainProvider::new();
    // Height advances by 1 every 60 queries (q / 60).
    // fetch_add returns previous value, so query #60 returns height+1.
    for _ in 0..60 {
        provider.get_block_height().await.unwrap();
    }
    // The 61st query (q=60) should return 886_001
    let h = provider.get_block_height().await.unwrap();
    assert_eq!(h, 886_001);
}

#[tokio::test]
async fn block_header_timestamp_is_plausible() {
    let provider = MockChainProvider::new();
    let header = provider.get_block_header(886_000).await.unwrap();
    // Genesis is 1231006505, plus ~10 min per block
    let expected = 1_231_006_505 + 886_000 * 600;
    assert_eq!(header.timestamp, expected);
}

#[tokio::test]
async fn fee_estimate_target_boundaries() {
    let provider = MockChainProvider::new();

    // Target 1 gets 5x multiplier
    let f1 = provider.estimate_fee(1).await.unwrap();
    assert!((f1.sat_per_vbyte - 25.0).abs() < 0.01);

    // Target 3 gets 3x multiplier
    let f3 = provider.estimate_fee(3).await.unwrap();
    assert!((f3.sat_per_vbyte - 15.0).abs() < 0.01);

    // Target 6 gets 2x multiplier
    let f6 = provider.estimate_fee(6).await.unwrap();
    assert!((f6.sat_per_vbyte - 10.0).abs() < 0.01);

    // Target 12 gets 1.5x multiplier
    let f12 = provider.estimate_fee(12).await.unwrap();
    assert!((f12.sat_per_vbyte - 7.5).abs() < 0.01);

    // Target 13+ gets 1x multiplier
    let f13 = provider.estimate_fee(13).await.unwrap();
    assert!((f13.sat_per_vbyte - 5.0).abs() < 0.01);
}

#[tokio::test]
async fn default_config_values() {
    let config = MockChainConfig::default();
    assert_eq!(config.initial_height, 886_000);
    assert!((config.default_fee_sat_per_vb - 5.0).abs() < 0.01);
}

#[tokio::test]
async fn trust_level_is_server_trust() {
    let provider = MockChainProvider::new();
    assert_eq!(provider.trust_level(), TrustLevel::ServerTrust);
}
