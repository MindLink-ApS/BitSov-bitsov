//! Hardening tests for chain crate — HTTP error handling, fee estimation edge cases,
//! mock provider boundaries, and Esplora edge cases.

use konsensus_chain::{EsploraConfig, EsploraProvider, MockChainConfig, MockChainProvider};
use konsensus_core::traits::chain::{ChainProvider, TrustLevel};

use axum::{extract::Path, routing::get, Router};

// ═══════════════════════════════════════════════════════════════════════════════
// ESPLORA — HTTP ERROR HANDLING
// ═══════════════════════════════════════════════════════════════════════════════

/// Start a mock Esplora server that returns specific error responses.
async fn mock_error_server(
    height_handler: axum::routing::MethodRouter,
    fee_handler: axum::routing::MethodRouter,
    tx_handler: axum::routing::MethodRouter,
) -> (EsploraConfig, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/api/blocks/tip/height", height_handler)
        .route("/api/fee-estimates", fee_handler)
        .route("/api/tx/:txid", tx_handler);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let config = EsploraConfig {
        api_url: format!("http://127.0.0.1:{}", addr.port()),
        trust_level: TrustLevel::ServerTrust,
        timeout_secs: 5,
    };

    (config, handle)
}

#[tokio::test]
async fn esplora_server_500_returns_backend_error() {
    let (config, _server) = mock_error_server(
        get(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "server error") }),
        get(|| async { "{}" }),
        get(|| async { "{}" }),
    )
    .await;

    let provider = EsploraProvider::new(config).unwrap();
    let result = provider.get_block_height().await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("500") || err.contains("server error") || err.contains("Backend"));
}

#[tokio::test]
async fn esplora_malformed_height_returns_error() {
    let (config, _server) = mock_error_server(
        get(|| async { "not_a_number" }),
        get(|| async { "{}" }),
        get(|| async { "{}" }),
    )
    .await;

    let provider = EsploraProvider::new(config).unwrap();
    let result = provider.get_block_height().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn esplora_empty_fee_estimates_returns_error() {
    let (config, _server) = mock_error_server(
        get(|| async { "850000" }),
        get(|| async { axum::Json(serde_json::json!({})) }),
        get(|| async { "{}" }),
    )
    .await;

    let provider = EsploraProvider::new(config).unwrap();
    let result = provider.estimate_fee(6).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("no fee estimates") || err.contains("FeeEstimationFailed"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn esplora_fee_single_target_always_selected() {
    // Server returns only one target
    let app = Router::new()
        .route(
            "/api/fee-estimates",
            get(|| async { axum::Json(serde_json::json!({"25": 8.5})) }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let config = EsploraConfig {
        api_url: format!("http://127.0.0.1:{}", addr.port()),
        trust_level: TrustLevel::ServerTrust,
        timeout_secs: 5,
    };

    let provider = EsploraProvider::new(config).unwrap();

    // Any target should use the only available estimate
    let est = provider.estimate_fee(1).await.unwrap();
    assert!((est.sat_per_vbyte - 8.5).abs() < 0.01);

    let est = provider.estimate_fee(144).await.unwrap();
    assert!((est.sat_per_vbyte - 8.5).abs() < 0.01);
}

#[tokio::test]
async fn esplora_tx_not_found_returns_error() {
    let (config, _server) = mock_error_server(
        get(|| async { "850000" }),
        get(|| async { axum::Json(serde_json::json!({"6": 10.0})) }),
        get(|Path(_txid): Path<String>| async {
            (axum::http::StatusCode::NOT_FOUND, "Transaction not found")
        }),
    )
    .await;

    let provider = EsploraProvider::new(config).unwrap();
    let result = provider.is_tx_confirmed("nonexistent_tx", 1).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn esplora_connection_refused() {
    // Point at a port with no server
    let config = EsploraConfig {
        api_url: "http://127.0.0.1:1".to_string(), // Almost certainly no server
        trust_level: TrustLevel::ServerTrust,
        timeout_secs: 1,
    };

    let provider = EsploraProvider::new(config).unwrap();
    let result = provider.get_block_height().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn esplora_is_synced_false_on_connection_error() {
    let config = EsploraConfig {
        api_url: "http://127.0.0.1:1".to_string(),
        trust_level: TrustLevel::ServerTrust,
        timeout_secs: 1,
    };

    let provider = EsploraProvider::new(config).unwrap();
    assert!(!provider.is_synced().await);
}

#[tokio::test]
async fn esplora_url_with_trailing_slash() {
    // URL with trailing slash should work (api_url trims it)
    let app = Router::new().route(
        "/api/blocks/tip/height",
        get(|| async { "900000" }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let config = EsploraConfig {
        api_url: format!("http://127.0.0.1:{}/", addr.port()), // trailing slash
        trust_level: TrustLevel::ServerTrust,
        timeout_secs: 5,
    };

    let provider = EsploraProvider::new(config).unwrap();
    let height = provider.get_block_height().await.unwrap();
    assert_eq!(height, 900_000);
}

#[tokio::test]
async fn esplora_trust_levels() {
    // Test all trust levels work
    for level in [TrustLevel::Spv, TrustLevel::ServerTrust, TrustLevel::FullValidation] {
        let config = EsploraConfig {
            api_url: "http://localhost:1".into(),
            trust_level: level,
            timeout_secs: 1,
        };
        let provider = EsploraProvider::new(config).unwrap();
        assert_eq!(provider.trust_level(), level);
    }
}

#[tokio::test]
async fn esplora_tx_confirmed_exact_confirmations() {
    // tx at height 849995, tip at 850000 = 6 confirmations
    let app = Router::new()
        .route("/api/blocks/tip/height", get(|| async { "850000" }))
        .route(
            "/api/tx/:txid",
            get(|| async {
                axum::Json(serde_json::json!({
                    "status": {
                        "confirmed": true,
                        "block_height": 849995
                    }
                }))
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let config = EsploraConfig {
        api_url: format!("http://127.0.0.1:{}", addr.port()),
        trust_level: TrustLevel::ServerTrust,
        timeout_secs: 5,
    };

    let provider = EsploraProvider::new(config).unwrap();

    // 6 confirmations exactly
    assert!(provider.is_tx_confirmed("tx1", 6).await.unwrap());
    // 7 would need height 849994 or lower
    assert!(!provider.is_tx_confirmed("tx1", 7).await.unwrap());
    // 1 confirmation — just confirmed flag
    assert!(provider.is_tx_confirmed("tx1", 1).await.unwrap());
}

// ═══════════════════════════════════════════════════════════════════════════════
// MOCK CHAIN PROVIDER — BOUNDARY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn mock_height_advances_every_60_queries() {
    let provider = MockChainProvider::new();
    let h_start = provider.get_block_height().await.unwrap();

    // 59 more queries (total 60 with the first)
    for _ in 0..59 {
        provider.get_block_height().await.unwrap();
    }

    // 61st query — should have advanced by 1
    let h_after = provider.get_block_height().await.unwrap();
    assert_eq!(h_after, h_start + 1);
}

#[tokio::test]
async fn mock_custom_config() {
    let config = MockChainConfig {
        initial_height: 100,
        default_fee_sat_per_vb: 20.0,
    };
    let provider = MockChainProvider::with_config(config);

    let h = provider.get_block_height().await.unwrap();
    assert_eq!(h, 100);

    let fee = provider.estimate_fee(144).await.unwrap();
    assert!((fee.sat_per_vbyte - 20.0).abs() < 0.01);
}

#[tokio::test]
async fn mock_fee_all_urgency_tiers() {
    let config = MockChainConfig {
        initial_height: 100,
        default_fee_sat_per_vb: 10.0,
    };
    let provider = MockChainProvider::with_config(config);

    let f1 = provider.estimate_fee(1).await.unwrap();
    let f3 = provider.estimate_fee(3).await.unwrap();
    let f6 = provider.estimate_fee(6).await.unwrap();
    let f12 = provider.estimate_fee(12).await.unwrap();
    let f144 = provider.estimate_fee(144).await.unwrap();

    // 1-block: 5x, 2-3: 3x, 4-6: 2x, 7-12: 1.5x, 13+: 1x
    assert!((f1.sat_per_vbyte - 50.0).abs() < 0.01);
    assert!((f3.sat_per_vbyte - 30.0).abs() < 0.01);
    assert!((f6.sat_per_vbyte - 20.0).abs() < 0.01);
    assert!((f12.sat_per_vbyte - 15.0).abs() < 0.01);
    assert!((f144.sat_per_vbyte - 10.0).abs() < 0.01);
}

#[tokio::test]
async fn mock_fee_boundary_targets() {
    let provider = MockChainProvider::new();

    // Target 2 is in the 2..=3 range
    let f2 = provider.estimate_fee(2).await.unwrap();
    let f3 = provider.estimate_fee(3).await.unwrap();
    assert!((f2.sat_per_vbyte - f3.sat_per_vbyte).abs() < 0.01);

    // Target 4 is in the 4..=6 range
    let f4 = provider.estimate_fee(4).await.unwrap();
    let f6 = provider.estimate_fee(6).await.unwrap();
    assert!((f4.sat_per_vbyte - f6.sat_per_vbyte).abs() < 0.01);

    // Target 7 is in the 7..=12 range
    let f7 = provider.estimate_fee(7).await.unwrap();
    let f12 = provider.estimate_fee(12).await.unwrap();
    assert!((f7.sat_per_vbyte - f12.sat_per_vbyte).abs() < 0.01);

    // Target 13 is in the 13+ range (multiplier 1.0)
    let f13 = provider.estimate_fee(13).await.unwrap();
    let f1000 = provider.estimate_fee(1000).await.unwrap();
    assert!((f13.sat_per_vbyte - f1000.sat_per_vbyte).abs() < 0.01);
}

#[tokio::test]
async fn mock_block_header_zero_height() {
    let provider = MockChainProvider::new();
    let header = provider.get_block_header(0).await.unwrap();
    assert_eq!(header.height, 0);
    assert!(header.hash.starts_with("0000"));
    // Genesis-like timestamp
    assert_eq!(header.timestamp, 1_231_006_505);
}

#[tokio::test]
async fn mock_block_header_very_high_height() {
    let provider = MockChainProvider::new();
    let header = provider.get_block_header(10_000_000).await.unwrap();
    assert_eq!(header.height, 10_000_000);
    assert!(header.hash.starts_with("0000"));
    assert!(header.timestamp > 0);
}

#[tokio::test]
async fn mock_hash_deterministic() {
    let provider = MockChainProvider::new();
    let h1 = provider.get_block_header(500_000).await.unwrap();
    let h2 = provider.get_block_header(500_000).await.unwrap();
    assert_eq!(h1.hash, h2.hash);
}

#[tokio::test]
async fn mock_hash_different_heights_different_hashes() {
    let provider = MockChainProvider::new();
    let h1 = provider.get_block_header(500_000).await.unwrap();
    let h2 = provider.get_block_header(500_001).await.unwrap();
    assert_ne!(h1.hash, h2.hash);
}

#[tokio::test]
async fn mock_default_provider() {
    // Test Default trait implementation
    let provider = MockChainProvider::default();
    let h = provider.get_block_height().await.unwrap();
    assert!(h >= 886_000);
    assert!(provider.is_synced().await);
    assert!(provider.is_tx_confirmed("anything", 100).await.unwrap());
}

#[tokio::test]
async fn mock_zero_fee_rate() {
    let config = MockChainConfig {
        initial_height: 100,
        default_fee_sat_per_vb: 0.0,
    };
    let provider = MockChainProvider::with_config(config);

    let fee = provider.estimate_fee(1).await.unwrap();
    assert!((fee.sat_per_vbyte - 0.0).abs() < 0.001);
}

#[tokio::test]
async fn mock_get_best_block_header() {
    let provider = MockChainProvider::new();
    let best = provider.get_best_block_header().await.unwrap();
    // Should be near the initial height
    assert!(best.height >= 886_000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ESPLORA CONFIG — FACTORY METHODS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn esplora_mempool_space_config() {
    let config = EsploraConfig::mempool_space();
    assert_eq!(config.api_url, "https://mempool.space");
    assert_eq!(config.trust_level, TrustLevel::ServerTrust);
    assert_eq!(config.timeout_secs, 30);
}

#[test]
fn esplora_custom_config() {
    let config = EsploraConfig::custom("http://mynode:3000".into(), TrustLevel::FullValidation);
    assert_eq!(config.api_url, "http://mynode:3000");
    assert_eq!(config.trust_level, TrustLevel::FullValidation);
}
