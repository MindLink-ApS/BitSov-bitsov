use super::*;
use axum::{extract::Path, routing::get, Router};

/// Start a mock Esplora server and return (config, server_handle).
async fn mock_esplora() -> (EsploraConfig, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/api/blocks/tip/height", get(|| async { "850000" }))
        .route(
            "/api/block-height/:height",
            get(|Path(height): Path<String>| async move {
                if height == "850000" {
                    "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72f8804bf"
                        .to_string()
                } else {
                    "not_found".to_string()
                }
            }),
        )
        .route(
            "/api/block/:hash",
            get(|| async {
                axum::Json(serde_json::json!({
                    "id": "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72f8804bf",
                    "height": 850000,
                    "timestamp": 1719500000,
                    "bits": 386089019,
                    "nonce": 123456,
                    "difficulty": 83148355189239.77_f64
                }))
            }),
        )
        .route(
            "/api/fee-estimates",
            get(|| async {
                axum::Json(serde_json::json!({
                    "1": 25.0,
                    "3": 15.0,
                    "6": 10.0,
                    "25": 5.0,
                    "144": 2.0,
                    "504": 1.0
                }))
            }),
        )
        .route(
            "/api/tx/:txid",
            get(|Path(txid): Path<String>| async move {
                if txid == "confirmed_tx" {
                    axum::Json(serde_json::json!({
                        "status": {
                            "confirmed": true,
                            "block_height": 849990
                        }
                    }))
                } else {
                    axum::Json(serde_json::json!({
                        "status": {
                            "confirmed": false,
                            "block_height": null
                        }
                    }))
                }
            }),
        );

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
async fn get_block_height() {
    let (config, _server) = mock_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    let height = provider.get_block_height().await.unwrap();
    assert_eq!(height, 850000);
}

#[tokio::test]
async fn get_block_header_existing() {
    let (config, _server) = mock_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    let header = provider.get_block_header(850000).await.unwrap();
    assert_eq!(header.height, 850000);
    assert_eq!(header.timestamp, 1719500000);
    assert!(header.hash.starts_with("0000"));
}

#[tokio::test]
async fn get_best_block_header() {
    let (config, _server) = mock_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    let header = provider.get_best_block_header().await.unwrap();
    assert_eq!(header.height, 850000);
}

#[tokio::test]
async fn estimate_fee_exact_target() {
    let (config, _server) = mock_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    let estimate = provider.estimate_fee(3).await.unwrap();
    assert_eq!(estimate.target_blocks, 3);
    assert!((estimate.sat_per_vbyte - 15.0).abs() < 0.01);
}

#[tokio::test]
async fn estimate_fee_closest_target() {
    let (config, _server) = mock_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    // Target 2 doesn't exist — should pick closest (1 or 3)
    let estimate = provider.estimate_fee(2).await.unwrap();
    assert_eq!(estimate.target_blocks, 2);
    // Should pick either 1 (25.0) or 3 (15.0) — both are 1 away
    assert!(estimate.sat_per_vbyte > 0.0);
}

#[tokio::test]
async fn tx_confirmed() {
    let (config, _server) = mock_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    let confirmed = provider.is_tx_confirmed("confirmed_tx", 1).await.unwrap();
    assert!(confirmed);
}

#[tokio::test]
async fn tx_unconfirmed() {
    let (config, _server) = mock_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    let confirmed = provider
        .is_tx_confirmed("unconfirmed_tx", 1)
        .await
        .unwrap();
    assert!(!confirmed);
}

#[tokio::test]
async fn tx_insufficient_confirmations() {
    let (config, _server) = mock_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    // tx at height 849990, tip at 850000 = 11 confirmations
    let confirmed = provider
        .is_tx_confirmed("confirmed_tx", 100)
        .await
        .unwrap();
    assert!(!confirmed);

    let confirmed = provider.is_tx_confirmed("confirmed_tx", 11).await.unwrap();
    assert!(confirmed);
}

#[tokio::test]
async fn is_synced_returns_true() {
    let (config, _server) = mock_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    assert!(provider.is_synced().await);
}

#[tokio::test]
async fn trust_level_matches_config() {
    let config = EsploraConfig::mempool_space();
    let provider = EsploraProvider::new(config).unwrap();
    assert_eq!(provider.trust_level(), TrustLevel::ServerTrust);
}

#[tokio::test]
async fn api_url_strips_trailing_api_suffix() {
    // Users commonly set api_url to "https://mempool.space/api" when the
    // code already adds the /api prefix. Verify both forms produce the
    // same URL.
    let (config, _server) = mock_esplora().await;
    let base = config.api_url.clone();
    let provider = EsploraProvider::new(config).unwrap();

    // Without /api suffix (correct form)
    let url_correct = provider.api_url("/blocks/tip/height");
    assert!(
        url_correct.ends_with("/api/blocks/tip/height"),
        "unexpected url: {url_correct}"
    );

    // With /api suffix (common mistake) — should produce the same result
    let config_with_suffix = EsploraConfig {
        api_url: format!("{base}/api"),
        trust_level: TrustLevel::ServerTrust,
        timeout_secs: 10,
    };
    let provider2 = EsploraProvider::new(config_with_suffix).unwrap();
    let url_suffix = provider2.api_url("/blocks/tip/height");
    assert_eq!(url_correct, url_suffix);
}

#[tokio::test]
async fn api_url_with_trailing_slash() {
    let (config, _server) = mock_esplora().await;
    let base = config.api_url.clone();
    // Trailing slash should also work
    let config_slash = EsploraConfig {
        api_url: format!("{base}/"),
        trust_level: TrustLevel::ServerTrust,
        timeout_secs: 10,
    };
    let provider = EsploraProvider::new(config_slash).unwrap();
    let url = provider.api_url("/blocks/tip/height");
    assert!(
        url.ends_with("/api/blocks/tip/height"),
        "unexpected url: {url}"
    );
    // Should not have double slash
    assert!(!url.contains("//api"));
}

/// Build a mock Esplora that returns HTTP errors for all endpoints.
async fn mock_error_esplora() -> (EsploraConfig, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route(
            "/api/blocks/tip/height",
            get(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "server error") }),
        )
        .route(
            "/api/block-height/:height",
            get(|| async { (axum::http::StatusCode::NOT_FOUND, "not found") }),
        )
        .route(
            "/api/fee-estimates",
            get(|| async { axum::Json(serde_json::json!({})) }),
        )
        .route(
            "/api/tx/:txid",
            get(|| async { (axum::http::StatusCode::NOT_FOUND, "not found") }),
        );

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
async fn block_height_server_error_returns_backend_error() {
    let (config, _server) = mock_error_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    let result = provider.get_block_height().await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, ChainError::Backend(_)),
        "expected Backend error, got: {err:?}"
    );
}

#[tokio::test]
async fn block_header_not_found_returns_error() {
    let (config, _server) = mock_error_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    // The error server returns 500 for block height, which will fail first
    let result = provider.get_block_header(999999).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn empty_fee_estimates_returns_error() {
    let (config, _server) = mock_error_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    let result = provider.estimate_fee(6).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, ChainError::FeeEstimationFailed(_)),
        "expected FeeEstimationFailed, got: {err:?}"
    );
}

#[tokio::test]
async fn tx_lookup_not_found_returns_error() {
    let (config, _server) = mock_error_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    let result = provider.is_tx_confirmed("nonexistent_tx", 1).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn unreachable_server_returns_connection_error() {
    let config = EsploraConfig {
        api_url: "http://127.0.0.1:1".to_string(), // Nobody listening on port 1
        trust_level: TrustLevel::ServerTrust,
        timeout_secs: 1,
    };
    let provider = EsploraProvider::new(config).unwrap();

    let result = provider.get_block_height().await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, ChainError::Connection(_)),
        "expected Connection error, got: {err:?}"
    );
}

#[tokio::test]
async fn is_synced_returns_false_on_unreachable() {
    let config = EsploraConfig {
        api_url: "http://127.0.0.1:1".to_string(),
        trust_level: TrustLevel::ServerTrust,
        timeout_secs: 1,
    };
    let provider = EsploraProvider::new(config).unwrap();

    assert!(!provider.is_synced().await);
}

#[tokio::test]
async fn custom_config_sets_trust_level() {
    let config = EsploraConfig::custom(
        "http://localhost:3000".to_string(),
        TrustLevel::FullValidation,
    );
    let provider = EsploraProvider::new(config).unwrap();
    assert_eq!(provider.trust_level(), TrustLevel::FullValidation);
}

#[tokio::test]
async fn mempool_space_config_defaults() {
    let config = EsploraConfig::mempool_space();
    assert_eq!(config.api_url, "https://mempool.space");
    assert_eq!(config.trust_level, TrustLevel::ServerTrust);
    assert_eq!(config.timeout_secs, 30);
}

#[tokio::test]
async fn confirmation_count_boundary() {
    let (config, _server) = mock_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    // tx at height 849990, tip at 850000 = 11 confirmations
    // Exactly 11 should pass
    assert!(provider.is_tx_confirmed("confirmed_tx", 11).await.unwrap());
    // 12 should fail
    assert!(!provider.is_tx_confirmed("confirmed_tx", 12).await.unwrap());
    // 1 should pass (just confirmed, no deep check needed)
    assert!(provider.is_tx_confirmed("confirmed_tx", 1).await.unwrap());
}

#[tokio::test]
async fn fee_estimate_all_targets() {
    let (config, _server) = mock_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    // Verify all exact targets return correct values
    let fee_1 = provider.estimate_fee(1).await.unwrap();
    assert!((fee_1.sat_per_vbyte - 25.0).abs() < 0.01);

    let fee_6 = provider.estimate_fee(6).await.unwrap();
    assert!((fee_6.sat_per_vbyte - 10.0).abs() < 0.01);

    let fee_144 = provider.estimate_fee(144).await.unwrap();
    assert!((fee_144.sat_per_vbyte - 2.0).abs() < 0.01);

    let fee_504 = provider.estimate_fee(504).await.unwrap();
    assert!((fee_504.sat_per_vbyte - 1.0).abs() < 0.01);
}

#[tokio::test]
async fn fake_hash_is_deterministic_and_looks_like_block_hash() {
    // Mock provider hashes are deterministic
    let h1 = super::super::mock::MockChainProvider::new();
    let header1 = h1.get_block_header(100).await.unwrap();
    let header2 = h1.get_block_header(100).await.unwrap();
    assert_eq!(header1.hash, header2.hash);

    // Different heights produce different hashes
    let header3 = h1.get_block_header(101).await.unwrap();
    assert_ne!(header1.hash, header3.hash);

    // Hashes start with zeros like real Bitcoin block hashes
    assert!(header1.hash.starts_with("000000"));
}
