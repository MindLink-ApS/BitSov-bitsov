use super::*;
use axum::{extract::Path, routing::get, Router};

#[path = "height_cache.rs"]
mod height_cache;

/// Start a mock Esplora server and return (config, server_handle).
async fn mock_esplora() -> (EsploraConfig, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/api/blocks/tip/height", get(|| async { "850000" }))
        .route(
            "/api/block-height/:height",
            get(|Path(height): Path<String>| async move {
                if height == "850000" {
                    "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72f8804bf".to_string()
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

    let confirmed = provider.is_tx_confirmed("unconfirmed_tx", 1).await.unwrap();
    assert!(!confirmed);
}

#[tokio::test]
async fn tx_insufficient_confirmations() {
    let (config, _server) = mock_esplora().await;
    let provider = EsploraProvider::new(config).unwrap();

    // tx at height 849990, tip at 850000 = 11 confirmations
    let confirmed = provider.is_tx_confirmed("confirmed_tx", 100).await.unwrap();
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
    let url_correct = format!("{}/blocks/tip/height", provider.endpoints[0].0);
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
    let url_suffix = format!("{}/blocks/tip/height", provider2.endpoints[0].0);
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
    let url = format!("{}/blocks/tip/height", provider.endpoints[0].0);
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
            get(|| async {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "server error",
                )
            }),
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

#[tokio::test]
async fn known_height_satisfies_height_only_sync_without_another_lookup() {
    // An unsupported URL makes an accidental lookup fail before any network I/O.
    let provider = EsploraProvider::new(EsploraConfig::custom(
        "unsupported://no-network".into(),
        TrustLevel::ServerTrust,
    ))
    .unwrap();
    assert!(provider.is_synced_with_height(900_000).await);
}

/// HTTP boundary fixture: the real provider, parser and shared limiter run.
#[derive(Debug)]
struct ScriptedHttp(
    std::sync::Mutex<std::collections::VecDeque<(&'static str, u16, &'static str)>>,
);
impl HttpTransport for ScriptedHttp {
    fn execute(
        &self,
        request: reqwest::RequestBuilder,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<reqwest::Response, esplora_client::Error>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let request = request.build().unwrap();
            let (host, status, body) = self
                .0
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected request (cooldown bypassed)");
            assert_eq!(request.url().host_str(), Some(host));
            assert!(request.url().path().starts_with("/api/"));
            if status == 0 {
                return std::future::pending().await;
            }
            Ok(http::Response::builder()
                .status(status)
                .header("retry-after", "86400")
                .body(body)
                .unwrap()
                .into())
        })
    }
}

#[tokio::test(start_paused = true)]
async fn issue204_primary_429_uses_fallback_and_shares_bounded_cooldown() {
    let mut provider = EsploraProvider::with_fallbacks(
        EsploraConfig::custom(
            "https://primary-204.invalid/api/".into(),
            TrustLevel::ServerTrust,
        ),
        vec![
            "https://primary-204.invalid".into(),
            "https://fallback-204.invalid".into(),
        ],
    )
    .unwrap();
    provider.transport = Some(Arc::new(ScriptedHttp(std::sync::Mutex::new(
        [
            ("primary-204.invalid", 429, "private error"),
            ("fallback-204.invalid", 200, "850123"),
            ("fallback-204.invalid", 200, "850124"),
            ("fallback-204.invalid", 200, "{\"6\": 5.0}"),
            ("primary-204.invalid", 200, "850125"),
        ]
        .into(),
    ))));
    assert_eq!(provider.get_block_height().await.unwrap(), 850123);
    assert_eq!(
        provider.chain_view().host.as_deref(),
        Some("fallback-204.invalid")
    );
    assert_eq!(provider.chain_view().trust_level, "third_party");
    // Same constructor as LDK: a new consumer must share the active cooldown.
    let ldk_limiter = RateLimitedTransport::shared("https://primary-204.invalid/api");
    assert!(ldk_limiter
        .run(false, || async { panic!("shared cooldown bypassed") })
        .await
        .is_err());
    tokio::time::advance(std::time::Duration::from_secs(30)).await;
    assert_eq!(provider.get_block_height().await.unwrap(), 850124);
    assert_eq!(provider.estimate_fee(6).await.unwrap().sat_per_vbyte, 5.0);
    tokio::time::advance(std::time::Duration::from_secs(269)).await;
    assert!(ldk_limiter
        .run(false, || async { panic!("retried early") })
        .await
        .is_err());
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    assert_eq!(provider.get_block_height().await.unwrap(), 850125);
    assert!(ldk_limiter.failure().is_none());
}

#[tokio::test]
async fn issue204_zero_or_malformed_height_tries_fallback() {
    for bad in ["0", "not a height"] {
        let mut provider = EsploraProvider::with_fallbacks(
            EsploraConfig::custom("https://bad-height.invalid".into(), TrustLevel::ServerTrust),
            vec!["https://good-height.invalid/api".into()],
        )
        .unwrap();
        provider.transport = Some(Arc::new(ScriptedHttp(std::sync::Mutex::new(
            [
                ("bad-height.invalid", 200, bad),
                ("good-height.invalid", 200, "850123"),
            ]
            .into(),
        ))));
        assert_eq!(provider.get_block_height().await.unwrap(), 850123);
    }
}

#[tokio::test]
async fn issue204_all_endpoints_down_returns_error_not_zero() {
    let mut provider = EsploraProvider::with_fallbacks(
        EsploraConfig::custom(
            "https://down-primary.invalid".into(),
            TrustLevel::ServerTrust,
        ),
        vec!["https://down-fallback.invalid/api".into()],
    )
    .unwrap();
    provider.transport = Some(Arc::new(ScriptedHttp(std::sync::Mutex::new(
        [
            ("down-primary.invalid", 429, "private"),
            ("down-fallback.invalid", 503, "private"),
        ]
        .into(),
    ))));
    assert!(provider.get_block_height().await.is_err());
}

#[tokio::test(start_paused = true)]
async fn issue204_stalled_primary_leaves_time_for_fallback_before_readiness_deadline() {
    let mut provider = EsploraProvider::with_fallbacks(
        EsploraConfig::custom("https://stalled.invalid".into(), TrustLevel::ServerTrust),
        vec!["https://working.invalid/api".into()],
    )
    .unwrap();
    provider.transport = Some(Arc::new(ScriptedHttp(std::sync::Mutex::new(
        [
            ("stalled.invalid", 0, ""),
            ("working.invalid", 200, "850123"),
        ]
        .into(),
    ))));
    let height = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        provider.get_block_height(),
    )
    .await;
    assert_eq!(height.unwrap().unwrap(), 850123);
}

#[tokio::test]
async fn bearer_token_failure_uses_existing_fallback_and_reports_actual_host() {
    #[derive(Debug)]
    struct AuthFailure;
    impl HttpTransport for AuthFailure {
        fn execute(&self, request: reqwest::RequestBuilder) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<reqwest::Response, esplora_client::Error>> + Send + '_>> {
            Box::pin(async move {
                let request = request.build().unwrap();
                assert_eq!(request.url().host_str(), Some("login.invalid"));
                Ok(http::Response::builder().status(401).body("private-secret").unwrap().into())
            })
        }
    }
    #[derive(Debug)]
    struct Fallback;
    impl HttpTransport for Fallback {
        fn execute(&self, request: reqwest::RequestBuilder) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<reqwest::Response, esplora_client::Error>> + Send + '_>> {
            Box::pin(async move {
                let request = request.build().unwrap();
                assert_eq!(request.url().host_str(), Some("fallback.invalid"));
                assert!(!request.headers().contains_key(reqwest::header::AUTHORIZATION));
                Ok(http::Response::builder().status(200).body("900000").unwrap().into())
            })
        }
    }
    let auth = crate::bearer::tests::auth_with_wire(Arc::new(AuthFailure));
    let mut provider = EsploraProvider::with_fallbacks(EsploraConfig::custom("https://paid.invalid/api".into(), TrustLevel::ServerTrust), vec!["https://fallback.invalid/api".into()]).unwrap().with_bearer(auth).unwrap();
    provider.transport = Some(Arc::new(Fallback));
    assert_eq!(provider.get_block_height().await.unwrap(), 900000);
    let view = provider.chain_view();
    assert_eq!(view.host.as_deref(), Some("fallback.invalid"));
    assert_eq!(view.trust_level, "third_party");
}
