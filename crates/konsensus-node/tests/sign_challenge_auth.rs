//! CLI `sign-challenge` must mint a signature `/auth/token` accepts.
#![cfg(unix)]

use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use konsensus_core::traits::lightning::LightningProvider;
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::NodeIdentity;
use konsensus_crypto::SessionManager;
use konsensus_message::{NoiseTransport, TransportConfig};
use std::net::SocketAddr;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

async fn owner_router(identity: Arc<NodeIdentity>) -> axum::Router {
    let transport = Arc::new(NoiseTransport::new(
        Arc::clone(&identity),
        TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        },
    ));
    let sessions = Arc::new(SessionManager::new(Arc::clone(&identity)));
    let audit = tempfile::NamedTempFile::new().unwrap();
    let state = Arc::new(konsensus_api::AppState {
        file_staging: Default::default(),
        identity: Arc::clone(&identity),
        storage: Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap()),
        lightning: Arc::new(konsensus_lightning::MockLightningProvider::new())
            as Arc<dyn LightningProvider>,
        chain: Arc::new(konsensus_chain::MockChainProvider::new()),
        pricing: Arc::new(konsensus_pricing::StaticPricingEngine::new(konsensus_pricing::StaticPricingConfig::default())),
        gate: Arc::new(konsensus_core::PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(konsensus_message::PeerRegistry::new())),
        transport: Arc::clone(&transport) as Arc<dyn MessageTransport>,
        session_manager: sessions,
        jwt_secret: "sign-challenge-e2e-jwt-secret".into(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        pairing: None,
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        has_identity_passphrase: false,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(konsensus_api::rate_limit::RateLimiter::new(100)),
        mnemonic_reveal_limiter: Arc::new(
            konsensus_api::rate_limit::RateLimiter::mnemonic_reveal_default(),
        ),
        audit_log: Arc::new(konsensus_api::audit::AuditLog::open(audit.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        invoice_requests: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        data_dir: None,
        backup_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        introduction: Default::default(),
        front_door: Default::default(),
        sponsor: Default::default(),
        stun_port: None,
        custody_mode: konsensus_api::custody::CustodyMode::LocalSeed,
        gossip_validator: None,
    });
    konsensus_api::build_router(state)
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 31_41))))
}

fn cli_sign(mnemonic: &std::path::Path, challenge: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args([
            "sign-challenge",
            "--mnemonic",
            mnemonic.to_str().unwrap(),
            "--challenge",
            challenge,
        ])
        .output()
        .expect("run sign-challenge");
    assert!(
        output.status.success(),
        "sign-challenge failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.to_lowercase().contains("abandon"),
        "mnemonic must never appear on stdout"
    );
    stdout.trim().to_owned()
}

#[tokio::test]
async fn cli_sign_challenge_accepted_by_auth_token_wrong_nonce_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mnemonic_path = dir.path().join("mnemonic.txt");
    std::fs::write(&mnemonic_path, TEST_MNEMONIC).unwrap();

    let identity = Arc::new(NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap());
    let app = owner_router(Arc::clone(&identity)).await;

    let challenge_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/challenge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let challenge_status = challenge_resp.status();
    let challenge_body = axum::body::to_bytes(challenge_resp.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        challenge_status,
        StatusCode::OK,
        "challenge failed: {} {}",
        challenge_status,
        String::from_utf8_lossy(&challenge_body)
    );
    let challenge_json: serde_json::Value = serde_json::from_slice(&challenge_body).unwrap();
    let challenge = challenge_json["challenge"].as_str().unwrap().to_owned();
    assert!(
        challenge.starts_with("bitsov-auth-v1:"),
        "unexpected challenge format: {challenge}"
    );

    let signature = cli_sign(&mnemonic_path, &challenge);
    let ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "challenge": challenge,
                        "signature": signature,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK, "CLI signature must mint a token");
    let token_body = axum::body::to_bytes(ok.into_body(), 4096).await.unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&token_body).unwrap();
    assert!(token_json["token"].as_str().unwrap().contains('.'));

    // Fresh challenge + signature over a different (wrong) nonce must be refused.
    let other = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/challenge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let other_body = axum::body::to_bytes(other.into_body(), 4096).await.unwrap();
    let other_json: serde_json::Value = serde_json::from_slice(&other_body).unwrap();
    let live_challenge = other_json["challenge"].as_str().unwrap().to_owned();
    let wrong_nonce_challenge = {
        // Same shape, different 32-byte nonce hex, keep the expiry suffix.
        let expiry = live_challenge.rsplit(':').next().unwrap();
        format!(
            "bitsov-auth-v1:{}:{expiry}",
            "11".repeat(32)
        )
    };
    let wrong_sig = cli_sign(&mnemonic_path, &wrong_nonce_challenge);
    let refused = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "challenge": live_challenge,
                        "signature": wrong_sig,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        refused.status(),
        StatusCode::UNAUTHORIZED,
        "signature over a wrong nonce must not mint a token"
    );
}

/// Drive `docs/ops/test-owner-token.sh` so cargo test covers the sourced-script
/// error path and loopback URL guard (see PR #125 review).
#[test]
fn owner_token_script_error_path_and_url_guard() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root");
    let script = repo_root.join("docs/ops/test-owner-token.sh");
    let status = Command::new("bash")
        .arg(&script)
        .current_dir(&repo_root)
        .status()
        .expect("spawn bash docs/ops/test-owner-token.sh");
    assert!(
        status.success(),
        "docs/ops/test-owner-token.sh failed (status {status})"
    );
}
