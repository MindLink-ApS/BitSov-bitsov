mod common;
use common::*;

use std::collections::HashMap;
use std::sync::Arc;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use tower::ServiceExt;

use konsensus_core::identity::NodeIdentity;
use konsensus_core::gate::PaymentGate;
use konsensus_core::traits::chain::{BlockHeader, ChainError, ChainProvider, FeeEstimate, TrustLevel};
use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails, PaymentDirection,
    PaymentStatus,
};
use konsensus_core::traits::pricing::{PricingEngine, PricingError};
use konsensus_core::traits::transport::{MessageTransport, TransportError};
use konsensus_core::types::{MessageId, NodeId, Nonce, Recipient, RoomId};
use konsensus_core::UkmEnvelope;
use konsensus_message::PeerRegistry;
use konsensus_storage::error::StorageError;
use konsensus_storage::models::{Peer, Room};
use konsensus_storage::Storage;
use async_trait::async_trait;

use konsensus_api::audit::AuditLog;
use konsensus_api::auth;
use konsensus_api::rate_limit::RateLimiter;
use konsensus_api::state::AppState;
use common::test_router as build_router;

fn test_dest_pubkey() -> String {
    format!("02{}", "11".repeat(32))
}

fn test_txid() -> String {
    format!("{}{}", "ba".repeat(16), "cd".repeat(16))
}

#[tokio::test]
async fn payments_balance() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/payments/balance")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["balance_msat"], 100_000_000);
}

#[tokio::test]
async fn payments_create_invoice() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/invoice")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "amount_msat": 5000,
                "description": "test invoice"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["bolt11"].is_string());
    assert!(json["payment_hash"].is_string());
}

#[tokio::test]
async fn payments_price_check() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/payments/price/1") // kind 1 = chat
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["kind"], 1);
    assert_eq!(json["price_msat"], 10);
}

#[tokio::test]
async fn payment_status_check() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/payments/aabbcc")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["payment_hash"], "aabbcc");
    assert!(json["status"].is_string());
}

#[tokio::test]
async fn list_payments_returns_history() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/payments?limit=10")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().expect("should be array");
    assert_eq!(arr.len(), 2);
    // First payment: outgoing
    assert_eq!(arr[0]["direction"], "outgoing");
    assert_eq!(arr[0]["amount_msat"], 25);
    assert_eq!(arr[0]["status"], "settled");
    assert_eq!(arr[0]["memo"], "test message");
    assert_eq!(arr[0]["fee_msat"], 1);
    // Second payment: incoming
    assert_eq!(arr[1]["direction"], "incoming");
    assert_eq!(arr[1]["amount_msat"], 50);
    assert!(arr[1]["memo"].is_null());
    assert!(arr[1]["fee_msat"].is_null());
}

#[tokio::test]
async fn list_payments_respects_limit() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/payments?limit=1")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 1);
}

// ─── Pricing endpoint tests ─────────────────────────────────────────

#[tokio::test]
async fn pricing_own_returns_prices() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/pricing")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // StubPricing returns 10 for all categories
    assert!(json["prices"]["communication"].is_number());
    assert_eq!(json["prices"]["communication"], 10);
    assert_eq!(json["prices"]["files_media"], 10);
    assert!(json["block_height"].is_number());
    assert_eq!(json["peer_tables_cached"], 0);
    // Mode is determined by engine type, not block height.
    // StubPricing is not ChainAwarePricingEngine, so mode = "static"
    // even though StubChain returns a non-zero block height.
    assert_eq!(json["mode"], "static");
    // Difficulty epoch and trust level fields (added in session #45)
    assert!(json["valid_blocks"].is_number());
    assert!(json["trust_level"].is_string());
    assert!(json["difficulty_epoch_position"].is_number());
}

#[tokio::test]
async fn pricing_own_chain_aware_reports_mode() {
    // Build a state with ChainAwarePricingEngine to verify mode detection
    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(Arc::new(test_identity())));

    let base_config = konsensus_pricing::StaticPricingConfig::default();
    let chain: Arc<dyn ChainProvider> = Arc::new(StubChain);
    let chain_config = konsensus_pricing::ChainAwarePricingConfig {
        base: base_config,
        fee_target_blocks: 6,
        cache_ttl: std::time::Duration::from_secs(60),
        max_price_multiplier: 5.0,
        fee_rate_ema_alpha: 0.3,
        category_fee_targets: HashMap::new(),
    };
    let chain_engine = konsensus_pricing::ChainAwarePricingEngine::new(
        chain_config,
        Arc::clone(&chain),
    );

    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(StubLightning),
        chain,
        pricing: Arc::new(chain_engine),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: Arc::new(StubTransport),
        session_manager,
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(konsensus_api::rate_limit::RateLimiter::new(100)),
        mnemonic_reveal_limiter: Arc::new(konsensus_api::rate_limit::RateLimiter::mnemonic_reveal_default()),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
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
        gossip_validator: None,
    });

    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/api/v1/pricing")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // ChainAwarePricingEngine correctly reports chain_aware mode
    assert_eq!(json["mode"], "chain_aware");
    // Chain-aware fields should be present
    assert!(json["max_price_multiplier"].is_number());
}

#[tokio::test]
async fn pricing_peers_empty() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/pricing/peers")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn pricing_peers_with_cached_table() {
    let state = test_state();
    let auth = auth_header(&state);

    // Insert a peer price table
    let peer_id = NodeId::from_bytes([0xAA; 32]);
    let mut prices = std::collections::HashMap::new();
    prices.insert("communication".to_string(), 20u64);
    prices.insert("files_media".to_string(), 200u64);
    state.peer_prices.update(peer_id, prices, 886_000, 144, 0.0).await;

    let app = build_router(Arc::clone(&state));

    // List all peer prices
    let req = Request::builder()
        .uri("/api/v1/pricing/peers")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["prices"]["communication"], 20);
    assert_eq!(arr[0]["prices"]["files_media"], 200);
    assert_eq!(arr[0]["block_height"], 886_000);
    assert_eq!(arr[0]["valid_blocks"], 144);
    assert!(arr[0]["age_secs"].is_number());
    // Should not be stale (just created, StubChain returns height 850_000 < 886_000 + 144)
    assert_eq!(arr[0]["stale"], false);
}

#[tokio::test]
async fn pricing_peer_by_id() {
    let state = test_state();
    let auth = auth_header(&state);

    let peer_id = NodeId::from_bytes([0xBB; 32]);
    let mut prices = std::collections::HashMap::new();
    prices.insert("communication".to_string(), 30u64);
    state.peer_prices.update(peer_id, prices, 886_000, 72, 0.0).await;

    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri(&format!("/api/v1/pricing/peers/{}", peer_id.to_hex()))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["prices"]["communication"], 30);
    assert_eq!(json["valid_blocks"], 72);
}

#[tokio::test]
async fn pricing_peer_not_found() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let fake_peer = "aa".repeat(32);
    let req = Request::builder()
        .uri(&format!("/api/v1/pricing/peers/{fake_peer}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pricing_peer_invalid_id() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/pricing/peers/not-a-hex-id")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pricing_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/pricing")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Payment: pay invoice ──────────────────────────────────────────

#[tokio::test]
async fn pay_invoice_success() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/pay")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "bolt11": "lnbc1test..."
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["payment_hash"].is_string());
    assert_eq!(json["amount_msat"], 1000);
    assert!(json["preimage"].is_string());
}

#[tokio::test]
async fn pay_invoice_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/pay")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"bolt11": "lnbc1test..."}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Payment: channels ─────────────────────────────────────────────

#[tokio::test]
async fn list_channels_returns_empty() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/payments/channels")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array());
}

#[tokio::test]
async fn channels_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/payments/channels")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Payment: balance + price require auth ─────────────────────────

#[tokio::test]
async fn balance_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/payments/balance")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn price_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/payments/price/100")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Invoice: validation ───────────────────────────────────────────

#[tokio::test]
async fn create_invoice_with_defaults() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    // Minimal request — amount_msat required, others have defaults
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/invoice")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"amount_msat": 100}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["bolt11"].as_str().unwrap().starts_with("lnbc"));
    assert!(json["payment_hash"].is_string());
}

// ─── Health: lightning balance field ───────────────────────────────

#[tokio::test]
async fn health_includes_lightning_balance() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["lightning_available"], true);
    assert_eq!(json["lightning_payment_capable"], true);
    // Balance is owner-only — redacted from the unauthenticated /health
    // endpoint and served only by /api/v1/status (A1 drift-kill).
    assert!(
        json.get("lightning_balance_msat").is_none(),
        "unauth /health must not expose wallet balance"
    );
}

#[tokio::test]
async fn pricing_endpoint_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/pricing")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn error_payment_required_returns_402() {
    let err = konsensus_api::error::ApiError::PaymentRequired("pay up".into());
    let resp = axum::response::IntoResponse::into_response(err);
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

// ─── Payment handler edge cases ────────────────────────────────────

#[tokio::test]
async fn pay_invoice_rejects_empty_bolt11() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/pay")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"bolt11": ""}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("bolt11"));
}

#[tokio::test]
async fn list_payments_limit_clamped_to_100() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    // Request limit=500 — should be clamped to 100 internally
    let req = Request::builder()
        .uri("/api/v1/payments?limit=500")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // StubLightning returns 2 payments max, so we just verify success
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.as_array().is_some());
}

#[tokio::test]
async fn list_payments_default_limit() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    // No limit param — default 50
    let req = Request::builder()
        .uri("/api/v1/payments")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn payment_status_returns_pending() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri(&format!("/api/v1/payments/{}", "aa".repeat(32)))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "Pending");
    assert_eq!(json["direction"], "Incoming");
    assert_eq!(json["amount_msat"], 1000);
}

#[tokio::test]
async fn list_payments_entries_have_all_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/api/v1/payments?limit=10")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 2);

    let first = &arr[0];
    assert!(first["payment_hash"].is_string());
    assert!(first["amount_msat"].is_number());
    assert!(first["status"].is_string());
    assert!(first["direction"].is_string());
    assert!(first["timestamp"].is_number());
    // preimage should be present for the first entry (Settled outgoing)
    assert!(first["preimage"].is_string());
}

// ═══════════════════════════════════════════════════════════════════════
// Invoice-Request Payment Flow Tests (QA-C1 Fix)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn create_payment_proof_zero_price_returns_valid_proof() {
    // Zero-price messages should get a valid proof without contacting Lightning.
    let state = test_state();
    let peer_id = NodeId::from_hex(&"bb".repeat(32)).unwrap();

    let result = konsensus_api::handlers::messages::create_payment_proof(&state, 0, &peer_id).await;
    assert!(result.is_ok(), "zero-price should succeed");

    let (hash, preimage, amount) = result.unwrap();
    assert_eq!(amount, 0);
    // Verify hash = SHA256(preimage)
    use sha2::{Digest, Sha256};
    let expected_hash: [u8; 32] = Sha256::digest(preimage).into();
    assert_eq!(hash, expected_hash);
}

#[tokio::test]
async fn create_payment_proof_lightning_unavailable_returns_error() {
    // Non-zero price with Lightning unavailable should return an error.
    // The StubLightning returns is_available = true, but StubTransport returns
    // is_connected = false, so we hit the "offline" check first.
    // This test verifies we get an error (not a fake proof) either way.
    let state = test_state();
    let peer_id = NodeId::from_hex(&"dd".repeat(32)).unwrap();

    let result = konsensus_api::handlers::messages::create_payment_proof(&state, 100, &peer_id).await;
    assert!(result.is_err(), "should fail when payment cannot be made");
}

#[tokio::test]
async fn invoice_request_oneshot_channel_works() {
    // Test the oneshot channel mechanism used for invoice request/response correlation.
    let state = test_state();
    let request_id = "test-req-001".to_string();

    let (tx, rx) = tokio::sync::oneshot::channel::<konsensus_api::state::InvoiceResponseData>();

    // Insert into the invoice_requests map.
    state
        .invoice_requests
        .lock()
        .await
        .insert(request_id.clone(), tx);

    // Simulate receiving an InvoiceResponse (what main.rs would do).
    let data = konsensus_api::state::InvoiceResponseData {
        bolt11: "lnbc250n1pj...test".into(),
        payment_hash: "ab".repeat(32),
    };

    // Remove and fulfill.
    let sender = state
        .invoice_requests
        .lock()
        .await
        .remove(&request_id)
        .expect("request should be in map");
    sender.send(data).expect("should send");

    // Receive on the other end.
    let response = rx.await.expect("should receive");
    assert!(response.bolt11.starts_with("lnbc"));
    assert_eq!(response.payment_hash.len(), 64);
}

#[tokio::test]
async fn invoice_request_timeout_cleanup() {
    // Test that stale entries are cleaned up when the receiver drops.
    let state = test_state();
    let request_id = "test-timeout-001".to_string();

    let (tx, rx) = tokio::sync::oneshot::channel::<konsensus_api::state::InvoiceResponseData>();

    state
        .invoice_requests
        .lock()
        .await
        .insert(request_id.clone(), tx);

    // Drop the receiver (simulates timeout/cancellation).
    drop(rx);

    // The sender should fail when trying to send.
    let sender = state
        .invoice_requests
        .lock()
        .await
        .remove(&request_id)
        .expect("should be in map");

    let data = konsensus_api::state::InvoiceResponseData {
        bolt11: "lnbc...".into(),
        payment_hash: "ab".repeat(32),
    };
    assert!(sender.send(data).is_err(), "send should fail when receiver is dropped");
}

#[tokio::test]
async fn create_invoice_rejects_unknown_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/invoice")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "amount_msat": 1000,
                "description": "test",
                "oops": "typo"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown fields in create invoice request should be rejected"
    );
}

#[tokio::test]
async fn pay_invoice_rejects_unknown_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/pay")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "bolt11": "lnbc1...",
                "amount": 999
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown fields in pay invoice request should be rejected"
    );
}

// ─── Input validation hardening tests ──────────────────────────────

#[tokio::test]
async fn invoice_description_too_long_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let long_desc = "x".repeat(700);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/invoice")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "amount_msat": 1000,
                "description": long_desc,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invoice_description_control_chars_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    // Null byte in description
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/invoice")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "amount_msat": 1000,
                "description": "test\0evil",
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invoice_expiry_too_large_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/invoice")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "amount_msat": 1000,
                "expiry_secs": 999_999_999_u32,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invoice_zero_amount_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/invoice")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "amount_msat": 0 }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invoice_amount_too_large_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/invoice")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "amount_msat": 200_000_000_000_u64 }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn bolt11_too_long_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let long_bolt11 = "lnbc".to_string() + &"a".repeat(2100);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/pay")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "bolt11": long_bolt11 }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Payments: keysend ────────────────────────────────────────────

#[tokio::test]
async fn keysend_success() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/keysend")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "dest_pubkey": test_dest_pubkey(),
                "amount_msat": 1000
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["payment_hash"].is_string());
    assert!(json["preimage"].is_string());
    assert!(json["amount_msat"].is_number());
    assert!(json["status"].is_string());
}

#[tokio::test]
async fn keysend_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/keysend")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "dest_pubkey": "02abcd",
                "amount_msat": 1000
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn keysend_rejects_empty_pubkey() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/keysend")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "dest_pubkey": "",
                "amount_msat": 1000
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn keysend_rejects_amount_below_minimum() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/keysend")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "dest_pubkey": test_dest_pubkey(),
                "amount_msat": 500
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn keysend_rejects_amount_above_maximum() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/keysend")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "dest_pubkey": test_dest_pubkey(),
                "amount_msat": 200_000_000_000_u64
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn keysend_rejects_oversized_pubkey() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let long_pubkey = "a".repeat(80);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/keysend")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "dest_pubkey": long_pubkey,
                "amount_msat": 1000
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn keysend_rejects_unknown_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/keysend")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "dest_pubkey": "02abcd",
                "amount_msat": 1000,
                "bogus_field": "should fail"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ─── Health Endpoint Edge Cases ────────────────────────────────────

#[tokio::test]
async fn health_lightning_unavailable_shows_null_balance() {
    struct UnavailableLightning;

    #[async_trait]
    impl LightningProvider for UnavailableLightning {
        async fn create_invoice(
            &self, _: u64, _: &str, _: u32,
        ) -> Result<Invoice, LightningError> {
            Err(LightningError::Connection("offline".into()))
        }
        async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::Connection("offline".into()))
        }
        async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::Connection("offline".into()))
        }
        async fn get_balance_msat(&self) -> Result<u64, LightningError> {
            Err(LightningError::Connection("offline".into()))
        }
        async fn list_payments(&self, _: u32) -> Result<Vec<PaymentDetails>, LightningError> {
            Err(LightningError::Connection("offline".into()))
        }
        async fn keysend(&self, _: &str, _: u64, _: Option<&str>) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::Connection("offline".into()))
        }
        async fn is_available(&self) -> bool {
            false
        }
    }

    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(Arc::new(test_identity())));
    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(UnavailableLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: Arc::new(StubTransport),
        session_manager,
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        mnemonic_reveal_limiter: Arc::new(RateLimiter::mnemonic_reveal_default()),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        data_dir: None,
        backup_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    });

    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["lightning_available"], false);
    assert_eq!(json["lightning_payment_capable"], false);
    assert!(json["lightning_balance_msat"].is_null());
}

// ═══════════════════════════════════════════════════════════════════
// Payments handler — input validation boundary tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn payments_invoice_zero_amount_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/invoice")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "amount_msat": 0 }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn payments_invoice_over_max_amount_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/invoice")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "amount_msat": 100_000_000_001_u64 }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn payments_invoice_overlong_description_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let long_desc = "x".repeat(640);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/invoice")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "amount_msat": 1000,
                "description": long_desc
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn payments_invoice_over_max_expiry_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/invoice")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "amount_msat": 1000,
                "expiry_secs": 700_000
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn payments_pay_returns_preimage_and_hash() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/pay")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "bolt11": "lnbc1stub..." }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["payment_hash"], "bb".repeat(32));
    assert_eq!(json["preimage"], "cc".repeat(32));
    assert_eq!(json["amount_msat"], 1000);
}

#[tokio::test]
async fn payments_pay_empty_bolt11_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/pay")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "bolt11": "" }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn payments_pay_overlong_bolt11_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let long_bolt11 = "l".repeat(2049);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/pay")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "bolt11": long_bolt11 }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn payments_keysend_validates_amount_bounds() {
    let state = test_state();
    let auth = auth_header(&state);
    let pubkey = "02".to_owned() + &"ab".repeat(32);

    // Below min (1 sat = 1000 msat)
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/keysend")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "dest_pubkey": pubkey,
                "amount_msat": 500
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Above max (>1 BTC)
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/keysend")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "dest_pubkey": pubkey,
                "amount_msat": 100_000_000_001_u64
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn payments_keysend_empty_pubkey_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/keysend")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "dest_pubkey": "",
                "amount_msat": 5000
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn payments_list_returns_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/api/v1/payments")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    // First payment is outgoing with preimage and fee
    assert_eq!(arr[0]["amount_msat"], 25);
    assert!(arr[0]["preimage"].is_string());
    assert!(arr[0]["fee_msat"].is_number());
    assert!(arr[0]["timestamp"].is_number());
    // Second payment has no preimage (incoming)
    assert_eq!(arr[1]["amount_msat"], 50);
}

#[tokio::test]
async fn payments_list_with_limit_caps_at_100() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    // Requesting limit > 100 should be capped
    let req = Request::builder()
        .uri("/api/v1/payments?limit=200")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn payments_get_balance_value() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/api/v1/payments/balance")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["balance_msat"], 100_000_000);
}

#[tokio::test]
async fn payments_status_returns_direction() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let hash = "dd".repeat(32);
    let req = Request::builder()
        .uri(format!("/api/v1/payments/{hash}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["payment_hash"], hash);
    assert!(json["direction"].as_str().unwrap().contains("ncoming"));
}

#[tokio::test]
async fn payments_price_check_returns_kind_and_price() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/api/v1/payments/price/101")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["kind"], 101);
    assert_eq!(json["price_msat"], 10);
}

#[tokio::test]
async fn payments_invoice_rejects_unknown_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/invoice")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "amount_msat": 1000,
                "extra_field": true
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ─── Chain Handler Tests ───────────────────────────────────────────

#[tokio::test]
async fn chain_status_returns_block_height_and_fees() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/api/v1/chain/status")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["block_height"], 850_000);
    assert_eq!(json["fee_rate_fast"], 5.0);
    assert_eq!(json["fee_rate_medium"], 5.0);
    assert_eq!(json["fee_rate_slow"], 5.0);
    assert_eq!(json["available"], true);
    assert!(json.get("error").is_none() || json["error"].is_null());
}

#[tokio::test]
async fn chain_status_auth_gate_rejects_no_token() {
    // L7b: chain/status now requires AuthUser. Unauthenticated callers
    // must be rejected with 401 — the response surfaces backend health
    // and current fee estimates, both of which leak operator info.
    let state = test_state();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/api/v1/chain/status")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn chain_status_with_failing_provider() {
    // Test with a chain provider that returns errors
    struct FailingChain;

    #[async_trait]
    impl ChainProvider for FailingChain {
        fn trust_level(&self) -> TrustLevel {
            TrustLevel::ServerTrust
        }

        async fn get_block_height(&self) -> Result<u64, ChainError> {
            Err(ChainError::NotAvailable("connection refused".into()))
        }

        async fn get_block_header(&self, _height: u64) -> Result<BlockHeader, ChainError> {
            Err(ChainError::NotAvailable("connection refused".into()))
        }

        async fn estimate_fee(&self, _target_blocks: u32) -> Result<FeeEstimate, ChainError> {
            Err(ChainError::NotAvailable("connection refused".into()))
        }

        async fn is_tx_confirmed(
            &self,
            _txid: &str,
            _min_confirmations: u32,
        ) -> Result<bool, ChainError> {
            Err(ChainError::NotAvailable("connection refused".into()))
        }

        async fn is_synced(&self) -> bool {
            false
        }
    }

    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(Arc::new(test_identity())));

    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(StubLightning),
        chain: Arc::new(FailingChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: Arc::new(StubTransport),
        session_manager,
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        mnemonic_reveal_limiter: Arc::new(RateLimiter::mnemonic_reveal_default()),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        data_dir: None,
        backup_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    });

    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/api/v1/chain/status")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // When chain fails, block_height is 0 and available is false
    assert_eq!(json["block_height"], 0);
    assert_eq!(json["fee_rate_fast"], 0.0);
    assert_eq!(json["fee_rate_medium"], 0.0);
    assert_eq!(json["fee_rate_slow"], 0.0);
    assert_eq!(json["available"], false);
    // Error field should contain the error messages
    assert!(json["error"].is_string());
    let error = json["error"].as_str().unwrap();
    assert!(error.contains("block height"), "error should mention block height: {error}");
    assert!(error.contains("connection refused"), "error should contain reason: {error}");
}

#[tokio::test]
async fn chain_status_partial_failure() {
    // Test when block height succeeds but fee estimates fail
    struct PartialChain;

    #[async_trait]
    impl ChainProvider for PartialChain {
        fn trust_level(&self) -> TrustLevel {
            TrustLevel::ServerTrust
        }

        async fn get_block_height(&self) -> Result<u64, ChainError> {
            Ok(943_500)
        }

        async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError> {
            Ok(BlockHeader {
                height,
                hash: "00".repeat(32),
                timestamp: 1_700_000_000,
                bits: 0x1703_2e3b,
            })
        }

        async fn estimate_fee(&self, _target_blocks: u32) -> Result<FeeEstimate, ChainError> {
            Err(ChainError::NotAvailable("fee service unavailable".into()))
        }

        async fn is_tx_confirmed(
            &self,
            _txid: &str,
            _min_confirmations: u32,
        ) -> Result<bool, ChainError> {
            Ok(true)
        }

        async fn is_synced(&self) -> bool {
            true
        }
    }

    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(Arc::new(test_identity())));

    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(StubLightning),
        chain: Arc::new(PartialChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: Arc::new(StubTransport),
        session_manager,
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        mnemonic_reveal_limiter: Arc::new(RateLimiter::mnemonic_reveal_default()),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        data_dir: None,
        backup_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    });

    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/api/v1/chain/status")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Block height succeeded
    assert_eq!(json["block_height"], 943_500);
    assert_eq!(json["available"], true);
    // Fee rates should be 0 (failed)
    assert_eq!(json["fee_rate_fast"], 0.0);
    assert_eq!(json["fee_rate_medium"], 0.0);
    assert_eq!(json["fee_rate_slow"], 0.0);
    // Error field should mention the fee failures
    assert!(json["error"].is_string());
    let error = json["error"].as_str().unwrap();
    assert!(error.contains("fee"), "error should mention fee: {error}");
}

#[tokio::test]
async fn chain_status_response_has_correct_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/api/v1/chain/status")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify all expected fields are present
    assert!(json.get("block_height").is_some(), "missing block_height");
    assert!(json.get("fee_rate_fast").is_some(), "missing fee_rate_fast");
    assert!(json.get("fee_rate_medium").is_some(), "missing fee_rate_medium");
    assert!(json.get("fee_rate_slow").is_some(), "missing fee_rate_slow");
    assert!(json.get("available").is_some(), "missing available");

    // Verify types
    assert!(json["block_height"].is_number());
    assert!(json["fee_rate_fast"].is_number());
    assert!(json["fee_rate_medium"].is_number());
    assert!(json["fee_rate_slow"].is_number());
    assert!(json["available"].is_boolean());
}

// ─── L1: fee_rate_sat_per_vb on send-onchain ──────────────────────────

/// Sending with an explicit fee_rate_sat_per_vb accepts the field and returns a txid.
#[tokio::test]
async fn send_onchain_with_fee_rate_succeeds() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/send-onchain")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                "amount_sats": 10_000_u64,
                "fee_rate_sat_per_vb": 5.0
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // StubLightning returns a deterministic txid; verify it is present and non-empty.
    assert!(json["txid"].is_string());
    assert!(!json["txid"].as_str().unwrap().is_empty());
}

/// Omitting fee_rate_sat_per_vb is backward-compatible — the field is optional.
#[tokio::test]
async fn send_onchain_without_fee_rate_is_backward_compatible() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/send-onchain")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                "amount_sats": 5_000_u64
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["txid"].is_string());
}

/// fee_rate_sat_per_vb = 0 must be rejected with HTTP 400.
#[tokio::test]
async fn send_onchain_fee_rate_zero_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/send-onchain")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                "amount_sats": 5_000_u64,
                "fee_rate_sat_per_vb": 0.0
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// fee_rate_sat_per_vb < 0 must also be rejected with HTTP 400.
#[tokio::test]
async fn send_onchain_fee_rate_negative_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/send-onchain")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                "amount_sats": 5_000_u64,
                "fee_rate_sat_per_vb": -1.0
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// L0a — fractional rates below 1.0 sat/vB silently floored to 0 in the
/// pre-L0a code, producing an unbroadcast tx. The shared validator must
/// reject them with HTTP 400.
#[tokio::test]
async fn send_onchain_fee_rate_below_one_sat_per_vb_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/send-onchain")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                "amount_sats": 5_000_u64,
                "fee_rate_sat_per_vb": 0.5
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// L0a — `NaN` slips past `<= 0.0` checks (NaN compares false everywhere).
/// The validator must reject it explicitly.
#[tokio::test]
async fn send_onchain_fee_rate_nan_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    // serde_json doesn't serialize f64::NAN, so build the body literally.
    let raw_body = r#"{"address":"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu","amount_sats":5000,"fee_rate_sat_per_vb":NaN}"#;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/send-onchain")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(raw_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Reject either at JSON parse (strict) or at validator (lenient parse) —
    // both are 4xx; NaN must never reach LDK.
    assert!(
        resp.status().is_client_error(),
        "expected 4xx, got {}",
        resp.status()
    );
}

/// L0f — a lightning provider that returns `BroadcastUnconfirmed` is
/// translated by the API handler to HTTP 202 Accepted (not HTTP 200 OK
/// or HTTP 502). Caller polls until the tx confirms or replaces it.
#[tokio::test]
async fn send_onchain_broadcast_unconfirmed_returns_202() {
    use async_trait::async_trait;
    use konsensus_core::traits::lightning::{Invoice, PaymentDetails};

    /// Lightning stub whose `send_onchain` always returns
    /// `BroadcastUnconfirmed`. Other methods are minimal stubs because
    /// the send-onchain handler doesn't touch them.
    struct UnconfirmedLightning;

    #[async_trait]
    impl LightningProvider for UnconfirmedLightning {
        async fn create_invoice(
            &self,
            _amount_msat: u64,
            _description: &str,
            _expiry_secs: u32,
        ) -> Result<Invoice, LightningError> {
            Err(LightningError::Backend("stub".into()))
        }
        async fn pay_invoice(&self, _bolt11: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::Backend("stub".into()))
        }
        async fn get_payment_status(
            &self,
            _payment_hash: &str,
        ) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::Backend("stub".into()))
        }
        async fn get_balance_msat(&self) -> Result<u64, LightningError> {
            Ok(0)
        }
        async fn is_available(&self) -> bool {
            true
        }
        async fn send_onchain(
            &self,
            _address: &str,
            _amount_sats: u64,
            _fee_rate_sat_per_vb: Option<f32>,
        ) -> Result<String, LightningError> {
            Err(LightningError::BroadcastUnconfirmed {
                txid: test_txid(),
            })
        }
    }

    // Build an AppState with the custom lightning provider. Reuse
    // `test_state()` then patch the `lightning` field via a fresh Arc.
    let base = test_state();
    let state = Arc::new(konsensus_api::AppState {
        identity: Arc::clone(&base.identity),
        storage: Arc::clone(&base.storage),
        lightning: Arc::new(UnconfirmedLightning),
        chain: Arc::clone(&base.chain),
        pricing: Arc::clone(&base.pricing),
        gate: Arc::clone(&base.gate),
        peer_registry: Arc::clone(&base.peer_registry),
        transport: Arc::clone(&base.transport),
        session_manager: Arc::clone(&base.session_manager),
        jwt_secret: base.jwt_secret.clone(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        cors_enabled: base.cors_enabled,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: base.ws_broadcast.clone(),
        ws_delivery_broadcast: base.ws_delivery_broadcast.clone(),
        rate_limiter: Arc::clone(&base.rate_limiter),
        mnemonic_reveal_limiter: Arc::clone(&base.mnemonic_reveal_limiter),
        audit_log: Arc::clone(&base.audit_log),
        started_at: base.started_at,
        content_dir: base.content_dir.clone(),
        web_page_price_msat: base.web_page_price_msat,
        peer_prices: Arc::clone(&base.peer_prices),
        routing: Arc::clone(&base.routing),
        plaintext_cipher: base.plaintext_cipher.clone(),
        send_timestamps: Arc::clone(&base.send_timestamps),
        invoice_requests: Arc::clone(&base.invoice_requests),
        data_dir: base.data_dir.clone(),
        backup_dir: None,
        peer_ln_pubkeys: Arc::clone(&base.peer_ln_pubkeys),
        lightning_backend: base.lightning_backend.clone(),
        chain_backend: base.chain_backend.clone(),
        gossip_validator: base.gossip_validator.clone(),
    });
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/send-onchain")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                "amount_sats": 5_000_u64,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "L0f: BroadcastUnconfirmed must map to HTTP 202, not 200 or 502"
    );

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["broadcast_status"], "unconfirmed");
    assert_eq!(body["txid"].as_str().unwrap(), test_txid());
}

/// L0a — rates above the 10_000 sat/vB sanity bound are rejected.
#[tokio::test]
async fn send_onchain_fee_rate_above_max_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/send-onchain")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                "amount_sats": 5_000_u64,
                "fee_rate_sat_per_vb": 50_000.0_f32
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── L3: close-channel API ───────────────────────────────────────────

#[tokio::test]
async fn close_channel_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/close-channel")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "channel_id": "stub-channel-id",
                "force": false
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn close_channel_rejects_empty_channel_id() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/close-channel")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "channel_id": "   ",
                "force": false
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn close_channel_returns_closing_status() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/payments/close-channel")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "channel_id": "stub-channel-id",
                "force": true
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["channel_id"], "stub-channel-id");
    assert_eq!(json["force"], true);
    assert_eq!(json["closing_txid"], "stub-closing-txid-force");
    assert_eq!(json["status"], "closing");
}
