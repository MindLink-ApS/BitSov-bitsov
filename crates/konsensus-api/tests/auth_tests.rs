mod common;
use common::*;

use std::collections::HashMap;
use std::sync::Arc;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
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


// ─── Tests ──────────────────────────────────────────────────────────

async fn fetch_auth_challenge(app: Router) -> String {
    let req = Request::builder()
        .uri("/api/v1/auth/challenge")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    json["challenge"].as_str().unwrap().to_owned()
}

async fn signed_auth_body(state: &AppState, app: Router) -> String {
    let challenge = fetch_auth_challenge(app).await;
    let sig = state.identity.sign(challenge.as_bytes());
    let sig_hex = hex::encode(sig.to_bytes());
    serde_json::json!({"challenge": challenge, "signature": sig_hex}).to_string()
}

#[tokio::test]
async fn health_returns_ok() {
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
    assert_eq!(json["status"], "ok");
    assert_eq!(json["version"], 2);
    // node_id is owner-only; the unauthenticated /health endpoint must not
    // expose node identity (moved to /api/v1/status — A1 drift-kill).
    assert!(
        json.get("node_id").is_none(),
        "unauth /health must not expose node identity"
    );
}

#[tokio::test]
async fn preflight_returns_ok_when_operator_probes_enabled() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/preflight")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["version"], 2);
    assert!(json["uptime_secs"].is_number());
    assert!(json.get("node_id").is_none(), "preflight must not expose node identity");
}

#[tokio::test]
async fn preflight_not_mounted_when_operator_probes_disabled() {
    let base = test_state();
    let state = Arc::new(AppState {
        operator_probes_enabled: false,
        sensitive_identity_routes_enabled: true,
        ..(*base).clone()
    });
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/preflight")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mnemonic_routes_not_mounted_when_sensitive_identity_disabled() {
    let temp_dir = tempfile::tempdir().unwrap();
    let base = test_state_with_data_dir(temp_dir.path().to_path_buf());
    let state = Arc::new(AppState {
        sensitive_identity_routes_enabled: false,
        ..(*base).clone()
    });
    let token = auth_header(&state);
    let app = build_router(state);

    let reveal_mnemonic = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/mnemonic")
        .header("Authorization", token.clone())
        .header("content-type", "application/json")
        .body(Body::from(r#"{"challenge":"x","signature":"00"}"#))
        .unwrap();
    let resp = app.clone().oneshot(reveal_mnemonic).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let restore = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/restore")
        .header("Authorization", token)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}"#,
        ))
        .unwrap();
    let resp = app.oneshot(restore).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unauthenticated_request_returns_401() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/identity")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_token_flow() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));
    let body = signed_auth_body(&state, app.clone()).await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["token"].is_string());
    assert!(json["expires_at"].is_number());
}

#[tokio::test]
async fn auth_challenge_does_not_leak_node_id() {
    // The unauthenticated /auth/challenge must not embed the node_id. `/health`
    // already redacts it (owner-only), so a scanner must not be able to recover
    // it via the challenge. The node_id is not load-bearing for token issuance —
    // the signature + single-use challenge-map membership are the auth, and the
    // 32-byte nonce makes each challenge unique.
    let state = test_state();
    let node_id_hex = state.identity.node_id().to_hex();
    let app = build_router(Arc::clone(&state));

    let challenge = fetch_auth_challenge(app.clone()).await;
    assert!(
        !challenge.contains(&node_id_hex),
        "auth challenge must not leak the node_id (got: {challenge})"
    );

    // The full sign -> token flow still succeeds with the node-id-free challenge.
    let body = signed_auth_body(&state, app.clone()).await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a node-id-free challenge must still authenticate"
    );
}

#[tokio::test]
async fn auth_token_challenge_is_single_use() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));
    let body = signed_auth_body(&state, app.clone()).await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(body.clone()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let replay = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(replay).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_rejects_bad_signature() {
    let state = test_state();
    let app = build_router(state);
    let challenge = fetch_auth_challenge(app.clone()).await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"challenge": challenge, "signature": "aa".repeat(64)}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn identity_returns_keys() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/identity")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["node_id"].is_string());
    assert!(json["x25519_public"].is_string());
    assert!(json["secp256k1_public"].is_string());
}

#[tokio::test]
async fn local_auth_rejects_non_localhost() {
    use axum::extract::connect_info::MockConnectInfo;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let state = test_state();
    // Inject a *non-loopback* client address. This passes the per-IP
    // rate-limit middleware (which fails closed only on a *missing* IP,
    // not on a public one) and reaches the auth/local handler, which then
    // rejects the request because the caller is not on localhost.
    let app = konsensus_api::build_router(state).layer(MockConnectInfo(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 40000),
    ));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/local")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rate_limiter_basic() {
    let limiter = RateLimiter::new(3);
    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

    assert!(limiter.check(ip));
    assert!(limiter.check(ip));
    assert!(limiter.check(ip));
    assert!(!limiter.check(ip)); // 4th request rejected
}

#[tokio::test]
async fn invalid_jwt_returns_401() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/identity")
        .header("authorization", "Bearer invalid.token.here")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn health_endpoint_returns_public_counters_and_redacts_secrets() {
    let state = test_state();
    let app = build_router(state);

    // Health endpoint requires no authentication
    let req = Request::builder()
        .uri("/api/v1/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Public, non-sensitive operational fields are present.
    assert_eq!(json["status"], "ok");
    assert_eq!(json["connected_peers"], 0);
    assert_eq!(json["e2ee_sessions"], 0);
    assert_eq!(json["pending_deliveries"], 0);
    assert_eq!(json["version"], 2);
    assert!(json["uptime_secs"].is_number());

    // Sensitive fields are redacted from the unauthenticated /health endpoint;
    // they are served only by the owner-only /api/v1/status (A1 drift-kill).
    assert!(json.get("node_id").is_none(), "unauth /health must not expose node_id");
    assert!(
        json.get("connected_peer_ids").is_none(),
        "unauth /health must not expose peer IDs (social graph)"
    );
    assert!(
        json.get("lightning_balance_msat").is_none(),
        "unauth /health must not expose wallet balance"
    );
    assert!(
        json.get("lightning_node_pubkey").is_none(),
        "unauth /health must not expose LN pubkey"
    );
}

#[tokio::test]
async fn status_endpoint_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    // The full node status (identity, peers, balance) is owner-only.
    let req = Request::builder()
        .uri("/api/v1/status")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "/api/v1/status must require auth"
    );
}

#[tokio::test]
async fn audit_log_records_events() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let log = AuditLog::open(tmp.path()).unwrap();

    log.record("test.event", "actor1", Some(serde_json::json!({"key": "value"})));
    log.record("test.event2", "actor2", None);

    let contents = std::fs::read_to_string(tmp.path()).unwrap();
    let lines: Vec<&str> = contents.trim().lines().collect();
    assert_eq!(lines.len(), 2);

    let entry1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(entry1["event"], "test.event");
    assert_eq!(entry1["seq"], 1);

    let entry2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(entry2["event"], "test.event2");
    assert_eq!(entry2["seq"], 2);
}

// ─── Auth edge case tests ────────────────────────────────────────

#[tokio::test]
async fn auth_rejects_malformed_hex_signature() {
    let state = test_state();
    let app = build_router(state);
    let challenge = fetch_auth_challenge(app.clone()).await;

    // Not valid hex
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"challenge": challenge, "signature": "zzzz-not-hex"}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Should return 400 (bad request) or 401 (unauthorized)
    assert!(
        resp.status() == StatusCode::BAD_REQUEST
            || resp.status() == StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn auth_rejects_truncated_signature() {
    let state = test_state();
    let app = build_router(state);
    let challenge = fetch_auth_challenge(app.clone()).await;

    // Valid hex but too short for Ed25519 signature (need 64 bytes = 128 hex chars)
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"challenge": challenge, "signature": "aabb"}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status() == StatusCode::BAD_REQUEST
            || resp.status() == StatusCode::UNAUTHORIZED
    );
}

// ─── Session endpoint tests ────────────────────────────────────────

#[tokio::test]
async fn sessions_list_empty() {
    let state = test_state();
    let auth = auth_header(&state);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/sessions")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let sessions: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(sessions.is_empty());
}

#[tokio::test]
async fn sessions_prekey_bundle() {
    let state = test_state();
    let auth = auth_header(&state);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/sessions/prekey")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let bundle = &result["bundle"];
    assert!(!bundle["identity_key"].as_str().unwrap().is_empty());
    assert!(!bundle["signed_prekey"].as_str().unwrap().is_empty());
    assert!(!bundle["signed_prekey_sig"].as_str().unwrap().is_empty());
    assert!(!bundle["node_id"].as_str().unwrap().is_empty());
    // Should have a one-time prekey
    assert!(bundle["one_time_prekey"].as_str().is_some());
}

#[tokio::test]
async fn sessions_prekey_requires_auth() {
    let state = test_state();
    let app = build_router(state);
    let req = Request::builder()
        .uri("/api/v1/sessions/prekey")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_status_no_session() {
    let state = test_state();
    let auth = auth_header(&state);
    let fake_peer = "aa".repeat(32);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(&format!("/api/v1/sessions/{fake_peer}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["active"], false);
    assert_eq!(result["peer_id"], fake_peer);
}

// ─── Sessions list requires auth ───────────────────────────────────

#[tokio::test]
async fn sessions_list_requires_auth() {
    let state = test_state();
    let app = build_router(state);
    let req = Request::builder()
        .uri("/api/v1/sessions")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Health: no auth required ──────────────────────────────────────

#[tokio::test]
async fn health_requires_no_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── Identity: requires auth ───────────────────────────────────────

#[tokio::test]
async fn identity_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/identity")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ═══════════════════════════════════════════════════════════════════
// Session endpoint tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn session_prekey_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/sessions/prekey")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_prekey_returns_bundle() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/api/v1/sessions/prekey")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["bundle"].is_object(), "response must contain bundle");
}

#[tokio::test]
async fn session_list_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/sessions")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_list_returns_array() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/api/v1/sessions")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array(), "session list must be an array");
}

#[tokio::test]
async fn session_status_requires_auth() {
    let state = test_state();
    let app = build_router(state);
    let peer_id = "aa".repeat(32);

    let req = Request::builder()
        .uri(format!("/api/v1/sessions/{peer_id}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_initiate_requires_auth() {
    let state = test_state();
    let app = build_router(state);
    let peer_id = "cc".repeat(32);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/sessions/{peer_id}/initiate"))
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_accept_requires_auth() {
    let state = test_state();
    let app = build_router(state);
    let peer_id = "dd".repeat(32);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/sessions/{peer_id}/accept"))
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ═══════════════════════════════════════════════════════════════════
// Additional edge case tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn health_returns_uptime() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["uptime_secs"].is_number());
}

#[tokio::test]
async fn identity_endpoint_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/identity")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ════════════════════════════════════════════════════════════════════
// Session #119: Hardening — API handler edge cases, error mapping,
// content helpers, payment/room/message lifecycle tests
// ════════════════════════════════════════════════════════════════════

// ─── API Error → HTTP status code mapping ──────────────────────────

#[tokio::test]
async fn error_not_found_returns_404() {
    let err = konsensus_api::error::ApiError::NotFound("gone".into());
    let resp = axum::response::IntoResponse::into_response(err);
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn error_bad_request_returns_400() {
    let err = konsensus_api::error::ApiError::BadRequest("bad".into());
    let resp = axum::response::IntoResponse::into_response(err);
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn error_unauthorized_returns_401() {
    let err = konsensus_api::error::ApiError::Unauthorized("no".into());
    let resp = axum::response::IntoResponse::into_response(err);
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn error_storage_returns_500() {
    let err = konsensus_api::error::ApiError::Storage("disk full".into());
    let resp = axum::response::IntoResponse::into_response(err);
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn error_transport_returns_502() {
    let err = konsensus_api::error::ApiError::Transport("peer down".into());
    let resp = axum::response::IntoResponse::into_response(err);
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn error_lightning_returns_502() {
    let err = konsensus_api::error::ApiError::Lightning("lnd unreachable".into());
    let resp = axum::response::IntoResponse::into_response(err);
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn error_internal_returns_500() {
    let err = konsensus_api::error::ApiError::Internal("oops".into());
    let resp = axum::response::IntoResponse::into_response(err);
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn error_body_contains_message_and_code() {
    let err = konsensus_api::error::ApiError::NotFound("item missing".into());
    let resp = axum::response::IntoResponse::into_response(err);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "item missing");
    assert_eq!(json["code"], 404);
}

#[tokio::test]
async fn auth_token_rejects_unknown_fields() {
    let state = test_state();
    let app = build_router(state);
    let challenge = fetch_auth_challenge(app.clone()).await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "challenge": challenge,
                "signature": "aa".repeat(64),
                "extra_field": "typo"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown fields in token request should be rejected"
    );
}

// ─── Identity endpoint auth tests ──────────────────────────────────

#[tokio::test]
async fn restore_identity_without_auth_returns_401() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/restore")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "restore endpoint must require authentication"
    );
}

#[tokio::test]
async fn verify_mnemonic_auth_gate_rejects_no_token() {
    // L7b: verify-mnemonic now requires AuthUser.
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/verify-mnemonic")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn verify_mnemonic_with_auth_succeeds() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/verify-mnemonic")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({
                "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["node_id"].is_string());
    assert!(!json["node_id"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn verify_mnemonic_invalid_returns_400() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/verify-mnemonic")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({
                "mnemonic": "not a valid mnemonic phrase at all"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn restore_identity_with_auth_and_data_dir_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state_with_data_dir(tmp.path().to_path_buf());
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/restore")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({
                "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["node_id"].is_string());
    assert_eq!(json["restart_required"], true);

    // Verify the mnemonic was written to disk
    let mnemonic_path = tmp.path().join("mnemonic.txt");
    assert!(mnemonic_path.exists());
    let written = std::fs::read_to_string(&mnemonic_path).unwrap();
    assert!(written.starts_with("abandon"));
}

#[tokio::test]
async fn restore_identity_invalid_mnemonic_returns_400() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state_with_data_dir(tmp.path().to_path_buf());
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/restore")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({
                "mnemonic": "invalid words here"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn verify_mnemonic_rejects_wrong_word_count() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    // 3 words — neither 12 nor 24
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/verify-mnemonic")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({
                "mnemonic": "abandon abandon abandon"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "mnemonic with wrong word count should be rejected"
    );

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"].as_str().unwrap().contains("12 or 24 words"),
        "error message should mention valid word counts"
    );
}

#[tokio::test]
async fn verify_mnemonic_rejects_100_word_input() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    // 100 words — resource exhaustion attempt
    let words = std::iter::repeat("abandon").take(100).collect::<Vec<_>>().join(" ");
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/verify-mnemonic")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({
                "mnemonic": words
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "100-word mnemonic should be rejected before derivation"
    );
}

/// Build a POST request to the hardened mnemonic reveal route carrying a
/// valid re-auth body (fresh challenge + node-key signature).
async fn reveal_request_with_reauth(state: &AppState, app: Router, auth: &str) -> Request<Body> {
    let body = signed_auth_body(state, app).await;
    Request::builder()
        .method("POST")
        .uri("/api/v1/identity/mnemonic")
        .header("authorization", auth)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn reveal_mnemonic_encrypted_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    // Create an encrypted mnemonic file
    std::fs::write(dir.path().join("mnemonic.enc"), b"encrypted-data").unwrap();

    let state = test_state_with_data_dir(dir.path().to_path_buf());
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = reveal_request_with_reauth(&state, app.clone(), &auth).await;
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reveal_mnemonic_missing_returns_not_found() {
    let dir = tempfile::tempdir().unwrap();
    // No mnemonic file exists

    let state = test_state_with_data_dir(dir.path().to_path_buf());
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = reveal_request_with_reauth(&state, app.clone(), &auth).await;
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reveal_mnemonic_requires_auth() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("mnemonic.txt"), "test words").unwrap();

    let state = test_state_with_data_dir(dir.path().to_path_buf());
    let app = build_router(state);

    // No Authorization header — AuthUser extractor rejects before re-auth.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/mnemonic")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"challenge":"x","signature":"00"}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn reveal_mnemonic_no_data_dir_returns_error() {
    // test_state() has data_dir: None
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = reveal_request_with_reauth(&state, app.clone(), &auth).await;
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ─── HARD-9: mnemonic reveal re-auth + rate-limit + audit ──────────────

/// A valid JWT alone (no re-auth signature) must NOT reveal the seed.
/// This is the core HARD-9 guarantee: a leaked session token cannot
/// silently exfiltrate the recovery phrase.
#[tokio::test]
async fn reveal_mnemonic_rejects_jwt_without_reauth_signature() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("mnemonic.txt"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();

    let state = test_state_with_data_dir(dir.path().to_path_buf());
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    // Hold a valid JWT but present an unknown challenge + bogus signature.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/mnemonic")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "challenge": "never-issued-challenge",
                "signature": "aa".repeat(64),
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a valid JWT without a fresh re-auth signature must not reveal the seed"
    );
}

/// A valid JWT + a fresh challenge but a WRONG signature must be rejected.
#[tokio::test]
async fn reveal_mnemonic_rejects_wrong_signature() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("mnemonic.txt"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();

    let state = test_state_with_data_dir(dir.path().to_path_buf());
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    // Fetch a real challenge, but sign garbage instead of the challenge.
    let challenge = fetch_auth_challenge(app.clone()).await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/mnemonic")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "challenge": challenge,
                "signature": "bb".repeat(64),
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// The happy path: valid JWT + valid re-auth signature reveals the seed,
/// the challenge is single-use, and a success audit event is written.
#[tokio::test]
async fn reveal_mnemonic_with_reauth_succeeds_and_audits() {
    const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("mnemonic.txt"), PHRASE).unwrap();

    // Place the audit log inside the (long-lived) test dir so we can read it
    // back by path after the request. `test_state_with_data_dir` would put it
    // in a NamedTempFile that is unlinked when the helper returns.
    let audit_path = dir.path().join("audit.log");
    let base = test_state_with_data_dir(dir.path().to_path_buf());
    let state = Arc::new(AppState {
        audit_log: Arc::new(AuditLog::open(&audit_path).unwrap()),
        ..(*base).clone()
    });
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = reveal_request_with_reauth(&state, app.clone(), &auth).await;
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["mnemonic"], PHRASE);

    // A success audit event must be present — and must NOT contain the seed.
    let audit = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        audit.contains("identity.mnemonic_revealed"),
        "reveal must emit an audit event"
    );
    assert!(
        audit.contains("\"success\":true"),
        "successful reveal must be audited as success"
    );
    assert!(
        !audit.contains("abandon"),
        "the audit log must never contain the seed phrase"
    );
}

/// The strict reveal limiter caps reveal attempts. Once the per-actor
/// budget is exhausted, further attempts are rate-limited (429) even with
/// a valid JWT — bounding brute-force of the re-auth gate (HARD-9).
#[tokio::test]
async fn reveal_mnemonic_is_rate_limited() {
    let dir = tempfile::tempdir().unwrap();
    // No file — the file checks come AFTER the rate-limit + re-auth gate, so
    // we drive the limiter without needing a valid signature each time.
    let base = test_state_with_data_dir(dir.path().to_path_buf());
    // Tight limiter: 2 attempts per (long) window so the test is deterministic.
    let state = Arc::new(AppState {
        mnemonic_reveal_limiter: Arc::new(
            konsensus_api::rate_limit::RateLimiter::with_window(
                2,
                std::time::Duration::from_secs(300),
            ),
        ),
        ..(*base).clone()
    });
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let make_req = |auth: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/identity/mnemonic")
            .header("authorization", auth)
            .header("content-type", "application/json")
            // Unknown challenge: fails re-auth with 401, but each call still
            // consumes one unit of the reveal limiter budget first.
            .body(Body::from(r#"{"challenge":"nope","signature":"00"}"#))
            .unwrap()
    };

    // First two attempts: pass the limiter, fail re-auth (401).
    for _ in 0..2 {
        let resp = app.clone().oneshot(make_req(&auth)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    // Third attempt: limiter is exhausted → 429 before re-auth is even checked.
    let resp = app.oneshot(make_req(&auth)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ─── WebSocket Auth Rejection Test ─────────────────────────────────

#[tokio::test]
async fn ws_rejects_missing_token() {
    let state = test_state();
    let app = build_router(state);

    // Attempt a WebSocket upgrade without a token query param.
    // Axum's Query<WsParams> extractor rejects before the handler runs.
    let req = Request::builder()
        .uri("/api/v1/ws")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Should fail (400 or 422) — not upgrade (101) or success (200).
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn ws_rejects_invalid_token() {
    let state = test_state();
    let app = build_router(state);

    // Without proper WebSocket upgrade headers, Axum returns 426 Upgrade Required
    // before the handler body runs. This verifies the endpoint doesn't accept
    // a plain HTTP request even with a token — it must be a real WS upgrade.
    let req = Request::builder()
        .uri("/api/v1/ws?token=invalid-jwt-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Should be a client error (401 or 426 depending on header presence).
    assert!(resp.status().is_client_error());
}

// ─── Auth Handler Edge Case Tests ──────────────────────────────────

#[tokio::test]
async fn auth_token_invalid_hex_signature() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));
    let challenge = fetch_auth_challenge(app.clone()).await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"challenge": challenge, "signature": "not-valid-hex"}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn auth_token_wrong_signature() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));
    let challenge = fetch_auth_challenge(app.clone()).await;

    // Sign a different message than the issued challenge.
    let sig = state.identity.sign(b"wrong-challenge");
    let sig_hex = hex::encode(sig.to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"challenge": challenge, "signature": sig_hex}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_token_truncated_signature() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));
    let challenge = fetch_auth_challenge(app.clone()).await;

    // A valid hex string but too short for an Ed25519 signature (64 bytes)
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"challenge": challenge, "signature": "aabbccdd"}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn auth_token_empty_signature() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));
    let challenge = fetch_auth_challenge(app.clone()).await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"challenge": challenge, "signature": ""}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn auth_token_missing_signature_field() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn auth_token_unknown_fields_rejected() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));
    let challenge = fetch_auth_challenge(app.clone()).await;
    let sig = state.identity.sign(challenge.as_bytes());
    let sig_hex = hex::encode(sig.to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "challenge": challenge,
                "signature": sig_hex,
                "extra_field": true
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn auth_local_without_connect_info_rejected() {
    // When the client IP is unavailable (no ConnectInfo), the request must
    // be refused and no token issued. As of HARD-8 the per-IP rate-limit
    // middleware fails closed on a missing client IP — it never substitutes
    // a loopback placeholder — so the request is rejected at that layer
    // (500) before it can reach the auth/local handler. Either way, the
    // security-critical invariant holds: a caller with no identifiable
    // address never receives a local-trust token.
    //
    // Uses the raw router (no injected MockConnectInfo) to reproduce the
    // genuinely-missing-ConnectInfo condition.
    let state = test_state();
    let app = konsensus_api::build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/local")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    // Must NOT succeed: no token for an unidentifiable caller.
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "a request with no client IP must never receive a local token"
    );
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    assert!(
        !String::from_utf8_lossy(&body).contains("token"),
        "rejected response must not contain a token"
    );
}

#[tokio::test]
async fn auth_local_rate_limited_after_burst() {
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    let state = test_state();
    let app = build_router(Arc::clone(&state));
    let loopback: SocketAddr = ([127, 0, 0, 1], 54321).into();

    let make_req = || {
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/local")
            .body(Body::empty())
            .unwrap();
        // Inject loopback ConnectInfo so the handler treats this as a local request
        // and reaches the SEC1 rate-limit check (the other /auth/local tests omit
        // ConnectInfo and are rejected 401 before it — so this is the only test that
        // drives the shared "auth_local" bucket, which therefore starts fresh here).
        req.extensions_mut().insert(ConnectInfo(loopback));
        req
    };

    // First 5 within the 60s window succeed.
    for i in 1..=5 {
        let resp = app.clone().oneshot(make_req()).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "local token issuance {i}/5 should succeed"
        );
    }
    // The 6th is throttled (SEC1: 5/min).
    let resp = app.clone().oneshot(make_req()).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the 6th /auth/local mint within a minute must be rate-limited"
    );
}

#[tokio::test]
async fn auth_local_not_mounted_when_sensitive_identity_disabled() {
    let base = test_state();
    let state = Arc::new(AppState {
        sensitive_identity_routes_enabled: false,
        ..(*base).clone()
    });
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/local")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn auth_token_response_has_correct_fields() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));
    let body = signed_auth_body(&state, app.clone()).await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["token"].is_string(), "missing token field");
    assert!(json["expires_at"].is_number(), "missing expires_at field");
    // Token should be non-empty
    assert!(!json["token"].as_str().unwrap().is_empty());
    // Expiry should be in the future
    let exp = json["expires_at"].as_i64().unwrap();
    assert!(exp > 0);
}

#[tokio::test]
async fn auth_token_get_method_not_allowed() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/token")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

// ─── HARD-9 (#238): reveal_mnemonic post-re-auth failures must still audit ────

/// Drive the real `POST /api/v1/identity/mnemonic` endpoint through a genuinely
/// passing re-auth (fresh challenge + node-key signature) and assert the given
/// post-re-auth failure path STILL records a `success:false`
/// `identity.mnemonic_revealed` audit event with the expected reason — and never
/// writes a seed phrase. These are the sensitive cases Codex flagged on #238:
/// the caller has already proven possession of the node key, so the
/// "every reveal attempt is audited" contract must hold on these returns too.
async fn assert_post_reauth_reveal_failure_audited(
    state: Arc<AppState>,
    audit_path: &std::path::Path,
    expected_status: StatusCode,
    expected_reason: &str,
) {
    let token = auth_header(&state);
    let app = build_router(state.clone());
    // Genuine re-auth: fetch a fresh challenge and sign it with the node key.
    let body = signed_auth_body(&state, app.clone()).await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/mnemonic")
        .header("Authorization", token)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        expected_status,
        "reveal failure path should return {expected_status} (reason {expected_reason})"
    );

    let contents = std::fs::read_to_string(audit_path).unwrap();
    assert!(
        contents.contains("mnemonic_revealed"),
        "post-re-auth failure must emit a mnemonic_revealed audit event: {contents}"
    );
    assert!(
        contents.contains(&format!("\"reason\":\"{expected_reason}\"")),
        "audit event must carry reason={expected_reason}: {contents}"
    );
    assert!(
        contents.contains("\"success\":false"),
        "audit event must record success=false: {contents}"
    );
    // The seed is never read on these paths; assert no BIP-39 phrase leaked into
    // the audit log (defence-in-depth against a future detail change).
    assert!(
        !contents.contains("abandon"),
        "audit log must never contain a seed phrase: {contents}"
    );
}

#[tokio::test]
async fn reveal_mnemonic_audits_no_data_dir_failure() {
    let scratch = tempfile::tempdir().unwrap();
    let audit_tmp = tempfile::NamedTempFile::new().unwrap();
    let audit_path = audit_tmp.path().to_path_buf();
    let base = test_state_with_data_dir(scratch.path().to_path_buf());
    let state = Arc::new(AppState {
        audit_log: Arc::new(AuditLog::open(&audit_path).unwrap()),
        data_dir: None,
        backup_dir: None,
        ..(*base).clone()
    });
    assert_post_reauth_reveal_failure_audited(
        state,
        &audit_path,
        StatusCode::INTERNAL_SERVER_ERROR,
        "no_data_dir",
    )
    .await;
}

#[tokio::test]
async fn reveal_mnemonic_audits_encrypted_failure() {
    let data_dir = tempfile::tempdir().unwrap();
    std::fs::write(data_dir.path().join("mnemonic.enc"), b"ciphertext").unwrap();
    let audit_tmp = tempfile::NamedTempFile::new().unwrap();
    let audit_path = audit_tmp.path().to_path_buf();
    let base = test_state_with_data_dir(data_dir.path().to_path_buf());
    let state = Arc::new(AppState {
        audit_log: Arc::new(AuditLog::open(&audit_path).unwrap()),
        ..(*base).clone()
    });
    assert_post_reauth_reveal_failure_audited(
        state,
        &audit_path,
        StatusCode::BAD_REQUEST,
        "mnemonic_encrypted",
    )
    .await;
}

#[tokio::test]
async fn reveal_mnemonic_audits_missing_file_failure() {
    // Empty data dir: neither mnemonic.txt nor mnemonic.enc present.
    let data_dir = tempfile::tempdir().unwrap();
    let audit_tmp = tempfile::NamedTempFile::new().unwrap();
    let audit_path = audit_tmp.path().to_path_buf();
    let base = test_state_with_data_dir(data_dir.path().to_path_buf());
    let state = Arc::new(AppState {
        audit_log: Arc::new(AuditLog::open(&audit_path).unwrap()),
        ..(*base).clone()
    });
    assert_post_reauth_reveal_failure_audited(
        state,
        &audit_path,
        StatusCode::NOT_FOUND,
        "mnemonic_file_missing",
    )
    .await;
}

/// Regression guard for the uniform-401 membrane fix (#332): the AuthUser
/// extractor must return the SAME opaque body — exactly "invalid token" — for
/// EVERY token-failure class. If the body ever again interpolates the error
/// (malformed vs bad-signature vs unsupported-alg vs expired vs bad-claims),
/// this test fails. Class detail stays in tracing/metrics only.
#[tokio::test]
async fn auth_user_rejection_body_is_uniform_across_failure_classes() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use hmac::Mac;

    let state = test_state();
    let secret = state.jwt_secret.clone();

    // Mint a token with arbitrary header/claims JSON and a VALID HMAC-SHA256
    // signature under `sign_secret` — lets us reach every rejection class.
    let mint = |header: &str, claims: &str, sign_secret: &str| -> String {
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let mut mac =
            hmac::Hmac::<sha2::Sha256>::new_from_slice(sign_secret.as_bytes()).unwrap();
        mac.update(h.as_bytes());
        mac.update(b".");
        mac.update(p.as_bytes());
        let s = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{h}.{p}.{s}")
    };

    let good_claims = r#"{"sub":"node1","iat":1000000,"exp":9999999999}"#;
    let cases: Vec<(&str, String)> = vec![
        ("malformed (not a JWT)", "garbage-not-a-jwt".to_string()),
        (
            "bad signature (signed with a different secret)",
            mint(r#"{"alg":"HS256","typ":"JWT"}"#, good_claims, "another-secret-entirely-000000"),
        ),
        (
            "unsupported alg (valid MAC, HS512 header)",
            mint(r#"{"alg":"HS512","typ":"JWT"}"#, good_claims, &secret),
        ),
        (
            "expired (valid MAC, past exp)",
            mint(
                r#"{"alg":"HS256","typ":"JWT"}"#,
                r#"{"sub":"node1","iat":1000000,"exp":1000001}"#,
                &secret,
            ),
        ),
        (
            "invalid claims (valid MAC, exp is a string)",
            mint(
                r#"{"alg":"HS256","typ":"JWT"}"#,
                r#"{"sub":"node1","iat":1000000,"exp":"soon"}"#,
                &secret,
            ),
        ),
    ];

    for (label, token) in cases {
        let app = build_router(Arc::clone(&state));
        let req = Request::builder()
            .uri("/api/v1/status")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{label}: expected 401");
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(
            body, "invalid token",
            "{label}: 401 body must be uniformly \"invalid token\", got {body:?}"
        );
    }
}
