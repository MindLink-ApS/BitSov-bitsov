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
use konsensus_api::build_router;


// ─── Tests ──────────────────────────────────────────────────────────

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
    assert!(json["node_id"].is_string());
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

    let get_mnemonic = Request::builder()
        .uri("/api/v1/identity/mnemonic")
        .header("Authorization", token.clone())
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(get_mnemonic).await.unwrap();
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

    // Sign the challenge "konsensus-auth" with the node's key
    let sig = state.identity.sign(b"konsensus-auth");
    let sig_hex = hex::encode(sig.to_bytes());

    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"signature": sig_hex}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["token"].is_string());
    assert!(json["expires_at"].is_number());
}

#[tokio::test]
async fn auth_rejects_bad_signature() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"signature": "aa".repeat(64)}).to_string(),
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
    let state = test_state();
    let app = build_router(state);

    // Without ConnectInfo (no TCP socket), the endpoint treats the
    // request as non-local and rejects it.
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
async fn health_endpoint_returns_extended_info() {
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

    assert_eq!(json["status"], "ok");
    assert!(json["node_id"].is_string());
    assert_eq!(json["connected_peers"], 0);
    assert!(json["connected_peer_ids"].is_array());
    assert_eq!(json["e2ee_sessions"], 0);
    assert_eq!(json["pending_deliveries"], 0);
    assert_eq!(json["version"], 2);
    assert!(json["uptime_secs"].is_number());
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

    // Not valid hex
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"signature": "zzzz-not-hex"}).to_string(),
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

    // Valid hex but too short for Ed25519 signature (need 64 bytes = 128 hex chars)
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"signature": "aabb"}).to_string(),
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

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
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

#[tokio::test]
async fn get_mnemonic_encrypted_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    // Create an encrypted mnemonic file
    std::fs::write(dir.path().join("mnemonic.enc"), b"encrypted-data").unwrap();

    let state = test_state_with_data_dir(dir.path().to_path_buf());
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/identity/mnemonic")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_mnemonic_missing_returns_not_found() {
    let dir = tempfile::tempdir().unwrap();
    // No mnemonic file exists

    let state = test_state_with_data_dir(dir.path().to_path_buf());
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/identity/mnemonic")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_mnemonic_requires_auth() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("mnemonic.txt"), "test words").unwrap();

    let state = test_state_with_data_dir(dir.path().to_path_buf());
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/identity/mnemonic")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_mnemonic_no_data_dir_returns_error() {
    // test_state() has data_dir: None
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/identity/mnemonic")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
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

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"signature": "not-valid-hex"}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn auth_token_wrong_signature() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));

    // Sign a different message than "konsensus-auth"
    let sig = state.identity.sign(b"wrong-challenge");
    let sig_hex = hex::encode(sig.to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"signature": sig_hex}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_token_truncated_signature() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));

    // A valid hex string but too short for an Ed25519 signature (64 bytes)
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"signature": "aabbccdd"}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn auth_token_empty_signature() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"signature": ""}).to_string(),
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

    let sig = state.identity.sign(b"konsensus-auth");
    let sig_hex = hex::encode(sig.to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
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
    // When ConnectInfo is not available (None), local auth should fail
    let state = test_state();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/local")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Without ConnectInfo (which is None in test without real listener),
    // is_local is false → 401
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_token_response_has_correct_fields() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));

    let sig = state.identity.sign(b"konsensus-auth");
    let sig_hex = hex::encode(sig.to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/token")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"signature": sig_hex}).to_string(),
        ))
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
