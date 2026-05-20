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


#[tokio::test]
async fn peers_list_empty() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/peers")
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
async fn peers_add_and_remove() {
    let state = test_state();
    let auth = auth_header(&state);

    // Create a valid node ID for the peer
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    // Add peer
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": peer_id.to_hex(),
                "addr": "10.0.0.1:9735",
                "label": "Test peer",
                "auto_connect": true
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["label"], "Test peer");
    assert_eq!(json["auto_connect"], true);

    // List peers — should have 1
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 1);

    // Get specific peer
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(format!("/api/v1/peers/{}", peer_id.to_hex()))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Remove peer
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/peers/{}", peer_id.to_hex()))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // List peers — should be empty again
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn connected_peers_returns_empty() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/peers/connected")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.as_array().unwrap().is_empty());
}

// ─── Peer validation tests ───────────────────────────────────────

#[tokio::test]
async fn add_peer_rejects_invalid_node_id() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": "invalid-hex-node-id",
                "addr": "10.0.0.1:9735"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn peers_export_import() {
    let state = test_state();
    let auth = auth_header(&state);

    // Create two peers
    let peer1_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };
    let peer2_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[43u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    for (peer_id, label) in [(&peer1_id, "Alpha"), (&peer2_id, "Beta")] {
        let app = build_router(Arc::clone(&state));
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/peers")
            .header("authorization", &auth)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "node_id": peer_id.to_hex(),
                    "addr": "10.0.0.1:9735",
                    "label": label,
                    "auto_connect": true,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Export
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/peers/export")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let backup: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(backup["version"], 1);
    assert_eq!(backup["peers"].as_array().unwrap().len(), 2);

    // Remove all peers
    for peer_id in [&peer1_id, &peer2_id] {
        let app = build_router(Arc::clone(&state));
        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/peers/{}", peer_id.to_hex()))
            .header("authorization", &auth)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Verify empty
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(list.as_array().unwrap().is_empty());

    // Import the backup
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers/import")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "backup": backup,
                "skip_existing": false,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["imported"], 2);
    assert_eq!(result["skipped"], 0);
    assert_eq!(result["errors"].as_array().unwrap().len(), 0);

    // Verify peers restored
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn peers_import_skip_existing() {
    let state = test_state();
    let auth = auth_header(&state);

    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    // Add a peer
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": peer_id.to_hex(),
                "addr": "10.0.0.1:9735",
                "label": "Original",
                "auto_connect": true,
            })
            .to_string(),
        ))
        .unwrap();
    app.oneshot(req).await.unwrap();

    // Import with skip_existing=true — peer already exists, should be skipped
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers/import")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "backup": {
                    "version": 1,
                    "exported_at": "2026-03-30T00:00:00Z",
                    "exported_by": "deadbeef",
                    "peers": [{
                        "node_id": peer_id.to_hex(),
                        "addr": "10.0.0.2:9735",
                        "label": "Updated",
                        "auto_connect": false,
                    }]
                },
                "skip_existing": true,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["imported"], 0);
    assert_eq!(result["skipped"], 1);
}

#[tokio::test]
async fn peers_import_rejects_invalid() {
    let state = test_state();
    let auth = auth_header(&state);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers/import")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "backup": {
                    "version": 1,
                    "exported_at": "2026-03-30T00:00:00Z",
                    "exported_by": "deadbeef",
                    "peers": [{
                        "node_id": "invalid_hex",
                        "addr": "10.0.0.1:9735",
                        "label": "Bad",
                        "auto_connect": true,
                    }]
                },
                "skip_existing": false,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["imported"], 0);
    assert_eq!(result["errors"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn session_status_invalid_peer_id() {
    let state = test_state();
    let auth = auth_header(&state);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/sessions/not-valid-hex")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Peer: update and get ──────────────────────────────────────────

#[tokio::test]
async fn peer_update_label() {
    let state = test_state();
    let auth = auth_header(&state);
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[55u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    // Add peer first
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": peer_id.to_hex(),
                "addr": "10.0.0.2:9735",
                "label": "Original"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Update the label
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/peers/{}", peer_id.to_hex()))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "label": "Updated Label"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["label"], "Updated Label");
}

// ─── Peer: get nonexistent ─────────────────────────────────────────

#[tokio::test]
async fn get_nonexistent_peer_returns_404() {
    let state = test_state();
    let auth = auth_header(&state);
    let fake_id = "dd".repeat(32);

    let app = build_router(state);
    let req = Request::builder()
        .uri(format!("/api/v1/peers/{fake_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── Peer: connect to peer ─────────────────────────────────────────

#[tokio::test]
async fn connect_peer_with_stored_peer() {
    let state = test_state();
    let auth = auth_header(&state);
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[88u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    // Add peer with an address
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": peer_id.to_hex(),
                "addr": "10.0.0.3:9735"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Connect — StubTransport always succeeds
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/peers/{}/connect", peer_id.to_hex()))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── Peer: update address ─────────────────────────────────────────

#[tokio::test]
async fn peer_update_address() {
    let state = test_state();
    let auth = auth_header(&state);
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[56u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    // Add peer
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": peer_id.to_hex(),
                "addr": "10.0.0.1:9735",
                "label": "Test"
            })
            .to_string(),
        ))
        .unwrap();
    app.oneshot(req).await.unwrap();

    // Update address only
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/peers/{}", peer_id.to_hex()))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "addr": "10.0.0.2:9736" }).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["addr"], "10.0.0.2:9736");
    // Label should be preserved
    assert_eq!(json["label"], "Test");
}

#[tokio::test]
async fn peer_update_clear_label() {
    let state = test_state();
    let auth = auth_header(&state);
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[57u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    // Add with label
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": peer_id.to_hex(),
                "addr": "10.0.0.1:9735",
                "label": "HasLabel"
            })
            .to_string(),
        ))
        .unwrap();
    app.oneshot(req).await.unwrap();

    // Clear label with empty string
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/peers/{}", peer_id.to_hex()))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "label": "" }).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["label"].is_null());
}

#[tokio::test]
async fn peer_update_auto_connect() {
    let state = test_state();
    let auth = auth_header(&state);
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[58u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    // Add with auto_connect=false (default)
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": peer_id.to_hex(),
                "addr": "10.0.0.1:9735"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["auto_connect"], false);

    // Enable auto_connect
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/peers/{}", peer_id.to_hex()))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "auto_connect": true }).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["auto_connect"], true);
}

#[tokio::test]
async fn peer_update_nonexistent_returns_404() {
    let state = test_state();
    let auth = auth_header(&state);
    let fake_id = "ee".repeat(32);

    let app = build_router(state);
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/peers/{fake_id}"))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "label": "no one" }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn peer_update_invalid_address() {
    let state = test_state();
    let auth = auth_header(&state);
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[59u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    // Add peer
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": peer_id.to_hex(),
                "addr": "10.0.0.1:9735"
            })
            .to_string(),
        ))
        .unwrap();
    app.oneshot(req).await.unwrap();

    // Update with invalid address
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/peers/{}", peer_id.to_hex()))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "addr": "not-an-address" }).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Peer: connect to nonexistent ─────────────────────────────────

#[tokio::test]
async fn connect_nonexistent_peer_returns_404() {
    let state = test_state();
    let auth = auth_header(&state);
    let fake_id = "ff".repeat(32);

    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/peers/{fake_id}/connect"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── Peer: import self is skipped ─────────────────────────────────

#[tokio::test]
async fn peer_import_skips_self() {
    let state = test_state();
    let auth = auth_header(&state);
    let self_id = state.identity.node_id().to_hex();

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers/import")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "backup": {
                    "version": 1,
                    "exported_at": "2026-03-30T00:00:00Z",
                    "exported_by": "other-node",
                    "peers": [{
                        "node_id": self_id,
                        "addr": "127.0.0.1:9735",
                        "label": "Me",
                        "auto_connect": false,
                    }]
                },
                "skip_existing": false,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["imported"], 0);
    assert_eq!(result["skipped"], 1);
}

#[tokio::test]
async fn peer_import_invalid_address() {
    let state = test_state();
    let auth = auth_header(&state);
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[60u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers/import")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "backup": {
                    "version": 1,
                    "exported_at": "2026-03-30T00:00:00Z",
                    "exported_by": "other",
                    "peers": [{
                        "node_id": peer_id.to_hex(),
                        "addr": "not-a-socket-addr",
                        "label": "Bad",
                        "auto_connect": false,
                    }]
                },
                "skip_existing": false,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["imported"], 0);
    assert_eq!(result["errors"].as_array().unwrap().len(), 1);
}

// ─── Peer: add with no label ──────────────────────────────────────

#[tokio::test]
async fn peer_add_without_label() {
    let state = test_state();
    let auth = auth_header(&state);
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[61u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": peer_id.to_hex(),
                "addr": "10.0.0.5:9735"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["label"].is_null());
    assert_eq!(json["auto_connect"], false);
    // Should have fingerprint and safety_number
    assert!(json["fingerprint"].is_string());
    assert!(json["safety_number"].is_string());
}

// ─── Peer: remove nonexistent ─────────────────────────────────────

#[tokio::test]
async fn remove_nonexistent_peer_returns_404() {
    let state = test_state();
    let auth = auth_header(&state);
    let fake_id = "ab".repeat(32);

    let app = build_router(state);
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/peers/{fake_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── Peer: requires auth for all operations ───────────────────────

#[tokio::test]
async fn peers_list_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/peers")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn peers_add_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": "aa".repeat(32),
                "addr": "10.0.0.1:9735"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn peers_export_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/peers/export")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn peers_import_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers/import")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "backup": {
                    "version": 1,
                    "exported_at": "2026-01-01T00:00:00Z",
                    "exported_by": "aa",
                    "peers": []
                },
                "skip_existing": false
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Peer: add with invalid address ───────────────────────────────

#[tokio::test]
async fn add_peer_rejects_invalid_address() {
    let state = test_state();
    let auth = auth_header(&state);
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[62u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": peer_id.to_hex(),
                "addr": "not-a-socket-addr"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Peer: export empty registry ──────────────────────────────────

#[tokio::test]
async fn export_empty_peers() {
    let state = test_state();
    let auth = auth_header(&state);

    let app = build_router(state);
    let req = Request::builder()
        .uri("/api/v1/peers/export")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["version"], 1);
    assert!(json["exported_at"].is_string());
    assert!(json["exported_by"].is_string());
    assert!(json["peers"].as_array().unwrap().is_empty());
}

// ─── Peer: connect requires auth ──────────────────────────────────

#[tokio::test]
async fn connect_peer_requires_auth() {
    let state = test_state();
    let fake_id = "aa".repeat(32);

    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/peers/{fake_id}/connect"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_status_bad_hex_peer_id() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/api/v1/sessions/not-valid-hex")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn session_status_nonexistent_peer() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));
    let peer_id = "bb".repeat(32);

    let req = Request::builder()
        .uri(format!("/api/v1/sessions/{peer_id}"))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["active"], false);
}

#[tokio::test]
async fn session_initiate_invalid_peer_id() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sessions/not-hex/initiate")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"peer_bundle":{}}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // 422 from JSON deserialization failure or 400 from bad peer ID
    assert!(
        resp.status() == StatusCode::UNPROCESSABLE_ENTITY
            || resp.status() == StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn session_accept_invalid_peer_id() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sessions/zzzz/accept")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"init_data":{}}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // 422 from JSON deserialization failure or 400 from bad peer ID
    assert!(
        resp.status() == StatusCode::UNPROCESSABLE_ENTITY
            || resp.status() == StatusCode::BAD_REQUEST
    );
}

// ═══════════════════════════════════════════════════════════════════
// Peer discover endpoint tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn discover_peers_requires_auth() {
    let state = test_state();
    let app = build_router(state);
    let peer_id = "ee".repeat(32);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/peers/{peer_id}/discover"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn discover_peers_invalid_node_id() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers/not-a-valid-id/discover")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Peer handler edge cases ───────────────────────────────────────

#[tokio::test]
async fn peer_add_with_auto_connect_flag() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": "cc".repeat(32),
                "addr": "10.0.0.1:9735",
                "label": "auto-peer",
                "auto_connect": true
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["auto_connect"], true);
    assert_eq!(json["label"], "auto-peer");
    assert_eq!(json["connected"], false);
    assert!(json["fingerprint"].is_string());
    assert!(json["safety_number"].is_string());
}

#[tokio::test]
async fn peer_update_multiple_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let peer_id = "dd".repeat(32);

    // Add peer first
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": peer_id,
                "addr": "10.0.0.1:9735"
            })
            .to_string(),
        ))
        .unwrap();
    app.oneshot(req).await.unwrap();

    // Update label, addr, and auto_connect simultaneously
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/peers/{peer_id}"))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "addr": "10.0.0.2:9736",
                "label": "new-label",
                "auto_connect": true
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["addr"], "10.0.0.2:9736");
    assert_eq!(json["label"], "new-label");
    assert_eq!(json["auto_connect"], true);
}

#[tokio::test]
async fn peer_update_requires_auth() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/peers/{}", "aa".repeat(32)))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"label": "test"}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn peer_get_requires_auth() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri(format!("/api/v1/peers/{}", "aa".repeat(32)))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn peer_delete_requires_auth() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/peers/{}", "aa".repeat(32)))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn peer_connect_requires_auth() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/peers/{}/connect", "aa".repeat(32)))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_payment_proof_offline_peer_returns_error() {
    // Non-zero price with offline peer should return an error (not a fake proof).
    let state = test_state();
    let peer_id = NodeId::from_hex(&"cc".repeat(32)).unwrap();

    let result = konsensus_api::handlers::messages::create_payment_proof(&state, 25_000, &peer_id).await;
    assert!(result.is_err(), "offline peer should fail");
    let err = result.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("offline") || err_str.contains("unavailable"),
        "error should mention offline/unavailable, got: {err_str}"
    );
}

#[tokio::test]
async fn add_peer_rejects_unknown_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": "bb".repeat(32),
                "addr": "127.0.0.1:9000",
                "extra": "rejected"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown fields in add peer request should be rejected"
    );
}

// ─── peer label length validation ───────────────────────────────────

#[tokio::test]
async fn add_peer_rejects_oversized_label() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let long_label = "x".repeat(257);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": "cc".repeat(32),
                "addr": "127.0.0.1:9000",
                "label": long_label,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "peer label over 256 bytes should be rejected"
    );
}

#[tokio::test]
async fn add_peer_accepts_max_length_label() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let max_label = "x".repeat(256);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": "cc".repeat(32),
                "addr": "127.0.0.1:9000",
                "label": max_label,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "peer label at exactly 256 bytes should be accepted"
    );
}

#[tokio::test]
async fn import_peers_rejects_oversized_label() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let long_label = "x".repeat(257);
    let node_id = "dd".repeat(32);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers/import")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "backup": {
                    "version": 1,
                    "exported_at": "2026-03-31T00:00:00Z",
                    "exported_by": node_id,
                    "peers": [{
                        "node_id": node_id,
                        "addr": "127.0.0.1:9000",
                        "label": long_label,
                        "auto_connect": false
                    }]
                },
                "skip_existing": false
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["imported"], 0, "peer with oversized label should not be imported");
    assert_eq!(json["errors"].as_array().unwrap().len(), 1, "should have 1 error");
}

#[tokio::test]
async fn peer_import_too_many_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    // Build a backup with 1001 entries
    let peers: Vec<serde_json::Value> = (0..1001)
        .map(|i| {
            serde_json::json!({
                "node_id": format!("{:064x}", i + 1),
                "addr": format!("10.0.0.{}:9735", i % 256),
                "auto_connect": false,
            })
        })
        .collect();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers/import")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "backup": {
                    "version": 1,
                    "exported_by": "test",
                    "exported_at": "2026-01-01T00:00:00Z",
                    "peers": peers
                }
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Invite Tests ───────────────────────────────────────────────────

#[tokio::test]
async fn invite_generate_returns_token_and_uri() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invite")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({
                "addr": "10.0.0.1:9735",
                "label": "Alice",
                "expiry_secs": 3600
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["token"].is_string());
    let uri = json["uri"].as_str().unwrap();
    assert!(uri.starts_with("konsensus://invite/"));
    assert!(json["expiry"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn invite_generate_no_expiry() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invite")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({ "addr": "10.0.0.1:9735" }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["expiry"].as_u64().unwrap(), 0);
}

#[tokio::test]
async fn invite_generate_empty_addr_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invite")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({ "addr": "" }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invite_generate_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invite")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "addr": "10.0.0.1:9735" }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invite_redeem_adds_peer() {
    let state = test_state();
    let auth = auth_header(&state);

    // Generate an invite from a different identity
    let other = konsensus_core::NodeIdentity::from_mnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "",
    )
    .unwrap();
    let token = konsensus_core::InviteToken::generate(
        &other,
        "10.0.0.2:9735",
        Some("Bob"),
        0,
    )
    .unwrap();

    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invite/redeem")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({ "invite": token }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["addr"], "10.0.0.2:9735");
    assert_eq!(json["label"], "Bob");
    assert!(json["added"].as_bool().unwrap());
    assert!(json["fingerprint"].is_string());

    // Verify peer is in registry
    let registry = state.peer_registry.read().await;
    let peer = registry
        .get(other.node_id())
        .expect("peer should be in registry");
    assert_eq!(peer.label.as_deref(), Some("Bob"));
}

#[tokio::test]
async fn invite_redeem_uri_format() {
    let state = test_state();
    let auth = auth_header(&state);

    let other = konsensus_core::NodeIdentity::from_mnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "",
    )
    .unwrap();
    let uri = konsensus_core::InviteToken::generate_uri(
        &other,
        "10.0.0.2:9735",
        None,
        0,
    )
    .unwrap();

    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invite/redeem")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({ "invite": uri }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["added"].as_bool().unwrap());
}

#[tokio::test]
async fn invite_redeem_duplicate_returns_not_added() {
    let state = test_state();
    let auth = auth_header(&state);

    let other = konsensus_core::NodeIdentity::from_mnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "",
    )
    .unwrap();
    let token = konsensus_core::InviteToken::generate(
        &other,
        "10.0.0.2:9735",
        None,
        0,
    )
    .unwrap();

    // First redeem
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invite/redeem")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({ "invite": &token }).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Second redeem — same invite
    let app2 = build_router(Arc::clone(&state));
    let req2 = Request::builder()
        .method("POST")
        .uri("/api/v1/invite/redeem")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({ "invite": &token }).to_string(),
        ))
        .unwrap();
    let resp2 = app2.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp2.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(!json["added"].as_bool().unwrap());
}

#[tokio::test]
async fn invite_redeem_self_rejected() {
    let state = test_state();
    let auth = auth_header(&state);

    // Generate invite from the SAME identity as the test state
    let token = konsensus_core::InviteToken::generate(
        &state.identity,
        "10.0.0.1:9735",
        None,
        0,
    )
    .unwrap();

    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invite/redeem")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({ "invite": token }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invite_redeem_invalid_token_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invite/redeem")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({ "invite": "not-a-valid-token" }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invite_roundtrip_generate_then_redeem() {
    let state = test_state();
    let auth = auth_header(&state);

    // Generate invite
    let app1 = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invite")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({
                "addr": "10.0.0.1:9735",
                "label": "TestNode"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app1.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let gen_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = gen_json["token"].as_str().unwrap().to_string();

    // Redeem from a different node's perspective —
    // this is a self-invite so it should be rejected
    let app2 = build_router(Arc::clone(&state));
    let req2 = Request::builder()
        .method("POST")
        .uri("/api/v1/invite/redeem")
        .header("content-type", "application/json")
        .header("authorization", &auth)
        .body(Body::from(
            serde_json::json!({ "invite": token }).to_string(),
        ))
        .unwrap();

    let resp2 = app2.oneshot(req2).await.unwrap();
    // Self-invite gets rejected
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
}

// ─── Routing Endpoint Tests ────────────────────────────────────────

#[tokio::test]
async fn routing_returns_empty_table() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/routing")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total_peers"], 0);
    assert_eq!(json["active_peers"], 0);
    assert!(json["peers"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn routing_returns_peer_scores_after_success() {
    let state = test_state();
    let auth = auth_header(&state);

    // Record a successful delivery to populate the routing table.
    let peer = konsensus_core::types::NodeId::from_bytes([1u8; 32]);
    state.routing.record_success(&peer, 42.0, 5000).await;

    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/routing")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total_peers"], 1);
    assert_eq!(json["active_peers"], 1);

    let peers = json["peers"].as_array().unwrap();
    assert_eq!(peers.len(), 1);

    let p = &peers[0];
    assert_eq!(p["node_id"], peer.to_hex());
    assert!(p["score"].as_f64().unwrap() > 0.0);
    assert!(p["weight"].as_f64().unwrap() > 0.0);
    assert!(p["latency_ema_ms"].as_f64().unwrap() > 0.0);
    assert!(p["success_rate"].as_f64().unwrap() > 0.0);
    assert_eq!(p["payment_volume_msat"], 5000);
    assert_eq!(p["pruned"], false);
    assert_eq!(p["suggest_direct"], false);
}

#[tokio::test]
async fn routing_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/routing")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn routing_multiple_peers_sorted() {
    let state = test_state();
    let auth = auth_header(&state);

    let peer_a = konsensus_core::types::NodeId::from_bytes([2u8; 32]);
    let peer_b = konsensus_core::types::NodeId::from_bytes([3u8; 32]);
    state.routing.record_success(&peer_a, 100.0, 1000).await;
    state.routing.record_success(&peer_b, 20.0, 2000).await;

    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/routing")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total_peers"], 2);
    assert_eq!(json["active_peers"], 2);
    assert_eq!(json["peers"].as_array().unwrap().len(), 2);
}

// ─── Routing After Multiple Record/Failure Cycles ──────────────────

#[tokio::test]
async fn routing_reflects_failure_rate() {
    let state = test_state();
    let auth = auth_header(&state);

    let peer = konsensus_core::types::NodeId::from_bytes([4u8; 32]);
    // Record 3 successes and 2 failures.
    state.routing.record_success(&peer, 50.0, 100).await;
    state.routing.record_success(&peer, 60.0, 200).await;
    state.routing.record_success(&peer, 70.0, 300).await;
    state.routing.record_failure(&peer).await;
    state.routing.record_failure(&peer).await;

    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/routing")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let peers = json["peers"].as_array().unwrap();
    assert_eq!(peers.len(), 1);
    let p = &peers[0];
    // Success rate should be less than 1.0 due to failures.
    assert!(p["success_rate"].as_f64().unwrap() < 1.0);
    // Payment volume should be sum of successes.
    assert_eq!(p["payment_volume_msat"], 600);
}

#[tokio::test]
async fn gossip_status_returns_metrics() {
    let state = test_state_with_gossip();
    let app = build_router(state.clone());
    let auth = auth_header(&state);

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/gossip/status")
                .header("authorization", &auth)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 10_000).await.unwrap(),
    ).unwrap();
    assert_eq!(body["dedup_entries"], 0);
    assert_eq!(body["tracked_senders"], 0);
    assert_eq!(body["max_per_sender_per_hour"], 60);
    assert_eq!(body["dedup_ttl_secs"], 7200);
    assert_eq!(body["max_age_secs"], 3600);
}

#[tokio::test]
async fn gossip_status_requires_auth() {
    let state = test_state_with_gossip();
    let app = build_router(state);

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/gossip/status")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn gossip_publish_web_manifest_rejected_until_paid_broadcast_lands() {
    let state = test_state_with_gossip();
    let app = build_router(state.clone());
    let auth = auth_header(&state);

    let body = serde_json::json!({
        "kind": 510,
        "payload": "{\"site_name\":\"test\",\"paths\":[\"/\"]}"
    });

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/gossip/publish")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn gossip_publish_rejects_disallowed_kind() {
    let state = test_state_with_gossip();
    let app = build_router(state.clone());
    let auth = auth_header(&state);

    let body = serde_json::json!({
        "kind": 100,  // KIND_CHAT — not allowed for gossip
        "payload": "hello"
    });

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/gossip/publish")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn gossip_publish_rejects_empty_payload() {
    let state = test_state_with_gossip();
    let app = build_router(state.clone());
    let auth = auth_header(&state);

    let body = serde_json::json!({
        "kind": 510,
        "payload": ""
    });

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/gossip/publish")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn gossip_publish_rejects_oversized_payload() {
    let state = test_state_with_gossip();
    let app = build_router(state.clone());
    let auth = auth_header(&state);

    // Create a payload larger than 64KB
    let big_payload = "x".repeat(65_537);
    let body = serde_json::json!({
        "kind": 510,
        "payload": big_payload
    });

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/gossip/publish")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn gossip_publish_requires_auth() {
    let state = test_state_with_gossip();
    let app = build_router(state);

    let body = serde_json::json!({
        "kind": 510,
        "payload": "hello"
    });

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/gossip/publish")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn gossip_status_without_validator_returns_error() {
    // Use regular test_state which has gossip_validator: None
    let state = test_state();
    let app = build_router(state.clone());
    let auth = auth_header(&state);

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/gossip/status")
                .header("authorization", &auth)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ═══════════════════════════════════════════════════════════════════
// Invite handler — input validation boundary tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn invite_generate_rejects_overlong_addr() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let long_addr = "a".repeat(256);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invite")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "addr": long_addr }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invite_generate_rejects_overlong_label() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let long_label = "b".repeat(256);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invite")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "addr": "10.0.0.1:9735", "label": long_label }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invite_generate_rejects_unknown_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invite")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "addr": "10.0.0.1:9735",
                "bogus_field": true
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn invite_redeem_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invite/redeem")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "invite": "test" }).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ═══════════════════════════════════════════════════════════════════
// Peers handler — add/remove/connect validation tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn peers_add_invalid_node_id_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": "not-a-hex-key",
                "addr": "10.0.0.2:9735"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn peers_add_self_succeeds() {
    // The peer handler does not reject self-adds — registry allows it
    let state = test_state();
    let auth = auth_header(&state);
    let self_id = state.identity.node_id().to_hex();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": self_id,
                "addr": "10.0.0.1:9735"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn peers_add_overlong_label_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let other = NodeIdentity::from_mnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "",
    )
    .unwrap();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": other.node_id().to_hex(),
                "addr": "10.0.0.2:9735",
                "label": "x".repeat(257)
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn peers_add_and_verify_fields() {
    let state = test_state();
    let auth = auth_header(&state);

    let other = NodeIdentity::from_mnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "",
    )
    .unwrap();
    let peer_id = other.node_id().to_hex();

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": peer_id,
                "addr": "10.0.0.2:9735",
                "label": "test-peer"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["node_id"], peer_id);
    assert_eq!(json["label"], "test-peer");
    assert_eq!(json["connected"], false);
    assert!(json["fingerprint"].is_string());
    assert!(json["safety_number"].is_string());
}

#[tokio::test]
async fn peers_remove_and_verify_empty() {
    let state = test_state();
    let auth = auth_header(&state);

    let other = NodeIdentity::from_mnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "",
    )
    .unwrap();
    let peer_id = other.node_id().to_hex();

    // Add
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": peer_id,
                "addr": "10.0.0.2:9735"
            })
            .to_string(),
        ))
        .unwrap();
    app.oneshot(req).await.unwrap();

    // Remove
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/peers/{peer_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify list is empty
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn peers_connect_unknown_returns_not_found() {
    let state = test_state();
    let auth = auth_header(&state);
    let fake_id = "ab".repeat(32);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/peers/{fake_id}/connect"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn peers_connect_known_peer_succeeds() {
    let state = test_state();
    let auth = auth_header(&state);

    let other = NodeIdentity::from_mnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "",
    )
    .unwrap();
    let peer_id = other.node_id().to_hex();

    // Add peer
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/peers")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "node_id": peer_id,
                "addr": "10.0.0.2:9735"
            })
            .to_string(),
        ))
        .unwrap();
    app.oneshot(req).await.unwrap();

    // Connect
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/peers/{peer_id}/connect"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
