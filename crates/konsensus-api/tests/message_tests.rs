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
async fn messages_list_empty() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/messages")
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
async fn nonexistent_message_returns_404() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let fake_id = "aa".repeat(32);
    let req = Request::builder()
        .uri(format!("/api/v1/messages/{fake_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── Compose input validation tests ──────────────────────────────

#[tokio::test]
async fn compose_rejects_empty_plaintext() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": "aa".repeat(32),
                "kind": 1,
                "plaintext": ""
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("empty"));
}

#[tokio::test]
async fn compose_rejects_oversized_plaintext() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    // 1 MiB + 1 byte
    let big = "x".repeat(1024 * 1024 + 1);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": "aa".repeat(32),
                "kind": 1,
                "plaintext": big
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("too large"));
}

#[tokio::test]
async fn compose_rejects_too_many_references() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let refs: Vec<String> = (0..101).map(|i| format!("{:064x}", i)).collect();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": "aa".repeat(32),
                "kind": 1,
                "plaintext": "hello",
                "references": refs
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("references"));
}

#[tokio::test]
async fn compose_rejects_invalid_recipient() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": "not-a-hex-node-id",
                "kind": 1,
                "plaintext": "hello"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("recipient"));
}

#[tokio::test]
async fn compose_fails_without_e2ee_session() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    // Valid Ed25519 key but no E2EE session established
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[77u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": peer_id.to_hex(),
                "kind": 1,
                "plaintext": "hello"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Should fail because no E2EE session exists with this peer
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("E2EE"));
}

#[tokio::test]
async fn get_message_rejects_malformed_hex() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/messages/not-hex-at-all!")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn content_list_pages_disabled() {
    let state = test_state(); // content_dir is None
    let app = build_router(Arc::clone(&state));
    let auth = auth_header(&state);

    let req = Request::builder()
        .uri("/api/v1/content/pages")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 64).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["enabled"], false);
    assert_eq!(json["pages"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn content_list_pages_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/content/pages")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn content_write_and_read_page() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let state = test_state_with_content_dir(tmp_dir.path().to_path_buf());
    let auth = auth_header(&state);

    // Write a page
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/content/pages/hello.md")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(r##"{"content":"# Hello\n\nWorld"}"##))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 64).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["path"], "/hello.md");
    assert_eq!(json["title"], "Hello");

    // Read the page back
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/content/pages/hello.md")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 64).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["path"], "/hello.md");
    assert_eq!(json["content"], "# Hello\n\nWorld");

    // List pages — should have 1
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/content/pages")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 64).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["enabled"], true);
    assert_eq!(json["pages"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn content_delete_page() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let state = test_state_with_content_dir(tmp_dir.path().to_path_buf());
    let auth = auth_header(&state);

    // Create a page
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/content/pages/todelete.md")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(r##"{"content":"# Delete Me"}"##))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Delete it
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/content/pages/todelete.md")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify it's gone
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/content/pages/todelete.md")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn content_path_traversal_rejected() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let state = test_state_with_content_dir(tmp_dir.path().to_path_buf());
    let auth = auth_header(&state);

    // Path traversal attempt
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/content/pages/..%2F..%2Fetc%2Fpasswd")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn content_invalid_extension_rejected() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let state = test_state_with_content_dir(tmp_dir.path().to_path_buf());
    let auth = auth_header(&state);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/content/pages/evil.sh")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(r##"{"content":"#!/bin/bash\nrm -rf /"}"##))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn content_read_nonexistent_404() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let state = test_state_with_content_dir(tmp_dir.path().to_path_buf());
    let auth = auth_header(&state);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/content/pages/nonexistent.md")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_message_returns_stored_envelope() {
    let state = test_state();
    let auth = auth_header(&state);
    let msg_id = store_test_envelope(&state).await;

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(format!("/api/v1/messages/{msg_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], msg_id);
    assert_eq!(json["kind"], 100);
    assert!(json["sender"].is_string());
    assert!(json["timestamp"].is_number());
}

#[tokio::test]
async fn get_message_requires_auth() {
    let state = test_state();
    let msg_id = store_test_envelope(&state).await;

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(format!("/api/v1/messages/{msg_id}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_messages_returns_stored() {
    let state = test_state();
    let auth = auth_header(&state);
    let _msg_id = store_test_envelope(&state).await;

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/messages")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn list_messages_with_limit() {
    let state = test_state();
    let auth = auth_header(&state);
    // Store 2 messages
    let _m1 = store_test_envelope(&state).await;
    let _m2 = store_test_envelope(&state).await;

    // Request with limit=1
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/messages?limit=1")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn list_messages_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/messages")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_message_removes_it() {
    let state = test_state();
    let auth = auth_header(&state);
    let msg_id = store_test_envelope(&state).await;

    // Delete it
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/messages/{msg_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["deleted"], true);

    // Verify it's gone — GET returns 404
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(format!("/api/v1/messages/{msg_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_nonexistent_message_returns_false() {
    let state = test_state();
    let auth = auth_header(&state);
    let fake_id = "bb".repeat(32);

    let app = build_router(state);
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/messages/{fake_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["deleted"], false);
}

#[tokio::test]
async fn delete_message_requires_auth() {
    let state = test_state();
    let msg_id = store_test_envelope(&state).await;

    let app = build_router(state);
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/messages/{msg_id}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Plaintext endpoint ────────────────────────────────────────────

#[tokio::test]
async fn plaintext_without_cipher_returns_error() {
    // Default test state has no plaintext_cipher configured
    let state = test_state();
    let auth = auth_header(&state);
    let msg_id = store_test_envelope(&state).await;

    let app = build_router(state);
    let req = Request::builder()
        .uri(format!("/api/v1/messages/{msg_id}/plaintext"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Should return 500 because plaintext cipher is not configured
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn plaintext_requires_auth() {
    let state = test_state();
    let msg_id = store_test_envelope(&state).await;

    let app = build_router(state);
    let req = Request::builder()
        .uri(format!("/api/v1/messages/{msg_id}/plaintext"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Send message (pre-encrypted ciphertext) ───────────────────────

#[tokio::test]
async fn send_message_stores_and_returns_id() {
    let state = test_state();
    let auth = auth_header(&state);
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[77u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    use sha2::{Digest, Sha256};
    let preimage = [0xCDu8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": peer_id.to_hex(),
                "kind": 100,
                "ciphertext": hex::encode(b"encrypted-data"),
                "payment_hash": hex::encode(hash),
                "preimage": hex::encode(preimage),
                "amount_msat": 10
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["message_id"].is_string());
    // StubTransport.is_connected() returns false, so delivered should be false
    assert_eq!(json["delivered"], false);
}

#[tokio::test]
async fn send_message_rejects_invalid_preimage() {
    let state = test_state();
    let auth = auth_header(&state);
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[77u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": peer_id.to_hex(),
                "kind": 100,
                "ciphertext": hex::encode(b"data"),
                "payment_hash": "aa".repeat(32),
                "preimage": "not-valid-hex!",
                "amount_msat": 10
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn send_message_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": "aa".repeat(32),
                "kind": 100,
                "ciphertext": "ff",
                "payment_hash": "aa".repeat(32),
                "preimage": "bb".repeat(32),
                "amount_msat": 10
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Send message: validation edge cases ──────────────────────────

#[tokio::test]
async fn send_message_rejects_short_payment_hash() {
    let state = test_state();
    let auth = auth_header(&state);
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[77u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": peer_id.to_hex(),
                "kind": 100,
                "ciphertext": hex::encode(b"data"),
                "payment_hash": "aabb",
                "preimage": "cc".repeat(32),
                "amount_msat": 10
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn send_message_rejects_invalid_ciphertext() {
    let state = test_state();
    let auth = auth_header(&state);
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[77u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": peer_id.to_hex(),
                "kind": 100,
                "ciphertext": "not-valid-hex!@#",
                "payment_hash": "aa".repeat(32),
                "preimage": "bb".repeat(32),
                "amount_msat": 10
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn send_message_rejects_invalid_recipient() {
    let state = test_state();
    let auth = auth_header(&state);

    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": "not-hex",
                "kind": 100,
                "ciphertext": "ff",
                "payment_hash": "aa".repeat(32),
                "preimage": "bb".repeat(32),
                "amount_msat": 10
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn send_message_room_recipient() {
    let state = test_state();
    let auth = auth_header(&state);

    use sha2::{Digest, Sha256};
    let preimage = [0xEEu8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();

    let room_id = uuid::Uuid::new_v4();

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": room_id.to_string(),
                "is_room": true,
                "kind": 100,
                "ciphertext": hex::encode(b"room-msg"),
                "payment_hash": hex::encode(hash),
                "preimage": hex::encode(preimage),
                "amount_msat": 10
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["message_id"].is_string());
    // No room members, so not delivered
    assert_eq!(json["delivered"], false);
}

#[tokio::test]
async fn send_message_invalid_room_id() {
    let state = test_state();
    let auth = auth_header(&state);

    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": "not-a-uuid",
                "is_room": true,
                "kind": 100,
                "ciphertext": "ff",
                "payment_hash": "aa".repeat(32),
                "preimage": "bb".repeat(32),
                "amount_msat": 10
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Content: additional edge cases ────────────────────────────────

#[tokio::test]
async fn content_rejects_subdirectory_path() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let state = test_state_with_content_dir(tmp_dir.path().to_path_buf());
    let auth = auth_header(&state);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/content/pages/subdir/page.md")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(r##"{"content":"# Test"}"##))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn content_rejects_oversized_page() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let state = test_state_with_content_dir(tmp_dir.path().to_path_buf());
    let auth = auth_header(&state);

    let big = "x".repeat(4 * 1024 * 1024 + 1);
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/content/pages/big.md")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::json!({ "content": big }).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Axum returns 413 Payload Too Large before the handler runs
    assert!(
        resp.status() == StatusCode::BAD_REQUEST
            || resp.status() == StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn content_write_txt_extension() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let state = test_state_with_content_dir(tmp_dir.path().to_path_buf());
    let auth = auth_header(&state);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/content/pages/notes.txt")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(r##"{"content":"Plain text content"}"##))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["path"], "/notes.txt");

    // Read back
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/content/pages/notes.txt")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["content_type"], "text/plain");
    assert_eq!(json["content"], "Plain text content");
}

#[tokio::test]
async fn content_null_byte_in_path_rejected() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let state = test_state_with_content_dir(tmp_dir.path().to_path_buf());
    let auth = auth_header(&state);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/content/pages/evil%00.md")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn content_backslash_in_path_rejected() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let state = test_state_with_content_dir(tmp_dir.path().to_path_buf());
    let auth = auth_header(&state);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/content/pages/evil%5C.md")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(r##"{"content":"test"}"##))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn content_write_disabled_returns_error() {
    // Default test state has content_dir=None
    let state = test_state();
    let auth = auth_header(&state);

    let app = build_router(state);
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/content/pages/test.md")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(r##"{"content":"# Test"}"##))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn content_delete_nonexistent_returns_404() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let state = test_state_with_content_dir(tmp_dir.path().to_path_buf());
    let auth = auth_header(&state);

    let app = build_router(state);
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/content/pages/ghost.md")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── Content: manifest ────────────────────────────────────────────

#[tokio::test]
async fn content_manifest_with_pages() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let state = test_state_with_content_dir(tmp_dir.path().to_path_buf());
    let auth = auth_header(&state);

    // Create a page first
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/content/pages/index.md")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(r##"{"content":"# Welcome\n\nHello World"}"##))
        .unwrap();
    app.oneshot(req).await.unwrap();

    // Get manifest
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/content/manifest")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["pages"].as_array().unwrap().len() >= 1);
    assert_eq!(json["default_price_msat"], 50);
    assert_eq!(json["block_height"], 850_000);
}

// ─── Message: list limit clamping ─────────────────────────────────

#[tokio::test]
async fn list_messages_clamps_overlarge_limit() {
    let state = test_state();
    let auth = auth_header(&state);

    // Request limit > 1000, should be clamped
    let app = build_router(state);
    let req = Request::builder()
        .uri("/api/v1/messages?limit=5000")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Should succeed — limit is clamped internally, not rejected
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── Message: delete with invalid ID format ───────────────────────

#[tokio::test]
async fn delete_message_rejects_invalid_id() {
    let state = test_state();
    let auth = auth_header(&state);

    let app = build_router(state);
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/messages/not-hex!")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Content: manifest disabled ───────────────────────────────────

#[tokio::test]
async fn content_manifest_disabled_returns_empty() {
    // No content_dir configured — manifest returns OK with empty pages
    let state = test_state();
    let auth = auth_header(&state);

    let app = build_router(state);
    let req = Request::builder()
        .uri("/api/v1/content/manifest")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["pages"].as_array().unwrap().is_empty());
    assert_eq!(json["default_price_msat"], 0);
    assert_eq!(json["block_height"], 850_000);
}

// ─── Content: empty path rejected ─────────────────────────────────

#[tokio::test]
async fn content_empty_path_rejected() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let state = test_state_with_content_dir(tmp_dir.path().to_path_buf());
    let auth = auth_header(&state);

    // The wildcard path /*path requires at least one character
    // An empty path won't match the route, so we test with just "/"
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/content/pages/")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Either BAD_REQUEST or NOT_FOUND depending on routing
    assert!(
        resp.status() == StatusCode::BAD_REQUEST
            || resp.status() == StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn messages_delete_nonexistent_returns_deleted_false() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));
    let fake_id = "ab".repeat(32);

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/messages/{fake_id}"))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["deleted"], false);
}

// ─── Content handler helper tests ──────────────────────────────────

#[tokio::test]
async fn content_write_extracts_h1_title() {
    let state = test_state_with_content_dir(tempfile::tempdir().unwrap().keep());
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/content/pages/test.md")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"content": "# My Title\n\nSome content here."}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["title"], "My Title");
    assert_eq!(json["path"], "/test.md");
}

#[tokio::test]
async fn content_write_no_h1_uses_filename() {
    let state = test_state_with_content_dir(tempfile::tempdir().unwrap().keep());
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/content/pages/untitled.md")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"content": "No heading here, just text."}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["title"], "untitled.md");
}

#[tokio::test]
async fn content_write_and_read_roundtrip() {
    let state = test_state_with_content_dir(tempfile::tempdir().unwrap().keep());
    let auth = auth_header(&state);
    let content = "# Roundtrip Test\n\nContent body.";

    // Write
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/content/pages/roundtrip.md")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"content": content}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Read
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/content/pages/roundtrip.md")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["content"], content);
    assert_eq!(json["title"], "Roundtrip Test");
    assert_eq!(json["content_type"], "text/markdown");
}

#[tokio::test]
async fn content_manifest_includes_written_pages() {
    let state = test_state_with_content_dir(tempfile::tempdir().unwrap().keep());
    let auth = auth_header(&state);

    // Write two pages
    for name in &["alpha.md", "beta.txt"] {
        let app = build_router(Arc::clone(&state));
        let content = if name.ends_with(".md") { "# Alpha\n\nPage A." } else { "Plain text file." };
        let req = Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/content/pages/{name}"))
            .header("authorization", &auth)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"content": content}).to_string(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Manifest
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/content/manifest")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let pages = json["pages"].as_array().unwrap();
    assert!(pages.len() >= 2);
    assert!(pages.iter().any(|p| p["path"] == "/alpha.md"));
    assert!(pages.iter().any(|p| p["path"] == "/beta.txt"));
}

#[tokio::test]
async fn content_rejects_double_dot_path() {
    let state = test_state_with_content_dir(tempfile::tempdir().unwrap().keep());
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/api/v1/content/pages/../../../etc/passwd.md")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn content_page_list_sorted_alphabetically() {
    let state = test_state_with_content_dir(tempfile::tempdir().unwrap().keep());
    let auth = auth_header(&state);

    // Write pages in reverse order
    for name in &["zebra.md", "apple.md", "mango.md"] {
        let app = build_router(Arc::clone(&state));
        let req = Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/content/pages/{name}"))
            .header("authorization", &auth)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"content": format!("# {name}")}).to_string(),
            ))
            .unwrap();
        app.oneshot(req).await.unwrap();
    }

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/content/pages")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let pages = json["pages"].as_array().unwrap();
    let paths: Vec<&str> = pages.iter().filter_map(|p| p["path"].as_str()).collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted);
}

#[tokio::test]
async fn content_delete_nonexistent_returns_404_with_content_dir() {
    let state = test_state_with_content_dir(tempfile::tempdir().unwrap().keep());
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/content/pages/nope.md")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── Message handler edge cases ────────────────────────────────────

#[tokio::test]
async fn send_message_to_room_stores_envelope() {
    let state = test_state();
    let auth = auth_header(&state);

    // Create a room first
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"name": "msg-room"}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let room: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let room_id = room["id"].as_str().unwrap();

    // Send a message to the room
    let preimage = [0xaa_u8; 32];
    use sha2::{Digest, Sha256};
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": room_id,
                "is_room": true,
                "kind": 100,
                "ciphertext": hex::encode([0xbb; 64]),
                "payment_hash": hex::encode(hash),
                "preimage": hex::encode(preimage),
                "amount_msat": 25
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["message_id"].is_string());
}

#[tokio::test]
async fn get_message_plaintext_requires_auth() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri(&format!("/api/v1/messages/{}/plaintext", "aa".repeat(32)))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_messages_with_before_param() {
    let state = test_state();
    let auth = auth_header(&state);

    // Store a message first
    use sha2::{Digest, Sha256};
    let preimage = [0xcc_u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": "bb".repeat(32),
                "kind": 100,
                "ciphertext": hex::encode([0xdd; 32]),
                "payment_hash": hex::encode(hash),
                "preimage": hex::encode(preimage),
                "amount_msat": 10
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // List with before=timestamp in the future
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/messages?before=9999999999999")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── deny_unknown_fields tests ─────────────────────────────────────
//
// API request structs reject unknown fields to prevent typos from being
// silently ignored (e.g., "pliantext" instead of "plaintext").

#[tokio::test]
async fn compose_rejects_unknown_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": "aa".repeat(32),
                "kind": 100,
                "plaintext": "hello",
                "unknown_field": "typo"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown fields in compose request should be rejected"
    );
}

#[tokio::test]
async fn send_message_rejects_oversized_ciphertext() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    // Create a ciphertext hex string just over 1 MiB (exceeds MAX_CIPHERTEXT_HEX_LEN).
    // Each "ab" = 2 hex chars = 1 byte decoded. 512 KiB + 1 byte decoded = 1 MiB + 2 hex chars.
    let huge_hex = "ab".repeat(512 * 1024 + 1);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "kind": 100,
                "recipient": "aa".repeat(32),
                "ciphertext": huge_hex,
                "payment_hash": "cc".repeat(32),
                "preimage": "dd".repeat(32),
                "amount_msat": 10
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "ciphertext over 512 KiB should be rejected"
    );
}

#[tokio::test]
async fn messages_peer_query_invalid_format_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    // Not a valid hex node ID or UUID
    let req = Request::builder()
        .uri("/api/v1/messages?peer=not-a-valid-id")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn messages_peer_query_valid_hex_accepted() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let valid_hex = "aa".repeat(32);
    let req = Request::builder()
        .uri(format!("/api/v1/messages?peer={valid_hex}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── Mnemonic endpoint tests ────────────────────────────────────

#[tokio::test]
async fn get_mnemonic_returns_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    std::fs::write(dir.path().join("mnemonic.txt"), mnemonic).unwrap();

    let state = test_state_with_data_dir(dir.path().to_path_buf());
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/identity/mnemonic")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["mnemonic"].as_str().unwrap(), mnemonic);
}

// ─── Messages: conversation filtering ─────────────────────────────

#[tokio::test]
async fn list_messages_with_peer_filter() {
    let state = test_state();
    let auth = auth_header(&state);

    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[77u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

    use sha2::{Digest, Sha256};
    let preimage = [0xCDu8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();

    // Send a message to peer
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": peer_id.to_hex(),
                "kind": 100,
                "ciphertext": hex::encode(b"convo-data"),
                "payment_hash": hex::encode(hash),
                "preimage": hex::encode(preimage),
                "amount_msat": 10
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // List with peer filter — should return the sent message
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(format!("/api/v1/messages?peer={}", peer_id.to_hex()))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert!(!arr.is_empty(), "conversation should contain the sent message");
}

#[tokio::test]
async fn list_messages_with_invalid_peer_id() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/messages?peer=not-valid-hex")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_messages_with_room_uuid_filter() {
    let state = test_state();
    let auth = auth_header(&state);

    // Create a room first
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"name": "test-convo-room"}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let room_id = json["id"].as_str().unwrap().to_string();

    // Query conversation messages for this room — should return empty
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(format!("/api/v1/messages?peer={room_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn list_messages_with_invalid_room_uuid() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/messages?peer=not-a-valid-uuid-format")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Content Path Length Edge Case ──────────────────────────────────

#[tokio::test]
async fn content_rejects_path_exceeding_max_length() {
    let dir = tempfile::tempdir().unwrap();
    let state = test_state_with_content_dir(dir.path().to_path_buf());
    let auth = auth_header(&state);
    let app = build_router(state);

    // Path of 256 chars (max is 255) + ".md" extension
    let long_name = format!("{}.md", "a".repeat(253));
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/content/pages/{long_name}"))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(r##"{"content":"# Test"}"##))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("too long"));
}

// ─── Happy-Path: Compose via Keysend ───────────────────────────────

#[tokio::test]
async fn compose_happy_path_keysend() {
    // Full pipeline: encrypt → price → keysend → build envelope → sign → store → deliver.
    // This is the primary compose path when the peer's Lightning pubkey is known.
    let invoice_requests = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let peer_id_for_transport;

    // Step 1: Set up E2EE session.
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(
        Arc::new(test_identity()),
    ));
    let peer_id = setup_e2ee_session(&session_manager).await;
    peer_id_for_transport = peer_id;

    // Step 2: Build state with connected transport.
    let transport = Arc::new(ConnectedStubTransport::new(
        vec![peer_id_for_transport],
        Arc::clone(&invoice_requests),
    ));
    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();

    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: transport.clone() as Arc<dyn MessageTransport>,
        session_manager: Arc::clone(&session_manager),
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::clone(&invoice_requests),
        data_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    });

    // Step 3: Register peer's Lightning pubkey (enables keysend path).
    state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(peer_id, "02aaaa".repeat(5));

    // Step 4: Compose a message via the HTTP endpoint.
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": peer_id.to_hex(),
                "kind": 100,
                "plaintext": "Hello via keysend!"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "compose should succeed");

    let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify response fields.
    assert!(json["message_id"].is_string(), "should return message_id");
    assert_eq!(json["delivered"], true, "should be delivered (peer connected)");
    assert!(json["amount_msat"].as_u64().unwrap() > 0, "should have paid");

    // Verify envelope was delivered through transport.
    let sent = transport.sent_envelopes.lock().unwrap();
    assert_eq!(sent.len(), 1, "exactly one envelope should be sent");
    assert_eq!(sent[0].0, peer_id, "sent to correct peer");

    // Verify the envelope has valid structure.
    let envelope = &sent[0].1;
    assert_eq!(envelope.kind, 100, "correct message kind");
    assert_eq!(envelope.sender, *identity.node_id(), "sender is us");
    assert!(!envelope.ciphertext.is_empty(), "ciphertext should not be empty");
    assert!(envelope.payment_proof.amount_msat > 0, "payment proof should have amount");

    // Verify the message was stored.
    let stored = state.storage.get_message(&envelope.id).await.unwrap();
    assert!(stored.is_some(), "message should be stored in database");
}

// ─── Happy-Path: Compose via Invoice-Request Flow ──────────────────

#[tokio::test]
async fn compose_happy_path_invoice_flow() {
    // Full pipeline with invoice-request/response round-trip.
    // This tests the path when no Lightning pubkey is known for the peer.
    let invoice_requests: Arc<tokio::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<konsensus_api::state::InvoiceResponseData>>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(
        Arc::new(test_identity()),
    ));
    let peer_id = setup_e2ee_session(&session_manager).await;

    // Create transport that auto-responds to invoice requests with valid BOLT11.
    let transport = Arc::new(
        ConnectedStubTransport::new(vec![peer_id], Arc::clone(&invoice_requests))
            .with_invoice_responder(move |_request_id, amount_msat| {
                // Respond with a valid BOLT11 invoice for the requested amount.
                // LNbits/LND round up sub-sat amounts, so use max(amount, 1000).
                let invoice_amount = amount_msat.max(1000);
                Some(konsensus_api::state::InvoiceResponseData {
                    bolt11: create_test_bolt11(invoice_amount),
                    payment_hash: "ab".repeat(32),
                })
            }),
    );

    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();

    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: transport.clone() as Arc<dyn MessageTransport>,
        session_manager: Arc::clone(&session_manager),
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::clone(&invoice_requests),
        data_dir: None,
        // No peer_ln_pubkeys → forces invoice-request path instead of keysend.
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    });

    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": peer_id.to_hex(),
                "kind": 100,
                "plaintext": "Hello via invoice flow!"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "compose via invoice should succeed");

    let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["message_id"].is_string());
    assert_eq!(json["delivered"], true);
    assert!(json["amount_msat"].as_u64().unwrap() > 0);

    // Verify envelope was sent.
    let sent = transport.sent_envelopes.lock().unwrap();
    assert_eq!(sent.len(), 1);

    // Verify no pending invoice requests remain (all cleaned up).
    assert!(
        invoice_requests.lock().await.is_empty(),
        "invoice request should be cleaned up after completion"
    );
}

// ─── Invoice Amount Mismatch: Security Check ───────────────────────

#[tokio::test]
async fn compose_rejects_invoice_amount_mismatch() {
    // Security: If a peer responds with an invoice for a different amount
    // than requested, the compose must reject it to prevent overcharging.
    let invoice_requests: Arc<tokio::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<konsensus_api::state::InvoiceResponseData>>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(
        Arc::new(test_identity()),
    ));
    let peer_id = setup_e2ee_session(&session_manager).await;

    // Respond with an invoice for 10x the requested amount (overcharging).
    let transport = Arc::new(
        ConnectedStubTransport::new(vec![peer_id], Arc::clone(&invoice_requests))
            .with_invoice_responder(|_request_id, amount_msat| {
                Some(konsensus_api::state::InvoiceResponseData {
                    bolt11: create_test_bolt11(amount_msat * 10), // 10x overcharge!
                    payment_hash: "ab".repeat(32),
                })
            }),
    );

    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();

    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: transport as Arc<dyn MessageTransport>,
        session_manager: Arc::clone(&session_manager),
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::clone(&invoice_requests),
        data_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    });

    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": peer_id.to_hex(),
                "kind": 100,
                "plaintext": "should fail due to amount mismatch"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // The compose should fail because the invoice amount doesn't match.
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "compose should fail when invoice amount is mismatched"
    );

    let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("does not match") || body_str.contains("overcharging"),
        "error should mention amount mismatch, got: {body_str}"
    );
}

// ─── Keysend Fallback to Invoice ───────────────────────────────────

#[tokio::test]
async fn compose_keysend_fallback_to_invoice() {
    // When keysend fails (peer doesn't support it), the handler should
    // fall back to the invoice-request flow.
    let invoice_requests: Arc<tokio::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<konsensus_api::state::InvoiceResponseData>>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(
        Arc::new(test_identity()),
    ));
    let peer_id = setup_e2ee_session(&session_manager).await;

    // Transport with invoice responder (for fallback).
    let transport = Arc::new(
        ConnectedStubTransport::new(vec![peer_id], Arc::clone(&invoice_requests))
            .with_invoice_responder(|_request_id, amount_msat| {
                let invoice_amount = amount_msat.max(1000);
                Some(konsensus_api::state::InvoiceResponseData {
                    bolt11: create_test_bolt11(invoice_amount),
                    payment_hash: "ab".repeat(32),
                })
            }),
    );

    // Use a Lightning stub that fails keysend.
    struct KeysendFailingLightning;

    #[async_trait]
    impl LightningProvider for KeysendFailingLightning {
        async fn create_invoice(&self, amount_msat: u64, desc: &str, expiry: u32) -> Result<Invoice, LightningError> {
            Ok(Invoice {
                bolt11: "lnbc1stub...".into(),
                payment_hash: "aa".repeat(32),
                amount_msat,
                description: desc.to_string(),
                expiry_secs: expiry,
                created_at: 1_700_000_000,
            })
        }
        async fn pay_invoice(&self, _bolt11: &str) -> Result<PaymentDetails, LightningError> {
            Ok(PaymentDetails {
                payment_hash: "bb".repeat(32),
                preimage: Some("cc".repeat(32)),
                amount_msat: 1000,
                status: PaymentStatus::Settled,
                direction: PaymentDirection::Outgoing,
                timestamp: 1_700_000_000,
                memo: None,
                fee_msat: None,
            })
        }
        async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::PaymentNotFound("not impl".into()))
        }
        async fn get_balance_msat(&self) -> Result<u64, LightningError> {
            Ok(100_000_000)
        }
        async fn list_payments(&self, _: u32) -> Result<Vec<PaymentDetails>, LightningError> {
            Ok(vec![])
        }
        async fn keysend(&self, _dest: &str, _amt: u64, _memo: Option<&str>) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::PaymentFailed("keysend not supported".into()))
        }
        async fn is_available(&self) -> bool {
            true
        }
    }

    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();

    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(KeysendFailingLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: transport.clone() as Arc<dyn MessageTransport>,
        session_manager: Arc::clone(&session_manager),
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::clone(&invoice_requests),
        data_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    });

    // Register peer LN pubkey so keysend is attempted first.
    state.peer_ln_pubkeys.lock().await.insert(peer_id, "02bbbb".repeat(5));

    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": peer_id.to_hex(),
                "kind": 100,
                "plaintext": "Hello via keysend fallback to invoice!"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "compose should succeed via invoice fallback after keysend failure"
    );

    let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["delivered"], true);
}

// ─── Compose Queues Pending Delivery When Transport Fails ──────────

#[tokio::test]
async fn compose_queues_when_transport_send_fails() {
    // When transport.send() fails (peer disconnects mid-compose), the
    // message should be queued for later delivery.
    let invoice_requests = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(
        Arc::new(test_identity()),
    ));
    let peer_id = setup_e2ee_session(&session_manager).await;

    // Transport where peer is "connected" for is_connected check but send fails.
    struct FailingSendTransport {
        connected: std::sync::Mutex<std::collections::HashSet<NodeId>>,
    }

    #[async_trait]
    impl MessageTransport for FailingSendTransport {
        async fn send(&self, _: &NodeId, _: &UkmEnvelope) -> Result<(), TransportError> {
            Err(TransportError::Other("connection lost mid-send".into()))
        }
        async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
            futures::future::pending().await
        }
        async fn connect(&self, _: &NodeId, _: &str) -> Result<(), TransportError> {
            Ok(())
        }
        async fn disconnect(&self, _: &NodeId) -> Result<(), TransportError> {
            Ok(())
        }
        async fn is_connected(&self, peer: &NodeId) -> bool {
            self.connected.lock().unwrap().contains(peer)
        }
        async fn connected_peers(&self) -> Vec<NodeId> {
            self.connected.lock().unwrap().iter().cloned().collect()
        }
    }

    let transport = Arc::new(FailingSendTransport {
        connected: std::sync::Mutex::new([peer_id].into_iter().collect()),
    });

    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();

    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: transport as Arc<dyn MessageTransport>,
        session_manager: Arc::clone(&session_manager),
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::clone(&invoice_requests),
        data_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    });

    // Register LN pubkey for keysend path (simpler than invoice flow).
    state.peer_ln_pubkeys.lock().await.insert(peer_id, "02cccc".repeat(5));

    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": peer_id.to_hex(),
                "kind": 100,
                "plaintext": "Will be queued due to send failure"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "compose should succeed even when delivery fails");

    let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Message should NOT be marked as delivered.
    assert_eq!(json["delivered"], false, "should report not delivered");
    // But it should still have a message_id (was stored).
    assert!(json["message_id"].is_string(), "should still have message_id");
}

// ─── Room Compose: Fan-out to Multiple Members ─────────────────────

#[tokio::test]
async fn compose_room_delivers_to_all_connected_members() {
    // Room compose should encrypt + pay + deliver per member, skip self.
    let invoice_requests = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(
        Arc::new(test_identity()),
    ));

    // Set up E2EE session with peer (Bob).
    let peer_id = setup_e2ee_session(&session_manager).await;

    let transport = Arc::new(ConnectedStubTransport::new(
        vec![peer_id],
        Arc::clone(&invoice_requests),
    ));

    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let storage = Arc::new(MemStorage::new());

    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::clone(&storage) as Arc<dyn Storage>,
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: transport.clone() as Arc<dyn MessageTransport>,
        session_manager: Arc::clone(&session_manager),
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::clone(&invoice_requests),
        data_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    });

    // Register LN pubkey for keysend (avoids invoice flow complexity).
    state.peer_ln_pubkeys.lock().await.insert(peer_id, "02dddd".repeat(5));

    // Create a room with our node + the peer as members.
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"name": "test-room"}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let room_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let room_id = room_json["id"].as_str().unwrap().to_string();

    // Add peer to the room.
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/rooms/{room_id}/members"))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"node_id": peer_id.to_hex()}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Compose a room message.
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": room_id,
                "is_room": true,
                "kind": 100,
                "plaintext": "Hello room!"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "room compose should succeed");

    let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["delivered"], true, "at least one member received it");
    assert!(json["amount_msat"].as_u64().unwrap() > 0, "payment was made");

    // Verify the envelope was sent to the peer (not to self).
    let sent = transport.sent_envelopes.lock().unwrap();
    assert_eq!(sent.len(), 1, "one envelope sent (to peer, not self)");
    assert_eq!(sent[0].0, peer_id, "sent to peer, not to self");
}

// ─── Compose: WS Broadcast Received ────────────────────────────────

#[tokio::test]
async fn compose_broadcasts_to_websocket() {
    // The compose handler should broadcast the message to WebSocket
    // subscribers so the frontend can show the sent message immediately.
    let invoice_requests = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(
        Arc::new(test_identity()),
    ));
    let peer_id = setup_e2ee_session(&session_manager).await;

    let transport = Arc::new(ConnectedStubTransport::new(
        vec![peer_id],
        Arc::clone(&invoice_requests),
    ));
    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let (ws_tx, _ws_rx) = tokio::sync::broadcast::channel::<Arc<konsensus_api::state::WsMessage>>(16);
    let mut ws_subscriber = ws_tx.subscribe();

    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: transport as Arc<dyn MessageTransport>,
        session_manager: Arc::clone(&session_manager),
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: ws_tx,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::clone(&invoice_requests),
        data_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    });

    state.peer_ln_pubkeys.lock().await.insert(peer_id, "02eeee".repeat(5));

    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": peer_id.to_hex(),
                "kind": 100,
                "plaintext": "WS broadcast test"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Check that we received the broadcast.
    let ws_msg = ws_subscriber.try_recv().expect("should receive WS broadcast");
    assert_eq!(
        ws_msg.plaintext.as_deref(),
        Some("WS broadcast test"),
        "broadcast should include plaintext"
    );
    assert_eq!(ws_msg.envelope.kind, 100);
}

// ─── Compose: Send Timestamps Tracked for STDP ─────────────────────

#[tokio::test]
async fn compose_records_send_timestamp_for_stdp() {
    // The compose handler should record send timestamps for STDP
    // (Spike-Timing-Dependent Plasticity) latency measurement.
    let invoice_requests = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(
        Arc::new(test_identity()),
    ));
    let peer_id = setup_e2ee_session(&session_manager).await;

    let transport = Arc::new(ConnectedStubTransport::new(
        vec![peer_id],
        Arc::clone(&invoice_requests),
    ));
    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let send_timestamps = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: transport as Arc<dyn MessageTransport>,
        session_manager: Arc::clone(&session_manager),
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::clone(&send_timestamps),
        invoice_requests: Arc::clone(&invoice_requests),
        data_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    });

    state.peer_ln_pubkeys.lock().await.insert(peer_id, "02ffff".repeat(5));

    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": peer_id.to_hex(),
                "kind": 100,
                "plaintext": "STDP timestamp test"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify send timestamp was recorded.
    let timestamps = send_timestamps.lock().await;
    assert_eq!(timestamps.len(), 1, "one send timestamp should be recorded");
}

// ─── Room Compose: All Members Fail ───────────────────────────────

#[tokio::test]
async fn compose_room_all_members_fail_returns_error() {
    // When no room member has an E2EE session, compose should return 400.
    let invoice_requests = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    // Do NOT set up an E2EE session — encryption will fail for all members.
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(
        Arc::new(test_identity()),
    ));

    let peer_identity = NodeIdentity::from_mnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "",
    )
    .unwrap();
    let peer_id = *peer_identity.node_id();

    let transport = Arc::new(ConnectedStubTransport::new(
        vec![peer_id],
        Arc::clone(&invoice_requests),
    ));

    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let storage = Arc::new(MemStorage::new());

    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::clone(&storage) as Arc<dyn Storage>,
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: transport.clone() as Arc<dyn MessageTransport>,
        session_manager: Arc::clone(&session_manager),
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::clone(&invoice_requests),
        data_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    });

    // Create a room with our node + the peer as members.
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"name": "no-session-room"}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let room_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let room_id = room_json["id"].as_str().unwrap().to_string();

    // Add peer to the room.
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/rooms/{room_id}/members"))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"node_id": peer_id.to_hex()}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Compose a room message — should fail because no E2EE session exists.
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": room_id,
                "is_room": true,
                "kind": 100,
                "plaintext": "This should fail"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "room compose with no E2EE sessions should return 400"
    );

    // Verify no envelopes were sent.
    let sent = transport.sent_envelopes.lock().unwrap();
    assert!(sent.is_empty(), "no envelopes should be sent when all members fail");
}

// ═══════════════════════════════════════════════════════════════════
// Messages handler — validation path tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn messages_get_nonexistent_returns_not_found() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let fake_id = "ab".repeat(32);
    let req = Request::builder()
        .uri(format!("/api/v1/messages/{fake_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn messages_compose_empty_plaintext_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let other = NodeIdentity::from_mnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "",
    )
    .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": other.node_id().to_hex(),
                "plaintext": "",
                "kind": 100
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn messages_compose_oversized_plaintext_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let other = NodeIdentity::from_mnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "",
    )
    .unwrap();

    let big_text = "x".repeat(1_048_577);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": other.node_id().to_hex(),
                "plaintext": big_text,
                "kind": 100
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn messages_compose_invalid_recipient_rejected() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": "not-valid-hex",
                "plaintext": "hello",
                "kind": 100
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn messages_delete_nonexistent_returns_deleted_false_v2() {
    // Delete handler returns 200 with { deleted: false }, not 404
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let fake_id = "cd".repeat(32);
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/messages/{fake_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["deleted"], false);
}

#[tokio::test]
async fn messages_peer_query_returns_empty_list() {
    // Conversation messages use ?peer= query param on the list endpoint
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let other = NodeIdentity::from_mnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "",
    )
    .unwrap();
    let peer_id = other.node_id().to_hex();

    let req = Request::builder()
        .uri(format!("/api/v1/messages?peer={peer_id}"))
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
async fn messages_compose_rejects_unknown_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let other = NodeIdentity::from_mnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "",
    )
    .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": other.node_id().to_hex(),
                "plaintext": "hello",
                "kind": 100,
                "bogus": true
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
