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
async fn files_list_empty() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/files")
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
async fn nonexistent_file_returns_404() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/files/nonexistent-file-id")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── File upload test ──────────────────────────────────────────────

#[tokio::test]
async fn file_upload_success() {
    let state = test_state();
    let auth = auth_header(&state);

    let data = b"hello world";
    let data_b64 = base64::engine::general_purpose::STANDARD.encode(data);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "filename": "hello.txt",
                "mime_type": "text/plain",
                "data_b64": data_b64,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(!result["file_id"].as_str().unwrap().is_empty());
    assert_eq!(result["size_bytes"], data.len() as u64);
    assert!(!result["blake3_hash"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn file_upload_rejects_empty_filename() {
    let state = test_state();
    let auth = auth_header(&state);

    let data_b64 = base64::engine::general_purpose::STANDARD.encode(b"data");

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "filename": "",
                "data_b64": data_b64,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn file_upload_rejects_path_traversal() {
    let state = test_state();
    let auth = auth_header(&state);

    let data_b64 = base64::engine::general_purpose::STANDARD.encode(b"data");

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "filename": "../../../etc/passwd",
                "data_b64": data_b64,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn file_upload_rejects_invalid_base64() {
    let state = test_state();
    let auth = auth_header(&state);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "filename": "test.txt",
                "data_b64": "not-valid-base64!!!",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn file_upload_requires_auth() {
    let state = test_state();
    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "filename": "test.txt",
                "data_b64": "aGVsbG8=",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ═══════════════════════════════════════════════════════════════════
// File send endpoint tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn send_file_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files/test-file-id/send")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"recipient":"aa"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn send_file_not_found() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));
    let recipient = "ff".repeat(32);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files/nonexistent-file-id/send")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(format!(r#"{{"recipient":"{recipient}"}}"#)))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn send_file_invalid_recipient() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    // First store a file so the 404 doesn't fire first
    let file_record = konsensus_storage::FileRecord {
        id: "test-file-1".into(),
        filename: "hello.txt".into(),
        mime_type: "text/plain".into(),
        size_bytes: 5,
        blake3_hash: "aa".repeat(32),
        sender: "00".repeat(32),
        message_id: None,
        data: b"hello".to_vec(),
        created_at: "2026-03-30T00:00:00Z".into(),
    };
    state.storage.store_file(&file_record).await.unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files/test-file-1/send")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"recipient":"not-valid-hex"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn upload_file_rejects_unknown_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "filename": "test.txt",
                "data_b64": base64::engine::general_purpose::STANDARD.encode(b"hello"),
                "bonus_field": 42
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown fields in upload request should be rejected"
    );
}

// ─── Files: delete ────────────────────────────────────────────────

#[tokio::test]
async fn delete_file_success() {
    let state = test_state();
    let auth = auth_header(&state);

    let data_b64 = base64::engine::general_purpose::STANDARD.encode(b"file-data");

    // Upload a file first
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "filename": "to_delete.txt",
                "mime_type": "text/plain",
                "data_b64": data_b64,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let file_id = json["file_id"].as_str().unwrap().to_string();

    // Delete the file
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/files/{file_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["deleted"], true);

    // Verify the file is gone
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(format!("/api/v1/files/{file_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_file_nonexistent_returns_false() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/files/nonexistent-id-1234")
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
async fn delete_file_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/files/some-id")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
