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


#[tokio::test]
async fn rooms_crud() {
    let state = test_state();
    let auth = auth_header(&state);

    // Create room
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
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let room_id = json["id"].as_str().unwrap().to_string();
    assert_eq!(json["name"], "test-room");

    // Get room
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(format!("/api/v1/rooms/{room_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // List rooms
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/rooms")
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
async fn nonexistent_room_returns_404() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let fake_id = uuid::Uuid::new_v4();
    let req = Request::builder()
        .uri(format!("/api/v1/rooms/{fake_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn room_members_add_and_list() {
    let state = test_state();
    let auth = auth_header(&state);

    // Create room
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"name": "group-room"}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let room_id = json["id"].as_str().unwrap().to_string();

    // Add a member
    let peer_id = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    };

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

    // List members
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(format!("/api/v1/rooms/{room_id}/members"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 1);
    assert_eq!(json[0], peer_id.to_hex());
}

// ─── Room validation tests ───────────────────────────────────────

#[tokio::test]
async fn create_room_rejects_empty_name() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"name": ""}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_room_rejects_whitespace_only_name() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"name": "   \t  "}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_room_rejects_null_byte_name() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"name": "test\x00room"}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_room_rejects_oversized_name() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let long_name = "a".repeat(257);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"name": long_name}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Room ID / message ID format tests ───────────────────────────

#[tokio::test]
async fn get_room_rejects_malformed_uuid() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/rooms/not-a-uuid")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Delete room test ──────────────────────────────────────────────

#[tokio::test]
async fn delete_room() {
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
            serde_json::json!({ "name": "test-room" }).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let room: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let room_id = room["id"].as_str().unwrap();

    // Delete the room
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("DELETE")
        .uri(&format!("/api/v1/rooms/{room_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["deleted"], true);

    // Verify room is gone
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(&format!("/api/v1/rooms/{room_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_room_requires_auth() {
    let state = test_state();
    let app = build_router(state);
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/rooms/00000000-0000-0000-0000-000000000001")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Room member removal test ──────────────────────────────────────

#[tokio::test]
async fn room_member_remove() {
    let state = test_state();
    let auth = auth_header(&state);

    // Create a room
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "name": "member-test" }).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let room: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let room_id = room["id"].as_str().unwrap().to_string();

    // Add a member
    let member_hex = "bb".repeat(32);
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri(&format!("/api/v1/rooms/{room_id}/members"))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "node_id": &member_hex }).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Remove the member
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("DELETE")
        .uri(&format!("/api/v1/rooms/{room_id}/members/{member_hex}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["removed"], true);

    // Verify member list is empty
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(&format!("/api/v1/rooms/{room_id}/members"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let members: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(members.is_empty());
}

// ─── Room: delete nonexistent ──────────────────────────────────────

#[tokio::test]
async fn delete_nonexistent_room_returns_404() {
    let state = test_state();
    let auth = auth_header(&state);
    let fake_id = uuid::Uuid::new_v4();
    let app = build_router(state);

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/rooms/{fake_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── Room: add member to nonexistent room ──────────────────────────

#[tokio::test]
async fn add_member_to_nonexistent_room_succeeds() {
    // MemStorage doesn't validate room existence — the add_room_member
    // trait method simply stores the mapping. This is by design: the
    // storage layer is append-only and doesn't enforce referential integrity.
    let state = test_state();
    let auth = auth_header(&state);
    let fake_room = uuid::Uuid::new_v4();
    let member = "cc".repeat(32);

    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/rooms/{fake_room}/members"))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"node_id": member}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── Room: add member with invalid node ID ─────────────────────────

#[tokio::test]
async fn add_member_rejects_invalid_node_id() {
    let state = test_state();
    let auth = auth_header(&state);

    // Create room first
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"name": "test-room-member"}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let room: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let room_id = room["id"].as_str().unwrap();

    // Try adding member with invalid node ID
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/rooms/{room_id}/members"))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"node_id": "not-valid-hex"}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Room: members requires auth ───────────────────────────────────

#[tokio::test]
async fn room_members_requires_auth() {
    let state = test_state();
    let fake_room = uuid::Uuid::new_v4();
    let app = build_router(state);

    let req = Request::builder()
        .uri(format!("/api/v1/rooms/{fake_room}/members"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rooms_get_nonexistent_returns_not_found() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));
    let fake_room = uuid::Uuid::new_v4();

    let req = Request::builder()
        .uri(format!("/api/v1/rooms/{fake_room}"))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── Room handler edge cases ───────────────────────────────────────

#[tokio::test]
async fn create_room_with_metadata() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": "test-room",
                "metadata": {"purpose": "testing", "priority": 1}
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["name"], "test-room");
    assert_eq!(json["metadata"]["purpose"], "testing");
    assert_eq!(json["metadata"]["priority"], 1);
}

#[tokio::test]
async fn create_room_trims_whitespace_name() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"name": "  trimmed  "}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["name"], "trimmed");
}

#[tokio::test]
async fn room_full_lifecycle() {
    let state = test_state();
    let auth = auth_header(&state);

    // 1. Create room
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"name": "lifecycle-room"}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let create_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let room_id = create_json["id"].as_str().unwrap().to_string();

    // 2. Get room by ID
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(format!("/api/v1/rooms/{room_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. List rooms — should contain our room
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(list.as_array().unwrap().iter().any(|r| r["name"] == "lifecycle-room"));

    // 4. Add a member
    let peer_id = "aa".repeat(32);
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/rooms/{room_id}/members"))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"node_id": peer_id}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. List members — should have 1 member
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(format!("/api/v1/rooms/{room_id}/members"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let members: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(members.as_array().unwrap().len(), 1);

    // 6. Remove member
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/rooms/{room_id}/members/{peer_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 7. Delete room
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/rooms/{room_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 8. Get deleted room — should 404
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(format!("/api/v1/rooms/{room_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn room_delete_requires_auth() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));
    let room_id = uuid::Uuid::new_v4();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/rooms/{room_id}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn room_add_member_requires_auth() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));
    let room_id = uuid::Uuid::new_v4();

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/rooms/{room_id}/members"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"node_id": "aa".repeat(32)}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn room_add_member_rejects_invalid_node_id() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));
    let room_id = uuid::Uuid::new_v4();

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/rooms/{room_id}/members"))
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"node_id": "not-hex"}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn room_remove_member_requires_auth() {
    let state = test_state();
    let app = build_router(Arc::clone(&state));
    let room_id = uuid::Uuid::new_v4();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/rooms/{room_id}/members/{}", "aa".repeat(32)))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_room_rejects_unknown_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": "test-room",
                "typo_field": true
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown fields in create room request should be rejected"
    );
}

// ─── input validation hardening tests ────────────────────────────────

#[tokio::test]
async fn room_metadata_rejects_oversized_json() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    // 64 KiB + 1 byte of metadata should be rejected
    let big_value = "x".repeat(65 * 1024);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": "test-room",
                "metadata": {"big": big_value},
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "room metadata over 64 KiB should be rejected"
    );
}

#[tokio::test]
async fn room_metadata_accepts_small_json() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rooms")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": "test-room",
                "metadata": {"key": "value", "count": 42},
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "small room metadata should be accepted"
    );
}

// ─── Room fan-out routes pricing through the single discounted choke point ──
//
// Regression guard for the HARD-13 single-choke-point money path as applied to
// the HARD-12 bounded room fan-out. Each room member must be charged its
// *single* trust-discounted price — never the undiscounted base (no-discount
// drift) and never the discount applied twice (double-discount drift).
//
// We drive a real room compose end-to-end through the HTTP handler. The stub
// Lightning keysend echoes back exactly the amount it is asked to pay, so the
// `amount_msat` the handler reports — and the per-member `payment_proof` amounts
// on the delivered envelopes — equal the prices the fan-out computed. We pick
// per-member base prices and discounts whose single-, double-, and no-discount
// totals are all distinct, so the assertion uniquely pins "exactly one discount
// per member, applied through the choke point."
#[tokio::test]
async fn room_fanout_charges_single_discounted_price_per_member() {
    use konsensus_pricing::apply_trust_discount;

    // ── Two distinct room members, each with a live sender E2EE session ──
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(Arc::new(
        test_identity(),
    )));
    // Distinct mnemonics → distinct NodeIds, neither equal to our own node id
    // (which is derived from the standard "abandon…about" test mnemonic), so
    // neither member is skipped as "self".
    let member_a = setup_e2ee_session_with_mnemonic(
        &session_manager,
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    )
    .await;
    let member_b = setup_e2ee_session_with_mnemonic(
        &session_manager,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    )
    .await;
    assert_ne!(member_a, member_b, "members must be distinct");

    // ── Connected transport so the keysend path (gated on is_connected) fires ──
    let invoice_requests = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let transport = Arc::new(ConnectedStubTransport::new(
        vec![member_a, member_b],
        Arc::clone(&invoice_requests),
    ));

    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let storage = Arc::new(MemStorage::new());

    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: storage.clone() as Arc<dyn Storage>,
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: transport.clone() as Arc<dyn MessageTransport>,
        session_manager: Arc::clone(&session_manager),
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
        invoice_requests: Arc::clone(&invoice_requests),
        data_dir: None,
        backup_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    });

    // Register Lightning pubkeys so the keysend path (which echoes the amount)
    // is taken for both members.
    {
        let mut pks = state.peer_ln_pubkeys.lock().await;
        pks.insert(member_a, "02aaaa".repeat(5));
        pks.insert(member_b, "02bbbb".repeat(5));
    }

    // ── Announce per-member price tables with distinct base + discount ──
    //
    // StubChain reports block height 850_000; tables anchored there with 144
    // valid blocks are fresh (not stale). Kind 1 maps to the "communication"
    // category.
    const KIND: u16 = 1;
    const BASE_A: u64 = 10_000; // discount 0.5  → single 5_000
    const DISCOUNT_A: f64 = 0.5;
    const BASE_B: u64 = 8_000; // discount 0.25 → single 6_000
    const DISCOUNT_B: f64 = 0.25;

    let mut prices_a = HashMap::new();
    prices_a.insert("communication".to_string(), BASE_A);
    state
        .peer_prices
        .update(member_a, prices_a, 850_000, 144, DISCOUNT_A)
        .await;

    let mut prices_b = HashMap::new();
    prices_b.insert("communication".to_string(), BASE_B);
    state
        .peer_prices
        .update(member_b, prices_b, 850_000, 144, DISCOUNT_B)
        .await;

    // Expected per-member single-discounted prices (the choke-point value),
    // floored to the minimum invoice amount the keysend path enforces.
    const MIN_INVOICE_AMOUNT_MSAT: u64 = 1_000;
    let expected_a = apply_trust_discount(BASE_A, DISCOUNT_A).max(MIN_INVOICE_AMOUNT_MSAT);
    let expected_b = apply_trust_discount(BASE_B, DISCOUNT_B).max(MIN_INVOICE_AMOUNT_MSAT);
    let expected_total = expected_a + expected_b;
    assert_eq!(expected_a, 5_000);
    assert_eq!(expected_b, 6_000);
    assert_eq!(expected_total, 11_000);

    // Sanity: the drift values we are guarding against are all distinct from the
    // correct total, so the equality assertion below is discriminating.
    let double_total = apply_trust_discount(apply_trust_discount(BASE_A, DISCOUNT_A), DISCOUNT_A)
        .max(MIN_INVOICE_AMOUNT_MSAT)
        + apply_trust_discount(apply_trust_discount(BASE_B, DISCOUNT_B), DISCOUNT_B)
            .max(MIN_INVOICE_AMOUNT_MSAT);
    let no_discount_total =
        BASE_A.max(MIN_INVOICE_AMOUNT_MSAT) + BASE_B.max(MIN_INVOICE_AMOUNT_MSAT);
    assert_ne!(double_total, expected_total, "double-discount must differ");
    assert_ne!(no_discount_total, expected_total, "no-discount must differ");

    // ── Create the room and add both members ──
    let room = Room::new("fanout-pricing".to_string(), *identity.node_id());
    let room_id = room.id;
    state.storage.create_room(&room).await.unwrap();
    state.storage.add_room_member(&room_id, &member_a).await.unwrap();
    state.storage.add_room_member(&room_id, &member_b).await.unwrap();

    // ── Compose to the room over HTTP ──
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": room_id.to_string(),
                "is_room": true,
                "kind": KIND,
                "plaintext": "fan this out to every member"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "room compose should succeed");

    let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // The summed amount across the fan-out must equal the single-discount total.
    assert_eq!(
        json["amount_msat"].as_u64().unwrap(),
        expected_total,
        "room fan-out total must be the single-discount sum (no double / no-discount drift)"
    );
    assert_eq!(json["delivered"], true, "both connected members delivered");

    // Per-member proof: each delivered envelope's payment proof equals that
    // member's single-discounted price — proving the discount was applied once
    // per member through the choke point, not skipped and not compounded.
    let sent = transport.sent_envelopes.lock().unwrap();
    assert_eq!(sent.len(), 2, "exactly one envelope per member");
    for (peer, envelope) in sent.iter() {
        let want = if *peer == member_a {
            expected_a
        } else if *peer == member_b {
            expected_b
        } else {
            panic!("envelope sent to an unexpected peer: {}", peer.to_hex());
        };
        assert_eq!(
            envelope.payment_proof.amount_msat, want,
            "member {} must be charged its single-discounted price",
            peer.to_hex()
        );
    }
}
