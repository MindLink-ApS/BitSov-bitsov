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
