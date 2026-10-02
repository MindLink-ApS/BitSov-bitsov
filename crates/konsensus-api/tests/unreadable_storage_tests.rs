//! Real encrypted SQLite through owner API routes, no listening socket.
mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use konsensus_api::state::AppState;
use konsensus_core::{kind::KIND_CHAT, NodeId, PaymentProof, Recipient, UkmEnvelopeBuilder};
use konsensus_storage::{EncryptedStorage, FileRecord, Peer, Room, SqliteStorage, Storage};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

async fn call(
    state: &Arc<AppState>,
    uri: &str,
    payload: Option<Value>,
    authorized: bool,
) -> (StatusCode, Value) {
    let mut req = Request::builder().uri(uri);
    if authorized {
        req = req.header("authorization", common::auth_header(state));
    }
    if payload.is_some() {
        req = req
            .method("POST")
            .header("content-type", "application/json");
    }
    let response = common::test_router(state.clone())
        .oneshot(
            req.body(payload.map_or(Body::empty(), |v| Body::from(v.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn lists_report_partial_reads_and_owner_status_warns_without_public_disclosure() {
    let store = Arc::new(EncryptedStorage::new(
        SqliteStorage::in_memory().await.unwrap(),
        &[7; 32],
    ));
    let state = common::test_state_with_storage_and_cipher(store.clone());
    let owner = *state.identity.node_id();
    let sender = NodeId::from_bytes([3; 32]);
    let make = |content: &str, timestamp| {
        UkmEnvelopeBuilder::new(
            KIND_CHAT,
            sender,
            Recipient::Node(owner),
            content.as_bytes().to_vec(),
            PaymentProof::new([1; 32], [2; 32], 10),
        )
        .timestamp(timestamp)
        .build()
    };
    let good = make("good", 10);
    let bad = make("secret bad content", 20);
    store.store_message(&good).await.unwrap();
    store
        .store_message_plaintext(
            &good.id,
            &common::test_plaintext_cipher()
                .encrypt(b"searchable")
                .unwrap(),
        )
        .await
        .unwrap();
    store.inner().store_message(&bad).await.unwrap();
    for uri in [
        "/api/v1/messages".into(),
        format!("/api/v1/messages?peer={}", sender.to_hex()),
        "/api/v1/messages/search?q=searchable".into(),
    ] {
        let (status, body) = call(&state, &uri, None, true).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["messages"].as_array().unwrap().len(), 1);
        assert_eq!(body["messages"][0]["id"], good.id.to_hex());
        assert_eq!(body["unreadable_count"], 1);
        assert_eq!(body["storage_key_mismatch"], true);
    }
    // Counts describe the scanned rows, even if room filtering returns none.
    let (_, room) = call(
        &state,
        &format!("/api/v1/messages?room={}", "ab".repeat(32)),
        None,
        true,
    )
    .await;
    assert_eq!(room["messages"], json!([]));
    assert_eq!(room["unreadable_count"], 1);
    let (status, discovery) = call(
        &state,
        "/api/v1/messages/resync",
        Some(json!({"phase":"discover", "peer_id":sender.to_hex(), "from_ms":0, "to_ms":100})),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(discovery["unreadable_count"], 1);
    assert_eq!(discovery["total_count"], 1);
    let (_, all_bad) = call(&state, "/api/v1/messages?limit=1", None, true).await;
    assert_eq!(all_bad["messages"], json!([]));
    assert_eq!(all_bad["unreadable_count"], 1);
    assert_eq!(all_bad["storage_key_mismatch"], true);
    let (_, healthy) = call(&state, "/api/v1/messages?before=20", None, true).await;
    assert_eq!(healthy["unreadable_count"], 0);
    assert_eq!(healthy["storage_key_mismatch"], false);
    let (status, _) = call(&state, &format!("/api/v1/messages/{}", bad.id), None, true).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let (_, status) = call(&state, "/api/v1/status", None, true).await;
    assert_eq!(status["storage_unreadable_rows"], 6);
    assert_eq!(status["storage_key_mismatch"], true);
    let (_, public) = call(&state, "/api/v1/health", None, false).await;
    assert!(public.get("storage_unreadable_rows").is_none());
    assert!(public.get("storage_key_mismatch").is_none());
    let (status, _) = call(&state, "/api/v1/status", None, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        store
            .inner()
            .get_message(&bad.id)
            .await
            .unwrap()
            .unwrap()
            .ciphertext,
        bad.ciphertext
    );
}

#[tokio::test]
async fn metadata_list_responses_disclose_unreadable_rows_and_zero() {
    let store = Arc::new(EncryptedStorage::new(
        SqliteStorage::in_memory().await.unwrap(),
        &[7; 32],
    ));
    let state = common::test_state_with_storage(store.clone());
    for (uri, key) in [
        ("/api/v1/rooms", "rooms"),
        ("/api/v1/files", "files"),
        ("/api/v1/peers", "peers"),
    ] {
        let (status, body) = call(&state, uri, None, true).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body[key], json!([]));
        assert_eq!(body["unreadable_count"], 0);
        assert_eq!(body["storage_key_mismatch"], false);
    }
    let owner = *state.identity.node_id();
    store
        .inner()
        .create_room(&Room::new("bad room".into(), owner))
        .await
        .unwrap();
    store
        .create_room(&Room::new("good room".into(), owner))
        .await
        .unwrap();
    store
        .inner()
        .upsert_peer(&Peer {
            node_id: owner,
            address: None,
            last_seen: None,
            display_name: Some("bad peer".into()),
            metadata: json!({}),
        })
        .await
        .unwrap();
    let file = FileRecord {
        id: uuid::Uuid::new_v4().to_string(),
        filename: "bad file".into(),
        mime_type: "text/plain".into(),
        size_bytes: 0,
        blake3_hash: "hash".into(),
        sender: owner.to_hex(),
        message_id: None,
        data: vec![],
        created_at: "2026-01-01T00:00:00Z".into(),
    };
    store.inner().store_file(&file).await.unwrap();
    store
        .store_file(&FileRecord {
            id: uuid::Uuid::new_v4().to_string(),
            ..file
        })
        .await
        .unwrap();
    for (uri, key, count) in [
        ("/api/v1/rooms", "rooms", 1),
        ("/api/v1/files", "files", 1),
        ("/api/v1/peers", "peers", 0),
    ] {
        let (status, body) = call(&state, uri, None, true).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body[key].as_array().unwrap().len(), count);
        assert_eq!(body["unreadable_count"], 1);
        assert_eq!(body["storage_key_mismatch"], true);
    }
    store.inner().pool().close().await;
    let (status, _) = call(&state, "/api/v1/messages", None, true).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
