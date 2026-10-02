//! Real encrypted SQLite through owner API routes, no listening socket.
mod common;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
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
) -> (StatusCode, HeaderMap, Value) {
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
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
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
        let (status, headers, body) = call(&state, &uri, None, true).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().unwrap().len(), 1);
        assert_eq!(body[0]["id"], good.id.to_hex());
        assert_eq!(headers["X-BitSov-Unreadable-Count"], "1");
        assert_eq!(headers["X-BitSov-Storage-Key-Mismatch"], "true");
    }
    // Counts describe the scanned rows, even if room filtering returns none.
    let (_, headers, room) = call(
        &state,
        &format!("/api/v1/messages?room={}", "ab".repeat(32)),
        None,
        true,
    )
    .await;
    assert_eq!(room, json!([]));
    assert_eq!(headers["X-BitSov-Unreadable-Count"], "1");
    assert_eq!(headers["X-BitSov-Storage-Key-Mismatch"], "true");
    let (status, headers, discovery) = call(
        &state,
        "/api/v1/messages/resync",
        Some(json!({"phase":"discover", "peer_id":sender.to_hex(), "from_ms":0, "to_ms":100})),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["X-BitSov-Unreadable-Count"], "1");
    assert_eq!(headers["X-BitSov-Storage-Key-Mismatch"], "true");
    assert_eq!(
        discovery,
        json!({
            "phase": "discover", "peer_id": sender.to_hex(),
            "messages": [{"id": good.id.to_hex(), "kind": KIND_CHAT, "timestamp": 10,
                "estimated_fee_msat": 5, "plaintext_available": true}],
            "total_count": 1, "estimated_total_msat": 5, "from_ms": 0, "to_ms": 100
        })
    );
    let (_, headers, all_bad) = call(&state, "/api/v1/messages?limit=1", None, true).await;
    assert_eq!(all_bad, json!([]));
    assert_eq!(headers["X-BitSov-Unreadable-Count"], "1");
    assert_eq!(headers["X-BitSov-Storage-Key-Mismatch"], "true");
    let (_, headers, healthy) = call(&state, "/api/v1/messages?before=20", None, true).await;
    assert_eq!(healthy.as_array().unwrap().len(), 1);
    assert_no_diagnostics(&headers);
    let (status, _, _) = call(&state, &format!("/api/v1/messages/{}", bad.id), None, true).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let (_, _, status) = call(&state, "/api/v1/status", None, true).await;
    assert_eq!(status["storage_unreadable_rows"], 6);
    assert_eq!(status["storage_key_mismatch"], true);
    let (_, _, public) = call(&state, "/api/v1/health", None, false).await;
    assert!(public.get("storage_unreadable_rows").is_none());
    assert!(public.get("storage_key_mismatch").is_none());
    let (status, _, _) = call(&state, "/api/v1/status", None, false).await;
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
async fn metadata_lists_keep_arrays_and_only_send_headers_for_unreadable_rows() {
    let store = Arc::new(EncryptedStorage::new(
        SqliteStorage::in_memory().await.unwrap(),
        &[7; 32],
    ));
    let state = common::test_state_with_storage_and_cipher(store.clone());
    for uri in [
        "/api/v1/rooms",
        "/api/v1/files",
        "/api/v1/peers",
        "/api/v1/messages",
        "/api/v1/messages/search?q=searchable",
    ] {
        let (status, headers, body) = call(&state, uri, None, true).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        assert_eq!(body, json!([]));
        assert_no_diagnostics(&headers);
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
    for (uri, count) in [
        ("/api/v1/rooms", 1),
        ("/api/v1/files", 1),
        ("/api/v1/peers", 0),
    ] {
        let (status, headers, body) = call(&state, uri, None, true).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().unwrap().len(), count);
        assert_eq!(headers["X-BitSov-Unreadable-Count"], "1");
        assert_eq!(headers["X-BitSov-Storage-Key-Mismatch"], "true");
    }
    store.inner().pool().close().await;
    let (status, _, _) = call(&state, "/api/v1/messages", None, true).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

fn assert_no_diagnostics(headers: &HeaderMap) {
    assert!(!headers.contains_key("X-BitSov-Unreadable-Count"));
    assert!(!headers.contains_key("X-BitSov-Storage-Key-Mismatch"));
}

#[tokio::test]
async fn below_threshold_sends_count_without_mismatch_and_resync_keeps_original_objects() {
    let store = Arc::new(EncryptedStorage::new(
        SqliteStorage::in_memory().await.unwrap(),
        &[7; 32],
    ));
    let state = common::test_state_with_storage(store.clone());
    let owner = *state.identity.node_id();
    for name in ["good one", "good two"] {
        store
            .create_room(&Room::new(name.into(), owner))
            .await
            .unwrap();
    }
    store
        .inner()
        .create_room(&Room::new("bad".into(), owner))
        .await
        .unwrap();
    let (status, headers, rooms) = call(&state, "/api/v1/rooms", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rooms.as_array().unwrap().len(), 2);
    assert_eq!(headers["X-BitSov-Unreadable-Count"], "1");
    assert!(!headers.contains_key("X-BitSov-Storage-Key-Mismatch"));

    let peer = NodeId::from_bytes([3; 32]).to_hex();
    for uri in [
        format!("/api/v1/messages?peer={peer}"),
        format!("/api/v1/messages?room={}", "ab".repeat(32)),
    ] {
        let (status, headers, body) = call(&state, &uri, None, true).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        assert_eq!(body, json!([]));
        assert_no_diagnostics(&headers);
    }
    let (status, headers, body) = call(
        &state,
        "/api/v1/messages/resync",
        Some(json!({"phase":"discover", "peer_id":peer, "from_ms":0, "to_ms":100})),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_no_diagnostics(&headers);
    assert_eq!(
        body,
        json!({"phase":"discover", "peer_id":peer, "messages":[],
        "total_count":0, "estimated_total_msat":0, "from_ms":0, "to_ms":100})
    );
    let (status, headers, body) = call(
        &state,
        "/api/v1/messages/resync",
        Some(json!({"phase":"fulfill", "peer_id":peer, "message_ids":["aa".repeat(32)]})),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_no_diagnostics(&headers);
    assert_eq!(
        body,
        json!({"phase":"fulfill", "resynced_count":0,
        "failed_count":1, "plaintext_count":0, "total_msat":0})
    );
}
