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
    let (_, headers, refilled) = call(&state, "/api/v1/messages?limit=1", None, true).await;
    assert_eq!(refilled.as_array().unwrap().len(), 1);
    assert_eq!(refilled[0]["id"], good.id.to_hex());
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

#[tokio::test]
async fn unreadable_blocks_refill_and_bounded_scans_can_continue() {
    let store = Arc::new(EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]));
    let state = common::test_state_with_storage(store.clone());
    let owner = *state.identity.node_id();
    let sender = NodeId::from_bytes([3; 32]);
    let make = |n: u64| UkmEnvelopeBuilder::new(KIND_CHAT, sender, Recipient::Node(owner),
        n.to_le_bytes().to_vec(), PaymentProof::new([1; 32], [2; 32], 10)).timestamp(n).build();
    for n in 1..=13 {
        let env = make(n);
        if n == 1 || n == 13 { store.store_message(&env).await.unwrap(); }
        else { store.inner().store_message(&env).await.unwrap(); }
    }
    let (_, headers, body) = call(&state, "/api/v1/messages?limit=2", None, true).await;
    assert_eq!(body.as_array().unwrap().len(), 2);
    assert_eq!(body[0]["timestamp"], 13);
    assert_eq!(body[1]["timestamp"], 1);
    assert_eq!(headers["X-BitSov-Unreadable-Count"], "11");
    let (_, headers, body) = call(&state, "/api/v1/messages?limit=1&before=13", None, true).await;
    assert_eq!(body, json!([]));
    assert_eq!(headers["X-BitSov-Unreadable-Count"], "10");
    assert_eq!(headers["X-BitSov-Oldest-Scanned-Timestamp"], "3");
    let uri = format!("/api/v1/messages?limit=1&before={}&before_id={}",
        headers["X-BitSov-Oldest-Scanned-Timestamp"].to_str().unwrap(),
        headers["X-BitSov-Oldest-Scanned-Id"].to_str().unwrap());
    let (_, headers, body) = call(&state, &uri, None, true).await;
    assert_eq!(body[0]["timestamp"], 1);
    assert_eq!(headers["X-BitSov-Oldest-Scanned-Timestamp"], "1");
}

#[tokio::test]
async fn resync_refills_past_its_raw_row_limit() {
    let store = Arc::new(EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]));
    let state = common::test_state_with_storage(store.clone());
    let sender = NodeId::from_bytes([3; 32]);
    for n in 1u64..=1002 {
        let env = UkmEnvelopeBuilder::new(KIND_CHAT, sender, Recipient::Node(*state.identity.node_id()),
            n.to_le_bytes().to_vec(), PaymentProof::new([1; 32], [2; 32], 10)).timestamp(n).build();
        if n == 1 { store.store_message(&env).await.unwrap(); }
        else { store.inner().store_message(&env).await.unwrap(); }
    }
    let (status, headers, body) = call(&state, "/api/v1/messages/resync",
        Some(json!({"phase":"discover", "peer_id":sender.to_hex(), "from_ms":0, "to_ms":2000})), true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total_count"], 1);
    assert_eq!(body["messages"][0]["timestamp"], 1);
    assert_eq!(headers["X-BitSov-Unreadable-Count"], "1001");
}

#[tokio::test]
async fn resync_scan_bound_exposes_a_cursor_that_reaches_older_history() {
    let store = Arc::new(EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]));
    let state = common::test_state_with_storage(store.clone());
    let sender = NodeId::from_bytes([3; 32]);
    for n in 1u64..=5002 {
        let env = UkmEnvelopeBuilder::new(KIND_CHAT, sender, Recipient::Node(*state.identity.node_id()),
            n.to_le_bytes().to_vec(), PaymentProof::new([1; 32], [2; 32], 10)).timestamp(n).build();
        if n == 1 { store.store_message(&env).await.unwrap(); }
        else { store.inner().store_message(&env).await.unwrap(); }
    }
    let request = json!({"phase":"discover", "peer_id":sender.to_hex(), "from_ms":0, "to_ms":6000});
    let (status, headers, body) = call(&state, "/api/v1/messages/resync", Some(request.clone()), true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total_count"], 0);
    assert_eq!(headers["X-BitSov-Unreadable-Count"], "5000");
    assert_eq!(headers["X-BitSov-Oldest-Scanned-Timestamp"], "3");
    let mut resume = request;
    resume["before"] = json!(3);
    resume["before_id"] = json!(headers["X-BitSov-Oldest-Scanned-Id"].to_str().unwrap());
    let (status, headers, body) = call(&state, "/api/v1/messages/resync", Some(resume), true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total_count"], 1);
    assert_eq!(body["messages"][0]["timestamp"], 1);
    assert_eq!(headers["X-BitSov-Unreadable-Count"], "1");
    assert_eq!(headers["X-BitSov-Oldest-Scanned-Timestamp"], "1");
}

#[tokio::test]
async fn staged_files_do_not_skip_readable_rows_at_the_scan_boundary() {
    let store = Arc::new(EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]));
    let state = common::test_state_with_storage(store.clone());
    for n in 1..=22 {
        let file = FileRecord {
            id: format!("{n:02}"), filename: "name".into(), mime_type: "text/plain".into(),
            size_bytes: 0, blake3_hash: "hash".into(), sender: state.identity.node_id().to_hex(),
            message_id: None, data: vec![], created_at: String::new(),
        };
        if n == 1 || n == 22 { store.store_file(&file).await.unwrap(); }
        else { store.inner().store_file(&file).await.unwrap(); }
    }
    sqlx::query("UPDATE files SET created_at = '2026-01-01T00:00:00Z'").execute(store.inner().pool()).await.unwrap();
    for _ in 0..2 {
        let (status, _, _) = call(&state, "/api/v1/files", Some(json!({"filename":"staged.txt", "data_b64":"aGk="})), true).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, headers, body) = call(&state, "/api/v1/files?limit=2", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 2);
    assert!(body[0]["id"].as_str().unwrap().starts_with("stage-"));
    assert!(body[1]["id"].as_str().unwrap().starts_with("stage-"));
    assert_eq!(headers["X-BitSov-Oldest-Scanned-Id"], "03");
    let uri = format!("/api/v1/files?limit=2&before={}&before_id={}",
        headers["X-BitSov-Next-Before"].to_str().unwrap().replace('+', "%2B"), headers["X-BitSov-Next-Before-Id"].to_str().unwrap());
    let (status, _, body) = call(&state, &uri, None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body[0]["id"], "22");
}

#[tokio::test]
async fn bounded_file_pages_return_every_readable_and_staged_file_exactly_once() {
    use konsensus_api::auth::{AuthUser, Scope};
    use std::collections::BTreeSet;

    for tied in [false, true] {
        let store = Arc::new(EncryptedStorage::new(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
        ));
        let state = common::test_state_with_storage(store.clone());
        let auth = AuthUser {
            node_id: state.identity.node_id().to_hex(),
            scopes: Scope::all(),
            pairing: None,
        };
        let timestamp = |n| {
            let base = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z").unwrap();
            (base + chrono::Duration::seconds(if tied { 0 } else { n }))
                .with_timezone(&chrono::Utc)
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        };
        let file = |id: String, n| FileRecord {
            id,
            filename: "name".into(),
            mime_type: "text/plain".into(),
            size_bytes: 0,
            blake3_hash: "hash".into(),
            sender: auth.node_id.clone(),
            message_id: None,
            data: vec![],
            created_at: timestamp(n),
        };
        let mut expected = BTreeSet::new();
        for n in 1..=65 {
            // IDs on both sides of stage-* exercise the timestamp tie-breaker.
            let record = file(format!("{}-{n:02}", if n % 2 == 0 { "z" } else { "a" }), n);
            if [1, 22, 43, 65].contains(&n) {
                store.store_file(&record).await.unwrap();
                expected.insert(record.id.clone());
            } else {
                store.inner().store_file(&record).await.unwrap();
            }
            sqlx::query("UPDATE files SET created_at = ? WHERE id = ?")
                .bind(&record.created_at)
                .bind(&record.id)
                .execute(store.inner().pool()).await.unwrap();
        }
        for n in [0, 2, 21, 22, 23, 42, 43, 44, 64, 65, 66] {
            let record = file(format!("stage-{n:02}"), n);
            expected.insert(record.id.clone());
            state.file_staging.lock().unwrap().insert(&state, &auth, record).unwrap();
        }

        // Exercise full, short and empty bounded pages, including changing limits.
        for limits in [&[1][..], &[2][..], &[3, 1, 2][..]] {
            let mut seen = BTreeSet::new();
            let mut cursor = String::new();
            let mut bounded_pages = 0;
            for page in 0..100 {
                let limit = limits[page % limits.len()];
                let uri = format!("/api/v1/files?limit={limit}{cursor}");
                let (status, headers, body) = call(&state, &uri, None, true).await;
                assert_eq!(status, StatusCode::OK, "{body}");
                for item in body.as_array().unwrap() {
                    let id = item["id"].as_str().unwrap().to_owned();
                    assert!(seen.insert(id.clone()), "duplicate {id}: tied={tied}, {uri}");
                }
                if headers.contains_key("X-BitSov-Oldest-Scanned-Id") {
                    bounded_pages += 1;
                }
                let Some(before) = headers.get("X-BitSov-Next-Before") else {
                    break;
                };
                cursor = format!("&before={}&before_id={}",
                    before.to_str().unwrap().replace('+', "%2B"),
                    headers["X-BitSov-Next-Before-Id"].to_str().unwrap());
                assert!(page < 99, "pagination did not terminate");
            }
            assert!(bounded_pages > 0, "fixture must reach the raw scan bound");
            assert_eq!(seen, expected, "lost files: tied={tied}, limits={limits:?}");
        }
    }
}

#[tokio::test]
async fn search_continuation_preserves_matches_not_yet_returned() {
    let store = Arc::new(EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]));
    let state = common::test_state_with_storage_and_cipher(store.clone());
    for n in 1u64..=5002 {
        let env = UkmEnvelopeBuilder::new(KIND_CHAT, NodeId::from_bytes([3; 32]), Recipient::Node(*state.identity.node_id()),
            n.to_le_bytes().to_vec(), PaymentProof::new([1; 32], [2; 32], 10)).timestamp(n).build();
        if n >= 5001 {
            store.store_message(&env).await.unwrap();
            store.store_message_plaintext(&env.id, &common::test_plaintext_cipher().encrypt(b"match").unwrap()).await.unwrap();
        } else { store.inner().store_message(&env).await.unwrap(); }
    }
    let (status, headers, body) = call(&state, "/api/v1/messages/search?q=match&limit=1", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body[0]["timestamp"], 5002);
    assert_eq!(headers["X-BitSov-Oldest-Scanned-Timestamp"], "3");
    assert_eq!(headers["X-BitSov-Next-Before"], "5002");
    let uri = format!("/api/v1/messages/search?q=match&limit=1&before={}&before_id={}",
        headers["X-BitSov-Next-Before"].to_str().unwrap().replace('+', "%2B"), headers["X-BitSov-Next-Before-Id"].to_str().unwrap());
    let (status, _, body) = call(&state, &uri, None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body[0]["timestamp"], 5001);
}

#[tokio::test]
async fn room_source_checkpoints_are_separate_from_logical_pages() {
    use konsensus_core::payloads::room::RoomBinding;
    let store = Arc::new(EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]));
    let state = common::test_state_with_storage_and_cipher(store.clone());
    let owner = *state.identity.node_id();
    let peers = [NodeId::from_bytes([3; 32]), NodeId::from_bytes([4; 32])];
    let room = RoomBinding::create(&[owner, peers[0], peers[1]]).unwrap();
    let plaintext = json!({"v":1, "room":room, "msg":"ab".repeat(16), "text":"copies across chunks"}).to_string();
    let mut expected_copies = std::collections::BTreeSet::new();
    for n in 1u64..=5002 {
        let env = UkmEnvelopeBuilder::new(KIND_CHAT, owner, Recipient::Node(if n == 1 { peers[0] } else { peers[1] }),
            n.to_le_bytes().to_vec(), PaymentProof::new([1; 32], [2; 32], 10)).timestamp(n).build();
        if n == 1 || n == 5002 {
            expected_copies.insert(env.id.to_hex());
            store.store_message(&env).await.unwrap();
            store.store_message_plaintext(&env.id, &common::test_plaintext_cipher().encrypt(plaintext.as_bytes()).unwrap()).await.unwrap();
        } else { store.inner().store_message(&env).await.unwrap(); }
    }
    let uri = format!("/api/v1/messages?room={}&limit=1", room.id);
    let (status, headers, first) = call(&state, &uri, None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first[0]["timestamp"], 5002);
    assert_eq!(headers["X-BitSov-Oldest-Scanned-Timestamp"], "3");
    assert!(!headers.contains_key("X-BitSov-Next-Before"));
    // Logical pagination keeps the same source chunk and does not split copies.
    let (_, _, drained) = call(&state, &format!("{uri}&before=5002"), None, true).await;
    assert_eq!(drained, json!([]));
    // Explicit raw-source continuation reaches older copies for client-side merging.
    let resume = format!("{uri}&scan_before=3&scan_before_id={}", headers["X-BitSov-Oldest-Scanned-Id"].to_str().unwrap());
    let (status, headers, older) = call(&state, &resume, None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(older[0]["timestamp"], 1);
    assert_eq!(older[0]["room_msg"], first[0]["room_msg"]);
    assert_ne!(older[0]["copies"][0]["id"], first[0]["copies"][0]["id"]);
    assert_eq!(headers["X-BitSov-Oldest-Scanned-Timestamp"], "1");
    // A logical room_msg can span chunks, but each source copy appears once.
    let mut seen_copies = std::collections::BTreeSet::new();
    for page in [&first, &older] {
        for entry in page.as_array().unwrap() {
            for copy in entry["copies"].as_array().unwrap() {
                assert!(seen_copies.insert(copy["id"].as_str().unwrap().to_owned()));
            }
        }
    }
    assert_eq!(seen_copies, expected_copies);
}

#[tokio::test]
async fn exhausted_unreadable_message_pages_keep_a_cursor_until_true_end() {
    for count in [1u64, 1000, 1001] {
        let store = Arc::new(EncryptedStorage::new(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
        ));
        let state = common::test_state_with_storage_and_cipher(store.clone());
        let sender = NodeId::from_bytes([3; 32]);
        let mut oldest_id = String::new();
        for n in 1..=count {
            let env = UkmEnvelopeBuilder::new(
                KIND_CHAT,
                sender,
                Recipient::Node(*state.identity.node_id()),
                n.to_le_bytes().to_vec(),
                PaymentProof::new([1; 32], [2; 32], 10),
            )
            .timestamp(n)
            .build();
            if n == 1 {
                oldest_id = env.id.to_hex();
            }
            store.inner().store_message(&env).await.unwrap();
        }
        for uri in [
            "/api/v1/messages?limit=1000".to_string(),
            format!("/api/v1/messages?limit=1000&peer={sender}"),
            "/api/v1/messages/search?q=match&limit=1000".to_string(),
        ] {
            let (status, headers, body) = call(&state, &uri, None, true).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, json!([]));
            assert_eq!(headers["X-BitSov-Unreadable-Count"], count.to_string());
            assert_eq!(headers["X-BitSov-Next-Before"], "1");
            assert_eq!(headers["X-BitSov-Next-Before-Id"], oldest_id);
            let resume = format!(
                "{uri}&before={}&before_id={}",
                headers["X-BitSov-Next-Before"].to_str().unwrap(),
                headers["X-BitSov-Next-Before-Id"].to_str().unwrap()
            );
            let (status, headers, body) = call(&state, &resume, None, true).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, json!([]));
            assert_no_diagnostics(&headers);
            assert!(!headers.contains_key("X-BitSov-Next-Before"));
            assert!(!headers.contains_key("X-BitSov-Oldest-Scanned-Timestamp"));
        }
    }
}

#[tokio::test]
async fn mixed_message_page_cursor_includes_unreadable_tail() {
    let store = Arc::new(EncryptedStorage::new(
        SqliteStorage::in_memory().await.unwrap(),
        &[7; 32],
    ));
    let state = common::test_state_with_storage(store.clone());
    let mut oldest_id = String::new();
    for n in 1u64..=3 {
        let env = UkmEnvelopeBuilder::new(
            KIND_CHAT,
            NodeId::from_bytes([3; 32]),
            Recipient::Node(*state.identity.node_id()),
            n.to_le_bytes().to_vec(),
            PaymentProof::new([1; 32], [2; 32], 10),
        )
        .timestamp(n)
        .build();
        if n == 1 {
            oldest_id = env.id.to_hex();
        }
        if n == 2 {
            store.store_message(&env).await.unwrap();
        } else {
            store.inner().store_message(&env).await.unwrap();
        }
    }
    let (status, headers, body) = call(&state, "/api/v1/messages?limit=3", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["timestamp"], 2);
    assert_eq!(headers["X-BitSov-Unreadable-Count"], "2");
    assert_eq!(headers["X-BitSov-Next-Before"], "1");
    assert_eq!(headers["X-BitSov-Next-Before-Id"], oldest_id);
}

#[tokio::test]
async fn exhausted_unreadable_file_page_keeps_a_lossless_cursor() {
    let store = Arc::new(EncryptedStorage::new(
        SqliteStorage::in_memory().await.unwrap(),
        &[7; 32],
    ));
    let state = common::test_state_with_storage(store.clone());
    for n in 0..1000 {
        store
            .inner()
            .store_file(&FileRecord {
                id: format!("{n:04}"),
                filename: "name".into(),
                mime_type: "text/plain".into(),
                size_bytes: 0,
                blake3_hash: "hash".into(),
                sender: state.identity.node_id().to_hex(),
                message_id: None,
                data: vec![],
                created_at: String::new(),
            })
            .await
            .unwrap();
    }
    sqlx::query("UPDATE files SET created_at = '2026-01-01T00:00:00Z'")
        .execute(store.inner().pool())
        .await
        .unwrap();
    let (status, headers, body) = call(&state, "/api/v1/files?limit=1000", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!([]));
    assert_eq!(headers["X-BitSov-Unreadable-Count"], "1000");
    assert_eq!(headers["X-BitSov-Next-Before"], "2026-01-01T00:00:00Z");
    assert_eq!(headers["X-BitSov-Next-Before-Id"], "0000");
    let (status, headers, body) = call(
        &state,
        "/api/v1/files?limit=1000&before=2026-01-01T00:00:00Z&before_id=0000",
        None,
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!([]));
    assert_no_diagnostics(&headers);
    assert!(!headers.contains_key("X-BitSov-Next-Before"));
}
