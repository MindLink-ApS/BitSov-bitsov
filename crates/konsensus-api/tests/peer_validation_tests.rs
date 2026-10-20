mod common;
#[path = "common/peer_admission.rs"]
mod probe;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use konsensus_api::{
    handlers::peers::{admit_peer, AddPeerRequest},
    state::AppState,
};
use konsensus_core::types::NodeId;
use std::sync::Arc;
use tower::ServiceExt;

fn request(state: &AppState, operation: &str, id: &str, addr: &str, label: &str) -> Request<Body> {
    let peer = serde_json::json!({"node_id":id,"addr":addr,"label":label,"auto_connect":true});
    let (method, uri, body) = match operation {
        "add" => ("POST", "/api/v1/peers".to_string(), peer),
        "put" => (
            "PUT",
            format!("/api/v1/peers/{id}"),
            serde_json::json!({"addr":addr,"label":label}),
        ),
        "import" => (
            "POST",
            "/api/v1/peers/import".to_string(),
            serde_json::json!({
                "backup":{"version":1,"exported_at":"test","exported_by":"owner","peers":[peer]}
            }),
        ),
        _ => unreachable!(),
    };
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", common::auth_header(state))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn seed(state: &Arc<AppState>) {
    admit_peer(
        state,
        "owner",
        "owner_control",
        AddPeerRequest {
            node_id: "ab".repeat(32),
            addr: "127.0.0.1:9735".into(),
            label: Some("Original".into()),
            auto_connect: true,
        },
        false,
    )
    .await
    .unwrap();
}

async fn reject_unsafe_labels(operation: &str) {
    for c in [
        '\0', '\n', '\r', '\t', '\u{1b}', '\u{7f}', '\u{85}', '\u{ad}', '\u{61c}', '\u{180e}',
        '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{2028}', '\u{2029}',
        '\u{202a}', '\u{202e}', '\u{2060}', '\u{2066}', '\u{2069}', '\u{feff}',
    ] {
        let (state, transport) = probe::state(Arc::new(common::MemStorage::new()), "ok");
        if operation == "put" {
            seed(&state).await;
        }
        transport.calls.lock().unwrap().clear();
        let response = common::test_router(state.clone())
            .oneshot(request(
                &state,
                operation,
                &"ab".repeat(32),
                "127.0.0.1:9736",
                &format!("Dad{c}spoof"),
            ))
            .await
            .unwrap();
        if operation == "import" {
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["imported"], 0, "{operation} accepted {c:?}");
            assert_eq!(body["errors"].as_array().unwrap().len(), 1);
        } else {
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{operation} accepted {c:?}"
            );
        }
        assert!(transport.calls.lock().unwrap().is_empty());
        let registry = state.peer_registry.read().await;
        let rows = state.storage.list_peers().await.unwrap();
        if operation == "put" {
            let id = NodeId::from_hex(&"ab".repeat(32)).unwrap();
            assert_eq!(
                registry.get(&id).unwrap().label.as_deref(),
                Some("Original")
            );
            assert_eq!(rows[0].display_name.as_deref(), Some("Original"));
            assert_eq!(rows[0].address.as_deref(), Some("127.0.0.1:9735"));
        } else {
            assert!(registry.is_empty());
            assert!(rows.is_empty());
        }
    }
}

#[tokio::test]
async fn admission_rejects_controls_bidi_and_zero_width_labels() {
    reject_unsafe_labels("add").await;
}
#[tokio::test]
async fn put_rejects_controls_bidi_and_zero_width_labels() {
    reject_unsafe_labels("put").await;
}
#[tokio::test]
async fn import_rejects_controls_bidi_and_zero_width_labels() {
    reject_unsafe_labels("import").await;
}

#[tokio::test]
async fn put_rejects_self_even_if_a_legacy_registry_entry_exists() {
    let (state, transport) = probe::state(Arc::new(common::MemStorage::new()), "ok");
    let id = *state.identity.node_id();
    state
        .peer_registry
        .write()
        .await
        .add(konsensus_message::PeerEntry {
            node_id: id,
            addr: "127.0.0.1:9735".parse().unwrap(),
            label: None,
            auto_connect: false,
        });
    let response = common::test_router(state.clone())
        .oneshot(request(&state, "put", &id.to_hex(), "127.0.0.1:9736", "Me"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(state
        .peer_registry
        .read()
        .await
        .get(&id)
        .unwrap()
        .label
        .is_none());
    assert!(state.storage.list_peers().await.unwrap().is_empty());
    assert!(transport.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn all_peer_writers_accept_ordinary_unicode_labels() {
    for operation in ["add", "put", "import"] {
        let (state, _) = probe::state(Arc::new(common::MemStorage::new()), "ok");
        if operation == "put" {
            seed(&state).await;
        }
        let response = common::test_router(state.clone())
            .oneshot(request(
                &state,
                operation,
                &"ab".repeat(32),
                "[::1]:9735",
                "Familie — København 家族 👋",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            state.storage.list_peers().await.unwrap()[0]
                .display_name
                .as_deref(),
            Some("Familie — København 家族 👋")
        );
    }
}
