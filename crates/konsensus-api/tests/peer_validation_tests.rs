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
        '\u{200b}', '\u{200e}', '\u{200f}', '\u{2028}', '\u{2029}', '\u{202a}', '\u{202b}',
        '\u{202c}', '\u{202d}', '\u{202e}', '\u{2060}', '\u{2066}', '\u{2067}', '\u{2068}',
        '\u{2069}', '\u{feff}',
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
    for label in [
        "👩‍💻",
        "👨‍👩‍👧",
        "🏳️‍🌈",
        "می\u{200c}روم",
        "æøå ÆØÅ",
        "家族 中文 日本語",
    ] {
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
                    label,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{operation}: {label}");
            let rows = state.storage.list_peers().await.unwrap();
            assert_eq!(rows.len(), 1, "{operation}: {label}");
            assert_eq!(rows[0].display_name.as_deref(), Some(label));
        }
    }
}

async fn reject_unusable_addresses(operation: &str) {
    for addr in [
        "0.0.0.0:9735",
        "[::]:9735",
        "127.0.0.1:0",
        "[::1]:0",
        "224.0.0.1:9735",
        "239.255.255.255:9735",
        "[ff02::1]:9735",
        "[::ffff:0.0.0.0]:9735",
        "[::ffff:224.0.0.1]:9735",
    ] {
        let (state, transport) = probe::state(Arc::new(common::MemStorage::new()), "ok");
        if operation == "put" {
            seed(&state).await;
        }
        transport.calls.lock().unwrap().clear();
        let response = common::test_router(state.clone())
            .oneshot(request(&state, operation, &"ab".repeat(32), addr, "Dad"))
            .await
            .unwrap();
        if operation == "import" {
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["imported"], 0, "import accepted {addr}");
            assert_eq!(body["errors"].as_array().unwrap().len(), 1);
            assert_eq!(body["results"][0]["status"], "rejected");
        } else {
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{operation} accepted {addr}"
            );
        }
        assert!(transport.calls.lock().unwrap().is_empty());
        let rows = state.storage.list_peers().await.unwrap();
        let registry = state.peer_registry.read().await;
        if operation == "put" {
            assert_eq!(rows[0].address.as_deref(), Some("127.0.0.1:9735"));
            assert_eq!(registry.all()[0].addr.to_string(), "127.0.0.1:9735");
        } else {
            assert!(rows.is_empty());
            assert!(registry.is_empty());
        }
    }
}

#[tokio::test]
async fn admission_rejects_unusable_addresses_with_400() {
    reject_unusable_addresses("add").await;
}
#[tokio::test]
async fn put_rejects_unusable_addresses_with_400() {
    reject_unusable_addresses("put").await;
}
#[tokio::test]
async fn import_reports_unusable_addresses_per_entry() {
    reject_unusable_addresses("import").await;
}

#[tokio::test]
async fn connect_rejects_legacy_unspecified_address_before_persistence() {
    let (state, transport) = probe::state(Arc::new(common::MemStorage::new()), "ok");
    let id = NodeId::from_hex(&"ab".repeat(32)).unwrap();
    state
        .peer_registry
        .write()
        .await
        .add(konsensus_message::PeerEntry {
            node_id: id,
            addr: "0.0.0.0:0".parse().unwrap(),
            label: None,
            auto_connect: false,
        });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/peers/{id}/connect"))
        .header("authorization", common::auth_header(&state))
        .body(Body::empty())
        .unwrap();
    let response = common::test_router(state.clone())
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(transport.calls.lock().unwrap().is_empty());
    assert!(state.storage.list_peers().await.unwrap().is_empty());
}

#[tokio::test]
async fn metadata_only_put_keeps_an_inbound_only_contacts_sentinel_address() {
    let (state, transport) = probe::state(Arc::new(common::MemStorage::new()), "ok");
    let id = NodeId::from_hex(&"ab".repeat(32)).unwrap();
    state
        .peer_registry
        .write()
        .await
        .add(konsensus_message::PeerEntry {
            node_id: id,
            addr: "0.0.0.0:0".parse().unwrap(),
            label: None,
            auto_connect: false,
        });
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/peers/{id}"))
        .header("authorization", common::auth_header(&state))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"label":"Inbound contact"}"#))
        .unwrap();
    let response = common::test_router(state.clone())
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let row = state.storage.get_peer(&id).await.unwrap().unwrap();
    assert_eq!(row.display_name.as_deref(), Some("Inbound contact"));
    assert!(transport.supervised_addrs.lock().unwrap().is_empty());
    assert_eq!(
        state
            .peer_registry
            .read()
            .await
            .addr(&id)
            .unwrap()
            .to_string(),
        "0.0.0.0:0"
    );
}
