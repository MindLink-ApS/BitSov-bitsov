mod common;
#[path = "common/peer_admission.rs"]
mod probe;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use konsensus_api::state::AppState;
use konsensus_core::types::NodeId;
use konsensus_message::PeerEntry;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

async fn call(state: &Arc<AppState>, method: &str, uri: &str, body: Value) -> Value {
    let response = common::test_router(state.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", common::auth_header(state))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn entry(id: &str, addr: &str) -> Value {
    json!({"node_id":id,"addr":addr,"label":"Contact","auto_connect":false})
}

#[tokio::test]
async fn export_import_round_trip_preserves_inbound_only_contact() {
    for auto_connect in [false, true] {
        let source = common::test_state();
        for (id, addr, auto_connect) in [
            ("ab".repeat(32), "0.0.0.0:0", false),
            ("cd".repeat(32), "127.0.0.1:9735", true),
        ] {
            source.peer_registry.write().await.add(PeerEntry {
                node_id: NodeId::from_hex(&id).unwrap(),
                addr: addr.parse().unwrap(),
                label: Some("Contact".into()),
                auto_connect,
            });
        }
        call(
            &source,
            "PUT",
            &format!("/api/v1/peers/{}", "ab".repeat(32)),
            json!({"auto_connect":auto_connect}),
        )
        .await;
        let backup = call(&source, "GET", "/api/v1/peers/export", Value::Null).await;
        let (restored, transport) = probe::state(Arc::new(common::MemStorage::new()), "ok");
        let report = call(
            &restored,
            "POST",
            "/api/v1/peers/import",
            json!({"backup":backup}),
        )
        .await;
        assert_eq!(report["imported"], 2);
        assert_eq!(report["errors"], json!([]));
        let exported = call(&restored, "GET", "/api/v1/peers/export", Value::Null).await;
        for peer in backup["peers"].as_array().unwrap() {
            assert!(exported["peers"].as_array().unwrap().contains(peer));
        }
        let id = NodeId::from_hex(&"ab".repeat(32)).unwrap();
        assert!(restored
            .peer_registry
            .read()
            .await
            .whitelist_set()
            .contains(&id));
        let stored = restored.storage.get_peer(&id).await.unwrap().unwrap();
        assert_eq!(stored.address.as_deref(), Some("0.0.0.0:0"));
        assert_eq!(stored.display_name.as_deref(), Some("Contact"));
        // Both contacts are admitted to the transport; only the dialable one is supervised.
        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|&&c| c == "whitelist").count(), 2);
        assert_eq!(calls.iter().filter(|&&c| c == "supervise").count(), 1);
        assert_eq!(
            *transport.supervised_addrs.lock().unwrap(),
            ["127.0.0.1:9735"]
        );
    }
}

#[tokio::test]
async fn import_reports_each_entry_and_continues_after_rejections_and_skips() {
    let (state, transport) = probe::state(Arc::new(common::MemStorage::new()), "ok");
    let existing = NodeId::from_hex(&"ab".repeat(32)).unwrap();
    state.peer_registry.write().await.add(PeerEntry {
        node_id: existing,
        addr: "127.0.0.1:9735".parse().unwrap(),
        label: Some("Original".into()),
        auto_connect: true,
    });
    let mut bad_label = entry(&"13".repeat(32), "127.0.0.1:9735");
    bad_label["label"] = json!("bad\nlabel");
    let mut invalid_placeholder = entry(&"14".repeat(32), "[::]:0");
    invalid_placeholder["auto_connect"] = json!(true);
    let peers = vec![
        entry(&"cd".repeat(32), "127.0.0.1:9736"),
        entry(&"ef".repeat(32), "224.0.0.1:9735"),
        entry(&state.identity.node_id().to_hex(), "0.0.0.0:0"),
        entry(&existing.to_hex(), "127.0.0.1:9999"),
        entry("invalid-id", "127.0.0.1:9735"),
        entry(&"12".repeat(32), "invalid-address"),
        bad_label,
        invalid_placeholder,
        entry(&"15".repeat(32), "0.0.0.0:0"),
    ];
    let report = call(
        &state,
        "POST",
        "/api/v1/peers/import",
        json!({
            "backup":{"version":1,"exported_at":"test","exported_by":"owner","peers":peers},
            "skip_existing":false
        }),
    )
    .await;
    assert_eq!(report["imported"], 2);
    assert_eq!(report["skipped"], 2);
    assert_eq!(report["errors"].as_array().unwrap().len(), 5);
    let results = report["results"].as_array().unwrap();
    assert_eq!(results.len(), peers.len());
    for ((result, peer), status) in results.iter().zip(&peers).zip([
        "imported", "rejected", "skipped", "skipped", "rejected", "rejected", "rejected",
        "rejected", "imported",
    ]) {
        assert_eq!(result["node_id"], peer["node_id"]);
        assert_eq!(result["status"], status);
        if status != "imported" {
            assert!(!result["reason"].as_str().unwrap().is_empty());
        }
    }
    assert!(results[2]["reason"].as_str().unwrap().contains("self"));
    assert!(results[3]["reason"].as_str().unwrap().contains("existing"));
    let registry = state.peer_registry.read().await;
    assert_eq!(
        registry.get(&existing).unwrap().label.as_deref(),
        Some("Original")
    );
    assert_eq!(
        registry.get(&existing).unwrap().addr.to_string(),
        "127.0.0.1:9735"
    );
    assert_eq!(registry.len(), 3);
    assert_eq!(state.storage.list_peers().await.unwrap().len(), 2);
    assert_eq!(
        *transport.supervised_addrs.lock().unwrap(),
        ["127.0.0.1:9736"]
    );
}

#[tokio::test]
async fn inbound_only_reimport_stays_unsupervised_when_an_old_dial_finishes() {
    let (state, transport) = probe::state(Arc::new(common::MemStorage::new()), "gate");
    let id = "ab".repeat(32);
    call(
        &state,
        "POST",
        "/api/v1/peers",
        entry(&id, "127.0.0.1:9735"),
    )
    .await;
    transport.calls.lock().unwrap().clear();
    let connect = common::test_router(state.clone()).oneshot(
        Request::builder()
            .method("POST")
            .uri(format!("/api/v1/peers/{id}/connect"))
            .header("authorization", common::auth_header(&state))
            .body(Body::empty())
            .unwrap(),
    );
    let connecting = tokio::spawn(connect);
    transport.dial_started.notified().await;
    call(
        &state,
        "DELETE",
        &format!("/api/v1/peers/{id}"),
        Value::Null,
    )
    .await;
    let report = call(
        &state,
        "POST",
        "/api/v1/peers/import",
        json!({
            "backup":{"version":1,"exported_at":"test","exported_by":"owner",
                "peers":[entry(&id, "0.0.0.0:0")]}
        }),
    )
    .await;
    assert_eq!(report["imported"], 1);
    assert_eq!(*transport.live.lock().unwrap(), (true, false, false));
    transport.finish_dial.notify_one();
    assert_eq!(
        connecting.await.unwrap().unwrap().status(),
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(*transport.live.lock().unwrap(), (true, true, false));
    assert!(transport
        .supervised_addrs
        .lock()
        .unwrap()
        .iter()
        .all(|addr| addr != "0.0.0.0:0"));
    let id = NodeId::from_hex(&id).unwrap();
    let registry = state.peer_registry.read().await;
    assert!(registry.whitelist_set().contains(&id));
    assert_eq!(registry.addr(&id).unwrap().to_string(), "0.0.0.0:0");
}
