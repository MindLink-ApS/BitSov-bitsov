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
use konsensus_storage::Storage;
use std::sync::Arc;
use tower::ServiceExt;

fn request(state: &AppState, operation: &str) -> Request<Body> {
    let id = "ab".repeat(32);
    let (method, uri, body) = match operation {
        "put" => (
            "PUT",
            format!("/api/v1/peers/{id}"),
            serde_json::json!({"addr":"127.0.0.1:9736", "label":"Updated"}),
        ),
        "connect" => (
            "POST",
            format!("/api/v1/peers/{id}/connect"),
            serde_json::json!({}),
        ),
        "delete" => (
            "DELETE",
            format!("/api/v1/peers/{id}"),
            serde_json::json!({}),
        ),
        "import" | "skip" => (
            "POST",
            "/api/v1/peers/import".into(),
            serde_json::json!({
                "backup":{"version":1,"exported_at":"test","exported_by":"owner", "peers":[{
                    "node_id":id,"addr":"127.0.0.1:9736","label":"Updated","auto_connect":true
                }]}, "skip_existing": operation == "skip"
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

async fn seed(state: &Arc<AppState>) -> NodeId {
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
    .unwrap()
    .entry
    .node_id
}

async fn write_racing_delete(operation: &str, fail: bool) {
    let storage = Arc::new(common::MemStorage::new());
    let (state, transport) = probe::state(storage.clone(), "ok");
    let id = seed(&state).await;
    transport.calls.lock().unwrap().clear();
    let gate = Arc::new(common::PeerWriteGate {
        fail,
        ..Default::default()
    });
    *storage.peer_upsert_gate.lock().unwrap() = Some(gate.clone());
    let writing =
        tokio::spawn(common::test_router(state.clone()).oneshot(request(&state, operation)));
    tokio::time::timeout(std::time::Duration::from_secs(1), gate.entered.notified())
        .await
        .expect("handler must reach persistence before live mutation");
    // Polling once deterministically queues DELETE behind the parked write.
    let deleting = common::test_router(state.clone()).oneshot(request(&state, "delete"));
    tokio::pin!(deleting);
    let early_delete = futures::poll!(&mut deleting);
    let serialized = early_delete.is_pending();
    gate.release.notify_one();
    let (written, deleted) = tokio::join!(writing, async {
        match early_delete {
            std::task::Poll::Ready(result) => result.unwrap(),
            std::task::Poll::Pending => deleting.await.unwrap(),
        }
    });
    let response = written.unwrap().unwrap();
    if fail {
        if operation == "import" {
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["imported"], 0);
            assert_eq!(body["errors"].as_array().unwrap().len(), 1);
        } else {
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }
        assert!(
            transport.calls.lock().unwrap().is_empty(),
            "failed write changed live state"
        );
    } else if operation == "connect" {
        // DELETE queues before post-dial revalidation, invalidating admission.
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    } else {
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(deleted.status(), StatusCode::OK);
    assert!(
        serialized,
        "DELETE completed before persistence: {operation}"
    );
    assert!(storage.get_peer(&id).await.unwrap().is_none());
    assert!(state.peer_registry.read().await.get(&id).is_none());
    assert_eq!(*transport.live.lock().unwrap(), (false, false, false));
}

#[tokio::test]
async fn put_serializes_persistence_with_delete() {
    write_racing_delete("put", false).await;
}
#[tokio::test]
async fn connect_serializes_persistence_with_delete() {
    write_racing_delete("connect", false).await;
}
#[tokio::test]
async fn import_serializes_persistence_with_delete() {
    write_racing_delete("import", false).await;
}
#[tokio::test]
async fn failed_put_has_no_live_side_effects() {
    write_racing_delete("put", true).await;
}
#[tokio::test]
async fn failed_connect_has_no_live_side_effects() {
    write_racing_delete("connect", true).await;
}
#[tokio::test]
async fn failed_import_has_no_live_side_effects() {
    write_racing_delete("import", true).await;
}

#[tokio::test]
async fn removal_during_connect_dial_wins_without_blocking_readers() {
    let (state, transport) = probe::state(Arc::new(common::MemStorage::new()), "gate");
    let id = seed(&state).await;
    transport.calls.lock().unwrap().clear();
    let connecting =
        tokio::spawn(common::test_router(state.clone()).oneshot(request(&state, "connect")));
    transport.dial_started.notified().await;
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        common::test_router(state.clone()).oneshot(request(&state, "delete")),
    )
    .await
    .expect("DELETE blocked on connect")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!state
        .peer_registry
        .read()
        .await
        .whitelist_set()
        .contains(&id));
    transport.finish_dial.notify_one();
    assert!(!connecting.await.unwrap().unwrap().status().is_success());
    assert!(state.storage.get_peer(&id).await.unwrap().is_none());
    assert_eq!(*transport.live.lock().unwrap(), (false, false, false));
}

#[tokio::test]
async fn simultaneous_skip_existing_imports_admit_only_once() {
    let storage = Arc::new(common::MemStorage::new());
    let (state, transport) = probe::state(storage.clone(), "ok");
    let gate = Arc::new(common::PeerWriteGate::default());
    *storage.peer_upsert_gate.lock().unwrap() = Some(gate.clone());
    let first = tokio::spawn(common::test_router(state.clone()).oneshot(request(&state, "skip")));
    gate.entered.notified().await;
    let second = common::test_router(state.clone()).oneshot(request(&state, "skip"));
    tokio::pin!(second);
    assert!(futures::poll!(&mut second).is_pending());
    gate.release.notify_one();
    assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
    let response = second.await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["skipped"], 1);
    assert_eq!(body["imported"], 0);
    assert_eq!(*transport.calls.lock().unwrap(), ["whitelist", "supervise"]);
}
