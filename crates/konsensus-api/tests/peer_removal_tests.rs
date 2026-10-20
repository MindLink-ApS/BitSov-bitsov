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
use konsensus_storage::{SqliteStorage, Storage};
use std::sync::Arc;
use tower::ServiceExt;

fn request(state: &AppState, method: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(format!("/api/v1/peers/{}", "ab".repeat(32)))
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

#[tokio::test]
async fn failed_delete_preserves_live_contact_and_restart_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.db");
    let storage = Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
    let (state, transport) = probe::state(storage.clone(), "ok");
    let id = seed(&state).await;
    *transport.live.lock().unwrap() = (true, true, true);
    sqlx::query("CREATE TRIGGER fail_delete BEFORE DELETE ON peers BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END")
        .execute(storage.pool()).await.unwrap();
    let response = common::test_router(state.clone())
        .oneshot(request(&state, "DELETE", ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(state
        .peer_registry
        .read()
        .await
        .whitelist_set()
        .contains(&id));
    assert_eq!(*transport.live.lock().unwrap(), (true, true, true));
    storage.pool().close().await;
    let reopened = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    assert_eq!(
        reopened
            .get_peer(&id)
            .await
            .unwrap()
            .unwrap()
            .display_name
            .as_deref(),
        Some("Original")
    );
}

#[tokio::test]
async fn failed_delete_does_not_remove_contact_from_queued_update() {
    let storage = Arc::new(common::MemStorage::new());
    let (state, transport) = probe::state(storage.clone(), "ok");
    let id = seed(&state).await;
    let gate = Arc::new(common::PeerWriteGate {
        fail: true,
        ..Default::default()
    });
    *storage.peer_delete_gate.lock().unwrap() = Some(gate.clone());
    let deleting =
        tokio::spawn(common::test_router(state.clone()).oneshot(request(&state, "DELETE", "")));
    gate.entered.notified().await;
    let updating = common::test_router(state.clone()).oneshot(request(
        &state,
        "PUT",
        r#"{"label":"Updated"}"#,
    ));
    tokio::pin!(updating);
    assert!(
        futures::poll!(&mut updating).is_pending(),
        "update must serialize with deletion"
    );
    gate.release.notify_one();
    assert_eq!(
        deleting.await.unwrap().unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(updating.await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        state
            .peer_registry
            .read()
            .await
            .get(&id)
            .unwrap()
            .label
            .as_deref(),
        Some("Updated")
    );
    assert_eq!(
        storage
            .get_peer(&id)
            .await
            .unwrap()
            .unwrap()
            .display_name
            .as_deref(),
        Some("Updated")
    );
    assert_eq!(*transport.live.lock().unwrap(), (true, false, true));
}
