mod common;
#[path = "common/peer_admission.rs"]
mod probe;
use konsensus_api::{
    handlers::peers::{admit_peer, AddPeerRequest},
    state::AppState,
};
use konsensus_core::types::NodeId;
use konsensus_storage::{SqliteStorage, Storage};
use std::sync::{Arc, Mutex};

fn request() -> AddPeerRequest {
    AddPeerRequest {
        node_id: "ab".repeat(32),
        addr: "127.0.0.1:9735".into(),
        label: Some("Dad".into()),
        auto_connect: true,
    }
}
fn state(
    storage: Arc<dyn Storage>,
    dial: &'static str,
) -> (Arc<AppState>, Arc<probe::AdmissionTransport>) {
    let base = common::test_state_with_storage(storage);
    let transport = Arc::new(probe::AdmissionTransport {
        storage: base.storage.clone(),
        registry: base.peer_registry.clone(),
        calls: Mutex::new(vec![]),
        dial_started: Default::default(),
        finish_dial: Default::default(),
        live: Default::default(),
        dial,
    });
    (
        Arc::new(AppState {
            transport: transport.clone(),
            ..(*base).clone()
        }),
        transport,
    )
}

#[tokio::test]
async fn admission_persists_before_live_changes_and_supervises_after_dial() {
    for dial in ["ok", "refused"] {
        let storage = Arc::new(SqliteStorage::open(":memory:").await.unwrap());
        let (state, transport) = state(storage, dial);
        let outcome = admit_peer(&state, "owner", "owner_control", request(), true)
            .await
            .unwrap();
        assert_eq!(outcome.dialed.is_ok(), dial == "ok");
        assert_eq!(
            *transport.calls.lock().unwrap(),
            ["whitelist", "dial", "supervise"]
        );
        let rows = state.storage.list_peers().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].address.as_deref(), Some("127.0.0.1:9735"));
        assert_eq!(rows[0].display_name.as_deref(), Some("Dad"));
        assert_eq!(rows[0].metadata["whitelist_source"], "owner_control");
        assert!(state
            .peer_registry
            .read()
            .await
            .whitelist()
            .contains(&outcome.entry.node_id));
    }
}

#[tokio::test(start_paused = true)]
async fn dial_is_bounded_and_admission_survives_timeout() {
    let (state, transport) = state(Arc::new(common::MemStorage::new()), "timeout");
    let start = tokio::time::Instant::now();
    let outcome = admit_peer(&state, "owner", "owner_control", request(), true)
        .await
        .unwrap();
    assert!(outcome.dialed.unwrap_err().contains("timed out"));
    assert_eq!(start.elapsed(), std::time::Duration::from_secs(10));
    assert_eq!(
        *transport.calls.lock().unwrap(),
        ["whitelist", "dial", "supervise"]
    );
    assert_eq!(state.storage.list_peers().await.unwrap().len(), 1);
}

#[tokio::test]
async fn persist_failure_leaves_registry_and_transport_untouched() {
    let storage = Arc::new(SqliteStorage::open(":memory:").await.unwrap());
    storage.pool().close().await;
    let (state, transport) = state(storage, "ok");
    assert!(
        admit_peer(&state, "owner", "owner_control", request(), true)
            .await
            .is_err()
    );
    assert!(state.peer_registry.read().await.all().is_empty());
    assert!(!state
        .peer_registry
        .read()
        .await
        .whitelist()
        .contains(&NodeId::from_hex(&request().node_id).unwrap()));
    assert!(transport.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn bad_peer_inputs_have_no_side_effects() {
    let (state, transport) = state(Arc::new(common::MemStorage::new()), "ok");
    for (id, addr, label) in [
        (state.identity.node_id().to_hex(), "127.0.0.1:9735", None),
        ("bad".into(), "127.0.0.1:9735", None),
        ("ab".repeat(32), "example.com:9735", None),
        ("ab".repeat(32), "127.0.0.1:9735", Some("a".repeat(257))),
        ("ab".repeat(32), "127.0.0.1:9735", Some("Dad\nspoof".into())),
        (
            "ab".repeat(32),
            "127.0.0.1:9735",
            Some("Dad\u{1b}[2J".into()),
        ),
    ] {
        let req = AddPeerRequest {
            node_id: id,
            addr: addr.into(),
            label,
            auto_connect: true,
        };
        assert!(admit_peer(&state, "owner", "owner_control", req, true)
            .await
            .is_err());
        assert!(state.storage.list_peers().await.unwrap().is_empty());
        assert!(state.peer_registry.read().await.all().is_empty());
        assert!(transport.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn http_admission_uses_shared_persistence_and_audit_without_immediate_dial() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let (base, transport) = state(Arc::new(common::MemStorage::new()), "ok");
    let state = Arc::new(AppState {
        audit_log: Arc::new(
            konsensus_api::audit::AuditLog::open(dir.path().join("audit.jsonl")).unwrap(),
        ),
        ..(*base).clone()
    });
    let req = Request::builder().method("POST").uri("/api/v1/peers")
        .header("authorization", common::auth_header(&state))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"node_id":"ab".repeat(32),"addr":"127.0.0.1:9735","label":"Dad","auto_connect":false}).to_string())).unwrap();
    let response = common::test_router(state.clone())
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let peer: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(peer["connected"], false);
    assert_eq!(peer["auto_connect"], false);
    assert_eq!(*transport.calls.lock().unwrap(), ["whitelist", "supervise"]);
    assert_eq!(
        state.storage.list_peers().await.unwrap()[0].metadata["whitelist_source"],
        "http_admin"
    );
    let log = std::fs::read_to_string(state.audit_log.path()).unwrap();
    let event: serde_json::Value = log
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .find(|e| e["event"] == "peer.added")
        .unwrap();
    assert_eq!(event["detail"]["source"], "http_admin");
    assert_eq!(event["detail"]["connected"], false);
}

#[tokio::test]
async fn removal_during_first_dial_cannot_leave_connection_or_supervision() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let (state, transport) = state(Arc::new(common::MemStorage::new()), "gate");
    let adding = state.clone();
    let add = tokio::spawn(async move {
        admit_peer(&adding, "owner", "owner_control", request(), true).await
    });
    transport.dial_started.notified().await;
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/peers/{}", request().node_id))
        .header("authorization", common::auth_header(&state))
        .body(Body::empty())
        .unwrap();
    let mut remove = tokio::spawn(common::test_router(state.clone()).oneshot(req));
    // Old code completes DELETE here, then the late dial resurrects live state.
    // Serialized mutations wait for the dial; either schedule must end removed.
    let early = tokio::time::timeout(std::time::Duration::from_millis(100), &mut remove).await;
    transport.finish_dial.notify_one();
    add.await.unwrap().unwrap();
    let response = match early {
        Ok(result) => result.unwrap().unwrap(),
        Err(_) => remove.await.unwrap().unwrap(),
    };
    assert_eq!(response.status(), StatusCode::OK);
    assert!(state.storage.list_peers().await.unwrap().is_empty());
    assert!(state.peer_registry.read().await.all().is_empty());
    assert_eq!(*transport.live.lock().unwrap(), (false, false, false));
}
