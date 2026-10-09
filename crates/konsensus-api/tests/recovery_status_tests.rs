//! Recovery journal diagnostics must never grant recovery authority or leak journal data.
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use konsensus_api::{
    auth::{self, Scope},
    state::AppState,
};
use std::sync::Arc;
use tower::ServiceExt;

async fn call(
    state: Arc<AppState>,
    path: &str,
    token: Option<String>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder().uri(path);
    if let Some(token) = token {
        request = request.header("authorization", token);
    }
    let response = test_router(state)
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let code = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 100_000)
        .await
        .unwrap();
    (
        code,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn recovery_journal_status_is_read_only_and_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let storage = dir.path().join("ldk");
    konsensus_lightning::recover::initialize(&storage).unwrap();
    let state = Arc::new(AppState {
        // Config/API data and mnemonic/LDK data need not share a parent.
        data_dir: Some(dir.path().join("different-config-directory")),
        recovery_dir: Some(storage.clone()),
        ..(*test_state()).clone()
    });
    let path = storage.join("recover.json");
    let before = std::fs::read(&path).unwrap();
    let (code, body) = call(state.clone(), "/api/v1/status", Some(auth_header(&state))).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["recovery"], serde_json::json!({"state": "open"}));
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let foreign =
        auth::create_token(&"ab".repeat(32), &state.jwt_secret, vec![Scope::Read]).unwrap();
    let limited = auth::create_token(
        &state.identity.node_id().to_hex(),
        &state.jwt_secret,
        vec![Scope::Receive],
    )
    .unwrap();
    for token in [
        None,
        Some(format!("Bearer {foreign}")),
        Some(format!("Bearer {limited}")),
    ] {
        let (code, body) = call(state.clone(), "/api/v1/status", token).await;
        assert!(matches!(
            code,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ));
        assert!(body.get("recovery").is_none());
    }
    let (_, public) = call(state.clone(), "/api/v1/health", None).await;
    assert!(public.get("recovery").is_none());
    let response = test_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/status")
                .header("authorization", auth_header(&state))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[tokio::test]
async fn recovery_status_reports_journal_health_without_contents_or_writes() {
    let dir = tempfile::tempdir().unwrap();
    let storage = dir.path().join("ldk");
    std::fs::create_dir(&storage).unwrap();
    let path = storage.join("recover.json");
    let state = Arc::new(AppState {
        recovery_dir: Some(storage.clone()),
        ..(*test_state()).clone()
    });
    let (_, body) = call(state.clone(), "/api/v1/status", Some(auth_header(&state))).await;
    assert_eq!(body["recovery"], serde_json::json!({"state": "absent"}));
    assert!(!path.exists());

    // Independent on-disk fixture with private operational data that must not be serialized.
    let recovery = serde_json::json!({
        "plan": {"node_id": "private-node", "network": "regtest",
            "destination": "private-destination", "fee_rate_sat_vb": 2},
        "funding": [], "closes": [], "sweeps": [],
        "report": {"node_id": "private-node", "closing_txids": ["private-close"],
            "sweep_txids": ["private-sweep"], "recovered_sats": 12345,
            "self_test": "private-report"},
        "verification": {"store_id": "private-marker", "hub": "private-hub",
            "invoice": "private-invoice", "payment_id": "private-payment"}
    });
    let full = serde_json::json!({"version": 1, "state": "done", "recovery": recovery});
    let mut incomplete = full.clone();
    incomplete["recovery"]["report"] = serde_json::Value::Null;
    for (bytes, expected) in [
        (full.to_string(), "done"),
        (incomplete.to_string(), "unavailable"),
        (r#"{"version":1,"state":"open"}"#.into(), "open"),
        (r#"{"version":1,"state":"done"}"#.into(), "done"),
        (r#"{"version":2,"state":"done"}"#.into(), "unavailable"),
        (
            r#"{"version":1,"state":"arbitrary-private-state"}"#.into(),
            "unavailable",
        ),
        (
            r#"{"version":1,"state":"done","secret":"private-secret"}"#.into(),
            "unavailable",
        ),
        ("private-corrupt-journal".into(), "unavailable"),
    ] {
        std::fs::write(&path, &bytes).unwrap();
        let (code, body) = call(state.clone(), "/api/v1/status", Some(auth_header(&state))).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["recovery"], serde_json::json!({"state": expected}));
        assert!(!body.to_string().contains("private-"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), bytes);
    }
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let (_, body) = call(state.clone(), "/api/v1/status", Some(auth_header(&state))).await;
    assert_eq!(
        body["recovery"],
        serde_json::json!({"state": "unavailable"})
    );
    assert!(path.is_dir());

    let unconfigured = test_state();
    let (_, body) = call(
        unconfigured.clone(),
        "/api/v1/status",
        Some(auth_header(&unconfigured)),
    )
    .await;
    assert!(body.get("recovery").is_none());
}

#[tokio::test]
async fn recovery_status_on_remote_router_requires_owner_read_authority() {
    let dir = tempfile::tempdir().unwrap();
    let storage = dir.path().join("ldk");
    konsensus_lightning::recover::initialize(&storage).unwrap();
    let state = Arc::new(AppState {
        recovery_dir: Some(storage.clone()),
        ..(*test_state()).clone()
    });
    let app = konsensus_api::build_remote_router(state.clone()).layer(
        axum::extract::connect_info::MockConnectInfo(
            "127.0.0.1:50000".parse::<std::net::SocketAddr>().unwrap(),
        ),
    );
    let foreign =
        auth::create_token(&"ab".repeat(32), &state.jwt_secret, vec![Scope::Read]).unwrap();
    for (path, token, expected, visible) in [
        (
            "/api/v1/status",
            Some(auth_header(&state)),
            StatusCode::OK,
            true,
        ),
        ("/api/v1/status", None, StatusCode::UNAUTHORIZED, false),
        (
            "/api/v1/status",
            Some(format!("Bearer {foreign}")),
            StatusCode::FORBIDDEN,
            false,
        ),
        ("/api/v1/health", None, StatusCode::NOT_FOUND, false),
    ] {
        let mut request = Request::builder().uri(path);
        if let Some(token) = token {
            request = request.header("authorization", token);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let bytes = axum::body::to_bytes(response.into_body(), 100_000)
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        if visible {
            assert_eq!(body["recovery"], serde_json::json!({"state": "open"}));
        } else {
            assert!(body.get("recovery").is_none());
        }
    }
    assert!(konsensus_lightning::recover::ensure_normal_start(&storage).is_err());
}
