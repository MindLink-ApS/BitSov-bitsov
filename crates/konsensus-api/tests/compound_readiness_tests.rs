mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn authenticated_status_exposes_unavailable_read_only_profile() {
    let lightning = Arc::new(common::CountingLightning::default());
    let state = common::test_state_with_lightning(lightning.clone());
    let router = common::test_router(state.clone());
    for generation in [7, 8] {
        let response = router.clone().oneshot(Request::builder()
            .uri(format!("/api/v1/status?compound_readiness=true&generation={generation}&request_id=refresh"))
            .header("authorization", common::auth_header(&state))
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 131072).await.unwrap()).unwrap();
        let envelope = &body["compound_readiness"]["envelope"];
        assert!(envelope.is_object(), "missing versioned readiness envelope");
        assert_eq!(envelope["connection_binding"]["generation"], generation);
        assert_eq!(envelope["node_binding"]["node_id"], body["node_id"]);
        let readiness = &body["compound_readiness"]["readiness"];
        assert_eq!(readiness["implemented"], false);
        assert_eq!(readiness["authorizes_dispatch"], false);
        assert_eq!(readiness["revalidation_required"], true);
        assert!(readiness["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["reason"] == "missing_dependency"));
    }
    assert_eq!(lightning.money(), 0);
    assert_eq!(lightning.invoices(), 0);
    assert!(state
        .storage
        .get_messages_for_recipient(
            &konsensus_core::Recipient::Node(*state.identity.node_id()),
            100,
            None
        )
        .await
        .unwrap()
        .is_empty());
    assert!(state.transport.connected_peers().await.is_empty());
    assert_eq!(state.session_manager.session_count().await, 0);
    assert!(state.pairing.is_none());
}

#[tokio::test]
async fn readiness_remains_authenticated_and_absent_from_public_health() {
    let state = common::test_state();
    let router = common::test_router(state);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/status?compound_readiness=true&generation=1&request_id=read")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/health?compound_readiness=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 131072).await.unwrap()).unwrap();
    assert!(body.get("compound_readiness").is_none());
}

#[tokio::test]
async fn status_refresh_commits_no_storage_writes_or_grants() {
    use konsensus_storage::SqliteStorage;
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(
        SqliteStorage::open(dir.path().join("observations.db").to_str().unwrap())
            .await
            .unwrap(),
    );
    sqlx::query("CREATE TABLE readiness_write_guard (source TEXT)")
        .execute(storage.pool())
        .await
        .unwrap();
    let tables: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'readiness_write_guard'")
        .fetch_all(storage.pool()).await.unwrap();
    for (index, table) in tables.iter().enumerate() {
        let name = table.replace('"', "\"\"");
        for action in ["INSERT", "UPDATE", "DELETE"] {
            sqlx::query(&format!("CREATE TRIGGER readiness_{index}_{action} AFTER {action} ON \"{name}\" BEGIN INSERT INTO readiness_write_guard VALUES ('write'); END"))
                .execute(storage.pool()).await.unwrap();
        }
    }
    let lightning = Arc::new(common::CountingLightning::default());
    let mut state =
        common::test_state_with_lightning_and_storage(lightning.clone(), storage.clone());
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(ReadOnlyTransport);
    let router = common::test_router(state.clone());
    for generation in 0..3 {
        let response = router.clone().oneshot(Request::builder()
            .uri(format!("/api/v1/status?compound_readiness=true&generation={generation}&request_id=poll"))
            .header("authorization", common::auth_header(&state))
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let writes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM readiness_write_guard")
        .fetch_one(storage.pool())
        .await
        .unwrap();
    assert_eq!(
        writes, 0,
        "refresh wrote storage or issued durable authority"
    );
    assert_eq!(lightning.money(), 0);
    assert_eq!(lightning.invoices(), 0);
}

#[tokio::test]
async fn requested_envelope_requires_bounded_correlation_and_selected_node() {
    let state = common::test_state();
    let router = common::test_router(state.clone());
    for query in [
        "compound_readiness=true",
        "compound_readiness=true&generation=1&request_id=",
        "compound_readiness=true&generation=1&request_id=bad%20id",
        "compound_readiness=true&generation=-1&request_id=read",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/status?{query}"))
                    .header("authorization", common::auth_header(&state))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
    }
    let other = common::test_state();
    let wrong_node = konsensus_api::auth::create_token(
        "other-node",
        &other.jwt_secret,
        konsensus_api::auth::Scope::all(),
    )
    .unwrap();
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/status?compound_readiness=true&generation=1&request_id=read")
                .header("authorization", format!("Bearer {wrong_node}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

struct ReadOnlyTransport;
#[async_trait::async_trait]
impl konsensus_core::traits::transport::MessageTransport for ReadOnlyTransport {
    async fn send(
        &self,
        _: &konsensus_core::NodeId,
        _: &konsensus_core::UkmEnvelope,
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        panic!("status refresh attempted a message send")
    }
    async fn send_raw_frame(
        &self,
        _: &konsensus_core::NodeId,
        _: &[u8],
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        panic!("status refresh attempted a frame send")
    }
    async fn connect(
        &self,
        _: &konsensus_core::NodeId,
        _: &str,
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        panic!("status refresh attempted a connection")
    }
    async fn disconnect(
        &self,
        _: &konsensus_core::NodeId,
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        panic!("status refresh attempted a disconnect")
    }
    async fn recv(
        &self,
    ) -> Result<konsensus_core::UkmEnvelope, konsensus_core::traits::transport::TransportError>
    {
        panic!("status refresh attempted a receive")
    }
    async fn is_connected(&self, _: &konsensus_core::NodeId) -> bool {
        false
    }
    async fn connected_peers(&self) -> Vec<konsensus_core::NodeId> {
        Vec::new()
    }
}

#[tokio::test]
async fn ordinary_status_retains_its_query_compatibility() {
    let state = common::test_state();
    let response = common::test_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/status?generation=unrelated&request_id=unrelated")
                .header("authorization", common::auth_header(&state))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 131072).await.unwrap()).unwrap();
    assert!(body.get("compound_readiness").is_none());
}
