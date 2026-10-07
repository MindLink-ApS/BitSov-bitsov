//! Pure in-process router tests; no listeners or external services.
#![allow(dead_code)]
mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use tower::ServiceExt;

#[tokio::test]
async fn tower_status_is_owner_read_only_and_default_off() {
    let state = test_state();
    for remote in [false, true] {
        let app = if remote {
            konsensus_api::build_remote_router(state.clone()).layer(
                axum::extract::connect_info::MockConnectInfo(
                    "127.0.0.1:50000".parse::<std::net::SocketAddr>().unwrap(),
                ),
            )
        } else {
            test_router(state.clone())
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/tower/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let token = konsensus_api::auth::create_token(
            &state.identity.node_id().to_hex(),
            &state.jwt_secret,
            vec![],
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/tower/status")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/tower/status")
                    .header("authorization", auth_header(&state))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 100_000)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["enabled"], false);
        assert_eq!(body["transport_enabled"], false);
        assert_eq!(body["coverage_scope"], "to_local_only");
        assert_eq!(body["channels"], serde_json::json!([]));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/tower/status")
                    .header("authorization", auth_header(&state))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
