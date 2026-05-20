mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn onboarding_state_full_start_returns_funding_fields() {
    let state = common::test_state();
    let app = konsensus_api::build_router(state.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/onboarding/start")
        .header("content-type", "application/json")
        .header("authorization", common::auth_header(&state))
        .body(Body::from(r#"{"tier":"full","funding_amount_sats":50000}"#))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["current_step"], "funding");
    assert_eq!(json["funding_amount_sats_required"], 50000);

    let req_state = Request::builder()
        .method("GET")
        .uri("/api/v1/onboarding/state")
        .header("authorization", common::auth_header(&state))
        .body(Body::empty())
        .unwrap();

    let res_state = konsensus_api::build_router(state).oneshot(req_state).await.unwrap();
    assert_eq!(res_state.status(), StatusCode::OK);
    let body_state = axum::body::to_bytes(res_state.into_body(), 4096).await.unwrap();
    let state_json: serde_json::Value = serde_json::from_slice(&body_state).unwrap();
    assert_eq!(state_json["current_step"], "funding");
}

#[tokio::test]
async fn onboarding_state_rejects_full_without_amount() {
    let state = common::test_state();
    let app = konsensus_api::build_router(state.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/onboarding/start")
        .header("content-type", "application/json")
        .header("authorization", common::auth_header(&state))
        .body(Body::from(r#"{"tier":"full"}"#))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}
