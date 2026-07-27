//! Money-adjacent disabled-path guard for the operator-hosting REST surface
//! (review #326). With the hosting feature flag OFF (the default), `routes()`
//! returns `Router::new()`, so a public/reference node exposes NO billing API.
//! This pins the actual call-site behavior (routes not mounted), not just the
//! flag predicate — if the `routes()` guard is removed while the predicate test
//! stays green, this fails.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn hosting_routes_not_mounted_when_flag_disabled() {
    // Default OFF: ensure the flag is absent so this is deterministic. No other
    // konsensus-api test sets this var, so no serial guard is needed here.
    std::env::remove_var("KONSENSUS_HOSTING_CONTRACTS_ENABLED");

    let state = common::test_state();
    let auth = common::auth_header(&state);
    let app = common::test_router(state);

    let req = Request::builder()
        .uri("/api/v1/hosting/contracts")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "with the hosting flag OFF, /api/v1/hosting/contracts must NOT be mounted \
         (routes() returns Router::new()); got {}",
        resp.status()
    );
}
