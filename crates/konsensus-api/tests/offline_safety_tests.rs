//! The owner status exposes local safety even when Lightning cannot sync.
mod common;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use konsensus_api::auth::{self, Scope};
use konsensus_core::offline_safety::*;
use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails,
};
use std::sync::Arc;
use tower::ServiceExt;

struct StalledLightning(SharedOfflineSafety);

#[async_trait]
impl LightningProvider for StalledLightning {
    fn offline_safety(&self) -> Option<SharedOfflineSafety> {
        Some(self.0.clone())
    }
    async fn is_available(&self) -> bool {
        false
    }
    async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
        unreachable!()
    }
    async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        unreachable!()
    }
    async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        unreachable!()
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        unreachable!()
    }
}

#[tokio::test]
async fn offline_safety_status_is_owner_auth_gated_read_only_and_amount_free() {
    let shared: SharedOfflineSafety = Default::default();
    // Deserializing an independent expected wire fixture also pins severity spelling.
    let fixture = serde_json::json!({
        "blocks_offline": 170, "smallest_window_blocks": 200,
        "percentage": 85.0, "severity": "critical", "estimated": false,
        "coverage_complete": true, "history_available_on_start": true,
        "heartbeat_error": null, "startup_alert": null,
        "channels": [{"channel_id": "channel-a", "window_blocks": 200,
                      "percentage": 85.0, "severity": "critical"}]
    });
    *shared.write().unwrap() = serde_json::from_value(fixture.clone()).unwrap();
    let state = common::test_state_with_lightning(Arc::new(StalledLightning(shared.clone())));
    let router = common::test_router(state.clone());
    for token in [None, Some("Bearer invalid".to_owned())] {
        let mut request = Request::builder().uri("/api/v1/status");
        if let Some(token) = token {
            request = request.header("Authorization", token);
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let token = auth::create_token(
        &state.identity.node_id().to_hex(),
        &state.jwt_secret,
        vec![Scope::Receive],
    )
    .unwrap();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .header("Authorization", common::auth_header(&state))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let status: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status["offline_safety"], fixture);
    assert_eq!(
        serde_json::to_value(&*shared.read().unwrap()).unwrap(),
        fixture
    );
    assert_eq!(status["money_ready"], false);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let health: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(health.get("offline_safety").is_none());
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/status")
                .header("Authorization", common::auth_header(&state))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}
