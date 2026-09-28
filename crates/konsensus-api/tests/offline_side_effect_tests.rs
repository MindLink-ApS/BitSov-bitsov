//! Offline money routes must refuse before pricing or local mutations.
mod common;
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use konsensus_api::state::AppState;
use konsensus_core::traits::lightning::*;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

struct Offline;
#[async_trait]
impl LightningProvider for Offline {
    async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
        panic!("offline invoice dispatch")
    }
    async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        panic!("offline payment dispatch")
    }
    async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::NotReady)
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Err(LightningError::NotReady)
    }
    async fn is_available(&self) -> bool {
        false
    }
}

async fn request(
    state: &Arc<AppState>,
    method: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = test_router(state.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", auth_header(state))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 100000)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(json!({"raw":String::from_utf8_lossy(&bytes)})),
    )
}

#[tokio::test]
async fn offline_file_refusal_must_preserve_staged_upload() {
    let state = test_state_with_lightning(Arc::new(Offline));
    let peer = setup_e2ee_session(&state.session_manager).await;
    let (status, uploaded) = request(
        &state,
        "POST",
        "/api/v1/files",
        json!({"filename":"offline.txt","data_b64":"aGVsbG8="}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{uploaded}");
    let id = uploaded["file_id"].as_str().unwrap();
    assert!(id.starts_with("stage-"));
    let path = format!("/api/v1/files/{id}");
    let (status, refused) = request(
        &state,
        "POST",
        &format!("{path}/send"),
        json!({"recipient":peer.to_hex()}),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refused}");
    assert_eq!(refused["code"], "not_ready");
    let (status, file) = request(&state, "GET", &path, Value::Null).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "offline refusal deleted the staged file: {file}"
    );
    assert_eq!(file["filename"], "offline.txt");
    assert_ratchet_unused(&state, &peer).await;
}

#[tokio::test]
async fn offline_calendar_without_session_must_return_not_ready() {
    let state = test_state_with_lightning(Arc::new(Offline));
    let (status, result) = request(
        &state,
        "POST",
        "/api/v1/calendar/events",
        json!({"title":"offline","start":1000,"end":2000,"attendees":["ab".repeat(32)]}),
    )
    .await;
    assert!(
        state
            .storage
            .list_calendar_events_in_range(0, 3000, 10)
            .await
            .unwrap()
            .is_empty(),
        "offline creation persisted an event"
    );
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "offline paid calendar operation succeeded: {result}"
    );
    assert_eq!(result["code"], "not_ready");
}

#[tokio::test]
async fn offline_calendar_update_must_not_mutate_before_refusal() {
    let state = test_state_with_lightning(Arc::new(Offline));
    let peer = setup_e2ee_session(&state.session_manager).await;
    let record = konsensus_storage::calendar::CalendarEventRecord {
        id: "offline-event".into(),
        message_id: None,
        organizer: state.identity.node_id().to_hex(),
        title: "original title".into(),
        description: None,
        start_ms: 1000,
        end_ms: 2000,
        tz: "UTC".into(),
        location: None,
        attendees_json: json!([peer.to_hex()]).to_string(),
        recurrence_json: None,
        color: None,
        created_at: String::new(),
        parent_id: None,
    };
    state.storage.store_calendar_event(&record).await.unwrap();
    let (status, result) = request(
        &state,
        "PUT",
        "/api/v1/calendar/events/offline-event",
        json!({"title":"changed despite offline"}),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{result}");
    assert_eq!(result["code"], "not_ready");
    let saved = state
        .storage
        .get_calendar_event(&record.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        saved.title, record.title,
        "offline calendar refusal committed an unsent update"
    );
    assert_ratchet_unused(&state, &peer).await;
}

struct PendingPricing;
#[async_trait]
impl konsensus_core::traits::pricing::PricingEngine for PendingPricing {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get_price_msat(
        &self,
        _: u16,
    ) -> Result<u64, konsensus_core::traits::pricing::PricingError> {
        std::future::pending().await
    }
    async fn get_category_price_msat(
        &self,
        _: konsensus_core::kind::KindCategory,
    ) -> Result<u64, konsensus_core::traits::pricing::PricingError> {
        std::future::pending().await
    }
}
#[tokio::test]
async fn offline_file_must_not_await_unavailable_dynamic_pricing() {
    let mut state = test_state_with_lightning(Arc::new(Offline));
    let peer = setup_e2ee_session(&state.session_manager).await;
    Arc::get_mut(&mut state).unwrap().pricing = Arc::new(PendingPricing);
    let (status, uploaded) = request(
        &state,
        "POST",
        "/api/v1/files",
        json!({"filename":"offline.txt","data_b64":"aGVsbG8="}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{uploaded}");
    let path = format!(
        "/api/v1/files/{}/send",
        uploaded["file_id"].as_str().unwrap()
    );
    let response = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        request(&state, "POST", &path, json!({"recipient":peer.to_hex()})),
    )
    .await;
    assert!(
        response.is_ok(),
        "offline money request waited for chain pricing instead of returning not_ready"
    );
    let (status, body) = response.unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "not_ready");
}

#[tokio::test]
async fn offline_full_onboarding_must_return_not_ready() {
    let provider = konsensus_lightning::RecoveringLightning::new(
        || async {
            Err(LightningError::ChainSourceUnavailable {
                network: "bitcoin".into(),
                service: "localhost".into(),
                attempts: 5,
                elapsed_ms: 60_000,
                cause: "unavailable".into(),
            })
        },
        Default::default(),
    )
    .await
    .unwrap();
    let provider = Arc::new(provider);
    let state = test_state_with_lightning(provider.clone());
    let result = request(
        &state,
        "POST",
        "/api/v1/onboarding/start",
        json!({"tier":"full","funding_amount_sats":10000}),
    )
    .await;
    provider.shutdown().await.unwrap();
    assert_eq!(result.0, StatusCode::SERVICE_UNAVAILABLE, "{result:?}");
    assert_eq!(result.1["code"], "not_ready");
    assert!(state
        .storage
        .get_onboarding_state()
        .await
        .unwrap()
        .is_none());
}

async fn assert_ratchet_unused(state: &AppState, peer: &konsensus_core::NodeId) {
    let first = state
        .session_manager
        .encrypt(peer, b"first actual send")
        .await
        .unwrap();
    assert_eq!(
        first.header.message_number, 0,
        "offline refusal advanced the ratchet"
    );
}

#[tokio::test]
async fn offline_calendar_with_session_must_not_persist_or_encrypt() {
    let state = test_state_with_lightning(Arc::new(Offline));
    let peer = setup_e2ee_session(&state.session_manager).await;
    let (status, result) = request(
        &state,
        "POST",
        "/api/v1/calendar/events",
        json!({
            "title":"offline", "start":1000, "end":2000, "attendees":[peer.to_hex()]
        }),
    )
    .await;
    assert!(state
        .storage
        .list_calendar_events_in_range(0, 3000, 10)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{result}");
    assert_eq!(result["code"], "not_ready");
    assert_ratchet_unused(&state, &peer).await;
}

#[tokio::test]
async fn offline_calendar_rsvp_must_not_advance_ratchet() {
    let state = test_state_with_lightning(Arc::new(Offline));
    let peer = setup_e2ee_session(&state.session_manager).await;
    let (status, result) = request(
        &state,
        "POST",
        "/api/v1/calendar/events/offline-event/rsvp",
        json!({
            "response":"accepted", "organizer":peer.to_hex()
        }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{result}");
    assert_eq!(result["code"], "not_ready");
    assert_ratchet_unused(&state, &peer).await;
}

#[tokio::test]
async fn offline_calendar_must_not_await_unavailable_dynamic_pricing() {
    for method in ["create", "update", "rsvp"] {
        let mut state = test_state_with_lightning(Arc::new(Offline));
        let peer = setup_e2ee_session(&state.session_manager).await;
        Arc::get_mut(&mut state).unwrap().pricing = Arc::new(PendingPricing);
        let record = konsensus_storage::calendar::CalendarEventRecord {
            id: "offline-event".into(),
            message_id: None,
            organizer: state.identity.node_id().to_hex(),
            title: "original title".into(),
            description: None,
            start_ms: 1000,
            end_ms: 2000,
            tz: "UTC".into(),
            location: None,
            attendees_json: json!([peer.to_hex()]).to_string(),
            recurrence_json: None,
            color: None,
            created_at: String::new(),
            parent_id: None,
        };
        state.storage.store_calendar_event(&record).await.unwrap();
        let (verb, path, body) = match method {
            "create" => (
                "POST",
                "/api/v1/calendar/events",
                json!({
                    "title":"offline", "start":1000, "end":2000, "attendees":[peer.to_hex()]
                }),
            ),
            "update" => (
                "PUT",
                "/api/v1/calendar/events/offline-event",
                json!({"title":"changed"}),
            ),
            _ => (
                "POST",
                "/api/v1/calendar/events/offline-event/rsvp",
                json!({
                    "response":"accepted", "organizer":peer.to_hex()
                }),
            ),
        };
        let (status, result) = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            request(&state, verb, path, body),
        )
        .await
        .expect("offline calendar waited for pricing");
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{method}: {result}"
        );
        assert_eq!(result["code"], "not_ready");
        let events = state
            .storage
            .list_calendar_events_in_range(0, 3000, 10)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].title, "original title");
        assert_ratchet_unused(&state, &peer).await;
    }
}

#[tokio::test]
async fn offline_light_onboarding_remains_local() {
    let state = test_state_with_lightning(Arc::new(Offline));
    let (status, result) = request(
        &state,
        "POST",
        "/api/v1/onboarding/start",
        json!({"tier":"light"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    let saved = state.storage.get_onboarding_state().await.unwrap().unwrap();
    assert_eq!(saved.tier.as_deref(), Some("light"));
    assert_eq!(saved.current_step, "connecting");
}
