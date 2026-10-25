//! Owner-API side of the inbound calendar caps: a create, a partial update and
//! an RSVP that attendees' nodes would refuse are refused here first, before
//! anything is stored, any ratchet advances or any payment is dispatched.

mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use konsensus_api::state::AppState;
use konsensus_core::payloads::calendar::{
    MAX_ATTENDEES, MAX_DESCRIPTION_BYTES, MAX_RECURRENCE_INSTANCES, MAX_RSVP_COMMENT_BYTES,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

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
    let bytes = axum::body::to_bytes(response.into_body(), 100_000)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(json!({"raw": String::from_utf8_lossy(&bytes)})),
    )
}

async fn ratchet_unused(state: &AppState, peer: &konsensus_core::NodeId) -> bool {
    state
        .session_manager
        .encrypt(peer, b"probe")
        .await
        .unwrap()
        .header
        .message_number
        == 0
}

fn state_and_peer() -> (Arc<AppState>, Arc<CountingLightning>) {
    let lightning = Arc::new(CountingLightning::default());
    let state = test_state_with_lightning(lightning.clone());
    (state, lightning)
}

async fn refused(state: &Arc<AppState>, method: &str, path: &str, body: Value, code: &str) {
    let (status, result) = request(state, method, path, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
    let error = result["error"].as_str().unwrap_or_default();
    assert!(
        error.starts_with(&format!("{code}: ")),
        "expected {code}, got {result}"
    );
}

/// Over-cap creates fail before storage, ratchet use or payment.
#[tokio::test]
async fn over_cap_create_is_refused_before_storage_and_payment() {
    let (state, lightning) = state_and_peer();
    let peer = setup_e2ee_session(&state.session_manager).await;
    let base = json!({
        "title": "Standup", "start": 1_700_000_000_000u64, "end": 1_700_003_600_000u64,
        "tz": "UTC", "attendees": [peer.to_hex()],
    });
    let cases = [
        (
            "description",
            json!("d".repeat(MAX_DESCRIPTION_BYTES + 1)),
            "calendar_field_too_long",
        ),
        (
            "recurrence",
            json!({"freq": "DAILY", "count": MAX_RECURRENCE_INSTANCES + 1}),
            "calendar_recurrence_too_large",
        ),
        (
            "recurrence",
            json!({"freq": "DAILY", "interval": 0}),
            "calendar_recurrence_invalid",
        ),
        (
            "recurrence",
            json!({"freq": "HOURLY"}),
            "calendar_recurrence_invalid",
        ),
    ];
    for (field, value, code) in cases {
        let mut body = base.clone();
        body[field] = value;
        refused(&state, "POST", "/api/v1/calendar/events", body, code).await;
    }
    // One over the attendee cap is refused by the request check with the same cap.
    let mut body = base.clone();
    body["attendees"] = json!(vec![peer.to_hex(); MAX_ATTENDEES + 1]);
    let (status, result) = request(&state, "POST", "/api/v1/calendar/events", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
    assert!(result["error"]
        .as_str()
        .unwrap()
        .contains(&MAX_ATTENDEES.to_string()));

    assert!(state
        .storage
        .list_calendar_events_in_range(0, u64::MAX, 100)
        .await
        .unwrap()
        .is_empty());
    assert!(ratchet_unused(&state, &peer).await);
    assert_eq!(lightning.money(), 0);
    assert_eq!(lightning.invoices(), 0);

    // The same event inside the caps passes the cap check: it is stored locally
    // before delivery, and the stub transport's offline answer is not a cap code.
    let (_, result) = request(&state, "POST", "/api/v1/calendar/events", base).await;
    assert!(
        !cap_code(&result),
        "in-cap create refused by the caps: {result}"
    );
    assert_eq!(
        state
            .storage
            .list_calendar_events_in_range(0, u64::MAX, 100)
            .await
            .unwrap()
            .len(),
        1
    );
}

fn cap_code(result: &Value) -> bool {
    result["error"]
        .as_str()
        .is_some_and(|e| e.starts_with("calendar_"))
}

/// A partial update that keeps the stored recurrence but moves the start so the
/// retained `UNTIL` series would exceed the cap is refused, and the stored
/// record is untouched. The same move with the recurrence replaced by an in-cap
/// one is accepted.
#[tokio::test]
async fn partial_update_retaining_recurrence_is_checked_against_the_new_start() {
    let (state, lightning) = state_and_peer();
    let peer = setup_e2ee_session(&state.session_manager).await;
    let start = 1_700_000_000_000u64;
    // Daily until 4000 days after the start: 4001 instances, inside the cap.
    let until = start + 4_000 * DAY_MS;
    let record = konsensus_storage::calendar::CalendarEventRecord {
        id: "retained-rule".into(),
        message_id: None,
        organizer: state.identity.node_id().to_hex(),
        title: "Daily".into(),
        description: None,
        start_ms: start,
        end_ms: start + 3_600_000,
        tz: "UTC".into(),
        location: None,
        attendees_json: json!([peer.to_hex()]).to_string(),
        recurrence_json: Some(json!({"freq": "DAILY", "until": until}).to_string()),
        color: None,
        created_at: String::new(),
        parent_id: None,
    };
    state.storage.store_calendar_event(&record).await.unwrap();

    // Moving the start 2000 days earlier makes the retained rule imply 6001.
    let earlier = start - 2_000 * DAY_MS;
    refused(
        &state,
        "PUT",
        "/api/v1/calendar/events/retained-rule",
        json!({"start": earlier, "end": earlier + 3_600_000}),
        "calendar_recurrence_too_large",
    )
    .await;
    let saved = state
        .storage
        .get_calendar_event("retained-rule")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.start_ms, start, "refused update must not be stored");
    assert_eq!(saved.recurrence_json, record.recurrence_json);
    assert!(ratchet_unused(&state, &peer).await);
    assert_eq!(lightning.money(), 0);

    // Moving the start later shrinks the retained series: past the caps and
    // stored (the stub transport's offline answer is not a cap code).
    let later = start + 1_000 * DAY_MS;
    let (_, result) = request(
        &state,
        "PUT",
        "/api/v1/calendar/events/retained-rule",
        json!({"start": later, "end": later + 3_600_000}),
    )
    .await;
    assert!(
        !cap_code(&result),
        "in-cap update refused by the caps: {result}"
    );
    let saved = state
        .storage
        .get_calendar_event("retained-rule")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.start_ms, later);
    assert_eq!(
        saved.recurrence_json, record.recurrence_json,
        "partial update keeps the rule"
    );
}

/// An RSVP comment over its cap is refused before the ratchet or a payment.
#[tokio::test]
async fn over_cap_rsvp_is_refused_before_ratchet_and_payment() {
    let (state, lightning) = state_and_peer();
    let organizer = setup_e2ee_session(&state.session_manager).await;
    refused(
        &state,
        "POST",
        "/api/v1/calendar/events/evt-1/rsvp",
        json!({
            "response": "accepted", "organizer": organizer.to_hex(),
            "comment": "c".repeat(MAX_RSVP_COMMENT_BYTES + 1),
        }),
        "calendar_field_too_long",
    )
    .await;
    assert!(ratchet_unused(&state, &organizer).await);
    assert_eq!(lightning.money(), 0);
    assert_eq!(lightning.invoices(), 0);

    let (_, result) = request(
        &state,
        "POST",
        "/api/v1/calendar/events/evt-1/rsvp",
        json!({"response": "accepted", "organizer": organizer.to_hex(), "comment": "see you"}),
    )
    .await;
    assert!(
        !cap_code(&result),
        "in-cap RSVP refused by the caps: {result}"
    );
}
