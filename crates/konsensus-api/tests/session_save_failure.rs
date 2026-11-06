//! When the save of an advanced send chain fails, the ciphertext is withheld and
//! no payment starts for it. Each encrypt site in the API reports that in its own
//! class. These are per-site results: earlier recipients of a fan-out keep theirs.
#![allow(dead_code)]
mod common;
use axum::{body::Body, http::{Request, StatusCode}};
use common::*;
use konsensus_api::state::AppState;
use konsensus_core::types::NodeId;
use konsensus_crypto::SessionManager;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const OTHER: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

struct Fx {
    state: Arc<AppState>,
    store: Arc<FlakySessionStore>,
    peer: NodeId,
    other: NodeId,
    lightning: Arc<CountingLightning>,
    transport: Arc<ConnectedStubTransport>,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(konsensus_storage::SqliteStorage::open(dir.path().join("node.sqlite").to_str().unwrap()).await.unwrap());
    sqlx::raw_sql("CREATE TABLE calendar_events (id TEXT PRIMARY KEY, message_id TEXT, organizer TEXT NOT NULL, title TEXT NOT NULL, description TEXT, start_ms BIGINT, end_ms BIGINT, tz TEXT, location TEXT, attendees_json TEXT, recurrence_json TEXT, color TEXT, created_at TEXT NOT NULL DEFAULT '', parent_id TEXT)").execute(db.pool()).await.unwrap();
    let lightning = Arc::new(CountingLightning::default());
    let mut state = test_state_with_lightning(lightning.clone());
    let store = Arc::new(FlakySessionStore::default());
    let sessions = Arc::new(SessionManager::with_store(state.identity.clone(), store.clone()));
    let peer = setup_e2ee_session(&sessions).await;
    let other = setup_e2ee_session_with_mnemonic(&sessions, OTHER).await;
    let transport = Arc::new(ConnectedStubTransport::new(vec![peer, other], state.invoice_requests.clone()));
    let inner = Arc::get_mut(&mut state).unwrap();
    inner.session_manager = sessions;
    inner.transport = transport.clone();
    inner.storage = db;
    inner.pricing = Arc::new(konsensus_pricing::StaticPricingEngine::new(konsensus_pricing::StaticPricingConfig {
        calendar_msat: 1000,
        ..Default::default()
    }));
    state.peer_ln_pubkeys.lock().await.insert(
        peer,
        konsensus_api::state::PeerLightningKey::Verified("02aaaa".repeat(5)),
    );
    state.peer_ln_pubkeys.lock().await.insert(
        other,
        konsensus_api::state::PeerLightningKey::Verified("02bbbb".repeat(5)),
    );
    Fx { state, store, peer, other, lightning, transport, _dir: dir }
}

impl Fx {
    async fn call(&self, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let response = test_router(self.state.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", auth_header(&self.state))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 100_000).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(json!({"raw": String::from_utf8_lossy(&bytes)})))
    }

    fn nothing_paid_or_sent(&self) {
        assert_eq!((self.lightning.money(), self.lightning.invoices()), (0, 0), "no payment started");
        assert!(self.transport.sent_envelopes.lock().unwrap().is_empty(), "no envelope left");
    }

    /// The position the next send takes on this peer's chain.
    async fn next_position(&self, peer: &NodeId) -> u32 {
        self.state.session_manager.encrypt(peer, b"probe").await.unwrap().header.message_number
    }
}

/// The code the app already treats as proven unpaid, with its own reason.
fn assert_refused_unpaid(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "not_dispatched", "{body}");
    assert_eq!(body["reason"], "session_save_failed", "{body}");
}

async fn stored_event(fx: &Fx, attendees: &[NodeId]) {
    fx.state.storage.store_calendar_event(&konsensus_storage::CalendarEventRecord {
        id: "event".into(),
        message_id: None,
        organizer: fx.state.identity.node_id().to_hex(),
        title: "before".into(),
        description: None,
        start_ms: 1000,
        end_ms: 2000,
        tz: "UTC".into(),
        location: None,
        attendees_json: serde_json::to_string(&attendees.iter().map(|a| a.to_hex()).collect::<Vec<_>>()).unwrap(),
        recurrence_json: None,
        color: None,
        created_at: String::new(),
        parent_id: None,
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn chat_is_refused_unpaid_and_the_same_send_works_after_the_save_recovers() {
    let fx = fixture().await;
    let operation = uuid::Uuid::new_v4().to_string();
    let request = json!({"operation_id": operation, "recipient": fx.peer.to_hex(), "kind": 0, "plaintext": "hello", "max_total_msat": 2000, "max_routing_fee_msat": 1000});
    fx.store.fail_all(true);
    let (status, body) = fx.call("POST", "/api/v1/messages/compose", request).await;
    assert_refused_unpaid(status, &body);
    assert_eq!(body["state"], "released", "the operation is released, not left unknown: {body}");
    fx.nothing_paid_or_sent();

    fx.store.fail_all(false);
    let request = json!({"recipient": fx.peer.to_hex(), "kind": 0, "plaintext": "hello", "max_total_msat": 2000, "max_routing_fee_msat": 1000});
    let (status, body) = fx.call("POST", "/api/v1/messages/compose", request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.lightning.money(), 1);
    assert_eq!(fx.transport.sent_envelopes.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn file_send_is_refused_unpaid() {
    let fx = fixture().await;
    let (_, file) = fx.call("POST", "/api/v1/files", json!({"filename": "hi.txt", "mime_type": "text/plain", "data_b64": "aGk="})).await;
    fx.store.fail_all(true);
    let path = format!("/api/v1/files/{}/send", file["file_id"].as_str().unwrap());
    let (status, body) = fx.call("POST", &path, json!({"recipient": fx.peer.to_hex(), "max_total_msat": 2000, "max_routing_fee_msat": 1000})).await;
    assert_refused_unpaid(status, &body);
    fx.nothing_paid_or_sent();
}

/// A room reports per member. The member whose save fails is refused with nothing
/// paid to it. The member that went first keeps its settled payment, so this is no
/// statement about the whole operation.
#[tokio::test]
async fn room_member_is_refused_unpaid_and_the_other_member_keeps_its_result() {
    let fx = fixture().await;
    let (_, room) = fx.call("POST", "/api/v1/rooms", json!({"name": "save"})).await;
    let id = room["id"].as_str().unwrap();
    for member in [fx.peer, fx.other] {
        assert_eq!(fx.call("POST", &format!("/api/v1/rooms/{id}/members"), json!({"node_id": member.to_hex()})).await.0, StatusCode::OK);
    }
    fx.store.fail_peer(Some(fx.other));
    let (status, receipt) = fx.call("POST", "/api/v1/messages/compose", json!({
        "recipient": id, "is_room": true, "kind": 100, "plaintext": "room", "max_total_msat": 4000, "max_routing_fee_msat": 1000,
        "max_recipient_msat": {fx.peer.to_hex(): 2000, fx.other.to_hex(): 2000},
    })).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    let rows = receipt["member_outcomes"].as_array().unwrap();
    let row = |member: NodeId| rows.iter().find(|r| r["recipient"] == member.to_hex()).unwrap();
    assert_eq!(row(fx.other)["status"], "refused", "{receipt}");
    assert_eq!(row(fx.other)["amount_msat"], 0, "{receipt}");
    assert!(row(fx.other).to_string().contains("could not be saved"), "{receipt}");
    assert_eq!(row(fx.peer)["status"], "settled", "{receipt}");
    assert_eq!(fx.lightning.money(), 1, "only the other member was paid");
    fx.store.fail_peer(None);
    assert_eq!(fx.next_position(&fx.other).await, 0, "the failed member's chain was put back");
}

/// A new event's fan-out: the attendee whose save fails is listed as not delivered
/// and not paid; the other attendee is paid.
#[tokio::test]
async fn calendar_create_skips_the_attendee_whose_save_failed_unpaid() {
    let fx = fixture().await;
    fx.store.fail_peer(Some(fx.other));
    let (status, body) = fx.call("POST", "/api/v1/calendar/events", json!({
        "title": "save", "start": 1000, "end": 2000, "attendees": [fx.peer.to_hex(), fx.other.to_hex()],
    })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["queued_for"], json!([fx.other.to_hex()]), "{body}");
    assert_eq!(fx.lightning.money(), 1, "only the other attendee was paid");
    let sent = fx.transport.sent_envelopes.lock().unwrap();
    assert!(sent.iter().all(|(to, _)| *to == fx.peer), "nothing left for the attendee whose save failed");
}

#[tokio::test]
async fn calendar_update_skips_the_attendee_whose_save_failed_unpaid() {
    let fx = fixture().await;
    stored_event(&fx, &[fx.peer, fx.other]).await;
    fx.store.fail_peer(Some(fx.other));
    let (status, body) = fx.call("PUT", "/api/v1/calendar/events/event", json!({"title": "after"})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["queued_for"], json!([fx.other.to_hex()]), "{body}");
    assert_eq!(fx.lightning.money(), 1, "only the other attendee was paid");
}

#[tokio::test]
async fn calendar_rsvp_is_refused_unpaid() {
    let fx = fixture().await;
    stored_event(&fx, &[]).await;
    fx.store.fail_all(true);
    let (status, body) = fx.call("POST", "/api/v1/calendar/events/event/rsvp", json!({"organizer": fx.peer.to_hex(), "response": "accepted"})).await;
    assert_refused_unpaid(status, &body);
    fx.nothing_paid_or_sent();
}
