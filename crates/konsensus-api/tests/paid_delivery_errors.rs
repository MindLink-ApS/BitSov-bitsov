#![allow(dead_code)]
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use konsensus_core::traits::lightning::LightningProvider;
use konsensus_core::{NodeIdentity, Recipient};
use konsensus_storage::{SqliteStorage, Storage};
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn file_and_calendar_queue_failures_report_settlement_and_preserve_reconcilable_envelope() {
    use konsensus_lightning::shared_mock::SharedMockProvider;
    for action in [
        "file",
        "calendar",
        "update",
        "rsvp",
        "calendar_fanout",
        "update_fanout",
    ] {
        for failure in ["INSERT", "UPDATE"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("sender.sqlite");
            let db = Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
            // Supply calendar content tables for this fixture; core migrations do not create them.
            sqlx::raw_sql("CREATE TABLE calendar_events (id TEXT PRIMARY KEY, message_id TEXT, organizer TEXT NOT NULL, title TEXT NOT NULL, description TEXT, start_ms BIGINT, end_ms BIGINT, tz TEXT, location TEXT, attendees_json TEXT, recurrence_json TEXT, color TEXT, created_at TEXT NOT NULL DEFAULT '', parent_id TEXT)").execute(db.pool()).await.unwrap();
            let ledger = dir.path().join("payments.sqlite");
            let payer = Arc::new(SharedMockProvider::new(&ledger, "a", 10000).unwrap());
            let payee = Arc::new(SharedMockProvider::new(&ledger, "b", 0).unwrap());
            let mut state = common::test_state_with_lightning(payer.clone());
            let (_, identity) = NodeIdentity::generate().unwrap();
            let peer = *identity.node_id();
            let (_, first_identity) = NodeIdentity::generate().unwrap();
            let first_peer = *first_identity.node_id();
            let fanout = action.ends_with("_fanout");
            let spent = if fanout { 2000 } else { 1000 };
            let attendees = if fanout {
                vec![first_peer.to_hex(), peer.to_hex()]
            } else {
                vec![peer.to_hex()]
            };
            let invoice_index = std::sync::atomic::AtomicUsize::new(0);
            let transport = Arc::new(
                common::ConnectedStubTransport::new(
                    vec![peer, first_peer],
                    state.invoice_requests.clone(),
                )
                .with_invoice_responder(move |_, amount| {
                    let invoice =
                        futures::executor::block_on(payee.create_invoice(amount, "delivery", 60))
                            .unwrap();
                    Some(konsensus_api::state::InvoiceResponseData {
                        recipient: if fanout
                            && invoice_index.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
                        {
                            first_peer
                        } else {
                            peer
                        },
                        bolt11: invoice.bolt11,
                        payment_hash: invoice.payment_hash,
                    })
                }),
            );
            let mutable = Arc::get_mut(&mut state).unwrap();
            mutable.transport = transport.clone();
            mutable.storage = db.clone();
            mutable.pricing = Arc::new(konsensus_pricing::StaticPricingEngine::new(
                konsensus_pricing::StaticPricingConfig {
                    calendar_msat: 1000,
                    file_ref_msat: 1000,
                    ..Default::default()
                },
            ));
            let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
            state
                .session_manager
                .initiate_session(&peer, &target.prekey_bundle().await)
                .await
                .unwrap();
            let first_target = konsensus_crypto::SessionManager::new(Arc::new(first_identity));
            state
                .session_manager
                .initiate_session(&first_peer, &first_target.prekey_bundle().await)
                .await
                .unwrap();
            let token = common::auth_header(&state);
            let app = common::test_router(state.clone());
            let req = |method: &str, uri: &str, body: serde_json::Value| {
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("authorization", &token)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            };
            let (method, uri, body) = if action == "file" {
                let response = app
                    .clone()
                    .oneshot(req(
                        "POST",
                        "/api/v1/files",
                        serde_json::json!({"filename":"f.txt","data_b64":"aGVsbG8="}),
                    ))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let value: serde_json::Value = serde_json::from_slice(
                    &axum::body::to_bytes(response.into_body(), 4096)
                        .await
                        .unwrap(),
                )
                .unwrap();
                (
                    "POST",
                    format!("/api/v1/files/{}/send", value["file_id"].as_str().unwrap()),
                    serde_json::json!({"recipient":peer.to_hex(),"max_total_msat":1000}),
                )
            } else {
                db.store_calendar_event(&konsensus_storage::CalendarEventRecord {
                    id: "event".into(),
                    message_id: None,
                    organizer: state.identity.node_id().to_hex(),
                    title: "test".into(),
                    description: None,
                    start_ms: 1000,
                    end_ms: 2000,
                    tz: "UTC".into(),
                    location: None,
                    attendees_json: serde_json::json!(attendees).to_string(),
                    recurrence_json: None,
                    color: None,
                    created_at: String::new(),
                    parent_id: None,
                })
                .await
                .unwrap();
                match action {
                    "calendar" | "calendar_fanout" => (
                        "POST",
                        "/api/v1/calendar/events".into(),
                        serde_json::json!({"title":"test","start":1000,"end":2000,"attendees":attendees}),
                    ),
                    "update" | "update_fanout" => (
                        "PUT",
                        "/api/v1/calendar/events/event".into(),
                        serde_json::json!({"title":"changed"}),
                    ),
                    _ => (
                        "POST",
                        "/api/v1/calendar/events/event/rsvp".into(),
                        serde_json::json!({"organizer":peer.to_hex(),"response":"accepted"}),
                    ),
                }
            };
            sqlx::query(&format!("CREATE TRIGGER fail_prepare BEFORE {failure} ON pending_deliveries WHEN NEW.recipient_id = '{}' BEGIN SELECT RAISE(ABORT, 'injected queue failure'); END", peer.to_hex())).execute(db.pool()).await.unwrap();
            let response = app.oneshot(req(method, &uri, body)).await.unwrap();
            let status = response.status();
            let json: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                payer.get_balance_msat().await.unwrap(),
                10000 - spent,
                "{action} {failure}: {json}"
            );
            assert_eq!(
                status,
                StatusCode::BAD_GATEWAY,
                "{action} {failure}: {json}"
            );
            assert_eq!(json["code"], "payment_settled_send_incomplete");
            assert_eq!(json["amount_msat"], spent);
            assert_eq!(
                transport.sent_envelopes.lock().unwrap().len(),
                usize::from(fanout)
            );
            let stored = db
                .get_messages_for_recipient(&Recipient::Node(peer), 10, None)
                .await
                .unwrap();
            assert_eq!(stored.len(), 1);
            let envelope = &stored[0];
            assert!(
                json["error"]
                    .as_str()
                    .unwrap()
                    .contains(&envelope.id.to_hex()),
                "the error identifies the saved paid envelope for reconciliation"
            );
            sqlx::query("DROP TRIGGER fail_prepare")
                .execute(db.pool())
                .await
                .unwrap();
            // Restart/reconcile the already-paid identity, without a second API POST.
            let reopened = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
            assert_eq!(
                reopened.get_message(&envelope.id).await.unwrap().unwrap(),
                *envelope
            );
            reopened
                .prepare_delivery(&envelope.id, &peer)
                .await
                .unwrap();
            assert_eq!(
                reopened.count_pending_deliveries().await.unwrap(),
                if fanout { 2 } else { 1 }
            );
            assert_eq!(payer.get_balance_msat().await.unwrap(), 10000 - spent);
        }
    }
}
