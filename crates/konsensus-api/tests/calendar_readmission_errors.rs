#![allow(dead_code)]
#[path = "common/mod.rs"]
mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use konsensus_api::state::{InvoiceRequestOutcome, InvoiceResponseData, InvoiceResponseError};
use konsensus_core::{
    traits::{
        lightning::LightningProvider,
        transport::{MessageTransport, TransportError},
    },
    NodeId, NodeIdentity, Recipient, UkmEnvelope,
};
use konsensus_lightning::shared_mock::SharedMockProvider;
use konsensus_storage::{SqliteStorage, Storage};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};
use tower::ServiceExt;

// Authenticated-peer transport fixture. Only the invoice exchange/admission delivery
// is stubbed: the real API, real settlement ledger, and SQLite failures are exercised.
struct ReadmitTransport {
    peer: NodeId,
    earlier_peer: NodeId,
    payee: Arc<SharedMockProvider>,
    pending: Arc<
        tokio::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<InvoiceRequestOutcome>>>,
    >,
    admitted: AtomicBool,
    proofs: AtomicUsize,
    refusals: AtomicUsize,
}
#[async_trait::async_trait]
impl MessageTransport for ReadmitTransport {
    async fn send(&self, peer: &NodeId, env: &UkmEnvelope) -> Result<(), TransportError> {
        if *peer == self.earlier_peer {
            return Ok(());
        }
        assert_eq!(*peer, self.peer);
        assert_eq!(env.ciphertext, b"konsensus:admission:v1");
        self.proofs.fetch_add(1, Ordering::SeqCst);
        self.admitted.store(true, Ordering::SeqCst);
        Ok(())
    }
    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        futures::future::pending().await
    }
    async fn connect(&self, _: &NodeId, _: &str) -> Result<(), TransportError> {
        Ok(())
    }
    async fn disconnect(&self, _: &NodeId) -> Result<(), TransportError> {
        Ok(())
    }
    async fn is_connected(&self, peer: &NodeId) -> bool {
        *peer == self.peer || *peer == self.earlier_peer
    }
    async fn connected_peers(&self) -> Vec<NodeId> {
        vec![self.peer, self.earlier_peer]
    }
    async fn send_raw_frame(&self, peer: &NodeId, bytes: &[u8]) -> Result<(), TransportError> {
        let konsensus_message::wire::Frame::RequestInvoice {
            request_id,
            amount_msat,
            purpose,
        } = konsensus_message::wire::Frame::from_bytes(bytes).unwrap()
        else {
            panic!("unexpected frame");
        };
        assert!(*peer == self.peer || *peer == self.earlier_peer);
        let admission = purpose.starts_with("konsensus:admission:");
        let result = if *peer == self.peer && !admission && !self.admitted.load(Ordering::SeqCst) {
            self.refusals.fetch_add(1, Ordering::SeqCst);
            Err(InvoiceResponseError {
                recipient: self.peer,
                reason: konsensus_api::invoice_refusal::ADMISSION_REQUIRED.into(),
            })
        } else {
            let description = if admission {
                format!("konsensus:{request_id}:message=1000")
            } else {
                "calendar".into()
            };
            // Shorter TTL stays inside request-bound 60s admission lifetime.
            let invoice = self
                .payee
                .create_invoice(amount_msat, &description, 55)
                .await
                .unwrap();
            Ok(InvoiceResponseData {
                recipient: *peer,
                bolt11: invoice.bolt11,
                payment_hash: invoice.payment_hash,
            })
        };
        self.pending
            .lock()
            .await
            .remove(&request_id)
            .unwrap()
            .send(result)
            .unwrap();
        Ok(())
    }
}

#[tokio::test]
async fn calendar_readmission_queue_error_reports_all_settled_principal() {
    for action in ["create", "update", "rsvp", "create_fanout", "update_fanout"] {
        for fault in ["INSERT", "UPDATE"] {
            let fanout = action.ends_with("fanout");
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("sender.sqlite");
            let db = Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
            sqlx::raw_sql("CREATE TABLE calendar_events (id TEXT PRIMARY KEY, message_id TEXT, organizer TEXT NOT NULL, title TEXT NOT NULL, description TEXT, start_ms BIGINT, end_ms BIGINT, tz TEXT, location TEXT, attendees_json TEXT, recurrence_json TEXT, color TEXT, created_at TEXT NOT NULL DEFAULT '', parent_id TEXT)").execute(db.pool()).await.unwrap();
            let ledger = dir.path().join("payments.sqlite");
            let payer = Arc::new(SharedMockProvider::new(&ledger, "payer", 10000).unwrap());
            let payee = Arc::new(SharedMockProvider::new(&ledger, "payee", 0).unwrap());
            let mut state = common::test_state_with_lightning(payer.clone());
            let (_, identity) = NodeIdentity::generate().unwrap();
            let peer = *identity.node_id();
            let (_, earlier_identity) = NodeIdentity::generate().unwrap();
            let earlier_peer = *earlier_identity.node_id();
            let transport = Arc::new(ReadmitTransport {
                peer,
                earlier_peer,
                payee,
                pending: state.invoice_requests.clone(),
                admitted: AtomicBool::new(false),
                proofs: AtomicUsize::new(0),
                refusals: AtomicUsize::new(0),
            });
            let mutable = Arc::get_mut(&mut state).unwrap();
            mutable.storage = db.clone();
            mutable.transport = transport.clone();
            mutable.pricing = Arc::new(konsensus_pricing::StaticPricingEngine::new(
                konsensus_pricing::StaticPricingConfig {
                    calendar_msat: 1000,
                    ..Default::default()
                },
            ));
            let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
            state
                .session_manager
                .initiate_session(&peer, &target.prekey_bundle().await)
                .await
                .unwrap();
            let earlier_target = konsensus_crypto::SessionManager::new(Arc::new(earlier_identity));
            state
                .session_manager
                .initiate_session(&earlier_peer, &earlier_target.prekey_bundle().await)
                .await
                .unwrap();
            let attendees = if fanout {
                vec![earlier_peer.to_hex(), peer.to_hex()]
            } else {
                vec![peer.to_hex()]
            };
            db.store_calendar_event(&konsensus_storage::CalendarEventRecord {
                id: "event".into(),
                message_id: None,
                organizer: state.identity.node_id().to_hex(),
                title: "before".into(),
                description: None,
                start_ms: 1000,
                end_ms: 2000,
                tz: "UTC".into(),
                location: None,
                attendees_json: serde_json::to_string(&attendees).unwrap(),
                recurrence_json: None,
                color: None,
                created_at: String::new(),
                parent_id: None,
            })
            .await
            .unwrap();
            sqlx::raw_sql(&format!("CREATE TRIGGER fail_prepare BEFORE {fault} ON pending_deliveries WHEN NEW.recipient_id = '{}' BEGIN SELECT RAISE(ABORT, 'review queue failure'); END", peer.to_hex())).execute(db.pool()).await.unwrap();
            let (method, uri, body) = match action {
                "update" | "update_fanout" => (
                    "PUT",
                    "/api/v1/calendar/events/event",
                    serde_json::json!({"title":"after"}),
                ),
                "rsvp" => (
                    "POST",
                    "/api/v1/calendar/events/event/rsvp",
                    serde_json::json!({"organizer":peer.to_hex(),"response":"accepted"}),
                ),
                _ => (
                    "POST",
                    "/api/v1/calendar/events",
                    serde_json::json!({"title":"admission accounting","start":1000,"end":2000,"attendees":attendees}),
                ),
            };
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                common::test_router(state.clone()).oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("authorization", common::auth_header(&state))
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            let status = response.status();
            let json: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
            )
            .unwrap();
            let spent = if fanout { 3000 } else { 2000 };
            let actual_principal = 10000 - payer.get_balance_msat().await.unwrap();
            eprintln!("review calendar re-admission: actual_principal={actual_principal}, HTTP={status}, response={json}");
            assert_eq!(transport.refusals.load(Ordering::SeqCst), 1);
            assert_eq!(transport.proofs.load(Ordering::SeqCst), 1);
            assert_eq!(
                actual_principal, spent,
                "admission plus calendar payment settled"
            );
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{json}");
            assert_eq!(json["code"], "payment_settled_send_incomplete");
            // Error accounting includes both settled payments, without inflating the message proof.
            assert_eq!(
                json["amount_msat"], spent,
                "calendar error includes paid admission: {json}"
            );
            if let Some(fee) = json.get("max_routing_fee_msat") {
                assert_eq!(
                    fee,
                    if fanout { 15000 } else { 10000 },
                    "merged response includes both fee ceilings"
                );
            }
            let envelopes = db
                .get_messages_for_recipient(&Recipient::Node(peer), 10, None)
                .await
                .unwrap();
            assert_eq!(envelopes.len(), 1);
            assert_eq!(
                envelopes[0].payment_proof.amount_msat, 1000,
                "admission cannot inflate the message proof"
            );
            assert!(json["error"]
                .as_str()
                .unwrap()
                .contains(&envelopes[0].id.to_hex()));
            sqlx::raw_sql("DROP TRIGGER fail_prepare")
                .execute(db.pool())
                .await
                .unwrap();
            let reopened = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
            reopened
                .prepare_delivery(&envelopes[0].id, &peer)
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
