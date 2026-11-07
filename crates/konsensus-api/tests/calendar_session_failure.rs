mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use konsensus_core::{NodeId, NodeIdentity};
use konsensus_crypto::{SessionManager, SessionStore};
use konsensus_storage::{SqliteStorage, Storage};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;

#[derive(Default)]
struct FailingSessionStore {
    fail_for: Mutex<Option<NodeId>>,
    sessions: tokio::sync::Mutex<HashMap<NodeId, Vec<u8>>>,
}

#[async_trait::async_trait]
impl SessionStore for FailingSessionStore {
    async fn save_session(
        &self,
        peer: &NodeId,
        bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if *self.fail_for.lock().unwrap() == Some(*peer) {
            return Err("injected session save failure".into());
        }
        self.sessions.lock().await.insert(*peer, bytes.to_vec());
        Ok(())
    }
    async fn load_session(
        &self,
        peer: &NodeId,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.sessions.lock().await.get(peer).cloned())
    }
    async fn delete_session(
        &self,
        peer: &NodeId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.sessions.lock().await.remove(peer);
        Ok(())
    }
    async fn list_sessions(&self) -> Result<Vec<NodeId>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.sessions.lock().await.keys().copied().collect())
    }
}

#[tokio::test]
async fn calendar_encryption_failure_is_not_reported_as_queued() {
    calendar_encryption_failure_case(false).await;
}

#[tokio::test]
async fn calendar_encryption_failure_preserves_paid_attendees_and_continues_fanout() {
    calendar_encryption_failure_case(true).await;
}

async fn calendar_encryption_failure_case(mixed: bool) {
    use konsensus_core::traits::lightning::LightningProvider;

    for update in [false, true] {
        for missing_session in [false, true] {
            let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
            sqlx::raw_sql("CREATE TABLE calendar_events (id TEXT PRIMARY KEY, message_id TEXT, organizer TEXT NOT NULL, title TEXT NOT NULL, description TEXT, start_ms BIGINT, end_ms BIGINT, tz TEXT, location TEXT, attendees_json TEXT, recurrence_json TEXT, color TEXT, created_at TEXT NOT NULL DEFAULT '', parent_id TEXT)").execute(db.pool()).await.unwrap();
            let store = Arc::new(FailingSessionStore::default());
            let wallet = Arc::new(
                konsensus_lightning::MockLightningProvider::new().with_routing_fee_msat(400),
            );
            let balance_before = wallet.get_balance_msat().await.unwrap();
            let mut state = common::test_state_with_lightning(wallet.clone());
            let sessions = Arc::new(SessionManager::with_store(
                state.identity.clone(),
                store.clone(),
            ));
            let (_, identity) = NodeIdentity::generate().unwrap();
            let peer = *identity.node_id();
            let recipient = SessionManager::new(Arc::new(identity));
            if !missing_session {
                sessions
                    .initiate_session(&peer, &recipient.prekey_bundle().await)
                    .await
                    .unwrap();
            }
            let mut healthy = Vec::new();
            if mixed {
                for _ in 0..2 {
                    let (_, identity) = NodeIdentity::generate().unwrap();
                    let id = *identity.node_id();
                    let recipient = SessionManager::new(Arc::new(identity));
                    sessions
                        .initiate_session(&id, &recipient.prekey_bundle().await)
                        .await
                        .unwrap();
                    healthy.push(id);
                }
            }
            let attendees = if mixed {
                vec![healthy[0], peer, healthy[1]]
            } else {
                vec![peer]
            };
            let transport = Arc::new(common::ConnectedStubTransport::new(
                attendees.clone(),
                state.invoice_requests.clone(),
            ));
            let mutable = Arc::get_mut(&mut state).unwrap();
            mutable.storage = db.clone();
            mutable.session_manager = sessions;
            mutable.transport = transport.clone();
            for id in &attendees {
                state
                    .peer_ln_pubkeys
                    .lock()
                    .await
                    .insert(*id, format!("02{}", "aa".repeat(32)));
            }
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
                attendees_json: serde_json::json!(attendees
                    .iter()
                    .map(NodeId::to_hex)
                    .collect::<Vec<_>>())
                .to_string(),
                recurrence_json: None,
                color: None,
                created_at: String::new(),
                parent_id: None,
            })
            .await
            .unwrap();
            let before = store.load_session(&peer).await.unwrap();
            *store.fail_for.lock().unwrap() = Some(peer);
            let payload = if update {
                serde_json::json!({"title":"updated"})
            } else {
                serde_json::json!({"title":"test", "start":1000, "end":2000, "attendees":attendees.iter().map(NodeId::to_hex).collect::<Vec<_>>()})
            };
            let request = Request::builder()
                .method(if update { "PUT" } else { "POST" })
                .uri(if update {
                    "/api/v1/calendar/events/event"
                } else {
                    "/api/v1/calendar/events"
                })
                .header("authorization", common::auth_header(&state))
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap();
            let response = common::test_router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "update={update}, missing={missing_session}"
            );
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(body["failed_for"], serde_json::json!([peer.to_hex()]));
            assert_eq!(body["queued_for"], serde_json::json!([]));
            assert_eq!(
                body["delivered_to"],
                serde_json::json!(healthy.iter().map(NodeId::to_hex).collect::<Vec<_>>())
            );
            assert_eq!(body["amount_msat"], if mixed { 2000 } else { 0 });
            assert_eq!(body["max_routing_fee_msat"], if mixed { 10000 } else { 0 });
            assert_eq!(
                balance_before - wallet.get_balance_msat().await.unwrap(),
                if mixed { 2800 } else { 0 }
            );
            assert_eq!(
                transport.sent_envelopes.lock().unwrap().len(),
                healthy.len()
            );
            assert_eq!(body["message_id"].is_string(), mixed);
            assert!(db
                .get_calendar_event(body["event_id"].as_str().unwrap())
                .await
                .unwrap()
                .is_some());
            assert_eq!(store.load_session(&peer).await.unwrap(), before);
            assert_eq!(
                db.count_pending_deliveries().await.unwrap(),
                healthy.len() as u64
            );
            assert!(db
                .get_messages_for_recipient(&konsensus_core::Recipient::Node(peer), 10, None)
                .await
                .unwrap()
                .is_empty());
        }
    }
}
