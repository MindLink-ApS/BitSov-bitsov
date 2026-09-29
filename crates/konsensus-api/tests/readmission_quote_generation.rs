//! #111 review finding 1: an admission quote belongs to the connection
//! generation that asked for it. A reconnect while its response is in flight
//! (on the compose path or the quote route) must never let it be paid.
mod common;

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use konsensus_api::{
    auth, invoice_refusal,
    state::{AppState, InvoiceRequestOutcome, InvoiceResponseData, InvoiceResponseError},
};
use konsensus_core::{
    traits::{
        lightning::LightningProvider,
        transport::{MessageTransport, TransportError},
    },
    NodeId, NodeIdentity, UkmEnvelope,
};
use konsensus_crypto::SessionManager;
use konsensus_lightning::shared_mock::SharedMockProvider;
use konsensus_message::wire::Frame;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tower::ServiceExt;

type Requests = Arc<AsyncMutex<HashMap<String, oneshot::Sender<InvoiceRequestOutcome>>>>;

/// A contact with a live E2EE session whose connection starts unpaid. It
/// answers an admission quote after `flap_on_quote` reconnects, if set.
struct ReconnectingContact {
    peer: NodeId,
    requests: Requests,
    recipient_wallet: Arc<SharedMockProvider>,
    generation: Mutex<Instant>,
    paid: AtomicBool,
    flap_on_quote: AtomicBool,
    quotes: AtomicUsize,
    /// The transport reports no live connection generation.
    no_generation: AtomicBool,
    /// After this many `connected_since` observations, reconnect once (0 = never).
    reconnect_after_connected_since: AtomicUsize,
    connected_since_calls: AtomicUsize,
}

impl ReconnectingContact {
    fn reconnect(&self) {
        *self.generation.lock().unwrap() = Instant::now();
        self.paid.store(false, Ordering::SeqCst);
    }
}

#[async_trait]
impl MessageTransport for ReconnectingContact {
    async fn send(&self, _: &NodeId, envelope: &UkmEnvelope) -> Result<(), TransportError> {
        if envelope.ciphertext == b"konsensus:admission:v1" {
            // The recipient's gate accepted the proof: this connection is paid.
            self.paid.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
    async fn send_on_connection(
        &self,
        peer: &NodeId,
        since: Option<Instant>,
        envelope: &UkmEnvelope,
    ) -> Result<(), TransportError> {
        if since != Some(*self.generation.lock().unwrap()) {
            return Err(TransportError::NotConnected("generation changed".into()));
        }
        self.send(peer, envelope).await
    }
    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        std::future::pending().await
    }
    async fn connect(&self, _: &NodeId, _: &str) -> Result<(), TransportError> {
        Ok(())
    }
    async fn disconnect(&self, _: &NodeId) -> Result<(), TransportError> {
        Ok(())
    }
    async fn is_connected(&self, _: &NodeId) -> bool {
        true
    }
    async fn connected_peers(&self) -> Vec<NodeId> {
        vec![self.peer]
    }
    async fn connected_since(&self, _: &NodeId) -> Option<Instant> {
        if self.no_generation.load(Ordering::SeqCst) {
            return None;
        }
        let n = self.connected_since_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let after = self.reconnect_after_connected_since.load(Ordering::SeqCst);
        if after > 0 && n == after {
            self.reconnect();
            self.reconnect_after_connected_since.store(0, Ordering::SeqCst);
        }
        Some(*self.generation.lock().unwrap())
    }
    async fn admission_paid_on_connection(&self, _: &NodeId) -> bool {
        self.paid.load(Ordering::SeqCst)
    }
    async fn mark_admission_paid(&self, _: &NodeId, since: Instant) {
        if since == *self.generation.lock().unwrap() {
            self.paid.store(true, Ordering::SeqCst);
        }
    }
    async fn send_raw_frame(&self, _: &NodeId, bytes: &[u8]) -> Result<(), TransportError> {
        let Frame::RequestInvoice { request_id, purpose, amount_msat } = Frame::from_bytes(bytes).unwrap()
        else {
            return Ok(());
        };
        let admission = purpose.starts_with("konsensus:admission");
        let outcome = if !admission && !self.paid.load(Ordering::SeqCst) {
            assert!(invoice_refusal::record(&request_id, &self.peer, invoice_refusal::ADMISSION_REQUIRED));
            Err(InvoiceResponseError { recipient: self.peer, reason: invoice_refusal::ADMISSION_REQUIRED.into() })
        } else {
            if admission {
                self.quotes.fetch_add(1, Ordering::SeqCst);
                // The quote was made on the connection that asked for it; the
                // sender reconnects before its response arrives.
                if self.flap_on_quote.swap(false, Ordering::SeqCst) {
                    self.reconnect();
                }
            }
            let description = if admission {
                format!("konsensus:{request_id}:message=2000")
            } else {
                "konsensus message".into()
            };
            let invoice = self
                .recipient_wallet
                .create_invoice(if admission { 2000 } else { amount_msat }, &description, 55)
                .await
                .unwrap();
            Ok(InvoiceResponseData { recipient: self.peer, bolt11: invoice.bolt11, payment_hash: invoice.payment_hash })
        };
        self.requests.lock().await.remove(&request_id).unwrap().send(outcome).unwrap();
        Ok(())
    }
}

struct Net {
    state: Arc<AppState>,
    contact: Arc<ReconnectingContact>,
    payer: Arc<SharedMockProvider>,
    token: String,
    _dir: tempfile::TempDir,
}

const START_MSAT: u64 = 100_000;

async fn net() -> Net {
    let dir = tempfile::tempdir().unwrap();
    let payer = Arc::new(SharedMockProvider::new(&dir.path().join("ledger.db"), "payer", START_MSAT).unwrap());
    let payee = Arc::new(SharedMockProvider::new(&dir.path().join("ledger.db"), "payee", 0).unwrap());
    let mut state = common::test_state_with_lightning(payer.clone());
    let (_, identity) = NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    // An existing contact: the E2EE session survives the reconnect.
    let recipient_sessions = SessionManager::new(Arc::new(identity));
    let init = state.session_manager
        .initiate_session(&peer, &recipient_sessions.prekey_bundle().await)
        .await
        .unwrap();
    recipient_sessions.accept_session(state.identity.node_id(), &init).await.unwrap();
    let contact = Arc::new(ReconnectingContact {
        peer,
        requests: state.invoice_requests.clone(),
        recipient_wallet: payee,
        generation: Mutex::new(Instant::now()),
        paid: AtomicBool::new(false),
        flap_on_quote: AtomicBool::new(false),
        quotes: AtomicUsize::new(0),
        no_generation: AtomicBool::new(false),
        reconnect_after_connected_since: AtomicUsize::new(0),
        connected_since_calls: AtomicUsize::new(0),
    });
    Arc::get_mut(&mut state).unwrap().transport = contact.clone();
    let token = auth::create_token(&state.identity.node_id().to_hex(), &state.jwt_secret, auth::Scope::all()).unwrap();
    Net { state, contact, payer, token, _dir: dir }
}

impl Net {
    async fn post(&self, uri: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
        let response = common::test_router(self.state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("authorization", format!("Bearer {}", self.token))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 65536).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    async fn compose(&self, operation_id: &str, cap: u64) -> (u16, serde_json::Value) {
        self.compose_with_fee(operation_id, cap, 0).await
    }

    async fn compose_with_fee(&self, operation_id: &str, cap: u64, fee: u64) -> (u16, serde_json::Value) {
        self.post("/api/v1/messages/compose", serde_json::json!({
            "recipient": self.contact.peer.to_hex(), "kind": 0, "plaintext": "after the reconnect",
            "max_total_msat": cap, "max_routing_fee_msat": fee, "operation_id": operation_id,
        })).await
    }

    async fn spent(&self) -> u64 {
        START_MSAT - self.payer.get_balance_msat().await.unwrap()
    }
}

#[tokio::test]
async fn reconnect_during_readmission_quote_response_pays_nothing() {
    let net = net().await;
    let operation_id = uuid::Uuid::new_v4().to_string();
    net.contact.flap_on_quote.store(true, Ordering::SeqCst);
    let (status, body) = net.compose(&operation_id, 4_000).await;
    assert_eq!((status, body["code"].as_str()), (400, Some("not_dispatched")), "{body}");
    assert_eq!(body["state"], "prepared", "{body}");
    assert_eq!(net.spent().await, 0, "a quote asked on the earlier connection is never paid");

    // The same operation on the stable connection: admission once, message once.
    let (status, body) = net.compose(&operation_id, 4_000).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!((body["amount_msat"].as_u64(), body["readmission_msat"].as_u64()), (Some(2_000), Some(2_000)), "{body}");
    assert_eq!(net.spent().await, 4_000);
    assert_eq!(net.contact.quotes.load(Ordering::SeqCst), 2, "a fresh quote on the new connection");
    let (status, _) = net.compose(&operation_id, 4_000).await;
    assert_eq!(status, 200);
    assert_eq!(net.spent().await, 4_000, "a retry of the operation pays nothing more");
}

#[tokio::test]
async fn quote_route_never_caches_a_response_across_a_reconnect() {
    let net = net().await;
    net.contact.flap_on_quote.store(true, Ordering::SeqCst);
    let quote = serde_json::json!({"recipient": net.contact.peer.to_hex()});
    let (status, body) = net.post("/api/v1/messages/first-contact/quote", quote.clone()).await;
    assert_eq!((status, body["code"].as_str()), (400, Some("not_dispatched")), "{body}");

    // Nothing was cached for the replacement connection: the send asks again.
    let (status, body) = net.compose(&uuid::Uuid::new_v4().to_string(), 4_000).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(net.spent().await, 4_000);
    assert_eq!(net.contact.quotes.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn quote_from_an_earlier_connection_is_not_paid_after_a_reconnect() {
    let net = net().await;
    let quote = serde_json::json!({"recipient": net.contact.peer.to_hex()});
    let (status, body) = net.post("/api/v1/messages/first-contact/quote", quote).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total_msat"].as_u64(), Some(body["admission_msat"].as_u64().unwrap()
        + body["message_msat"].as_u64().unwrap() + body["max_routing_fee_msat"].as_u64().unwrap()));
    net.contact.reconnect();
    let (status, body) = net.compose(&uuid::Uuid::new_v4().to_string(), 4_000).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(net.spent().await, 4_000);
    assert_eq!(net.contact.quotes.load(Ordering::SeqCst), 2, "the cached quote belonged to the earlier connection");
}

#[tokio::test]
async fn quote_fetched_by_a_refused_send_is_the_one_paid_under_a_cap_that_fits() {
    let net = net().await;
    let operation_id = uuid::Uuid::new_v4().to_string();
    let (status, body) = net.compose(&operation_id, 3_000).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!((body["code"].as_str(), body["reason"].as_str()), (Some("price_cap_exceeded"), Some("readmission_required")), "{body}");
    assert_eq!(net.spent().await, 0);
    let quote = serde_json::json!({"recipient": net.contact.peer.to_hex()});
    let (status, body) = net.post("/api/v1/messages/first-contact/quote", quote).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!((body["admission_msat"].as_u64(), body["message_msat"].as_u64()), (Some(2_000), Some(2_000)), "{body}");
    let (status, body) = net.compose(&operation_id, 4_000).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(net.spent().await, 4_000);
    assert_eq!(net.contact.quotes.load(Ordering::SeqCst), 1, "one quote: the refused send's, shown and then paid");
}

#[tokio::test]
async fn no_connection_generation_never_binds_or_pays_a_quote() {
    // #127 review finding 2: `None == None` must not pass as the same connection.
    let net = net().await;
    net.contact.no_generation.store(true, Ordering::SeqCst);
    let quote = serde_json::json!({"recipient": net.contact.peer.to_hex()});
    let (status, body) = net.post("/api/v1/messages/first-contact/quote", quote).await;
    assert_eq!((status, body["code"].as_str()), (400, Some("not_dispatched")), "{body}");
    let (status, body) = net.compose(&uuid::Uuid::new_v4().to_string(), 4_000).await;
    assert_eq!((status, body["code"].as_str()), (400, Some("not_dispatched")), "{body}");
    assert_eq!(net.spent().await, 0);
    assert_eq!(net.contact.quotes.load(Ordering::SeqCst), 0, "no quote was asked for");
}

/// #127 follow-up: refusals that never reach wallet dispatch must not report an
/// admission fee ceiling in `max_routing_fee_msat`.
const FEE: u64 = 100;

fn assert_message_fee_only(body: &serde_json::Value) {
    assert_eq!(
        body["max_routing_fee_msat"].as_u64(),
        Some(FEE),
        "refusal before admission dispatch reports the message fee only: {body}"
    );
}

#[tokio::test]
async fn cap_refusal_reports_no_admission_fee_ceiling() {
    let net = net().await;
    let (status, body) = net.compose_with_fee(&uuid::Uuid::new_v4().to_string(), 3_000, FEE).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        (body["code"].as_str(), body["reason"].as_str()),
        (Some("price_cap_exceeded"), Some("readmission_required")),
        "{body}"
    );
    assert_eq!(net.spent().await, 0);
    assert_message_fee_only(&body);
}

/// Cache a fitting quote, then reconnect on the Nth `connected_since` of the
/// next compose. On the cached-quote re-admission path the observations are:
/// readmit coverage, first_contact coverage, live take, then the three
/// post-quote generation checks (before reserve / after reserve / before pay).
async fn refuse_cached_quote_on_connected_since(n: usize) -> (u16, serde_json::Value, u64) {
    let net = net().await;
    let (status, body) = net.compose_with_fee(&uuid::Uuid::new_v4().to_string(), 3_000, FEE).await;
    assert_eq!(status, 409, "seed the cache under a too-small cap: {body}");
    assert_eq!(net.spent().await, 0);
    net.contact.connected_since_calls.store(0, Ordering::SeqCst);
    net.contact
        .reconnect_after_connected_since
        .store(n, Ordering::SeqCst);
    let (status, body) = net
        .compose_with_fee(&uuid::Uuid::new_v4().to_string(), 4_200, FEE)
        .await;
    let spent = net.spent().await;
    (status, body, spent)
}

#[tokio::test]
async fn generation_change_before_reservation_reports_no_admission_fee_ceiling() {
    let (status, body, spent) = refuse_cached_quote_on_connected_since(4).await;
    assert_eq!((status, body["code"].as_str()), (400, Some("not_dispatched")), "{body}");
    assert_eq!(spent, 0);
    assert_message_fee_only(&body);
}

#[tokio::test]
async fn generation_change_after_reservation_reports_no_admission_fee_ceiling() {
    let (status, body, spent) = refuse_cached_quote_on_connected_since(5).await;
    assert_eq!((status, body["code"].as_str()), (400, Some("not_dispatched")), "{body}");
    assert_eq!(spent, 0);
    assert_message_fee_only(&body);
}

#[tokio::test]
async fn generation_change_before_dispatch_reports_no_admission_fee_ceiling() {
    let (status, body, spent) = refuse_cached_quote_on_connected_since(6).await;
    assert_eq!((status, body["code"].as_str()), (400, Some("not_dispatched")), "{body}");
    assert_eq!(spent, 0);
    assert_message_fee_only(&body);
}
