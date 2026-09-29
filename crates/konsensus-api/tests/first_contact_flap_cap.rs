//! Codex #111 finding 4: one capped first-contact call must not spend its
//! original cap again after a mid-call reconnect.
mod common;

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use konsensus_api::{
    auth, invoice_refusal,
    state::{InvoiceRequestOutcome, InvoiceResponseData, InvoiceResponseError},
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

struct FlapTransport {
    peer: NodeId,
    requests: Requests,
    recipient_wallet: Arc<SharedMockProvider>,
    sender_sessions: Arc<SessionManager>,
    recipient_sessions: SessionManager,
    generation: Mutex<Instant>,
    paid: AtomicBool,
    flapped: AtomicBool,
    admissions: AtomicUsize,
}

#[async_trait]
impl MessageTransport for FlapTransport {
    async fn send(&self, _: &NodeId, envelope: &UkmEnvelope) -> Result<(), TransportError> {
        if envelope.ciphertext == b"konsensus:admission:v1" {
            self.admissions.fetch_add(1, Ordering::SeqCst);
            if !self.sender_sessions.has_session(&self.peer).await {
                self.sender_sessions
                    .initiate_session(&self.peer, &self.recipient_sessions.prekey_bundle().await)
                    .await
                    .unwrap();
            }
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
        let Frame::RequestInvoice {
            request_id,
            purpose,
            amount_msat,
        } = Frame::from_bytes(bytes).unwrap()
        else {
            return Ok(());
        };
        let admission = purpose.starts_with("konsensus:admission");
        // First admission proof was delivered and session setup completed. The
        // first message request lands on a replacement unpaid connection.
        let outcome = if !admission && !self.flapped.swap(true, Ordering::SeqCst) {
            assert_eq!(self.admissions.load(Ordering::SeqCst), 1);
            *self.generation.lock().unwrap() = Instant::now();
            self.paid.store(false, Ordering::SeqCst);
            assert!(invoice_refusal::record(
                &request_id,
                &self.peer,
                invoice_refusal::ADMISSION_REQUIRED
            ));
            Err(InvoiceResponseError {
                recipient: self.peer,
                reason: invoice_refusal::ADMISSION_REQUIRED.into(),
            })
        } else {
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
            Ok(InvoiceResponseData {
                recipient: self.peer,
                bolt11: invoice.bolt11,
                payment_hash: invoice.payment_hash,
            })
        };
        self.requests
            .lock()
            .await
            .remove(&request_id)
            .unwrap()
            .send(outcome)
            .unwrap();
        Ok(())
    }
}

#[tokio::test]
async fn first_contact_then_flap_must_not_spend_original_cap_twice() {
    let dir = tempfile::tempdir().unwrap();
    let payer = Arc::new(
        SharedMockProvider::new(&dir.path().join("ledger.db"), "payer", 100_000).unwrap(),
    );
    let payee = Arc::new(SharedMockProvider::new(&dir.path().join("ledger.db"), "payee", 0).unwrap());
    let mut state = common::test_state_with_lightning(payer.clone());
    let (_, identity) = NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let transport = Arc::new(FlapTransport {
        peer,
        requests: state.invoice_requests.clone(),
        recipient_wallet: payee,
        sender_sessions: state.session_manager.clone(),
        recipient_sessions: SessionManager::new(Arc::new(identity)),
        generation: Mutex::new(Instant::now()),
        paid: AtomicBool::new(false),
        flapped: AtomicBool::new(false),
        admissions: AtomicUsize::new(0),
    });
    Arc::get_mut(&mut state).unwrap().transport = transport.clone();
    let token = auth::create_token(
        &state.identity.node_id().to_hex(),
        &state.jwt_secret,
        auth::Scope::all(),
    )
    .unwrap();
    let response = common::test_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/messages/compose")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "recipient": peer.to_hex(),
                        "kind": 0,
                        "plaintext": "one capped call",
                        "max_total_msat": 4000,
                        "max_routing_fee_msat": 0
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 16384)
        .await
        .unwrap();
    let spent = 100_000 - payer.get_balance_msat().await.unwrap();
    eprintln!(
        "first-contact/flap cap evidence: status={status}, spent={spent}, admissions={}, body={}",
        transport.admissions.load(Ordering::SeqCst),
        String::from_utf8_lossy(&body)
    );
    assert!(
        spent <= 4000,
        "one 4000-msat capped call spent {spent} (status={status})"
    );
}
