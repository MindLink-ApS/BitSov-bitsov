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
    NodeId, NodeIdentity, UkmEnvelope,
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
    payee: Arc<SharedMockProvider>,
    pending: Arc<
        tokio::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<InvoiceRequestOutcome>>>,
    >,
    admitted: AtomicBool,
    proofs: AtomicUsize,
    refusals: AtomicUsize,
    refuse_after_admission: AtomicBool,
}
#[async_trait::async_trait]
impl MessageTransport for ReadmitTransport {
    async fn send(&self, peer: &NodeId, env: &UkmEnvelope) -> Result<(), TransportError> {
        assert_eq!(*peer, self.peer);
        if env.ciphertext == b"konsensus:admission:v1" {
            self.proofs.fetch_add(1, Ordering::SeqCst);
            self.admitted.store(true, Ordering::SeqCst);
        }
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
        *peer == self.peer
    }
    async fn connected_since(&self, peer: &NodeId) -> Option<std::time::Instant> {
        // One live connection, established before this test's first payment.
        static SINCE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        self.is_connected(peer).await.then(|| *SINCE.get_or_init(std::time::Instant::now))
    }
    async fn connected_peers(&self) -> Vec<NodeId> {
        vec![self.peer]
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
        assert!(*peer == self.peer);
        let admission = purpose.starts_with("konsensus:admission:");
        let result = if *peer == self.peer && !admission && !self.admitted.load(Ordering::SeqCst) {
            self.refusals.fetch_add(1, Ordering::SeqCst);
            Err(InvoiceResponseError {
                recipient: self.peer,
                reason: konsensus_api::invoice_refusal::ADMISSION_REQUIRED.into(),
            })
        } else if !admission && self.refuse_after_admission.swap(false, Ordering::SeqCst) {
            Err(InvoiceResponseError { recipient: self.peer, reason: "review113 message invoice refused".into() })
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
async fn operation_retry_preserves_prior_paid_readmission_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(SqliteStorage::open(dir.path().join("outbox.sqlite").to_str().unwrap()).await.unwrap());
    let ledger = dir.path().join("payments.sqlite");
    let payer = Arc::new(SharedMockProvider::new(&ledger, "payer", 10000).unwrap());
    let payee = Arc::new(SharedMockProvider::new(&ledger, "payee", 0).unwrap());
    let mut state = common::test_state_with_lightning(payer.clone());
    let (_, identity) = NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
    state.session_manager.initiate_session(&peer, &target.prekey_bundle().await).await.unwrap();
    let transport = Arc::new(ReadmitTransport {
        peer, payee, pending:state.invoice_requests.clone(),
        admitted: AtomicBool::new(false), proofs: AtomicUsize::new(0),
        refusals: AtomicUsize::new(0), refuse_after_admission: AtomicBool::new(true),
    });
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.storage = db.clone();
    mutable.transport = transport.clone();
    let id = uuid::Uuid::new_v4().to_string();
    let body = serde_json::json!({"operation_id":id,"recipient":peer.to_hex(),"kind":1,"plaintext":"preserve receipt","wait_ack_ms":0});
    let post = || async {
        let response = common::test_router(state.clone()).oneshot(Request::builder().method("POST").uri("/api/v1/messages/compose")
            .header("authorization", common::auth_header(&state)).header("content-type","application/json")
            .body(Body::from(body.to_string())).unwrap()).await.unwrap();
        let status = response.status();
        let body: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(response.into_body(),16384).await.unwrap()).unwrap();
        (status, body)
    };
    let first = post().await;
    assert_eq!(first.0, StatusCode::BAD_GATEWAY, "{first:?}");
    let before = db.get_outbox_operation(&id).await.unwrap().unwrap();
    assert_eq!(before.state, "prepared");
    assert_eq!(before.readmission_msat, 1000);
    assert_eq!(payer.get_balance_msat().await.unwrap(), 9000);
    let retry = post().await;
    assert_eq!(retry.0, StatusCode::OK, "{retry:?}");
    assert_eq!(payer.get_balance_msat().await.unwrap(), 8000);
    assert_eq!(transport.proofs.load(Ordering::SeqCst), 1);
    assert_eq!(retry.1["readmission_msat"], 1000, "operation's paid admission must remain in its durable receipt: {retry:?}");
    assert_eq!(db.get_outbox_operation(&id).await.unwrap().unwrap().readmission_msat, 1000);
}
