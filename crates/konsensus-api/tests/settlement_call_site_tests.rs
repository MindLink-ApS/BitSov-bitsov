//! Guard subscribe-before-dispatch at the production payment-proof call sites.
//! The recovery wrapper matches AppState.lightning in the running node.
mod common;

use async_trait::async_trait;
use futures::{stream::BoxStream, StreamExt};
use konsensus_api::{handlers::messages::create_payment_proof, state::InvoiceResponseData};
use konsensus_core::{
    traits::lightning::{
        Invoice, LightningError, LightningProvider, PaymentDetails, PaymentStatus,
    },
    NodeIdentity,
};
use konsensus_lightning::{MockLightningProvider, RecoveringLightning};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::time::Instant;

async fn ready_wrapper(backend: Arc<dyn LightningProvider>) -> Arc<dyn LightningProvider> {
    let lightning = Arc::new(
        RecoveringLightning::new(
            move || {
                let backend = backend.clone();
                async move { Ok(backend) }
            },
            Default::default(),
        )
        .await
        .unwrap(),
    );
    tokio::task::yield_now().await;
    assert!(lightning.money_ready().await);
    lightning
}

#[tokio::test(start_paused = true)]
async fn keysend_call_site_subscribes_before_dispatch() {
    let backend = Arc::new(MockLightningProvider::new());
    backend.defer_next_keysend_settlement(0).await;
    backend.hint_during_next_deferred_keysend();
    let lightning = ready_wrapper(backend.clone()).await;
    let mut state = common::test_state_with_lightning(lightning.clone());
    let (_, identity) = NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(common::ConnectedStubTransport::new(
        vec![peer],
        state.invoice_requests.clone(),
    ));
    state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(peer, format!("02{}", "aa".repeat(32)));

    // Invoke create_payment_proof -> try_keysend; the test never subscribes.
    let started = Instant::now();
    let (hash, preimage, amount) = create_payment_proof(&state, 2000, &peer).await.unwrap();
    assert_eq!(started.elapsed(), Duration::ZERO, "dispatch hint was lost");
    assert_eq!(amount, 2000);
    assert_eq!(hash, <[u8; 32]>::from(Sha256::digest(preimage)));
    assert_eq!(backend.list_payments(10).await.unwrap().len(), 1);
    lightning.shutdown().await.unwrap();
}

/// Model settlement racing with an invoice dispatch response: the authoritative
/// record is settled and its hint fires, but dispatch returns an older snapshot.
/// Keep this fixture local to tests; the stock mock already supplies this race
/// for keysend.
struct InvoiceSettlesDuringDispatch {
    backend: MockLightningProvider,
    dispatched_at: Mutex<Option<Instant>>,
    hints_seen: Arc<AtomicUsize>,
}

#[async_trait]
impl LightningProvider for InvoiceSettlesDuringDispatch {
    async fn create_invoice(
        &self,
        amount: u64,
        description: &str,
        expiry: u32,
    ) -> Result<Invoice, LightningError> {
        self.backend
            .create_invoice(amount, description, expiry)
            .await
    }

    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        self.pay_invoice_with_fee_limit(bolt11, u64::MAX).await
    }

    async fn pay_invoice_with_fee_limit(
        &self,
        bolt11: &str,
        cap: u64,
    ) -> Result<PaymentDetails, LightningError> {
        *self.dispatched_at.lock().unwrap() = Some(Instant::now());
        let mut details = self.backend.pay_invoice_with_fee_limit(bolt11, cap).await?;
        self.backend.hint_outgoing(&details.payment_hash);
        details.status = PaymentStatus::InFlight;
        details.preimage = None;
        Ok(details)
    }

    async fn keysend_with_fee_limit(
        &self,
        destination: &str,
        amount: u64,
        memo: Option<&str>,
        cap: u64,
    ) -> Result<PaymentDetails, LightningError> {
        self.backend.defer_next_keysend_settlement(0).await;
        self.backend.hint_during_next_deferred_keysend();
        self.backend
            .keysend_with_fee_limit(destination, amount, memo, cap)
            .await
    }

    fn outgoing_payment_updates(&self) -> Option<BoxStream<'static, String>> {
        let seen = self.hints_seen.clone();
        self.backend.outgoing_payment_updates().map(|updates| {
            updates
                .inspect(move |_| {
                    seen.fetch_add(1, Ordering::SeqCst);
                })
                .boxed()
        })
    }

    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        self.backend.get_payment_status(hash).await
    }

    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        self.backend.get_balance_msat().await
    }

    async fn is_available(&self) -> bool {
        true
    }
}

#[tokio::test(start_paused = true)]
async fn invoice_call_site_subscribes_before_dispatch() {
    let backend = Arc::new(InvoiceSettlesDuringDispatch {
        backend: MockLightningProvider::new(),
        dispatched_at: Mutex::new(None),
        hints_seen: Arc::new(AtomicUsize::new(0)),
    });
    let lightning = ready_wrapper(backend.clone()).await;
    let mut state = common::test_state_with_lightning(lightning.clone());
    let (_, identity) = NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let invoice = MockLightningProvider::new()
        .create_invoice(2000, "message", 60)
        .await
        .unwrap();
    let expected_hash = invoice.payment_hash.clone();
    let transport = common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
        .with_invoice_responder(move |_, amount| {
            assert_eq!(amount, 2000);
            Some(InvoiceResponseData {
                recipient: peer,
                bolt11: invoice.bolt11.clone(),
                payment_hash: invoice.payment_hash.clone(),
            })
        });
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(transport);

    // No peer LN key: create_payment_proof takes the recipient invoice path.
    // Measure from dispatch to exclude the fixture's 5 ms invoice round-trip.
    let (hash, preimage, amount) = create_payment_proof(&state, 2000, &peer).await.unwrap();
    assert_eq!(
        backend.dispatched_at.lock().unwrap().unwrap().elapsed(),
        Duration::ZERO,
        "dispatch hint was lost"
    );
    assert_eq!(amount, 2000);
    assert_eq!(hex::encode(hash), expected_hash);
    assert_eq!(hash, <[u8; 32]>::from(Sha256::digest(preimage)));
    assert_eq!(backend.backend.list_payments(10).await.unwrap().len(), 1);
    assert!(state.invoice_requests.lock().await.is_empty());
    lightning.shutdown().await.unwrap();
}

// Exercise the durable operation branch as well as the legacy proof helpers.
// Dropping the early subscription or retaining the fixed operation sleep makes
// these fail: the hint emitted inside dispatch must actually wake the poll.
async fn operation_dispatch_hint_is_consumed(keysend: bool) {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use konsensus_storage::{SqliteStorage, Storage};
    use tower::ServiceExt;

    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(
        SqliteStorage::open(dir.path().join("outbox.db").to_str().unwrap())
            .await
            .unwrap(),
    );
    let backend = Arc::new(InvoiceSettlesDuringDispatch {
        backend: MockLightningProvider::new(),
        dispatched_at: Mutex::new(None),
        hints_seen: Arc::new(AtomicUsize::new(0)),
    });
    let lightning = ready_wrapper(backend.clone()).await;
    let mut state = common::test_state_with_lightning(lightning.clone());
    let (_, identity) = NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let recipient = konsensus_crypto::SessionManager::new(Arc::new(identity));
    state
        .session_manager
        .initiate_session(&peer, &recipient.prekey_bundle().await)
        .await
        .unwrap();
    if keysend {
        state
            .peer_ln_pubkeys
            .lock()
            .await
            .insert(peer, format!("02{}", "aa".repeat(32)));
    }
    let invoice = MockLightningProvider::new()
        .create_invoice(1000, "operation message", 60)
        .await
        .unwrap();
    let transport = common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
        .with_invoice_responder(move |_, amount| {
            assert_eq!(amount, 1000);
            Some(InvoiceResponseData {
                recipient: peer,
                payment_hash: invoice.payment_hash.clone(),
                bolt11: invoice.bolt11.clone(),
            })
        });
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.storage = db.clone();
    mutable.transport = Arc::new(transport);
    let token = common::auth_header(&state);
    let app = common::test_router(state.clone());
    let id = uuid::Uuid::new_v4().to_string();
    let request = || {
        Request::builder().method("POST").uri("/api/v1/messages/compose")
        .header("authorization", &token).header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"operation_id":id,"recipient":peer.to_hex(),"kind":1,"plaintext":"hint race","wait_ack_ms":0}).to_string())).unwrap()
    };
    let response = app.clone().oneshot(request()).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(
        backend.hints_seen.load(Ordering::SeqCst) > 0,
        "operation settlement ignored the dispatch hint"
    );
    let operation = db.get_outbox_operation(&id).await.unwrap().unwrap();
    assert!(operation.settled_msat > 0, "settlement must remain durable");
    assert_eq!(
        app.oneshot(request()).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        backend.backend.list_payments(10).await.unwrap().len(),
        1,
        "operation replay paid twice"
    );
    lightning.shutdown().await.unwrap();
}

#[tokio::test]
async fn operation_keysend_subscribes_before_dispatch_and_journals_settlement() {
    operation_dispatch_hint_is_consumed(true).await;
}

#[tokio::test]
async fn operation_invoice_subscribes_before_dispatch_and_journals_settlement() {
    operation_dispatch_hint_is_consumed(false).await;
}
