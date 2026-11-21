//! The moment a payment is handed to the wallet is the dispatch boundary.
//!
//! A call payment holds the call's state until the wallet itself is first
//! polled, so a hangup that completes while the payment is still being
//! prepared is never followed by a payment. The contact's Lightning binding
//! is read again at that boundary without waiting; a binding that cannot be
//! read at that moment refuses the payment as not dispatched.

mod common;

use axum::{body::Body, http::Request};
use futures::stream::BoxStream;
use konsensus_api::{
    calls,
    error::ApiError,
    handlers::messages::create_payment_proof,
    state::{InvoiceResponseData, PeerLightningKey},
};
use konsensus_core::{
    NodeId,
    payloads::call::{self as rules, Phase},
    traits::lightning::{Invoice, LightningError, LightningProvider, PaymentDetails},
};
use konsensus_lightning::shared_mock::SharedMockProvider;
use konsensus_storage::Storage;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tower::ServiceExt;

const ID: &str = "0123456789abcdef0123456789abcdef";
type PeerKeys = Arc<tokio::sync::Mutex<HashMap<NodeId, PeerLightningKey>>>;
type Held = Arc<Mutex<Option<tokio::sync::OwnedMutexGuard<HashMap<NodeId, PeerLightningKey>>>>>;

/// A shared-mock wallet that records the call's phase when it is first asked
/// to pay. Its settlement subscription arranges for the next call read (the
/// one made while the call payment is being prepared) to take the contacts'
/// binding map and keep it until the test lets it go.
struct CallObservingWallet {
    inner: Arc<SharedMockProvider>,
    store: Arc<common::MemStorage>,
    setup: Mutex<Option<(PeerKeys, Held, Arc<tokio::sync::Notify>)>>,
    first_phase: Mutex<Option<Phase>>,
    peer: Mutex<Option<NodeId>>,
}

#[async_trait::async_trait]
impl LightningProvider for CallObservingWallet {
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        self.inner.create_invoice(amount_msat, description, expiry_secs).await
    }

    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        self.pay_invoice_with_fee_limit(bolt11, 0).await
    }

    async fn pay_invoice_with_fee_limit(
        &self,
        bolt11: &str,
        fee_limit_msat: u64,
    ) -> Result<PaymentDetails, LightningError> {
        let peer = self.peer.lock().unwrap().unwrap();
        let phase = self.store.call_get(&peer, ID).await.unwrap().unwrap().phase;
        self.first_phase.lock().unwrap().get_or_insert(phase);
        self.inner.pay_invoice_with_fee_limit(bolt11, fee_limit_msat).await
    }

    fn outgoing_payment_updates(&self) -> Option<BoxStream<'static, String>> {
        if let Some((map, held, entered)) = self.setup.lock().unwrap().take() {
            *self.store.call_get_hook.lock().unwrap() = Some(Box::new(move || {
                *held.lock().unwrap() = Some(map.try_lock_owned().unwrap());
                entered.notify_one();
            }));
        }
        None
    }

    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        self.inner.get_payment_status(hash).await
    }

    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        self.inner.get_balance_msat().await
    }

    async fn is_available(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn a_hangup_while_a_call_payment_is_being_prepared_is_never_paid_afterwards() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("payments.sqlite");
    let payer = Arc::new(SharedMockProvider::new(&ledger, "caller", 100_000).unwrap());
    let payee = Arc::new(SharedMockProvider::new(&ledger, "callee", 0).unwrap());
    let store = Arc::new(common::MemStorage::new());
    let wallet = Arc::new(CallObservingWallet {
        inner: payer.clone(),
        store: store.clone(),
        setup: Mutex::new(None),
        first_phase: Mutex::new(None),
        peer: Mutex::new(None),
    });
    let mut state = common::test_state_with_lightning(wallet.clone());
    let (_, identity) = konsensus_core::NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    *wallet.peer.lock().unwrap() = Some(peer);
    let transport = Arc::new(
        common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
            .with_invoice_responder(move |_, amount| {
                let invoice =
                    futures::executor::block_on(payee.create_invoice(amount, "call block", 60)).unwrap();
                Some(InvoiceResponseData {
                    recipient: peer,
                    bolt11: invoice.bolt11,
                    payment_hash: invoice.payment_hash,
                })
            }),
    );
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.transport = transport.clone();
    mutable.storage = store.clone();
    let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
    state
        .session_manager
        .initiate_session(&peer, &target.prekey_bundle().await)
        .await
        .unwrap();
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let ringing =
        rules::commit(rules::reserve(None, 400, "offer", "hash", now).unwrap(), "offer", now).unwrap();
    store
        .call_put(&peer, ID, &rules::receive(Some(ringing), 401, None, now).unwrap())
        .await
        .unwrap();
    let held: Held = Arc::new(Mutex::new(None));
    let entered = Arc::new(tokio::sync::Notify::new());
    *wallet.setup.lock().unwrap() =
        Some((state.peer_ln_pubkeys.clone(), held.clone(), entered.clone()));

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", common::auth_header(&state))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "operation_id": uuid::Uuid::new_v4().to_string(),
                "recipient": peer.to_hex(),
                "kind": 404,
                "plaintext": format!(r#"{{"call_id":"{ID}","seq":0}}"#),
                "wait_ack_ms": 0
            })
            .to_string(),
        ))
        .unwrap();
    let response = tokio::spawn(common::test_router(state.clone()).oneshot(request));

    // Answer the price query, then wait until the call payment is being
    // prepared (the call read inside its dispatch preparation).
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if transport.raw_frames.lock().unwrap().iter().any(|bytes| {
                matches!(
                    konsensus_message::wire::Frame::from_bytes(bytes).unwrap(),
                    konsensus_message::wire::Frame::PriceQuery { kind: 404 }
                )
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    state.peer_prices.update_kind_price(peer, 404, 23_000, 850_000).await;
    tokio::time::timeout(Duration::from_secs(10), entered.notified()).await.unwrap();

    // The callee hangs up and the call ends.
    let hangup = format!(r#"{{"v":1,"call_id":"{ID}","reason":"hangup"}}"#);
    tokio::time::timeout(
        Duration::from_secs(10),
        calls::admit_incoming(store.as_ref(), state.identity.node_id(), &peer, 403, Some(&hangup)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(store.call_get(&peer, ID).await.unwrap().unwrap().phase, Phase::Ended);

    drop(held.lock().unwrap().take());
    let response = tokio::time::timeout(Duration::from_secs(10), response)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let phase = *wallet.first_phase.lock().unwrap();
    let payments = payer.list_payments(100).await.unwrap();
    eprintln!(
        "wallet phase={phase:?}; payments={}; response={}",
        payments.len(),
        response.status()
    );
    assert_ne!(phase, Some(Phase::Ended), "an ended call is never handed to the wallet");
    assert!(payments.is_empty(), "nothing is paid after the call ended: {payments:?}");
}

/// A shared-mock wallet that counts invoice payments and, on its first
/// settlement subscription (the invoice path, after the invoice passed its
/// binding check and before it is dispatched), takes the contacts' binding
/// map and keeps it.
struct BindingHeldAtDispatch {
    inner: SharedMockProvider,
    invoices: AtomicUsize,
    map: Mutex<Option<PeerKeys>>,
    held: Held,
}

#[async_trait::async_trait]
impl LightningProvider for BindingHeldAtDispatch {
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        self.inner.create_invoice(amount_msat, description, expiry_secs).await
    }

    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        self.invoices.fetch_add(1, Ordering::SeqCst);
        self.inner.pay_invoice(bolt11).await
    }

    async fn pay_invoice_with_fee_limit(
        &self,
        bolt11: &str,
        _fee_limit_msat: u64,
    ) -> Result<PaymentDetails, LightningError> {
        self.pay_invoice(bolt11).await
    }

    fn outgoing_payment_updates(&self) -> Option<BoxStream<'static, String>> {
        if let Some(map) = self.map.lock().unwrap().take() {
            *self.held.lock().unwrap() = Some(map.try_lock_owned().unwrap());
        }
        None
    }

    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        self.inner.get_payment_status(hash).await
    }

    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        self.inner.get_balance_msat().await
    }

    async fn is_available(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn a_binding_that_cannot_be_read_at_dispatch_refuses_the_invoice_as_not_dispatched() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.db");
    let recipient_wallet = SharedMockProvider::new(&ledger, "recipient", 0).unwrap();
    let invoice = recipient_wallet
        .create_invoice(1000, "local invoice", 3600)
        .await
        .unwrap();
    let sender = Arc::new(BindingHeldAtDispatch {
        inner: SharedMockProvider::new(&ledger, "sender", 10_000).unwrap(),
        invoices: AtomicUsize::new(0),
        map: Mutex::new(None),
        held: Arc::new(Mutex::new(None)),
    });
    let mut state = common::test_state_with_lightning(sender.clone());
    let (_, identity) = konsensus_core::NodeIdentity::generate().unwrap();
    let recipient = *identity.node_id();
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(
        common::ConnectedStubTransport::new(vec![recipient], state.invoice_requests.clone())
            .with_invoice_responder(move |_, amount| {
                assert_eq!(amount, 1000);
                Some(InvoiceResponseData {
                    recipient,
                    bolt11: invoice.bolt11.clone(),
                    payment_hash: invoice.payment_hash.clone(),
                })
            }),
    );
    *sender.map.lock().unwrap() = Some(state.peer_ln_pubkeys.clone());

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        create_payment_proof(&state, 1000, &recipient),
    )
    .await
    .expect("the dispatch boundary never waits for the binding");
    assert!(sender.held.lock().unwrap().is_some(), "the binding was held at dispatch: {result:?}");
    drop(sender.held.lock().unwrap().take());

    let refusal = match &result {
        Err(ApiError::RoutingFee { source, .. }) => source.as_ref(),
        Err(other) => other,
        Ok(_) => panic!("the invoice must not be paid: {result:?}"),
    };
    assert!(
        matches!(refusal, ApiError::NotDispatched(_)),
        "refused as not dispatched: {result:?}"
    );
    assert_eq!(sender.invoices.load(Ordering::SeqCst), 0, "the wallet was never asked to pay");
    assert_eq!(sender.get_balance_msat().await.unwrap(), 10_000);
    assert_eq!(recipient_wallet.get_balance_msat().await.unwrap(), 0);
}
