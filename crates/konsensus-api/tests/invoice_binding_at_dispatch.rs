//! A contact's Lightning binding is read again when an invoice payment is
//! handed to the wallet, not only when the invoice is validated.
//!
//! The wallet below changes the contact's binding to `Unsigned` while the
//! invoice payment is being prepared: after the invoice passed its binding
//! check, before the payment future is polled. The payment must then be
//! refused as not dispatched, and no money may move.

mod common;

use async_trait::async_trait;
use futures::stream::BoxStream;
use konsensus_api::{
    handlers::messages::create_payment_proof,
    state::{InvoiceResponseData, PeerLightningKey},
};
use konsensus_core::{
    NodeId,
    traits::lightning::{Invoice, LightningError, LightningProvider, PaymentDetails},
};
use konsensus_lightning::shared_mock::SharedMockProvider;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

type PeerKeys = Arc<tokio::sync::Mutex<std::collections::HashMap<NodeId, PeerLightningKey>>>;

/// A shared-mock wallet that counts invoice payments and, on its second
/// settlement subscription, marks the contact `Unsigned`.
///
/// The payment path subscribes to settlement updates after validating the
/// invoice and before dispatching it. With a verified binding, the keysend
/// attempt subscribes first (and is refused by this wallet), so the invoice
/// path is the second subscription; with no binding, the invoice path is the
/// first, so the counter starts at one.
struct BindingChangesBeforeDispatch {
    inner: SharedMockProvider,
    invoices: AtomicUsize,
    subscriptions: AtomicUsize,
    change: Mutex<Option<(PeerKeys, NodeId)>>,
}

#[async_trait]
impl LightningProvider for BindingChangesBeforeDispatch {
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

    async fn keysend_with_fee_limit(
        &self,
        _destination: &str,
        _amount_msat: u64,
        _memo: Option<&str>,
        _fee_limit_msat: u64,
    ) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::PaymentNotDispatched("local no-route".into()))
    }

    fn outgoing_payment_updates(&self) -> Option<BoxStream<'static, String>> {
        if self.subscriptions.fetch_add(1, Ordering::SeqCst) == 1 {
            if let Some((map, peer)) = self.change.lock().unwrap().take() {
                map.try_lock().unwrap().insert(peer, PeerLightningKey::Unsigned);
            }
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

/// Pay a 1,000 msat invoice to a fresh contact. `verified`: the contact starts
/// with a verified binding to the invoice's payee (else with no binding).
/// `turns_unsigned`: the binding becomes `Unsigned` before dispatch.
async fn pay_contact(turns_unsigned: bool, verified: bool) {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.db");
    let recipient_wallet = SharedMockProvider::new(&ledger, "recipient", 0).unwrap();
    let invoice = recipient_wallet
        .create_invoice(1000, "local invoice", 3600)
        .await
        .unwrap();
    let payee = invoice
        .bolt11
        .parse::<lightning_invoice::Bolt11Invoice>()
        .unwrap()
        .recover_payee_pub_key()
        .to_string();
    let sender = Arc::new(BindingChangesBeforeDispatch {
        inner: SharedMockProvider::new(&ledger, "sender", 10_000).unwrap(),
        invoices: AtomicUsize::new(0),
        subscriptions: AtomicUsize::new(if verified { 0 } else { 1 }),
        change: Mutex::new(None),
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
    if verified {
        state
            .peer_ln_pubkeys
            .lock()
            .await
            .insert(recipient, PeerLightningKey::Verified(payee));
    }
    if turns_unsigned {
        *sender.change.lock().unwrap() = Some((state.peer_ln_pubkeys.clone(), recipient));
    }

    let result = create_payment_proof(&state, 1000, &recipient).await;
    let dispatched = sender.invoices.load(Ordering::SeqCst);
    let sender_msat = sender.get_balance_msat().await.unwrap();
    let recipient_msat = recipient_wallet.get_balance_msat().await.unwrap();

    if turns_unsigned {
        assert_eq!(dispatched, 0, "an Unsigned binding known before dispatch refuses the invoice");
        assert!(result.is_err(), "{result:?}");
        assert_eq!((sender_msat, recipient_msat), (10_000, 0));
    } else {
        assert!(result.is_ok(), "{result:?}");
        assert_eq!((dispatched, sender_msat, recipient_msat), (1, 9_000, 1_000));
    }
}

#[tokio::test]
async fn a_verified_contact_is_paid_by_invoice() {
    pay_contact(false, true).await;
}

#[tokio::test]
async fn a_verified_contact_that_turns_unsigned_before_dispatch_is_not_paid() {
    pay_contact(true, true).await;
}

#[tokio::test]
async fn a_contact_with_no_binding_that_turns_unsigned_before_dispatch_is_not_paid() {
    pay_contact(true, false).await;
}
