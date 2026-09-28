mod common;

use async_trait::async_trait;
use konsensus_api::{handlers::messages::create_payment_proof, state::InvoiceResponseData};
use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails,
};
use konsensus_lightning::shared_mock::SharedMockProvider;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// Entirely local shared-mock ledger. The first payment path explicitly proves
/// non-dispatch; the fallback records and really settles its mock invoice.
struct RejectedKeysend {
    inner: SharedMockProvider,
    expected_peer_key: String,
    keysend_calls: AtomicUsize,
    invoice_payments: AtomicUsize,
}

#[async_trait]
impl LightningProvider for RejectedKeysend {
    async fn pay_invoice_with_fee_limit(&self, invoice: &str, _cap: u64) -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError> {
        self.pay_invoice(invoice).await
    }

    async fn keysend_with_fee_limit(&self, dest: &str, amount: u64, memo: Option<&str>, _cap: u64) -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError> {
        self.keysend(dest, amount, memo).await
    }

    async fn create_invoice(
        &self,
        amount: u64,
        description: &str,
        expiry: u32,
    ) -> Result<Invoice, LightningError> {
        self.inner.create_invoice(amount, description, expiry).await
    }

    async fn pay_invoice(&self, invoice: &str) -> Result<PaymentDetails, LightningError> {
        self.invoice_payments.fetch_add(1, Ordering::SeqCst);
        self.inner.pay_invoice(invoice).await
    }

    async fn keysend(
        &self,
        destination: &str,
        _amount: u64,
        _memo: Option<&str>,
    ) -> Result<PaymentDetails, LightningError> {
        assert_eq!(destination, self.expected_peer_key);
        self.keysend_calls.fetch_add(1, Ordering::SeqCst);
        Err(LightningError::PaymentNotDispatched(
            "mock keysend unavailable before dispatch".into(),
        ))
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

async fn recipient_fallback_case(wrong_payee: bool) {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("mock-ledger.db");
    let intended = SharedMockProvider::new(&ledger, "recipient-b", 0).unwrap();
    let third_party = SharedMockProvider::new(&ledger, "third-party-c", 0).unwrap();
    let intended_invoice = intended
        .create_invoice(1000, "identify B's valid public key", 3600)
        .await
        .unwrap();
    let intended_key = intended_invoice
        .bolt11
        .parse::<lightning_invoice::Bolt11Invoice>()
        .unwrap()
        .recover_payee_pub_key()
        .to_string();
    let third_invoice = third_party
        .create_invoice(1000, "pay C instead of B", 3600)
        .await
        .unwrap();
    let third_key = third_invoice
        .bolt11
        .parse::<lightning_invoice::Bolt11Invoice>()
        .unwrap()
        .recover_payee_pub_key()
        .to_string();
    assert_ne!(intended_key, third_key);

    let invoice = if wrong_payee {
        third_invoice
    } else {
        intended_invoice
    };
    let sender = Arc::new(RejectedKeysend {
        inner: SharedMockProvider::new(&ledger, "sender-a", 10_000).unwrap(),
        expected_peer_key: intended_key.clone(),
        keysend_calls: AtomicUsize::new(0),
        invoice_payments: AtomicUsize::new(0),
    });
    let mut state = common::test_state_with_lightning(sender.clone());
    let (_, identity) = konsensus_core::identity::NodeIdentity::generate().unwrap();
    let recipient = *identity.node_id();
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(
        common::ConnectedStubTransport::new(vec![recipient], state.invoice_requests.clone())
            .with_invoice_responder(move |_, amount| {
                assert_eq!(amount, 1000);
                Some(InvoiceResponseData {
                    // Correct authenticated B responder; valid same-value invoice for C.
                    recipient,
                    bolt11: invoice.bolt11.clone(),
                    payment_hash: invoice.payment_hash.clone(),
                })
            }),
    );
    state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(recipient, intended_key);

    let result = create_payment_proof(&state, 1000, &recipient).await;
    let a = sender.get_balance_msat().await.unwrap();
    let b = intended.get_balance_msat().await.unwrap();
    let c = third_party.get_balance_msat().await.unwrap();
    eprintln!("recipient-binding repro: proof_ok={}, keysend_calls={}, pay_invoice_calls={}, A={a}, B={b}, C={c}",
        result.is_ok(), sender.keysend_calls.load(Ordering::SeqCst), sender.invoice_payments.load(Ordering::SeqCst));
    assert_eq!(sender.keysend_calls.load(Ordering::SeqCst), 1);
    if !wrong_payee {
        assert!(result.is_ok());
        assert_eq!(sender.invoice_payments.load(Ordering::SeqCst), 1);
        assert_eq!((a, b, c), (9000, 1000, 0));
        return;
    }
    assert_eq!(sender.invoice_payments.load(Ordering::SeqCst), 0,
        "must reject C's invoice before paying when B's Lightning key is known; A={a}, B={b}, C={c}, proof_ok={}", result.is_ok());
    assert!(result.is_err());
    assert_eq!((a, b, c), (10_000, 0, 0));
}

#[tokio::test]
async fn known_recipient_fallback_must_reject_third_party_payee_before_payment() {
    recipient_fallback_case(true).await;
}
#[tokio::test]
async fn known_recipient_fallback_pays_matching_payee_once() {
    recipient_fallback_case(false).await;
}
