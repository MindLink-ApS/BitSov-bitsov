//! Guard subscribe-before-dispatch at the production payment-proof call sites.
//! The recovery wrapper matches AppState.lightning in the running node.
mod common;

use async_trait::async_trait;
use futures::stream::BoxStream;
use konsensus_api::{handlers::messages::create_payment_proof, state::InvoiceResponseData};
use konsensus_core::{
    traits::lightning::{
        Invoice, LightningError, LightningProvider, PaymentDetails, PaymentStatus,
    },
    NodeIdentity,
};
use konsensus_lightning::{MockLightningProvider, RecoveringLightning};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
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

    fn outgoing_payment_updates(&self) -> Option<BoxStream<'static, String>> {
        self.backend.outgoing_payment_updates()
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
