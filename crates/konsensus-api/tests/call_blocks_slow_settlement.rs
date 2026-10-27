mod common;
use konsensus_api::calls;
use konsensus_core::payloads::call as rules;
use konsensus_storage::{SqliteStorage, Storage};
const ID: &str = "0123456789abcdef0123456789abcdef";
struct LateBlockWallet {
    inner: std::sync::Arc<konsensus_lightning::shared_mock::SharedMockProvider>,
    settle_at_ms: std::sync::atomic::AtomicU64,
    polled: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl konsensus_core::traits::lightning::LightningProvider for LateBlockWallet {
    async fn create_invoice(
        &self,
        amount: u64,
        description: &str,
        expiry: u32,
    ) -> Result<
        konsensus_core::traits::lightning::Invoice,
        konsensus_core::traits::lightning::LightningError,
    > {
        self.inner.create_invoice(amount, description, expiry).await
    }
    async fn pay_invoice(
        &self,
        invoice: &str,
    ) -> Result<
        konsensus_core::traits::lightning::PaymentDetails,
        konsensus_core::traits::lightning::LightningError,
    > {
        self.pay_invoice_with_fee_limit(invoice, 0).await
    }
    async fn pay_invoice_with_fee_limit(
        &self,
        invoice: &str,
        cap: u64,
    ) -> Result<
        konsensus_core::traits::lightning::PaymentDetails,
        konsensus_core::traits::lightning::LightningError,
    > {
        use std::sync::atomic::Ordering;
        self.polled.store(true, Ordering::SeqCst);
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let delay = self.settle_at_ms.load(Ordering::SeqCst).saturating_sub(now);
        let wallet = self.inner.clone();
        let invoice = invoice.to_owned();
        // Like LDK/LND, settlement may outlive cancellation of the dispatch future.
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            wallet.pay_invoice_with_fee_limit(&invoice, cap).await
        })
        .await
        .unwrap()
    }
    async fn get_payment_status(
        &self,
        hash: &str,
    ) -> Result<
        konsensus_core::traits::lightning::PaymentDetails,
        konsensus_core::traits::lightning::LightningError,
    > {
        self.inner.get_payment_status(hash).await
    }
    async fn get_balance_msat(
        &self,
    ) -> Result<u64, konsensus_core::traits::lightning::LightningError> {
        self.inner.get_balance_msat().await
    }
    async fn is_available(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn settlement_after_first_poll_never_charges_an_ungranted_interval() {
    use axum::{body::Body, http::Request};
    use konsensus_core::traits::lightning::LightningProvider;
    use konsensus_lightning::shared_mock::SharedMockProvider;
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    };
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("payments.sqlite");
    let payer = Arc::new(SharedMockProvider::new(&ledger, "caller", 100_000).unwrap());
    let payee = Arc::new(SharedMockProvider::new(&ledger, "callee", 0).unwrap());
    let wallet = Arc::new(LateBlockWallet {
        inner: payer.clone(),
        settle_at_ms: AtomicU64::new(0),
        polled: AtomicBool::new(false),
    });
    let mut state = common::test_state_with_lightning(wallet.clone());
    let (_, identity) = konsensus_core::NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let invoices = payee.clone();
    let transport = Arc::new(
        common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
            .with_invoice_responder(move |_, amount| {
                let invoice =
                    futures::executor::block_on(invoices.create_invoice(amount, "call block", 60))
                        .unwrap();
                Some(konsensus_api::state::InvoiceResponseData {
                    recipient: peer,
                    bolt11: invoice.bolt11,
                    payment_hash: invoice.payment_hash,
                })
            }),
    );
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.transport = transport;
    mutable.storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
    state
        .session_manager
        .initiate_session(&peer, &target.prekey_bundle().await)
        .await
        .unwrap();
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let answered_at = now - 10_000;
    let ringing = rules::commit(
        rules::reserve(None, 400, "offer", "hash", answered_at).unwrap(),
        "offer",
        answered_at,
    )
    .unwrap();
    let caller = rules::receive(Some(ringing), 401, None, answered_at).unwrap();
    let callee_store = SqliteStorage::in_memory().await.unwrap();
    let callee = rules::CallEntry {
        side: rules::Side::Callee,
        ..caller.clone()
    };
    callee_store
        .call_put(state.identity.node_id(), ID, &callee)
        .await
        .unwrap();
    wallet
        .settle_at_ms
        .store(caller.deadline_ms + 100, Ordering::SeqCst);
    state.storage.call_put(&peer, ID, &caller).await.unwrap();
    let plaintext = format!(r#"{{"call_id":"{ID}","seq":0}}"#);
    let request = Request::builder().method("POST").uri("/api/v1/messages/compose")
        .header("authorization", common::auth_header(&state)).header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"operation_id":uuid::Uuid::new_v4().to_string(),"recipient":peer.to_hex(),"kind":404,"plaintext":plaintext,"wait_ack_ms":0}).to_string())).unwrap();
    let quote = async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        state
            .peer_prices
            .update_kind_price(peer, 404, 23_000, 850_000)
            .await;
    };
    let (response, ()) = tokio::join!(common::test_router(state.clone()).oneshot(request), quote);
    let response = response.unwrap();
    // Let already-dispatched settlement complete even if compose stopped waiting.
    let remaining = wallet
        .settle_at_ms
        .load(Ordering::SeqCst)
        .saturating_sub(chrono::Utc::now().timestamp_millis() as u64);
    tokio::time::sleep(std::time::Duration::from_millis(remaining + 100)).await;
    let charged = 100_000 - payer.get_balance_msat().await.unwrap();
    calls::expire_calls(&callee_store, chrono::Utc::now().timestamp_millis() as u64).await.unwrap();
    let ended = callee_store.call_get(state.identity.node_id(), ID).await.unwrap().unwrap();
    assert_eq!(ended.phase, rules::Phase::Ended);
    let notice = rules::reserve_unpaid_hangup(Some(ended), "unpaid-notice", "hash").unwrap();
    callee_store.call_put(state.identity.node_id(), ID, &notice).await.unwrap();
    let admitted = calls::admit_incoming(
        &callee_store,
        &peer,
        state.identity.node_id(),
        404,
        Some(&plaintext),
    )
    .await
    .is_ok();
    let granted = admitted
        && calls::call_media_admitted(
            &callee_store,
            state.identity.node_id(),
            ID,
            chrono::Utc::now().timestamp_millis() as u64,
        )
        .await;
    assert!(
        wallet.polled.load(Ordering::SeqCst),
        "the regression must get past the first wallet poll"
    );
    assert!(
        charged == 23_000 && granted,
        "caller charged {charged} msat for a refused interval; compose status {}",
        response.status()
    );
}
