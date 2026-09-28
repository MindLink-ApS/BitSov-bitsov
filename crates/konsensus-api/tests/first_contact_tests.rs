mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use konsensus_api::{auth, state::InvoiceResponseData};
use konsensus_core::{traits::lightning::LightningProvider, NodeId};
use konsensus_lightning::shared_mock::SharedMockProvider;
use std::sync::Arc;
use tower::ServiceExt;

async fn admission_case(
    cap: u64,
    quote: u64,
    wrong_recipient: bool,
    wrong_hash: bool,
    establish: bool,
) -> (StatusCode, serde_json::Value, u64) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let a = Arc::new(SharedMockProvider::new(&path, "a", 100_000).unwrap());
    let b = Arc::new(SharedMockProvider::new(&path, "b", 0).unwrap());
    let mut state = common::test_state_with_lightning(a.clone());
    let (_, identity) = konsensus_core::identity::NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let handshake = if establish {
        let recipient = b.clone();
        let sender = state.session_manager.clone();
        Some(tokio::spawn(async move {
            loop {
                if recipient.get_balance_msat().await.unwrap() > 0 {
                    let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
                    sender
                        .initiate_session(&peer, &target.prekey_bundle().await)
                        .await
                        .unwrap();
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }))
    } else {
        None
    };
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(
        common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
            .with_invoice_responder(move |request_id, _hint| {
                let inv = futures::executor::block_on(b.create_invoice(
                    2000,
                    &format!("konsensus:{request_id}:message={quote}"),
                    55,
                ))
                .unwrap();
                Some(InvoiceResponseData {
                    recipient: if wrong_recipient {
                        NodeId::from_hex(&"ff".repeat(32)).unwrap()
                    } else {
                        peer
                    },
                    bolt11: inv.bolt11,
                    payment_hash: if wrong_hash {
                        "00".repeat(32)
                    } else {
                        inv.payment_hash
                    },
                })
            }),
    );
    let token = auth::create_token(
        &state.identity.node_id().to_hex(),
        &state.jwt_secret,
        auth::Scope::all(),
    )
    .unwrap();
    let response = common::test_router(state).oneshot(Request::builder().method("POST").uri("/api/v1/messages/compose")
        .header("authorization",format!("Bearer {token}")).header("content-type","application/json")
        .body(Body::from(serde_json::json!({"recipient":peer.to_hex(),"kind":0,"plaintext":"hello stranger","max_total_msat":cap}).to_string())).unwrap()).await.unwrap();
    if let Some(task) = handshake {
        task.abort();
    }
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 16_384)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap(),
        100_000 - a.get_balance_msat().await.unwrap(),
    )
}
#[tokio::test]
async fn target_aggregate_above_cap_is_refused_before_dispatch() {
    let (status, body, spent) = admission_case(13999, 2000, false, false, false).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "price_cap_exceeded");
    assert_eq!(spent, 0);
}
#[tokio::test(start_paused = true)]
async fn target_aggregate_at_cap_pays_admission_and_reports_later_timeout_as_paid() {
    let (status, body, spent) = admission_case(14000, 2000, false, false, false).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("payment settled"),
        "{body}"
    );
    assert_eq!(spent, 2000);
    assert_eq!(body["amount_msat"], 2000);
}
#[tokio::test]
async fn other_noise_recipient_cannot_redirect_admission_payment() {
    let (status, _, spent) = admission_case(14000, 2000, true, false, false).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(spent, 0);
}
#[tokio::test]
async fn admission_invoice_hash_must_match_authenticated_response() {
    let (status, _, spent) = admission_case(14000, 2000, false, true, false).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(spent, 0);
}

#[tokio::test]
async fn malicious_subminimum_quote_cannot_bypass_aggregate_cap() {
    let (status, _, spent) = admission_case(2001, 1, false, false, false).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(spent, 0);
}
#[tokio::test(start_paused = true)]
async fn complete_first_contact_reports_both_payments_under_one_cap() {
    let (status, body, spent) = admission_case(14000, 2000, false, false, true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["amount_msat"], 4000);
    assert_eq!(spent, 4000);
}

#[tokio::test(start_paused = true)]
async fn durable_unknown_attempt_is_reconciled_without_requesting_or_paying_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let a = Arc::new(SharedMockProvider::new(&path, "a", 100_000).unwrap());
    let b = SharedMockProvider::new(&path, "b", 0).unwrap();
    let (_, identity) = konsensus_core::identity::NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let invoice = b
        .create_invoice(2000, "konsensus:lost-request:message=2000", 60)
        .await
        .unwrap();
    // Model a prior process that settled, lost its response, then exited. Only
    // this durable attempt exists; the new API has no in-memory ledger entry.
    a.pay_invoice(&invoice.bolt11).await.unwrap();
    let journal = dir.path().join("admission-attempts");
    std::fs::create_dir(&journal).unwrap();
    std::fs::write(
        journal.join(peer.to_hex()),
        serde_json::to_vec(&serde_json::json!({
            "payment_hash":invoice.payment_hash,"amount_msat":2000,"quote":[0,2000],"envelope":null
        }))
        .unwrap(),
    )
    .unwrap();
    let mut state = common::test_state_with_lightning(a.clone());
    Arc::get_mut(&mut state).unwrap().data_dir = Some(dir.path().to_path_buf());
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = requests.clone();
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(
        common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
            .with_invoice_responder(move |_, _| {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                None
            }),
    );
    let token = auth::create_token(
        &state.identity.node_id().to_hex(),
        &state.jwt_secret,
        auth::Scope::all(),
    )
    .unwrap();
    let app = common::test_router(state);
    for _ in 0..2 {
        let response = app.clone().oneshot(Request::builder().method("POST").uri("/api/v1/messages/compose")
            .header("authorization",format!("Bearer {token}")).header("content-type","application/json")
            .body(Body::from(serde_json::json!({"recipient":peer.to_hex(),"kind":0,"plaintext":"retry","max_total_msat":14000}).to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let bytes = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(error["code"], "payment_settled_send_incomplete", "{error}");
        assert_eq!(
            error["amount_msat"], 0,
            "prior admission is not a new debit: {error}"
        );
    }
    assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(a.get_balance_msat().await.unwrap(), 98_000);
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(journal.join(peer.to_hex())).unwrap()).unwrap();
    assert!(persisted["envelope"].is_object());
}

struct FaultBackend {
    inner: SharedMockProvider,
    lose_response: bool,
    first: std::sync::atomic::AtomicBool,
    calls: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl LightningProvider for FaultBackend {
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
        use konsensus_core::traits::lightning::LightningError;
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let first = self.first.swap(false, std::sync::atomic::Ordering::SeqCst);
        if first && !self.lose_response {
            return Err(LightningError::PaymentNotDispatched(
                "local rejection".into(),
            ));
        }
        let paid = self.inner.pay_invoice(invoice).await?;
        if first {
            Err(LightningError::Connection(
                "response lost after dispatch".into(),
            ))
        } else {
            Ok(paid)
        }
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

#[tokio::test(start_paused = true)]
async fn lost_admission_response_never_pays_twice_but_explicit_non_dispatch_can_retry() {
    for lose_response in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.db");
        let a = Arc::new(FaultBackend {
            inner: SharedMockProvider::new(&path, "a", 100_000).unwrap(),
            lose_response,
            first: std::sync::atomic::AtomicBool::new(true),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let b = SharedMockProvider::new(&path, "b", 0).unwrap();
        let (_, identity) = konsensus_core::identity::NodeIdentity::generate().unwrap();
        let peer = *identity.node_id();
        let mut state = common::test_state_with_lightning(a.clone());
        Arc::get_mut(&mut state).unwrap().data_dir = Some(dir.path().to_path_buf());
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = requests.clone();
        Arc::get_mut(&mut state).unwrap().transport = Arc::new(
            common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
                .with_invoice_responder(move |rid, _| {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let inv = futures::executor::block_on(b.create_invoice(
                        2000,
                        &format!("konsensus:{rid}:message=2000"),
                        60,
                    ))
                    .unwrap();
                    Some(InvoiceResponseData {
                        recipient: peer,
                        bolt11: inv.bolt11,
                        payment_hash: inv.payment_hash,
                    })
                }),
        );
        let token = auth::create_token(
            &state.identity.node_id().to_hex(),
            &state.jwt_secret,
            auth::Scope::all(),
        )
        .unwrap();
        let app = common::test_router(state);
        for attempt in 0..2 {
            let response=app.clone().oneshot(Request::builder().method("POST").uri("/api/v1/messages/compose")
                .header("authorization",format!("Bearer {token}")).header("content-type","application/json")
                .body(Body::from(serde_json::json!({"recipient":peer.to_hex(),"kind":0,"plaintext":"retry","max_total_msat":14000}).to_string())).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            let bytes = axum::body::to_bytes(response.into_body(), 16384)
                .await
                .unwrap();
            let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            if attempt == 0 {
                assert_eq!(
                    dir.path()
                        .join("admission-attempts")
                        .join(peer.to_hex())
                        .exists(),
                    lose_response
                );
                assert!(
                    error["error"].as_str().unwrap().contains(if lose_response {
                        "unknown"
                    } else {
                        "not dispatched"
                    }),
                    "{error}"
                );
            } else {
                assert_eq!(error["code"], "payment_settled_send_incomplete", "{error}");
                assert_eq!(error["amount_msat"], if lose_response { 0 } else { 2000 });
            }
        }
        let expected = if lose_response { 1 } else { 2 };
        assert_eq!(a.calls.load(std::sync::atomic::Ordering::SeqCst), expected);
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), expected);
        assert_eq!(a.get_balance_msat().await.unwrap(), 98_000);
    }
}

/// The authenticated target may return a correctly signed invoice whose own
/// relative expiry is <=60 seconds but whose timestamp extends the attempt.
async fn admission_invoice_time_case(future_timestamp: bool) {
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let dir = tempfile::tempdir().unwrap();
    let payer = Arc::new(FaultBackend {
        inner: SharedMockProvider::new(&dir.path().join("ledger.db"), "payer", 100_000).unwrap(),
        lose_response: false,
        first: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
    });
    let mut state = common::test_state_with_lightning(payer.clone());
    let (_, identity) = konsensus_core::identity::NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(
        common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
            .with_invoice_responder(move |request_id, _| {
                let issued: u64 = request_id.split(':').nth(3).unwrap().parse().unwrap();
                let timestamp = if future_timestamp {
                    issued + 120
                } else {
                    // Model one second of target/backend latency. The invoice
                    // is current, but a fresh 60-second TTL exceeds the attempt.
                    std::thread::sleep(Duration::from_millis(1100));
                    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
                };
                let invoice = InvoiceBuilder::new(Currency::Regtest)
                    .description(format!("konsensus:{request_id}:message=2000"))
                    .payment_hash(sha256::Hash::hash(&[42; 32]))
                    .payment_secret(PaymentSecret([24; 32]))
                    .duration_since_epoch(Duration::from_secs(timestamp))
                    .min_final_cltv_expiry_delta(18)
                    .amount_milli_satoshis(2000)
                    .expiry_time(Duration::from_secs(60))
                    .build_signed(|hash| Secp256k1::new().sign_ecdsa_recoverable(
                        hash, &SecretKey::from_slice(&[7; 32]).unwrap(),
                    ))
                    .unwrap();
                Some(InvoiceResponseData {
                    recipient: peer,
                    payment_hash: invoice.payment_hash().to_string(),
                    bolt11: invoice.to_string(),
                })
            }),
    );
    let token = auth::create_token(&state.identity.node_id().to_hex(), &state.jwt_secret, auth::Scope::all()).unwrap();
    let response = common::test_router(state).oneshot(Request::builder()
        .method("POST").uri("/api/v1/messages/compose")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"recipient":peer.to_hex(),"kind":0,"plaintext":"hello","max_total_msat":14000}).to_string())).unwrap()).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 16_384).await.unwrap();
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{}", String::from_utf8_lossy(&body));
    assert_eq!(payer.calls.load(Ordering::SeqCst), 0, "invalid invoice time must be rejected before dispatch: {}", String::from_utf8_lossy(&body));
    assert_eq!(payer.get_balance_msat().await.unwrap(), 100_000);
}

#[tokio::test]
async fn admission_invoice_future_timestamp_is_rejected_before_dispatch() {
    admission_invoice_time_case(true).await;
}

#[tokio::test]
async fn admission_invoice_absolute_expiry_cannot_extend_attempt() {
    admission_invoice_time_case(false).await;
}

#[tokio::test]
async fn unsupported_quote_surfaces_code_without_payment() {
    use konsensus_api::state::InvoiceResponseError;
    let mut state = common::test_state();
    let peer = NodeId::from_bytes([87; 32]);
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone()));
    let requests = state.invoice_requests.clone();
    let refused = tokio::spawn(async move {
        loop {
            let mut pending = requests.lock().await;
            if let Some(id) = pending.keys().next().cloned() {
                pending.remove(&id).unwrap().send(Err(InvoiceResponseError {
                    recipient: peer, reason: "stateless_quote_unsupported".into(),
                })).unwrap();
                break;
            }
            drop(pending);
            tokio::task::yield_now().await;
        }
    });
    let balance = state.lightning.get_balance_msat().await.unwrap();
    let token = auth::create_token(&state.identity.node_id().to_hex(), &state.jwt_secret, auth::Scope::all()).unwrap();
    let response = common::test_router(state.clone()).oneshot(Request::builder().method("POST")
        .uri("/api/v1/messages/compose").header("authorization",format!("Bearer {token}"))
        .header("content-type","application/json")
        .body(Body::from(serde_json::json!({"recipient":peer.to_hex(),"kind":0,"plaintext":"hello","max_total_msat":14000}).to_string())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["code"], "stateless_quote_unsupported");
    assert_eq!(state.lightning.get_balance_msat().await.unwrap(), balance);
    refused.await.unwrap();
}
