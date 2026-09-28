//! Typed refusals must release only their own attempt, including after recovery.
use super::*;
use konsensus_api::handlers::messages::reconcile_operations;
use konsensus_storage::SqliteStorage;

async fn invoice_fixture() -> Fx {
    let mut fx = fixture().await;
    let peer = fx.peer;
    let transport = ConnectedStubTransport::new(vec![peer], fx.state.invoice_requests.clone())
        .with_invoice_responder(move |_, amount| {
            let bolt11 = create_test_bolt11(amount);
            let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
            Some(konsensus_api::state::InvoiceResponseData {
                payment_hash: invoice.payment_hash().to_string(), recipient: peer, bolt11,
            })
        });
    fx.state.peer_ln_pubkeys.lock().await.clear();
    fx.state = Arc::new(AppState {
        storage: Arc::new(SqliteStorage::open(fx.tmp.path().join("outbox.db").to_str().unwrap()).await.unwrap()),
        transport: Arc::new(transport),
        ..(*fx.state).clone()
    });
    fx
}

pub(super) async fn recover(fx: &mut Fx) {
    fx.restart();
    fx.state = Arc::new(AppState {
        storage: Arc::new(SqliteStorage::open(fx.tmp.path().join("outbox.db").to_str().unwrap()).await.unwrap()),
        ..(*fx.state).clone()
    });
    reconcile_operations(&fx.state).await.unwrap();
}

#[tokio::test]
async fn invoice_non_dispatch_retry_cannot_release_a_later_unknown_attempt() {
    let mut fx = invoice_fixture().await;
    let token = fx.grant(None, GrantTerms::new(4000)).await;
    let id = uuid::Uuid::new_v4().to_string();
    let request = json!({"operation_id":id,"recipient":fx.peer.to_hex(),"kind":100,
        "plaintext":"retry", "max_routing_fee_msat":500});
    fx.wallet.fee.store(501, Ordering::SeqCst);
    let (status, body) = fx.call("POST", "/api/v1/messages/compose", Some(request.clone()), Some(&token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "not_dispatched");
    assert_eq!(body["operation_id"], id);
    assert_eq!(body["state"], "prepared");
    assert_eq!(body["max_routing_fee_msat"], 500);
    assert_eq!(fx.used(), 0);
    assert_eq!(fx.wallet.money(), 0);
    recover(&mut fx).await;
    assert_eq!(fx.used(), 0);
    fx.wallet.fee.store(0, Ordering::SeqCst);
    fx.wallet.set(UNKNOWN);
    let (status, body) = fx.call("POST", "/api/v1/messages/compose", Some(request.clone()), Some(&token)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_ne!(body["code"], "not_dispatched");
    assert_eq!(body["state"], "payment_unknown");
    assert_eq!(fx.used(), 1500);
    for _ in 0..2 {
        recover(&mut fx).await;
        assert_eq!(fx.used(), 1500, "the previous release cannot consume this attempt");
        let (status, _) = fx.call("POST", "/api/v1/messages/compose", Some(request.clone()), Some(&token)).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }
    assert_eq!(fx.wallet.money(), 1, "unknown attempts cannot be dispatched again");
}

#[tokio::test]
async fn invoice_refusal_leaves_an_older_unknown_operation_held() {
    let mut fx = invoice_fixture().await;
    let token = fx.grant(None, GrantTerms::new(4000)).await;
    fx.wallet.set(UNKNOWN);
    let (status, body) = fx.compose(&token).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_ne!(body["code"], "not_dispatched");
    assert_eq!(fx.used(), 1000);
    fx.wallet.fee.store(1, Ordering::SeqCst);
    let (status, body) = fx.compose(&token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "not_dispatched");
    for _ in 0..2 {
        recover(&mut fx).await;
        assert_eq!(fx.used(), 1000, "only the refused attempt is released");
        assert_eq!(fx.service.reload_from_disk().unwrap().grants[0].budget.as_ref().unwrap().pending.len(), 1);
    }
}

#[tokio::test]
async fn channel_and_onchain_validation_is_not_dispatched_but_backend_errors_are_502() {
    for (route, request) in [
        ("open-channel", json!({"peer_pubkey":PEER_LN,"peer_addr":"127.0.0.1:9735","amount_sats":10000})),
        ("send-onchain", json!({"address":"bcrt1test","amount_sats":1000})),
    ] {
        let fx = fixture().await;
        let owner = auth_header(&fx.state);
        let owner = owner.trim_start_matches("Bearer ");
        let path = format!("/api/v1/payments/{route}");
        for rate in [0.0, 0.5, 10001.0] {
            let mut invalid = request.clone();
            invalid["fee_rate_sat_per_vb"] = json!(rate);
            let (status, body) = fx.call("POST", &path, Some(invalid), Some(owner)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{route}: {body}");
            assert_eq!(body["code"], "not_dispatched", "{route}: {body}");
            assert_eq!(fx.wallet.money(), 0);
        }
        fx.wallet.set(UNKNOWN);
        let (status, body) = fx.call("POST", &path, Some(request), Some(owner)).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{route}: {body}");
        assert_ne!(body["code"], "not_dispatched");
        assert_eq!(fx.wallet.money(), 1);
    }
}
