mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use konsensus_api::state::AppState;
use konsensus_core::traits::lightning::LightningProvider;
use konsensus_lightning::MockLightningProvider;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

// Simulate the already-converted LDK PaymentDetails at the API boundary.
// The real LDK conversion is covered by konsensus-lightning's unit tests.
fn fixture(backend: &str, fee: u64) -> (Arc<AppState>, Arc<MockLightningProvider>) {
    let wallet = Arc::new(MockLightningProvider::new().with_routing_fee_msat(fee));
    let mut state = test_state_with_lightning(wallet.clone());
    Arc::get_mut(&mut state).unwrap().lightning_backend = backend.into();
    (state, wallet)
}

async fn call(state: &Arc<AppState>, method: &str, path: &str, body: Value) -> Value {
    let response = test_router(state.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", auth_header(state))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 100_000)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "{method} {path}: {status}: {}: {e}",
            String::from_utf8_lossy(&bytes)
        )
    });
    assert_eq!(status, StatusCode::OK, "{value}");
    value
}

#[tokio::test]
async fn pay_and_keysend_report_actual_ldk_fee_including_zero() {
    for fee in [0, 400] {
        let (state, wallet) = fixture("ldk", fee);
        let invoice = wallet
            .create_invoice(1000, "fee report", 3600)
            .await
            .unwrap();
        let paid = call(
            &state,
            "POST",
            "/api/v1/payments/pay",
            json!({"bolt11":invoice.bolt11,"max_routing_fee_msat":1000}),
        )
        .await;
        assert_eq!(paid["fee_paid_msat"], fee);
        assert_eq!(paid["max_routing_fee_msat"], 1000);
        assert_eq!(paid["amount_msat"], 1000);
        let sent = call(&state, "POST", "/api/v1/payments/keysend", json!({"dest_pubkey":format!("02{}", "aa".repeat(32)),"amount_msat":1000,"max_routing_fee_msat":1000})).await;
        assert_eq!(sent["fee_paid_msat"], fee);
        assert_eq!(sent["max_routing_fee_msat"], 1000);
        assert_eq!(sent["amount_msat"], 1000);
        let status = call(
            &state,
            "GET",
            &format!(
                "/api/v1/payments/keysend-{}",
                sent["payment_hash"].as_str().unwrap()
            ),
            Value::Null,
        )
        .await;
        assert_eq!(status["fee_paid_msat"], fee);
    }
}

#[tokio::test]
async fn pending_and_other_backends_omit_actual_fee() {
    for backend in ["ldk", "lnd", "lnbits", "mock"] {
        let (state, wallet) = fixture(backend, 400);
        if backend == "ldk" {
            wallet.defer_next_keysend_settlement(100).await;
        }
        let sent = call(
            &state,
            "POST",
            "/api/v1/payments/keysend",
            json!({"dest_pubkey":format!("02{}", "aa".repeat(32)),"amount_msat":1000}),
        )
        .await;
        assert!(sent.get("fee_paid_msat").is_none(), "{backend}: {sent}");
        let status = call(
            &state,
            "GET",
            &format!(
                "/api/v1/payments/{}{}",
                if backend == "ldk" { "" } else { "keysend-" },
                sent["payment_hash"].as_str().unwrap()
            ),
            Value::Null,
        )
        .await;
        assert!(status.get("fee_paid_msat").is_none(), "{backend}: {status}");
        if backend != "ldk" {
            let invoice = wallet
                .create_invoice(1000, "fee report", 3600)
                .await
                .unwrap();
            let paid = call(
                &state,
                "POST",
                "/api/v1/payments/pay",
                json!({"bolt11":invoice.bolt11}),
            )
            .await;
            assert!(paid.get("fee_paid_msat").is_none(), "{backend}: {paid}");
        }
    }
}

#[tokio::test]
async fn compose_and_operation_replay_report_fee_without_repaying() {
    for (backend, fee) in [
        ("ldk", 0),
        ("ldk", 400),
        ("mock", 400),
        ("lnd", 400),
        ("lnbits", 400),
    ] {
        let (mut state, wallet) = fixture(backend, fee);
        let peer = setup_e2ee_session(&state.session_manager).await;
        Arc::get_mut(&mut state).unwrap().transport = Arc::new(ConnectedStubTransport::new(
            vec![peer],
            state.invoice_requests.clone(),
        ));
        state
            .peer_ln_pubkeys
            .lock()
            .await
            .insert(peer, format!("02{}", "aa".repeat(32)));
        let request = json!({"recipient":peer.to_hex(),"plaintext":"paid fee","kind":1,"max_total_msat":2000,"max_routing_fee_msat":1000,"wait_ack_ms":0});
        let paid = call(&state, "POST", "/api/v1/messages/compose", request.clone()).await;
        assert_eq!(paid["max_routing_fee_msat"], 1000);
        assert_eq!(paid["amount_msat"], 1000);
        let balance = wallet.get_balance_msat().await.unwrap();
        let mut replay_request = request;
        replay_request["operation_id"] = paid["operation_id"].clone();
        let replay = call(&state, "POST", "/api/v1/messages/compose", replay_request).await;
        let read = call(
            &state,
            "GET",
            &format!(
                "/api/v1/messages/operations/{}",
                paid["operation_id"].as_str().unwrap()
            ),
            Value::Null,
        )
        .await;
        for result in [paid, replay, read] {
            if backend == "ldk" {
                assert_eq!(result["fee_paid_msat"], fee, "{result}");
            } else {
                assert!(result.get("fee_paid_msat").is_none(), "{result}");
            }
        }
        assert_eq!(wallet.get_balance_msat().await.unwrap(), balance);
    }
}

#[tokio::test(start_paused = true)]
async fn room_fee_is_complete_sum_or_omitted_if_any_payment_is_unknown() {
    for (fee, pending) in [(0, false), (400, false), (400, true)] {
        let (mut state, wallet) = fixture("ldk", fee);
        let first = setup_e2ee_session(&state.session_manager).await;
        let second = setup_e2ee_session_with_mnemonic(
            &state.session_manager,
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .await;
        Arc::get_mut(&mut state).unwrap().transport = Arc::new(ConnectedStubTransport::new(
            vec![first, second],
            state.invoice_requests.clone(),
        ));
        let room = konsensus_storage::Room::new("fee room".into(), *state.identity.node_id());
        state.storage.create_room(&room).await.unwrap();
        for peer in [first, second] {
            state
                .storage
                .add_room_member(&room.id, &peer)
                .await
                .unwrap();
            state
                .peer_ln_pubkeys
                .lock()
                .await
                .insert(peer, format!("02{}", "aa".repeat(32)));
        }
        if pending {
            wallet.defer_next_keysend_settlement(u32::MAX).await;
        }
        let result = call(
            &state,
            "POST",
            "/api/v1/messages/compose",
            json!({
                "recipient":room.id.to_string(), "is_room":true, "kind":1, "plaintext":"room fees",
                "max_total_msat":4000, "max_routing_fee_msat":1000
            }),
        )
        .await;
        assert_eq!(result["max_routing_fee_msat"], 2000);
        if pending {
            assert!(result["member_outcomes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["status"] == "unknown"));
            assert!(result.get("fee_paid_msat").is_none(), "{result}");
        } else {
            assert_eq!(result["fee_paid_msat"], if fee == 0 { 0 } else { 800 });
            assert_eq!(result["amount_msat"], 2000);
        }
    }
}

#[tokio::test]
async fn changing_backend_does_not_turn_mock_history_into_ldk_fee_evidence() {
    let (mut state, _) = fixture("mock", 400);
    let peer = setup_e2ee_session(&state.session_manager).await;
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(ConnectedStubTransport::new(
        vec![peer],
        state.invoice_requests.clone(),
    ));
    state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(peer, format!("02{}", "aa".repeat(32)));
    let paid = call(
        &state,
        "POST",
        "/api/v1/messages/compose",
        json!({
            "recipient":peer.to_hex(), "kind":1, "plaintext":"mock history", "wait_ack_ms":0
        }),
    )
    .await;
    let mut restarted = test_state();
    Arc::get_mut(&mut restarted).unwrap().storage = state.storage.clone();
    Arc::get_mut(&mut restarted).unwrap().lightning_backend = "ldk".into();
    let result = call(
        &restarted,
        "GET",
        &format!(
            "/api/v1/messages/operations/{}",
            paid["operation_id"].as_str().unwrap()
        ),
        Value::Null,
    )
    .await;
    assert!(result.get("fee_paid_msat").is_none(), "{result}");
}
