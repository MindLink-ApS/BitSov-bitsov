#![allow(dead_code)]
mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use konsensus_api::state::AppState;
use konsensus_core::types::NodeId;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

async fn post(state: &Arc<AppState>, path: &str, mut body: Value) -> (StatusCode, Value) {
    if path == "/api/v1/messages/compose" || (path.starts_with("/api/v1/files/") && path.ends_with("/send")) {
        body["max_routing_fee_msat"] = json!(0);
    }
    let response = test_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", auth_header(state))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 100000)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(json!({"raw":String::from_utf8_lossy(&bytes)})),
    )
}
use async_trait::async_trait;
use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails,
};
fn invoice_payee() -> String {
    create_test_bolt11(1000).parse::<lightning_invoice::Bolt11Invoice>()
        .unwrap().recover_payee_pub_key().to_string()
}
#[derive(Default)]
struct MixedLightning {
    error_kind: u8,
    /// Incremented by `pay_invoice`, `keysend`, `send_onchain` and `open_channel`.
    pub spent_msat: std::sync::atomic::AtomicU64,
    pub money_calls: std::sync::atomic::AtomicUsize,
    /// Incremented by `create_invoice` — a receive-side action, counted separately.
    pub invoice_calls: std::sync::atomic::AtomicUsize,
}

impl MixedLightning {
    pub fn money(&self) -> usize {
        self.money_calls.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn invoices(&self) -> usize {
        self.invoice_calls.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn bump(counter: &std::sync::atomic::AtomicUsize) {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait]
impl LightningProvider for MixedLightning {
    async fn pay_invoice_with_fee_limit(&self, invoice: &str, _cap: u64) -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError> {
        self.pay_invoice(invoice).await
    }

    async fn keysend_with_fee_limit(&self, dest: &str, amount: u64, memo: Option<&str>, _cap: u64) -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError> {
        self.keysend(dest, amount, memo).await
    }

    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        Self::bump(&self.invoice_calls);
        StubLightning
            .create_invoice(amount_msat, description, expiry_secs)
            .await
    }
    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        Self::bump(&self.money_calls);
        let amount = bolt11
            .parse::<lightning_invoice::Bolt11Invoice>()
            .unwrap()
            .amount_milli_satoshis()
            .unwrap();
        self.spent_msat
            .fetch_add(amount, std::sync::atomic::Ordering::SeqCst);
        StubLightning.pay_invoice(bolt11).await
    }
    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        StubLightning.get_payment_status(hash).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        StubLightning.get_balance_msat().await
    }
    async fn list_payments(&self, limit: u32) -> Result<Vec<PaymentDetails>, LightningError> {
        StubLightning.list_payments(limit).await
    }
    async fn keysend(
        &self,
        _dest: &str,
        amount: u64,
        _memo: Option<&str>,
    ) -> Result<PaymentDetails, LightningError> {
        Self::bump(&self.money_calls);
        if self.error_kind == 4 || _dest == invoice_payee() {
            return Err(LightningError::PaymentNotDispatched(
                "local validation rejected keysend".into(),
            ));
        }
        // Model the real LND sequence: dispatch succeeded, response body lost.
        self.spent_msat
            .fetch_add(amount, std::sync::atomic::Ordering::SeqCst);
        Err(match self.error_kind {
            1 => LightningError::Connection("timeout after request write".into()),
            2 => LightningError::PaymentFailed("no keysend result in response".into()),
            3 => LightningError::Backend("unknown error".into()),
            _ => LightningError::Backend("read keysend response interrupted after dispatch".into()),
        })
    }
    async fn is_available(&self) -> bool {
        StubLightning.is_available().await
    }
    async fn get_funding_address(&self) -> Option<String> {
        StubLightning.get_funding_address().await
    }
    async fn send_onchain(
        &self,
        address: &str,
        amount_sats: u64,
        fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<String, LightningError> {
        Self::bump(&self.money_calls);
        StubLightning
            .send_onchain(address, amount_sats, fee_rate_sat_per_vb)
            .await
    }
    async fn open_channel(
        &self,
        peer_pubkey: &str,
        peer_addr: &str,
        amount_sats: u64,
        announce: bool,
        fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<String, LightningError> {
        Self::bump(&self.money_calls);
        StubLightning
            .open_channel(
                peer_pubkey,
                peer_addr,
                amount_sats,
                announce,
                fee_rate_sat_per_vb,
            )
            .await
    }
    async fn close_channel(
        &self,
        channel_id: &str,
        force: bool,
    ) -> Result<Option<String>, LightningError> {
        StubLightning.close_channel(channel_id, force).await
    }
}

async fn review_fixture(
    reply: bool,
    error_kind: u8,
) -> (
    Arc<AppState>,
    NodeId,
    Arc<MixedLightning>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let lightning = Arc::new(MixedLightning {
        error_kind,
        ..Default::default()
    });
    let mut state = test_state_with_lightning(lightning.clone());
    let peer = setup_e2ee_session(&state.session_manager).await;
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = requests.clone();
    let transport = ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
        .with_invoice_responder(move |_, amount| {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(konsensus_api::state::InvoiceResponseData {
                recipient: peer,
                bolt11: if reply {
                    create_test_bolt11(amount)
                } else {
                    "invalid invoice".into()
                },
                payment_hash: "c2f480d4dda9f4522b9f6d590011636d904accfe59f12f9d66a0221c2558e3a2".into(),
            })
        });
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(transport);
    state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(peer, if error_kind == 4 { invoice_payee() } else { "02aaaa".repeat(5) });
    (state, peer, lightning, requests)
}

#[tokio::test]
async fn lost_keysend_response_never_dispatches_a_second_payment() {
    for path in ["peer", "file", "room"] {
        let (state, peer, lightning, requests) = review_fixture(true, 0).await;
        let (status,receipt)=match path {
            "file" => {
                let (_,file)=post(&state,"/api/v1/files",json!({"filename":"hi.txt","mime_type":"text/plain","data_b64":"aGk="})).await;
                post(&state,&format!("/api/v1/files/{}/send",file["file_id"].as_str().unwrap()),json!({"recipient":peer.to_hex(),"max_total_msat":1000})).await
            },
            "room" => {
                let (_,room)=post(&state,"/api/v1/rooms",json!({"name":"review"})).await;
                let room=room["id"].as_str().unwrap();
                post(&state,&format!("/api/v1/rooms/{room}/members"),json!({"node_id":peer.to_hex()})).await;
                post(&state,"/api/v1/messages/compose",json!({"recipient":room,"is_room":true,"kind":100,"plaintext":"review","max_total_msat":1000,"max_recipient_msat":{peer.to_hex():1000}})).await
            },
            _ => post(&state,"/api/v1/messages/compose",json!({"recipient":peer.to_hex(),"kind":100,"plaintext":"review","max_total_msat":1000})).await
        };
        if path == "room" {
            assert_eq!(status, StatusCode::OK, "{receipt}");
            assert_eq!(receipt["member_outcomes"][0]["status"], "unknown");
            assert_eq!(receipt["member_outcomes"][0]["amount_msat"], 1000);
            assert_eq!(receipt["amount_msat"], 1000);
        } else {
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{receipt}");
        }
        assert_eq!(
            lightning
                .spent_msat
                .load(std::sync::atomic::Ordering::SeqCst),
            1000
        );
        assert_eq!(lightning.money(), 1);
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
        println!(
            "{path}: cap=1000, reserved/dispatched=1000, payment dispatches=1, invoice requests=0"
        );
    }
}

#[tokio::test]
async fn unresolved_room_keysend_reserves_cap_and_never_becomes_refused() {
    let (state, peer, lightning, requests) = review_fixture(false, 0).await;
    let (_, room) = post(&state, "/api/v1/rooms", json!({"name":"review"})).await;
    let room = room["id"].as_str().unwrap();
    post(
        &state,
        &format!("/api/v1/rooms/{room}/members"),
        json!({"node_id":peer.to_hex()}),
    )
    .await;
    let (status,receipt)=post(&state,"/api/v1/messages/compose",json!({"recipient":room,"is_room":true,"kind":100,"plaintext":"review","max_total_msat":1000,"max_recipient_msat":{peer.to_hex():1000}})).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["member_outcomes"][0]["status"], "unknown");
    assert_eq!(receipt["amount_msat"], 1000);
    assert_eq!(
        lightning
            .spent_msat
            .load(std::sync::atomic::Ordering::SeqCst),
        1000
    );
    assert_eq!(lightning.money(), 1);
    assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn generic_connection_parse_and_unknown_errors_never_allow_fallback() {
    for mode in 1..=3 {
        let (state, peer, lightning, requests) = review_fixture(true, mode).await;
        let (status,_) = post(&state,"/api/v1/messages/compose",json!({"recipient":peer.to_hex(),"kind":100,"plaintext":"review","max_total_msat":1000})).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(lightning.money(), 1);
        assert_eq!(
            lightning
                .spent_msat
                .load(std::sync::atomic::Ordering::SeqCst),
            1000
        );
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn proven_predispatch_rejection_can_fall_back_without_exceeding_cap() {
    let (state, peer, lightning, requests) = review_fixture(true, 4).await;
    let (status, receipt) = post(
        &state,
        "/api/v1/messages/compose",
        json!({"recipient":peer.to_hex(),"kind":100,"plaintext":"review","max_total_msat":1000}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["amount_msat"], 1000);
    assert_eq!(
        lightning
            .spent_msat
            .load(std::sync::atomic::Ordering::SeqCst),
        1000
    );
    assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        lightning.money(),
        2,
        "one rejected call and one invoice payment"
    );
}

#[tokio::test]
async fn room_reserves_unknown_member_alongside_safe_fallback_within_total_cap() {
    let (mut state, first, lightning, requests) = review_fixture(true, 0).await;
    let second = setup_e2ee_session_with_mnemonic(
        &state.session_manager,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    )
    .await;
    let counted = requests.clone();
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(
        ConnectedStubTransport::new(vec![first, second], state.invoice_requests.clone())
            .with_invoice_responder(move |_, amount| {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Some(konsensus_api::state::InvoiceResponseData {
                recipient: second,
                    bolt11: create_test_bolt11(amount),
                    payment_hash: "c2f480d4dda9f4522b9f6d590011636d904accfe59f12f9d66a0221c2558e3a2".into(),
                })
            }),
    );
    state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(second, invoice_payee());
    let (_, room) = post(&state, "/api/v1/rooms", json!({"name":"mixed"})).await;
    let room = room["id"].as_str().unwrap();
    for peer in [first, second] {
        post(
            &state,
            &format!("/api/v1/rooms/{room}/members"),
            json!({"node_id":peer.to_hex()}),
        )
        .await;
    }
    let mut request = json!({"recipient":room,"is_room":true,"kind":100,"plaintext":"review","max_total_msat":1999,"max_recipient_msat":{first.to_hex():1000,second.to_hex():1000}});
    assert_eq!(
        post(&state, "/api/v1/messages/compose", request.clone())
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(lightning.money(), 0);
    assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
    request["max_total_msat"] = json!(2000);
    let (status, receipt) = post(&state, "/api/v1/messages/compose", request).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["amount_msat"], 2000);
    let rows = receipt["member_outcomes"].as_array().unwrap();
    assert!(rows.iter().any(|row| row["recipient"] == first.to_hex()
        && row["status"] == "unknown"
        && row["amount_msat"] == 1000));
    assert!(rows.iter().any(|row| row["recipient"] == second.to_hex()
        && row["status"] == "settled"
        && row["amount_msat"] == 1000));
    assert_eq!(
        lightning
            .spent_msat
            .load(std::sync::atomic::Ordering::SeqCst),
        2000
    );
    assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
}
