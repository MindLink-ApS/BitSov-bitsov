#![allow(dead_code)]
mod common;
use common::*;
use std::sync::Arc;
use axum::{body::Body, http::{Request, StatusCode}};
use tower::ServiceExt;
use serde_json::{json, Value};
use konsensus_api::state::AppState;
use konsensus_core::types::NodeId;

async fn fixture() -> (Arc<AppState>, NodeId, Arc<CountingLightning>) {
    let lightning = Arc::new(CountingLightning::default());
    let mut state = test_state_with_lightning(lightning.clone());
    let peer = setup_e2ee_session(&state.session_manager).await;
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone()));
    state.peer_ln_pubkeys.lock().await.insert(peer, "02aaaa".repeat(5));
    (state, peer, lightning)
}
async fn post(state: &Arc<AppState>, path: &str, body: Value) -> (StatusCode, Value) {
    let response = test_router(state.clone()).oneshot(Request::builder().method("POST").uri(path)
        .header("authorization", auth_header(state)).header("content-type","application/json")
        .body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 100000).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(json!({"raw":String::from_utf8_lossy(&bytes)})))
}
#[tokio::test]
async fn cap_refuses_before_any_invoice_or_payment_and_exact_cap_succeeds() {
    let (state, peer, lightning) = fixture().await;
    let mut body = json!({"recipient":peer.to_hex(),"kind":100,"plaintext":"cap", "max_total_msat":999});
    let (status, error) = post(&state,"/api/v1/messages/compose",body.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert_eq!(error["code"], "price_cap_exceeded");
    assert_eq!((lightning.money(),lightning.invoices()),(0,0));
    tokio::task::yield_now().await; // timeout cleanup runs in its spawned task
    assert!(state.invoice_requests.lock().await.is_empty());
    body["max_total_msat"] = json!(1000);
    let (status, receipt) = post(&state,"/api/v1/messages/compose",body).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["amount_msat"],1000);
    assert_eq!(lightning.money(),1);
}
#[tokio::test]
async fn status_advertises_enforced_cap_and_room_outcomes() {
    let (state,_,_) = fixture().await;
    let response = test_router(state.clone()).oneshot(Request::builder().uri("/api/v1/status")
        .header("authorization",auth_header(&state)).body(Body::empty()).unwrap()).await.unwrap();
    let bytes=axum::body::to_bytes(response.into_body(),100000).await.unwrap();
    let body:Value=serde_json::from_slice(&bytes).unwrap();
    assert!(body["api_capabilities"].as_array().unwrap().contains(&json!("paid_send_caps_v1")));
    assert!(body["api_capabilities"].as_array().unwrap().contains(&json!("room_terminal_outcomes_v1")));
}
#[tokio::test]
async fn room_checks_entire_budget_before_any_payment_and_reports_refused_member() {
    let (state,peer,lightning)=fixture().await;
    let (_,room)=post(&state,"/api/v1/rooms",json!({"name":"cap"})).await;
    let id=room["id"].as_str().unwrap();
    let other="bb".repeat(32);
    for member in [peer.to_hex(),other.clone()] {
        assert_eq!(post(&state,&format!("/api/v1/rooms/{id}/members"),json!({"node_id":member})).await.0,StatusCode::OK);
    }
    let mut body=json!({"recipient":id,"is_room":true,"kind":100,"plaintext":"room", "max_total_msat":1999,
        "max_recipient_msat":{peer.to_hex():1000,other.clone():1000}});
    let (status,error)=post(&state,"/api/v1/messages/compose",body.clone()).await;
    assert_eq!(status,StatusCode::CONFLICT,"{error}");
    assert_eq!(lightning.money(),0);
    body["max_total_msat"]=json!(2000);
    body["max_recipient_msat"][&other]=json!(999);
    assert_eq!(post(&state,"/api/v1/messages/compose",body.clone()).await.0,StatusCode::CONFLICT);
    assert_eq!(lightning.money(),0);
    body["max_recipient_msat"][&other]=json!(1000);
    body["max_recipient_msat"]["cc".repeat(32)]=json!(1000);
    assert_eq!(post(&state,"/api/v1/messages/compose",body.clone()).await.0,StatusCode::CONFLICT);
    assert_eq!(lightning.money(),0, "removed members must be refused before fanout");
    body["max_recipient_msat"].as_object_mut().unwrap().remove(&"cc".repeat(32));
    let (status,receipt)=post(&state,"/api/v1/messages/compose",body).await;
    assert_eq!(status,StatusCode::OK,"{receipt}");
    let rows=receipt["member_outcomes"].as_array().unwrap();
    assert_eq!(rows.len(),2);
    assert!(rows.iter().any(|r|r["recipient"]==peer.to_hex() && r["status"]=="settled"));
    assert!(rows.iter().any(|r|r["recipient"]==other && r["status"]=="refused"));
    assert_eq!(lightning.money(),1);
}
#[tokio::test]
async fn preencrypted_send_rejects_amount_above_cap_before_storing() {
    let (state,peer,lightning)=fixture().await;
    let (status,error)=post(&state,"/api/v1/messages",json!({"recipient":peer.to_hex(),"kind":100,"ciphertext":"aa",
      "payment_hash":"bb".repeat(32),"preimage":"cc".repeat(32),"amount_msat":1000,"max_total_msat":999})).await;
    assert_eq!(status,StatusCode::CONFLICT,"{error}");
    assert_eq!(error["code"],"price_cap_exceeded");
    assert_eq!(lightning.money(),0);
}

#[tokio::test]
async fn file_cap_is_checked_before_payment_and_exact_cap_is_paid_once() {
    let (state,peer,lightning)=fixture().await;
    let (status,file)=post(&state,"/api/v1/files",json!({"filename":"hi.txt","mime_type":"text/plain","data_b64":"aGk="})).await;
    assert_eq!(status,StatusCode::OK,"{file}");
    let path=format!("/api/v1/files/{}/send",file["file_id"].as_str().unwrap());
    let (status,error)=post(&state,&path,json!({"recipient":peer.to_hex(),"max_total_msat":999})).await;
    assert_eq!(status,StatusCode::CONFLICT,"{error}");
    assert_eq!(error["code"],"price_cap_exceeded");
    assert_eq!((lightning.money(),lightning.invoices()),(0,0));
    let (status,receipt)=post(&state,&path,json!({"recipient":peer.to_hex(),"max_total_msat":1000})).await;
    assert_eq!(status,StatusCode::OK,"{receipt}");
    assert_eq!(receipt["amount_msat"],1000);
    assert_eq!(lightning.money(),1);
}

#[tokio::test(start_paused = true)]
async fn capped_first_contact_cannot_pay_an_unquoted_admission() {
    let (mut state,_,lightning)=fixture().await;
    let stranger=NodeId::from_hex(&"cc".repeat(32)).unwrap();
    Arc::get_mut(&mut state).unwrap().transport=Arc::new(ConnectedStubTransport::new(vec![stranger],state.invoice_requests.clone()));
    let (status,error)=post(&state,"/api/v1/messages/compose",json!({"recipient":stranger.to_hex(),"kind":100,"plaintext":"hello","max_total_msat":1000000})).await;
    assert_eq!(status,StatusCode::INTERNAL_SERVER_ERROR,"{error}");
    assert_eq!((lightning.money(),lightning.invoices()),(0,0));
    tokio::task::yield_now().await; // timeout cleanup runs in its spawned task
    assert!(state.invoice_requests.lock().await.is_empty());
}

#[tokio::test(start_paused = true)]
async fn room_reports_inflight_member_as_unknown_alongside_settled_member() {
    mixed_room("unknown", "unknown", 2000).await;
}
#[tokio::test]
async fn room_reports_terminal_failure_as_refused_not_unknown() {
    mixed_room("failed", "refused", 1000).await;
}
#[tokio::test]
async fn room_preserves_settlement_when_payment_proof_is_unavailable() {
    mixed_room("no-proof", "settled", 2000).await;
}
async fn mixed_room(mode: &str, expected: &str, total: u64) {
    let lightning=Arc::new(MixedLightning::default());
    let mut state=test_state_with_lightning(lightning.clone());
    let first=setup_e2ee_session(&state.session_manager).await;
    let second=setup_e2ee_session_with_mnemonic(&state.session_manager,"legal winner thank year wave sausage worth useful legal winner thank yellow").await;
    Arc::get_mut(&mut state).unwrap().transport=Arc::new(ConnectedStubTransport::new(vec![first,second],state.invoice_requests.clone()));
    state.peer_ln_pubkeys.lock().await.extend([(first,"settled".into()),(second,mode.into())]);
    let (_,room)=post(&state,"/api/v1/rooms",json!({"name":"mixed"})).await;
    let id=room["id"].as_str().unwrap();
    for peer in [first,second] {
        assert_eq!(post(&state,&format!("/api/v1/rooms/{id}/members"),json!({"node_id":peer.to_hex()})).await.0,StatusCode::OK);
    }
    let (status,receipt)=post(&state,"/api/v1/messages/compose",json!({"recipient":id,"is_room":true,"kind":100,"plaintext":"mixed",
        "max_total_msat":2000,"max_recipient_msat":{first.to_hex():1000,second.to_hex():1000}})).await;
    assert_eq!(status,StatusCode::OK,"{receipt}");
    let rows=receipt["member_outcomes"].as_array().unwrap();
    assert_eq!(rows.len(),2);
    assert!(rows.iter().any(|r|r["recipient"]==first.to_hex() && r["status"]=="settled"));
    assert!(rows.iter().any(|r|r["recipient"]==second.to_hex() && r["status"]==expected));
    assert_eq!(receipt["amount_msat"],total);
    assert_eq!(lightning.money_calls.load(std::sync::atomic::Ordering::SeqCst),2);
}

use async_trait::async_trait;
use konsensus_core::traits::lightning::{LightningProvider, LightningError, Invoice, PaymentDetails, PaymentStatus};
#[derive(Default)]
struct MixedLightning {
    /// Incremented by `pay_invoice`, `keysend`, `send_onchain` and `open_channel`.
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
        dest_pubkey: &str,
        amount_msat: u64,
        memo: Option<&str>,
    ) -> Result<PaymentDetails, LightningError> {
        Self::bump(&self.money_calls);
        let mut result = StubLightning.keysend(dest_pubkey, amount_msat, memo).await?;
        if dest_pubkey == "unknown" { result.status=PaymentStatus::InFlight; result.preimage=None; }
        if dest_pubkey == "failed" { result.status=PaymentStatus::Failed; result.preimage=None; }
        if dest_pubkey == "no-proof" { result.preimage=None; }
        Ok(result)
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
            .open_channel(peer_pubkey, peer_addr, amount_sats, announce, fee_rate_sat_per_vb)
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
