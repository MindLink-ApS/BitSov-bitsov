#![allow(dead_code)]
mod common;
use common::*;
use std::sync::Arc;
use axum::{body::Body, http::{Request, StatusCode}};
use tower::ServiceExt;
use serde_json::{json, Value};
use konsensus_api::state::AppState;
use konsensus_core::{UkmEnvelope, types::NodeId, traits::{lightning::LightningProvider, transport::{MessageTransport, TransportError}}};

async fn post(state: &Arc<AppState>, path: &str, body: Value) -> (StatusCode, Value) {
    let response = test_router(state.clone()).oneshot(Request::builder().method("POST").uri(path)
        .header("authorization", auth_header(state)).header("content-type", "application/json")
        .body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 100000).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn owner_can_pay_invoice_created_by_actual_stock_mock() {
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new().with_routing_fee_msat(400));
    let before = wallet.get_balance_msat().await.unwrap();
    let state = test_state_with_lightning(wallet.clone());
    let (status, invoice) = post(&state, "/api/v1/payments/invoice", json!({"amount_msat": 1000, "description": "review round trip"})).await;
    assert_eq!(status, StatusCode::OK, "{invoice}");
    let signed: lightning_invoice::Bolt11Invoice = invoice["bolt11"].as_str().unwrap().parse().unwrap();
    assert_eq!(signed.currency(), lightning_invoice::Currency::Regtest);
    assert_eq!(signed.amount_milli_satoshis(), Some(1000));
    let (status, _) = post(&state, "/api/v1/payments/pay", json!({"bolt11": invoice["bolt11"], "max_routing_fee_msat":399})).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(wallet.get_balance_msat().await.unwrap(), before);
    let (status, paid) = post(&state, "/api/v1/payments/pay", json!({"bolt11": invoice["bolt11"], "max_routing_fee_msat":400})).await;
    assert_eq!(status, StatusCode::OK, "stock mock invoice rejected: {paid}");
    assert_eq!(paid["payment_hash"], invoice["payment_hash"]);
    assert_eq!(paid["max_routing_fee_msat"], 400);
    assert_eq!(before - wallet.get_balance_msat().await.unwrap(), 400, "self-payment loses only its actual fee");
}

struct FailingDelivery(NodeId, bool);
#[async_trait::async_trait]
impl MessageTransport for FailingDelivery {
    async fn send(&self, _: &NodeId, _: &UkmEnvelope) -> Result<(), TransportError> { if self.1 { return futures::future::pending().await; } Err(TransportError::Other("review delivery failure".into())) }
    async fn recv(&self) -> Result<UkmEnvelope, TransportError> { futures::future::pending().await }
    async fn connect(&self, _: &NodeId, _: &str) -> Result<(), TransportError> { Ok(()) }
    async fn disconnect(&self, _: &NodeId) -> Result<(), TransportError> { Ok(()) }
    async fn is_connected(&self, peer: &NodeId) -> bool { *peer == self.0 }
    async fn connected_peers(&self) -> Vec<NodeId> { vec![self.0] }
}

#[tokio::test]
async fn paid_file_delivery_error_reports_fee_ceiling() {
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new().with_routing_fee_msat(400));
    let before = wallet.get_balance_msat().await.unwrap();
    let mut state = test_state_with_lightning(wallet.clone());
    let peer = setup_e2ee_session(&state.session_manager).await;
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(FailingDelivery(peer, false));
    state.peer_ln_pubkeys.lock().await.insert(peer, format!("02{}", "aa".repeat(32)));
    let (status, file) = post(&state, "/api/v1/files", json!({"filename":"review.txt", "mime_type":"text/plain", "data_b64":"aGk="})).await;
    assert_eq!(status, StatusCode::OK, "{file}");
    let path = format!("/api/v1/files/{}/send", file["file_id"].as_str().unwrap());
    let (status, receipt) = post(&state, &path, json!({"recipient":peer.to_hex(), "max_total_msat":2000, "max_routing_fee_msat":1000})).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{receipt}");
    assert_eq!(before - wallet.get_balance_msat().await.unwrap(), 1400);
    assert_eq!(receipt["code"], "payment_settled_send_incomplete", "{receipt}");
    assert_eq!(receipt["max_routing_fee_msat"], 1000, "paid file lost its fee ceiling: {receipt}");
}

#[tokio::test(start_paused = true)]
async fn file_deadline_preserves_the_authorized_fee_ceiling() {
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new().with_routing_fee_msat(400));
    let before = wallet.get_balance_msat().await.unwrap();
    let mut state = test_state_with_lightning(wallet.clone());
    let peer = setup_e2ee_session(&state.session_manager).await;
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(FailingDelivery(peer, true));
    state.peer_ln_pubkeys.lock().await.insert(peer, format!("02{}", "aa".repeat(32)));
    let (_, file) = post(&state, "/api/v1/files", json!({"filename":"timeout.txt", "mime_type":"text/plain", "data_b64":"aGk="})).await;
    let path = format!("/api/v1/files/{}/send", file["file_id"].as_str().unwrap());
    let (status, receipt) = post(&state, &path, json!({"recipient":peer.to_hex(), "max_total_msat":2000, "max_routing_fee_msat":1000})).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{receipt}");
    assert_eq!(before - wallet.get_balance_msat().await.unwrap(), 1400);
    assert_eq!(receipt["code"], 502, "{receipt}");
    assert!(receipt["error"].as_str().unwrap().contains("deadline exceeded"));
    assert_eq!(receipt["max_routing_fee_msat"], 1000, "{receipt}");
}

#[tokio::test]
async fn owner_amountless_invoice_is_bad_request_without_debit() {
    use bitcoin::hashes::Hash;
    let key = bitcoin::secp256k1::SecretKey::from_slice(&[42; 32]).unwrap();
    let invoice = lightning_invoice::InvoiceBuilder::new(lightning_invoice::Currency::Regtest)
        .description("amountless".into()).payment_hash(bitcoin::hashes::sha256::Hash::from_byte_array([3; 32]))
        .payment_secret(lightning_invoice::PaymentSecret([4; 32])).current_timestamp().min_final_cltv_expiry_delta(18)
        .build_signed(|m| bitcoin::secp256k1::Secp256k1::new().sign_ecdsa_recoverable(m, &key)).unwrap();
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let before = wallet.get_balance_msat().await.unwrap();
    let state = test_state_with_lightning(wallet.clone());
    let (status, body) = post(&state, "/api/v1/payments/pay", json!({"bolt11":invoice.to_string()})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(wallet.get_balance_msat().await.unwrap(), before);
}

#[tokio::test]
async fn calendar_fanout_and_rsvp_report_aggregate_authorized_ceiling() {
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new().with_routing_fee_msat(400));
    let mut state = test_state_with_lightning(wallet.clone());
    let peer = setup_e2ee_session(&state.session_manager).await;
    let other = setup_e2ee_session_with_mnemonic(&state.session_manager,
        "legal winner thank year wave sausage worth useful legal winner thank yellow").await;
    let requests = state.invoice_requests.clone();
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(ConnectedStubTransport::new(vec![peer, other], requests));
    for id in [peer, other] { state.peer_ln_pubkeys.lock().await.insert(id, format!("02{}", "aa".repeat(32))); }
    let (status, event) = post(&state, "/api/v1/calendar/events", json!({
        "title":"fee report", "start":1800000000000u64, "end":1800003600000u64,
        "attendees":[peer.to_hex(), other.to_hex()]
    })).await;
    assert_eq!(status, StatusCode::OK, "{event}");
    assert_eq!(event["max_routing_fee_msat"], 10000, "{event}");
    let path = format!("/api/v1/calendar/events/{}/rsvp", event["event_id"].as_str().unwrap());
    let (status, rsvp) = post(&state, &path, json!({"response":"accepted", "organizer":peer.to_hex()})).await;
    assert_eq!(status, StatusCode::OK, "{rsvp}");
    assert_eq!(rsvp["max_routing_fee_msat"], 5000, "{rsvp}");
}
