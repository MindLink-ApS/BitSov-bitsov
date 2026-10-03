//! In-process HTTP boundary tests. No node is started and no socket is opened.
mod common;
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use konsensus_core::traits::lightning::*;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

struct Wallet(Mutex<Vec<LocalSpendReservation>>, Option<String>);
#[async_trait]
impl LightningProvider for Wallet {
    async fn create_invoice(
        &self,
        amount: u64,
        desc: &str,
        expiry: u32,
    ) -> Result<Invoice, LightningError> {
        StubLightning.create_invoice(amount, desc, expiry).await
    }
    async fn pay_invoice(&self, invoice: &str) -> Result<PaymentDetails, LightningError> {
        StubLightning.pay_invoice(invoice).await
    }
    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        StubLightning.get_payment_status(hash).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(0)
    }
    async fn is_available(&self) -> bool {
        true
    }
    async fn open_channel_with_status(
        &self,
        _: &str,
        _: &str,
        _: u64,
        _: bool,
        _: Option<f32>,
    ) -> Result<ChannelOpenResult, LightningError> {
        Ok(ChannelOpenResult {
            channel_id: "pending-channel".into(),
            funding_txid: Some("ab".repeat(32)),
            status: ChannelOpenStatus::PendingVisibility,
        })
    }
    fn local_spend_diagnostics(&self) -> LocalSpendDiagnostics {
        LocalSpendDiagnostics {
            unreadable_rows: 2,
            reservations: self.0.lock().unwrap().clone(),
        }
    }
    async fn release_local_spend(&self, txid: &str) -> Result<(), LightningError> {
        if let Some(reason) = &self.1 {
            return Err(LightningError::Backend(reason.clone()));
        }
        self.0.lock().unwrap().retain(|r| r.txid != txid);
        Ok(())
    }
}
fn wallet() -> Arc<Wallet> {
    Arc::new(Wallet(
        Mutex::new(vec![LocalSpendReservation {
            txid: "ab".repeat(32),
            created_at: 123,
            last_seen_at: None,
        }]),
        None,
    ))
}
async fn json(resp: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 65536).await.unwrap()).unwrap()
}
#[tokio::test]
async fn pending_visibility_is_http_success_with_channel_and_txid() {
    let state = test_state_with_lightning(wallet());
    let auth = auth_header(&state);
    let resp = test_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/payments/open-channel")
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"peer_pubkey":"peer","peer_addr":"unused","amount_sats":50000}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json(resp).await;
    assert_eq!(body["status"], "pending_visibility");
    assert_eq!(body["channel_id"], "pending-channel");
    assert_eq!(body["funding_txid"], "ab".repeat(32));
}
#[tokio::test]
async fn owner_release_and_status_diagnostics() {
    let state = test_state_with_lightning(wallet());
    let auth = auth_header(&state);
    let app = test_router(state);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = json(resp).await;
    assert_eq!(body["local_spends"]["unreadable_rows"], 2);
    assert_eq!(body["local_spends"]["reservations"][0]["created_at"], 123);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/payments/release-local-spend")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"txid": "ab".repeat(32)}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(json(resp).await["warning"]
        .as_str()
        .unwrap()
        .contains("may still propagate"));
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        json(resp).await["local_spends"]["reservations"],
        serde_json::json!([])
    );
    let public = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(json(public).await.get("local_spends").is_none());
}

#[tokio::test]
async fn refused_release_returns_clear_error_and_keeps_owner_diagnostics() {
    for reason in [
        "transaction is visible to the chain source; reservation retained",
        "chain-source lookup is inconclusive; reservation retained",
    ] {
        let mut provider = wallet();
        Arc::get_mut(&mut provider).unwrap().1 = Some(reason.into());
        let state = test_state_with_lightning(provider);
        let auth = auth_header(&state);
        let app = test_router(state);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/payments/release-local-spend")
                    .header("authorization", &auth)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"txid": "ab".repeat(32)}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body = json(resp).await;
        assert!(body["error"].as_str().unwrap().contains(reason));
        assert!(body.get("status").is_none());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .header("authorization", &auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            json(resp).await["local_spends"]["reservations"][0]["txid"],
            "ab".repeat(32)
        );
    }
}
