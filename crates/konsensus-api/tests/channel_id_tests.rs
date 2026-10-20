//! Channel identifiers at the owner HTTP boundary.
mod common;
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use konsensus_core::traits::lightning::*;
use std::sync::Arc;
use tower::ServiceExt;

// A decimal u128 beyond both JavaScript's exact integers and u64.
const USER_ID: &str = "88160000000000000000000000000000000001";
const CHANNEL_ID: &str = "abababababababababababababababababababababababababababababababab";
const FUNDING_TXO: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd:1";

struct ChannelBackend;
#[async_trait]
impl LightningProvider for ChannelBackend {
    async fn create_invoice(&self, a: u64, d: &str, e: u32) -> Result<Invoice, LightningError> {
        StubLightning.create_invoice(a, d, e).await
    }
    async fn pay_invoice(&self, i: &str) -> Result<PaymentDetails, LightningError> {
        StubLightning.pay_invoice(i).await
    }
    async fn get_payment_status(&self, h: &str) -> Result<PaymentDetails, LightningError> {
        StubLightning.get_payment_status(h).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(0)
    }
    async fn is_available(&self) -> bool {
        true
    }
    async fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
        Ok(vec![serde_json::from_value(serde_json::json!({
            "user_channel_id": USER_ID, "channel_id": CHANNEL_ID, "funding_txo": FUNDING_TXO,
            "peer_pubkey": "02abcdef", "capacity_msat": 100_000_000,
            "local_balance_msat": 90_000_000, "remote_balance_msat": 10_000_000,
            "active": false, "short_channel_id": null
        }))
        .unwrap()])
    }
    async fn close_channel(&self, id: &str, force: bool) -> Result<Option<String>, LightningError> {
        assert!(!force);
        assert!([USER_ID, CHANNEL_ID].contains(&id));
        Ok(None)
    }
    async fn open_channel_with_status(
        &self,
        _: &str,
        _: &str,
        _: u64,
        _: bool,
        _: Option<f32>,
    ) -> Result<ChannelOpenResult, LightningError> {
        Ok(serde_json::from_value(serde_json::json!({
            "user_channel_id": USER_ID, "channel_id": CHANNEL_ID, "funding_txo": FUNDING_TXO,
            "funding_txid": "cd".repeat(32), "status": "opening"
        }))
        .unwrap())
    }
    async fn open_channel_with_funding(
        &self,
        p: &str,
        a: &str,
        s: u64,
        n: bool,
        _: FundingOptions,
        _: Option<u64>,
    ) -> Result<ChannelOpenResult, LightningError> {
        self.open_channel_with_status(p, a, s, n, None).await
    }
}

#[tokio::test]
async fn channels_return_distinct_ids_and_both_can_be_sent_to_close() {
    let state = test_state_with_lightning(Arc::new(ChannelBackend));
    let auth = auth_header(&state);
    let app = test_router(state);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/payments/channels")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body[0]["user_channel_id"], USER_ID);
    assert_eq!(body[0]["channel_id"], CHANNEL_ID);
    assert_eq!(body[0]["funding_txo"], FUNDING_TXO);
    assert!(body[0]["short_channel_id"].is_null());
    for key in ["user_channel_id", "channel_id"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/payments/close-channel")
                    .header("authorization", &auth)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"channel_id":body[0][key]}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn successful_open_returns_200_with_all_ids_on_both_paths() {
    for explicit in [false, true] {
        let state = test_state_with_lightning(Arc::new(ChannelBackend));
        let auth = auth_header(&state);
        let mut request =
            serde_json::json!({"peer_pubkey":"peer", "peer_addr":"unused", "amount_sats":100000});
        if explicit {
            request["funding_priority"] = "economy".into();
        }
        let response = test_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/payments/open-channel")
                    .header("authorization", auth)
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["user_channel_id"], USER_ID);
        assert_eq!(body["channel_id"], CHANNEL_ID);
        assert_eq!(body["funding_txo"], FUNDING_TXO);
        assert_eq!(body["funding_txid"], "cd".repeat(32));
        assert_eq!(body["status"], "opening");
    }
}
