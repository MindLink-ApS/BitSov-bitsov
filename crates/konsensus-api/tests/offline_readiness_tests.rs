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

struct Offline;
#[async_trait]
impl LightningProvider for Offline {
    async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
        panic!("offline invoice dispatched")
    }
    async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        panic!("offline pay dispatched")
    }
    async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::Connection("offline".into()))
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Err(LightningError::Connection("offline".into()))
    }
    async fn is_available(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn offline_money_routes_return_not_ready() {
    let state = test_state_with_lightning(Arc::new(Offline));
    let auth = auth_header(&state);
    let app = test_router(state);
    let cases = [
        (
            "invoice",
            serde_json::json!({"amount_msat":1000,"description":"test"}),
        ),
        (
            "pay",
            serde_json::json!({"bolt11":"unparsed-while-offline"}),
        ),
        (
            "keysend",
            serde_json::json!({"dest_pubkey":"02".to_string()+&"11".repeat(32),"amount_msat":1000}),
        ),
        (
            "open-channel",
            serde_json::json!({"peer_pubkey":"02","peer_addr":"localhost:9735","amount_sats":10000}),
        ),
        (
            "close-channel",
            serde_json::json!({"channel_id":"1","force":false}),
        ),
        (
            "send-onchain",
            serde_json::json!({"address":"unused","amount_sats":1000}),
        ),
        (
            "liquidity/quote",
            serde_json::json!({"gross_msat":1000,"max_lsp_fee_msat":10}),
        ),
        (
            "liquidity/accept",
            serde_json::json!({"quote_id":"unused","provider":"unused","max_lsp_fee_msat":10}),
        ),
    ];
    for (route, body) in cases {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/payments/{route}"))
                    .header("authorization", &auth)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{route}"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["code"], "not_ready", "{route}: {body}");
    }
}

#[tokio::test]
async fn offline_status_keeps_identity_and_reports_unknown_wallet() {
    let state = test_state_with_lightning(Arc::new(Offline));
    let expected = state.identity.node_id().to_hex();
    let auth = auth_header(&state);
    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 16384)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["node_id"], expected);
    assert_eq!(body["money_ready"], false);
    assert!(body["lightning_balance_msat"].is_null());
}

struct UnreachableChain;
#[async_trait]
impl konsensus_core::traits::chain::ChainProvider for UnreachableChain {
    async fn get_block_height(&self) -> Result<u64, konsensus_core::traits::chain::ChainError> {
        panic!("offline compose must not consult the chain service")
    }
    async fn get_block_header(
        &self,
        _: u64,
    ) -> Result<konsensus_core::traits::chain::BlockHeader, konsensus_core::traits::chain::ChainError>
    {
        unreachable!()
    }
    async fn estimate_fee(
        &self,
        _: u32,
    ) -> Result<konsensus_core::traits::chain::FeeEstimate, konsensus_core::traits::chain::ChainError>
    {
        unreachable!()
    }
    async fn is_tx_confirmed(
        &self,
        _: &str,
        _: u32,
    ) -> Result<bool, konsensus_core::traits::chain::ChainError> {
        unreachable!()
    }
    async fn is_synced(&self) -> bool {
        false
    }
    fn trust_level(&self) -> konsensus_core::traits::chain::TrustLevel {
        konsensus_core::traits::chain::TrustLevel::ServerTrust
    }
}

#[tokio::test]
async fn paid_compose_refused_before_transport_or_storage() {
    let state = test_state_with_lightning(Arc::new(Offline));
    let state = Arc::new(konsensus_api::state::AppState {
        chain: Arc::new(UnreachableChain),
        ..(*state).clone()
    });
    let auth = auth_header(&state);
    let response = test_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/messages/compose")
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"recipient":"ab".repeat(32),"kind":1,"plaintext":"offline"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["code"], "not_ready");
}

#[tokio::test]
async fn offline_local_reads_and_pairing_complete() {
    use ed25519_dalek::{Signer, SigningKey};
    use konsensus_api::{
        pairing::{self, PairingService},
        state::AppState,
    };
    let dir = tempfile::tempdir().unwrap();
    let base = test_state_with_data_dir(dir.path().into());
    let pairing = Arc::new(
        PairingService::open(
            dir.path(),
            pairing::identity_fingerprint(&base.identity.node_id().to_hex()),
            false,
        )
        .unwrap()
        .without_stdout_code(),
    );
    let state = Arc::new(AppState {
        lightning: Arc::new(Offline),
        pairing: Some(pairing.clone()),
        ..(*base).clone()
    });
    let auth = auth_header(&state);
    let app = test_router(state);
    for route in ["health", "identity", "peers", "messages"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/{route}"))
                    .header("authorization", &auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{route}");
    }
    async fn post(app: &axum::Router, path: &str, body: serde_json::Value) -> serde_json::Value {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16384)
                .await
                .unwrap(),
        )
        .unwrap()
    }
    let key = SigningKey::from_bytes(&[29; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let request = post(
        &app,
        "/api/v1/pair/request",
        serde_json::json!({"client_name":"offline desktop", "client_pubkey":pubkey}),
    )
    .await;
    let pair_id = request["pair_id"].as_str().unwrap();
    let challenge = std::fs::read(pairing.dir().join(format!("challenge-{pair_id}"))).unwrap();
    let signature = hex::encode(
        key.sign(&PairingService::proof_message(pair_id, &pubkey, &challenge))
            .to_bytes(),
    );
    let confirmation = post(
        &app,
        "/api/v1/pair/confirm",
        serde_json::json!({"pair_id":pair_id,"signature":signature}),
    )
    .await;
    assert!(confirmation["client_id"].is_string());
}
