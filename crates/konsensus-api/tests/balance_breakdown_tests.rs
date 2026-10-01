//! Wallet honesty: production router and provider wrappers, no sockets or funds.
mod common;

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use konsensus_api::auth::{self, Scope};
use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails, WalletBalanceBreakdown, WalletSync,
};
use konsensus_lightning::{CircuitBreakerLightning, RecoveringLightning};
use tower::ServiceExt;

struct BalanceProvider(Option<WalletBalanceBreakdown>);

#[async_trait]
impl LightningProvider for BalanceProvider {
    async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
        panic!("balance read must not create an invoice")
    }
    async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        panic!("balance read must not move money")
    }
    async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        panic!("balance read must not query a payment")
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(987_654)
    }
    async fn get_balance_breakdown(&self) -> Result<WalletBalanceBreakdown, LightningError> {
        self.0.clone().ok_or(LightningError::NotReady)
    }
    async fn is_available(&self) -> bool {
        true
    }
    async fn wallet_sync(&self) -> WalletSync {
        WalletSync::NeverSynced
    }
}

async fn read(
    provider: Arc<dyn LightningProvider>,
    scopes: Option<Vec<Scope>>,
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    let state = common::test_state_with_lightning(provider);
    let mut request = Request::builder().uri("/api/v1/payments/balance");
    if let Some(scopes) = scopes {
        let token = auth::create_token(
            &state.identity.node_id().to_hex(),
            &state.jwt_secret,
            scopes,
        )
        .unwrap();
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = common::test_router(state)
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn read_scope_returns_breakdown_through_runtime_wrappers_with_freshness() {
    let backend: Arc<dyn LightningProvider> =
        Arc::new(BalanceProvider(Some(WalletBalanceBreakdown {
            onchain_spendable_sats: Some(70_000),
            onchain_total_sats: Some(100_000),
            anchor_reserve_sats: Some(20_000),
            lightning_spendable_sats: Some(321),
            closing_sats: Some(456),
            contested_sats: Some(789),
        })));
    let recovering = Arc::new(
        RecoveringLightning::new(
            move || {
                let backend = backend.clone();
                async move { Ok(backend) }
            },
            Default::default(),
        )
        .await
        .unwrap(),
    );
    tokio::task::yield_now().await;
    assert!(recovering.money_ready().await);
    let wrapped = Arc::new(CircuitBreakerLightning::new(
        recovering.clone(),
        Default::default(),
    ));
    let (status, headers, body) = read(wrapped, Some(vec![Scope::Read])).await;
    recovering.shutdown().await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["bitsov-data-stale"], "1");
    assert_eq!(
        body,
        serde_json::json!({
            "balance_msat": 987_654,
            "onchain_spendable_sats": 70_000,
            "onchain_total_sats": 100_000,
            "anchor_reserve_sats": 20_000,
            "lightning_spendable_sats": 321,
            "closing_sats": 456,
            "contested_sats": 789,
        })
    );
}

#[tokio::test]
async fn unsupported_provider_preserves_legacy_shape() {
    let (status, _, body) = read(Arc::new(common::StubLightning), Some(vec![Scope::Read])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({"balance_msat": 100_000_000}));
}

#[tokio::test]
async fn unknown_categories_are_omitted_but_known_zero_is_returned() {
    let provider = Arc::new(BalanceProvider(Some(WalletBalanceBreakdown {
        onchain_total_sats: Some(25),
        closing_sats: Some(0),
        ..Default::default()
    })));
    let (status, _, body) = read(provider, Some(vec![Scope::Read])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::json!({
            "balance_msat": 987_654, "onchain_total_sats": 25, "closing_sats": 0,
        })
    );
}

#[tokio::test]
async fn balance_breakdown_requires_read_scope_and_authentication() {
    for (scopes, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(vec![Scope::Receive]), StatusCode::FORBIDDEN),
        (Some(vec![Scope::Spend]), StatusCode::FORBIDDEN),
    ] {
        // An unavailable backend would return 503 if authorization were bypassed.
        let (status, _, _) = read(Arc::new(BalanceProvider(None)), scopes).await;
        assert_eq!(status, expected);
    }
}

#[tokio::test]
async fn unavailable_breakdown_is_an_error_not_zero_funds() {
    let (status, _, body) = read(Arc::new(BalanceProvider(None)), Some(vec![Scope::Read])).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.get("closing_sats").is_none());
}
