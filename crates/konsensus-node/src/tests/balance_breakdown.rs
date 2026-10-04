//! Exercise the authenticated API through the node's real provider wrappers.
use super::test_common as common;

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use konsensus_api::auth::{self, Scope};
use konsensus_lightning::{CircuitBreakerLightning, RecoveringLightning};
use tower::ServiceExt;

struct BalanceProvider;

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
        Ok(WalletBalanceBreakdown {
            onchain_spendable_sats: Some(70_000),
            onchain_total_sats: Some(100_000),
            anchor_reserve_sats: Some(20_000),
            lightning_spendable_sats: Some(321),
            closing_sats: Some(456),
            contested_sats: Some(789),
        })
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn wallet_sync(&self) -> WalletSync {
        WalletSync::NeverSynced
    }
}

async fn assert_balance_breakdown(disk_floor: u64, with_circuit_breaker: bool) {
    let dir = tempfile::tempdir().unwrap();
    let disk = Arc::new(DiskGuard::new(dir.path().into(), disk_floor));
    assert_eq!(disk.refresh().disk_low, disk_floor == u64::MAX);
    let recovering = Arc::new(
        RecoveringLightning::new(
            || async { Ok(Arc::new(BalanceProvider) as Arc<dyn LightningProvider>) },
            Default::default(),
        )
        .await
        .unwrap(),
    );
    tokio::task::yield_now().await;
    assert!(recovering.money_ready().await);
    // Node::new's embedded API stack is GuardedLightning -> RecoveringLightning
    // -> backend. Also exercise all three wrappers composed together; the live
    // circuit breaker is currently used only by the inbound settlement verifier.
    let inner: Arc<dyn LightningProvider> = if with_circuit_breaker {
        Arc::new(CircuitBreakerLightning::with_defaults(recovering.clone()))
    } else {
        recovering.clone()
    };
    let provider = Arc::new(GuardedLightning {
        inner,
        disk,
        _state_guard: Arc::new(
            crate::safety::ensure_generation(dir.path(), crate::safety::STATE_GENERATION).unwrap(),
        ),
    });
    let state = common::test_state_with_lightning(provider);
    let token = auth::create_token(
        &state.identity.node_id().to_hex(),
        &state.jwt_secret,
        vec![Scope::Read],
    )
    .unwrap();
    let response = common::test_router(state)
        .oneshot(
            Request::builder()
                .uri("/api/v1/payments/balance")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    recovering.shutdown().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["bitsov-data-stale"], "1");
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
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
async fn balance_breakdown_survives_node_api_stack() {
    assert_balance_breakdown(0, false).await;
}

#[tokio::test]
async fn balance_breakdown_remains_readable_when_disk_guard_blocks_writes() {
    assert_balance_breakdown(u64::MAX, false).await;
}

#[tokio::test]
async fn balance_breakdown_survives_all_wrappers_with_low_disk() {
    assert_balance_breakdown(u64::MAX, true).await;
}
