//! Owner HTTP boundary, in-process: no sockets and no money.
mod common;
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use konsensus_core::traits::lightning::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tower::ServiceExt;

#[derive(Default)]
struct FundingBackend {
    opens: AtomicUsize,
    quotes: AtomicUsize,
}
fn estimate(options: FundingOptions) -> FundingFeeEstimate {
    let (blocks, rate) = match options.priority {
        FundingPriority::Economy => (144, 2.0),
        FundingPriority::Normal => (12, 6.0),
        FundingPriority::Fast => (6, 12.0),
    };
    FundingFeeEstimate {
        priority: options.priority,
        confirmation_target_blocks: blocks,
        expected_confirmation_minutes: blocks * 10,
        estimated_fee_rate_sat_per_vb: rate,
        max_funding_fee_sats: options.max_funding_fee_sats,
    }
}
#[async_trait]
impl LightningProvider for FundingBackend {
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
    async fn funding_fee_quote(
        &self,
        options: FundingOptions,
    ) -> Result<FundingFeeEstimate, LightningError> {
        self.quotes.fetch_add(1, Ordering::SeqCst);
        Ok(estimate(options))
    }
    async fn open_channel_with_funding(
        &self,
        peer: &str,
        addr: &str,
        amount: u64,
        announce: bool,
        options: FundingOptions,
    ) -> Result<ChannelOpenResult, LightningError> {
        assert_eq!(
            (peer, addr, amount, announce),
            ("peer", "unused", 50000, true)
        );
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(ChannelOpenResult {
            channel_id: "channel".into(),
            funding_txid: Some("ab".repeat(32)),
            status: ChannelOpenStatus::PendingVisibility,
            funding_fee: Some(estimate(options)),
        })
    }
}
async fn call(
    backend: Arc<dyn LightningProvider>,
    extra: serde_json::Value,
    owner: bool,
) -> (StatusCode, serde_json::Value) {
    let state = test_state_with_lightning(backend);
    let auth = if owner {
        auth_header(&state)
    } else {
        format!(
            "Bearer {}",
            konsensus_api::auth::create_token(
                &state.identity.node_id().to_hex(),
                &state.jwt_secret,
                konsensus_api::auth::Scope::loopback_only()
            )
            .unwrap()
        )
    };
    let mut body = serde_json::json!({"peer_pubkey":"peer","peer_addr":"unused","amount_sats":50000,"announce":true});
    body.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let response = test_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/payments/open-channel")
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::json!({"text":String::from_utf8_lossy(&bytes)}));
    (status, json)
}
#[tokio::test]
async fn preview_does_not_open_and_open_response_keeps_selected_estimate_and_visibility() {
    let backend = Arc::new(FundingBackend::default());
    for (priority, blocks, minutes, rate) in [
        ("economy", 144, 1440, 2.0),
        ("normal", 12, 120, 6.0),
        ("fast", 6, 60, 12.0),
    ] {
        let (status, preview) = call(backend.clone(), serde_json::json!({"funding_priority":priority,"dry_run":true,"max_funding_fee_sats":1000}),true).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(preview["status"], "preview");
        let fee = &preview["funding_fee"];
        assert_eq!(fee["priority"], priority);
        assert_eq!(fee["confirmation_target_blocks"], blocks);
        assert_eq!(fee["expected_confirmation_minutes"], minutes);
        assert_eq!(fee["estimated_fee_rate_sat_per_vb"], rate);
        assert_eq!(fee["max_funding_fee_sats"], 1000);
    }
    assert_eq!(backend.opens.load(Ordering::SeqCst), 0);
    let (status, opened) = call(
        backend.clone(),
        serde_json::json!({"funding_priority":"fast","max_funding_fee_sats":1000}),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(opened["status"], "pending_visibility");
    assert_eq!(opened["channel_id"], "channel");
    assert_eq!(opened["funding_fee"]["priority"], "fast");
    assert_eq!(opened["funding_fee"]["estimated_fee_rate_sat_per_vb"], 12.0);
    assert_eq!(opened["funding_fee"]["max_funding_fee_sats"], 1000);
    assert_eq!(backend.opens.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn rejects_unknown_priorities_invalid_caps_and_exact_rate_combinations_before_dispatch() {
    let backend = Arc::new(FundingBackend::default());
    for extra in [
        serde_json::json!({"funding_priority":"turbo"}),
        serde_json::json!({"confirmation_target_blocks":1}),
        serde_json::json!({"max_funding_fee_sats":0}),
        serde_json::json!({"max_funding_fee_sats":u64::MAX}),
        serde_json::json!({"funding_priority":"fast","fee_rate_sat_per_vb":2}),
        serde_json::json!({"dry_run":true,"fee_rate_sat_per_vb":2}),
    ] {
        let (status, _) = call(backend.clone(), extra, true).await;
        assert!(status.is_client_error());
    }
    assert_eq!(backend.opens.load(Ordering::SeqCst), 0);
    assert_eq!(backend.quotes.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn unsupported_backends_refuse_priorities_caps_and_preview() {
    for extra in [
        serde_json::json!({"funding_priority":"normal"}),
        serde_json::json!({"dry_run":true}),
        serde_json::json!({"max_funding_fee_sats":1000}),
    ] {
        let (status, body) = call(Arc::new(StubLightning), extra, true).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "not_dispatched");
        assert!(body["error"].as_str().unwrap().contains("not supported"));
    }
}
#[tokio::test]
async fn funding_controls_require_owner_spend_scope_including_preview() {
    let backend = Arc::new(FundingBackend::default());
    for dry_run in [true, false] {
        let (status, _) = call(
            backend.clone(),
            serde_json::json!({"funding_priority":"fast","dry_run":dry_run}),
            false,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    assert_eq!(backend.opens.load(Ordering::SeqCst), 0);
    assert_eq!(backend.quotes.load(Ordering::SeqCst), 0);
}
