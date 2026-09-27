//! Mock LSP + production quote store + real HTTP scope/caps/G1 ledger.
use super::*;
use konsensus_lightning::liquidity::{JitBackend, LiquidityClient};

struct MockLsp;
#[async_trait]
impl JitBackend for MockLsp {
    async fn prepare(
        &self,
        amount: u64,
        _cap: u64,
        expiry: u32,
    ) -> Result<(Invoice, u64), LightningError> {
        Ok((
            Invoice {
                bolt11: "private-funding-invoice".into(),
                payment_hash: "aa".repeat(32),
                amount_msat: amount,
                description: "BitSov wallet funding".into(),
                expiry_secs: expiry,
                created_at: chrono::Utc::now().timestamp() as u64,
            },
            2_000,
        ))
    }
}
async fn liquidity_fixture() -> Fx {
    let fx = fixture().await;
    *fx.wallet.liquidity.lock().unwrap() = Some(Arc::new(LiquidityClient::new(
        PEER_LN.into(),
        Arc::new(MockLsp),
    )));
    fx
}
fn terms(budget: u64) -> GrantTerms {
    let mut t = GrantTerms::new(budget);
    t.allow_liquidity_fees = true;
    t
}
async fn quote(fx: &Fx, token: &str) -> Value {
    let (status, body) = fx
        .call(
            "POST",
            "/api/v1/payments/liquidity/quote",
            Some(json!({"gross_msat":100_000,"max_lsp_fee_msat":2_000})),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["min_net_msat"], 98_000);
    assert!(body.get("bolt11").is_none());
    body
}
fn acceptance(q: &Value, cap: u64) -> Value {
    json!({"quote_id":q["quote_id"],"provider":q["provider"],"max_lsp_fee_msat":cap})
}
async fn accept(fx: &Fx, token: &str, q: &Value, cap: u64) -> (StatusCode, Value) {
    fx.call(
        "POST",
        "/api/v1/payments/liquidity/accept",
        Some(acceptance(q, cap)),
        Some(token),
    )
    .await
}

#[tokio::test]
async fn receive_and_ordinary_spend_scopes_cannot_purchase_liquidity() {
    let fx = liquidity_fixture().await;
    let read = fx.token().await;
    let q = quote(&fx, &read).await;
    assert_eq!(accept(&fx, &read, &q, 2_000).await.0, StatusCode::FORBIDDEN);
    let spend = fx.grant(None, GrantTerms::new(10_000)).await;
    let (status, body) = accept(&fx, &spend, &q, 2_000).await;
    assert_budget_exceeded(status, &body, "unpriced");
    assert_eq!(fx.used(), 0);
}

#[tokio::test]
async fn cap_and_budget_refusals_keep_invoice_private_then_one_accept_reserves_fee() {
    let mut fx = liquidity_fixture().await;
    let token = fx.grant(None, terms(3_000)).await;
    let q = quote(&fx, &token).await;
    let (status, body) = accept(&fx, &token, &q, 1_999).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "price_cap_exceeded");
    assert_eq!(fx.used(), 0);
    let mut wrong = acceptance(&q, 2_000);
    wrong["provider"] = json!(OTHER_LN);
    assert_eq!(
        fx.call(
            "POST",
            "/api/v1/payments/liquidity/accept",
            Some(wrong),
            Some(&token)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (status, invoice) = accept(&fx, &token, &q, 2_000).await;
    assert_eq!(status, StatusCode::OK, "{invoice}");
    assert_eq!(invoice["bolt11"], "private-funding-invoice");
    assert_eq!(fx.used(), 2_000);
    assert_eq!(fx.wallet.money(), 0, "receiving never initiates a spend");
    assert_eq!(
        accept(&fx, &token, &q, 2_000).await.0,
        StatusCode::BAD_REQUEST
    );
    fx.restart();
    let q2 = quote(&fx, &token).await;
    let (status, body) = accept(&fx, &token, &q2, 2_000).await;
    assert_budget_exceeded(status, &body, "total");
    assert_eq!(fx.used(), 2_000);
}

#[tokio::test]
async fn concurrent_accepts_cannot_exceed_shared_fee_budget() {
    let fx = liquidity_fixture().await;
    let token = fx.grant(None, terms(3_000)).await;
    let a = quote(&fx, &token).await;
    let b = quote(&fx, &token).await;
    let (a, b) = tokio::join!(
        accept(&fx, &token, &a, 2_000),
        accept(&fx, &token, &b, 2_000)
    );
    assert_ne!(a.0 == StatusCode::OK, b.0 == StatusCode::OK);
    assert_eq!(fx.used(), 2_000);
}

#[tokio::test]
async fn revoked_grant_cannot_publish_prepared_invoice() {
    let fx = liquidity_fixture().await;
    let token = fx.grant(None, terms(3_000)).await;
    let q = quote(&fx, &token).await;
    let response = control::handle(
        &fx.control(),
        ControlRequest::RevokeGrant {
            client_id: Some(fx.client_id.clone()),
        },
    );
    assert!(matches!(response, ControlResponse::Ok { .. }));
    assert_eq!(
        accept(&fx, &token, &q, 2_000).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(fx.wallet.money(), 0);
}
