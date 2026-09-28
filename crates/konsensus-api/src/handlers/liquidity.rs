//! Explicit funding bootstrap: prepare private terms, confirm fee, then publish.
use crate::{
    auth::{
        scoped::{Read, Receive, ScopedAuth},
        AuthUser,
    },
    error::ApiError,
    metered::MeteredSpend,
    spend_budget::Charge,
    state::AppState,
};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use konsensus_core::traits::lightning::{Invoice, LightningError};
use konsensus_core::traits::liquidity::{LiquidityInfo, LiquidityQuote};
use serde::Deserialize;
use std::sync::Arc;

pub const CAPABILITY: &str = "lsps2_funding_quotes_v1";

fn owner(user: &AuthUser) -> String {
    match &user.pairing {
        Some(p) => format!("pair:{}:{}:{}", p.client_id, p.epoch, p.fingerprint),
        None => format!("owner:{}", user.node_id),
    }
}

async fn info(_auth: ScopedAuth<Read>, State(state): State<Arc<AppState>>) -> Json<LiquidityInfo> {
    Json(state.lightning.liquidity_info())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuoteRequest {
    gross_msat: u64,
    /// Negotiation ceiling; invoice remains private until explicit acceptance.
    max_lsp_fee_msat: u64,
}

async fn quote(
    auth: ScopedAuth<Receive>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<QuoteRequest>,
) -> Result<Json<LiquidityQuote>, ApiError> {
    crate::error::require_money_ready(&state).await?;
    if req.gross_msat == 0
        || req.gross_msat > 100_000_000_000
        || req.max_lsp_fee_msat >= req.gross_msat
    {
        return Err(ApiError::BadRequest(
            "gross must be 1..100000000000 msat, fee ceiling below gross".into(),
        ));
    }
    state
        .lightning
        .quote_liquidity(&owner(&auth.user), req.gross_msat, req.max_lsp_fee_msat)
        .await
        .map(Json)
        .map_err(ApiError::from)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptRequest {
    quote_id: String,
    /// Bind consent to the provider displayed in the preview.
    provider: String,
    /// Mandatory, distinct from #80 message principal caps. May only narrow the preview.
    max_lsp_fee_msat: u64,
}

async fn accept_liquidity(
    auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    Json(req): Json<AcceptRequest>,
) -> Result<Json<Invoice>, ApiError> {
    crate::error::require_money_ready(&state).await?;
    let owner = owner(&auth.user);
    let q = state
        .lightning
        .liquidity_quote(&owner, &req.quote_id)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    if q.provider != req.provider {
        return Err(ApiError::PriceCapExceeded(
            "liquidity provider changed; refresh preview".into(),
        ));
    }
    super::messages::caps::check(q.max_fee_msat, Some(req.max_lsp_fee_msat))?;
    let debit = auth.debit_liquidity(
        &state,
        Charge {
            recipient: q.provider.clone(),
            amount_msat: q.max_fee_msat,
        },
    )?;
    let result = debit
        .dispatch(state.lightning.accept_liquidity(&owner, &req.quote_id))
        .await?;
    if matches!(&result, Err(LightningError::PaymentNotDispatched(_) | LightningError::NotReady)) {
        debit.released(&q.provider);
    }
    // Publication commits bounded future deductions. Keep the durable debit on
    // success, cancellation, timeout and unknown outcome, even across restart.
    // Expiry alone cannot prove no HTLC is in flight. Never retry automatically.
    result
        .map(Json)
        .map_err(ApiError::from)
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/payments/liquidity", get(info))
        .route("/api/v1/payments/liquidity/quote", post(quote))
        .route("/api/v1/payments/liquidity/accept", post(accept_liquidity))
}
