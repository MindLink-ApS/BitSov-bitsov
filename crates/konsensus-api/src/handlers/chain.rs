//! Chain data endpoint — proxies Bitcoin chain data through the node's
//! ChainProvider so the frontend doesn't need direct CORS access to
//! mempool.space or other Esplora backends.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::auth::AuthUser;
use crate::state::AppState;

/// Chain status response — block height, fee rates, halving data.
#[derive(Serialize)]
pub struct ChainStatusResponse {
    /// Current best block height (0 if unavailable).
    pub block_height: u64,
    /// Fee estimate for fast confirmation (1-2 blocks), sat/vB.
    pub fee_rate_fast: f64,
    /// Fee estimate for medium confirmation (~6 blocks), sat/vB.
    pub fee_rate_medium: f64,
    /// Fee estimate for slow/economy confirmation (~12+ blocks), sat/vB.
    pub fee_rate_slow: f64,
    /// Whether chain data is available (false if all queries failed).
    pub available: bool,
    /// Error message if chain data is unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `GET /api/v1/chain/status` — chain data proxied through the node backend.
///
/// Gated behind `AuthUser` (L7b): the response surfaces the node's chain
/// backend health and current fee estimates, both of which leak information
/// about the operator's setup. Callers must present a valid JWT.
async fn chain_status(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Json<ChainStatusResponse> {
    let mut block_height = 0u64;
    let mut fee_fast = 0.0f64;
    let mut fee_medium = 0.0f64;
    let mut fee_slow = 0.0f64;
    let mut errors = Vec::new();

    match state.chain.get_block_height().await {
        Ok(h) => block_height = h,
        Err(e) => {
            tracing::warn!(error = %e, "chain status: block height fetch failed");
            errors.push(format!("block height: {e}"));
        }
    }

    // Fast: 1-block target
    match state.chain.estimate_fee(1).await {
        Ok(est) => fee_fast = est.sat_per_vbyte,
        Err(e) => {
            tracing::warn!(error = %e, "chain status: fast fee estimate failed");
            errors.push(format!("fast fee: {e}"));
        }
    }

    // Medium: 6-block target
    match state.chain.estimate_fee(6).await {
        Ok(est) => fee_medium = est.sat_per_vbyte,
        Err(e) => {
            tracing::warn!(error = %e, "chain status: medium fee estimate failed");
            errors.push(format!("medium fee: {e}"));
        }
    }

    // Slow: 12-block target
    match state.chain.estimate_fee(12).await {
        Ok(est) => fee_slow = est.sat_per_vbyte,
        Err(e) => {
            tracing::warn!(error = %e, "chain status: slow fee estimate failed");
            errors.push(format!("slow fee: {e}"));
        }
    }

    let available = block_height > 0;

    Json(ChainStatusResponse {
        block_height,
        fee_rate_fast: fee_fast,
        fee_rate_medium: fee_medium,
        fee_rate_slow: fee_slow,
        available,
        error: if errors.is_empty() { None } else { Some(errors.join("; ")) },
    })
}

/// Registers chain data routes.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/chain/status", get(chain_status))
}
