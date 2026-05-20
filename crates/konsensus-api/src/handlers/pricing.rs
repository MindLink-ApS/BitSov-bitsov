//! Pricing endpoints — inspect current pricing and peer price tables.
//!
//! These read-only endpoints let users and scripts observe what prices
//! the node charges (own pricing) and what prices peers require (cached
//! peer price tables). Essential for debugging pricing mismatches and
//! monitoring Principle 5 health across the network.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use konsensus_core::kind::KindCategory;
use konsensus_core::traits::chain::TrustLevel;
use konsensus_pricing::peer_prices::{category_to_string, compute_valid_blocks};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

/// Own pricing response — what this node charges per category.
#[derive(Serialize)]
pub struct OwnPricingResponse {
    /// Pricing mode ("static" or "chain_aware").
    pub mode: String,
    /// Prices per kind category in millisatoshis.
    pub prices: HashMap<String, u64>,
    /// Current block height (0 if chain unavailable).
    pub block_height: u64,
    /// How many blocks the current price table is valid for,
    /// computed from the Bitcoin difficulty adjustment epoch position.
    pub valid_blocks: u32,
    /// Trust level of the chain data source ("spv", "server_trust", "full_validation").
    pub trust_level: String,
    /// Position within the current 2016-block difficulty adjustment epoch.
    pub difficulty_epoch_position: u64,
    /// Number of cached peer price tables.
    pub peer_tables_cached: usize,
    /// Raw fee rate from last chain query (sat/vB), if chain-aware (default target).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_fee_rate: Option<f64>,
    /// EMA-smoothed fee rate used for pricing (sat/vB), if chain-aware (default target).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ema_fee_rate: Option<f64>,
    /// Maximum price multiplier cap (0 = no cap), if chain-aware.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_price_multiplier: Option<f64>,
    /// Per-target fee rates (target_blocks → {raw, ema}), if chain-aware with multi-target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_rates_by_target: Option<HashMap<String, FeeRateDetail>>,
    /// Per-category confirmation targets, if configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category_fee_targets: Option<HashMap<String, u32>>,
}

/// Fee rate detail for a specific confirmation target.
#[derive(Serialize)]
pub struct FeeRateDetail {
    /// Raw fee rate from last chain query (sat/vB).
    pub raw_sat_per_vbyte: f64,
    /// EMA-smoothed fee rate (sat/vB).
    pub ema_sat_per_vbyte: f64,
}

/// Peer price table summary.
#[derive(Serialize)]
pub struct PeerPriceResponse {
    /// Peer node ID (hex).
    pub peer_id: String,
    /// Prices per kind category in millisatoshis.
    pub prices: HashMap<String, u64>,
    /// Block height at which prices were computed.
    pub block_height: u64,
    /// How many blocks this table is valid for (0 = until replaced).
    pub valid_blocks: u32,
    /// Seconds since this table was received.
    pub age_secs: u64,
    /// Whether this table is considered stale (block height or wall-clock).
    pub stale: bool,
}

/// `GET /api/v1/pricing` — get this node's current pricing.
async fn get_own_pricing(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<OwnPricingResponse>, ApiError> {
    let block_height = state.chain.get_block_height().await.unwrap_or(0);

    // Build price table from our own pricing engine
    let categories = [
        KindCategory::Communication,
        KindCategory::StructuredData,
        KindCategory::FilesMedia,
        KindCategory::Collaboration,
        KindCategory::WebContent,
        KindCategory::Control,
        KindCategory::AppExtension,
    ];

    let mut prices = HashMap::new();
    for cat in categories {
        match state.pricing.get_category_price_msat(cat).await {
            Ok(price) => {
                prices.insert(category_to_string(cat), price);
            }
            Err(e) => {
                tracing::warn!(category = %category_to_string(cat), error = %e, "failed to get price for category");
            }
        }
    }

    let peer_count = state.peer_prices.len().await;
    let valid_blocks = compute_valid_blocks(block_height);
    let trust_level = state.chain.trust_level();
    let difficulty_epoch_position = if block_height > 0 {
        block_height % 2016
    } else {
        0
    };

    // Detect pricing mode from the actual engine type, not block height.
    // A mock chain provider returns non-zero block heights but that doesn't
    // mean the node is running chain-aware pricing.
    let is_chain_aware = state
        .pricing
        .as_any()
        .downcast_ref::<konsensus_pricing::ChainAwarePricingEngine>()
        .is_some();
    let mode = if is_chain_aware {
        "chain_aware".to_string()
    } else {
        "static".to_string()
    };

    let trust_level_str = match trust_level {
        TrustLevel::Spv => "spv",
        TrustLevel::ServerTrust => "server_trust",
        TrustLevel::FullValidation => "full_validation",
    };

    // Populate chain-aware fields if the engine is a ChainAwarePricingEngine.
    let (raw_fee_rate, ema_fee_rate, max_price_multiplier, fee_rates_by_target, cat_fee_targets) =
        if let Some(chain_engine) = state
            .pricing
            .as_any()
            .downcast_ref::<konsensus_pricing::ChainAwarePricingEngine>()
        {
            let default_state = chain_engine.fee_rate_state().await;
            let all_targets = chain_engine.fee_rate_state_all().await;
            let cat_targets = chain_engine.category_fee_targets();

            let target_map: Option<HashMap<String, FeeRateDetail>> = if all_targets.len() > 1 {
                Some(
                    all_targets
                        .into_iter()
                        .map(|(k, (raw, ema))| {
                            (
                                k.to_string(),
                                FeeRateDetail {
                                    raw_sat_per_vbyte: raw,
                                    ema_sat_per_vbyte: ema,
                                },
                            )
                        })
                        .collect(),
                )
            } else {
                None // Don't show per-target if only one target
            };

            let cat_map = if cat_targets.is_empty() {
                None
            } else {
                Some(cat_targets.clone())
            };

            (
                default_state.map(|(raw, _)| raw),
                default_state.map(|(_, ema)| ema),
                Some(chain_engine.max_price_multiplier()),
                target_map,
                cat_map,
            )
        } else {
            (None, None, None, None, None)
        };

    Ok(Json(OwnPricingResponse {
        mode,
        prices,
        block_height,
        valid_blocks,
        trust_level: trust_level_str.to_string(),
        difficulty_epoch_position,
        peer_tables_cached: peer_count,
        raw_fee_rate,
        ema_fee_rate,
        max_price_multiplier,
        fee_rates_by_target,
        category_fee_targets: cat_fee_targets,
    }))
}

/// `GET /api/v1/pricing/peers` — list all cached peer price tables.
async fn list_peer_pricing(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PeerPriceResponse>>, ApiError> {
    let block_height = state.chain.get_block_height().await.unwrap_or(0);
    let max_age = std::time::Duration::from_secs(3600);
    let entries = state.peer_prices.all_entries().await;

    let mut responses: Vec<PeerPriceResponse> = entries
        .into_iter()
        .map(|(peer_id, entry)| PeerPriceResponse {
            peer_id: peer_id.to_hex(),
            prices: entry.prices.clone(),
            block_height: entry.block_height,
            valid_blocks: entry.valid_blocks,
            age_secs: entry.received_at.elapsed().as_secs(),
            stale: entry.is_stale(block_height, max_age),
        })
        .collect();

    // Sort by peer_id for deterministic output
    responses.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));

    Ok(Json(responses))
}

/// `GET /api/v1/pricing/peers/:id` — get a specific peer's price table.
async fn get_peer_pricing(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(peer_id_hex): Path<String>,
) -> Result<Json<PeerPriceResponse>, ApiError> {
    let peer_id = konsensus_core::types::NodeId::from_hex(&peer_id_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid peer ID: {e}")))?;

    let block_height = state.chain.get_block_height().await.unwrap_or(0);
    let max_age = std::time::Duration::from_secs(3600);

    let entry = state
        .peer_prices
        .get_peer_entry(&peer_id)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("no price table cached for peer {peer_id_hex}")))?;

    let stale = entry.is_stale(block_height, max_age);
    Ok(Json(PeerPriceResponse {
        peer_id: peer_id_hex,
        prices: entry.prices,
        block_height: entry.block_height,
        valid_blocks: entry.valid_blocks,
        age_secs: entry.received_at.elapsed().as_secs(),
        stale,
    }))
}

/// Registers pricing routes for querying own and peer pricing schedules.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/pricing", get(get_own_pricing))
        .route("/api/v1/pricing/peers", get(list_peer_pricing))
        .route("/api/v1/pricing/peers/:id", get(get_peer_pricing))
}
