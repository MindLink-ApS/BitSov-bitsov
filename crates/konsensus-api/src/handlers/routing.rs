//! Routing endpoints — synaptic routing table metrics and weight dump.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::auth::AuthUser;
use crate::state::AppState;

/// Routing table summary response.
#[derive(Serialize)]
pub struct RoutingResponse {
    /// Total known peers (including pruned).
    pub total_peers: usize,
    /// Active (non-pruned) peers.
    pub active_peers: usize,
    /// Per-peer routing scores.
    pub peers: Vec<PeerRoutingInfo>,
}

/// Routing info for a single peer.
#[derive(Serialize)]
pub struct PeerRoutingInfo {
    /// Peer's node ID (hex).
    pub node_id: String,
    /// Current routing score (higher = better).
    pub score: f64,
    /// Current synaptic weight [0.0, 1.0].
    pub weight: f64,
    /// Latency EMA in milliseconds.
    pub latency_ema_ms: f64,
    /// Success rate [0.0, 1.0].
    pub success_rate: f64,
    /// Cumulative payment volume in millisatoshis.
    pub payment_volume_msat: u64,
    /// Whether the connection has been pruned.
    pub pruned: bool,
    /// Whether a direct connection is suggested (dendritic growth).
    pub suggest_direct: bool,
}

/// `GET /api/v1/routing` — get routing table metrics and weight dump.
async fn get_routing(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Json<RoutingResponse> {
    let total_peers = state.routing.peer_count().await;
    let active_peers = state.routing.active_peer_count().await;
    let scores = state.routing.peer_scores().await;

    let peers = scores
        .into_iter()
        .map(|s| PeerRoutingInfo {
            node_id: s.peer_id.to_hex(),
            score: s.score,
            weight: s.weight,
            latency_ema_ms: s.latency_ema_ms,
            success_rate: s.success_rate,
            payment_volume_msat: s.payment_volume_msat,
            pruned: s.pruned,
            suggest_direct: s.suggest_direct,
        })
        .collect();

    Json(RoutingResponse {
        total_peers,
        active_peers,
        peers,
    })
}

/// Registers the routing route.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/routing", get(get_routing))
}
