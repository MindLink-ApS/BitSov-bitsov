//! Health and status endpoints.
//!
//! `GET /api/v1/health` is **unauthenticated** and returns only liveness +
//! non-sensitive operational counters. The full node status — identity, peer
//! list, wallet balance, and Lightning pubkey — is owner-only and lives behind
//! [`AuthUser`] at `GET /api/v1/status`. Exposing identity/topology/funds on an
//! unauthenticated endpoint links the node's IP to its NodeID, social graph,
//! and wallet, and is precisely the kind of free, unpaid disclosure the
//! payment-is-the-connection invariant forbids (see CODEX.md).

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::auth::AuthUser;
use crate::state::AppState;

/// Full node status response (owner-only, behind [`AuthUser`]).
#[derive(Serialize)]
pub struct HealthResponse {
    /// Always "ok" if the node is running.
    pub status: &'static str,
    /// Node ID (Ed25519 public key, hex).
    pub node_id: String,
    /// Number of connected peers.
    pub connected_peers: usize,
    /// Connected peer IDs (hex).
    pub connected_peer_ids: Vec<String>,
    /// Number of active E2EE sessions.
    pub e2ee_sessions: usize,
    /// Number of messages queued for delivery to offline peers.
    pub pending_deliveries: u64,
    /// Whether Lightning provider is available (backend reachable).
    pub lightning_available: bool,
    /// Whether this node can send outbound Lightning payments.
    ///
    /// `false` when the wallet is a VoidWallet, has no channels, or a
    /// previous payment failed with a funding-source error.
    pub lightning_payment_capable: bool,
    /// Lightning wallet balance in millisatoshis (`null` if unavailable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lightning_balance_msat: Option<u64>,
    /// Node uptime in seconds.
    pub uptime_secs: u64,
    /// Protocol version.
    pub version: u16,
    /// Lightning backend name (e.g. "lnbits", "mock", "void").
    pub lightning_backend: String,
    /// Lightning node public key (hex, compressed secp256k1). Used for channel opening.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lightning_node_pubkey: Option<String>,
    /// Chain backend name (e.g. "esplora", "mock").
    pub chain_backend: String,
    /// Current Bitcoin block height from the chain backend (`null` if unavailable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
}

/// Public (unauthenticated) health response.
///
/// Liveness + non-sensitive operational counters only. Deliberately omits
/// `node_id`, `connected_peer_ids`, `lightning_balance_msat`, and
/// `lightning_node_pubkey` (identity, social graph, funds, LN identity) — those
/// are owner-only at `GET /api/v1/status`. The fields kept here are the ones the
/// deploy/keepalive probes read (status + counts + availability flags).
#[derive(Serialize)]
pub struct PublicHealthResponse {
    /// Always "ok" if the node is running.
    pub status: &'static str,
    /// Number of connected peers (count only — not the peer IDs).
    pub connected_peers: usize,
    /// Number of active E2EE sessions.
    pub e2ee_sessions: usize,
    /// Number of messages queued for delivery to offline peers.
    pub pending_deliveries: u64,
    /// Whether Lightning provider is available (backend reachable).
    pub lightning_available: bool,
    /// Whether this node can send outbound Lightning payments.
    pub lightning_payment_capable: bool,
    /// Node uptime in seconds.
    pub uptime_secs: u64,
    /// Protocol version.
    pub version: u16,
    /// Lightning backend name (e.g. "lnbits", "mock", "void").
    pub lightning_backend: String,
    /// Chain backend name (e.g. "esplora", "mock").
    pub chain_backend: String,
    /// Current Bitcoin block height (public chain data; `null` if unavailable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
}

/// `GET /api/v1/health` — UNAUTHENTICATED liveness + non-sensitive counters.
///
/// Returns only the public subset; never queries the wallet balance or LN
/// pubkey. For full status (identity, peers, balance) use `GET /api/v1/status`.
async fn health(State(state): State<Arc<AppState>>) -> Json<PublicHealthResponse> {
    let connected = state.transport.connected_peers().await;
    let ln_available = state.lightning.is_available().await;
    let ln_payment_capable = state.lightning.is_payment_capable().await;
    let session_count = state.session_manager.session_count().await;
    let pending = match state.storage.count_pending_deliveries().await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "failed to query pending deliveries for health check");
            0
        }
    };
    let block_height = match state.chain.get_block_height().await {
        Ok(h) => Some(h),
        Err(e) => {
            tracing::warn!(error = %e, "failed to query block height for health check");
            None
        }
    };

    Json(PublicHealthResponse {
        status: "ok",
        connected_peers: connected.len(),
        e2ee_sessions: session_count,
        pending_deliveries: pending,
        lightning_available: ln_available,
        lightning_payment_capable: ln_payment_capable,
        uptime_secs: state.started_at.elapsed().as_secs(),
        version: 2,
        lightning_backend: state.lightning_backend.clone(),
        chain_backend: state.chain_backend.clone(),
        block_height,
    })
}

/// `GET /api/v1/status` — owner-only full node status (behind [`AuthUser`]).
///
/// Includes identity, connected peer IDs, wallet balance, and LN pubkey — the
/// fields redacted from the public `/health` endpoint.
async fn status(_auth: AuthUser, State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let connected = state.transport.connected_peers().await;
    let ln_available = state.lightning.is_available().await;
    let ln_payment_capable = state.lightning.is_payment_capable().await;
    let ln_balance = if ln_available {
        match state.lightning.get_balance_msat().await {
            Ok(b) => Some(b),
            Err(e) => {
                tracing::warn!(error = %e, "failed to query Lightning balance for status");
                None
            }
        }
    } else {
        None
    };
    let session_count = state.session_manager.session_count().await;
    let pending = match state.storage.count_pending_deliveries().await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "failed to query pending deliveries for status");
            0
        }
    };
    let uptime = state.started_at.elapsed().as_secs();

    let block_height = match state.chain.get_block_height().await {
        Ok(h) => Some(h),
        Err(e) => {
            tracing::warn!(error = %e, "failed to query block height for status");
            None
        }
    };

    Json(HealthResponse {
        status: "ok",
        node_id: state.identity.node_id().to_hex(),
        connected_peers: connected.len(),
        connected_peer_ids: connected.iter().map(|id| id.to_hex()).collect(),
        e2ee_sessions: session_count,
        pending_deliveries: pending,
        lightning_available: ln_available,
        lightning_payment_capable: ln_payment_capable,
        lightning_balance_msat: ln_balance,
        uptime_secs: uptime,
        version: 2,
        lightning_backend: state.lightning_backend.clone(),
        lightning_node_pubkey: state.lightning.get_node_pubkey().await,
        chain_backend: state.chain_backend.clone(),
        block_height,
    })
}

/// Cheap liveness response for deploy/keepalive probes.
#[derive(Serialize)]
pub struct PreflightResponse {
    /// Always "ok" if the API process is accepting requests.
    pub status: &'static str,
    /// Node uptime in seconds.
    pub uptime_secs: u64,
    /// Protocol version.
    pub version: u16,
}

/// `GET /api/v1/preflight` — cheap operator liveness probe.
///
/// This intentionally avoids Lightning, storage, chain, and peer queries.
/// It answers only "is the API process alive enough to route requests?"
async fn preflight(State(state): State<Arc<AppState>>) -> Json<PreflightResponse> {
    Json(PreflightResponse {
        status: "ok",
        uptime_secs: state.started_at.elapsed().as_secs(),
        version: 2,
    })
}

/// Registers the health/status routes for node monitoring.
///
/// `/api/v1/health` is unauthenticated (public, redacted); `/api/v1/status` is
/// owner-only (behind `AuthUser`).
pub fn routes(operator_probes_enabled: bool) -> Router<Arc<AppState>> {
    let router = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/status", get(status));
    if operator_probes_enabled {
        router
            .route("/api/v1/preflight", get(preflight))
            .route("/livez", get(preflight))
    } else {
        router
    }
}
