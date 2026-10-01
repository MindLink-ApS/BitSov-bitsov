//! Health and status endpoints.
//!
//! `GET /api/v1/health` is **unauthenticated** and returns only liveness +
//! non-sensitive operational counters. The full node status — identity, peer
//! list, wallet balance, and Lightning pubkey — is owner-only and lives behind
//! [`ScopedAuth<Read>`] at `GET /api/v1/status`. Exposing identity/topology/funds on an
//! unauthenticated endpoint links the node's IP to its NodeID, social graph,
//! and wallet, and is precisely the kind of free, unpaid disclosure the
//! payment-is-the-connection invariant forbids (see CODEX.md).

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::auth::scoped::{ScopedAuth, Read};
use crate::freshness::DataFreshness;
use crate::state::AppState;

/// Full node status response (owner-only, behind [`ScopedAuth<Read>`]).
#[derive(Serialize)]
pub struct HealthResponse {
    pub money_ready: bool,
    pub readiness: konsensus_core::traits::lightning::LightningReadiness,
    pub api_capabilities: Vec<&'static str>,
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
    /// UDP port of this node's STUN binding responder (`[calls] stun_listen`);
    /// omitted when it is off. Owner-only: the app may offer it as the STUN
    /// server for calls, never switch to it by itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stun_port: Option<u16>,
    /// `stun:host:port` for that responder at this node's dialable peer host
    /// (`[network] advertised_addr`); omitted when the responder is off or the
    /// node knows no reachable host (wildcard bind, loopback).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stun_url: Option<String>,
    /// Dialable `host:port` this node signs into introductions and front-door
    /// cards; omitted when none is known (see `peer_endpoint_reason`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_endpoint: Option<String>,
    /// `advertised` (owner set), `listen` (concrete bind) or `stun` (discovered).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_endpoint_source: Option<String>,
    /// Why there is no `peer_endpoint`: `no_dialable_endpoint`, `stun_pending`,
    /// `stun_unreachable` or `stun_invalid_response`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_endpoint_reason: Option<String>,
    /// Where the seed lives: `local_seed`, `encrypted_seed`, `hosted_custody`,
    /// `money_signer` or `remote_signer` (`docs/protocol/REMOTE-SIGNER.md` §2).
    /// Owner-only.
    pub custody_mode: crate::custody::CustodyMode,
}

/// `stun:host:port` for the STUN responder at the host of the node's
/// dialable peer endpoint (`host:port`, IPv6 in brackets). `None` for a
/// loopback or unspecified host, which no other machine can reach.
pub fn stun_url(endpoint: Option<&str>, stun_port: Option<u16>) -> Option<String> {
    let port = stun_port?;
    let (host, _) = endpoint?.trim().rsplit_once(':')?;
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        let ip = v6.parse::<std::net::Ipv6Addr>().ok()?;
        return (!ip.is_loopback() && !ip.is_unspecified()).then(|| format!("stun:[{ip}]:{port}"));
    }
    if host.is_empty()
        || host.eq_ignore_ascii_case("localhost")
        || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return None;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        if ip.is_loopback() || ip.is_unspecified() {
            return None;
        }
    }
    Some(format!("stun:{host}:{port}"))
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
///
/// `BitSov-Data-As-Of` is the time `block_height` was read from the chain
/// backend (a live query per request); omitted when `block_height` is null.
async fn health(State(state): State<Arc<AppState>>) -> (DataFreshness, Json<PublicHealthResponse>) {
    let readiness = state.lightning.readiness().await;
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
    let chain_read = DataFreshness::now();
    let (block_height, freshness) = if !readiness.money_ready {
        (None, DataFreshness::unknown())
    } else { match tokio::time::timeout(std::time::Duration::from_secs(1), state.chain.get_block_height()).await {
        Ok(Ok(h)) => (Some(h), chain_read),
        _ => {
            (None, DataFreshness::unknown())
        }
    }};

    (
        freshness,
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
        }),
    )
}

/// `GET /api/v1/status` — owner-only full node status (behind [`ScopedAuth<Read>`]).
///
/// Includes identity, connected peer IDs, wallet balance, and LN pubkey — the
/// fields redacted from the public `/health` endpoint.
async fn status(_auth: ScopedAuth<Read>, State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let readiness = state.lightning.readiness().await;
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

    let block_height = if readiness.money_ready {
        tokio::time::timeout(std::time::Duration::from_secs(1), state.chain.get_block_height()).await.ok().and_then(Result::ok)
    } else { None };

    let peer = state.introduction.endpoint_view();
    Json(HealthResponse {
        money_ready: readiness.money_ready,
        readiness,
        api_capabilities: vec![
            "offline_readiness_v1",
            "message_operations_v1",
            super::messages::caps::CAPABILITY,
            super::messages::caps::QUOTED_READMISSION_CAPABILITY,
            super::messages::caps::ROOM_CAPABILITY,
            super::organism::ENERGY_CAPABILITY,
            crate::membrane::CAPABILITY,
            crate::spend_budget::CAPABILITY,
            crate::spend_budget::FIRST_CONTACT_CAPABILITY,
            super::introduction::CAPABILITY,
            super::front_door::CAPABILITY,
            super::browse::CAPABILITY,
            super::liquidity::CAPABILITY,
            super::sponsor::CAPABILITY,
            konsensus_core::payloads::call::MEETING_CAPABILITY,
            konsensus_core::payloads::room::ROOM_BINDING_CAPABILITY,
        ],
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
        stun_port: state.stun_port,
        stun_url: stun_url(peer.endpoint.as_deref(), state.stun_port),
        peer_endpoint: peer.endpoint,
        peer_endpoint_source: peer.source.map(String::from),
        peer_endpoint_reason: peer.reason.map(String::from),
        custody_mode: state.custody_mode,
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
/// owner-only (behind `ScopedAuth<Read>`).
pub fn routes(operator_probes_enabled: bool) -> Router<Arc<AppState>> {
    let router = status_routes().route("/api/v1/health", get(health));
    if operator_probes_enabled {
        router
            .route("/api/v1/preflight", get(preflight))
            .route("/livez", get(preflight))
    } else {
        router
    }
}

/// Authenticated status only, for the encrypted remote API. Public/operator
/// liveness endpoints belong exclusively to the owner's local listener.
pub fn status_routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/status", get(status))
}
