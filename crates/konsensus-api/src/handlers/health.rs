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

use crate::auth::scoped::{Read, ScopedAuth};
use crate::freshness::DataFreshness;
use crate::state::AppState;

/// Full node status response (owner-only, behind [`ScopedAuth<Read>`]).
#[derive(Serialize)]
pub struct HealthResponse {
    /// Configured Bitcoin network; null when the backend configuration has none.
    pub network: Option<String>,
    /// Sanitized restore journal diagnostics, owner-only and read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<konsensus_lightning::recover::Status>,
    /// Active channel admission policy; null when backend enforcement is unavailable.
    pub channel_safety: Option<konsensus_core::traits::lightning::ChannelSafetyStatus>,
    /// Node-local, amount-free breach-window diagnostics. Null for unsupported backends.
    pub offline_safety: Option<konsensus_core::offline_safety::OfflineSafetyStatus>,
    pub local_spends: konsensus_core::traits::lightning::LocalSpendDiagnostics,
    /// Failed row reads since startup (repeat scans count again).
    pub storage_unreadable_rows: u64,
    /// Warning latched after a list has >=50% unreadable rows; clears on restart.
    pub storage_key_mismatch: bool,
    pub disk_low: bool,
    pub disk_free_bytes: Option<u64>,
    pub disk_free_floor_bytes: Option<u64>,
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
    pub chain_view: konsensus_core::traits::chain::ChainView,
    /// Observed LDK sync failure; null does not assert readiness.
    pub chain_sync: Option<konsensus_core::traits::lightning::ChainSyncStatus>,
    /// Current Bitcoin block height from the chain backend (`null` if unavailable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
    /// UDP port of this node's STUN binding responder (`[calls] stun_listen`);
    /// omitted when it is off. Owner-only: the app may offer it as the STUN
    /// server for calls, never switch to it by itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stun_port: Option<u16>,
    /// `stun:host:port` for ICE: this node's own STUN responder when it has a
    /// dialable peer host, else the owner's `[network] stun_server` when set and
    /// valid; omitted when neither applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stun_url: Option<String>,
    /// `own` (local responder + dialable host), `configured` (`[network] stun_server`),
    /// or omitted when no `stun_url` is reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stun_source: Option<&'static str>,
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
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
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

/// `stun:host:port` from a validated `[network] stun_server` (`host:port`).
/// Rejects `stuns:`, `stun:`-prefixed, and malformed values so they are never
/// reported on `/status`.
pub fn configured_stun_url(host_port: &str) -> Option<String> {
    let raw = host_port.trim();
    if raw.is_empty() {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("stuns:") || lower.starts_with("stun:") {
        return None;
    }
    let (host, port) = raw.rsplit_once(':')?;
    let _: u16 = port.parse().ok().filter(|p| *p != 0)?;
    let host_ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6.parse::<std::net::Ipv6Addr>().is_ok(),
        None => {
            !host.is_empty()
                && host.len() <= 253
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        }
    };
    if !host_ok {
        return None;
    }
    Some(format!("stun:{raw}"))
}

/// Resolve `stun_url` and `stun_source` for owner `/status`.
pub fn stun_status(
    endpoint: Option<&str>,
    stun_port: Option<u16>,
    configured_stun_server: Option<&str>,
) -> (Option<String>, Option<&'static str>) {
    if let Some(url) = stun_url(endpoint, stun_port) {
        return (Some(url), Some("own"));
    }
    if let Some(addr) = configured_stun_server {
        if let Some(url) = configured_stun_url(addr) {
            return (Some(url), Some("configured"));
        }
    }
    (None, None)
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
    /// Additive enrollment capability, omitted with rollout off.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub api_capabilities: Vec<&'static str>,
    /// Operator-supplied display label, not a custody claim.
    pub hosted_by: Option<String>,
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
pub(crate) async fn health(
    State(state): State<Arc<AppState>>,
) -> (DataFreshness, Json<PublicHealthResponse>) {
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
    } else {
        match tokio::time::timeout(
            std::time::Duration::from_secs(1),
            state.chain.get_block_height(),
        )
        .await
        {
            Ok(Ok(h)) => (Some(h), chain_read),
            _ => (None, DataFreshness::unknown()),
        }
    };

    (
        freshness,
        Json(PublicHealthResponse {
            api_capabilities: if state
                .pairing
                .as_ref()
                .is_some_and(|p| p.second_device_enrollment_enabled())
            {
                vec![crate::pairing::second_device::CAPABILITY]
            } else {
                vec![]
            },
            hosted_by: state
                .pairing
                .as_ref()
                .and_then(|p| p.hosted_by().map(str::to_owned)),
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
async fn status(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<HealthResponse>, axum::http::StatusCode> {
    if auth.node_id != state.identity.node_id().to_hex() {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }
    let recovery = if let Some(dir) = state.recovery_dir.clone() {
        Some(
            tokio::task::spawn_blocking(move || konsensus_lightning::recover::status(&dir))
                .await
                .unwrap_or(konsensus_lightning::recover::Status {
                    state: konsensus_lightning::recover::JournalState::Unavailable,
                }),
        )
    } else {
        None
    };
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
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            state.chain.get_block_height(),
        )
        .await
        .ok()
        .and_then(Result::ok)
    } else {
        None
    };

    let peer = state.introduction.endpoint_view();
    let disk = state.lightning.disk_status();
    let chain_sync = state.lightning.chain_sync_status();
    let storage_health = state.storage.storage_read_health();
    let (stun_url, stun_source) = stun_status(
        peer.endpoint.as_deref(),
        state.stun_port,
        state.configured_stun_server.as_deref(),
    );
    Ok(Json(HealthResponse {
        network: state.introduction.network.clone(),
        recovery,
        channel_safety: state.lightning.channel_safety(),
        offline_safety: state
            .lightning
            .offline_safety()
            .map(|shared| shared.read().unwrap().clone()),
        local_spends: state.lightning.local_spend_diagnostics(),
        storage_unreadable_rows: storage_health.storage_unreadable_rows,
        storage_key_mismatch: storage_health.storage_key_mismatch,
        disk_low: disk.is_some_and(|s| s.disk_low),
        disk_free_bytes: disk.and_then(|s| s.disk_free_bytes),
        disk_free_floor_bytes: disk.map(|s| s.disk_free_floor_bytes),
        money_ready: readiness.money_ready,
        readiness,
        api_capabilities: {
            let mut capabilities = vec![
                crate::pairing::approval::CAPABILITY,
                crate::pairing::approval::BREAKER_RESET_CAPABILITY,
                "storage_list_diagnostics_v1",
                "offline_readiness_v1",
                "message_operations_v1",
                "message_operation_abandon_v1",
                "channel_open_operations_v1",
                super::payments::direct::CAPABILITY,
                super::messages::caps::CAPABILITY,
                super::messages::caps::QUOTED_READMISSION_CAPABILITY,
                super::messages::caps::ROOM_CAPABILITY,
                super::organism::ENERGY_CAPABILITY,
                crate::membrane::CAPABILITY,
                crate::spend_budget::CAPABILITY,
                crate::spend_budget::RELATION_ENVELOPE_ID_CAPABILITY,
                crate::pairing::device::RELATION_INTENT_V2_CAPABILITY,
                crate::spend_budget::FIRST_CONTACT_CAPABILITY,
                super::introduction::CAPABILITY,
                super::front_door::CAPABILITY,
                super::browse::CAPABILITY,
                konsensus_core::payloads::content::PORCH_QUOTE_CAPABILITY,
                super::liquidity::CAPABILITY,
                super::sponsor::CAPABILITY,
                konsensus_core::payloads::call::MEETING_CAPABILITY,
                konsensus_core::payloads::room::ROOM_BINDING_CAPABILITY,
                konsensus_message::wire::CALL_MEDIA_CAPABILITY,
            ];
            if state.starter.config.enabled {
                capabilities.push("starter_channel_request_v1");
            }
            if state
                .pairing
                .as_ref()
                .is_some_and(|p| p.second_device_enrollment_enabled())
            {
                capabilities.push(crate::pairing::second_device::CAPABILITY);
            }
            capabilities
        },
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
        chain_view: state.chain.chain_view(),
        chain_sync,
        block_height,
        stun_port: state.stun_port,
        stun_url,
        stun_source,
        peer_endpoint: peer.endpoint,
        peer_endpoint_source: peer.source.map(String::from),
        peer_endpoint_reason: peer.reason.map(String::from),
        custody_mode: state.custody_mode,
    }))
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
    Router::new()
        .route("/api/v1/status", get(status))
        .route("/api/v1/tower/status", get(tower_status))
}

#[derive(Serialize)]
struct TowerResponse {
    coverage_scope: &'static str,
    #[serde(flatten)]
    status: konsensus_core::tower::TowerStatus,
}

/// Cached local diagnostics only. TODO(W2b): decide HTLC-gap UX before any
/// broader guarded claim or HUB_ONLY_WHILE_LOCKABLE relaxation.
async fn tower_status(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Json<TowerResponse> {
    let mut status = state.lightning.tower_status();
    status.warnings = konsensus_core::tower::warnings();
    Json(TowerResponse {
        coverage_scope: "to_local_only",
        status,
    })
}

#[cfg(test)]
mod tests {
    use super::{configured_stun_url, stun_status, stun_url};

    #[test]
    fn stun_status_own_responder_wins() {
        let (url, source) = stun_status(
            Some("node.example.org:9000"),
            Some(3478),
            Some("hub.example:3478"),
        );
        assert_eq!(url.as_deref(), Some("stun:node.example.org:3478"));
        assert_eq!(source, Some("own"));
    }

    #[test]
    fn stun_status_configured_when_no_dialable_own_host() {
        let (url, source) = stun_status(None, Some(3478), Some("stun.example.org:3478"));
        assert_eq!(url.as_deref(), Some("stun:stun.example.org:3478"));
        assert_eq!(source, Some("configured"));
    }

    #[test]
    fn stun_status_neither() {
        let (url, source) = stun_status(None, None, None);
        assert_eq!(url, None);
        assert_eq!(source, None);
    }

    #[test]
    fn stun_status_invalid_configured_never_reported() {
        for bad in [
            "stuns:stun.example.org:5349",
            "stun:stun.example.org:3478",
            "not-a-host",
            "h.example",
            "",
        ] {
            let (url, source) = stun_status(None, Some(3478), Some(bad));
            assert_eq!(url, None, "{bad}");
            assert_eq!(source, None, "{bad}");
        }
    }

    #[test]
    fn configured_stun_url_normalizes_host_port() {
        assert_eq!(
            configured_stun_url("stun.example.org:3478").as_deref(),
            Some("stun:stun.example.org:3478")
        );
        assert_eq!(
            configured_stun_url(" 203.0.113.7:3478 ").as_deref(),
            Some("stun:203.0.113.7:3478")
        );
        assert_eq!(
            configured_stun_url("[2001:db8::1]:3478").as_deref(),
            Some("stun:[2001:db8::1]:3478")
        );
    }

    #[test]
    fn stun_url_uses_the_dialable_host_only() {
        assert_eq!(
            stun_url(Some("203.0.113.5:9000"), Some(3478)).as_deref(),
            Some("stun:203.0.113.5:3478")
        );
        assert_eq!(
            stun_url(Some("[2001:db8::1]:9000"), Some(3478)).as_deref(),
            Some("stun:[2001:db8::1]:3478")
        );
        assert_eq!(
            stun_url(Some(" node.example.org:9000 "), Some(1)).as_deref(),
            Some("stun:node.example.org:1")
        );
        for bad in [
            "127.0.0.1:9000",
            "[::1]:9000",
            "0.0.0.0:9000",
            "localhost:9000",
            "nohost",
            ":9000",
            "a b:1",
            "user@h:1",
            "2001:db8::1:9000",
        ] {
            assert_eq!(stun_url(Some(bad), Some(3478)), None, "{bad}");
        }
        assert_eq!(stun_url(None, Some(3478)), None);
        assert_eq!(stun_url(Some("203.0.113.5:9000"), None), None);
    }
}
