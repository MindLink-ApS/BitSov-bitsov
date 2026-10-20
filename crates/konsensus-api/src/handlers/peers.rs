//! Peer management endpoints — list, add, remove, connect.

use crate::auth::scoped::{Admin, Read, ScopedAuth};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use konsensus_core::types::NodeId;
use konsensus_message::PeerEntry;

use crate::audit::events;
use crate::error::ApiError;
use crate::freshness::DataFreshness;
use crate::handlers::list_diagnostics::ListDiagnostics;
use crate::peer_validation::{validate_peer_addr, validate_peer_id, validate_peer_label};
use crate::state::AppState;

/// Peer in API response format.
#[derive(Serialize)]
pub struct PeerResponse {
    /// Node ID (hex).
    pub node_id: String,
    /// Network address.
    pub addr: String,
    /// Human-readable label.
    pub label: Option<String>,
    /// Whether this peer is currently connected.
    pub connected: bool,
    /// Whether auto-connect is enabled.
    pub auto_connect: bool,
    /// Short fingerprint (8 hex chars) for compact display.
    pub fingerprint: String,
    /// Safety number for out-of-band verification (12 groups of 5 digits).
    pub safety_number: String,
    /// Sovereignty tier advertised during federation handshake (e.g. "T1", "T2").
    /// Only present when the peer is connected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// Capabilities advertised during federation handshake (e.g. "X3dh", "FileTransfer").
    /// Only present when the peer is connected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
}

/// Request to add a peer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddPeerRequest {
    /// Node ID (hex-encoded Ed25519 public key).
    pub node_id: String,
    /// Network address (host:port).
    pub addr: String,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Legacy startup flag (defaults true); all local contacts are supervised.
    #[serde(default = "default_auto_connect")]
    pub auto_connect: bool,
}

fn default_auto_connect() -> bool {
    true
}

/// A single peer in an export/import backup.
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PeerBackupEntry {
    /// Node ID (hex-encoded Ed25519 public key).
    pub node_id: String,
    /// Network address (host:port).
    pub addr: String,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Whether to auto-connect on startup.
    pub auto_connect: bool,
}

/// Full contact backup for export/import.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerBackup {
    /// Format version for future compatibility.
    pub version: u32,
    /// ISO 8601 timestamp when the backup was created.
    pub exported_at: String,
    /// Node ID of the node that created this backup.
    pub exported_by: String,
    /// The peer entries.
    pub peers: Vec<PeerBackupEntry>,
}

/// Request to import peers from a backup.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportPeersRequest {
    /// The backup data (same format as export).
    pub backup: PeerBackup,
    /// If true, skip peers that already exist (default: false = upsert).
    #[serde(default)]
    pub skip_existing: bool,
}

/// Response from peer import.
#[derive(Serialize)]
pub struct ImportPeersResponse {
    /// Number of peers imported (added or updated).
    pub imported: usize,
    /// Number of peers skipped (already existed and skip_existing=true).
    pub skipped: usize,
    /// Peer IDs that had invalid format and were rejected.
    pub errors: Vec<String>,
}

/// Request to update a peer's mutable fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePeerRequest {
    /// Updated network address (host:port). If `None`, address is unchanged.
    pub addr: Option<String>,
    /// Updated label. If `None`, label is unchanged. Use `""` to clear.
    pub label: Option<String>,
    /// Updated auto-connect flag. If `None`, unchanged.
    pub auto_connect: Option<bool>,
}

/// Build a PeerResponse with safety number computed against the local node.
fn peer_response(
    entry: &PeerEntry,
    connected: bool,
    local_id: &NodeId,
    info: Option<konsensus_core::traits::ConnectedPeerInfo>,
) -> PeerResponse {
    PeerResponse {
        node_id: entry.node_id.to_hex(),
        addr: entry.addr.to_string(),
        label: entry.label.clone(),
        connected,
        auto_connect: entry.auto_connect,
        fingerprint: entry.node_id.short_fingerprint(),
        safety_number: local_id.safety_number(&entry.node_id),
        tier: info.as_ref().map(|i| i.tier.clone()),
        capabilities: info.map(|i| i.capabilities),
    }
}

/// `GET /api/v1/peers` — list all known peers with connection status.
///
/// Carries `BitSov-Data-As-Of` (see `crate::freshness`): the registry and the
/// live connection set are the node's own, read for this response, so the
/// stamp is taken before either read. Never stale.
async fn list_peers(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Result<(DataFreshness, ListDiagnostics, Json<Vec<PeerResponse>>), ApiError> {
    let read_at = DataFreshness::now();
    // Registry owns live connection data; scan storage to disclose unreadable persisted peers.
    let stored = state
        .storage
        .list_peers_with_diagnostics()
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;
    let diagnostics = (&stored).into();
    let registry = state.peer_registry.read().await;
    let connected = state.transport.connected_peers().await;
    let local_id = state.identity.node_id();

    let mut peers = Vec::new();
    for entry in registry.all() {
        let is_connected = connected.contains(&entry.node_id);
        let info = if is_connected {
            state.transport.peer_info(&entry.node_id).await
        } else {
            None
        };
        peers.push(peer_response(entry, is_connected, local_id, info));
    }

    Ok((read_at, diagnostics, Json(peers)))
}

/// `GET /api/v1/peers/connected` — list currently connected peers.
async fn connected_peers(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Json<Vec<String>> {
    let connected = state.transport.connected_peers().await;
    let hex_ids: Vec<_> = connected.iter().map(|id| id.to_hex()).collect();
    Json(hex_ids)
}

/// `POST /api/v1/peers` — add a peer to the registry.
async fn add_peer(
    _auth: ScopedAuth<Admin>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddPeerRequest>,
) -> Result<Json<PeerResponse>, ApiError> {
    let outcome = admit_peer(&state, &_auth.node_id, "http_admin", req, false).await?;
    Ok(Json(peer_response(
        &outcome.entry,
        false,
        state.identity.node_id(),
        None,
    )))
}

/// A durable admission and the result of its optional first dial.
pub struct AdmitPeerOutcome {
    /// The admitted contact.
    pub entry: PeerEntry,
    /// `Ok` if the first dial succeeded or no immediate dial was requested.
    pub dialed: Result<(), String>,
}

/// Validate and persist before admitting to the live registry and transport.
/// A failed first dial does not undo admission: supervision keeps retrying.
pub async fn admit_peer(
    state: &Arc<AppState>,
    actor: &str,
    source: &'static str,
    req: AddPeerRequest,
    dial_now: bool,
) -> Result<AdmitPeerOutcome, ApiError> {
    let node_id = NodeId::from_hex(&req.node_id)
        .map_err(|e| ApiError::BadRequest(format!("invalid node ID: {e}")))?;
    validate_peer_id(&node_id, state.identity.node_id())?;
    let addr: std::net::SocketAddr = req.addr.parse().map_err(|e| {
        ApiError::BadRequest(format!("invalid address (IP address and port only): {e}"))
    })?;
    validate_peer_addr(&addr)?;
    validate_peer_label(req.label.as_deref())?;
    let entry = PeerEntry {
        node_id,
        addr,
        label: req.label,
        auto_connect: req.auto_connect,
    };
    // Serialize admission with other registry mutations, including removal.
    // Keep persistence in this ordering so concurrent adds cannot install an
    // older address in the registry after a newer row has reached storage.
    let mut registry = state.peer_registry.write().await;
    let mut persisted = konsensus_storage::Peer::new(node_id);
    persisted.address = Some(addr.to_string());
    persisted.display_name = entry.label.clone();
    persisted.metadata = serde_json::json!({"whitelist_source": source});
    state
        .storage
        .upsert_peer(&persisted)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to persist peer: {e}")))?;

    registry.add(entry.clone());
    let generation = registry.generation(&node_id).expect("just admitted");
    state.transport.add_to_whitelist(&node_id).await;
    drop(registry);
    let dialed = dial_and_supervise(state, &entry, generation, dial_now).await;
    state.audit_log.record(
        events::PEER_ADDED,
        actor,
        Some(serde_json::json!({
            "peer_node_id": node_id.to_hex(),
            "addr": addr.to_string(),
            "label": entry.label,
            "source": source,
            "connected": state.transport.is_connected(&node_id).await,
        })),
    );
    Ok(AdmitPeerOutcome { entry, dialed })
}

/// Network I/O never holds the registry lock. Revalidate the admission before
/// installing retries, serialized with DELETE and replacement admissions.
async fn dial_and_supervise(
    state: &Arc<AppState>,
    entry: &PeerEntry,
    generation: u64,
    dial_now: bool,
) -> Result<(), String> {
    let node_id = &entry.node_id;
    let dialed = if dial_now {
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            state.transport.connect(node_id, &entry.addr.to_string()),
        )
        .await
        {
            Ok(result) => result.map_err(|e| e.to_string()),
            Err(_) => Err("connection timed out after 10 seconds".into()),
        }
    } else {
        Ok(())
    };
    let registry = state.peer_registry.write().await;
    if registry.generation(node_id) != Some(generation) {
        if let Some(current) = registry.get(node_id) {
            // connect() can remember its dial target internally. Restore the
            // current target, never the stale one, without revoking a re-add.
            state
                .transport
                .supervise_peer(node_id, &current.addr.to_string())
                .await;
        } else {
            // A transport may finish its handshake after DELETE disconnected.
            // Clear any late connection and transport-internal retry tracking.
            state.transport.remove_from_whitelist(node_id).await;
            if let Err(e) = state.transport.disconnect(node_id).await {
                tracing::warn!(peer = %node_id, error = %e, "failed to disconnect stale dial");
            }
        }
        return Err("peer removed or replaced during connection attempt".into());
    }
    state
        .transport
        .supervise_peer(node_id, &entry.addr.to_string())
        .await;
    dialed
}

/// `DELETE /api/v1/peers/:node_id` — remove a peer from the registry.
async fn remove_peer(
    _auth: ScopedAuth<Admin>,
    State(state): State<Arc<AppState>>,
    Path(node_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let node_id = NodeId::from_hex(&node_id_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid node ID: {e}")))?;

    // Keep removal ordered with admission through transport and durable cleanup.
    let mut registry = state.peer_registry.write().await;
    if registry.get(&node_id).is_none() {
        return Err(ApiError::NotFound(format!("peer {node_id_hex} not found")));
    }

    // Commit removal before touching live state. On a storage error the
    // contact and its supervision remain intact, matching restart behavior.
    state
        .storage
        .delete_peer(&node_id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;
    registry.remove(&node_id);

    // Remove from transport whitelist and disconnect (Principle 3).
    state.transport.remove_from_whitelist(&node_id).await;
    if state.transport.is_connected(&node_id).await {
        if let Err(e) = state.transport.disconnect(&node_id).await {
            tracing::warn!(peer = %node_id_hex, error = %e, "failed to disconnect removed peer");
        }
    }

    state.audit_log.record(
        events::PEER_REMOVED,
        &_auth.node_id,
        Some(serde_json::json!({"peer_node_id": node_id_hex})),
    );

    drop(registry);
    Ok(Json(serde_json::json!({ "removed": true })))
}

/// `GET /api/v1/peers/:node_id` — get a specific peer.
async fn get_peer(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(node_id_hex): Path<String>,
) -> Result<Json<PeerResponse>, ApiError> {
    let node_id = NodeId::from_hex(&node_id_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid node ID: {e}")))?;

    let registry = state.peer_registry.read().await;
    let entry = registry
        .get(&node_id)
        .ok_or_else(|| ApiError::NotFound(format!("peer {node_id_hex} not found")))?;

    let is_connected = state.transport.is_connected(&node_id).await;
    let info = if is_connected {
        state.transport.peer_info(&node_id).await
    } else {
        None
    };

    let local_id = state.identity.node_id();
    Ok(Json(peer_response(entry, is_connected, local_id, info)))
}

/// `PUT /api/v1/peers/:node_id` — update a peer's label, address, or auto-connect.
async fn update_peer(
    _auth: ScopedAuth<Admin>,
    State(state): State<Arc<AppState>>,
    Path(node_id_hex): Path<String>,
    Json(req): Json<UpdatePeerRequest>,
) -> Result<Json<PeerResponse>, ApiError> {
    let node_id = NodeId::from_hex(&node_id_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid node ID: {e}")))?;

    validate_peer_id(&node_id, state.identity.node_id())?;
    validate_peer_label(req.label.as_deref())?;

    let connected = state.transport.connected_peers().await;

    let mut registry = state.peer_registry.write().await;
    let existing = registry
        .get(&node_id)
        .ok_or_else(|| ApiError::NotFound(format!("peer {node_id_hex} not found")))?
        .clone();

    let new_addr = match &req.addr {
        Some(addr_str) => {
            let addr = addr_str
                .parse()
                .map_err(|e| ApiError::BadRequest(format!("invalid address: {e}")))?;
            validate_peer_addr(&addr)?;
            addr
        }
        // Inbound-only contacts have a nondialable sentinel. Metadata edits
        // need not invent an address; only newly supplied targets are checked.
        None => existing.addr,
    };

    let new_label = match req.label {
        Some(ref l) if l.is_empty() => None,
        Some(ref l) => Some(l.clone()),
        None => existing.label.clone(),
    };

    let new_auto_connect = req.auto_connect.unwrap_or(existing.auto_connect);

    let updated = PeerEntry {
        node_id,
        addr: new_addr,
        label: new_label.clone(),
        auto_connect: new_auto_connect,
    };

    // P3-2: persist the update so address/label/auto_connect edits survive
    // restart (merge_persisted_peers reloads the durable row at boot).
    let mut persisted = konsensus_storage::Peer::new(node_id);
    persisted.address = Some(new_addr.to_string());
    persisted.display_name = new_label.clone();
    state
        .storage
        .upsert_peer(&persisted)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to persist peer update: {e}")))?;

    registry.add(updated);
    state
        .transport
        .supervise_peer(&node_id, &new_addr.to_string())
        .await;
    drop(registry);

    state.audit_log.record(
        events::PEER_UPDATED,
        &_auth.node_id,
        Some(serde_json::json!({
            "peer_node_id": node_id_hex,
            "addr": new_addr.to_string(),
            "label": new_label,
        })),
    );

    let local_id = state.identity.node_id();
    let is_connected = connected.contains(&node_id);
    let info = if is_connected {
        state.transport.peer_info(&node_id).await
    } else {
        None
    };
    let result_entry = PeerEntry {
        node_id,
        addr: new_addr,
        label: new_label,
        auto_connect: new_auto_connect,
    };
    Ok(Json(peer_response(
        &result_entry,
        is_connected,
        local_id,
        info,
    )))
}

/// `POST /api/v1/peers/:node_id/connect` — connect to a peer.
///
/// Ensures the peer is whitelisted before connecting. Peers discovered via
/// exchange are in the registry but not whitelisted — this endpoint makes the
/// explicit user decision to whitelist and connect.
async fn connect_peer(
    _auth: ScopedAuth<Admin>,
    State(state): State<Arc<AppState>>,
    Path(node_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let node_id = NodeId::from_hex(&node_id_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid node ID: {e}")))?;

    // Serialize lookup, durable admission and live changes with DELETE.
    let registry = state.peer_registry.write().await;
    let entry = registry
        .get(&node_id)
        .ok_or_else(|| ApiError::NotFound(format!("peer {node_id_hex} not in registry")))?
        .clone();
    let generation = registry.generation(&node_id).expect("registered peer");
    let addr = entry.addr;
    validate_peer_addr(&addr)?;

    // P3-2: persist this explicit-consent admission so it survives restart.
    // connect_peer admits gossip-discovered peers that were registry-only;
    // without persistence they drop off both whitelists on the next boot.
    let mut persisted = konsensus_storage::Peer::new(node_id);
    persisted.address = Some(addr.to_string());
    persisted.display_name = entry.label.clone();
    state
        .storage
        .upsert_peer(&persisted)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to persist connected peer: {e}")))?;

    state.transport.add_to_whitelist(&node_id).await;
    drop(registry);
    dial_and_supervise(&state, &entry, generation, true)
        .await
        .map_err(ApiError::Transport)?;

    Ok(Json(serde_json::json!({ "connected": true })))
}

/// `POST /api/v1/peers/:node_id/discover` — legacy unpaid discovery is disabled.
/// A future buyer flow must authorize a signed quote and its per-request payment.
async fn discover_peers(
    _auth: ScopedAuth<Admin>,
    Path(node_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    NodeId::from_hex(&node_id_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid node ID: {e}")))?;
    Err(ApiError::BadRequest(
        "peer discovery requires a signed quote and per-request payment; this endpoint cannot authorize that purchase".into(),
    ))
}

/// `GET /api/v1/peers/export` — export all peers as a JSON backup.
///
/// Read scope suffices: peer fields match `GET /peers`; the remaining metadata
/// is the format version, export time and local public node ID. No secrets.
async fn export_peers(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Json<PeerBackup> {
    let registry = state.peer_registry.read().await;
    let local_id = state.identity.node_id();

    let peers: Vec<PeerBackupEntry> = registry
        .all()
        .into_iter()
        .map(|entry| PeerBackupEntry {
            node_id: entry.node_id.to_hex(),
            addr: entry.addr.to_string(),
            label: entry.label.clone(),
            auto_connect: entry.auto_connect,
        })
        .collect();

    let backup = PeerBackup {
        version: 1,
        exported_at: chrono::Utc::now().to_rfc3339(),
        exported_by: local_id.to_hex(),
        peers,
    };

    state.audit_log.record(
        events::PEERS_EXPORTED,
        &_auth.node_id,
        Some(serde_json::json!({ "count": backup.peers.len() })),
    );

    Json(backup)
}

/// Maximum number of peers in a single import request.
const MAX_IMPORT_PEERS: usize = 1000;

/// `POST /api/v1/peers/import` — import peers from a JSON backup.
async fn import_peers(
    _auth: ScopedAuth<Admin>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ImportPeersRequest>,
) -> Result<Json<ImportPeersResponse>, ApiError> {
    if req.backup.peers.len() > MAX_IMPORT_PEERS {
        return Err(ApiError::BadRequest(format!(
            "too many peers in import: {} (max {MAX_IMPORT_PEERS})",
            req.backup.peers.len()
        )));
    }

    // Reject prohibited dial targets before applying any part of a backup.
    // Malformed strings retain the existing per-entry import error reporting.
    for entry in &req.backup.peers {
        if let Ok(addr) = entry.addr.parse() {
            validate_peer_addr(&addr)?;
        }
    }

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut errors = Vec::new();

    let local_id = state.identity.node_id();

    for entry in &req.backup.peers {
        // Validate node ID
        let node_id = match NodeId::from_hex(&entry.node_id) {
            Ok(id) => id,
            Err(e) => {
                errors.push(format!("{}: invalid node ID — {e}", entry.node_id));
                continue;
            }
        };

        // Don't import self
        if validate_peer_id(&node_id, local_id).is_err() {
            skipped += 1;
            continue;
        }

        // Validate address
        let addr = match entry.addr.parse() {
            Ok(a) => a,
            Err(e) => {
                errors.push(format!("{}: invalid address — {e}", entry.node_id));
                continue;
            }
        };

        // The existence check belongs to the same write transaction as the
        // upsert, so simultaneous skip-existing imports cannot both admit.
        let mut registry = state.peer_registry.write().await;
        if req.skip_existing && registry.get(&node_id).is_some() {
            skipped += 1;
            continue;
        }

        if let Err(e) = validate_peer_label(entry.label.as_deref()) {
            errors.push(format!("{}: {e}", entry.node_id));
            continue;
        }

        let peer_entry = PeerEntry {
            node_id,
            addr,
            label: entry.label.clone(),
            auto_connect: entry.auto_connect,
        };

        // P3-2: persist so imported peers survive restart.
        let mut persisted = konsensus_storage::Peer::new(node_id);
        persisted.address = Some(addr.to_string());
        persisted.display_name = entry.label.clone();
        if let Err(e) = state.storage.upsert_peer(&persisted).await {
            errors.push(format!("{}: failed to persist peer: {e}", entry.node_id));
            continue;
        }
        registry.add(peer_entry);
        state.transport.add_to_whitelist(&node_id).await;
        state
            .transport
            .supervise_peer(&node_id, &addr.to_string())
            .await;
        imported += 1;
    }

    state.audit_log.record(
        events::PEERS_IMPORTED,
        &_auth.node_id,
        Some(serde_json::json!({
            "imported": imported,
            "skipped": skipped,
            "errors": errors.len(),
            "source": req.backup.exported_by,
        })),
    );

    Ok(Json(ImportPeersResponse {
        imported,
        skipped,
        errors,
    }))
}

/// Registers peer management routes for listing, adding, updating, removing, connecting, and discovering peers.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/peers", get(list_peers).post(add_peer))
        .route("/api/v1/peers/connected", get(connected_peers))
        .route("/api/v1/peers/export", get(export_peers))
        .route("/api/v1/peers/import", post(import_peers))
        .route(
            "/api/v1/peers/:node_id",
            get(get_peer).put(update_peer).delete(remove_peer),
        )
        .route("/api/v1/peers/:node_id/connect", post(connect_peer))
        .route("/api/v1/peers/:node_id/discover", post(discover_peers))
}

#[cfg(test)]
mod reconnect_tests {
    use super::*;

    #[test]
    fn owner_added_contact_defaults_to_auto_connect() {
        let req: AddPeerRequest = serde_json::from_value(serde_json::json!({
            "node_id": "unused by deserialization", "addr": "127.0.0.1:9735"
        }))
        .unwrap();
        assert!(
            req.auto_connect,
            "owner-added contacts should connect without a hidden opt-in"
        );
    }
}
