//! Invite endpoints — generate and redeem peer invitation tokens.
//!
//! Invite tokens encode a node's identity, network address, and optional label
//! in a signed, base58-encoded string. They can be shared as QR codes, links,
//! or plain text. Recipients redeem them to auto-add the inviter as a peer.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use konsensus_core::invite::InviteToken;
use konsensus_message::PeerEntry;

use crate::audit::events;
use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

/// Maximum invite address length (bytes).
const MAX_INVITE_ADDR_LEN: usize = 255;

/// Maximum invite label length (bytes).
const MAX_INVITE_LABEL_LEN: usize = 255;

/// Request to generate an invite token.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerateInviteRequest {
    /// Network address (host:port) that recipients should connect to.
    /// This should be the externally reachable address of this node.
    pub addr: String,
    /// Optional human-readable label for this node.
    #[serde(default)]
    pub label: Option<String>,
    /// Expiry in seconds from now. 0 or absent = no expiry.
    #[serde(default)]
    pub expiry_secs: u64,
}

/// Response containing the generated invite.
#[derive(Serialize)]
pub struct GenerateInviteResponse {
    /// Base58-encoded invite token.
    pub token: String,
    /// Full invite URI (`konsensus://invite/<token>`).
    pub uri: String,
    /// Expiry timestamp (Unix seconds), 0 = no expiry.
    pub expiry: u64,
}

/// Request to redeem an invite token.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemInviteRequest {
    /// The invite token (base58 string) or full URI (`konsensus://invite/...`).
    pub invite: String,
    /// Whether to auto-connect to this peer on startup.
    #[serde(default = "default_true")]
    pub auto_connect: bool,
}

fn default_true() -> bool {
    true
}

/// Response from redeeming an invite.
#[derive(Serialize)]
pub struct RedeemInviteResponse {
    /// The peer's node ID (hex).
    pub node_id: String,
    /// The peer's network address.
    pub addr: String,
    /// The peer's label (from invite token).
    pub label: Option<String>,
    /// Whether the peer was newly added (false if already in registry).
    pub added: bool,
    /// Short fingerprint for compact display.
    pub fingerprint: String,
}

/// `POST /api/v1/invite` — generate a signed invite token for this node.
async fn generate_invite(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<GenerateInviteRequest>,
) -> Result<Json<GenerateInviteResponse>, ApiError> {
    if req.addr.is_empty() {
        return Err(ApiError::BadRequest("addr is required".into()));
    }
    if req.addr.len() > MAX_INVITE_ADDR_LEN {
        return Err(ApiError::BadRequest(format!(
            "addr exceeds {MAX_INVITE_ADDR_LEN} bytes"
        )));
    }
    if let Some(ref label) = req.label {
        if label.len() > MAX_INVITE_LABEL_LEN {
            return Err(ApiError::BadRequest(format!(
                "label exceeds {MAX_INVITE_LABEL_LEN} bytes"
            )));
        }
    }

    let expiry = if req.expiry_secs > 0 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_add(req.expiry_secs)
    } else {
        0
    };

    let token = InviteToken::generate(
        &state.identity,
        &req.addr,
        req.label.as_deref(),
        expiry,
    )
    .map_err(|e| ApiError::BadRequest(format!("failed to generate invite: {e}")))?;

    let uri = format!("konsensus://invite/{token}");

    state.audit_log.record(
        events::INVITE_GENERATED,
        &_auth.node_id,
        Some(serde_json::json!({
            "addr": req.addr,
            "expiry": expiry,
        })),
    );

    Ok(Json(GenerateInviteResponse { token, uri, expiry }))
}

/// `POST /api/v1/invite/redeem` — redeem an invite token, adding the inviter as a peer.
async fn redeem_invite(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<RedeemInviteRequest>,
) -> Result<Json<RedeemInviteResponse>, ApiError> {
    // Parse the invite — accept both raw base58 tokens and full URIs
    let parsed = if req.invite.starts_with("konsensus://") {
        InviteToken::parse_uri(&req.invite)
    } else {
        InviteToken::parse(&req.invite)
    }
    .map_err(|e| ApiError::BadRequest(format!("invalid invite: {e}")))?;

    // Don't add ourselves
    if parsed.node_id == *state.identity.node_id() {
        return Err(ApiError::BadRequest("cannot add yourself as a peer".into()));
    }

    // Parse the address
    let addr = parsed
        .addr
        .parse()
        .map_err(|e| ApiError::BadRequest(format!("invalid address in invite: {e}")))?;

    let node_id_hex = parsed.node_id.to_hex();
    let fingerprint = node_id_hex[..8].to_string();

    // Check if already in registry
    let already_exists = {
        let registry = state.peer_registry.read().await;
        registry.get(&parsed.node_id).is_some()
    };

    if already_exists {
        return Ok(Json(RedeemInviteResponse {
            node_id: node_id_hex,
            addr: parsed.addr,
            label: parsed.label,
            added: false,
            fingerprint,
        }));
    }

    // Add to registry and whitelist
    let entry = PeerEntry {
        node_id: parsed.node_id,
        addr,
        label: parsed.label.clone(),
        auto_connect: req.auto_connect,
    };

    {
        let mut registry = state.peer_registry.write().await;
        registry.add(entry);
    }

    // Add to transport whitelist so the connection succeeds (Principle 3)
    state.transport.add_to_whitelist(&parsed.node_id).await;

    state.audit_log.record(
        events::INVITE_REDEEMED,
        &_auth.node_id,
        Some(serde_json::json!({
            "peer_node_id": node_id_hex,
            "addr": parsed.addr,
        })),
    );

    // Start supervised connection — auto-reconnects with exponential backoff
    // if the initial connection fails or if the peer disconnects later.
    // This gives redeemed peers the same resilience as config-file peers.
    if req.auto_connect {
        state
            .transport
            .supervise_peer(&parsed.node_id, &parsed.addr)
            .await;
    } else {
        // One-shot connect without supervision
        let transport = Arc::clone(&state.transport);
        let peer_id = parsed.node_id;
        let peer_addr = parsed.addr.clone();
        tokio::spawn(async move {
            if let Err(e) = transport.connect(&peer_id, &peer_addr).await {
                tracing::warn!(peer = %peer_id.to_hex(), error = %e, "invite: connect failed");
            }
        });
    }

    Ok(Json(RedeemInviteResponse {
        node_id: node_id_hex,
        addr: parsed.addr,
        label: parsed.label,
        added: true,
        fingerprint,
    }))
}

/// Registers the invite routes.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/invite", post(generate_invite))
        .route("/api/v1/invite/redeem", post(redeem_invite))
}
