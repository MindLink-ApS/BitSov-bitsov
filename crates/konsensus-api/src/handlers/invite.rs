//! Invite endpoints — generate and redeem peer invitation tokens.
//!
//! Invite tokens encode a node's identity, network address, and optional label
//! in a signed, base58-encoded string. They can be shared as QR codes, links,
//! or plain text. Recipients redeem them to auto-add the inviter as a peer.
//!
//! **Deprecated (ADR-029):** these legacy `InviteToken` routes (`/api/v1/invite`,
//! `/api/v1/invite/redeem`) are superseded by the canonical, invitee-bound
//! `BitSovInvite` flow in [`crate::handlers::invites`] (`/api/v1/invites` +
//! `/api/v1/invites/accept`). They remain fully functional and emit
//! `Deprecation`/`Sunset` headers; removal is an operator/ADR-029 decision.

use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
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

/// Published **target** sunset for the legacy base58/`konsensus://` InviteToken
/// routes (`/api/v1/invite`, `/api/v1/invite/redeem`). This is a migration signal,
/// NOT a hard removal commitment: both routes stay fully functional, and the actual
/// removal is an operator/ADR-029 decision (the legacy `InviteToken` and the
/// canonical `BitSovInvite` formats are non-interchangeable, so removal must wait
/// for a `BitSovInvite` peer-add UX to replace the redeem flow).
const LEGACY_INVITE_SUNSET: &str = "Sun, 31 Jan 2027 00:00:00 GMT";

/// Wrap a legacy-route JSON body with RFC 8594 / RFC 9745 deprecation signalling
/// (`Deprecation`, `Sunset`, and a `Link` to the successor route) **without**
/// changing the HTTP status (200) or the JSON body. Clients see byte-identical
/// JSON plus headers that let them migrate to `POST /api/v1/invites/accept` ahead
/// of any removal.
fn deprecated_response<T: Serialize>(body: T) -> Response {
    (
        [
            (header::HeaderName::from_static("deprecation"), "true"),
            (header::HeaderName::from_static("sunset"), LEGACY_INVITE_SUNSET),
            (
                header::LINK,
                "</api/v1/invites/accept>; rel=\"successor-version\"",
            ),
        ],
        Json(body),
    )
        .into_response()
}

/// `POST /api/v1/invite` — generate a signed invite token for this node.
///
/// **Deprecated (ADR-029, 2026-06-09):** this issues a legacy base58 `InviteToken`.
/// The canonical Tier-2 onboarding path is `POST /api/v1/invites` (issue) +
/// `POST /api/v1/invites/accept` (accept) using the invitee-bound `BitSovInvite`.
/// The route remains fully functional and emits `Deprecation`/`Sunset` headers.
async fn generate_invite(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<GenerateInviteRequest>,
) -> Result<Response, ApiError> {
    tracing::warn!(
        route = "/api/v1/invite",
        deprecated = true,
        "legacy InviteToken issue endpoint — migrate to POST /api/v1/invites (BitSovInvite)"
    );
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

    Ok(deprecated_response(GenerateInviteResponse {
        token,
        uri,
        expiry,
    }))
}

/// `POST /api/v1/invite/redeem` — redeem an invite token, adding the inviter as a peer.
///
/// **Deprecated (ADR-029, 2026-06-09):** this consumes a legacy base58 `InviteToken`
/// (symmetric peer-add, no invitee binding). The canonical Tier-2 onboarding path is
/// `POST /api/v1/invites/accept` using the invitee-bound `BitSovInvite`. The two token
/// formats are non-interchangeable, so this route stays fully functional until a
/// `BitSovInvite` peer-add UX replaces it; removal is an operator/ADR-029 decision. It
/// emits `Deprecation`/`Sunset` headers for clients to migrate ahead of time.
async fn redeem_invite(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<RedeemInviteRequest>,
) -> Result<Response, ApiError> {
    tracing::warn!(
        route = "/api/v1/invite/redeem",
        deprecated = true,
        "legacy InviteToken redeem endpoint — migrate to POST /api/v1/invites/accept (BitSovInvite)"
    );
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
        return Ok(deprecated_response(RedeemInviteResponse {
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

    // P3-2: persist so the gate whitelist survives restart. The PeerRegistry
    // is rebuilt at boot from the durable `peers` table (not just
    // `config.peers`); without this, a redeemed peer drops off the gate
    // whitelist on the next restart even though it works at runtime.
    let mut peer = konsensus_storage::Peer::new(parsed.node_id);
    peer.address = Some(parsed.addr.clone());
    peer.display_name = parsed.label.clone();
    state
        .storage
        .upsert_peer(&peer)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to persist redeemed peer: {e}")))?;

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

    Ok(deprecated_response(RedeemInviteResponse {
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
