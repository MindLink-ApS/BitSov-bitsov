//! Inviter-side BitSov invite issuance endpoint (ON-B2).
//!
//! Metadata-leak posture (Principle 4 — Data Sovereignty):
//! the `invite_token_b64` is `base64url(json(BitSovInvite))`, exposing
//! inviter_pubkey, invitee_pubkey, expiry, and nonce to anyone who
//! sees the deep link (logs, messengers, screenshots). This is
//! deliberate for v1: the invite is single-use bound to a known
//! invitee, and the metadata is required for the invitee's node to
//! verify the signature without an out-of-band lookup. Tier-3
//! anonymous invites (future ADR) will encrypt the payload to the
//! invitee's pubkey. Until then, share invite links only over
//! confidential channels.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use konsensus_core::invite::{BitSovInvite, UnsignedBitSovInvite, SUPPORTED_INVITE_VERSION};
use konsensus_core::NodeId;
use konsensus_storage::{
    AcceptedInviteRecord, InviteIssuedRecord, InviteSchemaCapabilities, InviteState,
    OnboardingStateRecord, Peer, StorageError,
};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

/// Maximum invite lifetime accepted by the issuance endpoint.
/// 30 days * 24h * 3600s = 2_592_000. Caller may not request an
/// expiry farther in the future than `now + MAX_INVITE_LIFETIME_SECS`.
/// Bounded to limit the time window during which a leaked invite link
/// remains redeemable; revisit if the operator finds 30 days too short
/// for the curated Tier-2 onboarding flow.
const MAX_INVITE_LIFETIME_SECS: u64 = 30 * 24 * 3600;
const INVITE_ISSUE_LIMIT_PER_HOUR: u32 = 10;
const INVITE_ACCEPT_LIMIT_PER_MINUTE: u32 = 10;
const MAX_INVITE_ADDR_LEN: usize = 255;
const DEFAULT_MAX_FEE_RATE_SAT_PER_VB: u32 = 50;

fn invite_issue_rate_limiter() -> &'static crate::rate_limit::RateLimiter {
    static LIMITER: std::sync::OnceLock<crate::rate_limit::RateLimiter> =
        std::sync::OnceLock::new();
    LIMITER.get_or_init(|| {
        crate::rate_limit::RateLimiter::with_window(
            INVITE_ISSUE_LIMIT_PER_HOUR,
            Duration::from_secs(3600),
        )
    })
}

fn invite_accept_rate_limiter() -> &'static crate::rate_limit::RateLimiter {
    static LIMITER: std::sync::OnceLock<crate::rate_limit::RateLimiter> =
        std::sync::OnceLock::new();
    LIMITER.get_or_init(|| {
        crate::rate_limit::RateLimiter::with_window(
            INVITE_ACCEPT_LIMIT_PER_MINUTE,
            Duration::from_secs(60),
        )
    })
}

/// Request body for issuing an invite.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueInviteRequest {
    /// Invitee Ed25519 pubkey (hex-encoded 32 bytes).
    pub invitee_pubkey: String,
    /// Absolute expiry (Unix seconds). Must be strictly in the future
    /// AND within `MAX_INVITE_LIFETIME_SECS` of now.
    pub expiry_unix: u64,
    /// Optional channel size hint in sats.
    #[serde(default)]
    pub channel_size_hint_sats: Option<u32>,
    /// Inviter's dialable network address (`host:port`) for the first connection.
    #[serde(default)]
    pub addr: String,
    /// Inviter-signed upper bound for automatic channel-open fee rate.
    #[serde(default)]
    pub max_fee_rate_sat_per_vb: Option<u32>,
    /// Inviter-signed expiry for automatic channel-open authorization.
    #[serde(default)]
    pub channel_open_intent_expiry_unix: Option<u64>,
}

/// Response for issued invites.
#[derive(Debug, Serialize)]
pub struct IssueInviteResponse {
    /// Invite UUID.
    pub invite_id: String,
    /// URL-safe base64(JSON(BitSovInvite)). See module docstring for the
    /// metadata-leak posture.
    pub invite_token_b64: String,
    /// Deep link containing the token.
    pub invite_link: String,
}

/// Runtime + storage invite capability response.
#[derive(Debug, Serialize)]
pub struct InviteCapabilitiesResponse {
    /// Invite versions this binary can verify.
    pub supported_versions: Vec<u8>,
    /// Version newly issued invites use.
    pub default_version: u8,
    /// Whether the compiled binary supports BitSovInvite v2 issuance.
    pub invite_v2_runtime_ready: bool,
    /// Whether the storage backend has every column required for v2 issuance.
    pub invite_v2_storage_ready: bool,
    /// Combined readiness gate used by issue_invite.
    pub invite_v2_ready: bool,
    pub addr_column: bool,
    pub max_fee_rate_sat_per_vb_column: bool,
    pub channel_open_intent_expiry_unix_column: bool,
}

/// Request body for accepting an invite token.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptInviteRequest {
    /// URL-safe base64(JSON(BitSovInvite)).
    pub token: String,
}

/// Response body for accepted invite.
#[derive(Debug, Serialize)]
pub struct AcceptInviteResponse {
    /// Inviter Ed25519 pubkey (hex-encoded 32 bytes).
    pub inviter_pubkey: String,
    /// Optional channel size hint copied from the invite.
    pub channel_size_hint: Option<u32>,
    /// Inviter's dialable address copied from the invite.
    pub addr: String,
    /// Inviter-signed upper bound for automatic channel-open fee rate.
    pub max_fee_rate_sat_per_vb: Option<u32>,
    /// Inviter-signed expiry for automatic channel-open authorization.
    pub channel_open_intent_expiry_unix: Option<u64>,
}

/// Response for issued invite list entry.
#[derive(Debug, Serialize)]
pub struct InviteListEntry {
    pub id: String,
    pub invitee_pubkey: String,
    pub expiry_unix: u64,
    pub channel_size_hint_sats: Option<u32>,
    pub addr: String,
    pub max_fee_rate_sat_per_vb: Option<u32>,
    pub channel_open_intent_expiry_unix: Option<u64>,
    pub state: String,
    pub created_at: u64,
    pub invite_token_b64: String,
}

fn invite_capabilities_response(
    storage_caps: InviteSchemaCapabilities,
) -> InviteCapabilitiesResponse {
    let runtime_v2_ready = SUPPORTED_INVITE_VERSION >= 2;
    let storage_v2_ready = storage_caps.v2_ready();

    InviteCapabilitiesResponse {
        supported_versions: vec![1, SUPPORTED_INVITE_VERSION],
        default_version: SUPPORTED_INVITE_VERSION,
        invite_v2_runtime_ready: runtime_v2_ready,
        invite_v2_storage_ready: storage_v2_ready,
        invite_v2_ready: runtime_v2_ready && storage_v2_ready,
        addr_column: storage_caps.addr_column,
        max_fee_rate_sat_per_vb_column: storage_caps.max_fee_rate_sat_per_vb_column,
        channel_open_intent_expiry_unix_column: storage_caps
            .channel_open_intent_expiry_unix_column,
    }
}

async fn invite_capabilities(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<InviteCapabilitiesResponse>, ApiError> {
    let storage_caps = state
        .storage
        .invite_schema_capabilities()
        .await
        .map_err(|e| ApiError::Internal(format!("failed to inspect invite schema: {e}")))?;

    Ok(Json(invite_capabilities_response(storage_caps)))
}

/// `GET /api/v1/invites` — list all invites issued by this node.
async fn list_invites(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<InviteListEntry>>, ApiError> {
    let records = state
        .storage
        .list_invites_issued()
        .await
        .map_err(|e| ApiError::Internal(format!("failed to list invites: {e}")))?;

    let mut entries = Vec::with_capacity(records.len());
    for r in records {
        // Recreate the token so the UI can share it.
        let version = if r.addr.is_empty() {
            1
        } else {
            SUPPORTED_INVITE_VERSION
        };
        let unsigned = UnsignedBitSovInvite {
            version,
            inviter_pubkey: state.identity.ed25519_verifying_key().to_bytes(),
            invitee_pubkey: r.invitee_pubkey,
            expiry_unix: r.expiry_unix,
            channel_size_hint_sats: r.channel_size_hint_sats,
            addr: r.addr.clone(),
            max_fee_rate_sat_per_vb: r.max_fee_rate_sat_per_vb,
            channel_open_intent_expiry_unix: r.channel_open_intent_expiry_unix,
            nonce: r.nonce,
        };
        let invite = BitSovInvite::sign(unsigned, state.identity.ed25519_signing_key())
            .map_err(|e| ApiError::Internal(format!("failed to sign invite: {e}")))?;
        let invite_json = serde_json::to_vec(&invite)
            .map_err(|e| ApiError::Internal(format!("failed to serialize invite: {e}")))?;
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(invite_json);

        entries.push(InviteListEntry {
            id: r.id.to_string(),
            invitee_pubkey: hex::encode(r.invitee_pubkey),
            expiry_unix: r.expiry_unix,
            channel_size_hint_sats: r.channel_size_hint_sats,
            addr: r.addr,
            max_fee_rate_sat_per_vb: r.max_fee_rate_sat_per_vb,
            channel_open_intent_expiry_unix: r.channel_open_intent_expiry_unix,
            state: r.state.to_string(),
            created_at: r.created_at,
            invite_token_b64: token,
        });
    }

    Ok(Json(entries))
}

/// `DELETE /api/v1/invites/:id` — revoke an issued invite.
async fn revoke_invite(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let invite_id = Uuid::parse_str(&id)
        .map_err(|e| ApiError::BadRequest(format!("invalid invite id: {e}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ApiError::Internal(format!("system clock before UNIX_EPOCH: {e}")))?
        .as_secs();

    let revoked = state
        .storage
        .revoke_invite(&invite_id, now)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to revoke invite: {e}")))?;

    if revoked {
        Ok(Json(serde_json::json!({ "revoked": true })))
    } else {
        Err(ApiError::NotFound(
            "invite not found or already revoked/accepted".into(),
        ))
    }
}

/// `POST /api/v1/invites` — issue an invite bound to a specific invitee pubkey.
async fn issue_invite(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<IssueInviteRequest>,
) -> Result<Json<IssueInviteResponse>, ApiError> {
    let invitee_bytes = hex::decode(&req.invitee_pubkey)
        .map_err(|e| ApiError::BadRequest(format!("invalid invitee_pubkey hex: {e}")))?;
    let invitee_pubkey: [u8; 32] = invitee_bytes
        .try_into()
        .map_err(|_| ApiError::BadRequest("invitee_pubkey must be 32 bytes".into()))?;
    if invitee_pubkey == state.identity.ed25519_verifying_key().to_bytes() {
        return Err(ApiError::BadRequest(
            "invitee_pubkey must not match inviter pubkey".into(),
        ));
    }

    // Source time once for both validation and the row's created_at. Propagate
    // a broken clock as an Internal error rather than silently defaulting to
    // 0 (which would mint a created_at=0 row — a data-integrity bug).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ApiError::Internal(format!("system clock before UNIX_EPOCH: {e}")))?
        .as_secs();

    // Reject invites that would be dead-on-arrival or too long-lived.
    if req.expiry_unix <= now {
        return Err(ApiError::BadRequest(format!(
            "expiry_unix ({}) must be strictly greater than now ({})",
            req.expiry_unix, now
        )));
    }
    let max_expiry = now.saturating_add(MAX_INVITE_LIFETIME_SECS);
    if req.expiry_unix > max_expiry {
        return Err(ApiError::BadRequest(format!(
            "expiry_unix ({}) exceeds max lifetime now+{}s ({})",
            req.expiry_unix, MAX_INVITE_LIFETIME_SECS, max_expiry
        )));
    }
    let addr = req.addr.trim().to_string();
    if addr.is_empty() {
        return Err(ApiError::BadRequest("addr cannot be empty".into()));
    }
    if addr.len() > MAX_INVITE_ADDR_LEN {
        return Err(ApiError::BadRequest(format!(
            "addr too long: {} bytes (max {MAX_INVITE_ADDR_LEN})",
            addr.len()
        )));
    }
    let Some((_, port)) = addr.rsplit_once(':') else {
        return Err(ApiError::BadRequest("addr must be host:port".into()));
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| ApiError::BadRequest("addr port must be a valid u16".into()))?;
    if port == 0 {
        return Err(ApiError::BadRequest("addr port must be greater than zero".into()));
    }
    let max_fee_rate_sat_per_vb = req
        .max_fee_rate_sat_per_vb
        .unwrap_or(DEFAULT_MAX_FEE_RATE_SAT_PER_VB);
    if max_fee_rate_sat_per_vb == 0 {
        return Err(ApiError::BadRequest(
            "max_fee_rate_sat_per_vb must be greater than zero".into(),
        ));
    }
    let channel_open_intent_expiry_unix = req
        .channel_open_intent_expiry_unix
        .unwrap_or(req.expiry_unix);
    if channel_open_intent_expiry_unix <= now {
        return Err(ApiError::BadRequest(format!(
            "channel_open_intent_expiry_unix ({channel_open_intent_expiry_unix}) must be strictly greater than now ({now})"
        )));
    }
    if channel_open_intent_expiry_unix > req.expiry_unix {
        return Err(ApiError::BadRequest(format!(
            "channel_open_intent_expiry_unix ({channel_open_intent_expiry_unix}) must not exceed expiry_unix ({})",
            req.expiry_unix
        )));
    }
    if !invite_issue_rate_limiter().check_key(&auth.node_id) {
        return Err(ApiError::TooManyRequests(
            "invite issue rate limit exceeded".into(),
        ));
    }

    let existing_invites = state
        .storage
        .list_invites_issued()
        .await
        .map_err(|e| ApiError::Internal(format!("failed to list invites: {e}")))?;
    let has_live_pending_for_invitee = existing_invites.iter().any(|invite| {
        invite.invitee_pubkey == invitee_pubkey
            && invite.state == InviteState::Pending
            && invite.expiry_unix > now
    });
    if has_live_pending_for_invitee {
        return Err(ApiError::Conflict(
            "pending invite already exists for this invitee; revoke it before re-issuing".into(),
        ));
    }

    let storage_caps = state
        .storage
        .invite_schema_capabilities()
        .await
        .map_err(|e| ApiError::Internal(format!("failed to inspect invite schema: {e}")))?;
    let capabilities = invite_capabilities_response(storage_caps);
    if !capabilities.invite_v2_ready {
        return Err(ApiError::Conflict(
            "invite v2 unavailable on this node; runtime/storage capability check failed".into(),
        ));
    }

    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    let unsigned = UnsignedBitSovInvite {
        version: SUPPORTED_INVITE_VERSION,
        inviter_pubkey: state.identity.ed25519_verifying_key().to_bytes(),
        invitee_pubkey,
        expiry_unix: req.expiry_unix,
        channel_size_hint_sats: req.channel_size_hint_sats,
        addr: addr.clone(),
        max_fee_rate_sat_per_vb: Some(max_fee_rate_sat_per_vb),
        channel_open_intent_expiry_unix: Some(channel_open_intent_expiry_unix),
        nonce,
    };

    let invite = BitSovInvite::sign(unsigned, state.identity.ed25519_signing_key())
        .map_err(|e| ApiError::Internal(format!("failed to sign invite: {e}")))?;

    let invite_json = serde_json::to_vec(&invite)
        .map_err(|e| ApiError::Internal(format!("failed to serialize invite: {e}")))?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(invite_json);

    let invite_id = Uuid::new_v4();

    // Atomic write boundary for invite issuance + invite-derived whitelist:
    // storage backends must commit both rows or roll back both rows.
    let issued = InviteIssuedRecord {
        id: invite_id,
        invitee_pubkey,
        expiry_unix: req.expiry_unix,
        channel_size_hint_sats: req.channel_size_hint_sats,
        addr,
        max_fee_rate_sat_per_vb: Some(max_fee_rate_sat_per_vb),
        channel_open_intent_expiry_unix: Some(channel_open_intent_expiry_unix),
        nonce,
        state: InviteState::Pending,
        created_at: now,
        accepted_at: None,
        revoked_at: None,
    };
    state
        .storage
        .add_invite_and_whitelist(&issued, invitee_pubkey)
        .await
        .map_err(|e| {
            ApiError::Internal(format!(
                "failed to persist issued invite + invite-derived whitelist atomically: {e}"
            ))
        })?;

    Ok(Json(IssueInviteResponse {
        invite_id: invite_id.to_string(),
        invite_link: format!("bitsov://invite/{token}"),
        invite_token_b64: token,
    }))
}

/// `POST /api/v1/invites/accept` — accept a signed invite token as invitee.
async fn accept_invite(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<AcceptInviteRequest>,
) -> Result<Response, ApiError> {
    if !invite_accept_rate_limiter().check_key(&auth.node_id) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "60")],
            Json(serde_json::json!({
                "error": "invite accept rate limit exceeded",
                "code": StatusCode::TOO_MANY_REQUESTS.as_u16(),
            })),
        )
            .into_response());
    }

    let invite_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.token)
        .map_err(|e| ApiError::BadRequest(format!("invalid token base64: {e}")))?;
    let invite: BitSovInvite = serde_json::from_slice(&invite_json)
        .map_err(|e| ApiError::BadRequest(format!("invalid token json: {e}")))?;

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ApiError::Internal(format!("system clock before UNIX_EPOCH: {e}")))?
        .as_secs();
    invite
        .verify(now_unix)
        .map_err(|e| ApiError::BadRequest(format!("invalid invite: {e}")))?;

    let this_pubkey = state.identity.ed25519_verifying_key().to_bytes();
    if invite.invitee_pubkey != this_pubkey {
        return Err(ApiError::BadRequest("wrong invitee".into()));
    }

    let inviter_node_id = NodeId::from_bytes(invite.inviter_pubkey);

    // ATOMICITY ORDER FIX (AI review PR #84 finding #2):
    // Insert accepted_invites row FIRST. The migration declares
    // accepted_invites.nonce as PRIMARY KEY, so:
    //  - First write wins; concurrent attempts hit a unique-constraint
    //    violation on the second insert. If the duplicate is the same
    //    authority row, keep going and re-run finalization so a lost
    //    response or crash after the authority commit can converge.
    //    A duplicate nonce for a different inviter/expiry still fails
    //    closed as a conflict.
    //  - If the row insert fails for any reason, no whitelist mutation
    //    has happened yet — the failure is observable to the caller
    //    and retryable.
    //  - Only after the persistent audit row is committed do we mutate
    //    the whitelist (the in-memory transport state can be rebuilt
    //    from accepted_invites on restart; the row cannot be rebuilt
    //    from in-memory state).
    let record = AcceptedInviteRecord {
        nonce: invite.nonce,
        inviter_pubkey: invite.inviter_pubkey,
        expiry_unix: invite.expiry_unix,
        accepted_at: now_unix,
    };
    let mut accepted_invite_already_committed = false;
    match state.storage.add_accepted_invite(&record).await {
        Ok(()) => {}
        Err(StorageError::AlreadyExists(_)) => {
            accepted_invite_already_committed = true;
            let existing = state
                .storage
                .find_accepted_invite(&invite.nonce)
                .await
                .map_err(|e| {
                    ApiError::Internal(format!(
                        "failed to load accepted invite after duplicate: {e}"
                    ))
                })?
                .ok_or_else(|| {
                    ApiError::Internal(
                        "accepted invite duplicate reported but row was not found".into(),
                    )
                })?;

            if existing.inviter_pubkey != invite.inviter_pubkey
                || existing.expiry_unix != invite.expiry_unix
            {
                return Err(ApiError::Conflict(
                    "invite nonce already accepted for different invite parameters".into(),
                ));
            }
        }
        Err(e) => {
            return Err(ApiError::Internal(format!(
                "failed to persist accepted invite: {e}"
            )));
        }
    }

    // SPEC FIX (AI review PR #84 finding #3):
    // The task spec says "add inviter_pubkey to whitelist via
    // Storage::add_whitelisted_peer". upsert_peer creates a Peer row
    // but does NOT necessarily set whitelist semantics. Until
    // Storage::add_whitelisted_peer ships, we call both:
    //   - upsert_peer for the peer-list row visible to operator UI
    //   - transport.add_to_whitelist for the runtime gate
    // This is a known-imperfect bridge; ONB4 ships add_whitelisted_peer
    // as a proper trait method with invite_ref metadata.
    // P3-2: the PaymentGate reads its whitelist from the in-memory PeerRegistry
    // (msg_handler builds the gate whitelist from `peer_registry.whitelist()`).
    // accept_invite previously updated only the durable peer row + the
    // transport whitelist, so the invited peer completed the Noise handshake
    // but every message was then rejected `NotWhitelisted` at the gate. Persist
    // the inviter (the durable authority reloaded into the registry at boot)
    // AND mirror the admission into the in-memory registry.
    //
    // The signed invite carries the inviter's dialable address, so record it —
    // discarding it would leave the invitee unable to ever initiate a
    // connection back to the inviter (reachable only if the inviter dials in).
    let inviter_addr: Option<std::net::SocketAddr> = invite.addr.parse().ok();
    let mut inviter_peer = Peer::new(inviter_node_id);
    inviter_peer.address = inviter_addr.map(|a| a.to_string());
    state
        .storage
        .upsert_peer(&inviter_peer)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to upsert inviter peer: {e}")))?;
    state.transport.add_to_whitelist(&inviter_node_id).await;
    {
        let mut registry = state.peer_registry.write().await;
        registry.add(konsensus_message::PeerEntry {
            node_id: inviter_node_id,
            addr: inviter_addr.unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0))),
            label: None,
            auto_connect: false,
        });
    }

    let previous_onboarding = state.storage.get_onboarding_state().await.ok().flatten();
    let should_update_onboarding = !accepted_invite_already_committed
        || previous_onboarding
            .as_ref()
            .map(|record| record.current_step == "connecting")
            .unwrap_or(true);
    if should_update_onboarding {
        let scoped_onboarding = OnboardingStateRecord {
            invite_id: previous_onboarding.as_ref().and_then(|record| record.invite_id),
            inviter_pubkey: Some(invite.inviter_pubkey),
            inviter_ln_pubkey: None,
            current_step: "connecting".to_string(),
            tier: previous_onboarding
                .as_ref()
                .and_then(|record| record.tier.clone())
                .or_else(|| Some("light".to_string())),
            funding_address: previous_onboarding
                .as_ref()
                .and_then(|record| record.funding_address.clone()),
            funding_amount_sats_required: previous_onboarding
                .as_ref()
                .and_then(|record| record.funding_amount_sats_required),
            funding_amount_sats_received: previous_onboarding
                .as_ref()
                .map(|record| record.funding_amount_sats_received)
                .unwrap_or(0),
            last_poll_at: Some(now_unix),
            funding_evidence: previous_onboarding
                .as_ref()
                .and_then(|record| record.funding_evidence.clone()),
        };
        state
            .storage
            .upsert_onboarding_state(&scoped_onboarding)
            .await
            .map_err(|e| ApiError::Internal(format!("failed to persist onboarding scope: {e}")))?;
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptInviteResponse {
            inviter_pubkey: hex::encode(invite.inviter_pubkey),
            channel_size_hint: invite.channel_size_hint_sats,
            addr: invite.addr,
            max_fee_rate_sat_per_vb: invite.max_fee_rate_sat_per_vb,
            channel_open_intent_expiry_unix: invite.channel_open_intent_expiry_unix,
        }),
    )
        .into_response())
}

/// Registers inviter-side invite issuance routes.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/invites", post(issue_invite).get(list_invites))
        .route("/api/v1/invites/capabilities", get(invite_capabilities))
        .route("/api/v1/invites/:id", axum::routing::delete(revoke_invite))
        .route("/api/v1/invites/accept", post(accept_invite))
}
