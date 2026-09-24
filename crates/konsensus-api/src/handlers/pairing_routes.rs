//! Pairing endpoints on the live router (#76).
//!
//! # What is deliberately absent
//!
//! There is no route here that writes a grant or consumes an approval. The app
//! may **create a pending request** and **read its status**; that separation is
//! the whole mechanism. Elevation is written only by the owner CLI over
//! `<data_dir>/control.sock` (see [`crate::control`]), which is not reachable
//! over loopback TCP and therefore excludes the in-scope attacker class.
//!
//! `tests/pairing_tests.rs::http_elevation_write_paths_absent` asserts that
//! absence against the real router rather than trusting this comment.
//!
//! # Why `/pair/request` and `/pair/confirm` are unauthenticated
//!
//! A client cannot hold a token before it is paired, so requiring one would
//! make the ceremony impossible. The gate is not authentication — it is
//! **read access to the data directory**: `/pair/request` returns no secret,
//! and `/pair/confirm` requires a signature over a 32-byte challenge that only
//! exists in a `0600` file under `data_dir`. A loopback-only attacker can call
//! `/pair/request` all day and get nothing usable.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::audit::events;
use crate::auth::scoped::{Admin, Read, ScopedAuth};
use crate::auth::Scope;
use crate::error::ApiError;
use crate::pairing::{self, ElevationStatus, PairingError, PairingService};
use crate::state::AppState;

/// Map a pairing failure onto the API's error type.
///
/// Every mapping is a refusal. None of them degrade a caller to a weaker
/// success — a failure here means the operation did not happen.
fn map_err(e: PairingError) -> ApiError {
    match e {
        PairingError::Closed => ApiError::Conflict(e.to_string()),
        PairingError::TooManyPending => ApiError::TooManyRequests(e.to_string()),
        PairingError::UnknownPending | PairingError::BadProof => {
            ApiError::Unauthorized(e.to_string())
        }
        PairingError::Malformed(_) => ApiError::BadRequest(e.to_string()),
        PairingError::UnknownClient | PairingError::UnknownOperation => {
            ApiError::NotFound(e.to_string())
        }
        PairingError::Io(_) => ApiError::Internal(e.to_string()),
        _ => ApiError::Forbidden(e.to_string()),
    }
}

fn service(state: &AppState) -> Result<&Arc<PairingService>, ApiError> {
    state
        .pairing
        .as_ref()
        .ok_or_else(|| ApiError::Internal("pairing is not configured on this node".into()))
}

/// `POST /api/v1/pair/request` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairRequestBody {
    /// Human-readable client name, rendered to the owner.
    pub client_name: String,
    /// Ed25519 client public key (hex, 32 bytes).
    pub client_pubkey: String,
}

/// `POST /api/v1/pair/request` response.
///
/// Note what is **not** here: the challenge, and the short code derived from
/// it. The code is printed to the node's own stdout as a tripwire; handing it
/// to the caller would hand it to exactly the attacker the ceremony excludes.
#[derive(Debug, Serialize)]
pub struct PairRequestResponse {
    /// Ceremony id.
    pub pair_id: String,
    /// Unix seconds after which the request can no longer be confirmed.
    pub expires_at: i64,
    /// Absolute path of the `0600` challenge file the client must read.
    pub challenge_path: String,
}

async fn pair_request(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PairRequestBody>,
) -> Result<Json<PairRequestResponse>, ApiError> {
    let svc = service(&state)?;
    let outcome = svc
        .request_pairing(&body.client_name, &body.client_pubkey)
        .map_err(map_err)?;
    state.audit_log.record(
        events::AUTH_ATTEMPT,
        &state.identity.node_id().to_hex(),
        Some(serde_json::json!({"pairing": "requested", "pair_id": outcome.pair_id})),
    );
    Ok(Json(PairRequestResponse {
        challenge_path: svc
            .dir()
            .join(format!("challenge-{}", outcome.pair_id))
            .display()
            .to_string(),
        pair_id: outcome.pair_id,
        expires_at: outcome.expires_at,
    }))
}

/// `POST /api/v1/pair/confirm` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairConfirmBody {
    /// Ceremony id from `/pair/request`.
    pub pair_id: String,
    /// Hex Ed25519 signature over `pair_id || client_pubkey || challenge`.
    pub signature: String,
}

/// `POST /api/v1/pair/confirm` response.
#[derive(Debug, Serialize)]
pub struct PairConfirmResponse {
    /// The paired client id.
    pub client_id: String,
    /// Scopes the pairing carries — `read` + `receive` by default (lock A).
    pub scopes: Vec<Scope>,
}

async fn pair_confirm(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PairConfirmBody>,
) -> Result<Json<PairConfirmResponse>, ApiError> {
    let svc = service(&state)?;
    // Default scopes, and nothing negotiable about them: a client asking for
    // more would achieve nothing, because a malicious client simply would not.
    let record = svc
        .confirm_pairing(
            &body.pair_id,
            &body.signature,
            pairing::default_pairing_scopes(),
        )
        .map_err(map_err)?;
    state.audit_log.record(
        events::AUTH_TOKEN_ISSUED,
        &state.identity.node_id().to_hex(),
        Some(serde_json::json!({"pairing": "confirmed", "client_id": record.client_id})),
    );
    Ok(Json(PairConfirmResponse {
        client_id: record.client_id,
        scopes: record.scopes,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeQuery {
    client_id: String,
}

async fn pair_challenge(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ChallengeQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let challenge = service(&state)?
        .issue_token_challenge(&q.client_id)
        .map_err(map_err)?;
    Ok(Json(serde_json::json!({ "challenge": challenge })))
}

/// `POST /api/v1/pair/token` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairTokenBody {
    /// Paired client id.
    pub client_id: String,
    /// Challenge from `GET /api/v1/pair/challenge`.
    pub challenge: String,
    /// Hex Ed25519 signature over the challenge.
    pub signature: String,
}

/// `POST /api/v1/pair/token` response.
#[derive(Debug, Serialize)]
pub struct PairTokenResponse {
    /// Short-lived JWT bound to this pairing.
    pub token: String,
    /// Unix seconds of expiry.
    pub expires_at: i64,
    /// Scopes the token actually carries.
    pub scopes: Vec<Scope>,
}

/// `POST /api/v1/pair/token` — the paired replacement for `/auth/local`.
///
/// The app signs a fresh node-issued challenge with its client key. The token
/// lives minutes, not 24 hours; the durable secret is the client key.
async fn pair_token(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PairTokenBody>,
) -> Result<Json<PairTokenResponse>, ApiError> {
    let node_id = state.identity.node_id().to_hex();
    let issued = service(&state)?
        .issue_token(
            &node_id,
            &state.jwt_secret,
            &body.client_id,
            &body.challenge,
            &body.signature,
        )
        .map_err(map_err)?;
    state.audit_log.record(
        events::AUTH_TOKEN_ISSUED,
        &node_id,
        Some(serde_json::json!({"method": "paired", "client_id": body.client_id})),
    );
    Ok(Json(PairTokenResponse {
        token: issued.token,
        expires_at: issued.expires_at,
        scopes: issued.scopes,
    }))
}

/// A paired client as the owner sees it.
#[derive(Debug, Serialize)]
pub struct PairedClientView {
    /// Client id.
    pub client_id: String,
    /// Client name.
    pub name: String,
    /// Scopes the pairing carries.
    pub scopes: Vec<Scope>,
    /// Revocation epoch.
    pub epoch: u64,
    /// When it was confirmed (Unix seconds).
    pub created_at: i64,
    /// Last token issuance (Unix seconds), if any.
    pub last_seen: Option<i64>,
}

/// `GET /api/v1/pair` — list paired clients.
///
/// Behind `read`: authority the owner cannot see is authority they cannot
/// manage. Public keys are not listed — the owner manages pairings by name and
/// id, and the key adds nothing they can act on.
async fn list_pairings(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PairedClientView>>, ApiError> {
    Ok(Json(
        service(&state)?
            .list_clients()
            .into_iter()
            .map(|c| PairedClientView {
                client_id: c.client_id,
                name: c.name,
                scopes: c.scopes,
                epoch: c.epoch,
                created_at: c.created_at,
                last_seen: c.last_seen,
            })
            .collect(),
    ))
}

/// `POST /api/v1/pair/revoke` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeBody {
    /// Client to revoke.
    pub client_id: String,
    /// When true, bump the epoch and keep the pairing; otherwise delete it.
    #[serde(default)]
    pub keep_pairing: bool,
}

/// `POST /api/v1/pair/revoke` — revoke from an `admin`-holding paired client.
///
/// Also reachable offline from the CLI, because the client being revoked may be
/// the compromised one.
async fn revoke_pairing(
    _auth: ScopedAuth<Admin>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<RevokeBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let svc = service(&state)?;
    if body.keep_pairing {
        let epoch = svc.bump_epoch(&body.client_id).map_err(map_err)?;
        Ok(Json(serde_json::json!({"revoked": true, "epoch": epoch})))
    } else {
        svc.revoke(&body.client_id).map_err(map_err)?;
        Ok(Json(serde_json::json!({"revoked": true})))
    }
}

/// `POST /api/v1/pair/rotate` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateBody {
    /// Client id being rotated.
    pub client_id: String,
    /// New Ed25519 public key (hex).
    pub new_pubkey: String,
    /// Hex signature over `bitsov-pair-rotate-v1:<client_id>:<new_pubkey>` by
    /// the **old** key.
    pub signature: String,
}

/// `POST /api/v1/pair/rotate` — rotate a client key.
///
/// Unauthenticated by token on purpose: possession of the old client key is the
/// proof, and a client whose token has expired must still be able to rotate.
/// The rotation bumps the epoch, so tokens minted for the retired key die.
async fn rotate_pairing(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RotateBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rotated = service(&state)?
        .rotate_client_key(&body.client_id, &body.new_pubkey, &body.signature)
        .map_err(map_err)?;
    Ok(Json(serde_json::json!({
        "client_id": rotated.client_id,
        "epoch": rotated.epoch,
    })))
}

/// `POST /api/v1/pair/window` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowBody {
    /// How long to accept new pairings, in seconds.
    #[serde(default)]
    pub seconds: Option<u64>,
}

/// `POST /api/v1/pair/window` — open a pairing window from an `admin` client.
///
/// Without a window, pairing is accepted only while no client is paired.
/// Otherwise an attacker could sit on `/pair/request` forever waiting for a
/// moment of weakness.
async fn open_window(
    _auth: ScopedAuth<Admin>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<WindowBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let secs = body
        .seconds
        .unwrap_or(pairing::DEFAULT_PAIRING_WINDOW.as_secs())
        .min(3600);
    let until = service(&state)?.open_pairing_window(Duration::from_secs(secs));
    Ok(Json(serde_json::json!({"window_until": until})))
}

/// `POST /api/v1/pair/elevation-request` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElevationRequestBody {
    /// Scopes requested. Only `spend` is ever grantable to a pairing.
    pub scopes: Vec<Scope>,
}

/// `POST /api/v1/pair/elevation-request` response.
#[derive(Debug, Serialize)]
pub struct ElevationRequestResponse {
    /// Operation id the owner names in their typed confirmation.
    pub op_id: String,
    /// Unix seconds after which the owner can no longer confirm it.
    pub expires_at: i64,
    /// What the owner must actually run. Stated here so the app can show it
    /// instead of inventing a path of its own.
    pub owner_action: String,
}

/// `POST /api/v1/pair/elevation-request` — ask; never obtain.
///
/// Creates a pending record and **writes no authority**. The grant is written
/// only by the owner at the control socket. In the packaged sidecar deployment
/// no such socket exists, so this request can never be fulfilled there — which
/// is the operator lock, surfaced honestly rather than as an opaque failure.
async fn elevation_request(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<ElevationRequestBody>,
) -> Result<Json<ElevationRequestResponse>, ApiError> {
    let binding = auth.pairing.as_ref().ok_or_else(|| {
        ApiError::Forbidden(
            "elevation can only be requested by a paired client — pair first".into(),
        )
    })?;
    let svc = service(&state)?;
    let op = svc
        .create_elevation_request(&binding.client_id, body.scopes)
        .map_err(map_err)?;
    let owner_action = if svc.owner_control_enabled() {
        format!("konsensus grant --op {}", op.op_id)
    } else {
        "unavailable in this deployment: the node was not started in owner-run mode, so there \
         is no owner control socket. A packaged sidecar app is a read+receive client by \
         design — to spend, run the node yourself and grant over <data_dir>/control.sock."
            .to_string()
    };
    Ok(Json(ElevationRequestResponse {
        op_id: op.op_id,
        expires_at: op.expires_at,
        owner_action,
    }))
}

/// `GET /api/v1/pair/elevation/{op_id}` — read status. A read, never a write.
async fn elevation_status(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let status = service(&state)?.elevation_status(&op_id);
    Ok(Json(serde_json::json!({
        "op_id": op_id,
        "status": status,
        "owner_confirmation_required": matches!(status, ElevationStatus::Pending),
    })))
}

/// `POST /api/v1/identity/replacement-request` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementRequestBody {
    /// The recovery phrase of the identity that would replace the live one.
    ///
    /// Used **only** to derive the destination fingerprint before anything is
    /// written, and then discarded. The node never stores it. The **owner**
    /// supplies the phrase again at the control socket
    /// (`konsensus approve-replacement`), where it is re-derived and must match
    /// the fingerprint recorded here — there is no HTTP route that consumes
    /// this approval or writes identity material.
    pub mnemonic: String,
}

/// `POST /api/v1/identity/replacement-request` response.
#[derive(Debug, Serialize)]
pub struct ReplacementRequestResponse {
    /// Operation id.
    pub op_id: String,
    /// Fingerprint of the identity being replaced.
    pub current_identity_fingerprint: String,
    /// Fingerprint of the destination identity, computed from the phrase.
    pub replacement_identity_fingerprint: String,
    /// Unix seconds after which the approval can no longer be confirmed.
    pub expires_at: i64,
    /// What the owner must run.
    pub owner_action: String,
}

/// `POST /api/v1/identity/replacement-request` — request replacement of a LIVE identity.
///
/// Replacing a live identity on a possibly funded node is destructive, so it
/// stays behind a per-operation owner approval (policy lock B). This route
/// computes the destination fingerprint and records a pending approval bound to
/// five fields. It grants nothing.
async fn replacement_request(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<ReplacementRequestBody>,
) -> Result<Json<ReplacementRequestResponse>, ApiError> {
    let binding = auth.pairing.as_ref().ok_or_else(|| {
        ApiError::Forbidden("identity replacement can only be requested by a paired client".into())
    })?;
    let words = body.mnemonic.split_whitespace().count();
    if words != 12 && words != 24 {
        return Err(ApiError::BadRequest(format!(
            "mnemonic must be 12 or 24 words, got {words}"
        )));
    }
    let svc = service(&state)?;
    let current = pairing::identity_fingerprint(&state.identity.node_id().to_hex());
    let approval = svc
        .create_replacement_request(&binding.client_id, &current, &body.mnemonic)
        .map_err(map_err)?;
    let owner_action = if svc.owner_control_enabled() {
        format!("konsensus approve-replacement --op {}", approval.op_id)
    } else {
        "unavailable in this deployment: replacing a live identity requires the owner control \
         socket, which a packaged sidecar node does not have. Fresh-install restore is \
         unaffected — it runs in identity-free bootstrap, where there is nothing to destroy."
            .to_string()
    };
    Ok(Json(ReplacementRequestResponse {
        op_id: approval.op_id,
        current_identity_fingerprint: approval.current_identity_fingerprint,
        replacement_identity_fingerprint: approval.replacement_identity_fingerprint,
        expires_at: approval.expires_at,
        owner_action,
    }))
}

/// Registers the pairing routes.
///
/// Mounted only when a pairing service exists (which needs a data directory).
/// When it does not, these paths are **absent** rather than mounted and
/// failing — the same discipline the sensitive identity routes already use.
///
/// Every route here is either the ceremony, a read, or the creation of a
/// pending request. None of them writes a grant or consumes an approval.
pub fn routes(pairing_enabled: bool) -> Router<Arc<AppState>> {
    if !pairing_enabled {
        return Router::new();
    }
    Router::new()
        .route("/api/v1/pair/request", post(pair_request))
        .route("/api/v1/pair/confirm", post(pair_confirm))
        .route("/api/v1/pair/challenge", get(pair_challenge))
        .route("/api/v1/pair/token", post(pair_token))
        .route("/api/v1/pair", get(list_pairings))
        .route("/api/v1/pair/revoke", post(revoke_pairing))
        .route("/api/v1/pair/rotate", post(rotate_pairing))
        .route("/api/v1/pair/window", post(open_window))
        .route("/api/v1/pair/elevation-request", post(elevation_request))
        .route("/api/v1/pair/elevation/:op_id", get(elevation_status))
        .route(
            "/api/v1/identity/replacement-request",
            post(replacement_request),
        )
}

#[cfg(test)]
mod tests {
    /// Structural guard: this module must not register a route that writes a
    /// grant or consumes an approval. The HTTP-level test
    /// (`tests/pairing_tests.rs::http_elevation_write_paths_absent`) proves the
    /// paths 404 on the real router; this proves no future edit *adds* one
    /// under a different name, which a path-by-path test cannot.
    #[test]
    fn no_grant_or_approval_consuming_route_is_registered() {
        let src = include_str!("pairing_routes.rs");
        // Needles built from parts so this assertion's own source does not
        // self-match under `include_str!`.
        for forbidden in [
            format!("{}_elevation", "grant"),
            format!("{}_replacement", "approve"),
            format!("{}_replacement_approval", "consume"),
        ] {
            assert!(
                !src.contains(&forbidden),
                "the HTTP router must not reach `{forbidden}` — elevation is written only \
                 over the owner control socket"
            );
        }
    }
}
