//! Pairing endpoints on the live router (#76).
//!
//! # What is deliberately absent
//!
//! Budget elevation is not writable over HTTP (a registered device key's
//! signed relation intent is the one exception; see
//! [`super::device_routes`]). First-contact approval is an
//! owner-authenticated exception bound to an already approved budget; paired
//! tokens cannot invoke it. The app
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
use zeroize::Zeroizing;

use serde::{Deserialize, Serialize};

use crate::audit::events;
use crate::auth::scoped::{Admin, Read, ScopedAuth, Spend};
use crate::auth::Scope;
use crate::error::ApiError;
use crate::pairing::{self, ElevationStatus, PairingError, PairingService};
use crate::spend_budget::GrantTerms;
use crate::state::AppState;

/// Map a pairing failure onto the API's error type.
///
/// Every mapping is a refusal. None of them degrade a caller to a weaker
/// success — a failure here means the operation did not happen.
fn map_err(e: PairingError) -> ApiError {
    match e {
        PairingError::Closed | PairingError::OwnerApprovalUnavailable => {
            ApiError::Conflict(e.to_string())
        }
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
/// it. The code is derived only from the protected challenge file and is never
/// printed or logged.
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
    /// Scopes requested. Only `spend`, or `front_door` on its own (no budget),
    /// is ever grantable to a pairing.
    pub scopes: Vec<Scope>,
    /// The budget window the client proposes (G1). A suggestion rendered to
    /// the owner, who sets the actual terms at the control socket.
    #[serde(default)]
    pub budget: Option<BudgetProposal>,
}

/// A proposed budget window, in millisatoshis like every other money field.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetProposal {
    /// Proposal only: the owner must explicitly approve this at the control socket.
    #[serde(default)]
    pub allow_liquidity_fees: bool,
    /// Total for the window.
    pub budget_msat: u64,
    /// Most one call may spend. Defaults to the whole budget.
    #[serde(default)]
    pub per_call_max_msat: Option<u64>,
    /// Per-recipient budgets (node id or Lightning pubkey, hex).
    #[serde(default)]
    pub per_recipient_msat: std::collections::BTreeMap<String, u64>,
    /// Window length in seconds. Defaults to, and may not exceed, 24 h.
    #[serde(default)]
    pub ttl_secs: Option<i64>,
}

impl BudgetProposal {
    fn into_terms(self) -> GrantTerms {
        let mut terms = GrantTerms::new(self.budget_msat);
        if let Some(max) = self.per_call_max_msat {
            terms = terms.per_call(max);
        }
        if let Some(ttl) = self.ttl_secs {
            terms = terms.for_secs(ttl);
        }
        terms.allow_liquidity_fees = self.allow_liquidity_fees;
        terms.per_recipient_msat = self.per_recipient_msat;
        terms
    }
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
        .create_budget_elevation_request(
            &binding.client_id,
            body.scopes,
            body.budget.map(BudgetProposal::into_terms),
        )
        .map_err(map_err)?;
    let owner_action = if svc.owner_control_enabled() {
        svc.owner_grant_command(&op.op_id)
    } else {
        "unavailable in this deployment: the node was not started in owner-run mode, so there \
         is no owner control socket. A packaged sidecar app is a read+receive client by \
         design — to spend or publish a front door, run the node yourself and grant over \
         <data_dir>/control.sock."
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
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let binding = auth.pairing.as_ref().ok_or_else(|| {
        ApiError::Forbidden("only a paired client can read an elevation request".into())
    })?;
    let status = service(&state)?.elevation_status(&binding.client_id, &op_id).map_err(map_err)?;
    Ok(Json(serde_json::json!({
        "op_id": op_id,
        "status": status,
        "owner_confirmation_required": matches!(status, ElevationStatus::Pending),
    })))
}

/// `GET /api/v1/pair/grant` — the caller's own live budget grant (G1).
///
/// A read, never a write: what is left, the per-call maximum, per-recipient
/// budgets and the absolute expiry. `{"grant": null}` when there is none —
/// never granted, spent-and-expired, revoked, or a sidecar deployment.
async fn own_grant(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let binding = auth.pairing.as_ref().ok_or_else(|| {
        ApiError::Forbidden("only a paired client holds a budget grant".into())
    })?;
    let grant = service(&state)?.grant_view_for(&binding.client_id);
    Ok(Json(serde_json::json!({ "grant": grant })))
}

/// `POST /api/v1/pair/first-contact-grant` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstContactGrantBody {
    /// Paired client for whom the owner approves this contact.
    pub client_id: String,
    /// Exact live budget grant the owner reviewed; replacement invalidates approval.
    pub grant_op_id: String,
    /// The new contact's node id (64 hex).
    pub recipient: String,
    /// The most the first contact may cost: admission plus the first message,
    /// msat, as the owner confirmed it (the target's quote).
    pub max_total_msat: u64,
    /// The contact's budget the owner chose with this confirmation, msat. If
    /// the grant has no cap for this contact yet, it becomes one, so a later
    /// re-admission after a reconnect is paid from the budget without asking.
    #[serde(default)]
    pub contact_budget_msat: Option<u64>,
}

/// `POST /api/v1/pair/first-contact-grant` — owner-authenticated approval for
/// a specific paired client and live budget, to contact this recipient for this
/// amount. Needs a live budget grant and fits inside it; single use; expires
/// after five minutes; memory only. The send then debits the budget grant once.
/// A first contact without one is refused (`budget_exceeded`, reason
/// `first_contact`). See `docs/SPEND_BUDGET_GRANTS.md`.
async fn first_contact_grant(
    auth: ScopedAuth<Spend>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<FirstContactGrantBody>,
) -> Result<Json<crate::spend_budget::FirstContactGrant>, ApiError> {
    // ScopedAuth<Spend> rejects every paired token. Only the independent
    // owner's credential can issue this approval; spend delegation cannot mint it.
    let grant = service(&state)?.grant_first_contact(
        &body.client_id,
        &body.grant_op_id,
        &body.recipient,
        body.max_total_msat,
        body.contact_budget_msat,
    ).map_err(ApiError::BudgetExceeded)?;
    state.audit_log.record(
        events::SPEND_FIRST_CONTACT_GRANTED,
        &auth.node_id,
        Some(serde_json::json!({
            "client_id": body.client_id,
            "grant_op_id": body.grant_op_id,
            "recipient": grant.recipient,
            "max_total_msat": grant.max_total_msat,
            "contact_budget_msat": body.contact_budget_msat,
            "expires_at": grant.expires_at,
        })),
    );
    Ok(Json(grant))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FirstContactStatusQuery {
    recipient: String,
}

/// `GET /api/v1/pair/first-contact-grant/:op_id?recipient=<node-id>`.
/// Paired read authority only, scoped to that client's exact live budget op.
/// No local receipt or owner secret crosses HTTP. This is an observation, not
/// authorization: compose still consumes and checks the node-held approval.
async fn first_contact_status(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
    Query(query): Query<FirstContactStatusQuery>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let binding = auth.pairing.as_ref().ok_or_else(||
        ApiError::Forbidden("only a paired client can read its first-contact approval".into()))?;
    let recipient = konsensus_core::NodeId::from_hex(&query.recipient)
        .map_err(|_| ApiError::BadRequest("invalid recipient node id".into()))?;
    let status = service(&state)?.first_contact_approval_status(
        &binding.client_id, binding.epoch, &op_id, &recipient.to_hex(),
    ).ok_or_else(|| ApiError::NotFound("no live budget operation".into()))?;
    Ok(([(axum::http::header::CACHE_CONTROL, "no-store")], Json(status)))
}

/// `POST /api/v1/identity/replacement-request` body.
#[derive(Deserialize)]
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
    pub mnemonic: Zeroizing<String>,
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
/// Every route here is either the ceremony, a read, the creation or
/// withdrawal of a pending request, or (merged from
/// [`super::device_routes`]) a relation intent that writes spend authority
/// only under a registered device key's signature. None of them writes an
/// owner console grant or consumes an owner approval.
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
        .route(
            "/api/v1/pair/elevation/:op_id",
            get(elevation_status).delete(super::device_routes::cancel_elevation),
        )
        .route("/api/v1/pair/grant", get(own_grant))
        .route("/api/v1/pair/first-contact-grant", post(first_contact_grant))
        .route("/api/v1/pair/first-contact-grant/:op_id", get(first_contact_status))
        .route(
            "/api/v1/identity/replacement-request",
            post(replacement_request),
        )
        .merge(super::device_routes::routes())
}

/// Pairing routes needed by a client that has already authenticated its Noise
/// transport. The remote listener performs first pairing itself, so the
/// file-challenge ceremony and owner-management routes are not exposed here.
pub fn remote_routes(pairing_enabled: bool) -> Router<Arc<AppState>> {
    if !pairing_enabled {
        return Router::new();
    }
    Router::new()
        .route("/api/v1/pair/challenge", get(pair_challenge))
        .route("/api/v1/pair/token", post(pair_token))
        .route("/api/v1/pair/rotate", post(rotate_pairing))
        .route("/api/v1/pair/elevation-request", post(elevation_request))
        .route(
            "/api/v1/pair/elevation/:op_id",
            get(elevation_status).delete(super::device_routes::cancel_elevation),
        )
        .route("/api/v1/pair/grant", get(own_grant))
        .route("/api/v1/pair/first-contact-grant/:op_id", get(first_contact_status))
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
            format!("{}_device_key", "approve"),
        ] {
            assert!(
                !src.contains(&forbidden),
                "the HTTP router must not reach `{forbidden}` — elevation is written only \
                 over the owner control socket"
            );
        }
    }
}
