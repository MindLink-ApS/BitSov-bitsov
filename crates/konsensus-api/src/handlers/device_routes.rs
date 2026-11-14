//! Paired device keys and signed relation intents over HTTP.
//!
//! Registration requests write no authority. The console can approve once,
//! or an enrolled owner device can sign a delegation in local-owner mode.
//! Relation intents require an enrolled device signature over exact terms.
//! A paired token alone, or a "user confirmed" flag, grants nothing.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::scoped::{Read, ScopedAuth};
use crate::auth::{EnrollmentAuth, PairingBinding};
use crate::error::{refusal_response, ApiError, RefusalReason};
use crate::pairing::{PairingError, PairingService, RelationIntent};
use crate::spend_budget::GrantView;
use crate::state::AppState;

pub(super) fn service(state: &AppState) -> Result<&Arc<PairingService>, ApiError> {
    state
        .pairing
        .as_ref()
        .ok_or_else(|| ApiError::Internal("pairing is not configured on this node".into()))
}

pub(super) fn binding(auth: &crate::auth::AuthUser) -> Result<&PairingBinding, ApiError> {
    auth.pairing.as_ref().ok_or_else(|| {
        ApiError::Forbidden("device keys belong to a paired client — pair first".into())
    })
}

/// A signature problem is a refusal of this request, not of the caller's
/// token: never a 401 that would send the app back to pairing.
pub(super) fn map_err(e: PairingError) -> ApiError {
    match e {
        PairingError::DeviceApprovalsDisabled(reason) => {
            ApiError::Forbidden(e.to_string()).with_reason(reason)
        }
        PairingError::BadProof => ApiError::Forbidden(
            "the device signature did not verify, or that intent was already used".into(),
        ),
        PairingError::Malformed(_) => ApiError::BadRequest(e.to_string()),
        PairingError::TooManyPending => ApiError::TooManyRequests(e.to_string()),
        PairingError::UnknownClient | PairingError::UnknownOperation => {
            ApiError::NotFound(e.to_string())
        }
        PairingError::Expired => ApiError::Conflict(
            "the intent's issued_at is too far from the node's clock; sign it again".into(),
        ),
        PairingError::OwnerApprovalUnavailable => ApiError::Conflict(e.to_string()),
        PairingError::Io(_) => ApiError::Internal(e.to_string()),
        _ => ApiError::Forbidden(e.to_string()),
    }
}

/// `POST /api/v1/pair/device-key` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceKeyRequest {
    /// SEC1 uncompressed P-256 public key, hex.
    pub public_key: String,
    /// Device name shown to the owner.
    pub name: String,
    /// DER signature over the registration message, hex.
    pub proof: String,
    /// Opt in to SAS v1 over an authenticated Noise connection.
    pub sas_version: Option<u8>,
}

/// `POST /api/v1/pair/device-key` response.
#[derive(Debug, Serialize)]
pub struct DeviceKeyResponse {
    /// Operation id the owner approves.
    pub op_id: String,
    /// Key id the device signs intents with.
    pub key_id: String,
    /// Short fingerprint the owner compares with the app.
    pub fingerprint: String,
    /// Unix seconds after which the owner can no longer approve it.
    pub expires_at: i64,
    /// What the owner runs, once.
    pub owner_action: String,
    /// Exact bytes to show and sign on an existing owner device in local mode.
    pub delegation_message: Option<String>,
    /// Negotiated SAS version, absent for legacy clients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sas_version: Option<u8>,
    /// Fresh nonce after the proof/key and Noise transcript are committed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub box_nonce: Option<String>,
}

pub(crate) async fn request_device_key(
    auth: EnrollmentAuth,
    State(state): State<Arc<AppState>>,
    noise: Option<axum::Extension<crate::rate_limit::AuthenticatedNoise>>,
    Json(body): Json<DeviceKeyRequest>,
) -> Result<Json<DeviceKeyResponse>, ApiError> {
    let binding = binding(&auth)?;
    let svc = service(&state)?;
    let noise = match body.sas_version {
        None => None,
        Some(1) | Some(2) => Some(
            noise
                .filter(|n| n.client_id.as_ref() == binding.client_id)
                .ok_or_else(|| ApiError::Forbidden("completed Noise transcript required".into()))?
                .binding,
        ),
        Some(_) => return Err(ApiError::BadRequest("unsupported SAS version".into())),
    };
    let op = svc
        .request_device_key_versioned(
            &binding.client_id,
            &body.public_key,
            &body.name,
            &body.proof,
            body.sas_version,
            noise,
        )
        .map_err(map_err)?;
    Ok(Json(DeviceKeyResponse {
        sas_version: op.sas_version,
        box_nonce: op.box_nonce(),
        owner_action: svc.owner_device_command(&op.op_id),
        delegation_message: (svc.local_owner_device()
            && op.sas_confirmed()
            && op.sas_version != Some(2))
        .then(|| crate::pairing::device::delegation_message(&svc.bound_fingerprint(), &op)),
        fingerprint: crate::pairing::device::key_fingerprint(&op.key_id),
        op_id: op.op_id,
        key_id: op.key_id,
        expires_at: op.expires_at,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SasFinalizeRequest {
    sas_version: u8,
    sas_digest: String,
    proof: String,
}

pub(crate) async fn finalize_device_sas(
    auth: EnrollmentAuth,
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
    noise: Option<axum::Extension<crate::rate_limit::AuthenticatedNoise>>,
    Json(body): Json<SasFinalizeRequest>,
) -> Result<axum::http::StatusCode, ApiError> {
    let binding = binding(&auth)?;
    if !matches!(body.sas_version, 1 | 2) {
        return Err(ApiError::BadRequest("unsupported SAS version".into()));
    }
    let noise = noise
        .filter(|n| n.client_id.as_ref() == binding.client_id)
        .ok_or_else(|| ApiError::Forbidden("completed Noise transcript required".into()))?;
    if service(&state)?
        .pending_device_key(&op_id)
        .map_or(body.sas_version == 2, |op| {
            op.sas_version != Some(body.sas_version)
        })
    {
        return Err(ApiError::Forbidden("SAS version mismatch".into()));
    }
    service(&state)?
        .confirm_device_sas(
            &binding.client_id,
            &op_id,
            &noise.binding,
            &body.sas_digest,
            &body.proof,
        )
        .map_err(map_err)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub(crate) async fn device_key_status(
    auth: EnrollmentAuth,
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let binding = binding(&auth)?;
    let svc = service(&state)?;
    let status = svc.device_key_status(&binding.client_id, &op_id);
    let message = svc
        .pending_device_key(&op_id)
        .filter(|op| {
            svc.local_owner_device()
                && op.sas_version != Some(2)
                && op.sas_confirmed()
                && op.client_id == binding.client_id
                && status == crate::pairing::DeviceKeyStatus::Pending
        })
        .map(|op| crate::pairing::device::delegation_message(&svc.bound_fingerprint(), &op));
    let mut view = serde_json::json!({"op_id":op_id,"status":status,"delegation_message":message});
    if svc
        .pending_device_key(&op_id)
        .is_some_and(|p| p.sas_version == Some(2))
    {
        view["approval"] = serde_json::json!("owner_device");
    }
    Ok(Json(view))
}

/// An enrolled owner's P-256 signature over the pending delegation tuple.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationRequest {
    /// Enrolled key belonging to the authenticated approver client.
    pub approver_key_id: String,
    /// P-256/SHA-256 DER signature, hex.
    pub signature: String,
}

async fn delegate_device_key(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
    Json(body): Json<DelegationRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let binding = binding(&auth)?;
    let key = service(&state)?
        .delegate_device_key(
            &binding.client_id,
            binding.epoch,
            &op_id,
            &body.approver_key_id,
            &body.signature,
        )
        .map_err(map_err)?;
    Ok(Json(
        serde_json::json!({ "op_id": op_id, "key_id": key.key_id, "status": "registered" }),
    ))
}

/// `DELETE /api/v1/pair/device-key/{op_id}` and
/// `DELETE /api/v1/pair/elevation/{op_id}`: withdraw your own pending request.
pub(crate) async fn cancel_pending(
    auth: EnrollmentAuth,
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let binding = binding(&auth)?;
    service(&state)?
        .cancel_pending(&binding.client_id, &op_id)
        .map_err(map_err)?;
    Ok(Json(
        serde_json::json!({ "op_id": op_id, "status": "cancelled" }),
    ))
}

pub(crate) async fn list_device_keys(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let binding = binding(&auth)?;
    let svc = service(&state)?;
    let keys: Vec<_> = svc
        .device_keys_for(&binding.client_id)
        .into_iter()
        .map(|k| {
            serde_json::json!({
                "key_id": k.key_id,
                "fingerprint": crate::pairing::device::key_fingerprint(&k.key_id),
                "name": k.name,
                "registered_at": k.registered_at,
            })
        })
        .collect();
    // `node`, `client_id` and `epoch` are the values a device copies into a
    // relation intent (see `pairing::device::intent_message`). Registration
    // proofs sign `node` and `client_id` only.
    Ok(Json(serde_json::json!({
        "node": svc.bound_fingerprint(),
        "client_id": binding.client_id,
        "epoch": binding.epoch,
        "owner_control": svc.owner_control_enabled(),
        "local_owner_device": svc.local_owner_device(),
        "owner_device_count": svc.owner_device_count(),
        // "enabled", or the reason code device approvals are off node-wide.
        "device_approvals": svc.device_authority_off().unwrap_or("enabled"),
        "device_keys": keys,
    })))
}

/// `DELETE /api/v1/pair/device-keys/{key_id}`: a client retires its own key
/// (a lost or wiped device). Its relation envelopes end with it.
async fn revoke_own_device_key(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(key_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let binding = binding(&auth)?;
    service(&state)?
        .revoke_device_key(&key_id, Some(&binding.client_id))
        .map_err(map_err)?;
    Ok(Json(
        serde_json::json!({ "key_id": key_id, "status": "revoked" }),
    ))
}

/// `POST /api/v1/pair/relation-intent` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationIntentRequest {
    /// The signed terms.
    pub intent: RelationIntent,
    /// DER signature over the canonical intent bytes, hex.
    pub signature: String,
}

// The error is the finished HTTP response, refusal extension included.
// Other handlers return `ApiError`; this one cannot, and axum moves it once.
#[allow(clippy::result_large_err)]
pub(super) async fn accept_relation_intent(
    state: &AppState,
    binding: &PairingBinding,
    body: RelationIntentRequest,
) -> Result<Json<RelationIntentResponse>, axum::response::Response> {
    let accepted = service(state)
        .map_err(|e| refusal_response(e, "pairing_unavailable"))?
        .apply_relation_intent_with_reason(
            &binding.client_id,
            binding.epoch,
            &body.intent,
            &body.signature,
        )
        .map_err(|refusal| refusal_response(map_err(refusal.error), refusal.reason))?;
    Ok(Json(RelationIntentResponse {
        envelope_id: accepted.envelope_id,
        grant: accepted.grant,
    }))
}

// The error is the finished HTTP response, refusal extension included.
// Other handlers return `ApiError`; this one cannot, and axum moves it once.
#[allow(clippy::result_large_err)]
pub(crate) async fn relation_intent(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<RelationIntentRequest>,
) -> Result<Json<RelationIntentResponse>, axum::response::Response> {
    let binding = binding(&auth).map_err(|e| refusal_response(e, "no_pairing"))?;
    accept_relation_intent(&state, binding, body).await
}

/// Wrap the router's filters too, so extractor and provisional-session refusals
/// are visible at info level. Never inspect or log either body or the query.
pub(crate) async fn log_relation_intent_refusal(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    const PATH: &str = "/api/v1/pair/relation-intent";
    let relation_intent = req.uri().path() == PATH;
    let response = next.run(req).await;
    if relation_intent {
        let reason = response
            .extensions()
            .get::<RefusalReason>()
            .map(|r| r.0)
            .unwrap_or_else(|| match response.status().as_u16() {
                400 | 413 | 415 | 422 => "malformed",
                401 => "unauthorized",
                403 => "forbidden",
                404 => "not_found",
                405 => "method_not_allowed",
                429 => "rate_limited",
                _ => "internal_error",
            });
        log_relation_intent_status(PATH, response.status(), reason);
    }
    response
}

/// Also used by the outer tunnel-identity filter, which can reject before the
/// router runs. Callers must supply only fixed, non-secret reason codes.
pub(crate) fn log_relation_intent_status(
    path: &str,
    status: axum::http::StatusCode,
    reason: &'static str,
) {
    const PATH: &str = "/api/v1/pair/relation-intent";
    if path == PATH && !status.is_success() {
        // This endpoint's ApiError code is the numeric HTTP status; use the
        // same code for middleware/extractor responses that have no JSON code.
        let code = status.as_u16();
        tracing::info!(
            path = PATH,
            status = code,
            code,
            reason,
            "relation intent refused"
        );
    }
}

/// `POST /api/v1/pair/relation-intent` response: the client's relation grant.
#[derive(Debug, Serialize)]
pub struct RelationIntentResponse {
    /// Identity of this accepted approval, independent of the aggregate grant.
    pub envelope_id: String,
    /// The grant as `GET /api/v1/pair/grant` reports it.
    pub grant: GrantView,
}

/// Mounted only where pairing is (see [`super::pairing_routes::routes`]).
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/pair/device-key", post(request_device_key))
        .route(
            "/api/v1/pair/device-key/:op_id",
            get(device_key_status).delete(cancel_pending),
        )
        .route(
            "/api/v1/pair/device-key/:op_id/delegate",
            post(delegate_device_key),
        )
        .route("/api/v1/pair/device-keys", get(list_device_keys))
        .route(
            "/api/v1/pair/device-keys/:key_id",
            delete(revoke_own_device_key),
        )
        .route("/api/v1/pair/relation-intent", post(relation_intent))
}

/// `DELETE` on the elevation status path (merged there so the path has one
/// router entry).
pub(crate) async fn cancel_elevation(
    auth: ScopedAuth<Read>,
    state: State<Arc<AppState>>,
    op_id: Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    cancel_pending(EnrollmentAuth(auth.user), state, op_id).await
}

#[cfg(test)]
mod tests {
    /// The owner's approval of a device key is reachable only over the
    /// control socket: this router must never call it.
    #[test]
    fn no_owner_approval_is_reachable_from_http() {
        let src = include_str!("device_routes.rs");
        for forbidden in [
            format!("{}_device_key", "approve"),
            format!("{}_elevation", "grant"),
            format!("{}_front_door", "grant"),
        ] {
            assert!(
                !src.contains(&forbidden),
                "HTTP must not reach `{forbidden}`"
            );
        }
    }
}
