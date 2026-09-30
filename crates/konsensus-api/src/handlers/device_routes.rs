//! Paired device keys and signed relation intents over HTTP.
//!
//! Registration here only **requests**: the key is registered by the owner
//! at the control socket (`konsensus device approve`), once. After that,
//! `POST /api/v1/pair/relation-intent` is the one HTTP path that writes spend
//! authority, and only with a registered device key's signature over the
//! exact terms (see [`crate::pairing::device`]). A paired token alone, or a
//! token plus a "user confirmed" flag, writes nothing.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::scoped::{Read, ScopedAuth};
use crate::auth::PairingBinding;
use crate::error::ApiError;
use crate::pairing::{PairingError, PairingService, RelationIntent};
use crate::spend_budget::GrantView;
use crate::state::AppState;

fn service(state: &AppState) -> Result<&Arc<PairingService>, ApiError> {
    state
        .pairing
        .as_ref()
        .ok_or_else(|| ApiError::Internal("pairing is not configured on this node".into()))
}

fn binding(auth: &ScopedAuth<Read>) -> Result<&PairingBinding, ApiError> {
    auth.pairing
        .as_ref()
        .ok_or_else(|| ApiError::Forbidden("device keys belong to a paired client — pair first".into()))
}

/// A signature problem is a refusal of this request, not of the caller's
/// token: never a 401 that would send the app back to pairing.
fn map_err(e: PairingError) -> ApiError {
    match e {
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
}

async fn request_device_key(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<DeviceKeyRequest>,
) -> Result<Json<DeviceKeyResponse>, ApiError> {
    let binding = binding(&auth)?;
    let svc = service(&state)?;
    let op = svc
        .request_device_key(&binding.client_id, &body.public_key, &body.name, &body.proof)
        .map_err(map_err)?;
    Ok(Json(DeviceKeyResponse {
        owner_action: svc.owner_device_command(&op.op_id),
        fingerprint: crate::pairing::device::key_fingerprint(&op.key_id),
        op_id: op.op_id,
        key_id: op.key_id,
        expires_at: op.expires_at,
    }))
}

async fn device_key_status(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let binding = binding(&auth)?;
    let status = service(&state)?.device_key_status(&binding.client_id, &op_id);
    Ok(Json(serde_json::json!({ "op_id": op_id, "status": status })))
}

/// `DELETE /api/v1/pair/device-key/{op_id}` and
/// `DELETE /api/v1/pair/elevation/{op_id}`: withdraw your own pending request.
async fn cancel_pending(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let binding = binding(&auth)?;
    service(&state)?
        .cancel_pending(&binding.client_id, &op_id)
        .map_err(map_err)?;
    Ok(Json(serde_json::json!({ "op_id": op_id, "status": "cancelled" })))
}

async fn list_device_keys(
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
    // `node` and `client_id` are the two values a device signs into every
    // registration proof and intent (see `pairing::device::intent_message`).
    Ok(Json(serde_json::json!({
        "node": svc.bound_fingerprint(),
        "client_id": binding.client_id,
        "owner_control": svc.owner_control_enabled(),
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
    Ok(Json(serde_json::json!({ "key_id": key_id, "status": "revoked" })))
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

async fn relation_intent(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<RelationIntentRequest>,
) -> Result<Json<RelationIntentResponse>, ApiError> {
    let binding = binding(&auth)?;
    let grant = service(&state)?
        .apply_relation_intent(&binding.client_id, binding.epoch, &body.intent, &body.signature)
        .map_err(map_err)?;
    Ok(Json(RelationIntentResponse { grant }))
}

/// `POST /api/v1/pair/relation-intent` response: the client's relation grant.
#[derive(Debug, Serialize)]
pub struct RelationIntentResponse {
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
        .route("/api/v1/pair/device-keys", get(list_device_keys))
        .route("/api/v1/pair/device-keys/:key_id", delete(revoke_own_device_key))
        .route("/api/v1/pair/relation-intent", post(relation_intent))
}

/// `DELETE` on the elevation status path (merged there so the path has one
/// router entry).
pub(crate) async fn cancel_elevation(
    auth: ScopedAuth<Read>,
    state: State<Arc<AppState>>,
    op_id: Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    cancel_pending(auth, state, op_id).await
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
            assert!(!src.contains(&forbidden), "HTTP must not reach `{forbidden}`");
        }
    }
}
