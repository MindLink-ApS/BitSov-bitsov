//! Explicit tunnel-only owner-device capabilities. Never console approval.
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::header::CACHE_CONTROL,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::device_routes::{binding, map_err, service, DelegationRequest};
use crate::{
    auth::{
        scoped::{Read, ScopedAuth},
        PairingBinding,
    },
    error::ApiError,
    rate_limit::AuthenticatedNoise,
    state::AppState,
};

fn tunnel<'a>(
    auth: &'a ScopedAuth<Read>,
    state: &AppState,
    noise: Option<Extension<AuthenticatedNoise>>,
) -> Result<&'a PairingBinding, ApiError> {
    let binding = binding(auth)?;
    let noise = noise
        .filter(|n| n.client_id.as_ref() == binding.client_id)
        .ok_or_else(|| {
            ApiError::Forbidden("matching authenticated Noise session required".into())
        })?;
    let svc = service(state)?;
    svc.validate_remote_authority(
        &binding.client_id,
        binding.epoch,
        &noise.binding.client_static,
        &svc.bound_fingerprint(),
    )
    .map_err(map_err)?;
    Ok(binding)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerQuery {
    approver_key_id: String,
}

pub(crate) async fn ticket_challenge(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    noise: Option<Extension<AuthenticatedNoise>>,
    Query(query): Query<OwnerQuery>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let binding = tunnel(&auth, &state, noise)?;
    let svc = service(&state)?;
    let nonce = svc
        .owner_ticket_challenge(&binding.client_id, binding.epoch, &query.approver_key_id)
        .map_err(map_err)?;
    Ok((
        [(CACHE_CONTROL, "no-store")],
        Json(json!({
            "message": format!("bitsov-ticket-v1\nnode:{}\nnonce:{nonce}", svc.bound_fingerprint()),
            "nonce": nonce,
        })),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TicketRequest {
    approver_key_id: String,
    nonce: String,
    signature: String,
}

pub(crate) async fn mint_ticket(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    noise: Option<Extension<AuthenticatedNoise>>,
    Json(body): Json<TicketRequest>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let binding = tunnel(&auth, &state, noise)?;
    let result = service(&state)?.mint_owner_ticket(
        &binding.client_id,
        binding.epoch,
        &body.approver_key_id,
        &body.nonce,
        &body.signature,
    );
    state.audit_log.record(
        if result.is_ok() {
            "pair.ticket_issued"
        } else {
            "pair.ticket_refused"
        },
        &binding.client_id,
        Some(json!({"key_id": body.approver_key_id, "epoch": binding.epoch})),
    );
    let link = result.map_err(map_err)?;
    let uri = link
        .to_uri()
        .map_err(|_| ApiError::Internal("ticket encoding failed".into()))?;
    Ok((
        [(CACHE_CONTROL, "no-store")],
        Json(json!({"uri":uri, "expires_at":link.expires_at})),
    ))
}

pub(crate) async fn pending_devices(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    noise: Option<Extension<AuthenticatedNoise>>,
    Query(query): Query<OwnerQuery>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let binding = tunnel(&auth, &state, noise)?;
    let pending = service(&state)?
        .owner_pending_devices(&binding.client_id, binding.epoch, &query.approver_key_id)
        .map_err(map_err)?;
    Ok((
        [(CACHE_CONTROL, "no-store")],
        Json(json!({"pending":pending})),
    ))
}

pub(crate) async fn pending_device(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(op): Path<String>,
    noise: Option<Extension<AuthenticatedNoise>>,
    Query(query): Query<OwnerQuery>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let binding = tunnel(&auth, &state, noise)?;
    let view = service(&state)?
        .owner_pending_device(
            &binding.client_id,
            binding.epoch,
            &query.approver_key_id,
            &op,
        )
        .map_err(map_err)?;
    Ok(([(CACHE_CONTROL, "no-store")], Json(view)))
}

pub(crate) async fn delegate(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(op): Path<String>,
    noise: Option<Extension<AuthenticatedNoise>>,
    Json(body): Json<DelegationRequest>,
) -> Result<Json<Value>, ApiError> {
    let binding = tunnel(&auth, &state, noise)?;
    let result = service(&state)?.delegate_device_key_over_tunnel(
        &binding.client_id,
        binding.epoch,
        &op,
        &body.approver_key_id,
        &body.signature,
    );
    state.audit_log.record(
        if result.is_ok() {
            "pair.device_delegated"
        } else {
            "pair.device_delegation_refused"
        },
        &binding.client_id,
        Some(json!({"key_id":body.approver_key_id, "op_id":op, "epoch":binding.epoch})),
    );
    let key = result.map_err(map_err)?;
    Ok(Json(
        json!({"op_id":op,"key_id":key.key_id,"status":"registered"}),
    ))
}
