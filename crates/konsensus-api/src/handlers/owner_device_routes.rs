//! Explicit tunnel-only owner-device capabilities. Never console approval.
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::header::CACHE_CONTROL,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::device_routes::{
    accept_relation_intent, binding, map_err, service, DelegationRequest, RelationIntentRequest,
    RelationIntentResponse,
};
use crate::{
    auth::{
        scoped::{Read, ScopedAuth},
        PairingBinding,
    },
    error::{refusal_response, ApiError},
    pairing::PairingRefusal,
    rate_limit::AuthenticatedNoise,
    state::AppState,
};

pub(super) fn tunnel<'a>(
    auth: &'a ScopedAuth<Read>,
    state: &AppState,
    noise: Option<Extension<AuthenticatedNoise>>,
) -> Result<&'a PairingBinding, ApiError> {
    tunnel_checked(auth, state, noise).map_err(|(error, _)| error)
}

/// Same channel check as [`tunnel`], plus the fixed refusal reason the
/// relation-intent log records. Other tunnel handlers keep the `ApiError`.
pub(super) fn tunnel_checked<'a>(
    auth: &'a ScopedAuth<Read>,
    state: &AppState,
    noise: Option<Extension<AuthenticatedNoise>>,
) -> Result<&'a PairingBinding, (ApiError, &'static str)> {
    let binding = binding(auth).map_err(|error| (error, "no_pairing"))?;
    let noise = noise
        .filter(|n| n.client_id.as_ref() == binding.client_id)
        .ok_or_else(|| {
            (
                ApiError::Forbidden("matching authenticated Noise session required".into()),
                "noise_required",
            )
        })?;
    let svc = service(state).map_err(|error| (error, "pairing_unavailable"))?;
    svc.validate_remote_authority(
        &binding.client_id,
        binding.epoch,
        &noise.binding.client_static,
        &svc.bound_fingerprint(),
    )
    .map_err(|error| {
        let refusal = PairingRefusal::from(error);
        let reason = refusal.reason;
        (map_err(refusal.error), reason)
    })?;
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
        .map_err(if svc.second_device_enrollment_enabled() {
            second_error
        } else {
            map_err
        })?;
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
    purpose: Option<String>,
}

pub(crate) async fn mint_ticket(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    noise: Option<Extension<AuthenticatedNoise>>,
    Json(body): Json<TicketRequest>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let binding = tunnel(&auth, &state, noise)?;
    if body.purpose.is_some() && !service(&state)?.second_device_enrollment_enabled() {
        return Err(ApiError::NotFound(
            "second-device enrollment disabled".into(),
        ));
    }
    let result = service(&state)?.mint_owner_ticket_with_purpose(
        &binding.client_id,
        binding.epoch,
        &body.approver_key_id,
        &body.nonce,
        &body.signature,
        body.purpose.as_deref(),
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
    let link = result.map_err(if body.purpose.is_some() {
        second_error
    } else {
        map_err
    })?;
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
        Json(if service(&state)?.second_device_enrollment_enabled() {
            json!({"pending":pending,"alerts":service(&state)?.second_device_alerts()})
        } else {
            json!({"pending":pending})
        }),
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

pub(crate) async fn second_approve(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(op): Path<String>,
    noise: Option<Extension<AuthenticatedNoise>>,
    Json(body): Json<DelegationRequest>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let binding = tunnel(&auth, &state, noise)?;
    let key = service(&state)?
        .approve_second_device(
            &binding.client_id,
            binding.epoch,
            &op,
            &body.approver_key_id,
            &body.signature,
        )
        .map_err(second_error)?;
    Ok((
        [(CACHE_CONTROL, "no-store")],
        Json(json!({"op_id":op,"key_id":key.key_id,"status":"registered"})),
    ))
}
pub(crate) async fn second_reject(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(op): Path<String>,
    noise: Option<Extension<AuthenticatedNoise>>,
    Json(body): Json<DelegationRequest>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let binding = tunnel(&auth, &state, noise)?;
    service(&state)?
        .reject_second_device(
            &binding.client_id,
            binding.epoch,
            &op,
            &body.approver_key_id,
            &body.signature,
        )
        .map_err(second_error)?;
    Ok((
        [(CACHE_CONTROL, "no-store")],
        axum::http::StatusCode::NO_CONTENT,
    ))
}
/// Remote `POST /api/v1/pair/relation-intent`. The loopback handler does not
/// require Noise; this one uses the same [`tunnel`] binding as the other
/// signed tunnel intents (ticket, delegation, owner approval).
#[allow(clippy::result_large_err)]
pub(crate) async fn relation_intent(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    noise: Option<Extension<AuthenticatedNoise>>,
    Json(body): Json<RelationIntentRequest>,
) -> Result<Json<RelationIntentResponse>, axum::response::Response> {
    let binding = tunnel_checked(&auth, &state, noise)
        .map_err(|(error, reason)| refusal_response(error, reason))?;
    accept_relation_intent(&state, binding, body).await
}

fn second_error(e: crate::pairing::PairingError) -> ApiError {
    match e {
        crate::pairing::PairingError::OwnerChannelUnavailable => ApiError::BoxLocked,
        crate::pairing::PairingError::PairingInvalid(ref reason) if reason == "contested" => {
            ApiError::PairingContested
        }
        crate::pairing::PairingError::PairingInvalid(ref reason) if reason == "no_owner_device" => {
            ApiError::Forbidden(e.to_string()).with_reason("no_owner_device")
        }
        _ => map_err(e),
    }
}
