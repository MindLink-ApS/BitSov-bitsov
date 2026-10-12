//! Proposal-only paired requests and explicit tunnel-only owner approval.
use super::{
    device_routes::{binding, map_err, service},
    owner_device_routes::tunnel,
};
use crate::{
    auth::scoped::{Read, ScopedAuth},
    error::ApiError,
    pairing::approval::{ApprovalError, ApprovalRequest},
    rate_limit::AuthenticatedNoise,
    state::AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::header::CACHE_CONTROL,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub(super) fn request_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/pair/approval-request", post(request))
        .route("/api/v1/pair/approval/:op_id", get(status))
}
pub(crate) async fn request(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<ApprovalRequest>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let binding = binding(&auth)?;
    let view = service(&state)?
        .request_owner_approval(&binding.client_id, binding.epoch, body)
        .map_err(map_err)?;
    Ok(([(CACHE_CONTROL, "no-store")], Json(view)))
}
pub(crate) async fn status(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(op): Path<String>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let binding = binding(&auth)?;
    let view = service(&state)?
        .owner_approval_status(&binding.client_id, binding.epoch, &op)
        .map_err(map_err)?;
    Ok(([(CACHE_CONTROL, "no-store")], Json(view)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerQuery {
    approver_key_id: String,
}
pub(crate) async fn pending(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    noise: Option<Extension<AuthenticatedNoise>>,
    Query(query): Query<OwnerQuery>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let binding = tunnel(&auth, &state, noise)?;
    let views = service(&state)?
        .owner_pending_approvals(&binding.client_id, binding.epoch, &query.approver_key_id)
        .map_err(map_err)?;
    Ok((
        [(CACHE_CONTROL, "no-store")],
        Json(json!({"pending":views})),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Approval {
    approver_key_id: String,
    signature: String,
}
pub(crate) async fn approve(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(op): Path<String>,
    noise: Option<Extension<AuthenticatedNoise>>,
    Json(body): Json<Approval>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    // Include transport failures in refusal audits. Never log submitted signatures.
    let result = (|| {
        let binding = tunnel(&auth, &state, noise)?;
        service(&state)?
            .approve_owner_request(
                &binding.client_id,
                binding.epoch,
                &op,
                &body.approver_key_id,
                &body.signature,
            )
            .map_err(|e| match e {
                ApprovalError::Pairing(e) => map_err(e),
                ApprovalError::Budget(e) => ApiError::BudgetExceeded(e),
            })
    })();
    let client = auth
        .pairing
        .as_ref()
        .map_or("unpaired", |b| b.client_id.as_str());
    let kind = service(&state)?.approval_kind_for_audit(&op);
    // Bound untrusted audit strings even on malformed key/op identifiers.
    state.audit_log.record(if result.is_ok(){"pair.owner_approved"}else{"pair.owner_approval_refused"},client,Some(json!({"key_id":body.approver_key_id.chars().take(64).collect::<String>(),"op_id":op.chars().take(64).collect::<String>(),"kind":kind})));
    Ok(([(CACHE_CONTROL, "no-store")], Json(result?)))
}
