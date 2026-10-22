//! Operator accepts an uncertain starter's possible cost without freeing money.
use crate::{
    auth::scoped::{Admin, ScopedAuth},
    error::ApiError,
    state::AppState,
};
use axum::{
    extract::{Path, State},
    routing::post,
    Json, Router,
};
use konsensus_storage::starter::StarterUpdate;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    resolution: String,
}
async fn resolve(
    _auth: ScopedAuth<Admin>,
    State(state): State<Arc<AppState>>,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if req.resolution != "charge" {
        return Err(ApiError::BadRequest(
            "resolution must be charge; absence of a channel is not non-dispatch proof".into(),
        ));
    }
    let out = state
        .storage
        .starter_update(StarterUpdate::ResolveUncertain { id: id.to_string() }, None)
        .await
        .map_err(|_| ApiError::Internal("starter resolution unavailable".into()))?;
    let g = out
        .grant
        .ok_or_else(|| ApiError::NotFound("starter grant".into()))?;
    if g.state != "resolved" {
        return Err(ApiError::Conflict(
            "grant must have an uncertain operation".into(),
        ));
    }
    Ok(Json(
        serde_json::json!({"request_id":g.request_id,"state":g.state,"resolution":"charge","committed_sats":g.capacity_sats,"inflight_released":true}),
    ))
}
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/api/v1/onboarding/starter-grants/:request_id/resolve",
        post(resolve),
    )
}
