//! Owner-requested inbound liquidity. The API never connects or sends before a
//! durable operation exists; the worker owns all subsequent network activity.
use crate::{
    auth::scoped::{Read, Receive, ScopedAuth},
    error::ApiError,
    state::AppState,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use konsensus_core::NodeId;
use konsensus_storage::starter_request::StarterRequest;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StarterConfig {
    pub enabled: bool,
    pub hub_node_id: String,
    /// Operator-configured display name only; never used for routing.
    pub hub_alias: Option<String>,
    pub allow_mainnet: bool,
}
impl StarterConfig {
    pub fn validate(&self, network: Option<&str>, ldk: bool) -> Result<(), String> {
        if self.allow_mainnet {
            return Err("starter_mainnet_not_approved".into());
        }
        if self.enabled && (!ldk || !matches!(network, Some("signet" | "regtest"))) {
            return Err("starter_network_not_allowed".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default)]
pub struct StarterSettings {
    pub config: StarterConfig,
    pub network: String,
    pub hub_ln_pubkey: String,
    pub hub_ln_address: String,
    pub hub_whitelisted: bool,
    pub trust_no_reserve: bool,
}
impl StarterSettings {
    /// Local configuration only: no network, wallet or readiness query.
    pub fn hub_configured(&self) -> bool {
        self.config.enabled
            && NodeId::from_hex(&self.config.hub_node_id).is_ok()
            && self.hub_whitelisted
            && self.hub_ln_pubkey.len() == 66
            && hex::decode(&self.hub_ln_pubkey).is_ok()
            && !self.hub_ln_address.is_empty()
    }
    fn discovery(&self, value: &mut serde_json::Value) {
        let configured = self.hub_configured();
        value["hub_configured"] = serde_json::json!(configured);
        if let Some(alias) = self
            .config
            .hub_alias
            .as_deref()
            .filter(|a| configured && !a.is_empty())
        {
            value["hub_alias"] = serde_json::json!(alias);
        }
    }

    pub fn precondition(&self, provider_network: Option<&str>) -> Option<&'static str> {
        if !self.config.enabled {
            return Some("starter_disabled");
        }
        if self.config.allow_mainnet
            || !matches!(self.network.as_str(), "signet" | "regtest")
            || provider_network != Some(self.network.as_str())
        {
            return Some("network_not_allowed");
        }
        if NodeId::from_hex(&self.config.hub_node_id).is_err()
            || !self.hub_whitelisted
            || self.hub_ln_pubkey.len() != 66
            || self.hub_ln_address.is_empty()
        {
            return Some("hub_not_configured");
        }
        if !self.trust_no_reserve {
            return Some("trust_no_reserve_required");
        }
        None
    }
    pub fn matches(&self, r: &StarterRequest) -> bool {
        self.config.hub_node_id == r.hub_node_id
            && self.hub_ln_pubkey == r.hub_ln_pubkey
            && self.network == r.network
    }
}
// Receive-only allowlist: adding cost, fee, amount or push inputs here would
// permit a spend without spend authorization. Reject them, including on replay.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    request_id: String,
}
fn error(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(serde_json::json!({"error":code,"code":code,"retry_allowed":false})),
    )
        .into_response()
}
fn not_dispatched(reason: &str) -> Response {
    (StatusCode::BAD_REQUEST,Json(serde_json::json!({"error":"not dispatched","code":"not_dispatched","reason":reason,"retry_allowed":true}))).into_response()
}
fn render(settings: &StarterSettings, r: StarterRequest, id: &str, status: StatusCode) -> Response {
    let mut value = serde_json::to_value(&r).expect("serializable request");
    settings.discovery(&mut value);
    value["operation_id"] = serde_json::json!(r.request_id);
    value["request_id"] = serde_json::json!(id);
    value["verified"] = serde_json::json!(r.state == "ready" && r.verified_at.is_some());
    (status, Json(value)).into_response()
}
async fn follow(state: &AppState, r: StarterRequest) -> Result<StarterRequest, ApiError> {
    if let Some(current) = state
        .storage
        .starter_request_current()
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?
    {
        if current.root_id() == r.root_id()
            || r.original_request_id.as_deref() == Some(&current.request_id)
        {
            return Ok(current);
        }
    }
    Ok(r)
}
async fn create(
    auth: ScopedAuth<Receive>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<Request>,
) -> Result<Response, ApiError> {
    if auth.pairing.is_none() {
        return Ok(error(StatusCode::FORBIDDEN, "paired_session_required"));
    }
    let id = match req.request_id.parse::<Uuid>() {
        Ok(id) if id.get_version_num() == 4 => id.to_string(),
        _ => return Ok(error(StatusCode::BAD_REQUEST, "invalid_request_id")),
    };
    // A persisted request is never described as not dispatched, including when
    // disabled/offline after a restart. The immutable config binding still holds.
    if let Some(r) = state
        .storage
        .starter_request_get(&id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?
    {
        if !state.starter.matches(&r) {
            return Ok(error(StatusCode::CONFLICT, "operation_mismatch"));
        }
        let current = follow(&state, r).await?;
        state
            .storage
            .starter_request_rearm(&current.request_id)
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))?;
        let current = state
            .storage
            .starter_request_get(&current.request_id)
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))?
            .expect("existing request");
        return Ok(render(&state.starter, current, &id, StatusCode::OK));
    }
    if let Some(reason) = state
        .starter
        .precondition(state.lightning.starter_network().as_deref())
    {
        return Ok(not_dispatched(reason));
    }
    if !state.lightning.money_ready().await {
        return Ok(not_dispatched("money_not_ready"));
    }
    let hub = NodeId::from_hex(&state.starter.config.hub_node_id).expect("checked hub");
    if state.transport.peer_info(&hub).await.is_some_and(|p| {
        !p.capabilities
            .iter()
            .any(|c| c == "Custom(\"starter_hub_v1\")")
    }) {
        return Ok(not_dispatched("hub_unsupported"));
    }
    if state.lightning.disk_status().is_some_and(|d| d.disk_low) {
        return Err(ApiError::NotDispatched("disk_low".into()));
    }
    state
        .audit_log
        .starter_requested(
            &id,
            &auth.pairing.as_ref().expect("checked pairing").client_id,
        )
        .map_err(|e| ApiError::Storage(format!("starter audit: {e}")))?;
    let row = StarterRequest::new(
        id.clone(),
        state.starter.config.hub_node_id.clone(),
        state.starter.hub_ln_pubkey.clone(),
        state.starter.network.clone(),
        chrono::Utc::now().timestamp(),
    );
    let (stored, created) = state
        .storage
        .starter_request_create(&row)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;
    if stored.request_id != id {
        state.audit_log.record("starter.request_conflict", &auth.pairing.as_ref().expect("checked pairing").client_id,
            Some(serde_json::json!({"request_id":id,"paired_device_id":auth.pairing.as_ref().expect("checked pairing").client_id,"reason":"starter_already_requested"})));
        return Ok((StatusCode::CONFLICT,Json(serde_json::json!({"error":"starter_already_requested","code":"starter_already_requested","request_id":stored.root_id(),"state":stored.state,"retry_allowed":false}))).into_response());
    }
    Ok(render(
        &state.starter,
        stored,
        &id,
        if created {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        },
    ))
}
async fn status(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let id = id.to_string();
    let row = state
        .storage
        .starter_request_get(&id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound("starter request".into()))?;
    Ok(render(
        &state.starter,
        follow(&state, row).await?,
        &id,
        StatusCode::OK,
    ))
}
async fn current(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Result<Response, ApiError> {
    let row = state
        .storage
        .starter_request_current()
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;
    let Some(row) = row else {
        let mut value = serde_json::json!({"state":"not_requested"});
        state.starter.discovery(&mut value);
        return Ok((StatusCode::OK, Json(value)).into_response());
    };
    let id = row.root_id().to_owned();
    Ok(render(&state.starter, row, &id, StatusCode::OK))
}
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/onboarding/starter-channel",
            get(current).post(create),
        )
        .route(
            "/api/v1/onboarding/starter-channel/:request_id",
            get(status),
        )
}
