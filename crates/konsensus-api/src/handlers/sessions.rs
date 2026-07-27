//! Session endpoints — E2EE session management (X3DH + Double Ratchet).
//!
//! These endpoints manage the lifecycle of encrypted sessions with peers.
//! Sessions must be established before messages can be composed via the
//! compose endpoint.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::info;

use konsensus_core::types::NodeId;
use konsensus_crypto::{SerializablePrekeyBundle, SerializableSessionInit};

use crate::audit::events;
use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

/// Response with our prekey bundle for X3DH key exchange.
#[derive(Serialize)]
pub struct PrekeyBundleResponse {
    /// The node's prekey bundle (identity key, signed prekey, one-time prekeys).
    pub bundle: SerializablePrekeyBundle,
}

/// Request to initiate an E2EE session with a peer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitiateSessionRequest {
    /// The peer's prekey bundle (received via wire protocol or API).
    pub peer_bundle: SerializablePrekeyBundle,
}

/// Response after initiating a session.
#[derive(Serialize)]
pub struct InitiateSessionResponse {
    /// Session init data to send to the peer.
    pub init_data: SerializableSessionInit,
    /// Whether the session was successfully established on our side.
    pub established: bool,
}

/// Request to accept a session initiated by a peer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptSessionRequest {
    /// The session init data from the peer.
    pub init_data: SerializableSessionInit,
}

/// Session status response.
#[derive(Serialize)]
pub struct SessionStatusResponse {
    /// Peer node ID.
    pub peer_id: String,
    /// Whether an active E2EE session exists.
    pub active: bool,
}

/// `GET /api/v1/sessions/prekey` — get our prekey bundle for distribution.
async fn get_prekey_bundle(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<PrekeyBundleResponse>, ApiError> {
    let bundle = state.session_manager.prekey_bundle().await;
    Ok(Json(PrekeyBundleResponse { bundle }))
}

/// `POST /api/v1/sessions/:peer_id/initiate` — initiate E2EE session with a peer.
async fn initiate_session(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(peer_id_hex): Path<String>,
    Json(req): Json<InitiateSessionRequest>,
) -> Result<Json<InitiateSessionResponse>, ApiError> {
    let peer_id = NodeId::from_hex(&peer_id_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid peer ID: {e}")))?;

    let init_data = state
        .session_manager
        .initiate_session(&peer_id, &req.peer_bundle)
        .await
        .map_err(|e| ApiError::BadRequest(format!("session initiation failed: {e}")))?;

    info!(peer = %peer_id, "E2EE session initiated");

    state.audit_log.record(
        events::SESSION_ESTABLISHED,
        &_auth.node_id,
        Some(serde_json::json!({
            "peer": peer_id_hex,
            "role": "initiator",
        })),
    );

    Ok(Json(InitiateSessionResponse {
        init_data,
        established: true,
    }))
}

/// `POST /api/v1/sessions/:peer_id/accept` — accept E2EE session from a peer.
async fn accept_session(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(peer_id_hex): Path<String>,
    Json(req): Json<AcceptSessionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let peer_id = NodeId::from_hex(&peer_id_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid peer ID: {e}")))?;

    state
        .session_manager
        .accept_session(&peer_id, &req.init_data)
        .await
        .map_err(|e| ApiError::BadRequest(format!("session acceptance failed: {e}")))?;

    info!(peer = %peer_id, "E2EE session accepted");

    state.audit_log.record(
        events::SESSION_ESTABLISHED,
        &_auth.node_id,
        Some(serde_json::json!({
            "peer": peer_id_hex,
            "role": "responder",
        })),
    );

    Ok(Json(serde_json::json!({ "accepted": true })))
}

/// `GET /api/v1/sessions/:peer_id` — check E2EE session status with a peer.
async fn get_session_status(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(peer_id_hex): Path<String>,
) -> Result<Json<SessionStatusResponse>, ApiError> {
    let peer_id = NodeId::from_hex(&peer_id_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid peer ID: {e}")))?;

    let active = state.session_manager.has_session(&peer_id).await;

    Ok(Json(SessionStatusResponse {
        peer_id: peer_id_hex,
        active,
    }))
}

/// `GET /api/v1/sessions` — list all active E2EE sessions.
async fn list_sessions(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<SessionStatusResponse>>, ApiError> {
    let sessions = state.session_manager.active_sessions().await;

    let responses: Vec<_> = sessions
        .into_iter()
        .map(|peer_id| SessionStatusResponse {
            peer_id: peer_id.to_hex(),
            active: true,
        })
        .collect();

    Ok(Json(responses))
}

/// Registers E2EE session routes for prekey bundles, session listing, initiation, and acceptance.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/sessions/prekey", get(get_prekey_bundle))
        .route("/api/v1/sessions", get(list_sessions))
        .route(
            "/api/v1/sessions/:peer_id",
            get(get_session_status),
        )
        .route(
            "/api/v1/sessions/:peer_id/initiate",
            post(initiate_session),
        )
        .route(
            "/api/v1/sessions/:peer_id/accept",
            post(accept_session),
        )
}
