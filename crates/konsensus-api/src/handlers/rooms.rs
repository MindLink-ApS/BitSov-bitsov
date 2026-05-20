//! Room management endpoints.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use konsensus_core::types::{NodeId, RoomId};
use konsensus_storage::Room;

use crate::audit::events;
use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

/// Request to create a room.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRoomRequest {
    /// Room name.
    pub name: String,
    /// Optional metadata (JSON object).
    pub metadata: Option<serde_json::Value>,
}

/// Room in API response format.
#[derive(Serialize)]
pub struct RoomResponse {
    /// Room ID (UUID).
    pub id: String,
    /// Room name.
    pub name: String,
    /// Node ID (hex) of the room creator.
    pub created_by: String,
    /// ISO 8601 timestamp when the room was created.
    pub created_at: String,
    /// Arbitrary JSON metadata.
    pub metadata: serde_json::Value,
}

impl From<&Room> for RoomResponse {
    fn from(room: &Room) -> Self {
        Self {
            id: room.id.to_string(),
            name: room.name.clone(),
            created_by: room.created_by.to_hex(),
            created_at: room.created_at.clone(),
            metadata: room.metadata.clone(),
        }
    }
}

/// Request to add/remove a room member.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberRequest {
    /// Node ID (hex) of the member to add/remove.
    pub node_id: String,
}

/// Maximum room name length in bytes.
const MAX_ROOM_NAME_LEN: usize = 256;

/// Maximum serialized size for room metadata JSON (64 KiB).
const MAX_ROOM_METADATA_SIZE: usize = 64 * 1024;

/// `POST /api/v1/rooms` — create a new room.
async fn create_room(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateRoomRequest>,
) -> Result<Json<RoomResponse>, ApiError> {
    // Validate room name
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::BadRequest("room name cannot be empty".into()));
    }
    if name.len() > MAX_ROOM_NAME_LEN {
        return Err(ApiError::BadRequest(format!(
            "room name too long: {} bytes (max {MAX_ROOM_NAME_LEN})",
            name.len()
        )));
    }
    if name.contains('\0') {
        return Err(ApiError::BadRequest("room name contains null bytes".into()));
    }

    let mut room = Room::new(name, *state.identity.node_id());
    if let Some(meta) = req.metadata {
        // Validate metadata size to prevent storage exhaustion.
        let serialized = serde_json::to_string(&meta)
            .map_err(|e| ApiError::BadRequest(format!("invalid metadata: {e}")))?;
        if serialized.len() > MAX_ROOM_METADATA_SIZE {
            return Err(ApiError::BadRequest(format!(
                "metadata too large: {} bytes (max {MAX_ROOM_METADATA_SIZE})",
                serialized.len()
            )));
        }
        room.metadata = meta;
    }

    state
        .storage
        .create_room(&room)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    state.audit_log.record(
        events::ROOM_CREATED,
        &_auth.node_id,
        Some(serde_json::json!({"room_id": room.id.to_string(), "name": room.name})),
    );

    Ok(Json(RoomResponse::from(&room)))
}

/// `GET /api/v1/rooms` — list all rooms.
async fn list_rooms(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<RoomResponse>>, ApiError> {
    let rooms = state
        .storage
        .list_rooms()
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    let responses: Vec<_> = rooms.iter().map(RoomResponse::from).collect();
    Ok(Json(responses))
}

/// `GET /api/v1/rooms/:id` — get a room.
async fn get_room(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(id_str): Path<String>,
) -> Result<Json<RoomResponse>, ApiError> {
    let id = RoomId::parse(&id_str)
        .map_err(|e| ApiError::BadRequest(format!("invalid room ID: {e}")))?;

    let room = state
        .storage
        .get_room(&id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("room {id_str} not found")))?;

    Ok(Json(RoomResponse::from(&room)))
}

/// `DELETE /api/v1/rooms/:id` — delete a room and its memberships.
async fn delete_room(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(id_str): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = RoomId::parse(&id_str)
        .map_err(|e| ApiError::BadRequest(format!("invalid room ID: {e}")))?;

    let deleted = state
        .storage
        .delete_room(&id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    if !deleted {
        return Err(ApiError::NotFound(format!("room {id_str} not found")));
    }

    state.audit_log.record(
        events::ROOM_DELETED,
        &_auth.node_id,
        Some(serde_json::json!({"room_id": id_str})),
    );

    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// `GET /api/v1/rooms/:id/members` — list room members.
async fn list_members(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(id_str): Path<String>,
) -> Result<Json<Vec<String>>, ApiError> {
    let id = RoomId::parse(&id_str)
        .map_err(|e| ApiError::BadRequest(format!("invalid room ID: {e}")))?;

    let members = state
        .storage
        .get_room_members(&id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    let hex_ids: Vec<_> = members.iter().map(|m| m.to_hex()).collect();
    Ok(Json(hex_ids))
}

/// `POST /api/v1/rooms/:id/members` — add a member to a room.
async fn add_member(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(id_str): Path<String>,
    Json(req): Json<MemberRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let room_id = RoomId::parse(&id_str)
        .map_err(|e| ApiError::BadRequest(format!("invalid room ID: {e}")))?;

    let node_id = NodeId::from_hex(&req.node_id)
        .map_err(|e| ApiError::BadRequest(format!("invalid node ID: {e}")))?;

    state
        .storage
        .add_room_member(&room_id, &node_id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    state.audit_log.record(
        events::ROOM_MEMBER_ADDED,
        &_auth.node_id,
        Some(serde_json::json!({"room_id": id_str, "member": req.node_id})),
    );

    Ok(Json(serde_json::json!({ "added": true })))
}

/// `DELETE /api/v1/rooms/:id/members/:node_id` — remove a member from a room.
async fn remove_member(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path((id_str, member_hex)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let room_id = RoomId::parse(&id_str)
        .map_err(|e| ApiError::BadRequest(format!("invalid room ID: {e}")))?;

    let node_id = NodeId::from_hex(&member_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid node ID: {e}")))?;

    state
        .storage
        .remove_room_member(&room_id, &node_id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    state.audit_log.record(
        events::ROOM_MEMBER_REMOVED,
        &_auth.node_id,
        Some(serde_json::json!({"room_id": id_str, "member": member_hex})),
    );

    Ok(Json(serde_json::json!({ "removed": true })))
}

/// Build the room/group management routes.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/rooms", post(create_room).get(list_rooms))
        .route("/api/v1/rooms/:id", get(get_room).delete(delete_room))
        .route(
            "/api/v1/rooms/:id/members",
            get(list_members).post(add_member),
        )
        .route(
            "/api/v1/rooms/:id/members/:node_id",
            axum::routing::delete(remove_member),
        )
}
