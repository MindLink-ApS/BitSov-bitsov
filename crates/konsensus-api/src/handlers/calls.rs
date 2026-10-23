//! Read-only, owner-scoped view of durable open calls. See docs/v2/API_CALLS.md.
use std::sync::Arc;

use axum::{
    extract::{rejection::QueryRejection, Query, State},
    routing::get,
    Json, Router,
};
use konsensus_core::{payloads::call::Side, NodeId};
use serde::{Deserialize, Serialize};

use crate::{
    auth::scoped::{Read, ScopedAuth},
    error::ApiError,
    AppState,
};

#[derive(Deserialize)]
struct CallsQuery {
    peer: String,
}

#[derive(Serialize)]
struct OpenCall {
    id: String,
    state: &'static str,
    direction: &'static str,
    unresolved_paid_admission: bool,
    created: Option<i64>,
    op_id: Option<String>,
}

async fn open_calls(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    query: Result<Query<CallsQuery>, QueryRejection>,
) -> Result<Json<Vec<OpenCall>>, ApiError> {
    if auth.node_id != state.identity.node_id().to_hex() {
        return Err(ApiError::Forbidden("owner read required".into()));
    }
    let invalid_peer = || ApiError::BadRequest("invalid peer id".into());
    let Query(query) = query.map_err(|_| invalid_peer())?;
    let peer = NodeId::from_hex(&query.peer).map_err(|_| invalid_peer())?;
    let now = u64::try_from(chrono::Utc::now().timestamp_millis())
        .map_err(|_| ApiError::Internal("call time unavailable".into()))?;
    let storage_error =
        |e: konsensus_storage::StorageError| ApiError::Internal(format!("call state: {e}"));
    let entries = state
        .storage
        .call_open_by_peer(&peer, now)
        .await
        .map_err(storage_error)?;
    let mut calls = Vec::with_capacity(entries.len());
    for (id, entry) in entries {
        let mut created = None;
        if let Some(pending) = &entry.pending {
            // Only an exactly bound offer operation supplies creation metadata.
            // An answer/hangup's timestamp must not become a call creation time.
            if pending.kind == konsensus_core::kind::KIND_CALL_INVITE {
                if let Some(op) = state
                    .storage
                    .get_outbox_operation(&pending.operation_id)
                    .await
                    .map_err(storage_error)?
                {
                    if op.recipient == peer.to_hex()
                        && op.kind == i64::from(pending.kind)
                        && op.request_hash == pending.request_hash
                    {
                        created = Some(op.created_at);
                    }
                }
            }
        }
        // Age a copy only: pending payment evidence must never be discarded by GET.
        if let Some(entry) = entry.at(now) {
            calls.push(OpenCall {
                id,
                state: entry.phase.as_str(),
                direction: match entry.side {
                    Side::Caller => "outgoing",
                    Side::Callee => "incoming",
                },
                unresolved_paid_admission: entry.pending.is_some(),
                created,
                op_id: entry.pending.map(|p| p.operation_id),
            });
        }
    }
    Ok(Json(calls))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/calls", get(open_calls))
}
