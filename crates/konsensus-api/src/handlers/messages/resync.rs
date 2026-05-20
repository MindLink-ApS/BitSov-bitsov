//! `POST /api/v1/messages/resync` — two-phase message history restoration.
//!
//! Two phases: discover (returns manifest of message_ids + estimated fees in
//! a time window at 50% `RESYNC_DISCOUNT`) and fulfill (broadcasts stored
//! messages via WebSocket so the frontend can restore conversation history).

use std::sync::Arc;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use konsensus_core::types::{MessageId, NodeId};
use crate::audit::events;
use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

const MAX_FULFILL_IDS: usize = 500;
const MAX_DISCOVERY_LIMIT: u32 = 1000;

#[derive(Deserialize)]
#[serde(tag = "phase", rename_all = "lowercase")]
pub enum ResyncRequest {
    Discover { peer_id: String, from_ms: u64, to_ms: u64 },
    Fulfill  { peer_id: String, message_ids: Vec<String> },
}

#[derive(Serialize)]
pub struct ResyncEntry {
    pub id: String,
    pub kind: u16,
    pub timestamp: u64,
    pub estimated_fee_msat: u64,
    pub plaintext_available: bool,
}

#[derive(Serialize)]
pub struct ResyncDiscoverResponse {
    pub phase: &'static str,
    pub peer_id: String,
    pub messages: Vec<ResyncEntry>,
    pub total_count: usize,
    pub estimated_total_msat: u64,
    pub from_ms: u64,
    pub to_ms: u64,
}

#[derive(Serialize)]
pub struct ResyncFulfillResponse {
    pub phase: &'static str,
    pub resynced_count: usize,
    pub failed_count: usize,
    pub plaintext_count: usize,
    pub total_msat: u64,
}

pub(super) async fn resync_messages(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ResyncRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    match req {
        ResyncRequest::Discover { peer_id, from_ms, to_ms } => {
            let r = discover(&state, peer_id, from_ms, to_ms).await?;
            Ok(Json(serde_json::to_value(r)
                .map_err(|e| ApiError::Internal(format!("serialization error: {e}")))?))
        }
        ResyncRequest::Fulfill { peer_id, message_ids } => {
            let r = fulfill(&state, peer_id, message_ids).await?;
            Ok(Json(serde_json::to_value(r)
                .map_err(|e| ApiError::Internal(format!("serialization error: {e}")))?))
        }
    }
}

async fn discover(
    state: &AppState,
    peer_id: String,
    from_ms: u64,
    to_ms: u64,
) -> Result<ResyncDiscoverResponse, ApiError> {
    if from_ms > to_ms {
        return Err(ApiError::BadRequest("from_ms must be <= to_ms".into()));
    }
    NodeId::from_hex(&peer_id)
        .map_err(|e| ApiError::BadRequest(format!("invalid peer_id: {e}")))?;

    let my_node_hex = state.identity.node_id().to_hex();
    let envelopes = state
        .storage
        .get_conversation_messages(&my_node_hex, &peer_id, false, MAX_DISCOVERY_LIMIT, Some(to_ms.saturating_add(1)))
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    let in_window: Vec<_> = envelopes.into_iter().filter(|env| env.timestamp >= from_ms).collect();

    let mut entries = Vec::with_capacity(in_window.len());
    let mut estimated_total: u64 = 0;
    for env in &in_window {
        let base_msat = state.pricing.get_price_msat(env.kind).await.unwrap_or(1);
        let fee_msat = konsensus_pricing::apply_resync_discount(base_msat);
        let plaintext_available = state.storage.get_message_plaintext(&env.id).await.unwrap_or(None).is_some();
        entries.push(ResyncEntry {
            id: env.id.to_hex(),
            kind: env.kind,
            timestamp: env.timestamp,
            estimated_fee_msat: fee_msat,
            plaintext_available,
        });
        estimated_total = estimated_total.saturating_add(fee_msat);
    }
    entries.sort_by_key(|e| e.timestamp);
    let total_count = entries.len();

    state.audit_log.record(events::MESSAGE_COMPOSED, &state.identity.node_id().to_hex(),
        Some(serde_json::json!({"action":"resync_discover","peer_id":peer_id,"from_ms":from_ms,"to_ms":to_ms,"found":total_count})));
    tracing::info!(peer = %peer_id, from_ms, to_ms, found = total_count, estimated_msat = estimated_total, "resync discovery complete");

    Ok(ResyncDiscoverResponse { phase: "discover", peer_id, messages: entries, total_count, estimated_total_msat: estimated_total, from_ms, to_ms })
}

async fn fulfill(
    state: &AppState,
    peer_id: String,
    message_id_strs: Vec<String>,
) -> Result<ResyncFulfillResponse, ApiError> {
    if message_id_strs.is_empty() {
        return Err(ApiError::BadRequest("message_ids must not be empty".into()));
    }
    if message_id_strs.len() > MAX_FULFILL_IDS {
        return Err(ApiError::BadRequest(format!("too many message_ids: {} (max {MAX_FULFILL_IDS})", message_id_strs.len())));
    }
    NodeId::from_hex(&peer_id)
        .map_err(|e| ApiError::BadRequest(format!("invalid peer_id: {e}")))?;

    let mut ids: Vec<MessageId> = Vec::with_capacity(message_id_strs.len());
    for id_str in &message_id_strs {
        ids.push(MessageId::from_hex(id_str)
            .map_err(|e| ApiError::BadRequest(format!("invalid message_id {id_str}: {e}")))?);
    }

    let cipher = state.plaintext_cipher.as_deref();
    let (mut resynced, mut failed, mut plaintext_count, mut total_msat) = (0usize, 0usize, 0usize, 0u64);

    for id in &ids {
        let envelope = match state.storage.get_message(id).await {
            Ok(Some(env)) => env,
            Ok(None) => { tracing::warn!(msg_id = %id.to_hex(), "resync: message not found"); failed += 1; continue; }
            Err(e)    => { tracing::warn!(msg_id = %id.to_hex(), error = %e, "resync: storage error"); failed += 1; continue; }
        };

        let plaintext = if let Some(c) = cipher {
            match state.storage.get_message_plaintext(id).await {
                Ok(Some(enc)) => match c.decrypt(&enc) {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(text) => { plaintext_count += 1; Some(text) }
                        Err(_)   => None,
                    },
                    Err(_) => None,
                },
                _ => None,
            }
        } else { None };

        let ws_msg = Arc::new(crate::state::WsMessage { envelope: envelope.clone(), plaintext });
        if let Err(e) = state.ws_broadcast.send(ws_msg) {
            tracing::debug!(msg_id = %id.to_hex(), error = %e, "resync: no WS clients connected");
        }

        let base_msat = state.pricing.get_price_msat(envelope.kind).await.unwrap_or(1);
        total_msat = total_msat.saturating_add(konsensus_pricing::apply_resync_discount(base_msat));
        resynced += 1;
    }

    state.audit_log.record(events::MESSAGE_COMPOSED, &state.identity.node_id().to_hex(),
        Some(serde_json::json!({"action":"resync_fulfill","peer_id":peer_id,"requested":ids.len(),"resynced":resynced,"failed":failed})));
    tracing::info!(peer = %peer_id, resynced, failed, plaintext_count, total_msat, "resync fulfillment complete");

    Ok(ResyncFulfillResponse { phase: "fulfill", resynced_count: resynced, failed_count: failed, plaintext_count, total_msat })
}

#[cfg(test)]
mod tests {
    #[test]
    fn resync_discount_is_half_price()        { assert_eq!(konsensus_pricing::apply_resync_discount(10), 5); }
    #[test]
    fn resync_discount_minimum_one_msat()     { assert_eq!(konsensus_pricing::apply_resync_discount(1),  1); }
    #[test]
    fn resync_discount_rounds_up()            { assert_eq!(konsensus_pricing::apply_resync_discount(3),  2); }
    #[test]
    fn resync_discount_zero_clamps_to_one()   { assert_eq!(konsensus_pricing::apply_resync_discount(0),  1); }
}
