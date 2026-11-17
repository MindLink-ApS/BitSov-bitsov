//! Owner routes for an outbound BLVM chat session.
//!
//! Creating a request stores BIP70 outputs on this node's blvm-payment module.
//! Confirming a session verifies that payment here and writes the row chat
//! compose debits. A request that exists only on the other node does not verify.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use konsensus_core::NodeId;

use crate::auth::scoped::{Read, Receive, ScopedAuth, Spend};
use crate::error::ApiError;
use crate::state::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/blvm/chat", get(chat_status))
        .route("/api/v1/blvm/chat-session/request", post(create_request))
        .route("/api/v1/blvm/chat-session", post(confirm_session))
        .route("/api/v1/blvm/chat-session/:node_id", get(read_session))
}

fn owner(auth_node: &str, state: &AppState) -> Result<(), ApiError> {
    if auth_node != state.identity.node_id().to_hex() {
        return Err(ApiError::Forbidden("blvm chat is owner only".into()));
    }
    Ok(())
}

fn sessions(state: &AppState) -> Result<std::sync::Arc<dyn konsensus_core::BlvmSessionControl>, ApiError> {
    state.gate.blvm_sessions().ok_or_else(|| {
        ApiError::Forbidden("blvm chat is not enabled".into())
    })
}

#[derive(Serialize)]
struct ChatStatus {
    enabled: bool,
}

async fn chat_status(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ChatStatus>, ApiError> {
    owner(&auth.node_id, &state)?;
    Ok(Json(ChatStatus {
        enabled: state.gate.blvm_chat_enabled() && state.gate.blvm_sessions().is_some(),
    }))
}

#[derive(Deserialize)]
struct CreateRequest {
    amount_sats: u64,
    script_pubkey_hex: String,
}

#[derive(Serialize)]
struct CreatedRequest {
    payment_request_id: String,
}

async fn create_request(
    auth: ScopedAuth<Receive>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateRequest>,
) -> Result<Json<CreatedRequest>, ApiError> {
    owner(&auth.node_id, &state)?;
    validate_amount(req.amount_sats)?;
    validate_script(&req.script_pubkey_hex)?;
    let payment_request_id = sessions(&state)?
        .create_chat_payment_request(req.amount_sats, &req.script_pubkey_hex)
        .await
        .map_err(ApiError::BadRequest)?;
    Ok(Json(CreatedRequest { payment_request_id }))
}

#[derive(Deserialize)]
struct ConfirmRequest {
    recipient: String,
    payment_request_id: String,
    tx_hash: String,
}

#[derive(Serialize)]
struct SessionResponse {
    recipient: String,
    payment_request_id: String,
    tx_hash: String,
    amount_sats: u64,
    debit_counter: u64,
    spent_msat: u64,
    remaining_msat: u64,
}

async fn confirm_session(
    auth: ScopedAuth<Spend>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConfirmRequest>,
) -> Result<Json<SessionResponse>, ApiError> {
    owner(&auth.node_id, &state)?;
    let recipient = parse_recipient(&req.recipient)?;
    validate_request_id(&req.payment_request_id)?;
    validate_tx_hash(&req.tx_hash)?;
    let view = sessions(&state)?
        .confirm_chat_session(&recipient, &req.payment_request_id, &req.tx_hash)
        .await
        .map_err(ApiError::BadRequest)?;
    Ok(Json(session_response(view)))
}

async fn read_session(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> Result<Json<SessionResponse>, ApiError> {
    owner(&auth.node_id, &state)?;
    let recipient = parse_recipient(&node_id)?;
    match sessions(&state)?.chat_session(&recipient).await.map_err(ApiError::BadRequest)? {
        Some(view) => Ok(Json(session_response(view))),
        None => Err(ApiError::NotFound("no open blvm chat session for that recipient".into())),
    }
}

fn session_response(view: konsensus_core::BlvmOutboundSessionView) -> SessionResponse {
    let prepaid = view.amount_sats.saturating_mul(1000);
    SessionResponse {
        recipient: view.recipient.to_hex(),
        payment_request_id: view.payment_request_id,
        tx_hash: hex::encode(view.tx_hash),
        amount_sats: view.amount_sats,
        debit_counter: view.debit_counter,
        spent_msat: view.spent_msat,
        remaining_msat: prepaid.saturating_sub(view.spent_msat),
    }
}

fn parse_recipient(hex_id: &str) -> Result<NodeId, ApiError> {
    NodeId::from_hex(hex_id.trim()).map_err(|_| ApiError::BadRequest("recipient is not a node id".into()))
}

fn validate_amount(amount_sats: u64) -> Result<(), ApiError> {
    if amount_sats == 0 || amount_sats > (i64::MAX as u64) / 1000 {
        return Err(ApiError::BadRequest("amount_sats is outside the chat session range".into()));
    }
    Ok(())
}

fn validate_script(script_pubkey_hex: &str) -> Result<(), ApiError> {
    let script = hex::decode(script_pubkey_hex.trim())
        .map_err(|_| ApiError::BadRequest("script_pubkey_hex is not hex".into()))?;
    if script.is_empty() || script.len() > 10_000 {
        return Err(ApiError::BadRequest(
            "script_pubkey_hex is outside the script length range".into(),
        ));
    }
    Ok(())
}

fn validate_request_id(id: &str) -> Result<(), ApiError> {
    if id.is_empty()
        || id.len() > 128
        || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError::BadRequest("payment_request_id is invalid".into()));
    }
    Ok(())
}

fn validate_tx_hash(tx_hash: &str) -> Result<(), ApiError> {
    let bytes = hex::decode(tx_hash.trim())
        .map_err(|_| ApiError::BadRequest("tx_hash is not hex".into()))?;
    if bytes.len() != 32 {
        return Err(ApiError::BadRequest("tx_hash must be 32 bytes".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_fields_reject_empty_and_oversized_values() {
        assert!(validate_amount(0).is_err());
        assert!(validate_amount(1).is_ok());
        assert!(validate_script("zz").is_err());
        assert!(validate_script("51").is_ok());
        assert!(validate_request_id("").is_err());
        assert!(validate_request_id("req-1").is_ok());
        assert!(validate_request_id("req 1").is_err());
        assert!(validate_tx_hash("abcd").is_err());
        assert!(validate_tx_hash(&hex::encode([1u8; 32])).is_ok());
    }
}
