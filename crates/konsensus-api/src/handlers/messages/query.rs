//! Message query and management endpoints — list, get, get plaintext, and delete.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use konsensus_core::types::{MessageId, Recipient};

use crate::audit::events;
use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

/// Maximum allowed limit for list queries.
pub(super) const MAX_LIST_LIMIT: u32 = 1000;

/// Query parameters for listing messages.
#[derive(Deserialize)]
pub struct ListMessagesQuery {
    /// Maximum number of messages to return (capped at 1000).
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Return messages before this timestamp (ms since epoch).
    pub before: Option<u64>,
    /// Filter to a specific conversation (peer node ID or room UUID).
    ///
    /// When set, returns both sent and received messages for the conversation.
    /// Without this, only incoming messages (recipient = this node) are returned.
    pub peer: Option<String>,
}

fn default_limit() -> u32 {
    50
}

/// Clamp a user-supplied limit to the allowed maximum.
pub(super) fn clamp_limit(limit: u32) -> u32 {
    limit.min(MAX_LIST_LIMIT)
}

/// Message in API response format.
#[derive(Serialize)]
pub struct MessageResponse {
    /// Message ID (hex-encoded blake3 hash).
    pub id: String,
    /// Message kind (u16 from the kind taxonomy, e.g. 100 = chat).
    pub kind: u16,
    /// Sender node ID (hex).
    pub sender: String,
    /// Recipient node ID (hex) or room ID (UUID string).
    pub recipient: String,
    /// Timestamp in milliseconds since Unix epoch.
    pub timestamp: u64,
    /// E2E-encrypted ciphertext (hex-encoded).
    pub ciphertext: String,
    /// Payment amount in millisatoshis attached to this message.
    pub payment_amount_msat: u64,
    /// Payment hash (hex, 32 bytes).
    pub payment_hash: String,
    /// Decrypted plaintext content, if available from the plaintext cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext: Option<String>,
    /// Message references for threading (hex-encoded MessageId list).
    /// Present on KIND_REPLY (kind=2) messages; omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

impl MessageResponse {
    pub(super) fn from_envelope(env: &konsensus_core::UkmEnvelope) -> Self {
        let recipient_str = match &env.recipient {
            Recipient::Node(id) => id.to_hex(),
            Recipient::Room(id) => id.to_string(),
            Recipient::Broadcast => "broadcast".to_string(),
        };
        Self {
            id: env.id.to_hex(),
            kind: env.kind,
            sender: env.sender.to_hex(),
            recipient: recipient_str,
            timestamp: env.timestamp,
            ciphertext: hex::encode(&env.ciphertext),
            payment_amount_msat: env.payment_proof.amount_msat,
            payment_hash: hex::encode(env.payment_proof.payment_hash),
            plaintext: None,
            references: env.references.iter().map(|r| r.to_hex()).collect(),
        }
    }

    /// Attach cached plaintext by decrypting the at-rest encrypted blob.
    pub(super) fn with_cached_plaintext(mut self, encrypted: Option<Vec<u8>>, cipher: Option<&konsensus_crypto::PlaintextCacheCipher>) -> Self {
        if let (Some(enc), Some(c)) = (encrypted, cipher) {
            match c.decrypt(&enc) {
                Ok(bytes) => {
                    if let Ok(text) = String::from_utf8(bytes) {
                        self.plaintext = Some(text);
                    }
                }
                Err(e) => {
                    tracing::debug!(msg_id = %self.id, error = %e, "failed to decrypt cached plaintext");
                }
            }
        }
        self
    }
}

/// `GET /api/v1/messages/:id` — get a specific message.
pub(super) async fn get_message(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(id_hex): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    let id = MessageId::from_hex(&id_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid message ID: {e}")))?;

    let envelope = state
        .storage
        .get_message(&id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("message {id_hex} not found")))?;

    let cached = state
        .storage
        .get_message_plaintext(&id)
        .await
        .unwrap_or(None);

    let cipher = state.plaintext_cipher.as_deref();
    Ok(Json(MessageResponse::from_envelope(&envelope).with_cached_plaintext(cached, cipher)))
}

/// `GET /api/v1/messages/:id/plaintext` — get decrypted plaintext for a message.
///
/// Returns the cached decrypted content if available. The plaintext is stored
/// AES-256-GCM encrypted at rest and decrypted on retrieval using the node's
/// derived key. Returns 404 if no cached plaintext exists (e.g., the message
/// could not be decrypted on receive, or predates the plaintext cache).
pub(super) async fn get_message_plaintext(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = MessageId::from_hex(&id_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid message ID: {e}")))?;

    let cipher = state
        .plaintext_cipher
        .as_ref()
        .ok_or_else(|| ApiError::Internal("plaintext cipher not configured".into()))?;

    let encrypted = state
        .storage
        .get_message_plaintext(&id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("no cached plaintext for message {id_hex}")))?;

    let decrypted = cipher
        .decrypt(&encrypted)
        .map_err(|e| ApiError::Internal(format!("plaintext decryption failed: {e}")))?;

    // Try to parse as UTF-8 text; fall back to base64 for binary content
    let content = match String::from_utf8(decrypted.clone()) {
        Ok(text) => serde_json::json!({
            "message_id": id_hex,
            "plaintext": text,
            "encoding": "utf8",
        }),
        Err(_) => {
            use base64::Engine;
            serde_json::json!({
                "message_id": id_hex,
                "plaintext": base64::engine::general_purpose::STANDARD.encode(&decrypted),
                "encoding": "base64",
            })
        }
    };

    Ok(Json(content))
}

/// `GET /api/v1/messages` — list messages for this node.
///
/// Without `peer` param: returns incoming messages (recipient = this node).
/// With `peer` param: returns both sent and received messages for that
/// conversation, enabling full conversation history including outgoing messages.
pub(super) async fn list_messages(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListMessagesQuery>,
) -> Result<Json<Vec<MessageResponse>>, ApiError> {
    let my_node_hex = state.identity.node_id().to_hex();

    let messages = if let Some(ref peer_id) = params.peer {
        // Validate peer_id format: either a hex node ID or a UUID room ID.
        let is_room = if peer_id.contains('-') {
            // Validate as UUID
            Uuid::parse_str(peer_id)
                .map_err(|e| ApiError::BadRequest(format!("invalid room UUID: {e}")))?;
            true
        } else {
            // Validate as hex node ID (64 hex chars)
            if peer_id.len() != 64 || !peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ApiError::BadRequest(
                    "invalid peer: expected 64-char hex node ID or UUID".into(),
                ));
            }
            false
        };
        state
            .storage
            .get_conversation_messages(
                &my_node_hex,
                peer_id,
                is_room,
                clamp_limit(params.limit),
                params.before,
            )
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))?
    } else {
        let recipient = Recipient::Node(*state.identity.node_id());
        state
            .storage
            .get_messages_for_recipient(&recipient, clamp_limit(params.limit), params.before)
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))?
    };

    let cipher = state.plaintext_cipher.as_deref();
    let mut responses = Vec::with_capacity(messages.len());
    for env in &messages {
        let mut resp = MessageResponse::from_envelope(env);
        if cipher.is_some() {
            let cached = state
                .storage
                .get_message_plaintext(&env.id)
                .await
                .unwrap_or(None);
            resp = resp.with_cached_plaintext(cached, cipher);
        }
        responses.push(resp);
    }

    Ok(Json(responses))
}

/// `DELETE /api/v1/messages/:id` — delete a message.
pub(super) async fn delete_message(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = MessageId::from_hex(&id_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid message ID: {e}")))?;

    let deleted = state
        .storage
        .delete_message(&id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    state.audit_log.record(
        events::MESSAGE_DELETED,
        &_auth.node_id,
        Some(serde_json::json!({"message_id": id_hex})),
    );

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}
