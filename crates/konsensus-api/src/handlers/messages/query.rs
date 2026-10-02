//! Message query and management endpoints — list, get, get plaintext, and delete.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use konsensus_core::payloads::room::{RoomBinding, RoomChat};
use konsensus_core::types::{MessageId, NodeId, Recipient};

use crate::audit::events;
use crate::auth::scoped::{ScopedAuth, Admin, Read};
use crate::error::ApiError;
use crate::freshness::DataFreshness;
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
    /// Only chats bound to this room id (64 lowercase hex): the room thread,
    /// received and sent, among the most recent [`MAX_SEARCH_SCAN`] chats
    /// with any node. Our per-member copies of one room message are one entry,
    /// at its newest copy's timestamp; `before` and `limit` count entries.
    /// Not combined with `peer`.
    pub room: Option<String>,
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
    /// The room this chat belongs to (its binding, both ends in the roster).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room: Option<RoomBinding>,
    /// The room message id (`msg`), the same on every member's copy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_msg: Option<String>,
    /// In a room thread (`?room=`), our own room message is one entry whose
    /// `recipient` is the room id, `payment_amount_msat` the sum, and `id`,
    /// `ciphertext` and `payment_hash` those of its newest copy; this lists
    /// every member's copy, sorted by recipient.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub copies: Vec<RoomCopy>,
}

/// One member's copy of our own room message.
#[derive(Serialize)]
pub struct RoomCopy {
    pub recipient: String,
    pub id: String,
    pub payment_amount_msat: u64,
}

impl MessageResponse {
    /// This chat's room: its binding, if sender and recipient node are both in
    /// the roster (a refused one is withdrawn on receive; this holds on read).
    fn room_of(&self, plaintext: &str) -> Option<RoomChat> {
        if self.kind != konsensus_core::kind::KIND_CHAT {
            return None;
        }
        let chat = RoomChat::parse(plaintext).ok()??;
        let (from, to) = (NodeId::from_hex(&self.sender).ok()?, NodeId::from_hex(&self.recipient).ok()?);
        chat.room.check(&from, &to).ok()?;
        Some(chat)
    }

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
            room: None,
            room_msg: None,
            copies: Vec::new(),
        }
    }

    /// Attach cached plaintext by decrypting the at-rest encrypted blob.
    pub(super) fn with_cached_plaintext(mut self, encrypted: Option<Vec<u8>>, cipher: Option<&konsensus_crypto::PlaintextCacheCipher>) -> Self {
        if let (Some(enc), Some(c)) = (encrypted, cipher) {
            match c.decrypt(&enc) {
                Ok(bytes) => {
                    if let Ok(text) = String::from_utf8(bytes) {
                        if let Some(chat) = self.room_of(&text) {
                            self.room = Some(chat.room);
                            self.room_msg = Some(chat.msg);
                        }
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
    _auth: ScopedAuth<Read>,
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
    _auth: ScopedAuth<Read>,
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
/// With `room` param (64 lowercase hex): the room thread, both directions:
/// chats carrying a valid binding to that room id among the newest
/// `MAX_SEARCH_SCAN` chats with any node, our per-member copies of one room
/// message shown once (see [`MessageResponse::copies`]).
///
/// `BitSov-Data-As-Of` is the time the message store was read for this
/// response (the store is local and authoritative, so normally "now").
pub(super) async fn list_messages(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListMessagesQuery>,
) -> Result<(DataFreshness, Json<MessagesResponse>), ApiError> {
    let my_node_hex = state.identity.node_id().to_hex();
    let store_read = DataFreshness::now();
    let limit = clamp_limit(params.limit);
    if let Some(room) = &params.room {
        if !konsensus_core::payloads::room::is_room_id(room) {
            return Err(ApiError::BadRequest("invalid room: expected a 64-char lowercase hex room id".into()));
        }
        if params.peer.is_some() {
            return Err(ApiError::BadRequest("room and peer are exclusive".into()));
        }
        return Ok((store_read, Json(room_thread(&state, &my_node_hex, room, limit, params.before).await?)));
    }

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
            .get_conversation_messages_with_diagnostics(
                &my_node_hex,
                peer_id,
                is_room,
                limit,
                params.before,
            )
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))?
    } else {
        let recipient = Recipient::Node(*state.identity.node_id());
        state
            .storage
            .get_messages_for_recipient_with_diagnostics(&recipient, limit, params.before)
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))?
    };

    let diagnostics = (&messages).into();
    let cipher = state.plaintext_cipher.as_deref();
    let mut responses = Vec::with_capacity(messages.items.len());
    for env in &messages.items {
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

    Ok((store_read, Json(MessagesResponse { messages: responses, diagnostics })))
}

/// `?room=`: the room thread, both directions, as logical entries: a received
/// chat, or one of our room messages with every member copy (same `msg`). It
/// is built from the newest [`MAX_SEARCH_SCAN`] chats with any node, always
/// from the top: copies of one message can be far apart (a resend to a member
/// that was refused), so `before` cannot be applied to single envelopes
/// without splitting a message across pages (Codex #155 delta 1). Each entry
/// is placed at its newest copy's timestamp, ordered newest first (ties by
/// id); `before` and `limit` then apply to entries, so a page never repeats
/// or splits a message.
async fn room_thread(state: &AppState, me: &str, room_id: &str, limit: u32, before: Option<u64>) -> Result<MessagesResponse, ApiError> {
    let messages = state
        .storage
        .get_node_messages_of_kind_with_diagnostics(me, konsensus_core::kind::KIND_CHAT, MAX_SEARCH_SCAN, None)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;
    let diagnostics = (&messages).into();
    let Some(cipher) = state.plaintext_cipher.as_deref() else { return Ok(MessagesResponse { messages: Vec::new(), diagnostics }) };
    let mut thread: Vec<MessageResponse> = Vec::new();
    // Our room message id -> its entry in `thread`.
    let mut sent: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for env in &messages.items {
        let cached = state.storage.get_message_plaintext(&env.id).await.unwrap_or(None);
        let mut resp = MessageResponse::from_envelope(env).with_cached_plaintext(cached, Some(cipher));
        if resp.room.as_ref().is_none_or(|room| room.id != room_id) {
            continue;
        }
        if resp.sender == me {
            let copy = RoomCopy { recipient: resp.recipient.clone(), id: resp.id.clone(), payment_amount_msat: resp.payment_amount_msat };
            let msg = resp.room_msg.clone().unwrap_or_default();
            if let Some(&at) = sent.get(&msg) {
                let entry = &mut thread[at];
                entry.payment_amount_msat = entry.payment_amount_msat.saturating_add(copy.payment_amount_msat);
                if resp.timestamp > entry.timestamp || (resp.timestamp == entry.timestamp && resp.id > entry.id) {
                    // The newest copy represents the entry.
                    (entry.id, entry.timestamp, entry.ciphertext, entry.payment_hash) = (resp.id, resp.timestamp, resp.ciphertext, resp.payment_hash);
                }
                entry.copies.push(copy);
                continue;
            }
            resp.recipient = room_id.to_string();
            resp.copies.push(copy);
            sent.insert(msg, thread.len());
        }
        thread.push(resp);
    }
    thread.sort_by(|a, b| (b.timestamp, &b.id).cmp(&(a.timestamp, &a.id)));
    thread.retain(|entry| before.is_none_or(|before| entry.timestamp < before));
    thread.truncate(limit as usize);
    for entry in &mut thread {
        entry.copies.sort_by(|a, b| a.recipient.cmp(&b.recipient));
    }
    Ok(MessagesResponse { messages: thread, diagnostics })
}

/// Maximum number of most-recent messages a single search will decrypt and scan.
/// Bounds the in-memory decryption work so a search cannot be turned into a DoS.
pub(super) const MAX_SEARCH_SCAN: u32 = 1000;

/// Query parameters for searching messages.
#[derive(Deserialize)]
pub struct SearchMessagesQuery {
    /// Case-insensitive substring to match against decrypted message plaintext.
    pub q: String,
    /// Maximum number of matches to return (capped at 1000).
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Restrict the search to one conversation (peer node ID hex or room UUID).
    /// Without it, searches this node's received messages.
    pub peer: Option<String>,
}

/// A single search hit — message metadata plus a plaintext snippet around the match.
#[derive(Serialize)]
pub struct SearchResult {
    /// Message ID (hex-encoded blake3 hash).
    pub id: String,
    /// Message kind (u16 from the kind taxonomy).
    pub kind: u16,
    /// Sender node ID (hex).
    pub sender: String,
    /// Recipient node ID (hex) or room ID (UUID string).
    pub recipient: String,
    /// Timestamp in milliseconds since Unix epoch.
    pub timestamp: u64,
    /// Plaintext snippet around the first match. Built in RAM; never persisted.
    pub snippet: String,
}

/// Build a plaintext snippet around the first (case-insensitive) match.
///
/// Character-based windowing keeps this panic-free on any UTF-8 input. The match
/// index is derived from the lowercased haystack; for input whose length changes
/// under lowercasing the window may shift by a few characters — acceptable for a
/// display snippet and never unsafe.
fn search_snippet(text: &str, needle_lower: &str, ctx: usize) -> String {
    let lower = text.to_lowercase();
    match lower.find(needle_lower) {
        Some(byte_idx) => {
            let match_char = lower[..byte_idx].chars().count();
            let start = match_char.saturating_sub(ctx);
            let take = ctx * 2 + needle_lower.chars().count();
            let body: String = text.chars().skip(start).take(take).collect();
            let prefix = if start > 0 { "\u{2026}" } else { "" };
            let suffix = if text.chars().count() > start + take { "\u{2026}" } else { "" };
            format!("{prefix}{body}{suffix}")
        }
        None => text.chars().take(ctx * 2).collect(),
    }
}

/// `GET /api/v1/messages/search?q=…` — local, on-device message search.
///
/// **Principle 4:** there is NO plaintext (or FTS) index at rest. This decrypts
/// the `plaintext_enc` cache of the most-recent messages IN MEMORY (bounded by
/// [`MAX_SEARCH_SCAN`]) and substring-matches on the fly — exactly as
/// `list_messages` already decrypts for display. Nothing is written; the
/// decrypted content never leaves the node's RAM. Binary/undecryptable messages
/// are silently skipped. Without `peer`, searches received messages (mirrors
/// `list_messages`); with `peer`, searches that conversation.
pub(super) async fn search_messages(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchMessagesQuery>,
) -> Result<Json<MessagesResponse<SearchResult>>, ApiError> {
    let needle = params.q.trim();
    if needle.is_empty() {
        return Err(ApiError::BadRequest("search query 'q' must not be empty".into()));
    }
    let needle_lower = needle.to_lowercase();

    let cipher = state.plaintext_cipher.as_deref().ok_or_else(|| {
        ApiError::Internal("search requires the plaintext cache to be configured".into())
    })?;

    let my_node_hex = state.identity.node_id().to_hex();

    // Load the most-recent messages to scan (bounded). Mirrors list_messages.
    let messages = if let Some(ref peer_id) = params.peer {
        let is_room = if peer_id.contains('-') {
            Uuid::parse_str(peer_id)
                .map_err(|e| ApiError::BadRequest(format!("invalid room UUID: {e}")))?;
            true
        } else {
            if peer_id.len() != 64 || !peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ApiError::BadRequest(
                    "invalid peer: expected 64-char hex node ID or UUID".into(),
                ));
            }
            false
        };
        state
            .storage
            .get_conversation_messages_with_diagnostics(&my_node_hex, peer_id, is_room, MAX_SEARCH_SCAN, None)
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))?
    } else {
        let recipient = Recipient::Node(*state.identity.node_id());
        state
            .storage
            .get_messages_for_recipient_with_diagnostics(&recipient, MAX_SEARCH_SCAN, None)
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))?
    };

    let limit = clamp_limit(params.limit) as usize;
    let diagnostics = (&messages).into();
    let mut results = Vec::new();
    for env in &messages.items {
        if results.len() >= limit {
            break;
        }
        let encrypted = match state.storage.get_message_plaintext(&env.id).await {
            Ok(Some(blob)) => blob,
            _ => continue, // no cached plaintext (undecryptable / pre-cache) — skip
        };
        let decrypted = match cipher.decrypt(&encrypted) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let text = match String::from_utf8(decrypted) {
            Ok(t) => t,
            Err(_) => continue, // binary content — not text-searchable
        };
        if text.to_lowercase().contains(&needle_lower) {
            let recipient_str = match &env.recipient {
                Recipient::Node(id) => id.to_hex(),
                Recipient::Room(id) => id.to_string(),
                Recipient::Broadcast => "broadcast".to_string(),
            };
            results.push(SearchResult {
                id: env.id.to_hex(),
                kind: env.kind,
                sender: env.sender.to_hex(),
                recipient: recipient_str,
                timestamp: env.timestamp,
                snippet: search_snippet(&text, &needle_lower, 48),
            });
        }
    }

    Ok(Json(MessagesResponse { messages: results, diagnostics }))
}

/// `DELETE /api/v1/messages/:id` — delete a message.
pub(super) async fn delete_message(
    _auth: ScopedAuth<Admin>,
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

#[cfg(test)]
mod search_snippet_tests {
    use super::search_snippet;

    #[test]
    fn snippet_wraps_match_with_ellipses() {
        let text = "the quick brown fox jumps over the lazy dog and keeps going for a while";
        let s = super::search_snippet(text, "brown fox", 5);
        assert!(s.contains("brown fox"), "snippet must contain the match: {s}");
        // Match is mid-text, so both ends are elided.
        assert!(s.starts_with('\u{2026}'), "expected leading ellipsis: {s}");
    }

    #[test]
    fn snippet_at_start_has_no_leading_ellipsis() {
        let s = search_snippet("hello world this is a message", "hello", 20);
        assert!(s.starts_with("hello"), "no leading ellipsis when match is at start: {s}");
    }

    #[test]
    fn snippet_case_insensitive_positioning() {
        // Needle is already lowercased by the caller; text has mixed case.
        let s = search_snippet("Meeting about the QUARTERLY budget review", "quarterly", 4);
        assert!(s.to_lowercase().contains("quarterly"), "matches case-insensitively: {s}");
        // Original casing is preserved in the returned snippet.
        assert!(s.contains("QUARTERLY"), "preserves original casing: {s}");
    }

    #[test]
    fn snippet_no_match_returns_head() {
        let s = search_snippet("some other content entirely", "absent", 6);
        assert!(!s.contains('\u{2026}') || s.len() <= "some other content entirely".len() + 3);
        assert!(s.starts_with("some"), "falls back to head of text: {s}");
    }

    #[test]
    fn snippet_is_panic_safe_on_multibyte() {
        // Multibyte content around the match must never panic (char-based windowing).
        let text = "café ☕ meeting notes — quarterly café review ☕ done";
        let _ = search_snippet(text, "quarterly", 3);
        let _ = search_snippet(text, "café", 2);
        let _ = search_snippet("日本語のメッセージ test 検索", "test", 2);
    }
}

#[derive(Serialize)]
pub struct MessagesResponse<T = MessageResponse> {
    pub messages: Vec<T>,
    #[serde(flatten)]
    pub diagnostics: crate::handlers::list_diagnostics::ListDiagnostics,
}
