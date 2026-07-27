//! `POST /api/v1/messages` — send a pre-encrypted message.
//!
//! The client provides the ciphertext already encrypted; the node signs,
//! stores, and delivers the envelope. Use `compose` if you want the node
//! to handle E2EE encryption and Lightning payment automatically.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use konsensus_core::types::{NodeId, Recipient};
use konsensus_storage::StorageNonceAdapter;

use crate::audit::events;
use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

/// Request to send a message to a peer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendMessageRequest {
    /// Recipient node ID (hex) or room ID (UUID).
    pub recipient: String,
    /// Whether the recipient is a room (true) or node (false).
    #[serde(default)]
    pub is_room: bool,
    /// Message kind (u16 from kind taxonomy).
    pub kind: u16,
    /// Ciphertext (hex-encoded, already E2E encrypted by the client).
    pub ciphertext: String,
    /// Payment hash (hex, 32 bytes).
    pub payment_hash: String,
    /// Payment preimage (hex, 32 bytes).
    pub preimage: String,
    /// Payment amount in millisatoshis.
    pub amount_msat: u64,
}

/// Response after sending a message.
#[derive(Serialize)]
pub struct SendMessageResponse {
    /// The message ID assigned to this envelope.
    pub message_id: String,
    /// Whether the message was delivered to a connected peer.
    pub delivered: bool,
}

/// `POST /api/v1/messages` — send a message.
pub(super) async fn send_message(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<SendMessageResponse>, ApiError> {
    // Parse recipient
    let recipient = if req.is_room {
        let room_id = konsensus_core::RoomId::parse(&req.recipient)
            .map_err(|e| ApiError::BadRequest(format!("invalid room ID: {e}")))?;
        Recipient::Room(room_id)
    } else {
        let node_id = NodeId::from_hex(&req.recipient)
            .map_err(|e| ApiError::BadRequest(format!("invalid node ID: {e}")))?;
        Recipient::Node(node_id)
    };

    // Parse payment proof
    let payment_hash: [u8; 32] = hex::decode(&req.payment_hash)
        .map_err(|e| ApiError::BadRequest(format!("invalid payment hash: {e}")))?
        .try_into()
        .map_err(|_| ApiError::BadRequest("payment hash must be 32 bytes".into()))?;

    let preimage: [u8; 32] = hex::decode(&req.preimage)
        .map_err(|e| ApiError::BadRequest(format!("invalid preimage: {e}")))?
        .try_into()
        .map_err(|_| ApiError::BadRequest("preimage must be 32 bytes".into()))?;

    let proof = konsensus_core::PaymentProof::new(payment_hash, preimage, req.amount_msat);

    // Parse ciphertext with size validation.
    // Reject before hex-decoding if the hex string is too large.
    // Limit: 512 KiB decoded = 1 MiB hex. This is well above any single message
    // (large payloads use chunked Noise transport, not the REST API).
    const MAX_CIPHERTEXT_HEX_LEN: usize = 1024 * 1024; // 512 KiB decoded
    if req.ciphertext.len() > MAX_CIPHERTEXT_HEX_LEN {
        return Err(ApiError::BadRequest(format!(
            "ciphertext too large: {} bytes hex (max {MAX_CIPHERTEXT_HEX_LEN})",
            req.ciphertext.len()
        )));
    }
    let ciphertext = hex::decode(&req.ciphertext)
        .map_err(|e| ApiError::BadRequest(format!("invalid ciphertext hex: {e}")))?;

    // Build envelope
    let sender = *state.identity.node_id();
    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        req.kind,
        sender,
        recipient,
        ciphertext,
        proof,
    )
    .build();

    // Sign the envelope
    let sig = state.identity.sign(&envelope.signable_bytes());
    envelope.signature = konsensus_core::Signature::from_ed25519(&sig);

    envelope
        .validate()
        .map_err(|e| ApiError::BadRequest(format!("invalid envelope: {e}")))?;

    let nonce_store = StorageNonceAdapter::new(Arc::clone(&state.storage));
    state
        .gate
        .verify(
            &envelope,
            &nonce_store,
            state.pricing.as_ref(),
            None,
            Some(state.lightning.as_ref()),
            0.0,
            // Send path: the envelope is addressed to a PEER, not this node, so
            // recipient binding is intentionally N/A here (unchanged behavior).
            None,
        )
        .await
        .map_err(|e| ApiError::PaymentRequired(e.to_string()))?;

    // Store the message
    state
        .storage
        .store_message(&envelope)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    // Attempt to deliver to connected peer; queue for later if offline
    let delivered = match &recipient {
        Recipient::Node(peer_id) => {
            if state.transport.is_connected(peer_id).await {
                state
                    .transport
                    .send(peer_id, &envelope)
                    .await
                    .map_err(|e| ApiError::Transport(e.to_string()))?;
                true
            } else {
                // Peer offline — queue for delivery when they reconnect
                if let Err(e) = state.storage.queue_pending_delivery(&envelope.id, peer_id).await {
                    tracing::warn!(error = %e, "failed to queue pending delivery");
                }
                false
            }
        }
        Recipient::Room(ref room_id) => {
            // Room delivery: send to all room members who are connected.
            //
            // DBH2 / ROOM-FANOUT-STREAM: get_room_members() is now UNBOUNDED (the old
            // LIMIT 10000 was a silent-truncation fail-open). We collect the full
            // member set into a Vec and fan out in one synchronous pass below, which
            // is fine at present mesh size but is a memory/latency cliff on a very
            // large room. Tracked follow-up ROOM-FANOUT-STREAM (TASK_QUEUE.md, Track
            // DBH) replaces this collect-then-send with chunked/streamed delivery +
            // backpressure. Keep this loop O(members)-friendly until then.
            let members = state
                .storage
                .get_room_members(room_id)
                .await
                .map_err(|e| ApiError::Storage(e.to_string()))?;

            let mut any_delivered = false;
            for member in &members {
                // Don't send to self
                if member == state.identity.node_id() {
                    continue;
                }
                if state.transport.is_connected(member).await {
                    if let Err(e) = state.transport.send(member, &envelope).await {
                        tracing::warn!(
                            peer = %member,
                            error = %e,
                            "failed to deliver room message to member"
                        );
                    } else {
                        any_delivered = true;
                    }
                } else {
                    // Queue for this room member
                    if let Err(e) = state.storage.queue_pending_delivery(&envelope.id, member).await {
                        tracing::warn!(peer = %member, error = %e, "failed to queue pending room delivery");
                    }
                }
            }
            any_delivered
        }
        Recipient::Broadcast => {
            // Broadcast/gossip messages are not sent via the compose API.
            // They use the gossip protocol (Frame::Gossip) directly.
            return Err(ApiError::BadRequest(
                "Broadcast messages cannot be sent via compose. Use the gossip protocol.".into(),
            ));
        }
    };

    // Broadcast to WebSocket clients (no plaintext — user pre-encrypted)
    if let Err(e) = state.ws_broadcast.send(Arc::new(crate::state::WsMessage {
        envelope: envelope.clone(),
        plaintext: None,
    })) {
        tracing::debug!(error = %e, "no WebSocket clients connected for message broadcast");
    }

    state.audit_log.record(
        events::MESSAGE_SENT,
        &sender.to_hex(),
        Some(serde_json::json!({
            "message_id": envelope.id.to_hex(),
            "kind": req.kind,
            "recipient": req.recipient,
            "delivered": delivered,
            "amount_msat": req.amount_msat,
        })),
    );

    Ok(Json(SendMessageResponse {
        message_id: envelope.id.to_hex(),
        delivered,
    }))
}
