//! Gossip publishing endpoints.
//!
//! Free gossip is disabled until paid broadcast semantics land. The route is
//! kept to provide an explicit fail-closed response instead of silently
//! creating a payment-gate bypass.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use konsensus_core::types::{PaymentProof, Recipient, Signature};
use konsensus_core::UkmEnvelopeBuilder;
use konsensus_message::Frame;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::handlers::utils::generate_valid_proof;
use crate::state::AppState;

/// Allowed legacy free-gossip kinds.
///
/// Empty by design: public launch must not expose an unpaid broadcast lane.
/// Paid broadcast/gossip will re-open this surface through the normal UKM
/// payment gate.
const GOSSIP_ALLOWED_KINDS: &[u16] = &[];

/// Maximum gossip payload size (64 KB — web manifests should be small).
const MAX_GOSSIP_PAYLOAD: usize = 65_536;

/// Request body for publishing a gossip message.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishGossipRequest {
    /// The message kind (must be an allowed gossip kind, e.g., 510).
    pub kind: u16,
    /// The payload content (will be included as plaintext ciphertext since
    /// gossip is public data — no E2EE needed).
    pub payload: String,
}

/// Response from a successful gossip publish.
#[derive(Debug, Serialize)]
pub struct PublishGossipResponse {
    /// The message ID of the published gossip message.
    pub message_id: String,
    /// Number of peers the message was sent to.
    pub peers_sent: u32,
    /// Number of connected peers.
    pub peers_total: u32,
}

/// Gossip status/metrics.
#[derive(Debug, Serialize)]
pub struct GossipStatusResponse {
    /// Number of entries in the dedup store.
    pub dedup_entries: usize,
    /// Number of senders currently tracked in the rate limiter.
    pub tracked_senders: usize,
    /// Maximum messages per sender per hour.
    pub max_per_sender_per_hour: u32,
    /// Dedup TTL in seconds.
    pub dedup_ttl_secs: u64,
    /// Maximum message age in seconds.
    pub max_age_secs: u64,
}

/// Build the gossip routes.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/gossip/publish", post(publish_gossip))
        .route("/api/v1/gossip/status", get(gossip_status))
}

/// POST /api/v1/gossip/publish — publish a gossip message to the mesh.
///
/// Currently returns an explicit fail-closed error for every kind. Paid
/// broadcast/gossip must be implemented on the normal UKM payment-gated path.
async fn publish_gossip(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<PublishGossipRequest>,
) -> Result<Json<PublishGossipResponse>, ApiError> {
    // 1. Validate kind is allowed for gossip
    if !GOSSIP_ALLOWED_KINDS.contains(&req.kind) {
        return Err(ApiError::BadRequest(format!(
            "legacy free gossip is disabled until paid broadcast lands (kind {})",
            req.kind
        )));
    }

    // 2. Validate payload size
    let payload_bytes = req.payload.as_bytes();
    if payload_bytes.is_empty() {
        return Err(ApiError::BadRequest("payload must not be empty".into()));
    }
    if payload_bytes.len() > MAX_GOSSIP_PAYLOAD {
        return Err(ApiError::BadRequest(format!(
            "payload too large: {} bytes (max {MAX_GOSSIP_PAYLOAD})",
            payload_bytes.len()
        )));
    }

    // 3. Build the envelope for any future explicitly enabled legacy kind.
    let (hash, preimage, amount) = generate_valid_proof(0);
    let proof = PaymentProof::new(hash, preimage, amount);
    let sender = *state.identity.node_id();

    let mut envelope = UkmEnvelopeBuilder::new(
        req.kind,
        sender,
        Recipient::Broadcast,
        payload_bytes.to_vec(),
        proof,
    )
    .build();

    // 4. Sign the envelope
    let sig = state.identity.sign(&envelope.signable_bytes());
    envelope.signature = Signature::from_ed25519(&sig);

    let msg_id = envelope.id.to_hex();

    // 5. Serialize the Frame::Gossip to bytes
    let gossip_frame = Frame::Gossip(Box::new(envelope));
    let frame_bytes = gossip_frame
        .to_bytes()
        .map_err(|e| ApiError::Internal(format!("failed to serialize gossip frame: {e}")))?;

    // 6. Send to all connected peers
    let connected = state.transport.connected_peers().await;
    let total = u32::try_from(connected.len()).unwrap_or(u32::MAX);
    let mut sent = 0u32;

    for peer_id in &connected {
        match state.transport.send_raw_frame(peer_id, &frame_bytes).await {
            Ok(()) => sent = sent.saturating_add(1),
            Err(e) => {
                warn!(
                    peer = %peer_id,
                    error = %e,
                    "failed to send gossip to peer"
                );
            }
        }
    }

    info!(
        message_id = %msg_id,
        kind = req.kind,
        payload_bytes = payload_bytes.len(),
        peers_sent = sent,
        peers_total = total,
        "published gossip message"
    );

    state.audit_log.record(
        "gossip_published",
        &sender.to_hex(),
        Some(serde_json::json!({
            "message_id": msg_id,
            "kind": req.kind,
            "payload_bytes": payload_bytes.len(),
            "peers_sent": sent,
            "peers_total": total,
        })),
    );

    Ok(Json(PublishGossipResponse {
        message_id: msg_id,
        peers_sent: sent,
        peers_total: total,
    }))
}

/// GET /api/v1/gossip/status — return gossip protocol metrics.
///
/// Returns the current state of the gossip validator (dedup store size,
/// tracked senders, configuration).
async fn gossip_status(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<GossipStatusResponse>, ApiError> {
    let validator = state
        .gossip_validator
        .as_ref()
        .ok_or_else(|| ApiError::Internal("gossip validator not available".into()))?;

    let config = validator.config();
    Ok(Json(GossipStatusResponse {
        dedup_entries: validator.store().len(),
        tracked_senders: validator.tracked_senders(),
        max_per_sender_per_hour: config.max_per_sender_per_hour,
        dedup_ttl_secs: config.dedup_ttl_secs,
        max_age_secs: config.max_age_secs,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gossip_allowed_kinds_empty_until_paid_broadcast_lands() {
        assert!(GOSSIP_ALLOWED_KINDS.is_empty());
    }

    #[test]
    fn gossip_allowed_kinds_rejects_chat() {
        assert!(!GOSSIP_ALLOWED_KINDS.contains(&konsensus_core::kind::KIND_CHAT));
    }

    #[test]
    fn publish_request_deserializes() {
        let json = r#"{"kind": 510, "payload": "hello mesh"}"#;
        let req: PublishGossipRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.kind, 510);
        assert_eq!(req.payload, "hello mesh");
    }

    #[test]
    fn publish_request_rejects_unknown_fields() {
        let json = r#"{"kind": 510, "payload": "test", "extra": true}"#;
        let result: Result<PublishGossipRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn publish_response_serializes() {
        let resp = PublishGossipResponse {
            message_id: "abc123".into(),
            peers_sent: 2,
            peers_total: 3,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["message_id"], "abc123");
        assert_eq!(json["peers_sent"], 2);
        assert_eq!(json["peers_total"], 3);
    }

    #[test]
    fn gossip_status_response_serializes() {
        let resp = GossipStatusResponse {
            dedup_entries: 42,
            tracked_senders: 5,
            max_per_sender_per_hour: 60,
            dedup_ttl_secs: 7200,
            max_age_secs: 3600,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["dedup_entries"], 42);
        assert_eq!(json["tracked_senders"], 5);
        assert_eq!(json["max_per_sender_per_hour"], 60);
    }
}
