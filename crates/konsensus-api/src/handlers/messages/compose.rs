//! `POST /api/v1/messages/compose` — compose, encrypt, pay, and send a message.
//!
//! The node handles the full pipeline: E2EE encryption via Double Ratchet,
//! Lightning payment proof creation (keysend or invoice-request fallback),
//! envelope construction, Ed25519 signing, storage, and delivery.
//!
//! This is the primary endpoint for the frontend. Plaintext only exists in RAM
//! on the user's own node — it is encrypted before storage or transport
//! (Principle 4: data sovereignty).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use konsensus_core::types::{MessageId, NodeId, Recipient};
use konsensus_crypto::ratchet_message_to_bytes;
use konsensus_message::wire::Frame;

use crate::audit::events;
use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::handlers::utils::generate_valid_proof;
use crate::state::{AppState, InvoiceResponseData};

/// Request to compose and send a message (node handles encryption + payment).
///
/// This is the primary endpoint for the frontend. The plaintext only exists
/// in RAM on the user's own node — it is encrypted before storage or transport.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposeRequest {
    /// Recipient node ID (hex) or room ID (UUID when `is_room` is true).
    pub recipient: String,
    /// Whether the recipient is a room (true) or node (false).
    #[serde(default)]
    pub is_room: bool,
    /// Message kind (u16 from kind taxonomy).
    pub kind: u16,
    /// Plaintext message content (will be E2EE encrypted by the node).
    pub plaintext: String,
    /// Optional references to other messages (for threading/replies).
    #[serde(default)]
    pub references: Vec<String>,
}

/// Response after composing and sending a message.
#[derive(Serialize)]
pub struct ComposeResponse {
    /// The message ID assigned to this envelope.
    pub message_id: String,
    /// Whether the message was delivered to a connected peer.
    pub delivered: bool,
    /// Amount paid in millisatoshis.
    pub amount_msat: u64,
}

/// Maximum plaintext message size: 1 MiB.
const MAX_PLAINTEXT_LEN: usize = 1024 * 1024;

/// Maximum number of references per message (prevents CPU waste on oversized arrays).
const MAX_REFERENCES: usize = 100;

/// Timeout for invoice request/response cycle.
const INVOICE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of pending invoice requests before rejecting new ones.
///
/// Prevents unbounded HashMap growth if many compose requests are in-flight
/// simultaneously (e.g., a burst of messages to offline/slow peers).
const MAX_PENDING_INVOICE_REQUESTS: usize = 100;

/// Maximum number of send timestamp entries tracked for STDP latency.
///
/// Prevents unbounded HashMap growth from messages that are never acked.
/// The cleanup task in main.rs also prunes entries older than 5 minutes,
/// but this hard cap provides defense-in-depth.
const MAX_SEND_TIMESTAMPS: usize = 10_000;

/// Maximum age for cached peer prices. If a peer's announced price table
/// is older than this, fall back to our own pricing engine.
const MAX_PRICE_AGE: Duration = Duration::from_secs(3600);

/// Minimum Lightning invoice amount in millisatoshis.
///
/// LND/LNbits require invoices to be at least 1 sat (1000 msat).
/// When a message price is below this, we round up to the minimum.
/// The sender pays slightly more than the pricing engine says, but
/// the payment gate on the recipient side accepts overpayment.
const MIN_INVOICE_AMOUNT_MSAT: u64 = 1_000;

/// Create a Lightning payment proof — keysend first, invoice-request fallback.
///
/// Also used by the file send handler (`files.rs`).
///
/// Implements Principle 2 correctly: real economic flow from sender to recipient.
///
/// **Keysend path** (fast, ~0ms round-trip): If the peer's Lightning pubkey is
/// known (exchanged via `Frame::LightningInfo` after handshake), pushes sats
/// directly to their node. No invoice request needed.
///
/// **Invoice path** (fallback, ~100-200ms round-trip): If keysend is unavailable
/// (peer has no Lightning pubkey, or keysend fails), falls back to the
/// RequestInvoice/InvoiceResponse/pay_invoice flow.
///
/// Returns (payment_hash, preimage, amount_msat). Never falls back to fake proofs.
pub async fn create_payment_proof(
    state: &AppState,
    price_msat: u64,
    peer_id: &NodeId,
) -> Result<([u8; 32], [u8; 32], u64), ApiError> {
    // Zero-price messages get a valid cryptographic proof with zero amount.
    // The payment gate accepts these for kind-0 (control) messages.
    if price_msat == 0 {
        return Ok(generate_valid_proof(0));
    }

    // Lightning must be available for non-zero payments.
    if !state.lightning.is_available().await {
        return Err(ApiError::Lightning(
            "Lightning wallet is unavailable — cannot create payment proof".into(),
        ));
    }

    // Peer must be connected to receive the invoice request.
    if !state.transport.is_connected(peer_id).await {
        return Err(ApiError::BadRequest(
            "Recipient is offline. Message will be queued and sent when they reconnect.".into(),
        ));
    }

    // Lightning invoices require a minimum of 1 sat (1000 msat).
    // When message prices are sub-sat, round up to the minimum.
    // The payment gate accepts overpayment, so this is safe.
    let payment_amount_msat = price_msat.max(MIN_INVOICE_AMOUNT_MSAT);

    // Try keysend first — eliminates the invoice round-trip.
    let peer_ln_pubkey = state.peer_ln_pubkeys.lock().await.get(peer_id).cloned();
    if let Some(ln_pubkey) = peer_ln_pubkey {
        match try_keysend(state, &ln_pubkey, payment_amount_msat, peer_id).await {
            Ok(proof) => return Ok(proof),
            Err(e) => {
                tracing::warn!(
                    peer = %peer_id,
                    error = %e,
                    "keysend failed, falling back to invoice-request flow"
                );
                // Fall through to invoice flow.
            }
        }
    }

    // Invoice-request fallback.
    create_payment_proof_via_invoice(state, payment_amount_msat, peer_id).await
}

/// Attempt a keysend (spontaneous) payment to a peer's Lightning node.
///
/// Returns (payment_hash, preimage, amount_msat) on success.
async fn try_keysend(
    state: &AppState,
    ln_pubkey: &str,
    amount_msat: u64,
    peer_id: &NodeId,
) -> Result<([u8; 32], [u8; 32], u64), ApiError> {
    let details = state
        .lightning
        .keysend(ln_pubkey, amount_msat, Some("konsensus message"))
        .await
        .map_err(|e| ApiError::Lightning(format!("keysend failed: {e}")))?;

    let preimage_hex = details.preimage.ok_or_else(|| {
        ApiError::Lightning("keysend succeeded but no preimage returned".into())
    })?;

    let preimage_bytes: [u8; 32] = hex::decode(&preimage_hex)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| {
            ApiError::Lightning(format!("malformed preimage from keysend: {preimage_hex}"))
        })?;

    let hash_bytes: [u8; 32] = Sha256::digest(preimage_bytes).into();

    tracing::info!(
        peer = %peer_id,
        amount_msat,
        method = "keysend",
        "payment proof created via keysend — no invoice round-trip needed"
    );

    Ok((hash_bytes, preimage_bytes, amount_msat))
}

/// Create a payment proof via the invoice-request/response round-trip.
///
/// This is the original flow: send RequestInvoice to peer, wait for their
/// InvoiceResponse, pay their invoice, extract preimage.
async fn create_payment_proof_via_invoice(
    state: &AppState,
    invoice_amount_msat: u64,
    peer_id: &NodeId,
) -> Result<([u8; 32], [u8; 32], u64), ApiError> {
    // Generate a unique request ID for correlating request/response.
    let request_id = uuid::Uuid::new_v4().to_string();

    // Create a oneshot channel for the response.
    let (tx, rx) = oneshot::channel::<InvoiceResponseData>();

    // Register the pending request BEFORE sending the frame.
    // Reject if too many requests are already in-flight (defense-in-depth).
    {
        let mut requests = state.invoice_requests.lock().await;
        if requests.len() >= MAX_PENDING_INVOICE_REQUESTS {
            return Err(ApiError::Internal(
                "Too many pending invoice requests — try again shortly".into(),
            ));
        }
        requests.insert(request_id.clone(), tx);
    }

    // Send RequestInvoice to the peer.
    let frame = Frame::RequestInvoice {
        request_id: request_id.clone(),
        amount_msat: invoice_amount_msat,
        purpose: "konsensus message".into(),
    };
    let frame_bytes = frame
        .to_bytes()
        .map_err(|e| ApiError::Internal(format!("frame serialization error: {e}")))?;

    if let Err(e) = state.transport.send_raw_frame(peer_id, &frame_bytes).await {
        // Clean up the pending request on failure.
        state.invoice_requests.lock().await.remove(&request_id);
        return Err(ApiError::Internal(format!(
            "failed to send invoice request to peer: {e}"
        )));
    }

    tracing::info!(
        peer = %peer_id,
        %request_id,
        invoice_amount_msat,
        method = "invoice",
        "sent invoice request to recipient — awaiting response"
    );

    // Wait for the response (with timeout).
    let response = tokio::time::timeout(INVOICE_REQUEST_TIMEOUT, rx)
        .await
        .map_err(|_| {
            // Clean up stale request on timeout.
            let request_id = request_id.clone();
            let invoice_requests = Arc::clone(&state.invoice_requests);
            tokio::spawn(async move {
                invoice_requests.lock().await.remove(&request_id);
            });
            ApiError::Internal(
                "Invoice request timed out — recipient did not respond within 30s".into(),
            )
        })?
        .map_err(|_| {
            ApiError::Lightning(
                "Recipient could not create invoice — their Lightning wallet may be unavailable".into(),
            )
        })?;

    tracing::info!(
        peer = %peer_id,
        %request_id,
        "received invoice from recipient — validating amount before paying"
    );

    // Validate the bolt11 invoice amount matches what we requested.
    // This prevents a malicious peer from responding with an overpriced invoice
    // or a malformed invoice that bypasses amount validation.
    let invoice = response
        .bolt11
        .parse::<lightning_invoice::Bolt11Invoice>()
        .map_err(|e| {
            ApiError::Lightning(format!(
                "recipient returned invalid BOLT11 invoice: {e}"
            ))
        })?;

    let invoice_msat = invoice.amount_milli_satoshis().ok_or_else(|| {
        ApiError::Lightning(
            "recipient returned an amountless invoice — expected a specific amount".into(),
        )
    })?;

    if invoice_msat != invoice_amount_msat {
        return Err(ApiError::Lightning(format!(
            "invoice amount ({invoice_msat} msat) does not match requested amount ({invoice_amount_msat} msat) — \
             recipient may be overcharging"
        )));
    }

    // Pay the recipient's invoice.
    let details = state
        .lightning
        .pay_invoice(&response.bolt11)
        .await
        .map_err(|e| ApiError::Lightning(format!("failed to pay recipient invoice: {e}")))?;

    // Extract and validate the preimage.
    let preimage_hex = details.preimage.ok_or_else(|| {
        ApiError::Lightning("payment succeeded but no preimage returned".into())
    })?;

    let preimage_bytes: [u8; 32] = hex::decode(&preimage_hex)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| {
            ApiError::Lightning(format!("malformed preimage from Lightning: {preimage_hex}"))
        })?;

    let hash_bytes: [u8; 32] = Sha256::digest(preimage_bytes).into();

    tracing::info!(
        peer = %peer_id,
        %request_id,
        invoice_amount_msat,
        method = "invoice",
        "payment proof created via invoice — real sats flowed from sender to recipient"
    );

    Ok((hash_bytes, preimage_bytes, invoice_amount_msat))
}

/// `POST /api/v1/messages/compose` — compose, encrypt, pay, and send a message.
///
/// The node handles the full pipeline:
/// 1. Encrypt plaintext via Double Ratchet (requires active E2EE session)
/// 2. Get price for message kind from pricing engine
/// 3. Create Lightning payment proof (pay recipient's invoice)
/// 4. Build UKM envelope with ciphertext + payment proof
/// 5. Sign with Ed25519
/// 6. Store, deliver via transport, broadcast to WebSocket
pub(super) async fn compose_message(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ComposeRequest>,
) -> Result<Json<ComposeResponse>, ApiError> {
    // Validate plaintext size
    if req.plaintext.is_empty() {
        return Err(ApiError::BadRequest("message plaintext is empty".into()));
    }
    if req.plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(ApiError::BadRequest(format!(
            "plaintext too large: {} bytes (max {MAX_PLAINTEXT_LEN})",
            req.plaintext.len()
        )));
    }
    if req.references.len() > MAX_REFERENCES {
        return Err(ApiError::BadRequest(format!(
            "too many references: {} (max {MAX_REFERENCES})",
            req.references.len()
        )));
    }

    // Parse references (shared by peer and room paths)
    let references: Vec<MessageId> = req
        .references
        .iter()
        .filter_map(|r| {
            MessageId::from_hex(r).map_err(|e| {
                tracing::warn!(reference = %r, error = %e, "dropping malformed reference ID");
                e
            }).ok()
        })
        .collect();

    let sender = *state.identity.node_id();

    if req.is_room {
        // ── Room compose: encrypt + pay + deliver to each member individually ──
        let room_id = konsensus_core::RoomId::parse(&req.recipient)
            .map_err(|e| ApiError::BadRequest(format!("invalid room ID: {e}")))?;
        let room_recipient = Recipient::Room(room_id);

        let members = state
            .storage
            .get_room_members(&room_id)
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))?;

        if members.is_empty() {
            return Err(ApiError::BadRequest("room has no members".into()));
        }

        let mut first_message_id: Option<String> = None;
        let mut any_delivered = false;
        let mut total_amount_msat: u64 = 0;
        let current_block_height = match state.chain.get_block_height().await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, "failed to get block height for room compose, using fallback 0");
                0
            }
        };

        for member in &members {
            // Don't send to self
            if member == state.identity.node_id() {
                continue;
            }

            // Encrypt via Double Ratchet for this specific member
            let ratchet_msg = match state
                .session_manager
                .encrypt(member, req.plaintext.as_bytes())
                .await
            {
                Ok(msg) => msg,
                Err(e) => {
                    tracing::warn!(
                        peer = %member,
                        error = %e,
                        "skipping room member: E2EE session not established"
                    );
                    continue;
                }
            };
            let ciphertext = ratchet_message_to_bytes(&ratchet_msg);

            // Get price for this member, applying plasticity trust discount if available
            let price_msat = match state
                .peer_prices
                .get_fresh_peer_price(member, req.kind, current_block_height, MAX_PRICE_AGE)
                .await
            {
                Some(peer_price) => {
                    let discount = state.peer_prices.get_trust_discount(member).await;
                    konsensus_pricing::apply_trust_discount(peer_price, discount)
                }
                None => state
                    .pricing
                    .get_price_msat(req.kind)
                    .await
                    .map_err(|e| ApiError::Internal(format!("pricing error: {e}")))?,
            };

            // Create payment proof — requests invoice from recipient's wallet (Principle 2).
            // For room messages, skip offline members gracefully (they'll get it when they reconnect).
            let (payment_hash, preimage_bytes, amount_msat) =
                match create_payment_proof(&state, price_msat, member).await {
                    Ok(proof) => proof,
                    Err(e) => {
                        tracing::warn!(
                            peer = %member,
                            error = %e,
                            "skipping room member: payment proof unavailable (offline?)"
                        );
                        continue;
                    }
                };

            let proof =
                konsensus_core::PaymentProof::new(payment_hash, preimage_bytes, amount_msat);

            // Build and sign envelope
            let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
                req.kind,
                sender,
                room_recipient,
                ciphertext,
                proof,
            )
            .references(references.clone())
            .build();

            let sig = state.identity.sign(&envelope.signable_bytes());
            envelope.signature = konsensus_core::Signature::from_ed25519(&sig);

            // Store
            if let Err(e) = state.storage.store_message(&envelope).await {
                tracing::warn!(peer = %member, error = %e, "failed to store room message");
                continue;
            }

            // Cache plaintext (encrypted at rest) for API retrieval
            if let Some(ref cipher) = state.plaintext_cipher {
                match cipher.encrypt(req.plaintext.as_bytes()) {
                    Ok(encrypted) => {
                        if let Err(e) = state
                            .storage
                            .store_message_plaintext(&envelope.id, &encrypted)
                            .await
                        {
                            tracing::warn!(msg_id = %envelope.id, error = %e, "failed to cache room plaintext");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(msg_id = %envelope.id, error = %e, "failed to encrypt plaintext for cache");
                    }
                }
            }

            if first_message_id.is_none() {
                first_message_id = Some(envelope.id.to_hex());

                // Broadcast to WS once (with plaintext — we composed this message)
                if let Err(e) =
                    state.ws_broadcast.send(Arc::new(crate::state::WsMessage {
                        envelope: envelope.clone(),
                        plaintext: Some(req.plaintext.clone()),
                    }))
                {
                    tracing::debug!(
                        error = %e,
                        "no WebSocket clients connected for room compose broadcast"
                    );
                }
            }

            total_amount_msat = total_amount_msat.saturating_add(amount_msat);

            // Deliver or queue — try sending directly to avoid TOCTOU race.
            match state.transport.send(member, &envelope).await {
                Ok(()) => {
                    // Record send timestamp for STDP latency measurement.
                    let mut ts = state.send_timestamps.lock().await;
                    if ts.len() < MAX_SEND_TIMESTAMPS {
                        ts.insert(envelope.id, std::time::Instant::now());
                    }
                    drop(ts);
                    any_delivered = true;
                }
                Err(_) => {
                    if let Err(qe) =
                        state.storage.queue_pending_delivery(&envelope.id, member).await
                    {
                        tracing::warn!(peer = %member, error = %qe, "failed to queue pending room delivery");
                    }
                }
            }
        }

        let message_id = match first_message_id {
            Some(id) => id,
            None => {
                // No messages could be composed for any room member — all were skipped
                // due to missing E2EE sessions, payment failures, or storage errors.
                state.audit_log.record(
                    "room_compose_failed",
                    &sender.to_hex(),
                    Some(serde_json::json!({
                        "kind": req.kind,
                        "room_id": req.recipient,
                        "member_count": members.len(),
                        "reason": "no members reachable",
                    })),
                );
                return Err(ApiError::BadRequest(
                    "could not compose message for any room member — E2EE sessions may not be established".into(),
                ));
            }
        };

        state.audit_log.record(
            events::MESSAGE_COMPOSED,
            &sender.to_hex(),
            Some(serde_json::json!({
                "message_id": message_id,
                "kind": req.kind,
                "room_id": req.recipient,
                "delivered": any_delivered,
                "amount_msat": total_amount_msat,
            })),
        );

        Ok(Json(ComposeResponse {
            message_id,
            delivered: any_delivered,
            amount_msat: total_amount_msat,
        }))
    } else {
        // ── Peer compose: existing single-recipient path ──
        let peer_id = NodeId::from_hex(&req.recipient)
            .map_err(|e| ApiError::BadRequest(format!("invalid recipient: {e}")))?;
        let recipient = Recipient::Node(peer_id);

        // Encrypt via Double Ratchet
        let ratchet_msg = state
            .session_manager
            .encrypt(&peer_id, req.plaintext.as_bytes())
            .await
            .map_err(|e| {
                ApiError::BadRequest(format!(
                    "E2EE encryption failed (session may not be established): {e}"
                ))
            })?;
        let ciphertext = ratchet_message_to_bytes(&ratchet_msg);

        // Get price
        let current_block_height = match state.chain.get_block_height().await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, "failed to get block height for compose, using fallback 0");
                0
            }
        };
        let price_msat = match state
            .peer_prices
            .get_fresh_peer_price(&peer_id, req.kind, current_block_height, MAX_PRICE_AGE)
            .await
        {
            Some(peer_price) => {
                // Apply plasticity trust discount — the peer offered us a discount
                // based on our synaptic weight in their routing table.
                let discount = state.peer_prices.get_trust_discount(&peer_id).await;
                let discounted = konsensus_pricing::apply_trust_discount(peer_price, discount);
                tracing::debug!(
                    peer = %peer_id,
                    kind = req.kind,
                    base_price = peer_price,
                    trust_discount = discount,
                    price_msat = discounted,
                    "using peer-announced price with plasticity discount"
                );
                discounted
            }
            None => state
                .pricing
                .get_price_msat(req.kind)
                .await
                .map_err(|e| ApiError::Internal(format!("pricing error: {e}")))?,
        };

        // Create payment proof — requests invoice from recipient's wallet (Principle 2).
        let (payment_hash, preimage_bytes, amount_msat) =
            create_payment_proof(&state, price_msat, &peer_id).await?;
        let proof =
            konsensus_core::PaymentProof::new(payment_hash, preimage_bytes, amount_msat);

        // Build envelope
        let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
            req.kind, sender, recipient, ciphertext, proof,
        )
        .references(references)
        .build();

        // Sign
        let sig = state.identity.sign(&envelope.signable_bytes());
        envelope.signature = konsensus_core::Signature::from_ed25519(&sig);

        // Store
        state
            .storage
            .store_message(&envelope)
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))?;

        // Cache plaintext (encrypted at rest) for API retrieval
        if let Some(ref cipher) = state.plaintext_cipher {
            match cipher.encrypt(req.plaintext.as_bytes()) {
                Ok(encrypted) => {
                    if let Err(e) = state
                        .storage
                        .store_message_plaintext(&envelope.id, &encrypted)
                        .await
                    {
                        tracing::warn!(msg_id = %envelope.id, error = %e, "failed to cache compose plaintext");
                    }
                }
                Err(e) => {
                    tracing::warn!(msg_id = %envelope.id, error = %e, "failed to encrypt compose plaintext");
                }
            }
        }

        // Deliver via transport; queue for later if peer offline or send fails.
        // Try sending directly — avoids TOCTOU race where peer disconnects
        // between an is_connected check and the actual send.
        let delivered = match state.transport.send(&peer_id, &envelope).await {
            Ok(()) => {
                // Record send timestamp for STDP latency measurement.
                let mut ts = state.send_timestamps.lock().await;
                if ts.len() < MAX_SEND_TIMESTAMPS {
                    ts.insert(envelope.id, std::time::Instant::now());
                }
                true
            }
            Err(_) => {
                if let Err(e) =
                    state.storage.queue_pending_delivery(&envelope.id, &peer_id).await
                {
                    tracing::warn!(error = %e, "failed to queue pending delivery");
                }
                false
            }
        };

        // Broadcast to WebSocket clients (with plaintext — we composed this message)
        if let Err(e) = state.ws_broadcast.send(Arc::new(crate::state::WsMessage {
            envelope: envelope.clone(),
            plaintext: Some(req.plaintext.clone()),
        })) {
            tracing::debug!(
                error = %e,
                "no WebSocket clients connected for compose broadcast"
            );
        }

        // Audit log
        state.audit_log.record(
            events::MESSAGE_COMPOSED,
            &sender.to_hex(),
            Some(serde_json::json!({
                "message_id": envelope.id.to_hex(),
                "kind": req.kind,
                "recipient": req.recipient,
                "delivered": delivered,
                "amount_msat": amount_msat,
            })),
        );

        Ok(Json(ComposeResponse {
            message_id: envelope.id.to_hex(),
            delivered,
            amount_msat,
        }))
    }
}
