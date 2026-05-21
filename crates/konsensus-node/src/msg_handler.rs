//! Incoming message handler — routes P2P messages through the payment gate to storage + WebSocket.
//!
//! This module implements PRINCIPLE 2: every incoming message MUST pass the payment gate
//! (fail-closed). Messages that pass are stored, decrypted if an E2EE session exists,
//! broadcast to WebSocket clients, and acknowledged back to the sender.

use std::sync::Arc;

use tokio::sync::broadcast;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use konsensus_core::identity::NodeIdentity;
use konsensus_core::traits::chain::ChainProvider;
use konsensus_core::traits::lightning::LightningProvider;
use konsensus_core::traits::transport::MessageTransport;
use konsensus_crypto::{PlaintextCacheCipher, SessionManager};
use konsensus_message::peer::PeerRegistry;
use konsensus_message::NoiseTransport;

use konsensus_api::audit::AuditLog;
use konsensus_api::state::WsMessage;
use konsensus_core::gate::PaymentGate;
use konsensus_message::Frame;
use konsensus_routing::RoutingTable;

use crate::content_server::ContentServer;

/// All dependencies needed by the incoming message handler task.
pub(crate) struct MsgHandlerDeps {
    pub transport: Arc<NoiseTransport>,
    pub transport_ack: Arc<NoiseTransport>,
    pub storage: Arc<dyn konsensus_storage::Storage>,
    pub gate: Arc<PaymentGate>,
    pub pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine>,
    pub lightning: Arc<dyn LightningProvider>,
    pub chain: Arc<dyn ChainProvider>,
    pub peer_registry: Arc<tokio::sync::RwLock<PeerRegistry>>,
    pub session_manager: Arc<SessionManager>,
    pub nonce_adapter: Arc<konsensus_storage::StorageNonceAdapter<dyn konsensus_storage::Storage>>,
    pub content_server: Option<Arc<ContentServer>>,
    pub routing: Arc<RoutingTable>,
    pub identity: Arc<NodeIdentity>,
    pub plaintext_cipher: Arc<PlaintextCacheCipher>,
    pub ws_tx: broadcast::Sender<Arc<WsMessage>>,
    pub audit_log: Arc<AuditLog>,
    pub shutdown_rx: watch::Receiver<bool>,
}

/// Runs the incoming message handler loop.
///
/// Receives envelopes from the transport, validates them through the payment gate,
/// stores them, decrypts if possible, and broadcasts to WebSocket clients.
pub(crate) async fn run(deps: MsgHandlerDeps) {
    let MsgHandlerDeps {
        transport: transport_for_recv,
        transport_ack: transport_for_ack,
        storage: storage_for_recv,
        gate: gate_for_recv,
        pricing: pricing_for_recv,
        lightning: lightning_for_recv,
        chain: chain_for_recv,
        peer_registry: peer_registry_for_recv,
        session_manager: session_mgr_for_recv,
        nonce_adapter,
        content_server: content_server_for_recv,
        routing: routing_for_recv,
        identity: identity_for_recv,
        plaintext_cipher,
        ws_tx: ws_tx_for_recv,
        audit_log: audit_for_recv,
        mut shutdown_rx,
    } = deps;

    loop {
        tokio::select! {
            result = transport_for_recv.recv() => {
                match result {
                    Ok(envelope) => {
                        // PRINCIPLE 2: Every incoming message MUST pass the payment gate.
                        // Fail-closed: any verification failure = message rejected.
                        let whitelist = peer_registry_for_recv
                            .read()
                            .await
                            .whitelist()
                            .into_iter()
                            .collect::<std::collections::HashSet<_>>();

                        let sender = envelope.sender;
                        let msg_id = envelope.id;

                        // Compute plasticity trust discount from sender's synaptic weight.
                        // Trusted peers (high weight) get lower required payment.
                        let trust_discount = routing_for_recv
                            .get_peer_weight(&sender)
                            .await
                            .map(konsensus_pricing::compute_trust_discount)
                            .unwrap_or(0.0);

                        if let Err(rejection) = gate_for_recv
                            .verify(
                                &envelope,
                                nonce_adapter.as_ref(),
                                pricing_for_recv.as_ref(),
                                Some(&whitelist),
                                Some(lightning_for_recv.as_ref()),
                                trust_discount,
                            )
                            .await
                        {
                            // Increment the appropriate Prometheus counter based on
                            // rejection type so alert rules can fire on the right signal.
                            match &rejection {
                                konsensus_core::gate::GateRejection::NotWhitelisted(_) => {
                                    metrics::counter!(
                                        konsensus_api::metrics::WHITELIST_REJECTIONS
                                    )
                                    .increment(1);
                                }
                                konsensus_core::gate::GateRejection::InsufficientPayment { .. }
                                | konsensus_core::gate::GateRejection::PaymentNotSettled(_)
                                | konsensus_core::gate::GateRejection::LightningUnavailable(_) => {
                                    metrics::counter!(
                                        konsensus_api::metrics::PAYMENT_FAILURES
                                    )
                                    .increment(1);
                                }
                                _ => {}
                            }

                            warn!(
                                sender = %sender,
                                kind = envelope.kind,
                                error = %rejection,
                                "payment gate REJECTED incoming message"
                            );
                            audit_for_recv.record(
                                konsensus_api::audit::events::MESSAGE_REJECTED,
                                &sender.to_hex(),
                                Some(serde_json::json!({
                                    "reason": rejection.to_string(),
                                    "kind": envelope.kind,
                                })),
                            );
                            // Send MessageReject back to sender
                            let reject = Frame::MessageReject {
                                id: msg_id,
                                reason: rejection.to_string(),
                            };
                            if let Err(e) = transport_for_ack.send_frame(&sender, &reject).await {
                                warn!(peer = %sender, error = %e, "failed to send MessageReject");
                            }

                            // On pricing mismatch, proactively send our current price table
                            // so the sender can update their cache and retry successfully.
                            if matches!(rejection, konsensus_core::gate::GateRejection::InsufficientPayment { .. }) {
                                let meta = konsensus_pricing::peer_prices::build_full_price_table(
                                    pricing_for_recv.as_ref(),
                                    chain_for_recv.as_ref(),
                                ).await;
                                let peer_discount = routing_for_recv
                                    .get_peer_weight(&sender)
                                    .await
                                    .map(konsensus_pricing::compute_trust_discount)
                                    .unwrap_or(0.0);
                                let price_frame = Frame::PriceTable {
                                    prices: meta.prices,
                                    block_height: meta.block_height,
                                    valid_blocks: meta.valid_blocks,
                                    trust_discount: peer_discount,
                                };
                                if let Err(e) = transport_for_ack.send_frame(&sender, &price_frame).await {
                                    warn!(peer = %sender, error = %e, "failed to send corrective price table");
                                } else {
                                    info!(peer = %sender, "sent corrective price table after payment mismatch");
                                }
                            }
                            continue;
                        }

                        // Gate passed — store the message (must succeed before ACK)
                        if let Err(e) = storage_for_recv.store_message(&envelope).await {
                            error!(error = %e, "failed to store incoming message — rejecting");
                            let reject = Frame::MessageReject {
                                id: msg_id,
                                reason: "storage error".to_string(),
                            };
                            if let Err(e) = transport_for_ack.send_frame(&sender, &reject).await {
                                warn!(peer = %sender, error = %e, "failed to send MessageReject after storage failure");
                            }
                            continue;
                        }

                        // Attempt to decrypt ciphertext via Double Ratchet session
                        let plaintext = decrypt_and_process(
                            &envelope,
                            &sender,
                            &session_mgr_for_recv,
                            &plaintext_cipher,
                            &storage_for_recv,
                            &content_server_for_recv,
                            &chain_for_recv,
                            &pricing_for_recv,
                            &identity_for_recv,
                            &transport_for_ack,
                            &audit_for_recv,
                        ).await;

                        // Broadcast to WebSocket clients (with plaintext if decrypted)
                        if let Err(e) = ws_tx_for_recv.send(Arc::new(
                            WsMessage {
                                envelope,
                                plaintext,
                            },
                        )) {
                            debug!(error = %e, "no WebSocket clients connected for incoming message broadcast");
                        }

                        // Send MessageAck back to sender
                        let ack = Frame::MessageAck { id: msg_id };
                        if let Err(e) = transport_for_ack.send_frame(&sender, &ack).await {
                            warn!(peer = %sender, error = %e, "failed to send MessageAck");
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "transport recv error");
                        break;
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("message handler shutting down");
                break;
            }
        }
    }
}

/// Decrypts an incoming envelope and processes special message kinds (files, web content).
///
/// Returns the plaintext string if decryption succeeded, or None if no session exists
/// or decryption failed (triggers session re-negotiation).
#[allow(clippy::too_many_arguments)]
async fn decrypt_and_process(
    envelope: &konsensus_core::UkmEnvelope,
    sender: &konsensus_core::types::NodeId,
    session_mgr: &SessionManager,
    plaintext_cipher: &PlaintextCacheCipher,
    storage: &Arc<dyn konsensus_storage::Storage>,
    content_server: &Option<Arc<ContentServer>>,
    chain: &Arc<dyn ChainProvider>,
    pricing: &Arc<dyn konsensus_core::traits::pricing::PricingEngine>,
    identity: &Arc<NodeIdentity>,
    transport: &Arc<NoiseTransport>,
    audit: &Arc<AuditLog>,
) -> Option<String> {
    if !session_mgr.has_session(sender).await {
        debug!(sender = %sender, "no E2EE session, cannot decrypt");
        return None;
    }

    let ratchet_msg = match konsensus_crypto::ratchet_message_from_bytes(&envelope.ciphertext) {
        Ok(msg) => msg,
        Err(e) => {
            debug!(sender = %sender, error = %e, "ciphertext is not a valid ratchet message");
            return None;
        }
    };

    let bytes = match session_mgr.decrypt(sender, &ratchet_msg).await {
        Ok(bytes) => bytes,
        Err(e) => {
            // Decryption failed — session is likely stale (peer re-established with different keys).
            // Remove the broken session so the session handler can re-negotiate.
            warn!(
                sender = %sender,
                error = %e,
                "decryption failed, removing stale session for re-negotiation"
            );
            session_mgr.remove_session(sender).await;
            // Send our PrekeyOffer to trigger re-negotiation
            let bundle = session_mgr.prekey_bundle().await;
            if let Ok(bundle_json) = serde_json::to_value(&bundle) {
                let frame = Frame::PrekeyOffer { bundle: bundle_json };
                if let Err(e) = transport.send_frame(sender, &frame).await {
                    warn!(peer = %sender, error = %e, "failed to send PrekeyOffer for re-negotiation");
                }
            }
            return None;
        }
    };

    // Cache decrypted plaintext (encrypted at rest) for API access
    match plaintext_cipher.encrypt(&bytes) {
        Ok(encrypted) => {
            if let Err(e) = storage.store_message_plaintext(&envelope.id, &encrypted).await {
                warn!(msg_id = %envelope.id, error = %e, "failed to cache plaintext");
            }
        }
        Err(e) => {
            warn!(msg_id = %envelope.id, error = %e, "failed to encrypt plaintext for cache");
        }
    }

    // Route based on message kind
    if envelope.kind == konsensus_core::kind::KIND_FILE_REF {
        process_file_message(&bytes, sender, envelope, storage, audit).await
    } else if envelope.kind == konsensus_core::kind::KIND_CALENDAR_EVENT
        || envelope.kind == konsensus_core::kind::KIND_CALENDAR_UPDATE
    {
        process_calendar_event(&bytes, sender, envelope, storage).await
    } else if envelope.kind == konsensus_core::kind::KIND_RSVP {
        process_rsvp(&bytes, sender, envelope, storage).await
    } else if envelope.kind == konsensus_core::kind::KIND_WEB_MANIFEST {
        process_web_manifest(sender, content_server, chain, pricing, identity, session_mgr, transport).await
    } else if envelope.kind == konsensus_core::kind::KIND_PAGE_REQUEST {
        process_page_request(&bytes, sender, envelope, content_server, pricing, identity, session_mgr, transport, audit).await
    } else if konsensus_message::wire::is_realtime_signal(envelope.kind) {
        // Real-time signaling (400–499): log at INFO and relay plaintext to WebSocket.
        // Dedicated legacy Call* frame variants are rejected by the transport;
        // signaling must use this payment-gated UKM path.
        info!(
            sender = %sender,
            kind = envelope.kind,
            msg_id = %envelope.id,
            "received real-time signal — forwarding to frontend"
        );
        match String::from_utf8(bytes) {
            Ok(text) => Some(text),
            Err(_) => {
                debug!(sender = %sender, kind = envelope.kind, "real-time signal payload is not UTF-8");
                None
            }
        }
    } else {
        match String::from_utf8(bytes) {
            Ok(text) => {
                debug!(sender = %sender, "decrypted incoming message");
                Some(text)
            }
            Err(_) => {
                debug!(sender = %sender, "decrypted content is not UTF-8");
                None
            }
        }
    }
}

/// Process an incoming file transfer message (KIND_FILE_REF).
async fn process_file_message(
    bytes: &[u8],
    sender: &konsensus_core::types::NodeId,
    envelope: &konsensus_core::UkmEnvelope,
    storage: &Arc<dyn konsensus_storage::Storage>,
    audit: &Arc<AuditLog>,
) -> Option<String> {
    let payload: konsensus_api::handlers::files::FilePayload = match serde_json::from_slice(bytes) {
        Ok(p) => p,
        Err(e) => {
            debug!(sender = %sender, error = %e, "KIND_FILE_REF payload not valid JSON");
            return None;
        }
    };

    let file_data = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &payload.data_b64,
    ) {
        Ok(data) => data,
        Err(e) => {
            warn!(sender = %sender, error = %e, "failed to decode base64 file data");
            return Some(format!("[file: {}]", payload.filename));
        }
    };

    let hash = blake3::hash(&file_data).to_hex().to_string();
    if hash != payload.blake3_hash {
        warn!(
            sender = %sender,
            filename = %payload.filename,
            expected = %payload.blake3_hash,
            actual = %hash,
            "file hash mismatch — file data corrupted, discarding"
        );
        audit.record(
            konsensus_api::audit::events::FILE_INTEGRITY_FAILED,
            &sender.to_hex(),
            Some(serde_json::json!({
                "filename": payload.filename,
                "expected_hash": payload.blake3_hash,
                "actual_hash": hash,
                "message_id": envelope.id.to_hex(),
            })),
        );
        return Some(format!("[file: {}]", payload.filename));
    }

    let file = konsensus_storage::FileRecord {
        id: uuid::Uuid::new_v4().to_string(),
        filename: payload.filename.clone(),
        mime_type: payload.mime_type.clone(),
        size_bytes: payload.size_bytes,
        blake3_hash: hash,
        sender: sender.to_hex(),
        message_id: Some(envelope.id.to_hex()),
        data: file_data,
        created_at: String::new(),
    };
    let file_id = file.id.clone();
    if let Err(e) = storage.store_file(&file).await {
        error!(error = %e, "failed to store received file");
    } else {
        info!(
            sender = %sender,
            file_id = %file_id,
            filename = %payload.filename,
            size = payload.size_bytes,
            "stored received file"
        );
        audit.record(
            konsensus_api::audit::events::FILE_RECEIVED,
            &sender.to_hex(),
            Some(serde_json::json!({
                "file_id": file_id,
                "filename": payload.filename,
                "size_bytes": payload.size_bytes,
                "message_id": envelope.id.to_hex(),
            })),
        );
    }

    Some(format!("[file: {}]", payload.filename))
}

/// Process an incoming calendar event (KIND_CALENDAR_EVENT or KIND_CALENDAR_UPDATE).
async fn process_calendar_event(
    bytes: &[u8],
    sender: &konsensus_core::types::NodeId,
    envelope: &konsensus_core::UkmEnvelope,
    storage: &Arc<dyn konsensus_storage::Storage>,
) -> Option<String> {
    let payload: konsensus_core::payloads::calendar::CalendarEventPayload =
        match serde_json::from_slice(bytes) {
            Ok(p) => p,
            Err(e) => {
                debug!(sender = %sender, error = %e, "calendar event payload not valid JSON");
                return None;
            }
        };

    let attendees_json = serde_json::to_string(&payload.attendees).unwrap_or_else(|_| "[]".into());
    let recurrence_json = payload
        .recurrence
        .as_ref()
        .and_then(|r| serde_json::to_string(r).ok());

    let record = konsensus_storage::CalendarEventRecord {
        id: payload.event_id.clone(),
        message_id: Some(envelope.id.to_hex()),
        organizer: payload.organizer.clone(),
        title: payload.title.clone(),
        description: payload.description.clone(),
        start_ms: payload.start_ms,
        end_ms: payload.end_ms,
        tz: payload.tz.clone(),
        location: payload.location.clone(),
        attendees_json,
        recurrence_json,
        color: payload.color.clone(),
        created_at: String::new(),
        parent_id: None,
    };

    if let Err(e) = storage.store_calendar_event(&record).await {
        warn!(
            sender = %sender,
            event_id = %payload.event_id,
            error = %e,
            "failed to store incoming calendar event"
        );
    } else {
        info!(
            sender = %sender,
            event_id = %payload.event_id,
            title = %payload.title,
            "stored incoming calendar event"
        );
    }

    Some(format!("[calendar: {}]", payload.title))
}

/// Process an incoming RSVP (KIND_RSVP).
async fn process_rsvp(
    bytes: &[u8],
    sender: &konsensus_core::types::NodeId,
    envelope: &konsensus_core::UkmEnvelope,
    storage: &Arc<dyn konsensus_storage::Storage>,
) -> Option<String> {
    let payload: konsensus_core::payloads::calendar::RsvpPayload =
        match serde_json::from_slice(bytes) {
            Ok(p) => p,
            Err(e) => {
                debug!(sender = %sender, error = %e, "RSVP payload not valid JSON");
                return None;
            }
        };

    let response_str = format!("{:?}", payload.response).to_lowercase();
    let record = konsensus_storage::RsvpRecord {
        id: uuid::Uuid::new_v4().to_string(),
        event_id: payload.event_id.clone(),
        responder: sender.to_hex(),
        response: response_str.clone(),
        comment: payload.comment.clone(),
        created_at: String::new(),
    };

    // Best-effort: the organizer stores the event locally; the attendee may not have it.
    let _ = storage.store_rsvp(&record).await;

    info!(
        sender = %sender,
        event_id = %payload.event_id,
        response = %response_str,
        msg_id = %envelope.id,
        "received RSVP"
    );

    Some(format!("[rsvp: {}]", response_str))
}

/// Process an incoming web manifest request (KIND_WEB_MANIFEST).
async fn process_web_manifest(
    sender: &konsensus_core::types::NodeId,
    content_server: &Option<Arc<ContentServer>>,
    chain: &Arc<dyn ChainProvider>,
    pricing: &Arc<dyn konsensus_core::traits::pricing::PricingEngine>,
    identity: &Arc<NodeIdentity>,
    session_mgr: &SessionManager,
    transport: &Arc<NoiseTransport>,
) -> Option<String> {
    let Some(cs) = content_server else {
        debug!(sender = %sender, "manifest request received but content server disabled");
        return Some("[web manifest request]".to_string());
    };

    let block_height = chain.get_block_height().await.unwrap_or(0);
    let default_price = pricing
        .get_price_msat(konsensus_core::kind::KIND_PAGE_RESPONSE)
        .await
        .unwrap_or(50);
    let manifest = cs.build_manifest(block_height, default_price);
    info!(sender = %sender, pages = manifest.pages.len(), "served web manifest");

    if session_mgr.can_send(sender).await {
        send_encrypted_response(
            sender,
            &manifest,
            konsensus_core::kind::KIND_WEB_MANIFEST,
            identity,
            session_mgr,
            pricing,
            transport,
        ).await;
    }

    Some("[web manifest request]".to_string())
}

/// Process an incoming page request (KIND_PAGE_REQUEST).
#[allow(clippy::too_many_arguments)]
async fn process_page_request(
    bytes: &[u8],
    sender: &konsensus_core::types::NodeId,
    envelope: &konsensus_core::UkmEnvelope,
    content_server: &Option<Arc<ContentServer>>,
    pricing: &Arc<dyn konsensus_core::traits::pricing::PricingEngine>,
    identity: &Arc<NodeIdentity>,
    session_mgr: &SessionManager,
    transport: &Arc<NoiseTransport>,
    audit: &Arc<AuditLog>,
) -> Option<String> {
    let page_req: konsensus_core::payloads::content::PageRequest = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => {
            debug!(sender = %sender, error = %e, "KIND_PAGE_REQUEST payload not valid JSON");
            return None;
        }
    };

    let Some(cs) = content_server else {
        debug!(sender = %sender, "page request received but content server disabled");
        return Some(format!("[page request: {}]", page_req.path));
    };

    let response = cs.handle_request(&page_req);
    info!(
        sender = %sender,
        path = %page_req.path,
        status = ?response.status,
        "handled page request"
    );

    if session_mgr.can_send(sender).await {
        send_encrypted_response(
            sender,
            &response,
            konsensus_core::kind::KIND_PAGE_RESPONSE,
            identity,
            session_mgr,
            pricing,
            transport,
        ).await;
    }

    audit.record(
        "page_served",
        &sender.to_hex(),
        Some(serde_json::json!({
            "path": page_req.path,
            "request_id": page_req.request_id,
        })),
    );

    // Also record from envelope for traceability
    let _ = envelope;

    Some(format!("[page request: {}]", page_req.path))
}

/// Encrypt and send a response envelope back to a peer.
async fn send_encrypted_response<T: serde::Serialize>(
    peer_id: &konsensus_core::types::NodeId,
    payload: &T,
    kind: u16,
    identity: &NodeIdentity,
    session_mgr: &SessionManager,
    pricing: &Arc<dyn konsensus_core::traits::pricing::PricingEngine>,
    transport: &Arc<NoiseTransport>,
) {
    let json_bytes = match serde_json::to_vec(payload) {
        Ok(b) => b,
        Err(e) => {
            warn!(peer = %peer_id, error = %e, "failed to serialize response payload");
            return;
        }
    };

    let ratchet_msg = match session_mgr.encrypt(peer_id, &json_bytes).await {
        Ok(msg) => msg,
        Err(e) => {
            warn!(peer = %peer_id, error = %e, "failed to encrypt response");
            return;
        }
    };

    let ciphertext = konsensus_crypto::ratchet_message_to_bytes(&ratchet_msg);
    let our_id = *identity.node_id();
    let price = pricing.get_price_msat(kind).await.unwrap_or(50);
    let (hash, preimage, amount) = konsensus_api::handlers::utils::generate_valid_proof(price);
    let proof = konsensus_core::PaymentProof::new(hash, preimage, amount);
    let mut resp_envelope = konsensus_core::UkmEnvelopeBuilder::new(
        kind,
        our_id,
        konsensus_core::Recipient::Node(*peer_id),
        ciphertext,
        proof,
    )
    .build();
    let sig = identity.sign(&resp_envelope.signable_bytes());
    resp_envelope.signature = konsensus_core::Signature::from_ed25519(&sig);

    if let Err(e) = transport.send(peer_id, &resp_envelope).await {
        warn!(peer = %peer_id, error = %e, "failed to send response envelope");
    }
}

#[cfg(test)]
#[path = "tests/msg_handler.rs"]
mod tests;
