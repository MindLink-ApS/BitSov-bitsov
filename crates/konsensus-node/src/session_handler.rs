//! Session and control event handler — orchestrates E2EE session establishment,
//! delivery confirmations, pricing exchange, invoice requests, and peer discovery.
//!
//! Flow (after federation handshake succeeds):
//! 1. PeerConnected → send our PrekeyOffer to peer
//! 2. Receive PrekeyOffer → if our NodeId < peer NodeId: initiate X3DH, send SessionInit;
//!    if our NodeId > peer NodeId: ignore (wait for SessionInit)
//! 3. Receive SessionInit → accept session, send SessionAck
//! 4. Receive SessionAck → send RatchetInit to finalize bidirectional E2EE
//!
//! The NodeId tiebreaker deterministically resolves the race where both sides
//! receive PrekeyOffer simultaneously. Lower NodeId always initiates.

use std::sync::Arc;

use ed25519_dalek::Verifier;
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, error, info, warn};

use konsensus_core::identity::NodeIdentity;
use konsensus_core::traits::chain::ChainProvider;
use konsensus_core::traits::lightning::LightningProvider;
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::types::NodeId;
use konsensus_crypto::SessionManager;
use konsensus_message::peer::PeerRegistry;
use konsensus_message::{ControlEvent, Frame, NoiseTransport};
use konsensus_pricing::PeerPriceCache;

use konsensus_api::audit::AuditLog;
use konsensus_api::state::WsDeliveryStatus;
use konsensus_api::InvoiceResponseData;

use crate::onboarding::auto_channel::AutoChannelEvent;
use crate::onboarding::funding_poll;

/// All dependencies needed by the session/control event handler task.
pub(crate) struct SessionHandlerDeps {
    pub transport: Arc<NoiseTransport>,
    pub session_manager: Arc<SessionManager>,
    pub storage: Arc<dyn konsensus_storage::Storage>,
    pub our_node_id: NodeId,
    pub identity: Arc<NodeIdentity>,
    pub audit_log: Arc<AuditLog>,
    pub pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine>,
    pub chain: Arc<dyn ChainProvider>,
    pub peer_prices: Arc<PeerPriceCache>,
    pub peer_registry: Arc<tokio::sync::RwLock<PeerRegistry>>,
    pub routing: Arc<konsensus_routing::RoutingTable>,
    pub gossip_validator: Arc<konsensus_gossip::GossipValidator>,
    pub send_timestamps: Arc<tokio::sync::Mutex<std::collections::HashMap<konsensus_core::types::MessageId, std::time::Instant>>>,
    pub lightning: Arc<dyn LightningProvider>,
    pub lightning_addr: Option<String>,
    pub invoice_requests: Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceResponseData>>>>,
    pub peer_ln_pubkeys: Arc<tokio::sync::Mutex<std::collections::HashMap<NodeId, String>>>,
    pub ws_broadcast: broadcast::Sender<Arc<konsensus_api::state::WsMessage>>,
    pub ws_delivery_tx: broadcast::Sender<Arc<WsDeliveryStatus>>,
    pub pending_tx: tokio::sync::mpsc::Sender<NodeId>,
    pub auto_channel_tx: mpsc::Sender<AutoChannelEvent>,
    pub shutdown_rx: watch::Receiver<bool>,
}

/// Per-peer session negotiation cooldown to prevent DoS via rapid
/// PrekeyOffer/SessionInit flooding. A whitelisted peer could otherwise
/// force expensive X3DH computations + storage churn with no rate limit.
const SESSION_NEGOTIATION_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(10);

/// Periodic self-heal cadence for connected peers that have Noise transport
/// but no bidirectional E2EE sending chain yet.
const SESSION_SELF_HEAL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Per-peer PeerExchange cooldown — prevents a peer from spamming
/// PeerExchange requests/responses to trigger expensive registry writes.
const PEER_EXCHANGE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);

/// Maximum number of peer exchange entries we process from a single response.
const MAX_PEER_EXCHANGE_ENTRIES: usize = 50;

/// Runs the session/control event handler loop.
pub(crate) async fn run(deps: SessionHandlerDeps) {
    let SessionHandlerDeps {
        transport,
        session_manager,
        storage,
        our_node_id,
        identity,
        audit_log,
        pricing,
        chain,
        peer_prices,
        peer_registry,
        routing,
        gossip_validator,
        send_timestamps,
        lightning,
        lightning_addr,
        invoice_requests,
        peer_ln_pubkeys,
        ws_broadcast,
        ws_delivery_tx,
        pending_tx,
        auto_channel_tx,
        mut shutdown_rx,
    } = deps;

    /// Maximum entries in cooldown maps before forced eviction to prevent
    /// memory exhaustion from a burst of unique peer identities.
    const MAX_COOLDOWN_ENTRIES: usize = 10_000;

    let mut last_negotiation: std::collections::HashMap<NodeId, tokio::time::Instant> =
        std::collections::HashMap::new();
    let mut last_peer_exchange: std::collections::HashMap<NodeId, tokio::time::Instant> =
        std::collections::HashMap::new();

    // Periodic cleanup interval for the cooldown maps to prevent unbounded growth.
    let mut cooldown_cleanup_interval = tokio::time::interval(std::time::Duration::from_secs(300));
    cooldown_cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Periodic E2EE self-heal. Transport supervision can reconnect peers after
    // restart/flap without a fresh application message; this loop makes the
    // session membrane repair itself without operator intervention.
    let mut session_self_heal_interval = tokio::time::interval(SESSION_SELF_HEAL_INTERVAL);
    session_self_heal_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            event = transport.recv_control() => {
                let Some(event) = event else {
                    info!("control channel closed, session handler exiting");
                    break;
                };

                match event {
                    ControlEvent::PeerConnected { peer_id } => {
                        handle_peer_connected(
                            &peer_id, &identity, &session_manager, &transport, &pricing,
                            &chain, &pending_tx, &lightning, &routing,
                            &lightning_addr,
                            &storage,
                            &ws_delivery_tx,
                            our_node_id,
                        ).await;
                    }

                    ControlEvent::PrekeyOffer { peer_id, bundle } => {
                        handle_prekey_offer(
                            &peer_id, bundle, our_node_id, &session_manager, &storage,
                            &transport, &audit_log, &mut last_negotiation,
                        ).await;
                    }

                    ControlEvent::SessionInit { peer_id, init_data } => {
                        handle_session_init(
                            &peer_id, init_data, &session_manager, &storage,
                            &transport, &audit_log, &mut last_negotiation,
                        ).await;
                    }

                    ControlEvent::SessionAck { peer_id } => {
                        handle_session_ack(
                            &peer_id, &session_manager, &transport, &audit_log,
                        ).await;
                    }

                    ControlEvent::RatchetInit { peer_id, payload } => {
                        handle_ratchet_init(
                            &peer_id, &payload, &session_manager, &storage, &transport,
                        ).await;
                    }

                    ControlEvent::MessageAcked { peer_id, message_id } => {
                        handle_message_acked(
                            &peer_id, &message_id, &send_timestamps, &storage,
                            &routing, &ws_delivery_tx,
                        ).await;
                    }

                    ControlEvent::MessageRejected { peer_id, message_id, reason } => {
                        handle_message_rejected(
                            &peer_id, &message_id, &reason, &routing, &ws_delivery_tx,
                        ).await;
                    }

                    ControlEvent::PriceTableReceived { peer_id, prices, block_height, valid_blocks, trust_discount } => {
                        info!(
                            peer = %peer_id,
                            categories = prices.len(),
                            block_height,
                            valid_blocks,
                            trust_discount,
                            "received peer price table"
                        );
                        peer_prices.update(peer_id, prices, block_height, valid_blocks, trust_discount).await;
                    }

                    ControlEvent::PriceQueryReceived { peer_id, kind } => {
                        handle_price_query(&peer_id, kind, &pricing, &chain, &transport).await;
                    }

                    ControlEvent::PriceResponseReceived { peer_id, kind, price_msat, block_height } => {
                        debug!(
                            peer = %peer_id, kind, price_msat, block_height,
                            "received price response, updating peer cache"
                        );
                        peer_prices.update_kind_price(peer_id, kind, price_msat, block_height).await;
                    }

                    ControlEvent::InvoiceRequested { peer_id, request_id, amount_msat, purpose } => {
                        handle_invoice_requested(
                            &peer_id, &request_id, amount_msat, &purpose,
                            &lightning, &transport,
                        ).await;
                    }

                    ControlEvent::InvoiceResponseReceived { peer_id, request_id, bolt11, payment_hash } => {
                        handle_invoice_response(
                            &peer_id, &request_id, bolt11, payment_hash, &invoice_requests,
                        ).await;
                    }

                    ControlEvent::InvoiceErrorReceived { peer_id, request_id, reason } => {
                        warn!(
                            peer = %peer_id, %request_id, %reason,
                            "peer reported invoice creation error — failing compose"
                        );
                        let mut requests = invoice_requests.lock().await;
                        // Remove and drop the sender — the compose handler's
                        // rx.await will return Err (channel closed).
                        requests.remove(&request_id);
                    }

                    ControlEvent::PeerExchangeRequested { peer_id } => {
                        handle_peer_exchange_request(
                            &peer_id, our_node_id, &peer_registry, &transport,
                            &mut last_peer_exchange,
                        ).await;
                    }

                    ControlEvent::PeerExchangeReceived { peer_id, peers } => {
                        handle_peer_exchange_received(
                            &peer_id, peers, our_node_id, &peer_registry,
                            &mut last_peer_exchange,
                        ).await;
                    }

                    ControlEvent::LightningInfoReceived { peer_id, ln_pubkey, ln_addr } => {
                        let valid = handle_lightning_info_received(
                            &peer_id, &ln_pubkey, &peer_ln_pubkeys,
                        ).await;
                        if valid {
                            match funding_poll::record_inviter_lightning_info(
                                storage.as_ref(),
                                &ws_delivery_tx,
                                &peer_id,
                                &ln_pubkey,
                            ).await {
                                Ok(true) => {
                                    funding_poll::ensure_poll_task(
                                        our_node_id.to_hex(),
                                        Arc::clone(&storage),
                                        Arc::clone(&lightning),
                                        ws_delivery_tx.clone(),
                                    ).await;
                                }
                                Ok(false) => {}
                                Err(e) => warn!(peer = %peer_id, error = %e, "failed to persist onboarding inviter Lightning info"),
                            }
                            let event = AutoChannelEvent::PeerLightningInfo {
                                peer_id,
                                ln_pubkey,
                                ln_addr,
                            };
                            if let Err(e) = auto_channel_tx.send(event).await {
                                warn!(peer = %peer_id, error = %e, "failed to queue auto-channel event");
                            }
                        }
                    }

                    ControlEvent::GossipReceived { from_peer, envelope } => {
                        handle_gossip_received(
                            from_peer, *envelope, &gossip_validator,
                            &transport, &audit_log, &ws_broadcast,
                        ).await;
                    }

                    ControlEvent::CallOfferReceived { peer_id, session_id, sdp } => {
                        warn!(
                            peer = %peer_id,
                            %session_id,
                            sdp_len = sdp.len(),
                            "rejected legacy unpaid call offer; use paid UKM realtime kind"
                        );
                    }

                    ControlEvent::CallAnswerReceived { peer_id, session_id, sdp } => {
                        warn!(
                            peer = %peer_id,
                            %session_id,
                            sdp_len = sdp.len(),
                            "rejected legacy unpaid call answer; use paid UKM realtime kind"
                        );
                    }

                    ControlEvent::IceCandidateReceived { peer_id, session_id, candidate } => {
                        warn!(
                            peer = %peer_id,
                            %session_id,
                            candidate_len = candidate.len(),
                            "rejected legacy unpaid ICE candidate; use paid UKM realtime kind"
                        );
                    }

                    ControlEvent::CallEndReceived { peer_id, session_id, reason } => {
                        warn!(
                            peer = %peer_id,
                            %session_id,
                            %reason,
                            "rejected legacy unpaid call end; use paid UKM realtime kind"
                        );
                    }
                }
            }
            // Periodically prune stale entries from cooldown maps.
            _ = cooldown_cleanup_interval.tick() => {
                let now = tokio::time::Instant::now();
                let before_neg = last_negotiation.len();
                last_negotiation.retain(|_, ts| now.duration_since(*ts) < SESSION_NEGOTIATION_COOLDOWN * 6);
                let before_pex = last_peer_exchange.len();
                last_peer_exchange.retain(|_, ts| now.duration_since(*ts) < PEER_EXCHANGE_COOLDOWN * 6);
                // Defense-in-depth: if maps still exceed cap after TTL eviction,
                // force-clear to prevent unbounded growth from a burst of unique peer IDs.
                if last_negotiation.len() > MAX_COOLDOWN_ENTRIES {
                    warn!(len = last_negotiation.len(), cap = MAX_COOLDOWN_ENTRIES, "negotiation cooldown map exceeded cap, clearing");
                    last_negotiation.clear();
                }
                if last_peer_exchange.len() > MAX_COOLDOWN_ENTRIES {
                    warn!(len = last_peer_exchange.len(), cap = MAX_COOLDOWN_ENTRIES, "peer exchange cooldown map exceeded cap, clearing");
                    last_peer_exchange.clear();
                }
                let removed_neg = before_neg - last_negotiation.len();
                let removed_pex = before_pex - last_peer_exchange.len();
                if removed_neg > 0 || removed_pex > 0 {
                    debug!(
                        removed_negotiation = removed_neg,
                        removed_peer_exchange = removed_pex,
                        "pruned stale cooldown map entries"
                    );
                }
            }
            _ = session_self_heal_interval.tick() => {
                heal_connected_e2ee_sessions(&session_manager, &transport).await;
            }
            _ = shutdown_rx.changed() => {
                info!("session handler shutting down");
                break;
            }
        }
    }
}

// ── Individual event handlers ─────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_peer_connected(
    peer_id: &NodeId,
    identity: &NodeIdentity,
    session_manager: &SessionManager,
    transport: &Arc<NoiseTransport>,
    pricing: &Arc<dyn konsensus_core::traits::pricing::PricingEngine>,
    chain: &Arc<dyn ChainProvider>,
    pending_tx: &tokio::sync::mpsc::Sender<NodeId>,
    lightning: &Arc<dyn LightningProvider>,
    routing: &konsensus_routing::RoutingTable,
    lightning_addr: &Option<String>,
    storage: &Arc<dyn konsensus_storage::Storage>,
    ws_delivery_tx: &broadcast::Sender<Arc<WsDeliveryStatus>>,
    our_node_id: NodeId,
) {
    info!(peer = %peer_id, "peer connected, sending prekey offer + price table");

    // Notify pending delivery flusher about reconnected peer.
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        pending_tx.send(*peer_id),
    ).await {
        Ok(Err(e)) => warn!(error = %e, "pending delivery channel closed"),
        Err(_) => warn!(peer = %peer_id, "pending delivery notification timed out (5s)"),
        Ok(Ok(())) => {}
    }

    if let Err(e) = send_prekey_offer(session_manager, transport, peer_id).await {
        warn!(peer = %peer_id, error = %e, "failed to send prekey offer");
    }
    if let Err(e) = funding_poll::emit_progress_step(
        storage.as_ref(),
        ws_delivery_tx,
        peer_id,
        "noise_connected",
        "Secure transport connected",
    )
    .await
    {
        warn!(error = %e, "failed to persist onboarding noise_connected step");
    }

    // Send our price table so the peer knows what we charge.
    // Compute the trust discount we offer this peer based on their synaptic weight
    // in our routing table — stronger relationships get lower prices.
    let meta = konsensus_pricing::peer_prices::build_full_price_table(
        pricing.as_ref(),
        chain.as_ref(),
    ).await;
    let peer_discount = routing
        .get_peer_weight(peer_id)
        .await
        .map(konsensus_pricing::compute_trust_discount)
        .unwrap_or(0.0);
    let price_frame = Frame::PriceTable {
        prices: meta.prices,
        block_height: meta.block_height,
        valid_blocks: meta.valid_blocks,
        trust_discount: peer_discount,
    };
    if let Err(e) = transport.send_frame(peer_id, &price_frame).await {
        warn!(peer = %peer_id, error = %e, "failed to send price table");
    }

    // Send our Lightning pubkey if available (enables keysend payments from peer).
    if let Some(ln_pubkey) = lightning.get_node_pubkey().await {
        let ln_frame = Frame::LightningInfo {
            ln_pubkey,
            ln_addr: lightning_addr.clone(),
        };
        if let Err(e) = transport.send_frame(peer_id, &ln_frame).await {
            warn!(peer = %peer_id, error = %e, "failed to send Lightning info");
        } else {
            if let Err(e) = funding_poll::emit_progress_step(
                storage.as_ref(),
                ws_delivery_tx,
                peer_id,
                "lightning_info_sent",
                "Lightning details shared",
            )
            .await
            {
                warn!(error = %e, "failed to persist onboarding lightning_info_sent step");
            }
            funding_poll::ensure_poll_task(
                our_node_id.to_hex(),
                Arc::clone(storage),
                Arc::clone(lightning),
                ws_delivery_tx.clone(),
            )
            .await;
        }
    }

    // Request peer's known peers for mesh discovery.
    if let Err(e) = transport.send_frame(peer_id, &Frame::PeerExchangeRequest).await {
        warn!(peer = %peer_id, error = %e, "failed to send peer exchange request");
    }

    // Send our KIND_PROFILE (103) so the peer can display our identity.
    crate::profile_handler::send_profile_to(identity, transport, peer_id).await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_prekey_offer(
    peer_id: &NodeId,
    bundle: serde_json::Value,
    our_node_id: NodeId,
    session_manager: &SessionManager,
    storage: &Arc<dyn konsensus_storage::Storage>,
    transport: &Arc<NoiseTransport>,
    audit: &Arc<AuditLog>,
    last_negotiation: &mut std::collections::HashMap<NodeId, tokio::time::Instant>,
) {
    // Rate-limit session re-negotiation per peer.
    if let Some(last) = last_negotiation.get(peer_id) {
        if last.elapsed() < SESSION_NEGOTIATION_COOLDOWN {
            warn!(
                peer = %peer_id,
                "session re-negotiation throttled (cooldown {}s)",
                SESSION_NEGOTIATION_COOLDOWN.as_secs()
            );
            return;
        }
    }

    // Deterministic tiebreaker: lower NodeId initiates X3DH
    if our_node_id.as_bytes() >= peer_id.as_bytes() {
        debug!(
            peer = %peer_id,
            "received prekey offer but we are not the initiator, waiting for SessionInit"
        );
        return;
    }

    // We are the initiator — perform X3DH with peer's bundle.
    if session_manager.has_session(peer_id).await {
        warn!(peer = %peer_id, "peer sent PrekeyOffer but session exists — replacing stale session");
        session_manager.remove_session(peer_id).await;
        if let Err(e) = storage.clear_pending_for_peer(peer_id).await {
            warn!(peer = %peer_id, error = %e, "failed to clear stale pending deliveries");
        }
    }

    let peer_bundle: konsensus_crypto::SerializablePrekeyBundle =
        match serde_json::from_value(bundle) {
            Ok(b) => b,
            Err(e) => {
                warn!(peer = %peer_id, error = %e, "invalid prekey bundle");
                return;
            }
        };

    match session_manager.initiate_session(peer_id, &peer_bundle).await {
        Ok(init_data) => {
            last_negotiation.insert(*peer_id, tokio::time::Instant::now());
            info!(peer = %peer_id, "X3DH initiated, sending SessionInit");
            let init_json = match serde_json::to_value(&init_data) {
                Ok(v) => v,
                Err(e) => {
                    error!(error = %e, "failed to serialize session init");
                    return;
                }
            };
            let frame = Frame::SessionInit { init_data: init_json };
            if let Err(e) = transport.send_frame(peer_id, &frame).await {
                warn!(peer = %peer_id, error = %e, "failed to send SessionInit");
            }
        }
        Err(e) => {
            warn!(peer = %peer_id, error = %e, "X3DH initiation failed");
        }
    }

    let _ = audit;
}

async fn handle_session_init(
    peer_id: &NodeId,
    init_data: serde_json::Value,
    session_manager: &SessionManager,
    storage: &Arc<dyn konsensus_storage::Storage>,
    transport: &Arc<NoiseTransport>,
    audit: &Arc<AuditLog>,
    last_negotiation: &mut std::collections::HashMap<NodeId, tokio::time::Instant>,
) {
    // Rate-limit session re-negotiation per peer.
    if let Some(last) = last_negotiation.get(peer_id) {
        if last.elapsed() < SESSION_NEGOTIATION_COOLDOWN {
            warn!(
                peer = %peer_id,
                "session re-negotiation throttled (cooldown {}s)",
                SESSION_NEGOTIATION_COOLDOWN.as_secs()
            );
            return;
        }
    }

    // If a session already exists, replace the stale one.
    if session_manager.has_session(peer_id).await {
        warn!(peer = %peer_id, "peer sent SessionInit but session exists — replacing stale session");
        session_manager.remove_session(peer_id).await;
        if let Err(e) = storage.clear_pending_for_peer(peer_id).await {
            warn!(peer = %peer_id, error = %e, "failed to clear stale pending deliveries");
        }
    }

    let init: konsensus_crypto::SerializableSessionInit =
        match serde_json::from_value(init_data) {
            Ok(d) => d,
            Err(e) => {
                warn!(peer = %peer_id, error = %e, "invalid session init data");
                return;
            }
        };

    match session_manager.accept_session(peer_id, &init).await {
        Ok(()) => {
            last_negotiation.insert(*peer_id, tokio::time::Instant::now());
            info!(peer = %peer_id, "E2EE session accepted, sending SessionAck");
            let frame = Frame::SessionAck;
            if let Err(e) = transport.send_frame(peer_id, &frame).await {
                warn!(peer = %peer_id, error = %e, "failed to send SessionAck");
            }
            audit.record(
                "e2ee_session_established",
                &peer_id.to_hex(),
                Some(serde_json::json!({ "role": "responder" })),
            );
        }
        Err(e) => {
            warn!(peer = %peer_id, error = %e, "session accept failed");
        }
    }
}

async fn handle_session_ack(
    peer_id: &NodeId,
    session_manager: &SessionManager,
    transport: &Arc<NoiseTransport>,
    audit: &Arc<AuditLog>,
) {
    info!(peer = %peer_id, "E2EE session established (initiator), sending ratchet init");
    audit.record(
        "e2ee_session_established",
        &peer_id.to_hex(),
        Some(serde_json::json!({ "role": "initiator" })),
    );

    // Send a ratchet init message so the acceptor can initialize their sending chain.
    match session_manager.encrypt(peer_id, b"ratchet-init").await {
        Ok(ratchet_msg) => {
            let payload = konsensus_crypto::ratchet_message_to_bytes(&ratchet_msg);
            let frame = Frame::RatchetInit { payload };
            if let Err(e) = transport.send_frame(peer_id, &frame).await {
                warn!(peer = %peer_id, error = %e, "failed to send RatchetInit");
            }
        }
        Err(e) => {
            warn!(
                peer = %peer_id, error = %e,
                "failed to encrypt ratchet init — removing corrupt session"
            );
            session_manager.remove_session(peer_id).await;
        }
    }
}

async fn handle_ratchet_init(
    peer_id: &NodeId,
    payload: &[u8],
    session_manager: &SessionManager,
    storage: &Arc<dyn konsensus_storage::Storage>,
    transport: &Arc<NoiseTransport>,
) {
    match konsensus_crypto::ratchet_message_from_bytes(payload) {
        Ok(ratchet_msg) => {
            match session_manager.decrypt(peer_id, &ratchet_msg).await {
                Ok(_) => {
                    info!(peer = %peer_id, "ratchet init received, bidirectional E2EE ready");
                }
                Err(e) => {
                    warn!(
                        peer = %peer_id, error = %e,
                        "failed to decrypt ratchet init — removing broken session and re-negotiating"
                    );
                    session_manager.remove_session(peer_id).await;
                    if let Err(clear_err) = storage.clear_pending_for_peer(peer_id).await {
                        warn!(peer = %peer_id, error = %clear_err, "failed to clear pending after ratchet init failure");
                    }
                    // Send fresh PrekeyOffer to trigger re-negotiation
                    if let Err(send_err) = send_prekey_offer(session_manager, transport, peer_id).await {
                        warn!(peer = %peer_id, error = %send_err, "failed to send PrekeyOffer after ratchet init failure");
                    }
                }
            }
        }
        Err(e) => {
            warn!(peer = %peer_id, error = %e, "invalid ratchet init payload");
        }
    }
}

async fn heal_connected_e2ee_sessions(
    session_manager: &SessionManager,
    transport: &Arc<NoiseTransport>,
) {
    let connected_peers = transport.connected_peers().await;
    for peer_id in connected_peers {
        if !e2ee_needs_self_heal(session_manager, &peer_id).await {
            continue;
        }

        match send_prekey_offer(session_manager, transport, &peer_id).await {
            Ok(()) => {
                debug!(
                    peer = %peer_id,
                    "sent E2EE self-heal PrekeyOffer to connected peer without ready sending chain"
                );
            }
            Err(e) => {
                warn!(
                    peer = %peer_id,
                    error = %e,
                    "failed to send E2EE self-heal PrekeyOffer"
                );
            }
        }
    }
}

async fn e2ee_needs_self_heal(session_manager: &SessionManager, peer_id: &NodeId) -> bool {
    !session_manager.can_send(peer_id).await
}

async fn send_prekey_offer(
    session_manager: &SessionManager,
    transport: &Arc<NoiseTransport>,
    peer_id: &NodeId,
) -> Result<(), String> {
    let bundle = session_manager.prekey_bundle().await;
    let bundle_json = serde_json::to_value(&bundle)
        .map_err(|e| format!("serialize prekey bundle: {e}"))?;
    let frame = Frame::PrekeyOffer { bundle: bundle_json };
    transport
        .send_frame(peer_id, &frame)
        .await
        .map_err(|e| e.to_string())
}

async fn handle_message_acked(
    peer_id: &NodeId,
    message_id: &konsensus_core::types::MessageId,
    send_timestamps: &tokio::sync::Mutex<std::collections::HashMap<konsensus_core::types::MessageId, std::time::Instant>>,
    storage: &Arc<dyn konsensus_storage::Storage>,
    routing: &konsensus_routing::RoutingTable,
    ws_delivery_tx: &broadcast::Sender<Arc<WsDeliveryStatus>>,
) {
    // Compute STDP latency from send timestamp.
    let latency_ms = {
        let mut timestamps = send_timestamps.lock().await;
        let latency = timestamps.remove(message_id)
            .map(|sent_at| sent_at.elapsed().as_secs_f64() * 1000.0)
            .unwrap_or(0.0);
        // Prune stale entries (>5 min) to prevent unbounded growth
        if timestamps.len() > 1000 {
            let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(300);
            timestamps.retain(|_, sent_at| *sent_at > cutoff);
        }
        latency
    };

    // Look up payment amount from stored envelope for routing weight.
    let payment_msat = match storage.get_message(message_id).await {
        Ok(Some(env)) => env.payment_proof.amount_msat,
        _ => 0,
    };

    debug!(
        peer = %peer_id,
        msg_id = %message_id,
        latency_ms = format!("{latency_ms:.1}"),
        payment_msat,
        "message delivery confirmed"
    );

    // Hebbian learning: successful delivery strengthens routing weight.
    routing.record_success(peer_id, latency_ms, payment_msat).await;

    // Broadcast delivery confirmation to WebSocket clients.
    if let Err(e) = ws_delivery_tx.send(Arc::new(
        WsDeliveryStatus {
            event_type: "delivery_status",
            message_id: message_id.to_hex(),
            status: "delivered".to_string(),
            reason: None,
        },
    )) {
        tracing::debug!(error = %e, "no WebSocket clients for delivery status");
    }
}

async fn handle_message_rejected(
    peer_id: &NodeId,
    message_id: &konsensus_core::types::MessageId,
    reason: &str,
    routing: &konsensus_routing::RoutingTable,
    ws_delivery_tx: &broadcast::Sender<Arc<WsDeliveryStatus>>,
) {
    warn!(peer = %peer_id, msg_id = %message_id, %reason, "message rejected by peer");
    routing.record_failure(peer_id).await;

    if let Err(e) = ws_delivery_tx.send(Arc::new(
        WsDeliveryStatus {
            event_type: "delivery_status",
            message_id: message_id.to_hex(),
            status: "rejected".to_string(),
            reason: Some(reason.to_string()),
        },
    )) {
        tracing::debug!(error = %e, "no WebSocket clients for delivery rejection");
    }
}

async fn handle_price_query(
    peer_id: &NodeId,
    kind: u16,
    pricing: &Arc<dyn konsensus_core::traits::pricing::PricingEngine>,
    chain: &Arc<dyn ChainProvider>,
    transport: &Arc<NoiseTransport>,
) {
    match pricing.get_price_msat(kind).await {
        Ok(price_msat) => {
            let block_height: u64 = match chain.get_block_height().await {
                Ok(h) => h,
                Err(e) => {
                    warn!(peer = %peer_id, error = %e, "chain backend unavailable, skipping price response");
                    return;
                }
            };
            let frame = Frame::PriceResponse { kind, price_msat, block_height };
            if let Err(e) = transport.send_frame(peer_id, &frame).await {
                warn!(peer = %peer_id, error = %e, "failed to send price response");
            }
        }
        Err(e) => {
            debug!(peer = %peer_id, kind, error = %e, "cannot price kind for peer query");
        }
    }
}

async fn handle_invoice_requested(
    peer_id: &NodeId,
    request_id: &str,
    amount_msat: u64,
    purpose: &str,
    lightning: &Arc<dyn LightningProvider>,
    transport: &Arc<NoiseTransport>,
) {
    info!(
        peer = %peer_id, %request_id, amount_msat, %purpose,
        "peer requested invoice — creating on our wallet"
    );
    let description = format!("konsensus:{request_id}");
    match lightning.create_invoice(amount_msat, &description, 3600).await {
        Ok(invoice) => {
            let response = Frame::InvoiceResponse {
                request_id: request_id.to_string(),
                bolt11: invoice.bolt11,
                payment_hash: invoice.payment_hash,
            };
            if let Err(e) = transport.send_frame(peer_id, &response).await {
                warn!(peer = %peer_id, %request_id, error = %e, "failed to send invoice response");
            } else {
                info!(peer = %peer_id, %request_id, amount_msat, "sent invoice response — awaiting payment");
            }
        }
        Err(e) => {
            warn!(
                peer = %peer_id, %request_id, error = %e,
                "failed to create invoice for peer request — sending error to peer"
            );
            let error_frame = Frame::InvoiceError {
                request_id: request_id.to_string(),
                reason: format!("invoice creation failed: {e}"),
            };
            if let Err(send_err) = transport.send_frame(peer_id, &error_frame).await {
                warn!(peer = %peer_id, %request_id, error = %send_err, "failed to send invoice error frame");
            }
        }
    }
}

async fn handle_invoice_response(
    peer_id: &NodeId,
    request_id: &str,
    bolt11: String,
    payment_hash: String,
    invoice_requests: &tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceResponseData>>>,
) {
    info!(peer = %peer_id, %request_id, "received invoice response from peer");
    let mut requests = invoice_requests.lock().await;
    if let Some(sender) = requests.remove(request_id) {
        let data = InvoiceResponseData { bolt11, payment_hash };
        if sender.send(data).is_err() {
            warn!(%request_id, "invoice response receiver already dropped (timeout?)");
        }
    } else {
        warn!(peer = %peer_id, %request_id, "received invoice response for unknown request_id");
    }
}

async fn handle_peer_exchange_request(
    peer_id: &NodeId,
    our_node_id: NodeId,
    peer_registry: &tokio::sync::RwLock<PeerRegistry>,
    transport: &Arc<NoiseTransport>,
    last_peer_exchange: &mut std::collections::HashMap<NodeId, tokio::time::Instant>,
) {
    if let Some(last) = last_peer_exchange.get(peer_id) {
        if last.elapsed() < PEER_EXCHANGE_COOLDOWN {
            warn!(
                peer = %peer_id,
                "peer exchange throttled (cooldown {}s)",
                PEER_EXCHANGE_COOLDOWN.as_secs()
            );
            return;
        }
    }
    last_peer_exchange.insert(*peer_id, tokio::time::Instant::now());
    info!(peer = %peer_id, "peer requested peer exchange");

    let registry = peer_registry.read().await;
    let entries: Vec<konsensus_message::wire::PeerExchangeEntry> = registry
        .all()
        .iter()
        .filter(|p| p.node_id != *peer_id)
        .take(50)
        .map(|p| konsensus_message::wire::PeerExchangeEntry {
            node_id: p.node_id,
            addr: p.addr,
            label: p.label.clone(),
            tier: konsensus_message::wire::SovereigntyTier::T1,
        })
        .collect();
    let count = entries.len();
    drop(registry);

    if let Err(e) = transport.send_frame(
        peer_id,
        &Frame::PeerExchangeResponse { peers: entries },
    ).await {
        warn!(peer = %peer_id, error = %e, "failed to send peer exchange response");
    } else {
        info!(peer = %peer_id, count, "sent peer exchange response");
    }

    let _ = our_node_id;
}

async fn handle_peer_exchange_received(
    peer_id: &NodeId,
    peers: Vec<konsensus_message::wire::PeerExchangeEntry>,
    our_node_id: NodeId,
    peer_registry: &tokio::sync::RwLock<PeerRegistry>,
    last_peer_exchange: &mut std::collections::HashMap<NodeId, tokio::time::Instant>,
) {
    if let Some(last) = last_peer_exchange.get(peer_id) {
        if last.elapsed() < PEER_EXCHANGE_COOLDOWN {
            warn!(
                peer = %peer_id,
                "peer exchange response throttled (cooldown {}s)",
                PEER_EXCHANGE_COOLDOWN.as_secs()
            );
            return;
        }
    }
    last_peer_exchange.insert(*peer_id, tokio::time::Instant::now());

    if peers.len() > MAX_PEER_EXCHANGE_ENTRIES {
        warn!(
            peer = %peer_id,
            count = peers.len(),
            max = MAX_PEER_EXCHANGE_ENTRIES,
            "peer exchange too large — truncating"
        );
    }
    let peers_to_process = &peers[..peers.len().min(MAX_PEER_EXCHANGE_ENTRIES)];
    info!(
        peer = %peer_id,
        count = peers_to_process.len(),
        "received peer exchange — storing discovered peers"
    );

    let mut registry = peer_registry.write().await;
    let mut added = 0u32;
    for entry in peers_to_process {
        if entry.node_id == our_node_id {
            continue;
        }
        if !registry.contains(&entry.node_id) {
            registry.add(konsensus_message::peer::PeerEntry {
                node_id: entry.node_id,
                addr: entry.addr,
                label: entry.label.clone(),
                auto_connect: false,
            });
            added += 1;
        }
    }
    if added > 0 {
        info!(added, "added discovered peers to registry");
    }
}

/// Handle a peer's Lightning pubkey announcement.
///
/// Validates the pubkey format (66-char hex compressed pubkey) and stores
/// it for keysend payments. Invalid pubkeys are logged and discarded.
async fn handle_lightning_info_received(
    peer_id: &NodeId,
    ln_pubkey: &str,
    peer_ln_pubkeys: &Arc<tokio::sync::Mutex<std::collections::HashMap<NodeId, String>>>,
) -> bool {
    // Validate compressed pubkey format: 66 hex chars, starts with 02 or 03.
    if ln_pubkey.len() != 66 {
        warn!(
            peer = %peer_id,
            len = ln_pubkey.len(),
            "received invalid Lightning pubkey — expected 66 hex chars"
        );
        return false;
    }
    if !ln_pubkey.starts_with("02") && !ln_pubkey.starts_with("03") {
        warn!(
            peer = %peer_id,
            prefix = &ln_pubkey[..2],
            "received invalid Lightning pubkey — must start with 02 or 03"
        );
        return false;
    }
    if hex::decode(ln_pubkey).is_err() {
        warn!(
            peer = %peer_id,
            "received Lightning pubkey with invalid hex encoding"
        );
        return false;
    }

    peer_ln_pubkeys.lock().await.insert(*peer_id, ln_pubkey.to_string());
    info!(
        peer = %peer_id,
        ln_pubkey_prefix = &ln_pubkey[..16],
        "stored peer Lightning pubkey — keysend payments enabled"
    );
    true
}

/// Allowed legacy free-gossip kinds.
///
/// Empty by design: free gossip is disabled until paid broadcast semantics
/// land on the normal UKM payment-gated path.
const GOSSIP_ALLOWED_KINDS: &[u16] = &[];

/// Handle an incoming legacy gossip message: validate policy, then re-broadcast.
///
/// Free gossip is currently disabled. If legacy kinds are explicitly re-enabled
/// for a closed deployment, they are:
/// 1. Recipient-checked (must be Broadcast)
/// 2. Kind-restricted (only allowed gossip types)
/// 3. Deduplicated, rate-limited, and time-bounded (GossipValidator)
/// 4. Structurally validated (message ID, ciphertext, payment proof)
/// 5. Ed25519 signature-verified (sender's public key)
/// 6. Re-broadcast to all peers except sender
async fn handle_gossip_received(
    from_peer: NodeId,
    envelope: konsensus_core::UkmEnvelope,
    gossip_validator: &konsensus_gossip::GossipValidator,
    transport: &Arc<NoiseTransport>,
    audit_log: &Arc<AuditLog>,
    ws_broadcast: &broadcast::Sender<Arc<konsensus_api::state::WsMessage>>,
) {
    let sender = envelope.sender;
    let msg_id = envelope.id;
    let kind = envelope.kind;

    // 1. Check recipient is Broadcast
    if !matches!(envelope.recipient, konsensus_core::types::Recipient::Broadcast) {
        warn!(
            from = %from_peer,
            sender = %sender,
            msg_id = %msg_id,
            "gossip message has non-broadcast recipient — rejecting"
        );
        return;
    }

    // 2. Check kind is allowed for gossip
    if !GOSSIP_ALLOWED_KINDS.contains(&kind) {
        warn!(
            from = %from_peer,
            sender = %sender,
            kind,
            "gossip message has disallowed kind — rejecting"
        );
        return;
    }

    // 2b. Reject oversized gossip payloads — the API enforces 64 KB but a
    //     malicious peer could send up to MAX_FRAME_SIZE (16 MiB) via direct
    //     Noise connection.  Without this check every connected peer would
    //     re-broadcast the oversized frame, amplifying bandwidth consumption.
    const MAX_GOSSIP_RELAY_PAYLOAD: usize = 65_536;
    if envelope.ciphertext.len() > MAX_GOSSIP_RELAY_PAYLOAD {
        warn!(
            from = %from_peer,
            sender = %sender,
            msg_id = %msg_id,
            payload_len = envelope.ciphertext.len(),
            max = MAX_GOSSIP_RELAY_PAYLOAD,
            "gossip payload too large — rejecting"
        );
        return;
    }

    // 3. Verify envelope integrity (message ID, ciphertext, payment proof)
    if let Err(e) = envelope.validate() {
        warn!(
            from = %from_peer,
            sender = %sender,
            msg_id = %msg_id,
            error = %e,
            "gossip envelope validation failed"
        );
        return;
    }

    // 4. Verify Ed25519 signature BEFORE dedup/rate-limit — forged messages
    //    must not consume dedup store space or rate-limit quota, as a
    //    malicious peer could otherwise poison the dedup store with invalid
    //    signatures and exhaust the legitimate sender's rate-limit budget.
    {
        let verifying_key = match sender.to_verifying_key() {
            Ok(k) => k,
            Err(e) => {
                warn!(
                    from = %from_peer,
                    sender = %sender,
                    msg_id = %msg_id,
                    error = %e,
                    "gossip sender has invalid Ed25519 key — rejecting"
                );
                return;
            }
        };
        let signable = envelope.signable_bytes();
        let ed_sig = envelope.signature.to_ed25519();
        if let Err(e) = verifying_key.verify(&signable, &ed_sig) {
            warn!(
                from = %from_peer,
                sender = %sender,
                msg_id = %msg_id,
                error = %e,
                "gossip Ed25519 signature verification failed — rejecting"
            );
            return;
        }
    }

    // 5. Validate deduplication, freshness, rate limit — only after
    //    signature is verified to prevent dedup store poisoning.
    if let Err(e) = gossip_validator.validate(&msg_id, &sender, envelope.timestamp) {
        debug!(
            from = %from_peer,
            sender = %sender,
            msg_id = %msg_id,
            error = %e,
            "gossip validation failed"
        );
        return;
    }

    info!(
        from = %from_peer,
        sender = %sender,
        msg_id = %msg_id,
        kind,
        "accepted gossip message — re-broadcasting"
    );

    audit_log.record(
        "gossip_received",
        &sender.to_hex(),
        Some(serde_json::json!({
            "from_peer": from_peer.to_hex(),
            "kind": kind,
            "message_id": msg_id.to_hex(),
        })),
    );

    // 6. Broadcast to WebSocket clients — gossip payload is public data, so
    //    we pass the ciphertext as plaintext (it's unencrypted JSON).
    let plaintext = String::from_utf8(envelope.ciphertext.clone()).ok();
    if let Err(e) = ws_broadcast.send(Arc::new(konsensus_api::state::WsMessage {
        envelope: envelope.clone(),
        plaintext,
    })) {
        debug!(error = %e, "no WebSocket clients connected for gossip broadcast");
    }

    // 7. Re-broadcast to all connected peers EXCEPT the one we received from.
    //    Serialize the frame once and use send_raw_frame to avoid redundant
    //    JSON serialization per peer (N peers = 1 serialize, not N).
    let gossip_frame = Frame::Gossip(Box::new(envelope));
    let frame_bytes = match gossip_frame.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            warn!(msg_id = %msg_id, error = %e, "failed to serialize gossip frame for re-broadcast");
            return;
        }
    };
    let connected_peers = transport.connected_peers().await;
    let mut forwarded = 0u32;
    for peer_id in &connected_peers {
        if *peer_id == from_peer {
            continue; // Don't echo back to sender
        }
        if let Err(e) = transport.send_raw_frame(peer_id, &frame_bytes).await {
            debug!(
                peer = %peer_id,
                error = %e,
                "failed to forward gossip to peer"
            );
        } else {
            forwarded = forwarded.saturating_add(1);
        }
    }

    debug!(
        msg_id = %msg_id,
        forwarded,
        total_peers = connected_peers.len(),
        "gossip re-broadcast complete"
    );
}

#[cfg(test)]
#[path = "tests/session_handler.rs"]
mod tests;
