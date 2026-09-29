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
use crate::relay::RelayEngine;

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
    /// Operator-selectable admission mode. In `Whitelist` (default) the receive-path
    /// gate still passes `Some(&whitelist)` (Step-2 membership enforced); in
    /// `PriceOpen` it passes `None`, skipping ONLY the membership test — every other
    /// gate step (integrity, freshness, signature, replay, price-floor, and
    /// recipient-bound settlement) still runs, so a stranger is admitted only by
    /// full payment (P2 fail-closed, no free lane).
    pub admission_mode: konsensus_message::ReachabilityMode,
    /// R3 SEAM-B (Route B, default-off). `Some` ONLY when `[relay] enabled` — the
    /// engine is constructed at node build only when enabled, so a disabled node
    /// holds `None` and the receive path is byte-identical to a non-relay build.
    /// When `Some`, kind-600+ (Storage-category) paid UKMs are intercepted after
    /// the gate, before store/decrypt, and routed to the relay engine (never
    /// stored as a message, never decrypted).
    pub relay_engine: Option<Arc<RelayEngine>>,
    pub shutdown_rx: watch::Receiver<bool>,
}

/// Payment-gate verification (Principle 2) with the closed-mesh whitelist
/// (Principle 3) enforced **inside** the gate, and the `PeerRegistry` read guard
/// released **before** the gate await.
///
/// Extracted from [`run`] so the HARD-11 lock-release-before-await contract is
/// directly unit-testable. We take an O(1) reference-counted snapshot of the
/// registry's cached whitelist set ([`PeerRegistry::whitelist_arc`]) under a
/// short-lived read lock, drop the guard, then pass that snapshot **into**
/// `PaymentGate::verify` as `whitelist = Some(&snapshot)`. The gate therefore
/// remains the sole authority for the Step-2 whitelist check (it owns the
/// ordering, the `NotWhitelisted` rejection, and any audit/metrics shape) —
/// closing the Principle-3 split where the receive path checked membership by
/// hand and mirrored the rejection. `verify` awaits the nonce store, pricing
/// engine, and (optionally) the Lightning backend; holding the read guard across
/// that I/O would stall every peer add / remove / revocation behind in-flight
/// verification, so only the cheap `Arc` clone happens under the lock. Mutations
/// copy-on-write, so this in-flight snapshot is unaffected by a concurrent
/// revocation.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn whitelist_then_verify(
    envelope: &konsensus_core::UkmEnvelope,
    membrane: &konsensus_api::membrane::Membrane,
    peer_registry: &tokio::sync::RwLock<PeerRegistry>,
    gate: &PaymentGate,
    nonce_store: &dyn konsensus_core::gate::NonceStore,
    pricing: &dyn konsensus_core::traits::pricing::PricingEngine,
    lightning: Option<&dyn LightningProvider>,
    trust_discount: f64,
    our_node_id: Option<&konsensus_core::types::NodeId>,
    admission_mode: konsensus_message::ReachabilityMode,
    commit_replay: bool,
) -> Result<(bool, bool), konsensus_core::gate::GateRejection> {
    // Snapshot the whitelist UNCONDITIONALLY (preserves the HARD-11
    // lock-release-before-await seam even in PriceOpen, where the snapshot is
    // ignored). Only the cheap Arc clone is held across the gate await.
    let whitelist = {
        let registry = peer_registry.read().await;
        registry.whitelist_arc()
    };
    // M1a gate carrier (carrier A): branch ONLY the Step-2 membership argument.
    //   Whitelist => Some(&whitelist), EXACTLY as before (Step-2 enforced).
    //   PriceOpen  => None, so `PaymentGate::verify` short-circuits and SKIPS only
    //                 the membership test. Steps 1, 2.5, 3, 4, 5 and the
    //                 recipient-bound settlement (our_node_id, UNCHANGED) all still
    //                 run — a stranger is admitted only by full payment.
    let wl_arg: Option<&std::collections::HashSet<konsensus_core::types::NodeId>> =
        match admission_mode {
            konsensus_message::ReachabilityMode::Whitelist => Some(&whitelist),
            konsensus_message::ReachabilityMode::PriceOpen => None,
        };
    let result = if commit_replay {
        gate.verify(envelope, nonce_store, pricing, wl_arg, lightning, trust_discount, our_node_id).await.map(|()| false)
    } else {
        gate.validate_received_paid_envelope(envelope, nonce_store, pricing, wl_arg, lightning, trust_discount, our_node_id).await
    };
    // Ordinary admission is observed only after the durable acceptance commit.
    // Return the same whitelist snapshot classification across that boundary.
    let first_contact = !whitelist.contains(&envelope.sender);
    match &result {
        Ok(_) if commit_replay => { membrane.admitted(envelope, first_contact); }
        Err(rejection) => { membrane.refused(envelope, rejection); }
        _ => {}
    }
    result.map(|already_accepted| (first_contact, already_accepted))
}

/// Cooldown between corrective price-table resends to the same privileged peer.
const CORRECTIVE_PRICE_TABLE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(10);

/// Maximum retained corrective-price-table cooldown entries.
const MAX_CORRECTIVE_PRICE_TABLE_ENTRIES: usize = 10_000;

/// Throttle corrective responses for privileged peers. Unpaid strangers never
/// enter this path or allocate these per-peer guards.
fn corrective_price_table_rate_limited(
    last_sent: &mut std::collections::HashMap<konsensus_core::types::NodeId, tokio::time::Instant>,
    peer: &konsensus_core::types::NodeId,
    now: tokio::time::Instant,
) -> bool {
    if let Some(last) = last_sent.get(peer) {
        if now.duration_since(*last) < CORRECTIVE_PRICE_TABLE_COOLDOWN {
            return true;
        }
    }
    // Bound memory before inserting a new key: when saturated, evict entries
    // whose cooldown has fully elapsed (mirrors the session-handler eviction).
    if last_sent.len() >= MAX_CORRECTIVE_PRICE_TABLE_ENTRIES {
        last_sent.retain(|_, ts| now.duration_since(*ts) < CORRECTIVE_PRICE_TABLE_COOLDOWN);
    }
    last_sent.insert(*peer, now);
    false
}

/// PSI-SPEED: offer our X3DH prekey to `peer` right after a settled payment
/// promoted its connection (generation `promoted`), so the session forms now rather than on the next
/// self-heal tick. Skipped when a sending chain already exists (an offer would
/// make a lower-NodeId peer replace a working session) or when the limiter
/// refuses; the periodic self-heal remains the fallback either way.
async fn offer_prekey_after_promotion(
    transport: &NoiseTransport,
    sessions: &SessionManager,
    peer: &konsensus_core::types::NodeId,
    promoted: std::time::Instant,
    limiter: &mut konsensus_message::EagerOfferLimiter,
) {
    if sessions.can_send(peer).await {
        return;
    }
    if !limiter.allow(peer, std::time::Instant::now()) {
        debug!(peer = %peer, "eager PrekeyOffer rate-limited; self-heal will offer");
        return;
    }
    let bundle = match serde_json::to_value(sessions.prekey_bundle().await) {
        Ok(bundle) => bundle,
        Err(e) => {
            warn!(peer = %peer, error = %e, "failed to serialize prekey bundle for eager offer");
            return;
        }
    };
    let frame = match (Frame::PrekeyOffer { bundle }).to_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(peer = %peer, error = %e, "failed to encode eager PrekeyOffer");
            return;
        }
    };
    // Only on the exact connection this payment promoted, and only while it is
    // still privileged: a replacement that reconnected meanwhile is unpaid.
    match transport.send_raw_frame_on(peer, promoted, konsensus_message::Standing::Privileged, &frame).await {
        Ok(()) => info!(peer = %peer, "sent PrekeyOffer to the payer just promoted (PSI-SPEED)"),
        Err(e) => warn!(peer = %peer, error = %e, "failed to send eager PrekeyOffer after promotion"),
    }
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
        admission_mode: admission_mode_for_recv,
        relay_engine: relay_engine_for_recv,
        mut shutdown_rx,
    } = deps;

    // Per-peer cooldown for privileged corrective price-table responses.
    let mut last_corrective_price_table: std::collections::HashMap<
        konsensus_core::types::NodeId,
        tokio::time::Instant,
    > = std::collections::HashMap::new();

    // PSI-SPEED: bounds the prekey offers sent right after promote-on-paid.
    // Separate from the other two eager limiters on purpose; see `eager_offers`
    // in the compose handler.
    let mut eager_offers = konsensus_message::EagerOfferLimiter::new();

    // Doorway hardening #3: wrap the settlement-verification provider in a
    // circuit-breaker (timeout + breaker + bounded concurrency + short negative
    // cache). A slow/down/unhealthy backend now fails the gate fast (fail-closed
    // — never an admission) instead of head-of-line-stalling this inbound loop.
    // Admission semantics are unchanged: a `Settled` result passes through
    // verbatim, so the gate's recipient-binding/amount/replay/preimage checks all
    // still run; the wrapper can only cause more rejections, never an admission.
    let verify_lightning: std::sync::Arc<dyn konsensus_core::traits::lightning::LightningProvider> =
        std::sync::Arc::new(konsensus_lightning::CircuitBreakerLightning::with_defaults(
            std::sync::Arc::clone(&lightning_for_recv),
        ));

    loop {
        tokio::select! {
            result = transport_for_recv.recv() => {
                match result {
                    Ok(envelope) => {
                        // PRINCIPLE 2: Every incoming message MUST pass the payment gate.
                        // Fail-closed: any verification failure = message rejected.
                        let sender = envelope.sender;
                        let msg_id = envelope.id;

                        // Compute plasticity trust discount from sender's synaptic weight.
                        // Trusted peers (high weight) get lower required payment.
                        let trust_discount = routing_for_recv
                            .get_peer_weight(&sender)
                            .await
                            .map(konsensus_pricing::compute_trust_discount)
                            .unwrap_or(0.0);

                        // Whitelist check (Principle 3: closed mesh) + payment-gate
                        // verify (Principle 2), with the registry read guard
                        // released BEFORE the gate await. Extracted into
                        // `whitelist_then_verify` so the HARD-11
                        // lock-release-before-await contract is directly
                        // unit-testable (tests::whitelist_read_guard_released_*).
                        let is_relay_control = relay_engine_for_recv.is_some()
                            && konsensus_core::kind::KindCategory::from_kind(envelope.kind)
                                == konsensus_core::kind::KindCategory::Storage;
                        let mut gate_result = whitelist_then_verify(
                            &envelope,
                            audit_for_recv.membrane(),
                            peer_registry_for_recv.as_ref(),
                            gate_for_recv.as_ref(),
                            nonce_adapter.as_ref(),
                            pricing_for_recv.as_ref(),
                            Some(verify_lightning.as_ref()),
                            trust_discount,
                            // Bind settlement to THIS node so a payment proof
                            // addressed to a different node is non-transferable.
                            Some(identity_for_recv.node_id()),
                            // M1a: Whitelist => Step-2 membership enforced;
                            // PriceOpen => membership skipped, payment still gates.
                            admission_mode_for_recv,
                            is_relay_control,
                        )
                        .await;

                        if matches!(gate_result, Ok((_, true))) {
                            let ack = Frame::MessageAck { id: msg_id, duplicate: true };
                            if let Err(e) = transport_for_ack.send_frame(&sender, &ack).await {
                                warn!(error = %e, "failed to send duplicate ACK");
                            }
                            continue;
                        }

                        if gate_result.is_ok() && !is_relay_control {
                            use konsensus_storage::PaidAcceptance;
                            match storage_for_recv.accept_paid_envelope(&envelope).await {
                                Ok(PaidAcceptance::Accepted) => {
                                    audit_for_recv.membrane().admitted(&envelope, gate_result.as_ref().expect("validated").0);
                                }
                                Ok(PaidAcceptance::AlreadyAccepted) => {
                                    // No second promotion, decrypt, application side effect or write.
                                    let ack = Frame::MessageAck { id: msg_id, duplicate: true };
                                    if let Err(e) = transport_for_ack.send_frame(&sender, &ack).await {
                                        warn!(error = %e, "failed to send duplicate ACK");
                                    }
                                    continue;
                                }
                                Ok(PaidAcceptance::NonceReused) => {
                                    let rejection = konsensus_core::gate::GateRejection::ReplayDetected;
                                    audit_for_recv.membrane().refused(&envelope, &rejection);
                                    gate_result = Err(rejection);
                                }
                                Ok(PaidAcceptance::PaymentReused) => {
                                    let rejection = konsensus_core::gate::GateRejection::PaymentProofReused {
                                        payment_hash: hex::encode(envelope.payment_proof.payment_hash),
                                    };
                                    audit_for_recv.membrane().refused(&envelope, &rejection);
                                    gate_result = Err(rejection);
                                }
                                Err(e) => {
                                    error!(error = %e, "atomic paid acceptance failed; replay keys rolled back");
                                    audit_for_recv.membrane().refused(&envelope,
                                        &konsensus_core::gate::GateRejection::NonceCheckFailed(e.to_string()));
                                    let reject = Frame::MessageReject { id: msg_id, reason: "storage error".into() };
                                    let _ = transport_for_ack.send_frame(&sender, &reject).await;
                                    continue;
                                }
                            }
                        }

                        if let Err(rejection) = gate_result {
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
                                | konsensus_core::gate::GateRejection::PaymentSettlementMismatch(_)
                                | konsensus_core::gate::GateRejection::PaymentProofReused { .. }
                                | konsensus_core::gate::GateRejection::LightningUnavailable(_) => {
                                    metrics::counter!(
                                        konsensus_api::metrics::PAYMENT_FAILURES
                                    )
                                    .increment(1);
                                }
                                _ => {}
                            }

                            // Rejected PriceOpen strangers get no application record
                            // or response. In particular, an underpaid self-generated
                            // proof must not bypass the bounded chat quote to obtain
                            // arbitrary-kind prices or the complete price table.
                            if matches!(admission_mode_for_recv, konsensus_message::ReachabilityMode::PriceOpen)
                                && !transport_for_recv.connected_privileged_peers().await.contains(&sender)
                            {
                                continue;
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
                            // so the sender can update their cache and retry successfully —
                            // but throttle it per-peer. Only privileged peers reach
                            // this response path; unpaid PriceOpen strangers were
                            // dropped above without revealing a price table.
                            if matches!(rejection, konsensus_core::gate::GateRejection::InsufficientPayment { .. }) {
                                if corrective_price_table_rate_limited(
                                    &mut last_corrective_price_table,
                                    &sender,
                                    tokio::time::Instant::now(),
                                ) {
                                    debug!(peer = %sender, "corrective price table rate-limited; not resent");
                                } else {
                                    let meta = konsensus_pricing::peer_prices::build_full_price_table(
                                        pricing_for_recv.as_ref(),
                                        chain_for_recv.as_ref(),
                                    ).await;
                                    let price_frame = Frame::PriceTable {
                                        prices: meta.prices,
                                        block_height: meta.block_height,
                                        valid_blocks: meta.valid_blocks,
                                        // Reuse the trust_discount already computed for this
                                        // sender above — no second wallet weight lookup.
                                        trust_discount,
                                    };
                                    if let Err(e) = crate::delivery_prices::send_price_frame(&transport_for_ack, storage_for_recv.as_ref(), &sender, &price_frame, pricing_for_recv.as_ref()).await {
                                        warn!(peer = %sender, error = %e, "failed to send corrective price table");
                                    } else {
                                        info!(peer = %sender, "sent corrective price table after payment mismatch");
                                    }
                                }
                            }
                            continue;
                        }

                        // M1b promote-on-paid: the PaymentGate just accepted a
                        // PAID, M2-recipient-bound UKM from `sender`. Flip this
                        // connection to privileged so its subsequent control frames
                        // (session/X3DH/invoice/peer-exchange/Lightning) are no
                        // longer dropped. We promote by `sender`; the transport peer
                        // map is keyed by the AUTHENTICATED federation NodeId, so a
                        // relayer that forwards someone else's proof cannot promote
                        // its own connection — only the connection that authenticated
                        // as `sender` is flipped (binding: envelope.sender ==
                        // connection.peer_id). In Whitelist mode the peer is already
                        // privileged, so this is a no-op (byte-identical).
                        //
                        // PSI-SPEED: offer our prekey on that connection now,
                        // instead of on the next self-heal tick (up to 15 s).
                        // Only the connection just promoted by this payment is
                        // offered to, never an unpaid peer, and the offer is
                        // rate-limited (`EagerOfferLimiter`).
                        if matches!(
                            admission_mode_for_recv,
                            konsensus_message::ReachabilityMode::PriceOpen
                        ) {
                            if let Some(promoted) = transport_for_recv.promote_to_privileged_at(&sender).await {
                                offer_prekey_after_promotion(
                                    &transport_for_ack,
                                    &session_mgr_for_recv,
                                    &sender,
                                    promoted,
                                    &mut eager_offers,
                                )
                                .await;
                            } else {
                                debug!(sender = %sender, "paid sender has no live connection to promote (relayed/offline proof)");
                            }
                        }

                        // R3 SEAM-B (Route B) — relay-control intercept. Fires only
                        // when the relay engine is enabled (`Some`) and the kind is
                        // Storage-category (600–699). The gate above has ALREADY
                        // settled + recipient-bound + single-use + charged this
                        // control UKM, so this is pure post-payment routing (no new
                        // admission authority). Runs BEFORE `store_message` /
                        // `decrypt_and_process`: a relay-control UKM is never stored
                        // as a message and never fed to the ratchet — the relay
                        // touches opaque routing fields only ("host the box, never
                        // the plaintext"). Inert when disabled (None → skipped,
                        // byte-identical to today).
                        if let Some(relay_engine) = relay_engine_for_recv.as_ref() {
                            if konsensus_core::kind::KindCategory::from_kind(envelope.kind)
                                == konsensus_core::kind::KindCategory::Storage
                            {
                                for (peer, frame) in crate::relay::dispatch::handle_relay_control(
                                    relay_engine.as_ref(),
                                    &envelope,
                                    identity_for_recv.node_id(),
                                )
                                .await
                                {
                                    if let Err(e) =
                                        transport_for_ack.send_frame(&peer, &frame).await
                                    {
                                        warn!(peer = %peer, error = %e, "failed to send relay-control reply");
                                    }
                                }
                                continue;
                            }
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

                        // 1:1 calls: the gate made this envelope paid and single-use;
                        // the call registry makes the offer single-use per call id and
                        // accepts answer/ICE/hangup only for a live call with this
                        // sender. A refused signal never reaches the app.
                        if konsensus_api::calls::is_call_kind(envelope.kind) {
                            if let Err(refusal) = konsensus_api::calls::admit_incoming(storage_for_recv.as_ref(), &sender, envelope.kind, plaintext.as_deref()).await {
                                warn!(sender = %sender, kind = envelope.kind, reason = %refusal, "call signal refused; not forwarded");
                                // Paid but refused: withdraw the stored message and its
                                // plaintext and mark the receipt application-rejected, so
                                // history, resync and a resend never present it as
                                // delivered (Codex P1). Payment hash and nonce stay burned.
                                if let Err(e) = storage_for_recv.reject_accepted_envelope(&envelope).await {
                                    error!(msg_id = %msg_id, error = %e, "failed to withdraw a refused call signal");
                                }
                                audit_for_recv.record(
                                    konsensus_api::audit::events::MESSAGE_REJECTED,
                                    &sender.to_hex(),
                                    Some(serde_json::json!({ "reason": refusal.to_string(), "kind": envelope.kind })),
                                );
                                let reject = Frame::MessageReject { id: msg_id, reason: refusal.to_string() };
                                if let Err(e) = transport_for_ack.send_frame(&sender, &reject).await {
                                    warn!(peer = %sender, error = %e, "failed to send MessageReject");
                                }
                                continue;
                            }
                        }

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
                        let ack = Frame::MessageAck { id: msg_id, duplicate: false };
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
                let frame = Frame::PrekeyOffer {
                    bundle: bundle_json,
                };
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
            if let Err(e) = storage
                .store_message_plaintext(&envelope.id, &encrypted)
                .await
            {
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
    } else if konsensus_core::is_web_service_reply(envelope) {
        // 510/501 reply bound to our paid request: deliver plaintext to the
        // frontend, never treat it as a fresh manifest/page request (F3).
        match String::from_utf8(bytes) {
            Ok(text) => {
                info!(
                    sender = %sender,
                    kind = envelope.kind,
                    msg_id = %envelope.id,
                    "received web service reply — forwarding to frontend"
                );
                Some(text)
            }
            Err(_) => {
                debug!(sender = %sender, kind = envelope.kind, "web service reply payload is not UTF-8");
                None
            }
        }
    } else if envelope.kind == konsensus_core::kind::KIND_WEB_MANIFEST {
        process_web_manifest(
            sender,
            envelope,
            content_server,
            chain,
            pricing,
            identity,
            session_mgr,
            transport,
        )
        .await
    } else if envelope.kind == konsensus_core::kind::KIND_PAGE_REQUEST {
        process_page_request(
            &bytes,
            sender,
            envelope,
            content_server,
            pricing,
            identity,
            session_mgr,
            transport,
            audit,
        )
        .await
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
#[allow(clippy::too_many_arguments)]
async fn process_web_manifest(
    sender: &konsensus_core::types::NodeId,
    request: &konsensus_core::UkmEnvelope,
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
            request,
            &manifest,
            konsensus_core::kind::KIND_WEB_MANIFEST,
            identity,
            session_mgr,
            transport,
        )
        .await;
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
    _pricing: &Arc<dyn konsensus_core::traits::pricing::PricingEngine>,
    identity: &Arc<NodeIdentity>,
    session_mgr: &SessionManager,
    transport: &Arc<NoiseTransport>,
    audit: &Arc<AuditLog>,
) -> Option<String> {
    let page_req: konsensus_core::payloads::content::PageRequest =
        match serde_json::from_slice(bytes) {
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
            envelope,
            &response,
            konsensus_core::kind::KIND_PAGE_RESPONSE,
            identity,
            session_mgr,
            transport,
        )
        .await;
    }

    audit.record(
        "page_served",
        &sender.to_hex(),
        Some(serde_json::json!({
            "path": page_req.path,
            "request_id": page_req.request_id,
        })),
    );

    Some(format!("[page request: {}]", page_req.path))
}

/// Encrypt and send a web service reply bound to the requester's paid request.
///
/// Uses [`konsensus_core::reply_bound_proof`] (amount 0, request's hash/preimage)
/// and references the request MessageId. Never calls `generate_valid_proof`.
async fn send_encrypted_response<T: serde::Serialize>(
    peer_id: &konsensus_core::types::NodeId,
    request: &konsensus_core::UkmEnvelope,
    payload: &T,
    kind: u16,
    identity: &NodeIdentity,
    session_mgr: &SessionManager,
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
    let proof = konsensus_core::reply_bound_proof(&request.payment_proof);
    let mut resp_envelope = konsensus_core::UkmEnvelopeBuilder::new(
        kind,
        our_id,
        konsensus_core::Recipient::Node(*peer_id),
        ciphertext,
        proof,
    )
    .references(vec![request.id])
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
