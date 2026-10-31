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
use konsensus_core::payloads::calendar::{CalendarEventPayload, CalendarPayloadError, RsvpPayload};
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
    /// The owner's published card, answered at `/front-door.json` whether or
    /// not `[web]` is enabled: publishing it is consent to share it.
    pub front_door: konsensus_api::handlers::front_door::FrontDoorStore,
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
    // This act's quote must be authenticated before any payment is consumed.
    // Only PeerExchangePaidRequest reaches that path; ordinary Message frames
    // cannot spend a quote payment or turn it into a durable connection grant.
    if envelope.kind == konsensus_core::kind::KIND_PEER_EXCHANGE {
        return Err(konsensus_core::gate::GateRejection::InvalidEnvelope(
            "peer exchange requires the quoted paid request carrier".into(),
        ));
    }
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

/// The fixed, non-empty payload of a first-contact admission proof (see the
/// compose handler): a paid envelope that carries no readable content and is
/// sent before, or outside, any E2EE session. It is acknowledged as received,
/// never read.
const ADMISSION_ENVELOPE_MARKER: &[u8] = b"konsensus:admission:v1";

/// Whether `envelope` is a first-contact admission proof: the shape the
/// compose handler builds and the outbox and pending flusher recognise, a
/// `KIND_CHAT` whose ciphertext is exactly the marker. The gate has already
/// bound its recipient, settlement and signature. Any other kind carrying the
/// marker is an ordinary paid envelope and must decrypt like one.
fn is_admission_proof(envelope: &konsensus_core::UkmEnvelope) -> bool {
    envelope.kind == konsensus_core::kind::KIND_CHAT
        && envelope.ciphertext == ADMISSION_ENVELOPE_MARKER
}

/// Why a paid envelope that passed the gate and was stored is refused instead
/// of acknowledged as delivered: this node could not produce its plaintext and
/// keep it. The envelope is withdrawn (`reject_accepted_envelope`), so history
/// and resync never show it and a resend of the same bytes is answered
/// `message withdrawn`; the payment hash and nonce stay burned. The sender
/// gets a `MessageReject` whose reason starts with [`ReceiptRefusal::code`],
/// which its delivery tracking treats as terminal for that envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceiptRefusal {
    /// No session with the sender, not a ratchet message, or the ratchet
    /// refused the ciphertext.
    Undecryptable(&'static str),
    /// Decrypted, but the plaintext (or the file it carries) was not kept.
    NotPersisted(&'static str),
    /// A file whose payload is damaged or whose hash does not match its data.
    FileCorrupted(&'static str),
}

impl ReceiptRefusal {
    /// Stable code, the first word of the `MessageReject` reason.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            ReceiptRefusal::Undecryptable(_) => "undecryptable",
            ReceiptRefusal::NotPersisted(_) => "not_persisted",
            ReceiptRefusal::FileCorrupted(_) => "file_corrupted",
        }
    }

    fn detail(&self) -> &'static str {
        match self {
            ReceiptRefusal::Undecryptable(d)
            | ReceiptRefusal::NotPersisted(d)
            | ReceiptRefusal::FileCorrupted(d) => d,
        }
    }
}

impl std::fmt::Display for ReceiptRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.detail())
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
        front_door: front_door_for_recv,
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

                        if envelope.kind == konsensus_core::kind::KIND_CALL_BLOCK {
                            match storage_for_recv.is_paid_envelope_rejected(&envelope).await {
                                Ok(true) => {
                                    let reject = Frame::MessageReject { id: msg_id, reason: "call_block_overpayment".into() };
                                    let _ = transport_for_ack.send_frame(&sender, &reject).await;
                                    continue;
                                },
                                Err(e) => { error!(error = %e, "cannot read call payment receipt; withholding response"); continue; },
                                Ok(false) => {},
                            }
                        }

                        if matches!(gate_result, Ok((_, true))) {
                            let paid_until_ms = if envelope.kind == konsensus_core::kind::KIND_CALL_BLOCK {
                                match konsensus_api::calls::block_grant(storage_for_recv.as_ref(), &plaintext_cipher, &sender, &msg_id).await {
                                    Ok(grant) => grant,
                                    Err(e) => { error!(error = %e, "cannot recover call grant; withholding ACK"); continue; }
                                }
                            } else { None };
                            let ack = Frame::MessageAck { id: msg_id, duplicate: true, paid_until_ms };
                            if let Err(e) = transport_for_ack.send_frame(&sender, &ack).await {
                                warn!(error = %e, "failed to send duplicate ACK");
                            }
                            continue;
                        }

                        // Validate the block against call state before consuming its
                        // proof. Keep the call lock through acceptance so a timer or
                        // hangup cannot turn an admitted payment into a late refusal.
                        let mut incoming_block = None;
                        if gate_result.is_ok() && envelope.kind == konsensus_core::kind::KIND_CALL_BLOCK {
                            // A refusal or storage failure must leave ratchet keys
                            // available for a retransmission of this paid envelope.
                            let block_plaintext = match konsensus_crypto::ratchet_message_from_bytes(&envelope.ciphertext) {
                                Ok(message) => session_mgr_for_recv.preview_decrypt(&sender, &message).await.ok()
                                    .and_then(|bytes| String::from_utf8(bytes).ok()),
                                Err(_) => None,
                            };
                            match konsensus_api::calls::prepare_incoming_block(
                                storage_for_recv.as_ref(), &sender, block_plaintext.as_deref(), &envelope.payment_proof.payment_hash,
                            ).await {
                                Ok(block) => incoming_block = Some(block),
                                Err(refusal) => {
                                    audit_for_recv.record(
                                        konsensus_api::audit::events::MESSAGE_REJECTED,
                                        &sender.to_hex(),
                                        Some(serde_json::json!({
                                            "reason": refusal.to_string(), "kind": envelope.kind,
                                            "message_id": msg_id.to_hex(),
                                        })),
                                    );
                                    let reject = Frame::MessageReject { id: msg_id, reason: refusal.to_string() };
                                    let _ = transport_for_ack.send_frame(&sender, &reject).await;
                                    continue;
                                }
                            }
                        }

                        // Every paid envelope is held (invisible to history,
                        // plaintext, resync and duplicate ACKs) from before its
                        // paid acceptance until its admission is final: a call
                        // signal and a candidate room chat by their admission
                        // checks, a calendar envelope once its payload passed the
                        // inbound caps and its change committed with the release,
                        // everything else once its plaintext is produced and kept
                        // (a file once stored). A refusal withdraws the hold with
                        // the envelope; should that withdrawal fail, the hold still
                        // keeps the envelope hidden and unacknowledged until the
                        // startup/periodic sweep withdraws it (Codex delta2 #4,
                        // #155). The kinds whose admission is decided after
                        // acceptance are accepted under their hold (below).
                        let held_kind = konsensus_api::calls::is_call_kind(envelope.kind)
                            || konsensus_api::room_binding::is_candidate(envelope.kind)
                            || is_calendar_kind(envelope.kind);
                        let mut call_hold = false;
                        if gate_result.is_ok() && !is_relay_control {
                            match konsensus_api::calls::hold_incoming(storage_for_recv.as_ref(), &envelope).await {
                                Ok(placed) => call_hold = placed,
                                Err(e) => {
                                    drop(incoming_block.take());
                                    // Fail closed: unheld, a refused message could stay visible.
                                    error!(msg_id = %msg_id, error = %e, "incoming message not held; not accepted");
                                    let reject = Frame::MessageReject { id: msg_id, reason: "storage error".into() };
                                    let _ = transport_for_ack.send_frame(&sender, &reject).await;
                                    continue;
                                }
                            }
                        }

                        if gate_result.is_ok() && !is_relay_control {
                            use konsensus_storage::PaidAcceptance;
                            // A held kind is accepted under its hold, inside the
                            // acceptance transaction: if the sweep withdrew the hold
                            // in between, nothing is accepted and the sender's retry
                            // places a fresh hold.
                            let acceptance = if held_kind {
                                storage_for_recv.accept_held_paid_envelope(&envelope).await
                            } else {
                                storage_for_recv.accept_paid_envelope(&envelope).await
                            };
                            // Burned replay keys: decide, fail closed, what the resend
                            // is told BEFORE the gate's payment-reuse reason can be
                            // produced (the sender reads that one as a legacy ACK).
                            let burned_reply = match &acceptance {
                                Ok(PaidAcceptance::NonceReused | PaidAcceptance::PaymentReused) => {
                                    burned_replay_reply(storage_for_recv.as_ref(), &envelope).await
                                }
                                _ => None,
                            };
                            match acceptance {
                                // A web reply the gate accepted is bound to OUR paid
                                // request: the sender paid nothing, so it is no admission.
                                Ok(PaidAcceptance::Accepted) if konsensus_core::is_web_service_reply(&envelope) => {}
                                Ok(PaidAcceptance::Accepted) => {
                                    audit_for_recv.membrane().admitted(&envelope, gate_result.as_ref().expect("validated").0);
                                }
                                Ok(PaidAcceptance::AlreadyAccepted) => {
                                    drop(incoming_block.take());
                                    // A duplicate ACK needs POSITIVE, durable evidence of
                                    // admission (receipt accepted and not held), read now,
                                    // after the acceptance transaction: a still-held
                                    // envelope was never admitted, one the sweep withdrew
                                    // meanwhile no longer exists, and an unreadable status
                                    // is not evidence. The absence of a hold is not proof.
                                    if matches!(storage_for_recv.is_paid_envelope_accepted(&envelope).await, Ok(true)) {
                                        // No second promotion, decrypt, application side effect or write.
                                        let paid_until_ms = if envelope.kind == konsensus_core::kind::KIND_CALL_BLOCK {
                                            match konsensus_api::calls::block_grant(storage_for_recv.as_ref(), &plaintext_cipher, &sender, &msg_id).await {
                                                Ok(grant) => grant,
                                                Err(e) => { error!(error = %e, "cannot recover call grant; withholding ACK"); continue; }
                                            }
                                        } else { None };
                                        let ack = Frame::MessageAck { id: msg_id, duplicate: true, paid_until_ms };
                                        if let Err(e) = transport_for_ack.send_frame(&sender, &ack).await {
                                            warn!(error = %e, "failed to send duplicate ACK");
                                        }
                                        continue;
                                    }
                                    let reason = if matches!(storage_for_recv.is_application_rejected(&envelope).await, Ok(true)) {
                                        application_rejected_reason()
                                    } else if konsensus_api::calls::is_call_kind(envelope.kind) {
                                        "call signal withdrawn".into()
                                    } else {
                                        "message withdrawn".into()
                                    };
                                    let reject = Frame::MessageReject { id: msg_id, reason };
                                    let _ = transport_for_ack.send_frame(&sender, &reject).await;
                                    continue;
                                }
                                Ok(PaidAcceptance::NonceReused | PaidAcceptance::PaymentReused)
                                    if burned_reply.is_some() =>
                                {
                                    // A resend of a paid envelope this node accepted and
                                    // then refused at the application (a withdrawn call
                                    // signal, room chat or calendar payload, or one the
                                    // hold sweep withdrew), or one whose withdrawal
                                    // status could not be read. Neither may fall through
                                    // to the payment-reuse reason below.
                                    drop(incoming_block.take());
                                    if call_hold {
                                        let _ = storage_for_recv.call_admission_release(&msg_id).await;
                                    }
                                    let reject = Frame::MessageReject { id: msg_id, reason: burned_reply.unwrap_or_default() };
                                    if let Err(e) = transport_for_ack.send_frame(&sender, &reject).await {
                                        warn!(peer = %sender, error = %e, "failed to send MessageReject");
                                    }
                                    continue;
                                }
                                Ok(PaidAcceptance::NonceReused) => {
                                    let rejection = konsensus_core::gate::GateRejection::ReplayDetected;
                                    audit_for_recv.membrane().refused(&envelope, &rejection);
                                    gate_result = Err(rejection);
                                }
                                Ok(PaidAcceptance::Withdrawn) => {
                                    drop(incoming_block.take());
                                    // This exact envelope was accepted, then refused and
                                    // withdrawn (a call, a room chat, a receipt refusal).
                                    // Its payment stays burned. The sender hears the
                                    // refusal again, terminal on its side, never the
                                    // reused-proof reply its legacy receipt path could
                                    // mistake for a delivery: a lost refusal is not a
                                    // delivery on retry.
                                    if call_hold {
                                        let _ = storage_for_recv.call_admission_release(&msg_id).await;
                                    }
                                    let reason = if konsensus_api::calls::is_call_kind(envelope.kind) { "call signal withdrawn" } else { "message withdrawn" };
                                    let reject = Frame::MessageReject { id: msg_id, reason: reason.into() };
                                    if let Err(e) = transport_for_ack.send_frame(&sender, &reject).await {
                                        warn!(peer = %sender, error = %e, "failed to send MessageReject");
                                    }
                                    continue;
                                }
                                Ok(PaidAcceptance::PaymentReused) => {
                                    let rejection = konsensus_core::gate::GateRejection::PaymentProofReused {
                                        payment_hash: hex::encode(envelope.payment_proof.payment_hash),
                                    };
                                    audit_for_recv.membrane().refused(&envelope, &rejection);
                                    gate_result = Err(rejection);
                                }
                                Err(e) => {
                                    drop(incoming_block.take());
                                    // The hold placed above is KEPT: the acceptance may
                                    // have committed before the error (a lost commit
                                    // response), and releasing would expose an accepted
                                    // envelope that never had its admission, which a
                                    // replay could then duplicate-acknowledge. Held, it
                                    // stays hidden; a retry re-admits it (the hold is
                                    // inherited) or the sweep withdraws it.
                                    error!(error = %e, held = call_hold, "atomic paid acceptance failed; replay keys rolled back");
                                    audit_for_recv.membrane().refused(&envelope,
                                        &konsensus_core::gate::GateRejection::NonceCheckFailed(e.to_string()));
                                    let reject = Frame::MessageReject { id: msg_id, reason: "storage error".into() };
                                    let _ = transport_for_ack.send_frame(&sender, &reject).await;
                                    continue;
                                }
                            }
                        }

                        if gate_result.is_err() {
                            drop(incoming_block.take());
                        }
                        if call_hold && gate_result.is_err() {
                            // Nothing of ours was stored under this hold.
                            let _ = storage_for_recv.call_admission_release(&msg_id).await;
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
                                    let meta = match konsensus_pricing::peer_prices::build_full_price_table(
                                        pricing_for_recv.as_ref(),
                                        chain_for_recv.as_ref(),
                                    ).await {
                                        Ok(meta) => meta,
                                        Err(_) => {
                                            warn!(peer = %sender, "not_ready: chain unavailable for corrective price table");
                                            continue;
                                        }
                                    };
                                    let price_frame = Frame::PriceTable {
                                        prices: meta.prices,
                                        block_height: meta.block_height,
                                        valid_blocks: meta.valid_blocks,
                                        // Reuse the trust_discount already computed for this
                                        // sender above — no second wallet weight lookup.
                                        trust_discount,
                                    };
                                    if let Err(e) = crate::delivery_prices::send_price_frame(&transport_for_ack, storage_for_recv.as_ref(), &sender, &price_frame, pricing_for_recv.as_ref(), gate_for_recv.min_admission_cost_msat()).await {
                                        warn!(peer = %sender, error = %e, "failed to send corrective price table");
                                    } else {
                                        info!(peer = %sender, "sent corrective price table after payment mismatch");
                                    }
                                }
                            }
                            continue;
                        }

                        // A committed block's grant: its call state and the release
                        // of its hold were written in one transaction, so from here
                        // on it is admitted for good and only the ACK remains.
                        let mut committed_until = None;
                        let admitted_block = match incoming_block {
                            Some(block) => {
                                let identity = block.signal().clone();
                                if let Some(refusal) = block.refusal() {
                                    error!(msg_id = %msg_id, reason = %refusal, "PAID CALL BLOCK NOT SERVED: overpayment requires reconciliation");
                                    let recorded = audit_for_recv.record_durable(
                                        konsensus_api::audit::events::CALL_BLOCK_OVERPAYMENT,
                                        &sender.to_hex(), serde_json::json!({
                                            "message_id": msg_id.to_hex(), "call_id": identity.call_id,
                                            "seq": identity.seq, "amount_msat": envelope.payment_proof.amount_msat,
                                            "payment_hash": hex::encode(envelope.payment_proof.payment_hash),
                                            "reason": refusal.to_string(), "reconciliation_required": true,
                                        }));
                                    let audit_failed = recorded.is_err();
                                    if let Err(e) = recorded {
                                        error!(msg_id = %msg_id, error = %e, "OVERPAYMENT AUDIT WRITE FAILED; retained payment receipt requires reconciliation");
                                    }
                                    drop(block);
                                    if let Err(e) = storage_for_recv.reject_accepted_envelope(&envelope).await {
                                        error!(msg_id = %msg_id, error = %e, "overpayment receipt could not be marked rejected");
                                        if audit_failed {
                                            error!(msg_id = %msg_id, call_id = %identity.call_id, seq = ?identity.seq,
                                                amount_msat = envelope.payment_proof.amount_msat,
                                                payment_hash = %hex::encode(envelope.payment_proof.payment_hash),
                                                "CRITICAL: OVERPAYMENT AUDIT AND REJECT MARKING BOTH FAILED; manual reconciliation required");
                                        }
                                    }
                                    let reject = Frame::MessageReject { id: msg_id, reason: "call_block_overpayment".into() };
                                    let _ = transport_for_ack.send_frame(&sender, &reject).await;
                                    continue;
                                }
                                let committed = async {
                                    let bytes = serde_json::to_vec(&identity).map_err(|e| konsensus_storage::StorageError::Conversion(e.to_string()))?;
                                    let cached = plaintext_cipher.encrypt(&bytes).map_err(|e| konsensus_storage::StorageError::Conversion(e.to_string()))?;
                                    storage_for_recv.store_message_plaintext(&msg_id, &cached).await?;
                                    block.commit(&msg_id).await
                                }.await;
                                match committed {
                                    Ok((signal, paid_until_ms)) => {
                                        committed_until = paid_until_ms;
                                        Some(signal)
                                    }
                                    Err(e) => {
                                        error!(msg_id = %msg_id, error = %e, "accepted block state could not be stored; withheld");
                                        // The receipt retains settlement evidence even when
                                        // withdrawal removes the message. Link it to the
                                        // failed service interval for reconciliation; never
                                        // put a preimage or decrypted payload in the audit.
                                        audit_for_recv.record(
                                            konsensus_api::audit::events::CALL_BLOCK_COMMIT_FAILED,
                                            &sender.to_hex(),
                                            Some(serde_json::json!({
                                                "message_id": msg_id.to_hex(),
                                                "call_id": identity.call_id,
                                                "seq": identity.seq,
                                                "amount_msat": envelope.payment_proof.amount_msat,
                                                "reconciliation_required": true,
                                            })),
                                        );
                                        let _ = storage_for_recv.reject_accepted_envelope(&envelope).await;
                                        let reject = Frame::MessageReject { id: msg_id, reason: "storage error".into() };
                                        let _ = transport_for_ack.send_frame(&sender, &reject).await;
                                        continue;
                                    }
                                }
                            },
                            None => None,
                        };

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
                        //
                        // A web reply bound to our paid request promotes nothing:
                        // we paid, the replying node did not (BROWSE.md §4).
                        if matches!(
                            admission_mode_for_recv,
                            konsensus_message::ReachabilityMode::PriceOpen
                        ) && !konsensus_core::is_web_service_reply(&envelope)
                        {
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

                        // Attempt to decrypt ciphertext via Double Ratchet session.
                        // A paid envelope whose plaintext cannot be produced and
                        // kept is never acknowledged as delivered: it is withdrawn
                        // (the payment hash and nonce stay burned) and the sender
                        // gets a typed `MessageReject`. If the withdrawal fails, a
                        // held chat stays hidden until the sweep.
                        //
                        // A committed call block is the exception: its grant is
                        // already durable, its hold already released with it, and
                        // its metadata was cached before the commit, so no second
                        // plaintext write is made, and a later refusal never
                        // withdraws it. Withdrawing would keep the caller's
                        // settled debit as failed while the interval stays
                        // granted here; the ratchet still advances and the grant
                        // is acknowledged (and replayed) as usual.
                        let committed_block = admitted_block.is_some();
                        let plaintext = match decrypt_and_process(
                            &envelope,
                            &sender,
                            &session_mgr_for_recv,
                            &plaintext_cipher,
                            &storage_for_recv,
                            &content_server_for_recv,
                            &front_door_for_recv,
                            &chain_for_recv,
                            &pricing_for_recv,
                            &identity_for_recv,
                            &transport_for_ack,
                            &audit_for_recv,
                            &gate_for_recv,
                            trust_discount,
                            !committed_block,
                        ).await {
                            Ok(plaintext) => plaintext,
                            Err(InboundRefusal::Receipt(refusal)) if committed_block => {
                                error!(sender = %sender, msg_id = %msg_id, reason = %refusal, "committed call block: post-commit refusal ignored; the durable grant stands and is acknowledged");
                                None
                            }
                            Err(InboundRefusal::Receipt(refusal)) => {
                                warn!(sender = %sender, kind = envelope.kind, msg_id = %msg_id, reason = %refusal, "paid message not readable or not kept; refused, not acknowledged");
                                if let Err(e) = storage_for_recv.reject_accepted_envelope(&envelope).await {
                                    error!(msg_id = %msg_id, error = %e, "failed to withdraw a refused message; a held chat stays hidden until the sweep");
                                }
                                audit_for_recv.record(
                                    konsensus_api::audit::events::MESSAGE_REJECTED,
                                    &sender.to_hex(),
                                    Some(serde_json::json!({ "reason": refusal.code(), "kind": envelope.kind, "message_id": msg_id.to_hex() })),
                                );
                                let reject = Frame::MessageReject { id: msg_id, reason: refusal.to_string() };
                                if let Err(e) = transport_for_ack.send_frame(&sender, &reject).await {
                                    warn!(peer = %sender, error = %e, "failed to send MessageReject");
                                }
                                continue;
                            }
                            Err(InboundRefusal::NotCommitted) => {
                                // The calendar envelope passed the caps but its event or
                                // RSVP and hold release did not commit together: nothing
                                // of it was persisted, it stays held and hidden for the
                                // sweep, and the sender gets a transient reject, not an
                                // ACK.
                                let reject = Frame::MessageReject { id: msg_id, reason: "storage error".into() };
                                let _ = transport_for_ack.send_frame(&sender, &reject).await;
                                continue;
                            }
                            Err(InboundRefusal::Calendar(refusal)) => {
                                // A calendar payload over the inbound caps is refused
                                // before it is cached, copied, stored or expanded. Like
                                // a refused call signal: the paid envelope is withdrawn
                                // (payment hash and nonce stay burned) and the sender
                                // gets a typed reason it can act on. The envelope was
                                // held before acceptance, so if the withdrawal fails it
                                // stays hidden and the sweep withdraws it.
                                warn!(sender = %sender, kind = envelope.kind, reason = %refusal, "calendar payload refused; not stored");
                                if let Err(e) = storage_for_recv.reject_accepted_envelope(&envelope).await {
                                    error!(msg_id = %msg_id, error = %e, "failed to withdraw a refused calendar payload; it stays held until the sweep");
                                }
                                audit_for_recv.record(
                                    konsensus_api::audit::events::MESSAGE_REJECTED,
                                    &sender.to_hex(),
                                    Some(serde_json::json!({ "reason": refusal.code(), "kind": envelope.kind })),
                                );
                                let reject = Frame::MessageReject { id: msg_id, reason: calendar_reject_reason(&refusal) };
                                if let Err(e) = transport_for_ack.send_frame(&sender, &reject).await {
                                    warn!(peer = %sender, error = %e, "failed to send MessageReject");
                                }
                                continue;
                            }
                        };

                        // The plaintext is produced and kept (a file stored): lift
                        // the hold now, except for a call signal or a candidate
                        // room chat, whose admission checks below lift their own,
                        // and a calendar envelope, whose hold was lifted in the
                        // transaction that committed its event or RSVP.
                        // Released whether or not this attempt placed the hold: a
                        // retry can inherit one left by an earlier attempt whose
                        // acceptance rolled back and whose cleanup failed, and an
                        // acknowledged message must never stay hidden. If the
                        // write fails the envelope stays held and the sweep
                        // withdraws it: fail closed, a reject, not an ACK.
                        if !konsensus_api::calls::is_call_kind(envelope.kind)
                            && !konsensus_api::room_binding::is_candidate(envelope.kind)
                            && !is_calendar_kind(envelope.kind)
                        {
                            if let Err(e) = storage_for_recv.call_admission_release(&msg_id).await {
                                error!(msg_id = %msg_id, error = %e, "admitted message could not be released; withheld");
                                let reject = Frame::MessageReject { id: msg_id, reason: "storage error".into() };
                                let _ = transport_for_ack.send_frame(&sender, &reject).await;
                                continue;
                            }
                        }

                        // 1:1 calls: the gate made this envelope paid and single-use;
                        // the call registry makes the offer single-use per call id and
                        // accepts answer/ICE/hangup only for a live call with this
                        // sender. A refused signal never reaches the app.
                        if konsensus_api::calls::is_call_kind(envelope.kind) {
                            let admitted = match admitted_block {
                                Some(signal) => Ok(signal),
                                None => konsensus_api::calls::admit_incoming(storage_for_recv.as_ref(), identity_for_recv.node_id(), &sender, envelope.kind, plaintext.as_deref()).await,
                            };
                            // Admitted: lift the hold before the app sees it. If that
                            // write fails the signal stays held and is withdrawn by the
                            // sweep: fail closed, the peer gets a reject, not an ACK.
                            // A committed block's hold was lifted in its commit
                            // transaction: nothing is left that could withhold its
                            // grant ACK or let the sweep withdraw it (Codex P1).
                            let admitted = match admitted {
                                Ok(signal) if committed_block => Ok(signal),
                                Ok(signal) => match storage_for_recv.call_admission_release(&msg_id).await {
                                    Ok(()) => Ok(signal),
                                    Err(e) => {
                                        error!(msg_id = %msg_id, error = %e, "admitted call signal could not be released; withheld");
                                        let reject = Frame::MessageReject { id: msg_id, reason: "storage error".into() };
                                        let _ = transport_for_ack.send_frame(&sender, &reject).await;
                                        continue;
                                    }
                                },
                                Err(refusal) => Err(refusal),
                            };
                            if let Err(refusal) = admitted {
                                warn!(sender = %sender, kind = envelope.kind, reason = %refusal, "call signal refused; not forwarded");
                                // Paid but refused: withdraw the stored message and its
                                // plaintext and mark the receipt application-rejected, so
                                // history, resync and a resend never present it as
                                // delivered (Codex P1). Payment hash and nonce stay burned.
                                // If this fails the hold keeps it invisible and the
                                // startup/periodic sweep withdraws it (Codex delta2 #4).
                                if let Err(e) = storage_for_recv.reject_accepted_envelope(&envelope).await {
                                    error!(msg_id = %msg_id, error = %e, "failed to withdraw a refused call signal; it stays held until the sweep");
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

                        // Rooms: a held chat is checked after decryption. A bound
                        // chat whose binding is invalid or whose roster lacks the
                        // sender or this node is refused like a call signal:
                        // withdrawn (the payment hash and nonce stay burned) and
                        // never shown; if the withdrawal fails it stays held until
                        // the sweep. Anything else is released before the app sees
                        // it (whether or not this attempt placed the hold: a retry
                        // can inherit one); if that write fails it stays held:
                        // fail closed.
                        let room = konsensus_api::room_binding::admit_incoming(identity_for_recv.node_id(), &sender, envelope.kind, plaintext.as_deref());
                        // Released whether this attempt placed the hold or inherited it
                        // from an attempt whose acceptance errored (the hold is kept
                        // then, see above): an admitted chat must never stay held.
                        if room.is_ok() && konsensus_api::room_binding::is_candidate(envelope.kind) {
                            if let Err(e) = storage_for_recv.call_admission_release(&msg_id).await {
                                error!(msg_id = %msg_id, error = %e, "admitted chat could not be released; withheld");
                                let reject = Frame::MessageReject { id: msg_id, reason: "storage error".into() };
                                let _ = transport_for_ack.send_frame(&sender, &reject).await;
                                continue;
                            }
                        }
                        if let Err(refusal) = room {
                            warn!(sender = %sender, reason = %refusal, "room chat refused; not forwarded");
                            if let Err(e) = storage_for_recv.reject_accepted_envelope(&envelope).await {
                                error!(msg_id = %msg_id, error = %e, "failed to withdraw a refused room chat; it stays held until the sweep");
                            }
                            audit_for_recv.record(
                                konsensus_api::audit::events::MESSAGE_REJECTED,
                                &sender.to_hex(),
                                Some(serde_json::json!({ "reason": refusal.code(), "kind": envelope.kind })),
                            );
                            let reject = Frame::MessageReject { id: msg_id, reason: format!("{}: {refusal}", refusal.code()) };
                            if let Err(e) = transport_for_ack.send_frame(&sender, &reject).await {
                                warn!(peer = %sender, error = %e, "failed to send MessageReject");
                            }
                            continue;
                        }

                        // A committed block is acknowledged with the boundary it
                        // just committed, never re-read: no storage read can
                        // withhold the ACK of a durable grant. A duplicate
                        // replays the same boundary from storage.
                        let paid_until_ms = if committed_block { committed_until } else { None };
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
                        let ack = Frame::MessageAck { id: msg_id, duplicate: false, paid_until_ms };
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
/// Returns the plaintext string when it was produced and kept (`Ok(None)` when
/// it was kept but is not UTF-8 text, or for an admission proof, which carries
/// none). Returns [`InboundRefusal::Receipt`] when no plaintext could be
/// produced (no session, not a ratchet message, or a failed decryption, which
/// also triggers session re-negotiation) or kept; the caller then withdraws the
/// envelope and refuses it instead of acknowledging delivery. The other
/// [`InboundRefusal`] variants are a calendar envelope the caller must not
/// acknowledge: a payload refused by the inbound caps (nothing of it was cached,
/// copied or stored; the caller withdraws the envelope and tells the sender why)
/// or an admission that did not commit (nothing was persisted; the envelope
/// stays held for the sweep).
///
/// Calendar order: decode under the caps, cache the plaintext, then persist the event
/// or RSVP and release the admission hold in one storage transaction. A refusal
/// therefore never follows a calendar mutation, a mutation never lands on an envelope
/// that stays held, and an accepted, unheld envelope always has its mutation.
#[allow(clippy::too_many_arguments)]
async fn decrypt_and_process(
    envelope: &konsensus_core::UkmEnvelope,
    sender: &konsensus_core::types::NodeId,
    session_mgr: &SessionManager,
    plaintext_cipher: &PlaintextCacheCipher,
    storage: &Arc<dyn konsensus_storage::Storage>,
    content_server: &Option<Arc<ContentServer>>,
    front_door: &konsensus_api::handlers::front_door::FrontDoorStore,
    chain: &Arc<dyn ChainProvider>,
    pricing: &Arc<dyn konsensus_core::traits::pricing::PricingEngine>,
    identity: &Arc<NodeIdentity>,
    transport: &Arc<NoiseTransport>,
    audit: &Arc<AuditLog>,
    gate: &PaymentGate,
    trust_discount: f64,
    cache_plaintext: bool,
) -> Result<Option<String>, InboundRefusal> {
    // A first-contact admission proof carries nothing to read; it is
    // acknowledged as received whether or not a session exists yet.
    if is_admission_proof(envelope) {
        debug!(sender = %sender, "admission proof envelope; nothing to decrypt");
        return Ok(None);
    }
    if !session_mgr.has_session(sender).await {
        debug!(sender = %sender, "no E2EE session, cannot decrypt");
        return Err(InboundRefusal::Receipt(ReceiptRefusal::Undecryptable(
            "no E2EE session with the sender",
        )));
    }

    let ratchet_msg = match konsensus_crypto::ratchet_message_from_bytes(&envelope.ciphertext) {
        Ok(msg) => msg,
        Err(e) => {
            debug!(sender = %sender, error = %e, "ciphertext is not a valid ratchet message");
            return Err(InboundRefusal::Receipt(ReceiptRefusal::Undecryptable(
                "ciphertext is not a ratchet message",
            )));
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
            return Err(InboundRefusal::Receipt(ReceiptRefusal::Undecryptable(
                "the session could not decrypt the ciphertext",
            )));
        }
    };

    // Calendar payloads are bounded BEFORE the plaintext cache below and before
    // any record is built: the transport's per-peer byte budget and the payment
    // gate already ran on the envelope; the decode-time caps (bytes, field
    // lengths, attendee count, implied recurrence size) run here, so an
    // over-cap payload is refused with nothing copied, stored or expanded.
    let calendar = match envelope.kind {
        konsensus_core::kind::KIND_CALENDAR_EVENT | konsensus_core::kind::KIND_CALENDAR_UPDATE => {
            Some(CalendarInbound::Event(Box::new(CalendarEventPayload::decode(&bytes).map_err(|e| {
                debug!(sender = %sender, reason = %e, "calendar event payload refused at decode");
                InboundRefusal::Calendar(e)
            })?)))
        }
        konsensus_core::kind::KIND_RSVP => {
            Some(CalendarInbound::Rsvp(RsvpPayload::decode(&bytes).map_err(|e| {
                debug!(sender = %sender, reason = %e, "RSVP payload refused at decode");
                InboundRefusal::Calendar(e)
            })?))
        }
        _ => None,
    };

    // Cache decrypted plaintext (encrypted at rest) for API access. A paid
    // message this node cannot keep is not delivered. A committed call block
    // (`cache_plaintext == false`) already cached its metadata before commit.
    if cache_plaintext {
        match plaintext_cipher.encrypt(&bytes) {
            Ok(encrypted) => {
                if let Err(e) = storage
                    .store_message_plaintext(&envelope.id, &encrypted)
                    .await
                {
                    warn!(msg_id = %envelope.id, error = %e, "failed to cache plaintext");
                    return Err(InboundRefusal::Receipt(ReceiptRefusal::NotPersisted(
                        "the plaintext could not be stored",
                    )));
                }
            }
            Err(e) => {
                warn!(msg_id = %envelope.id, error = %e, "failed to encrypt plaintext for cache");
                return Err(InboundRefusal::Receipt(ReceiptRefusal::NotPersisted(
                    "the plaintext could not be stored",
                )));
            }
        }
    }

    // The calendar payload passed the caps: persist its event or RSVP and lift
    // the admission hold in ONE transaction, whether this attempt placed the hold
    // or inherited it from an attempt whose acceptance rolled back and whose
    // cleanup failed. On any failure nothing is written: the envelope stays held
    // and hidden for the sweep and the caller rejects. A withdrawn envelope can
    // never leave a calendar change behind, and an accepted, unheld one always
    // carries its change.
    if let Some(calendar) = calendar {
        let (admission, summary) = build_calendar_admission(calendar, sender, envelope);
        storage
            .commit_calendar_admission(envelope, &admission)
            .await
            .map_err(|e| {
                error!(sender = %sender, msg_id = %envelope.id, error = %e, "calendar admission did not commit; envelope withheld for the sweep");
                InboundRefusal::NotCommitted
            })?;
        info!(sender = %sender, msg_id = %envelope.id, summary = %summary, "calendar envelope admitted");
        return Ok(Some(summary));
    }

    // Route based on message kind
    if envelope.kind == konsensus_core::kind::KIND_FILE_REF {
        return process_file_message(&bytes, sender, envelope, storage, audit)
            .await
            .map(Some)
            .map_err(InboundRefusal::Receipt);
    }
    let plaintext = if konsensus_core::is_web_service_reply(envelope) {
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
            gate,
            trust_discount,
        )
        .await
    } else if envelope.kind == konsensus_core::kind::KIND_PAGE_REQUEST {
        process_page_request(
            &bytes,
            sender,
            envelope,
            content_server,
            front_door,
            pricing,
            identity,
            session_mgr,
            transport,
            audit,
            gate,
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
    };
    Ok(plaintext)
}

/// Why `decrypt_and_process` refused to admit an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InboundRefusal {
    /// No plaintext could be produced or kept (any kind, a calendar envelope
    /// included): the caller withdraws the envelope and sends the typed
    /// [`ReceiptRefusal`] reason, never an ACK.
    Receipt(ReceiptRefusal),
    /// A calendar payload failed the inbound caps: the caller withdraws the
    /// envelope and tells the sender the typed reason.
    Calendar(CalendarPayloadError),
    /// A calendar envelope passed the caps but its admission did not commit:
    /// the event or RSVP write and the hold release share one transaction and
    /// it rolled back. Nothing was persisted; it stays held for the sweep and
    /// the caller answers with a transient storage error.
    NotCommitted,
}

/// Calendar kinds are held from before paid acceptance until their payload has
/// passed the inbound caps, like call signals and room chats.
pub(crate) fn is_calendar_kind(kind: u16) -> bool {
    matches!(
        kind,
        konsensus_core::kind::KIND_CALENDAR_EVENT
            | konsensus_core::kind::KIND_CALENDAR_UPDATE
            | konsensus_core::kind::KIND_RSVP
    )
}

/// Reason prefix for a resend of a paid envelope this node withdrew at the
/// application. Terminal for the sender (`terminal_paid_rejection`): the proof
/// is burned and nothing will be delivered.
pub(crate) const APPLICATION_REJECTED_PREFIX: &str = "application_rejected:";

pub(crate) fn application_rejected_reason() -> String {
    format!("{APPLICATION_REJECTED_PREFIX} the recipient withdrew this message; it will not be delivered")
}

/// What a resend whose replay keys are already burned is told, before the
/// gate's payment-reuse reason is considered. `Some` for an envelope this node
/// withdrew at the application (terminal `application_rejected:`) and, fail
/// closed, for a withdrawal status that could not be read (`storage error`,
/// transient): neither may fall through to `payment proof already used`, which
/// the sender's legacy-ACK compatibility path records as delivered. `None`
/// only for a genuine reuse whose status read succeeded.
pub(crate) async fn burned_replay_reply(
    storage: &dyn konsensus_storage::Storage,
    envelope: &konsensus_core::UkmEnvelope,
) -> Option<String> {
    match storage.is_application_rejected(envelope).await {
        Ok(true) => Some(application_rejected_reason()),
        Ok(false) => None,
        Err(e) => {
            error!(msg_id = %envelope.id, error = %e, "withdrawal status unreadable; replay answered as storage error, not as payment reuse");
            Some("storage error".into())
        }
    }
}

/// The `MessageReject` reason for a refused calendar payload: the stable code,
/// then the static description. The sender's `terminal_paid_rejection` matches
/// the `<code>:` prefix, so the refusal is final there (the payment proof is
/// consumed) and is never retried.
pub(crate) fn calendar_reject_reason(refusal: &CalendarPayloadError) -> String {
    format!("{}: {refusal}", refusal.code())
}

/// A calendar payload decoded under the inbound caps, ahead of the plaintext cache.
pub(crate) enum CalendarInbound {
    Event(Box<CalendarEventPayload>),
    Rsvp(RsvpPayload),
}

/// Process an incoming file transfer message (KIND_FILE_REF).
///
/// A file is received only once its data has been decoded, has matched its
/// hash and has been stored; otherwise it is refused and never surfaced to
/// the app as arrived.
async fn process_file_message(
    bytes: &[u8],
    sender: &konsensus_core::types::NodeId,
    envelope: &konsensus_core::UkmEnvelope,
    storage: &Arc<dyn konsensus_storage::Storage>,
    audit: &Arc<AuditLog>,
) -> Result<String, ReceiptRefusal> {
    let payload = match konsensus_api::handlers::files::FilePayload::from_wire_bytes(bytes) {
        Ok(p) => p,
        Err(e) => {
            debug!(sender = %sender, error = %e, "KIND_FILE_REF payload not valid JSON");
            return Err(ReceiptRefusal::FileCorrupted("the payload is not a file"));
        }
    };

    let file_data = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &payload.data_b64,
    ) {
        Ok(data) => data,
        Err(e) => {
            warn!(sender = %sender, error = %e, "failed to decode base64 file data");
            return Err(ReceiptRefusal::FileCorrupted("the file data is not base64"));
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
        return Err(ReceiptRefusal::FileCorrupted(
            "the file data does not match its hash",
        ));
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
        return Err(ReceiptRefusal::NotPersisted("the file could not be stored"));
    }
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

    Ok(format!("[file: {}]", payload.filename))
}

/// Build the storage mutation and the frontend summary for a decoded calendar
/// payload. Nothing is written here: the caller commits the mutation together
/// with the hold release.
pub(crate) fn build_calendar_admission(
    inbound: CalendarInbound,
    sender: &konsensus_core::types::NodeId,
    envelope: &konsensus_core::UkmEnvelope,
) -> (konsensus_storage::CalendarAdmission, String) {
    match inbound {
        CalendarInbound::Event(payload) => {
            let attendees_json =
                serde_json::to_string(&payload.attendees).unwrap_or_else(|_| "[]".into());
            let recurrence_json = payload
                .recurrence
                .as_ref()
                .and_then(|r| serde_json::to_string(r).ok());
            let summary = format!("[calendar: {}]", payload.title);
            let record = konsensus_storage::CalendarEventRecord {
                id: payload.event_id,
                message_id: Some(envelope.id.to_hex()),
                organizer: payload.organizer,
                title: payload.title,
                description: payload.description,
                start_ms: payload.start_ms,
                end_ms: payload.end_ms,
                tz: payload.tz,
                location: payload.location,
                attendees_json,
                recurrence_json,
                color: payload.color,
                created_at: String::new(),
                parent_id: None,
            };
            (konsensus_storage::CalendarAdmission::Event(record), summary)
        }
        CalendarInbound::Rsvp(payload) => {
            let response = format!("{:?}", payload.response).to_lowercase();
            let summary = format!("[rsvp: {response}]");
            let record = konsensus_storage::RsvpRecord {
                id: uuid::Uuid::new_v4().to_string(),
                event_id: payload.event_id,
                responder: sender.to_hex(),
                response,
                comment: payload.comment,
                created_at: String::new(),
            };
            (konsensus_storage::CalendarAdmission::Rsvp(record), summary)
        }
    }
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
    gate: &PaymentGate,
    trust_discount: f64,
) -> Option<String> {
    let Some(cs) = content_server else {
        debug!(sender = %sender, "manifest request received but content server disabled");
        return Some("[web manifest request]".to_string());
    };

    let block_height = chain.get_block_height().await.unwrap_or(0);
    let manifest = priced_manifest(cs, block_height, pricing.as_ref(), gate, trust_discount).await?;
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
    front_door: &konsensus_api::handlers::front_door::FrontDoorStore,
    pricing: &Arc<dyn konsensus_core::traits::pricing::PricingEngine>,
    identity: &Arc<NodeIdentity>,
    session_mgr: &SessionManager,
    transport: &Arc<NoiseTransport>,
    audit: &Arc<AuditLog>,
    gate: &PaymentGate,
) -> Option<String> {
    let page_req: konsensus_core::payloads::content::PageRequest =
        match konsensus_core::wire_json::from_slice(bytes) {
            Ok(r) => r,
            Err(e) => {
                debug!(sender = %sender, error = %e, "KIND_PAGE_REQUEST payload not valid JSON");
                return None;
            }
        };

    let response = if page_req.path == konsensus_core::payloads::content::PORCH_CARD_PATH {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        priced_card_response(
            &page_req.request_id, front_door, identity, pricing.as_ref(), gate, now,
        ).await
    } else if let Some(cs) = content_server {
        cs.handle_request(&page_req)
    } else {
        debug!(sender = %sender, "page request received but content server disabled");
        crate::content_server::not_found(page_req.request_id.clone())
    };
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
    if kind == konsensus_core::kind::KIND_WEB_MANIFEST
        && json_bytes.len() > konsensus_core::payloads::content::MAX_PORCH_BODY_BYTES
    {
        warn!(
            peer = %peer_id,
            size = json_bytes.len(),
            limit = konsensus_core::payloads::content::MAX_PORCH_BODY_BYTES,
            "refusing oversized manifest response"
        );
        return;
    }

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

async fn priced_manifest(
    content: &ContentServer,
    block_height: u64,
    pricing: &dyn konsensus_core::traits::pricing::PricingEngine,
    gate: &PaymentGate,
    trust_discount: f64,
) -> Option<konsensus_core::payloads::content::WebManifest> {
    let kind = konsensus_core::kind::KIND_PAGE_RESPONSE;
    let base = pricing.get_price_msat(kind).await.ok()?;
    let discounted = konsensus_pricing::peer_prices::apply_trust_discount(base, trust_discount);
    Some(content.build_manifest(block_height, gate.price_with_floor_msat(discounted)))
}

async fn priced_card_response(
    request_id: &str,
    front_door: &konsensus_api::handlers::front_door::FrontDoorStore,
    identity: &NodeIdentity,
    pricing: &dyn konsensus_core::traits::pricing::PricingEngine,
    gate: &PaymentGate,
    now: u64,
) -> konsensus_core::payloads::content::PageResponse {
    match front_door.priced_card(identity, pricing, gate).await {
        Ok(card) => crate::content_server::card_response(request_id.into(), card.as_ref(), now),
        Err(error) => {
            warn!(%error, "could not derive porch card price");
            konsensus_core::payloads::content::PageResponse {
                request_id: request_id.into(),
                status: konsensus_core::payloads::content::PageStatus::InternalError,
                content_type: String::new(),
                body: "Card temporarily unavailable".into(),
                cache_seconds: 0,
                is_complete: true,
                chunk_index: 0,
                total_chunks: 1,
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/msg_handler.rs"]
mod tests;
