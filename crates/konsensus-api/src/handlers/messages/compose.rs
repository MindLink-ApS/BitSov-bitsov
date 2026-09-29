//! `POST /api/v1/messages/compose` — compose, encrypt, pay, and send a message.
//!
//! The node handles the full pipeline: E2EE encryption via Double Ratchet,
//! Lightning payment proof creation (keysend or invoice-request fallback),
//! envelope construction, Ed25519 signing, storage, and delivery.
//!
//! This is the primary endpoint for the frontend. Plaintext only exists in RAM
//! on the user's own node — it is encrypted before storage or transport
//! (Principle 4: data sovereignty).

use crate::metered::{Debit, MeteredSpend};
use crate::spend_budget::Charge;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use konsensus_core::traits::lightning::{
    LightningError, LightningProvider, PaymentDetails, PaymentDirection, PaymentStatus,
};
use konsensus_core::types::{MessageId, NodeId, Recipient};
use konsensus_crypto::ratchet_message_to_bytes;
use konsensus_message::wire::Frame;

use crate::audit::events;
use crate::error::ApiError;
use crate::handlers::utils::generate_valid_proof;
use crate::invoice_refusal;
use crate::state::{AppState, InvoiceRequestOutcome, InvoiceResponseData};

/// Request to compose and send a message (node handles encryption + payment).
///
/// This is the primary endpoint for the frontend. The plaintext only exists
/// in RAM on the user's own node — it is encrypted before storage or transport.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposeRequest {
    /// Client-generated UUIDv4; omitted ids are generated and returned by the node.
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub wait_ack_ms: Option<u64>,
    #[serde(default)]
    pub max_routing_fee_msat: Option<u64>,
    #[serde(default)]
    pub max_total_msat: Option<u64>,
    #[serde(default)]
    pub max_recipient_msat: Option<std::collections::HashMap<String, u64>>,
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
    pub operation_id: Option<String>,
    pub state: String,
    pub accepted: bool,
    pub payment_hash: Option<String>,
    pub retry_allowed: bool,
    /// Sum of approved routing ceilings for this call.
    pub max_routing_fee_msat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_outcomes: Option<Vec<MemberPaymentOutcome>>,
    /// The message ID assigned to this envelope.
    pub message_id: String,
    /// Whether the message was delivered to a connected peer.
    pub delivered: bool,
    /// Settled principal plus reserved principal for unknown room members.
    pub amount_msat: u64,
    /// Admission paid again during this send because a reconnect left the
    /// recipient's connection unpaid, msat. Not part of `amount_msat`: a paired
    /// caller's confirmed cap covers the message, and the contact's budget in
    /// the grant bounds this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readmission_msat: Option<u64>,
}

/// One room recipient's payment result. Unknown is never retry permission.
#[derive(Serialize)]
pub struct MemberPaymentOutcome {
    pub recipient: String,
    pub status: &'static str,
    /// Settled principal, or the full reserved principal when status is unknown.
    pub amount_msat: u64,
    pub message_id: Option<String>,
    pub reason: Option<String>,
}

async fn quoted_price(state: &AppState, peer: &NodeId, kind: u16, height: u64) -> Result<u64, ApiError> {
    let ready = state.lightning.money_ready().await;
    if !ready && !state.session_manager.has_session(peer).await {
        return Err(ApiError::NotReady);
    }
    let quote = async {
        match state.peer_prices.get_fresh_discounted_peer_price(peer, kind, height, MAX_PRICE_AGE).await {
            Some(price) => Ok(price),
            None => state.pricing.get_price_msat(kind).await.map_err(|e| ApiError::Internal(format!("pricing error: {e}"))),
        }
    };
    // Preserve established zero-price conversations when a local quote is
    // available. Never wait on dynamic chain pricing or assume a free price.
    let price = if ready { quote.await? } else {
        tokio::time::timeout(Duration::from_millis(100), quote).await.map_err(|_| ApiError::NotReady)??
    };
    if super::caps::payable(price) > 0 || !state.session_manager.has_session(peer).await {
        crate::error::require_money_ready(state).await?;
    }
    Ok(super::caps::payable(price))
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

/// Maximum number of members a single room compose may fan out to.
///
/// Room compose performs one payment + encryption + delivery operation **per
/// member** (Principle 2: every recipient is individually gated). Without a
/// cap, one HTTP request to a huge room amplifies into an unbounded number of
/// Lightning operations against this node and its peers — a latency cliff and
/// an amplification vector. We reject rooms larger than this with explicit
/// back-pressure (`ApiError::BadRequest`) rather than silently processing them.
///
/// This is the bounded interim of `ROOM-FANOUT-STREAM`: a hard guard plus
/// bounded parallelism, not the eventual streaming/batched delivery design.
/// At world scale, very large rooms must move to a fan-out worker; until then
/// this cap keeps the synchronous compose path predictable.
const MAX_ROOM_FANOUT_MEMBERS: usize = 256;

/// Maximum number of per-member fan-out operations processed concurrently.
///
/// Each member still gets its own payment proof and envelope (semantics are
/// unchanged) — this only bounds how many are *in flight* at once. It turns
/// the old `O(N)` serial latency (N × per-member Lightning round-trip) into
/// `O(ceil(N / C))` while never holding more than `C` concurrent Lightning
/// operations open, which also bounds pressure on `invoice_requests`
/// (`MAX_PENDING_INVOICE_REQUESTS`).
const MAX_ROOM_FANOUT_CONCURRENCY: usize = 8;

/// Minimum Lightning invoice amount in millisatoshis.
///
/// LND/LNbits require invoices to be at least 1 sat (1000 msat).
/// When a message price is below this, we round up to the minimum.
/// The sender pays slightly more than the pricing engine says, but
/// the payment gate on the recipient side accepts overpayment.
const MIN_INVOICE_AMOUNT_MSAT: u64 = 1_000;

/// How long to poll an in-flight payment for terminal settlement before giving
/// up. Lightning HTLCs normally settle in well under a second on a warm node,
/// but a freshly-restarted node (cold scorer/network graph) can take several
/// seconds, so the window is generous.
const PAYMENT_SETTLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Longest wait between settlement-status polls.
const PAYMENT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// First settlement re-check after dispatch. Waits double from here up to
/// [`PAYMENT_POLL_INTERVAL`]: a routed HTLC settles in a few hundred ms, and a
/// fixed 2 s first wait was most of every paid send on real LDK.
const PAYMENT_POLL_INITIAL: Duration = Duration::from_millis(50);

/// The backend's outgoing-payment update hints, subscribed BEFORE the payment
/// is dispatched (or, on resume, before its status is first probed). A backend
/// may settle and emit the terminal hint before the dispatch call returns; a
/// subscription taken afterwards would never see it. Taken first, the hint is
/// buffered and ends the first wait at once.
struct SettlementUpdates(Option<futures::stream::BoxStream<'static, String>>);

impl SettlementUpdates {
    fn subscribe(lightning: &dyn LightningProvider) -> Self {
        Self(lightning.outgoing_payment_updates())
    }
}

/// Paces the settlement polls of one outgoing payment. Each wait ends at the
/// backoff timer or at the backend's update hint for this payment, whichever
/// comes first; the caller then re-reads `get_payment_status`, which stays the
/// only thing it acts on (a hint is never proof of settlement).
struct SettlementPoll {
    updates: Option<futures::stream::BoxStream<'static, String>>,
    payment_hash: String,
    next: Duration,
    started: tokio::time::Instant,
}

impl SettlementPoll {
    fn new(updates: SettlementUpdates, payment_hash: &str) -> Self {
        Self {
            updates: updates.0,
            payment_hash: payment_hash.to_owned(),
            next: PAYMENT_POLL_INITIAL,
            started: tokio::time::Instant::now(),
        }
    }

    async fn wait(&mut self) {
        use futures::StreamExt;
        let delay = self.next;
        self.next = (self.next * 2).min(PAYMENT_POLL_INTERVAL);
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        let Some(updates) = self.updates.as_mut() else {
            return sleep.await;
        };
        loop {
            tokio::select! {
                () = &mut sleep => return,
                hint = updates.next() => match hint {
                    Some(hash) if hash.is_empty() || hash == self.payment_hash => return,
                    Some(_) => {}
                    None => break,
                },
            }
        }
        self.updates = None;
        sleep.await;
    }

    fn timed_out(&self) -> bool {
        self.started.elapsed() >= PAYMENT_SETTLE_TIMEOUT
    }
}

/// Outcome of a keysend attempt, distinguishing the two cases the caller must
/// treat very differently:
/// * [`KeysendOutcome::Settled`] — the HTLC settled; proof is ready.
/// * [`KeysendOutcome::NotDispatched`] — the `keysend` call failed *before* any
///   HTLC went out, so it is safe to fall back to the invoice flow.
///
/// A keysend that *was* dispatched but did not settle is NOT represented here —
/// it returns `Err`, because falling back to the invoice flow in that case would
/// risk paying the recipient twice for one message.
enum KeysendOutcome {
    Settled(([u8; 32], [u8; 32], u64)),
    NotDispatched,
}

/// Poll an in-flight Lightning payment to a terminal status.
///
/// Lightning payments dispatch asynchronously: `keysend`/`pay_invoice` return as
/// soon as the HTLC is in flight — often with `InFlight`/`Pending` status before
/// the preimage is known. Treating that as failure (the historic behavior) both
/// dropped successfully-settling messages (the caller `502`'d while the sats
/// actually moved) and, for keysend, invited a double payment when the caller
/// then fell back to the invoice flow. This polls `get_payment_status` until the
/// payment settles, fails, or the timeout elapses.
///
/// Returns the settled [`PaymentDetails`]. Errors if the payment failed, timed
/// out, or carries no payment hash to track — in the last two cases the caller
/// MUST NOT re-dispatch the payment by another path, to avoid paying twice.
///
/// `updates` must have been subscribed before the payment was dispatched.
async fn await_settlement(
    lightning: &Arc<dyn LightningProvider>,
    updates: SettlementUpdates,
    initial: PaymentDetails,
    method: &str,
) -> Result<PaymentDetails, ApiError> {
    match initial.status {
        PaymentStatus::Settled => return Ok(initial),
        PaymentStatus::Failed | PaymentStatus::Expired => {
            return Err(ApiError::Lightning(format!(
                "{method} payment failed before settlement: {:?}",
                initial.status
            )));
        }
        PaymentStatus::Pending | PaymentStatus::InFlight => {}
    }

    if initial.payment_hash.is_empty() {
        // Dispatched but not yet trackable (rare race where the backend had not
        // recorded the payment when it returned). Do NOT re-dispatch via another
        // path — that would risk paying twice. Preserve the unknown outcome.
        return Err(ApiError::PaymentUnresolved(format!(
            "{method} dispatched but returned no payment hash to confirm settlement — \
             not retrying to avoid a double payment; reconcile the original payment before any new send"
        )));
    }

    let mut poll = SettlementPoll::new(updates, &initial.payment_hash);
    loop {
        poll.wait().await;

        let details = lightning
            .get_payment_status(&initial.payment_hash)
            .await
            .map_err(|e| {
                ApiError::PaymentUnresolved(format!("{method}: failed to poll payment status: {e}"))
            })?;

        match details.status {
            PaymentStatus::Settled => return Ok(details),
            PaymentStatus::Failed | PaymentStatus::Expired => {
                return Err(ApiError::Lightning(format!(
                    "{method} payment failed: {:?}",
                    details.status
                )));
            }
            PaymentStatus::Pending | PaymentStatus::InFlight => {
                if poll.timed_out() {
                    return Err(ApiError::PaymentUnresolved(format!(
                        "{method} payment still in flight after {}s — not retrying to avoid a double payment",
                        PAYMENT_SETTLE_TIMEOUT.as_secs()
                    )));
                }
            }
        }
    }
}

/// Keep operation checkpoints while using the subscription taken before dispatch.
async fn await_message_settlement(state: &AppState, debit: &Debit, updates: SettlementUpdates, mut details: PaymentDetails, method: &str) -> Result<PaymentDetails, ApiError> {
    let Some(operation) = debit.operation() else { return await_settlement(&state.lightning, updates, details, method).await; };
    let mut poll = SettlementPoll::new(updates, &details.payment_hash);
    loop {
        operation.record(&details).await.map_err(|e| ApiError::PaymentUnresolved(format!("payment polled but journal failed: {e}")))?;
        match details.status {
            PaymentStatus::Settled => return Ok(details),
            PaymentStatus::Failed | PaymentStatus::Expired => return Err(ApiError::Lightning(format!("{method} payment failed"))),
            _ => {}
        }
        if details.payment_hash.is_empty() || poll.timed_out() {
            return Err(ApiError::PaymentUnresolved(format!("{method} outcome unknown; reconcile operation")));
        }
        poll.wait().await;
        details = state.lightning.get_payment_status(&details.payment_hash).await
            .map_err(|e| ApiError::PaymentUnresolved(format!("{method} status: {e}")))?;
    }
}

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
/// **Invoice path** (fallback, ~100-200ms round-trip): If the peer has no
/// Lightning pubkey, or keysend is positively rejected before dispatch, use the
/// RequestInvoice/InvoiceResponse/pay_invoice flow.
///
/// Returns (payment_hash, preimage, amount_msat). Never falls back to fake proofs.
pub async fn create_payment_proof(
    state: &AppState,
    price_msat: u64,
    peer_id: &NodeId,
) -> Result<([u8; 32], [u8; 32], u64), ApiError> {
    create_payment_proof_with_fee_report(state, price_msat, peer_id).await.map(|(proof, _, _)| proof)
}

/// Return message proof, combined routing-fee ceiling, and all principal settled
/// by this call (including re-admission). Admission never inflates the proof.
pub(crate) async fn create_payment_proof_with_fee_report(
    state: &AppState, price_msat: u64, peer_id: &NodeId,
) -> Result<(([u8; 32], [u8; 32], u64), u64, u64), ApiError> {
    let mut charge = FirstContactCharge::default();
    let readmission = Readmission::for_cap(None);
    let result = create_metered_payment_proof(state, price_msat, peer_id, &Debit::unmetered(), &readmission, None, &mut charge).await;
    let message_msat = charge.message_authorized.unwrap_or(super::caps::payable(price_msat));
    let fee = state.lightning.routing_fee_policy().ceiling(message_msat, None);
    let ceiling = fee.saturating_add(readmission.fee_ceiling_msat());
    result.map(|proof| {
        let settled_msat = proof.2.saturating_add(charge.settled_msat);
        (proof, ceiling, settled_msat)
    }).map_err(|error| charge.error(error).with_routing_fee(ceiling))
}

/// How a paid send may pay admission again when the recipient refuses it with
/// `admission_required` (a reconnect starts every connection unpaid), and what
/// it paid for that.
#[derive(Debug, Default)]
pub(crate) struct Readmission {
    /// Confirmed all-in ceiling for admission + message + both fee ceilings.
    ///
    /// - `None`: uncapped (protocol `ADMISSION_MAX_MSAT` still bounds the quote).
    /// - `Some(n)` with `n > 0`: quoted capped re-admission for **single-recipient
    ///   chat only** — the payee's signed quote must fit this ceiling.
    /// - `Some(0)`: capped call that must refuse before any quote (rooms, files,
    ///   and other non-chat kinds keep pre-#111 fail-closed behaviour until a
    ///   member-/kind-scoped budget exists).
    caller_cap: Option<u64>,
    /// Single-recipient compose already holds the per-peer admission lock.
    lock_held: bool,
    /// Admission paid again during this send, msat.
    paid_msat: std::sync::atomic::AtomicU64,
    fee_ceiling_msat: std::sync::atomic::AtomicU64,
}

impl Readmission {
    pub(crate) fn fee_ceiling_msat(&self) -> u64 {
        self.fee_ceiling_msat.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub(crate) fn for_cap(caller_cap: Option<u64>) -> Self {
        Self { caller_cap, ..Self::default() }
    }

    /// Admission paid again during this send, if any, msat.
    pub(crate) fn paid_msat(&self) -> Option<u64> {
        Some(self.paid_msat.load(std::sync::atomic::Ordering::Relaxed)).filter(|m| *m > 0)
    }
}

/// Paired paid paths carry the original reservation through every fallback.
pub(crate) async fn create_metered_payment_proof(
    state: &AppState,
    price_msat: u64,
    peer_id: &NodeId,
    debit: &Debit,
    readmission: &Readmission,
    kind: Option<u16>,
    charge: &mut FirstContactCharge,
) -> Result<([u8; 32], [u8; 32], u64), ApiError> {
    // Zero-price messages get a valid cryptographic proof with zero amount.
    // The payment gate accepts these for kind-0 (control) messages.
    if price_msat == 0 {
        return Ok(generate_valid_proof(0));
    }

    // Recheck after quoting: readiness may have changed before dispatch.
    crate::error::require_money_ready(state).await?;

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
        match try_keysend(state, &ln_pubkey, payment_amount_msat, peer_id, debit).await {
            Ok(KeysendOutcome::Settled(proof)) => return Ok(proof),
            Ok(KeysendOutcome::NotDispatched) => {
                tracing::warn!(
                    peer = %peer_id,
                    "keysend unavailable (not dispatched) — falling back to invoice-request flow"
                );
                // Safe to fall through: no HTLC was dispatched.
            }
            Err(e) => {
                // No proof of non-dispatch: the payment may already have
                // settled. Surface the unresolved/terminal error without a
                // second payment path.
                tracing::warn!(
                    peer = %peer_id,
                    error = %e,
                    "keysend outcome does not permit fallback (double-pay guard)"
                );
                return Err(e);
            }
        }
    }

    // Invoice-request fallback (only reached when keysend was not dispatched).
    match create_payment_proof_via_invoice(state, payment_amount_msat, peer_id, debit, None).await {
        Err(e) if is_admission_refusal(&e) => {
            readmit_then_pay(state, payment_amount_msat, peer_id, debit, readmission, kind, charge).await
        }
        other => other,
    }
}

/// A target issues at most one admission quote per source address per this
/// window (and none in its first second after startup). A re-admission that
/// lands inside it is refused out loud and waits it out once.
const ADMISSION_QUOTE_WINDOW: Duration = Duration::from_secs(10);

/// How long to keep asking for the message invoice after paying admission again.
/// The recipient promotes the connection when its gate accepts the admission
/// envelope, which can land just after our next invoice request.
const READMIT_PROMOTION_TIMEOUT: Duration = Duration::from_secs(20);

/// Interval between invoice requests while that promotion lands.
const READMIT_PROMOTION_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Stable `reason` on the 409 `price_cap_exceeded` that refuses a capped
/// reconnect re-admission (clients match this, not the English message).
pub(crate) const READMISSION_REQUIRED: &str = "readmission_required";

/// Start of the message of the error for an `admission_required` refusal.
const ADMISSION_REFUSAL_MESSAGE: &str = "the recipient requires admission on this connection";

fn admission_refusal(peer_id: &NodeId) -> ApiError {
    ApiError::PaymentRequired(format!(
        "{ADMISSION_REFUSAL_MESSAGE}: {peer_id} does not hold it as paid (a reconnect starts \
         every connection unpaid) — nothing was paid for this message"
    ))
}

fn is_admission_refusal(e: &ApiError) -> bool {
    matches!(e, ApiError::PaymentRequired(m) if m.starts_with(ADMISSION_REFUSAL_MESSAGE))
}

/// The error for an invoice request whose pending entry was dropped: the peer
/// answered with `InvoiceError`, stating `refusal` when the request was bound.
fn invoice_refused(peer_id: &NodeId, refusal: Option<String>) -> ApiError {
    match refusal.as_deref() {
        Some(invoice_refusal::ADMISSION_REQUIRED) => admission_refusal(peer_id),
        Some(reason) => ApiError::Lightning(format!(
            "Recipient refused the invoice request: {reason}"
        )),
        None => ApiError::Lightning(
            "Recipient could not create invoice — their Lightning wallet may be unavailable".into(),
        ),
    }
}

/// The recipient refused our message invoice with `admission_required`.
///
/// Admission is not a durable object: the recipient holds a connection as paid
/// only after a settled admission on that connection, and a reconnect starts
/// unpaid. So we re-prove it on the normal paid path (the first-contact
/// admission invoice and its signed proof), then ask for the message invoice
/// again. The E2EE session is untouched; both sides still hold it.
///
/// Quoted capped re-admission is only for **single-recipient chat**: the payee
/// must return a fresh signed quote whose admission principal, message
/// principal, and both routing fee ceilings fit the caller cap (and any grant).
/// That all-in amount is reserved before dispatch and reconciled after, exactly
/// like first-contact admission. Rooms, files, and other kinds keep refusing a
/// capped reconnect (`caller_cap = Some(0)`) before any quote. A chat call with
/// `Some(0)` or a cap below the message all-in also refuses before asking,
/// preserving the payee's quote window. No quote, or a quote that does not fit,
/// is refused before payment. An uncapped request may use existing admission
/// authority under the same G1 contact/call/grant limits. Mark and proof send
/// stay generation-bound (#100).
async fn readmit_then_pay(
    state: &AppState,
    amount_msat: u64,
    peer_id: &NodeId,
    debit: &Debit,
    readmission: &Readmission,
    kind: Option<u16>,
    charge: &mut FirstContactCharge,
) -> Result<([u8; 32], [u8; 32], u64), ApiError> {
    let peer_key = peer_id.to_hex();
    // Capped non-chat (rooms/files/kind != chat) uses Some(0). Refuse before any
    // quote so we do not spend the payee's per-source admission window.
    let message_all_in = amount_msat
        .checked_add(debit.fee_limit(state, amount_msat))
        .ok_or_else(|| ApiError::PriceCapExceeded("message all-in overflow".into()))?;
    // One call-wide ceiling: admissions already settled in this compose consume
    // the confirmed cap and must not be re-authorized for a mid-call reconnect
    // (Codex #111 finding 4).
    let already_spent_all_in = charge
        .settled_msat
        .saturating_add(charge.fee_ceiling_msat);
    let remaining_cap = readmission
        .caller_cap
        .map(|cap| cap.saturating_sub(already_spent_all_in));
    let refuse_capped = match remaining_cap {
        Some(0) => true,
        Some(_) if kind != Some(konsensus_core::kind::KIND_CHAT) => true,
        Some(cap) if cap < message_all_in => true,
        _ => false,
    };
    if refuse_capped {
        return Err(ApiError::PriceCapExceeded(format!(
            "{peer_id} requires admission again on a new connection, and the confirmed cap \
             cannot cover a quoted re-admission for this send; no invoice was paid. \
             Ask for the admission quote and send again under an all-in cap that fits \
             admission plus the message (single-recipient chat only)."
        )).with_reason(READMISSION_REQUIRED));
    }
    debit.readmission_allowed(&peer_key)?;
    tracing::info!(
        peer = %peer_id,
        "recipient requires admission — checking payment on the current connection"
    );
    let _guard = if readmission.lock_held {
        None
    } else {
        Some(acquire_peer_admission_lock(peer_id).await.ok_or_else(|| ApiError::Internal("admission capacity reached".into()))?)
    };
    recover_admission_attempt(state, peer_id).await?;
    let connected_since = state.transport.connected_since(peer_id).await;
    let paid_on_live = state.transport.admission_paid_on_connection(peer_id).await;
    let coverage = lock_admission_ledger().settled_coverage(peer_id, connected_since, paid_on_live, Instant::now());
    let covered = coverage == SettledCoverage::Covered;
    if !covered {
        if coverage == SettledCoverage::Consumed {
            reconcile_admission_budget(state, peer_id, debit.reservation().as_ref()).await?;
            super::admission_journal::clear(state, peer_id)?;
            lock_admission_ledger().quotes.remove(peer_id);
        }
        let mut attempt = FirstContactCharge { operation: charge.operation.clone(), ..Default::default() };
        let mut readmit = Readmit {
            parent: debit, reserved: None, fee_ceiling: &readmission.fee_ceiling_msat,
            reprice_message: kind == Some(konsensus_core::kind::KIND_CHAT),
        };
        charge.readmission_blocks_message = true;
        // Remaining call-wide cap (not the original total) — finding 4.
        let result = first_contact_admission(
            state, peer_id, konsensus_core::kind::KIND_CHAT, remaining_cap, &mut attempt,
            debit, Some(&mut readmit),
        ).await;
        if result.is_err() && matches!(lock_admission_ledger().prior_admission(peer_id, Instant::now()), PriorAdmission::None) {
            attempt.reserved_msat = 0;
        }
        // Re-admission owns a separate debit from the message. Resolve it once;
        // keep a possibly dispatched payment reserved until reconciliation.
        if let Some(reserved) = &readmit.reserved {
            if result.is_ok() || attempt.reserved_msat <= attempt.settled_msat {
                reserved.settled(&peer_key, attempt.settled_msat);
            }
        }
        if attempt.settled_msat > 0 {
            readmission.paid_msat.fetch_add(attempt.settled_msat, std::sync::atomic::Ordering::Relaxed);
        }
        charge.readmission_msat = charge.readmission_msat.saturating_add(attempt.settled_msat);
        charge.include_attempt(attempt);
        result?;
        charge.readmission_blocks_message = false;
    }
    if covered {
        if let Some((quoted_kind, price)) = lock_admission_ledger().quotes.get(peer_id) {
            if Some(*quoted_kind) == kind { charge.message_price = Some(*price); }
        }
    }
    // The stateless admission quote prices chat only. Never substitute it for
    // another service kind's price.
    let quoted_msat = if kind == Some(konsensus_core::kind::KIND_CHAT) {
        charge.message_price.unwrap_or(amount_msat)
    } else { amount_msat };
    let reserved_msat = amount_msat;
    let amount_msat = quoted_msat;
    if amount_msat == 0 { return Ok(generate_valid_proof(0)); }
    let amount_msat = amount_msat.max(MIN_INVOICE_AMOUNT_MSAT);
    // Whatever branch the re-admission took (a fresh quote, a recovered or
    // in-flight admission, or a connection already covered), the message price
    // it produced is checked again here, before the message is paid (#127
    // review finding 1). Nothing new is paid on a refusal.
    let message_all_in = amount_msat
        .checked_add(debit.fee_limit(state, amount_msat))
        .ok_or_else(|| ApiError::PriceCapExceeded("message all-in overflow".into()))?;
    // A paired caller pays an increase only if this call reserved it (the
    // fresh quote's top-up); otherwise the grant never checked it.
    if debit.is_metered() && amount_msat > reserved_msat
        && charge.message_reserved_all_in.is_none_or(|reserved| reserved < message_all_in)
    {
        return Err(ApiError::BudgetExceeded(crate::spend_budget::BudgetRefusal::Unpriced(
            "recipient's new message quote exceeds the reserved message amount; refresh the price before retrying".into(),
        )));
    }
    // Any caller cap bounds the message after every admission this call paid.
    if let Some(cap) = readmission.caller_cap {
        let left = cap.saturating_sub(charge.settled_msat.saturating_add(charge.fee_ceiling_msat));
        if message_all_in > left {
            return Err(ApiError::PriceCapExceeded(format!(
                "{peer_id} prices this message at {amount_msat} msat, {message_all_in} msat all-in with \
                 its routing fee, more than the {left} msat left under the confirmed cap after \
                 admission; nothing more was paid. Ask for the admission quote and send again under \
                 a cap that fits."
            )).with_reason(READMISSION_REQUIRED));
        }
    }
    charge.message_authorized = Some(amount_msat);

    let deadline = tokio::time::Instant::now() + READMIT_PROMOTION_TIMEOUT;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(admission_refusal(peer_id));
        }
        match create_payment_proof_via_invoice(state, amount_msat, peer_id, debit, Some(deadline)).await {
            // One wall-clock budget includes every prepayment request/response
            // and retry sleep. A payment already dispatched is never cancelled.
            Err(e) if is_admission_refusal(&e) => {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Err(e);
                }
                tokio::time::sleep_until((now + READMIT_PROMOTION_POLL_INTERVAL).min(deadline)).await;
            }
            other => return other,
        }
    }
}

/// Attempt a keysend (spontaneous) payment to a peer's Lightning node.
///
/// * `Ok(KeysendOutcome::Settled(proof))` — the HTLC settled.
/// * `Ok(KeysendOutcome::NotDispatched)` — the `keysend` call failed before any
///   HTLC went out; the caller may safely fall back to the invoice flow.
/// * `Err(_)` — dispatch or settlement is uncertain, or a dispatched payment
///   failed/expired. The caller must NOT fall back to another payment path.
async fn try_keysend(
    state: &AppState,
    ln_pubkey: &str,
    amount_msat: u64,
    peer_id: &NodeId,
    debit: &Debit,
) -> Result<KeysendOutcome, ApiError> {
    let updates = SettlementUpdates::subscribe(state.lightning.as_ref());
    let details = match debit.dispatch_message(state, None, amount_msat, state
        .lightning
        .keysend_with_fee_limit(ln_pubkey, amount_msat, Some("konsensus message"), debit.fee_limit(state, amount_msat)))
        .await?
    {
        Ok(details) => details,
        Err(LightningError::NotReady) => return Err(ApiError::NotReady),
        Err(LightningError::PaymentNotDispatched(reason)) => {
            tracing::warn!(peer = %peer_id, %reason, "keysend rejected before dispatch");
            return Ok(KeysendOutcome::NotDispatched);
        }
        Err(e) => {
            // A response read/parse failure or timeout may follow settlement.
            // Keep this amount reserved; NEVER create a second payment without
            // positive evidence that the first was not dispatched.
            return Err(ApiError::PaymentUnresolved(format!(
                "keysend outcome unknown; not retrying via invoice: {e}"
            )));
        }
    };

    // A payment record exists: never re-dispatch by another path. Poll any
    // in-flight payment to terminal settlement.
    let settled = await_message_settlement(state, debit, updates, details, "keysend").await?;
    debit.record_payment(&peer_id.to_hex(), &settled);

    let preimage_hex = settled.preimage.ok_or_else(|| {
        ApiError::PaymentProofUnavailable { amount_msat, reason: "keysend settled but no preimage returned".into() }
    })?;

    let preimage_bytes: [u8; 32] = hex::decode(&preimage_hex)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| {
            ApiError::PaymentProofUnavailable { amount_msat, reason: "malformed proof from settled keysend".into() }
        })?;

    let hash_bytes: [u8; 32] = Sha256::digest(preimage_bytes).into();

    tracing::info!(
        peer = %peer_id,
        amount_msat,
        method = "keysend",
        "payment proof created via keysend — settled"
    );

    Ok(KeysendOutcome::Settled((hash_bytes, preimage_bytes, amount_msat)))
}

/// Create a payment proof via the invoice-request/response round-trip.
///
/// This is the original flow: send RequestInvoice to peer, wait for their
/// InvoiceResponse, pay their invoice, extract preimage.
async fn create_payment_proof_via_invoice(
    state: &AppState,
    invoice_amount_msat: u64,
    peer_id: &NodeId,
    debit: &Debit,
    promotion_deadline: Option<tokio::time::Instant>,
) -> Result<([u8; 32], [u8; 32], u64), ApiError> {
    // Generate a unique request ID for correlating request/response.
    let request_id = uuid::Uuid::new_v4().to_string();

    // Create a oneshot channel for the response.
    let (tx, rx) = oneshot::channel::<InvoiceRequestOutcome>();

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
    // Bound to this peer until the answer arrives, so a refusal from it is heard
    // even when it has not paid us (see `invoice_refusal`).
    let binding = invoice_refusal::bind(&request_id, *peer_id);

    // Send RequestInvoice to the peer.
    let frame = Frame::RequestInvoice {
        request_id: request_id.clone(),
        amount_msat: invoice_amount_msat,
        purpose: "konsensus message".into(),
    };
    let frame_bytes = frame
        .to_bytes()
        .map_err(|e| ApiError::Internal(format!("frame serialization error: {e}")))?;

    // Only the prepayment exchange is cancellable by the promotion deadline.
    // Once an invoice is accepted below, dispatch and settlement keep their
    // existing financial outcome handling even if this deadline then elapses.
    let response = async {
        debit.request_invoice(state.transport.send_raw_frame(peer_id, &frame_bytes))
            .await?
            .map_err(|e| ApiError::Internal(format!(
                "failed to send invoice request to peer: {e}"
            )))?;

        tracing::info!(
            peer = %peer_id, %request_id, invoice_amount_msat, method = "invoice",
            "sent invoice request to recipient — awaiting response"
        );

        tokio::time::timeout(INVOICE_REQUEST_TIMEOUT, rx)
            .await
            .map_err(|_| ApiError::Internal(
                "Invoice request timed out — recipient did not respond within 30s".into()
            ))?
            .map_err(|_| ApiError::Lightning(
                "Recipient could not create invoice — their Lightning wallet may be unavailable".into()
            ))?
            .map_err(|error| {
                if error.recipient != *peer_id {
                    return ApiError::Lightning("invoice refusal came from another recipient".into());
                }
                invoice_refused(peer_id, Some(error.reason))
            })
    };
    let response = if let Some(deadline) = promotion_deadline {
        tokio::time::timeout_at(deadline, response)
            .await
            .unwrap_or_else(|_| Err(admission_refusal(peer_id)))
    } else {
        response.await
    };
    let _ = binding.finish();
    // Includes deadline cancellation while sending, before the response wait.
    state.invoice_requests.lock().await.remove(&request_id);
    let response = response?;

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

    // Message invoices only refuse an already-expired BOLT11 (`is_expired()`
    // uses the payer clock). They do not reject a future `timestamp`, so a
    // recipient a fraction of a second ahead of NTP cannot stall a paid
    // message the way the admission path used to. Expired invoices stay
    // refused; do not add a skew that would keep them payable.
    if response.recipient != *peer_id || response.payment_hash != invoice.payment_hash().to_string() || invoice.is_expired() {
        return Err(ApiError::Lightning("recipient invoice provenance/hash/expiry mismatch".into()));
    }

    if let Some(expected) = state.peer_ln_pubkeys.lock().await.get(peer_id) {
        if invoice.recover_payee_pub_key().to_string() != *expected {
            return Err(ApiError::Lightning(
                "invoice payee does not match recipient".into(),
            ));
        }
    }

    if promotion_deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
        return Err(admission_refusal(peer_id));
    }

    // Pay the recipient's invoice, then poll the in-flight payment to terminal
    // settlement (it commonly returns Pending/InFlight before the preimage is
    // known; treating that as failure dropped settling messages).
    let updates = SettlementUpdates::subscribe(state.lightning.as_ref());
    let details = debit.dispatch_message(state, Some(invoice.payment_hash().to_string()), invoice_amount_msat, state
        .lightning
        .pay_invoice_with_fee_limit(&response.bolt11, debit.fee_limit(state, invoice_amount_msat)))
        .await?
        .map_err(|e| match e {
            LightningError::NotReady => ApiError::NotReady,
            LightningError::PaymentNotDispatched(reason) => ApiError::NotDispatched(reason),
            other => ApiError::PaymentUnresolved(format!("failed to pay recipient invoice: {other}")),
        })?;

    let details = await_message_settlement(state, debit, updates, details, "invoice payment").await?;
    debit.record_payment(&peer_id.to_hex(), &details);

    // Extract and validate the preimage.
    let preimage_hex = details.preimage.ok_or_else(|| {
        ApiError::PaymentProofUnavailable { amount_msat: invoice_amount_msat, reason: "payment succeeded but no preimage returned".into() }
    })?;

    let preimage_bytes: [u8; 32] = hex::decode(&preimage_hex)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| {
            ApiError::PaymentProofUnavailable { amount_msat: invoice_amount_msat, reason: "malformed proof from settled invoice payment".into() }
        })?;

    let hash_bytes: [u8; 32] = Sha256::digest(preimage_bytes).into();
    if hex::encode(hash_bytes) != invoice.payment_hash().to_string()
        || details.payment_hash != invoice.payment_hash().to_string()
        || details.amount_msat != invoice_msat || details.direction != PaymentDirection::Outgoing {
        return Err(ApiError::PaymentProofUnavailable { amount_msat: invoice_msat, reason: "settled invoice payment identity/proof mismatch".into() });
    }

    tracing::info!(
        peer = %peer_id,
        %request_id,
        invoice_amount_msat,
        method = "invoice",
        "payment proof created via invoice — real sats flowed from sender to recipient"
    );

    Ok((hash_bytes, preimage_bytes, invoice_amount_msat))
}

/// How long to wait for the target to promote us to privileged and complete the
/// X3DH handshake after a settled first-contact admission payment. The promotion
/// (`msg_handler.rs:257`) and the prekey/self-heal path that follows are async on
/// the target, so we poll our own session store rather than block a single RPC.
const ADMISSION_SESSION_TIMEOUT: Duration = Duration::from_secs(25);

/// Interval between session-establishment polls after a first-contact admission.
/// `can_send` is an in-memory check; the session now forms within round
/// trips of the proof (PSI-SPEED), so a coarse poll would dominate first contact.
const ADMISSION_SESSION_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Fixed non-empty sentinel payload for a first-contact admission envelope.
///
/// MUST be non-empty: `UkmEnvelope::validate()` (the receiver's first gate step)
/// rejects an empty ciphertext before the settlement check, which would drop the
/// admission envelope before promote-on-paid fires. The bytes are not E2EE and
/// carry no message content — admission authenticates the signed outer envelope
/// (recipient + settled proof + signature), which the gate never decrypts.
const ADMISSION_ENVELOPE_MARKER: &[u8] = b"konsensus:admission:v1";

/// Re-derive the admission price (in msat) for a first-contact payment.
///
/// The amount is taken from **our own view of pricing** — the peer's announced
/// `KIND_CHAT` price if we have a fresh cached table, otherwise our own
/// `PricingEngine` — and floored at [`MIN_INVOICE_AMOUNT_MSAT`]. It is **never**
/// taken from caller input: a stranger must not be able to name their own
/// admission price (Principle 2, no free lane). Kept as a pure function so the
/// derivation + floor invariant is unit-testable without a full `AppState`.
fn derive_admission_msat(peer_announced_price_msat: Option<u64>, own_price_msat: u64) -> u64 {
    peer_announced_price_msat
        .unwrap_or(own_price_msat)
        .max(MIN_INVOICE_AMOUNT_MSAT)
}

/// Reserved invoice-request purpose an UNPRIVILEGED (`price_open` stranger) peer
/// is allowed to make: the single admission invoice. MUST match the target's
/// `session_handler::ADMISSION_INVOICE_PURPOSE` byte-for-byte, or the target
/// drops the request.
const ADMISSION_INVOICE_PURPOSE: &str = "konsensus:admission";

/// Upper bound (msat) we will pay for an admission invoice. The target sets the
/// price (recipient-priced), but we refuse an absurd/malicious invoice above this
/// cap so a hostile target cannot drain a stranger who is merely trying to be
/// admitted. Generous relative to any legitimate `KIND_CHAT` admission floor.
const ADMISSION_MAX_MSAT: u64 = 100_000;

/// Whether a target-set admission price is acceptable to pay: strictly positive
/// (no free admission) and within [`ADMISSION_MAX_MSAT`] (bounds a malicious
/// invoice). Pure function so the boundary is unit-testable.
fn admission_price_acceptable(msat: u64) -> bool {
    (1..=ADMISSION_MAX_MSAT).contains(&msat)
}

/// How long a settled admission payment to a peer suppresses a SECOND admission
/// payment to that same peer (idempotence window).
///
/// Scenario this guards: admission settles + envelope is delivered, but the E2EE
/// session does not establish within [`ADMISSION_SESSION_TIMEOUT`], so `compose`
/// returns "retry the message shortly". Without this guard the retry re-enters
/// the no-session branch and PAYS ADMISSION AGAIN — the target happily issues a
/// fresh invoice each time. Within this window a retry re-sends the already-paid
/// admission envelope instead of paying.
///
/// Expiry is deliberate: if the target restarts and loses our promotion, our old
/// payment hash is spent (its `payment_receipts` replay table consumed it) and a
/// genuinely NEW admission payment is the only way back in — so the suppression
/// must not be permanent.
const ADMISSION_SETTLED_TTL: Duration = Duration::from_secs(15 * 60);

/// Bound on peers tracked in the [`AdmissionLedger`] — memory-bounds a caller
/// that composes to many strangers. Expired settled entries and then oldest
/// settled entries are evicted past the cap. In-flight entries are not evicted:
/// forgetting one can let a retry pay again while the original HTLC later
/// settles.
const ADMISSION_LEDGER_MAX_ENTRIES: usize = 1024;

/// A pre-dispatch capacity [`AdmissionRecord::Reserved`] self-heals after this if
/// the admission attempt leaks it (panic before it is released or committed).
/// Short: a reservation resolves to a real dispatch guard or is released within
/// one invoice round-trip; the TTL only backstops a leak.
const ADMISSION_RESERVED_TTL: Duration = Duration::from_secs(90);

/// What the [`AdmissionLedger`] knows about a prior admission to a peer.
#[derive(Debug, Clone, PartialEq)]
enum PriorAdmission {
    /// No live guard — paying is required (the normal first path). Also returned
    /// for a bare `Reserved` slot: a retry re-drives the paid path and `try_reserve`
    /// treats the peer's own reservation as already-held.
    None,
    /// A payment MAY have been dispatched (the pre-`pay_invoice` guard) but is not
    /// confirmed tracked. A retry must PROBE this hash: promote to [`Self::InFlight`]
    /// if the backend knows it. Only a matching terminal failure clears it.
    /// Time passing or PaymentNotFound never authorizes another payment.
    DispatchUnknown {
        payment_hash: String,
        amount_msat: u64,
    },
    /// A trackable payment is CONFIRMED in flight (no TTL). Retry resumes polling
    /// this hash; do NOT request/pay a fresh invoice.
    InFlight {
        payment_hash: String,
        amount_msat: u64,
    },
    /// We settled an admission within the TTL and hold the signed envelope:
    /// re-send it, do NOT pay again.
    SettledWithProof(Box<konsensus_core::UkmEnvelope>),
    /// We settled an admission within the TTL but could not construct the proof
    /// envelope (e.g. the Lightning backend returned a malformed preimage).
    /// Still do NOT pay again — money moved once; never twice for one admission.
    SettledNoProof,
}

/// A re-admission after the recipient refused us with `admission_required`.
struct Readmit<'a> {
    /// The message's debit: a paired caller's re-admission is reserved
    /// against the same grant.
    parent: &'a Debit,
    /// The re-admission's own reservation, once the signed quote is known.
    reserved: Option<Debit>,
    fee_ceiling: &'a std::sync::atomic::AtomicU64,
    /// The message is chat, so the quote's signed chat price replaces the
    /// reserved one: its increase is reserved together with the admission.
    reprice_message: bool,
}

/// Record of one admission attempt to one peer.
#[derive(Debug, Clone)]
enum AdmissionRecord {
    /// Atomic capacity hold, taken under the ledger lock BEFORE the invoice
    /// round-trip so parallel distinct-peer admissions cannot overrun the cap
    /// (review finding #2, 2026-07-07). Released on pre-dispatch failure; replaced
    /// by `DispatchUnknown` once we pay. The short TTL backstops a panic leak.
    Reserved { started_at: Instant },
    /// Payment MAY be dispatched; carries the BOLT11 hash so a retry can probe it.
    /// No TTL: only positive failure evidence permits another attempt.
    DispatchUnknown {
        payment_hash: String,
        amount_msat: u64,
    },
    /// Payment CONFIRMED in flight; NO TTL (only cleared on terminal status or on
    /// settlement) — forgetting a pending HTLC would re-open double-pay.
    InFlight {
        payment_hash: String,
        amount_msat: u64,
    },
    /// A payment settled. Retrying either re-sends the proof envelope or refuses
    /// to pay again if proof construction failed.
    Settled {
        settled_at: Instant,
        /// Recovered wall-clock evidence has no identity for this connection.
        /// Its timestamp bounds cache retention, never current admission.
        recovered: bool,
        /// The signed admission envelope, attached once built. Kept so a retry can
        /// re-deliver the PROOF without re-paying (heals settled-but-envelope-lost).
        envelope: Option<Box<konsensus_core::UkmEnvelope>>,
        /// Whether the envelope may have reached a connection. Set before the
        /// write and cleared only when the transport proves nothing was written
        /// (`NotConnected` from `send_on_connection`). An undelivered proof is
        /// unspent: a retry delivers it on the live connection instead of paying.
        delivered: bool,
    },
}

/// How a settled admission relates to the live connection (see
/// [`AdmissionLedger::settled_coverage`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettledCoverage {
    /// No settled admission is recorded.
    NoRecord,
    /// It covers the live connection: never pay again.
    Covered,
    /// The proof never went out: deliver it on the live connection, never pay again.
    Unsent,
    /// The proof went out on an earlier connection (a flap, or before a
    /// restart) and was consumed there: this connection needs its own admission.
    Consumed,
}

/// Sender-side ledger of first-contact admission attempts.
///
/// This is the money-path idempotence guard for [`first_contact_admission`]:
/// one reserved/in-flight/settled admission per peer, no matter how many times
/// the caller retries. Production attempts are journaled before dispatch and
/// reloaded after restart. This in-memory cache also supports ephemeral tests.
/// Methods take `now` explicitly so TTL behaviour is unit-testable.
#[derive(Debug, Default)]
struct AdmissionLedger {
    readmissions: std::collections::HashMap<NodeId, super::admission_journal::ReadmissionSettlement>,
    quotes: std::collections::HashMap<NodeId, (u16, u64)>,
    entries: std::collections::HashMap<NodeId, AdmissionRecord>,
}

impl AdmissionLedger {
    /// ATOMIC capacity reserve (replaces the old check-then-act gate, review
    /// finding #2). Under the single ledger lock: prune expired entries, then —
    /// if `peer` already holds a guard/reservation, allow it (a retry reuses its
    /// own slot and adds nothing); else if there is room, insert a `Reserved`
    /// hold and allow it; else the node is at capacity, refuse. Because the check
    /// and the insert are one locked operation, two concurrent NEW peers cannot
    /// both pass at `MAX - 1`.
    fn try_reserve(&mut self, peer: NodeId, now: Instant) -> bool {
        self.prune(now);
        if self.entries.contains_key(&peer) {
            return true;
        }
        if self.entries.len() >= ADMISSION_LEDGER_MAX_ENTRIES {
            return false;
        }
        self.entries
            .insert(peer, AdmissionRecord::Reserved { started_at: now });
        true
    }

    /// Release a capacity reservation on a pre-dispatch failure. Removes the entry
    /// ONLY if it is still `Reserved` — never a real dispatch/settled guard.
    fn release_reservation(&mut self, peer: &NodeId) {
        if matches!(self.entries.get(peer), Some(AdmissionRecord::Reserved { .. })) {
            self.entries.remove(peer);
        }
    }

    /// Record that we are ABOUT to dispatch a payment for `peer` (replaces the
    /// `Reserved` hold). Carries the BOLT11 hash so a retry can probe it.
    /// Unknown outcomes remain reserved until positive failure evidence.
    fn record_dispatch_unknown(
        &mut self,
        peer: NodeId,
        payment_hash: String,
        amount_msat: u64,
        _now: Instant,
    ) {
        self.entries.insert(
            peer,
            AdmissionRecord::DispatchUnknown {
                payment_hash,
                amount_msat,
            },
        );
    }

    /// Promote a `DispatchUnknown` to a CONFIRMED `InFlight` guard once the
    /// backend accepts the payment (no TTL — a confirmed pending HTLC must not
    /// silently expire and re-open double-pay).
    fn promote_to_inflight(&mut self, peer: NodeId, payment_hash: String, amount_msat: u64) {
        self.entries.insert(
            peer,
            AdmissionRecord::InFlight {
                payment_hash,
                amount_msat,
            },
        );
    }

    /// Record that an admission payment to `peer` settled at `now`. Called the
    /// moment settlement is confirmed — BEFORE anything else that can fail — so
    /// no later error path can lead a retry back into paying.
    fn record_settled(&mut self, peer: NodeId, now: Instant) {
        self.prune(now);
        self.entries.insert(
            peer,
            AdmissionRecord::Settled {
                settled_at: now,
                recovered: false,
                envelope: None,
                delivered: false,
            },
        );
    }

    /// Attach the signed admission envelope to the recorded settlement so a
    /// retry can re-send the proof instead of re-paying.
    fn attach_envelope(&mut self, peer: &NodeId, envelope: konsensus_core::UkmEnvelope) {
        if let Some(AdmissionRecord::Settled {
            envelope: stored, ..
        }) = self.entries.get_mut(peer)
        {
            *stored = Some(Box::new(envelope));
        }
    }

    /// Clear a terminal failed/expired tracked payment (`InFlight` OR
    /// `DispatchUnknown`) with the matching hash so a later admission can request
    /// a fresh invoice. Never clears a settled record.
    fn clear_tracked(&mut self, peer: &NodeId, payment_hash: &str) {
        let matches_hash = match self.entries.get(peer) {
            Some(AdmissionRecord::InFlight { payment_hash: h, .. })
            | Some(AdmissionRecord::DispatchUnknown { payment_hash: h, .. }) => h == payment_hash,
            _ => false,
        };
        if matches_hash {
            self.entries.remove(peer);
        }
    }

    /// Whether the settled proof to `peer` may already have gone out.
    fn delivered(&self, peer: &NodeId) -> bool {
        matches!(self.entries.get(peer), Some(AdmissionRecord::Settled { delivered: true, .. }))
    }

    /// Record whether the settled proof to `peer` may have gone out.
    fn set_delivered(&mut self, peer: &NodeId, value: bool) {
        if let Some(AdmissionRecord::Settled { delivered, .. }) = self.entries.get_mut(peer) {
            *delivered = value;
        }
    }

    /// How a settled admission relates to our connection to `peer`,
    /// established at `connected_since`, on which our live paid flag is
    /// `paid_on_live`.
    ///
    /// Another payment is authorized (`Consumed`, and the record is forgotten)
    /// only with evidence that the proof went out on an EARLIER connection: it
    /// may have been written, the live connection is not the one marked paid,
    /// and it is a different connection (recovered after a restart, or opened
    /// after the settlement). A proof that never went out is `Unsent`, whatever
    /// the timestamps say, so a flap between settlement and send never buys the
    /// admission twice. An unknown generation counts as covered, so an
    /// untracked transport never pays twice.
    fn settled_coverage(
        &mut self,
        peer: &NodeId,
        connected_since: Option<Instant>,
        paid_on_live: bool,
        now: Instant,
    ) -> SettledCoverage {
        // The live paid flag wins over any record (or none): this connection
        // was paid for, whatever the cache still holds.
        if paid_on_live {
            return SettledCoverage::Covered;
        }
        let Some(AdmissionRecord::Settled { settled_at, recovered, delivered, .. }) = self.entries.get(peer) else {
            self.prune(now);
            return SettledCoverage::NoRecord;
        };
        if !*delivered {
            return SettledCoverage::Unsent;
        }
        if connected_since.is_some_and(|since| *recovered || *settled_at < since) {
            self.entries.remove(peer);
            return SettledCoverage::Consumed;
        }
        SettledCoverage::Covered
    }

    /// What we know about a prior admission to `peer` as of `now`.
    fn prior_admission(&self, peer: &NodeId, now: Instant) -> PriorAdmission {
        match self.entries.get(peer) {
            Some(AdmissionRecord::InFlight {
                payment_hash,
                amount_msat,
            }) => PriorAdmission::InFlight {
                payment_hash: payment_hash.clone(),
                amount_msat: *amount_msat,
            },
            Some(AdmissionRecord::DispatchUnknown {
                payment_hash,
                amount_msat,
                ..
            }) => {
                PriorAdmission::DispatchUnknown {
                    payment_hash: payment_hash.clone(),
                    amount_msat: *amount_msat,
                }
            }
            Some(AdmissionRecord::Settled {
                settled_at,
                envelope,
                ..
            }) if now.saturating_duration_since(*settled_at) < ADMISSION_SETTLED_TTL => {
                match envelope {
                    Some(env) => PriorAdmission::SettledWithProof(env.clone()),
                    None => PriorAdmission::SettledNoProof,
                }
            }
            // Bare `Reserved`, or any expired record: a retry re-drives the paid
            // path and `try_reserve` treats the peer's own reservation as held.
            _ => PriorAdmission::None,
        }
    }

    /// Drop ONLY expired entries. A live CONFIRMED guard is NEVER evicted:
    /// `InFlight` has no TTL at all (forgetting a pending HTLC would re-open
    /// double-pay); `DispatchUnknown` also has no TTL. The settled cache expires
    /// but durable attempts reload it; bare reservations have a short TTL. Capacity is enforced at
    /// admission time by [`Self::try_reserve`], never by evicting a live guard.
    fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, e| match e {
            AdmissionRecord::InFlight { .. } => true,
            AdmissionRecord::Reserved { started_at } => {
                now.saturating_duration_since(*started_at) < ADMISSION_RESERVED_TTL
            }
            AdmissionRecord::DispatchUnknown { .. } => true,
            AdmissionRecord::Settled { settled_at, .. } => {
                now.saturating_duration_since(*settled_at) < ADMISSION_SETTLED_TTL
            }
        });
        self.quotes.retain(|peer, _| self.entries.contains_key(peer));
        self.readmissions.retain(|peer, _| self.entries.contains_key(peer));
    }
}

/// Process-wide [`AdmissionLedger`]. A `std` mutex (never held across `await`);
/// poisoning is recovered by taking the inner value — losing the ledger to a
/// panic elsewhere must not turn into a payment-path panic here.
fn admission_ledger() -> &'static std::sync::Mutex<AdmissionLedger> {
    static LEDGER: std::sync::OnceLock<std::sync::Mutex<AdmissionLedger>> =
        std::sync::OnceLock::new();
    LEDGER.get_or_init(|| std::sync::Mutex::new(AdmissionLedger::default()))
}

/// Lock the ledger, recovering from poison (see [`admission_ledger`]).
fn lock_admission_ledger() -> std::sync::MutexGuard<'static, AdmissionLedger> {
    admission_ledger()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Per-peer admission singleflight locks.
///
/// The [`AdmissionLedger`] alone closes the SEQUENTIAL retry double-pay but not
/// the CONCURRENT one: two simultaneous composes to the same no-session peer
/// would both read [`PriorAdmission::None`] before either records a settlement,
/// and both pay (review finding, 2026-07-06). Serializing the whole admission
/// attempt per peer closes that window: the second caller waits on this lock,
/// then re-reads the ledger and takes the resend path instead of paying.
///
/// The map itself is guarded by a `std` mutex held only to clone out the
/// per-peer `Arc` (never across `await`); the per-peer lock is a `tokio` mutex
/// held across the full admission attempt (invoice request → pay → settle →
/// envelope), which is a bounded wait: every awaited step inside has its own
/// timeout. Entries nobody holds are pruned once the map exceeds the cap
/// (fail-safe direction: pruning only forgets an idle lock, and the ledger
/// still suppresses re-pay).
fn admission_locks(
) -> &'static std::sync::Mutex<std::collections::HashMap<NodeId, Arc<tokio::sync::Mutex<()>>>> {
    static LOCKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<NodeId, Arc<tokio::sync::Mutex<()>>>>,
    > = std::sync::OnceLock::new();
    LOCKS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Acquire the per-peer admission lock (see [`admission_locks`]).
///
/// Returns `None` when the node is at admission-lock capacity for a NEW peer:
/// the map is full of locks that are all currently held or awaited (so idle-lock
/// pruning frees nothing). Failing closed here bounds the number of concurrent
/// distinct-peer admission attempts (review finding #3, 2026-07-07) rather than
/// growing the map past the cap. An EXISTING peer's lock is always returned — a
/// retry must be able to serialize on its own in-flight attempt.
async fn acquire_peer_admission_lock(peer: &NodeId) -> Option<tokio::sync::OwnedMutexGuard<()>> {
    let per_peer = {
        let mut map = admission_locks()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = map.get(peer) {
            Arc::clone(existing)
        } else {
            if map.len() >= ADMISSION_LEDGER_MAX_ENTRIES {
                // Drop locks no task currently holds or awaits (map holds the only Arc).
                map.retain(|_, lock| Arc::strong_count(lock) > 1);
            }
            if map.len() >= ADMISSION_LEDGER_MAX_ENTRIES {
                // Still full of active locks — fail closed for this new peer.
                return None;
            }
            Arc::clone(map.entry(*peer).or_default())
        }
    };
    Some(per_peer.lock_owned().await)
}

/// RAII release of a pre-dispatch admission [`AdmissionRecord::Reserved`] slot.
///
/// A reservation is taken atomically before the invoice round-trip. If the
/// admission attempt returns before it commits to a dispatch guard (any `?`
/// early-return during invoice request / parse / price-check, or a panic), this
/// frees the slot so capacity is not leaked. Once we record a `DispatchUnknown`
/// (i.e. we are about to pay), `committed` is set and the slot is left in place —
/// it now has its own bounded lifecycle in the ledger.
struct ReservationGuard<'a> {
    peer: &'a NodeId,
    committed: bool,
}

impl Drop for ReservationGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            lock_admission_ledger().release_reservation(self.peer);
        }
    }
}

/// Poll a trackable admission payment to terminal settlement.
///
/// Unlike the generic [`await_settlement`], this helper knows about the
/// admission ledger. If a trackable payment remains pending through the timeout,
/// the ledger entry is intentionally kept so a retry resumes polling the same
/// payment hash instead of paying again. Only terminal failed/expired states
/// clear the in-flight entry and reopen the paid path.
///
/// `updates` must have been subscribed before the payment was dispatched, or
/// on resume before its status was first probed.
async fn await_admission_settlement(
    state: &AppState,
    peer_id: &NodeId,
    updates: SettlementUpdates,
    initial: PaymentDetails,
) -> Result<PaymentDetails, ApiError> {
    let validate = |details: &PaymentDetails| -> Result<(), ApiError> {
        match lock_admission_ledger().prior_admission(peer_id, Instant::now()) {
            PriorAdmission::InFlight { payment_hash, amount_msat } | PriorAdmission::DispatchUnknown { payment_hash, amount_msat }
                if details.payment_hash == payment_hash && details.amount_msat == amount_msat && details.direction == PaymentDirection::Outgoing => Ok(()),
            _ => Err(ApiError::PaymentUnresolved("admission backend returned a different payment identity".into())),
        }
    };
    validate(&initial)?;
    match initial.status {
        PaymentStatus::Settled => return Ok(initial),
        PaymentStatus::Failed | PaymentStatus::Expired => {
            super::admission_journal::clear_failed(state, peer_id)?;
            lock_admission_ledger().clear_tracked(peer_id, &initial.payment_hash);
            return Err(ApiError::Lightning(format!(
                "admission invoice payment failed before settlement: {:?}",
                initial.status
            )));
        }
        PaymentStatus::Pending | PaymentStatus::InFlight => {}
    }

    if initial.payment_hash.is_empty() {
        return Err(ApiError::Lightning(
            "admission invoice dispatched but returned no payment hash to confirm settlement \
             -- not retrying to avoid a double payment"
                .into(),
        ));
    }

    let mut poll = SettlementPoll::new(updates, &initial.payment_hash);
    loop {
        poll.wait().await;

        let details = state
            .lightning
            .get_payment_status(&initial.payment_hash)
            .await
            .map_err(|e| {
                ApiError::Lightning(format!(
                    "admission invoice: failed to poll payment status: {e}"
                ))
            })?;

        validate(&details)?;
        match details.status {
            PaymentStatus::Settled => return Ok(details),
            PaymentStatus::Failed | PaymentStatus::Expired => {
                super::admission_journal::clear_failed(state, peer_id)?;
                lock_admission_ledger().clear_tracked(peer_id, &initial.payment_hash);
                return Err(ApiError::Lightning(format!(
                    "admission invoice payment failed: {:?}",
                    details.status
                )));
            }
            PaymentStatus::Pending | PaymentStatus::InFlight => {
                if poll.timed_out() {
                    return Err(ApiError::Lightning(format!(
                        "admission invoice payment {} still in flight after {}s -- \
                         not paying another invoice; retry will resume polling this payment",
                        initial.payment_hash,
                        PAYMENT_SETTLE_TIMEOUT.as_secs()
                    )));
                }
            }
        }
    }
}

/// Called under the per-peer admission lock for both immediate and recovered
/// settlement. The notification belongs to the original attempt, not the
/// retrying client's grant. The journal marker prevents proof replay duplicates.
fn report_readmission_settlement(state: &AppState, peer: &NodeId, amount_msat: u64) -> Result<(), ApiError> {
    let mut journal = super::admission_journal::load(state, peer)?;
    let event = journal.as_ref().and_then(|a| a.readmission.clone())
        .or_else(|| lock_admission_ledger().readmissions.get(peer).cloned());
    let Some(mut event) = event.filter(|e| !e.reported) else { return Ok(()); };
    event.reported = true;
    if let Some(attempt) = &mut journal {
        attempt.readmission = Some(event.clone());
        super::admission_journal::save(state, peer, attempt)?;
    }
    lock_admission_ledger().readmissions.insert(*peer, event.clone());
    state.audit_log.membrane().readmission_paid(peer, amount_msat, event.budget_msat);
    Ok(())
}

/// Record in the ledger and the journal whether the settled proof to `peer`
/// may have gone out.
fn set_proof_delivered(state: &AppState, peer: &NodeId, delivered: bool) -> Result<(), ApiError> {
    lock_admission_ledger().set_delivered(peer, delivered);
    if let Some(mut attempt) = super::admission_journal::load(state, peer)? {
        if attempt.envelope.is_some() && attempt.proof_delivered != delivered {
            attempt.proof_delivered = delivered;
            super::admission_journal::save(state, peer, &attempt)?;
        }
    }
    Ok(())
}

/// PSI-SPEED: bounds the prekey offers the payer sends right after its proof.
///
/// One of three separate limiters, one per eager path (this one, the payee's
/// offer after promotion in `msg_handler`, and the payer's reply in
/// `session_handler`). They are deliberately not shared: each path runs in its
/// own task (this one in API handlers, the others in their own loops), and in
/// one first contact the payer's offer here and its reply there go to the same
/// peer within milliseconds, so a shared per-peer cooldown would drop the
/// reply that the lower-NodeId payee needs. Each is bounded on its own (one
/// offer per peer per 10 s, 16 per second), so the node-wide total is at most
/// three times that.
fn eager_offers() -> std::sync::MutexGuard<'static, konsensus_message::EagerOfferLimiter> {
    static LIMITER: std::sync::OnceLock<std::sync::Mutex<konsensus_message::EagerOfferLimiter>> =
        std::sync::OnceLock::new();
    LIMITER
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// PSI-SPEED: right after the admission proof went out, offer our X3DH prekey
/// on the same connection, so the session does not wait for the next
/// self-heal tick. Offering it to the node we just paid is part of the act we
/// bought (BUG-PSI); nothing is offered unless that very connection generation
/// is still the live one and marked paid, and the offer is rate-limited. The
/// payee usually reads this before its own promotion and drops it; the session
/// then forms from the payee's offer on promotion (and our reply to it).
/// Best-effort: the periodic self-heal remains the fallback.
async fn offer_prekey_after_proof(state: &AppState, peer_id: &NodeId, since: Option<Instant>) {
    let Some(since) = since else { return };
    if state.session_manager.can_send(peer_id).await {
        return;
    }
    if !eager_offers().allow(peer_id, Instant::now()) {
        tracing::debug!(peer = %peer_id, "eager PrekeyOffer after proof rate-limited; self-heal will offer");
        return;
    }
    let frame = match serde_json::to_value(state.session_manager.prekey_bundle().await)
        .map_err(|e| e.to_string())
        .and_then(|bundle| Frame::PrekeyOffer { bundle }.to_bytes().map_err(|e| e.to_string()))
    {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(peer = %peer_id, error = %e, "failed to build eager PrekeyOffer");
            return;
        }
    };
    // Written only on generation `since`, and only while it is still marked
    // paid: checked under that connection's lock, never via a fresh NodeId
    // lookup that could land on an unpaid replacement.
    match state.transport.send_raw_frame_on_paid_connection(peer_id, since, &frame).await {
        Ok(()) => tracing::info!(peer = %peer_id, "sent PrekeyOffer right after the admission proof (PSI-SPEED)"),
        Err(e) => tracing::warn!(peer = %peer_id, error = %e, "failed to send eager PrekeyOffer after the admission proof"),
    }
}

/// Send the admission proof on connection generation `since` (captured by the
/// caller, who marked that generation paid) and on no other.
///
/// The proof is recorded as possibly delivered BEFORE the write, so a crash
/// mid-send errs toward "consumed". If the transport proves nothing was
/// written (the generation was replaced or is gone), the record goes back to
/// what it was before this attempt: a proof that never went out stays unspent
/// (a retry delivers it on the live connection instead of paying again), and
/// a re-send of a proof that already went out never makes it look unspent.
async fn send_admission_proof(
    state: &AppState,
    peer_id: &NodeId,
    since: Option<Instant>,
    envelope: &konsensus_core::UkmEnvelope,
    on_error: impl FnOnce(konsensus_core::traits::transport::TransportError) -> ApiError,
) -> Result<(), ApiError> {
    let before = lock_admission_ledger().delivered(peer_id);
    set_proof_delivered(state, peer_id, true)?;
    match state.transport.send_on_connection(peer_id, since, envelope).await {
        Ok(()) => {
            offer_prekey_after_proof(state, peer_id, since).await;
            Ok(())
        }
        Err(e) => {
            if matches!(e, konsensus_core::traits::transport::TransportError::NotConnected(_)) {
                tracing::warn!(
                    peer = %peer_id,
                    error = %e,
                    "admission proof not sent: the connection it was bound to is gone"
                );
                set_proof_delivered(state, peer_id, before)?;
            }
            Err(on_error(e))
        }
    }
}

/// Record a settled admission, build its signed proof envelope, attach it to the
/// ledger, and deliver it. The settlement is recorded before proof construction
/// so any malformed-preimage/backend-contract error still suppresses re-pay.
async fn deliver_settled_admission(
    state: &AppState,
    peer_id: &NodeId,
    settled: PaymentDetails,
) -> Result<(), ApiError> {
    report_readmission_settlement(state, peer_id, settled.amount_msat)?;
    lock_admission_ledger().record_settled(*peer_id, Instant::now());
    // Marked BEFORE the proof goes out. Besides guarding against a second
    // payment, this is what lets the payee's replies that complete the act we
    // paid for (its prekey and session handshake, acks, prices) through our own
    // P2 gate on this connection (BUG-PSI). It dies with the connection.
    //
    // The generation is captured ONCE: the proof below is sent on this same
    // connection or not at all (`send_on_connection`), so the connection marked
    // paid and the connection the proof admits cannot differ.
    let since = state.transport.connected_since(peer_id).await;
    if let Some(since) = since {
        state.transport.mark_admission_paid(peer_id, since).await;
    }

    let preimage_hex = settled.preimage.ok_or_else(|| {
        ApiError::Lightning("admission invoice settled but no preimage returned".into())
    })?;
    let preimage_bytes: [u8; 32] = hex::decode(&preimage_hex)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| {
            ApiError::Lightning(format!(
                "malformed preimage from admission invoice: {preimage_hex}"
            ))
        })?;
    let hash_bytes: [u8; 32] = Sha256::digest(preimage_bytes).into();
    if hex::encode(hash_bytes) != settled.payment_hash {
        return Err(ApiError::Lightning("admission preimage does not match invoice".into()));
    }

    let proof = konsensus_core::PaymentProof::new(hash_bytes, preimage_bytes, settled.amount_msat);

    // Build + sign the admission envelope and send it on the pre-session control
    // path that reaches the target's gate.
    //
    // The payload is a fixed NON-EMPTY sentinel, NOT `Vec::new()`: the receiver's
    // first gate step is `UkmEnvelope::validate()`, which rejects an empty
    // ciphertext before the settlement check.
    let sender = *state.identity.node_id();
    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_CHAT,
        sender,
        Recipient::Node(*peer_id),
        ADMISSION_ENVELOPE_MARKER.to_vec(),
        proof,
    )
    .build();
    let sig = state.identity.sign(&envelope.signable_bytes());
    envelope.signature = konsensus_core::Signature::from_ed25519(&sig);

    // Attach the signed proof to the ledger BEFORE attempting delivery: if the
    // send fails now, a retry re-sends this envelope instead of paying again.
    lock_admission_ledger().attach_envelope(peer_id, envelope.clone());
    let previous = super::admission_journal::load(state, peer_id)?;
    super::admission_journal::save(state, peer_id, &super::admission_journal::Attempt {
        dispatch_started: true,
        previous_attempt: None,
        operation: previous.as_ref().and_then(|a| a.operation.clone()),
        max_routing_fee_msat: previous.as_ref().and_then(|a| a.max_routing_fee_msat),
        readmission: previous.as_ref().and_then(|a| a.readmission.clone())
            .or_else(|| lock_admission_ledger().readmissions.get(peer_id).cloned()),
        original_reservation: previous.as_ref().and_then(|a| a.original_reservation.clone()),
        message_may_have_dispatched: previous.as_ref().is_some_and(|a| a.message_may_have_dispatched),
        payment_hash: settled.payment_hash.clone(), amount_msat: settled.amount_msat,
        quote: lock_admission_ledger().quotes.get(peer_id).copied(), envelope: Some(envelope.clone()),
        settled_at_unix: Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()),
        proof_delivered: false,
    })?;

    send_admission_proof(state, peer_id, since, &envelope, |e| {
        ApiError::Internal(format!(
            "admission payment settled but delivering the admission envelope failed \
             (a retry will re-send the paid proof, not pay again): {e}"
        ))
    })
    .await?;

    tracing::info!(
        peer = %peer_id,
        admission_msat = settled.amount_msat,
        "first-contact admission: settled recipient-priced admission invoice + delivered signed admission envelope"
    );

    Ok(())
}

/// Sender-side paid first-contact for a `price_open` stranger.
///
/// When `compose` cannot establish an E2EE session with a non-whitelisted peer,
/// the target is withholding its X3DH prekey until we become *privileged*, and
/// we become privileged only when the target's payment gate accepts a settled,
/// recipient-bound payment from us (promote-on-paid, `msg_handler.rs:257`). This
/// function performs exactly that admission step:
///
/// Admission is **invoice-based**, not keysend: we send the target a
/// `Frame::RequestInvoice` with the reserved `konsensus:admission` purpose (the
/// one request an unprivileged peer is allowed to make, `session_handler.rs`).
/// The target re-prices it from *its own* `PricingEngine` at `KIND_CHAT` and
/// returns a BOLT11 — which carries its own routing (including private-channel
/// route hints), so we can pay it WITHOUT knowing the target's Lightning pubkey
/// (`price_open` withholds it) and WITHOUT a public multi-hop route. We pay the
/// invoice, then deliver a signed admission envelope carrying the settled proof;
/// the target gate-checks the signed *outer* envelope before any decrypt and
/// fires promote-on-paid (`msg_handler.rs:257`).
///
/// Money-path safety: the target sets the price (recipient-priced, NEVER caller
/// input); we accept it only in `1..=`[`ADMISSION_MAX_MSAT`] to bound a malicious
/// invoice; [`await_admission_settlement`] is the double-pay guard for a SINGLE
/// attempt (no re-dispatch of an in-flight payment); the [`AdmissionLedger`] is
/// the double-pay guard across SEQUENTIAL attempts (a compose retried after the
/// payment/session-poll timeout resumes or re-sends the already-paid admission
/// proof instead of paying again); the per-peer lock ([`admission_locks`]) is the double-pay
/// guard across CONCURRENT attempts (simultaneous composes to the same stranger
/// serialize here, so the loser of the race re-reads the ledger and resends).
///
/// Returns `Ok(())` once the admission envelope is dispatched (or re-dispatched
/// from the ledger on a retry). The caller then waits for the session to
/// establish and retries the real (E2EE) send.
/// Financial state survives every operational exit. G1 reserves the checked
/// first-contact aggregate once; re-admission owns a separate budget debit.
#[derive(Default)]
pub(crate) struct FirstContactCharge {
    operation: Option<super::operations::Operation>,
    fee_ceiling_msat: u64,
    reserved_msat: u64,
    pub(crate) settled_msat: u64,
    /// Settled re-admission is reported, but has its own budget reservation.
    pub(crate) readmission_msat: u64,
    /// A separate admission debit may be unresolved before any message dispatch.
    pub(crate) readmission_blocks_message: bool,
    message_price: Option<u64>,
    /// All-in message amount a fresh re-admission quote reserved in the grant
    /// (the parent's top-up), if any.
    message_reserved_all_in: Option<u64>,
    /// Message principal this call last authorized the wallet to pay; a
    /// fresh signed quote on re-admission may reprice it (#111 finding 2).
    message_authorized: Option<u64>,
    message_settled: u64,
    current_dispatch: bool,
    /// Reconciled prior payment, never attributed to this call's grant/debit.
    prior_settled_msat: u64,
}
impl FirstContactCharge {
    /// A connection can change again during one compose. Retain every paid or
    /// uncertain admission instead of overwriting the earlier attempt.
    fn include_attempt(&mut self, attempt: Self) {
        self.fee_ceiling_msat = self.fee_ceiling_msat.saturating_add(attempt.fee_ceiling_msat);
        self.reserved_msat = self.reserved_msat.saturating_add(attempt.reserved_msat);
        self.settled_msat = self.settled_msat.saturating_add(attempt.settled_msat);
        self.prior_settled_msat = self.prior_settled_msat.saturating_add(attempt.prior_settled_msat);
        self.current_dispatch |= attempt.current_dispatch;
        if attempt.message_price.is_some() { self.message_price = attempt.message_price; }
        if attempt.message_reserved_all_in.is_some() { self.message_reserved_all_in = attempt.message_reserved_all_in; }
    }
    pub(crate) fn error(&self, error: ApiError) -> ApiError {
        if self.reserved_msat > self.settled_msat {
            return ApiError::PaymentUnresolved(format!(
                "admission outcome unknown; {} msat remains reserved: {error}",
                self.reserved_msat
            ));
        }
        // A recovered admission belongs to an earlier call. A definitive cap
        // or grant refusal before this call paid must retain its API/N2 code.
        if self.settled_msat == 0 && self.message_settled == 0
            && matches!(error.without_reason(), ApiError::PriceCapExceeded(_) | ApiError::BudgetExceeded(_))
        {
            return error;
        }
        if self.settled_msat == 0 && self.message_settled == 0 && self.prior_settled_msat == 0 {
            return error;
        }
        match error {
            ApiError::PaymentUnresolved(reason) => ApiError::PaymentUnresolved(format!("admission settled for {} msat; message outcome unknown: {reason}", self.settled_msat)),
            ApiError::PaymentProofUnavailable { amount_msat, reason } => ApiError::PaymentProofUnavailable { amount_msat: self.settled_msat.saturating_add(amount_msat), reason },
            other => ApiError::PaymentProofUnavailable { amount_msat: self.settled_msat + self.message_settled, reason: format!("payment settled but send did not complete (prior admission: {} msat; current call: {} msat): {other}", self.prior_settled_msat, self.settled_msat + self.message_settled) },
        }
    }
}

/// A stranger's quote, validated: the admission invoice and the signed price
/// of the first message.
struct AdmissionQuote {
    invoice: lightning_invoice::Bolt11Invoice,
    admission_msat: u64,
    message_price: u64,
    /// When the quote stops being payable, unix seconds.
    expires_at_unix: u64,
}

/// Ask the target for its signed admission invoice (F1 payment preparation).
/// The requested amount is a hint only — the target re-prices from its own
/// engine. `debit` authorizes starting the request for a metered caller.
async fn request_admission_invoice(
    state: &AppState,
    peer_id: &NodeId,
    kind: u16,
    debit: &Debit,
) -> Result<(String, InvoiceResponseData), ApiError> {
    if kind != konsensus_core::kind::KIND_CHAT {
        return Err(ApiError::BadRequest("first contact must be a chat message".into()));
    }
    let current_block_height = state.chain.get_block_height().await.unwrap_or(0);
    let peer_announced = state
        .peer_prices
        .get_fresh_discounted_peer_price(
            peer_id,
            konsensus_core::kind::KIND_CHAT,
            current_block_height,
            MAX_PRICE_AGE,
        )
        .await;
    let own_price = state
        .pricing
        .get_price_msat(konsensus_core::kind::KIND_CHAT)
        .await
        .map_err(|e| ApiError::Internal(format!("pricing error: {e}")))?;
    let requested_msat = derive_admission_msat(peer_announced, own_price);
    let request_id = konsensus_core::admission_quote::request_id(
        peer_id, state.identity.node_id(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
    );
    let (tx, rx) = oneshot::channel::<InvoiceRequestOutcome>();
    {
        let mut requests = state.invoice_requests.lock().await;
        if requests.len() >= MAX_PENDING_INVOICE_REQUESTS {
            return Err(ApiError::Internal(
                "Too many pending invoice requests — try again shortly".into(),
            ));
        }
        requests.insert(request_id.clone(), tx);
    }
    let _binding = invoice_refusal::bind(&request_id, *peer_id);
    let frame = Frame::RequestInvoice {
        request_id: request_id.clone(),
        amount_msat: requested_msat,
        purpose: format!("{ADMISSION_INVOICE_PURPOSE}:{kind}"),
    };
    let frame_bytes = frame
        .to_bytes()
        .map_err(|e| ApiError::Internal(format!("frame serialization error: {e}")))?;
    let sent = match debit.request_invoice(state.transport.send_raw_frame(peer_id, &frame_bytes)).await {
        Ok(sent) => sent,
        Err(refused) => {
            state.invoice_requests.lock().await.remove(&request_id);
            return Err(refused);
        }
    };
    if let Err(e) = sent {
        state.invoice_requests.lock().await.remove(&request_id);
        return Err(ApiError::Internal(format!(
            "failed to send admission invoice request: {e}"
        )));
    }

    // Await the target's repriced BOLT11.
    let response = tokio::time::timeout(INVOICE_REQUEST_TIMEOUT, rx)
        .await
        .map_err(|_| {
            let rid = request_id.clone();
            let reqs = Arc::clone(&state.invoice_requests);
            tokio::spawn(async move {
                reqs.lock().await.remove(&rid);
            });
            ApiError::Internal(
                "admission invoice request timed out — target did not respond".into(),
            )
        })?
        .map_err(|_| ApiError::Lightning("target could not create an admission invoice".into()))?
        .map_err(|error| {
            if error.recipient == *peer_id && error.reason == "stateless_quote_unsupported" {
                ApiError::StatelessQuoteUnsupported
            } else if error.recipient == *peer_id
                && error.reason == invoice_refusal::ADMISSION_RATE_LIMITED
            {
                ApiError::TooManyRequests(format!(
                    "the target rate-limits admission quotes; retry in {} s",
                    ADMISSION_QUOTE_WINDOW.as_secs()
                ))
            } else {
                ApiError::Lightning("target refused admission quote".into())
            }
        })?;
    Ok((request_id, response))
}

/// How far a BOLT11 `timestamp` may lead the payer's clock.
///
/// BOLT11 timestamps are whole seconds from the **recipient** clock. A payer
/// a fraction of a second behind NTP can see a same-second invoice as
/// future-dated and refuse it before dispatch (`duration_since_epoch() > now`
/// with zero slack). This bound is **only** for that future-timestamp check:
/// it must not extend invoice expiry, the live attempt window, or what is paid.
const INVOICE_TIMESTAMP_SKEW: Duration = Duration::from_secs(5);

/// Admission-invoice time bounds with an injected payer clock (`now`).
///
/// `attempt_end` is the unix second the live attempt expires
/// ([`konsensus_core::admission_quote::expires_at`]). Relative TTL must still
/// be ≤ [`konsensus_core::admission_quote::EXPIRY_SECS`].
fn admission_invoice_time_valid(
    created: Duration,
    expires_at: Option<Duration>,
    relative_expiry_secs: u64,
    now: Duration,
    attempt_end: Option<u64>,
) -> bool {
    let Some(end) = attempt_end else {
        return false;
    };
    if created > now.saturating_add(INVOICE_TIMESTAMP_SKEW) {
        return false;
    }
    let Some(expiry) = expires_at else {
        return false;
    };
    // Payer clock: already expired. Do not add skew here (would keep paying).
    if now >= expiry {
        return false;
    }
    // Live attempt window. Do not add skew here (would stretch the attempt).
    if expiry > Duration::from_secs(end) {
        return false;
    }
    relative_expiry_secs <= u64::from(konsensus_core::admission_quote::EXPIRY_SECS)
}

/// Check a target's admission invoice before anything is paid: the
/// authenticated responder, its bounded price, hash, live request-bound
/// expiry, known payee and the signed first-message price.
async fn validate_admission_invoice(
    state: &AppState,
    peer_id: &NodeId,
    request_id: &str,
    response: &InvoiceResponseData,
) -> Result<AdmissionQuote, ApiError> {
    // The Noise session authenticates the target that authorized this invoice.
    // Do not trust the UUID alone: a different peer cannot redirect payment.
    if response.recipient != *peer_id {
        return Err(ApiError::Lightning(
            "admission invoice came from another recipient".into(),
        ));
    }
    // 3. Parse + bound the target's price (recipient-priced; accept up to the cap).
    let invoice = response
        .bolt11
        .parse::<lightning_invoice::Bolt11Invoice>()
        .map_err(|e| ApiError::Lightning(format!("target returned invalid BOLT11: {e}")))?;
    let admission_msat = invoice.amount_milli_satoshis().ok_or_else(|| {
        ApiError::Lightning("target returned an amountless admission invoice".into())
    })?;
    if !admission_price_acceptable(admission_msat) {
        return Err(ApiError::Lightning(format!(
            "target admission price {admission_msat} msat outside accepted range (1..={ADMISSION_MAX_MSAT})"
        )));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let attempt_expiry = konsensus_core::admission_quote::expires_at(
        request_id, peer_id, state.identity.node_id(), now.as_secs(),
    );
    // A short relative TTL alone does not bound a future-dated or delayed
    // invoice. Its signed absolute expiry must fit the original live attempt.
    // The only slack is `INVOICE_TIMESTAMP_SKEW` on the BOLT11 timestamp
    // itself (recipient clock); it must not stretch expiry or the attempt.
    let valid_invoice_time = admission_invoice_time_valid(
        invoice.duration_since_epoch(),
        invoice.expires_at(),
        invoice.expiry_time().as_secs(),
        now,
        attempt_expiry,
    );
    if response.payment_hash != invoice.payment_hash().to_string() || !valid_invoice_time {
        return Err(ApiError::Lightning(
            "admission invoice hash/expiry mismatch".into(),
        ));
    }
    if let Some(expected) = state.peer_ln_pubkeys.lock().await.get(peer_id) {
        if invoice.recover_payee_pub_key().to_string() != *expected {
            return Err(ApiError::Lightning(
                "admission invoice payee does not match recipient".into(),
            ));
        }
    }
    let prefix = format!("konsensus:{request_id}:message=");
    let message_price = invoice
        .description()
        .to_string()
        .strip_prefix(&prefix)
        .and_then(|n| n.parse::<u64>().ok())
        .ok_or_else(|| {
            ApiError::Lightning("target did not sign a request-bound message quote".into())
        })?;
    let message_price = super::caps::payable(message_price);
    // G1: reserve the aggregate cap once BEFORE requesting this invoice,
    // then resolve that same reservation once using the actual combined total.
    // See docs/v2/F1-CAPPED-FIRST-CONTACT.md; never debit only the message.
    // The target is authoritative for BOTH prices. A stale local price cannot
    // spuriously reject a stranger or cause an additional unchecked payment.
    let expires_at_unix = invoice.expires_at().ok_or_else(|| ApiError::Lightning("admission invoice expiry overflow".into()))?.as_secs();
    Ok(AdmissionQuote {
        invoice,
        admission_msat,
        message_price,
        expires_at_unix,
    })
}

/// Quotes the owner has seen, by peer: the send pays exactly this invoice while
/// it is valid, so confirming never makes the target issue a second one (it
/// rate-limits strangers). Memory only; one per peer; validated again on use.
/// Bound to the connection generation that obtained the quote — a reconnect
/// must fetch a fresh one (Codex #111 finding 5).
struct CachedQuote {
    request_id: String,
    response: InvoiceResponseData,
    expires_at_unix: u64,
    /// `transport.connected_since` when the quote was obtained.
    connected_since: Option<Instant>,
}
type QuoteCache = std::sync::Mutex<std::collections::HashMap<NodeId, CachedQuote>>;

fn quote_cache() -> &'static QuoteCache {
    static CACHE: std::sync::OnceLock<QuoteCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Bound on remembered quotes (each expires within 60 s anyway).
const MAX_CACHED_QUOTES: usize = 256;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cache_quote(
    peer: NodeId,
    request_id: String,
    response: InvoiceResponseData,
    expires_at_unix: u64,
    connected_since: Option<Instant>,
) {
    let mut cache = quote_cache().lock().unwrap_or_else(|e| e.into_inner());
    let now = now_unix();
    cache.retain(|_, q| q.expires_at_unix > now);
    if cache.len() >= MAX_CACHED_QUOTES && !cache.contains_key(&peer) {
        return; // bounded: the send will simply ask for a fresh quote
    }
    cache.insert(peer, CachedQuote { request_id, response, expires_at_unix, connected_since });
}

/// A cached, still-valid quote for `peer` on the current connection generation.
fn peek_cached_quote(
    peer: &NodeId,
    connected_since: Option<Instant>,
) -> Option<(String, InvoiceResponseData)> {
    let cache = quote_cache().lock().unwrap_or_else(|e| e.into_inner());
    let q = cache.get(peer)?;
    (q.expires_at_unix > now_unix() && q.connected_since == connected_since)
        .then(|| (q.request_id.clone(), q.response.clone()))
}

fn take_cached_quote(
    peer: &NodeId,
    connected_since: Option<Instant>,
) -> Option<(String, InvoiceResponseData)> {
    let mut cache = quote_cache().lock().unwrap_or_else(|e| e.into_inner());
    let q = cache.remove(peer)?;
    (q.expires_at_unix > now_unix() && q.connected_since == connected_since)
        .then_some((q.request_id, q.response))
}

/// The connection changed between asking for an admission quote and paying it.
/// The quote belongs to the earlier connection and is never paid.
fn quote_generation_changed(peer_id: &NodeId) -> ApiError {
    ApiError::NotDispatched(format!(
        "the connection to {peer_id} changed while its admission quote was in flight; that \
         quote belongs to the earlier connection — nothing was paid"
    ))
}

/// Ask for an admission quote on the live connection and return it with the
/// generation it was asked on. A reconnect before the response refuses it.
async fn request_generation_bound_quote(
    state: &AppState, peer_id: &NodeId, kind: u16, debit: &Debit,
) -> Result<(Option<Instant>, String, InvoiceResponseData), ApiError> {
    let generation = state.transport.connected_since(peer_id).await;
    // No live connection is no generation: never bind a quote to it (#127 review finding 2).
    if generation.is_none() {
        return Err(ApiError::NotDispatched(format!(
            "{peer_id} has no live connection to bind an admission quote to — nothing was paid"
        )));
    }
    let (request_id, response) = request_admission_invoice(state, peer_id, kind, debit).await?;
    if state.transport.connected_since(peer_id).await != generation {
        return Err(quote_generation_changed(peer_id));
    }
    Ok((generation, request_id, response))
}

/// `POST /api/v1/messages/first-contact/quote` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstContactQuoteRequest {
    /// The stranger's node id (64 hex).
    pub recipient: String,
}

/// What a first contact to this stranger would cost, from the target's own
/// signed quote. Nothing has been paid.
#[derive(Debug, Serialize)]
pub struct FirstContactQuoteResponse {
    pub max_routing_fee_msat: u64,
    pub recipient: String,
    /// The target's admission price, msat (paid once).
    pub admission_msat: u64,
    /// The target's price for this first message, msat (signed in the quote).
    pub message_msat: u64,
    /// Admission plus first message plus both routing ceilings: cap to confirm, msat.
    pub total_msat: u64,
    /// The quote is payable until this unix time (≤ 60 s).
    pub expires_at: u64,
}

/// `POST /api/v1/messages/first-contact/quote` — show the owner a stranger's
/// own price before anything is paid (the "door card"). Asks the connected
/// target for its signed admission quote (F1's bounded payment preparation),
/// validates it exactly as a send would, and remembers it for up to 60 s so
/// the confirmed send pays this very invoice. Pays nothing and reserves
/// nothing. Needs `spend`; a paired client also needs a live budget grant.
pub(super) async fn first_contact_quote(
    auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    Json(req): Json<FirstContactQuoteRequest>,
) -> Result<Json<FirstContactQuoteResponse>, ApiError> {
    if !auth.has_live_grant(&state) {
        return Err(ApiError::BudgetExceeded(crate::spend_budget::BudgetRefusal::NoGrant));
    }
    let peer_id = NodeId::from_hex(&req.recipient)
        .map_err(|e| ApiError::BadRequest(format!("invalid recipient: {e}")))?;
    if !state.transport.is_connected(&peer_id).await {
        return Err(ApiError::BadRequest(
            "Recipient is offline. A first-contact quote needs a connected node.".into(),
        ));
    }
    // A contact we already hold a session with needs this quote only to be
    // admitted again after a reconnect (its connection starts unpaid). Its
    // earlier admission is spent, so the paid/in-flight check below does not
    // apply; the send re-checks the ledger before paying anything.
    let contact = state.session_manager.has_session(&peer_id).await;
    let generation = state.transport.connected_since(&peer_id).await;
    if let Some((request_id, response)) = contact
        .then(|| peek_cached_quote(&peer_id, generation))
        .flatten()
    {
        // Reuse the quote the refused send already fetched: the target
        // rate-limits quotes, and the send pays exactly this invoice.
        let quote = validate_admission_invoice(&state, &peer_id, &request_id, &response).await?;
        let total_msat = super::caps::first_contact_total(super::caps::all_in(&state, quote.admission_msat, None)?, super::caps::all_in(&state, quote.message_price, None)?, None)?;
        return Ok(Json(FirstContactQuoteResponse {
            max_routing_fee_msat: total_msat - quote.admission_msat - quote.message_price,
            recipient: peer_id.to_hex(),
            admission_msat: quote.admission_msat,
            message_msat: quote.message_price,
            total_msat,
            expires_at: quote.expires_at_unix,
        }));
    }
    if !contact
        && (!matches!(lock_admission_ledger().prior_admission(&peer_id, Instant::now()), PriorAdmission::None)
            || super::admission_journal::load(&state, &peer_id)?.is_some())
    {
        return Err(ApiError::Conflict(
            "a first contact to this node is already paid or in flight; sending resumes it without paying again".into(),
        ));
    }
    let (generation, request_id, response) = request_generation_bound_quote(
        &state, &peer_id, konsensus_core::kind::KIND_CHAT, &Debit::unmetered(),
    ).await?;
    let quote = validate_admission_invoice(&state, &peer_id, &request_id, &response).await?;
    let total_msat = super::caps::first_contact_total(super::caps::all_in(&state, quote.admission_msat, None)?, super::caps::all_in(&state, quote.message_price, None)?, None)?;
    // Bound to the generation that obtained it, never the one live after the
    // response: a reconnect at any point before the send pays means a new quote.
    if state.transport.connected_since(&peer_id).await != generation {
        return Err(quote_generation_changed(&peer_id));
    }
    cache_quote(peer_id, request_id, response, quote.expires_at_unix, generation);
    Ok(Json(FirstContactQuoteResponse {
        max_routing_fee_msat: total_msat - quote.admission_msat - quote.message_price,
        recipient: peer_id.to_hex(),
        admission_msat: quote.admission_msat,
        message_msat: quote.message_price,
        total_msat,
        expires_at: quote.expires_at_unix,
    }))
}

async fn reconcile_admission_budget(
    state: &AppState, peer: &NodeId, current: Option<&crate::spend_budget::Reservation>,
) -> Result<(), ApiError> {
    let Some(attempt) = super::admission_journal::load(state, peer)? else { return Ok(()); };
    let Some(original) = &attempt.original_reservation else { return Ok(()); };
    if Some(original) == current || attempt.message_may_have_dispatched { return Ok(()); }
    let Ok(details) = state.lightning.get_payment_status(&attempt.payment_hash).await else { return Ok(()); };
    if details.payment_hash != attempt.payment_hash || details.amount_msat != attempt.amount_msat
        || details.direction != PaymentDirection::Outgoing { return Ok(()); }
    let actual = match details.status {
        PaymentStatus::Settled => {
            report_readmission_settlement(state, peer, attempt.amount_msat)?;
            let Some(total) = details.fee_msat.and_then(|fee| attempt.amount_msat.checked_add(fee)) else { return Ok(()); };
            total
        },
        PaymentStatus::Failed | PaymentStatus::Expired => 0,
        _ => return Ok(()),
    };
    if let Some(service) = &state.pairing { service.resolve_spend(original, &peer.to_hex(), actual); }
    Ok(())
}

/// Recover payment evidence before deciding whether the current connection is
/// covered. In particular, a restarted sender must classify its settled journal
/// against the new connection before deciding to resend a proof. Uncertain
/// attempts remain recovery guards and never authorize another payment.
pub(super) async fn clear_undispatched_admission(state: &AppState, peer_id: &NodeId, hash: &str) -> Result<bool, ApiError> {
    if let Some(attempt) = super::admission_journal::load(state, peer_id)? {
        if !attempt.dispatch_started && attempt.payment_hash == hash {
            if let Some(link) = &attempt.operation {
                super::operations::record_undispatched_admission(state, peer_id, link, attempt.original_reservation.as_ref()).await?;
            }
        }
    }
    let cleared = super::admission_journal::undo_undispatched(state, peer_id, hash)?;
    if cleared { lock_admission_ledger().clear_tracked(peer_id, hash); }
    Ok(cleared)
}

async fn recover_admission_attempt(state: &AppState, peer_id: &NodeId) -> Result<(), ApiError> {
    if let Some(attempt) = super::admission_journal::load(state, peer_id)? {
        clear_undispatched_admission(state, peer_id, &attempt.payment_hash).await?;
    }
    // Reload a durable attempt before considering any new dispatch. An unknown
    // backend result (including PaymentNotFound) never authorizes a new invoice.
    if matches!(
        lock_admission_ledger().prior_admission(peer_id, Instant::now()),
        PriorAdmission::None
    ) {
        if let Some(attempt) = super::admission_journal::load(state, peer_id)? {
            let settled_age = attempt.settled_at_unix.map(|t| Duration::from_secs(
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs().saturating_sub(t)
            ));
            let settled_expired = attempt.envelope.is_some()
                && settled_age.is_some_and(|age| age >= ADMISSION_SETTLED_TTL);
            if settled_expired {
                // Preserve the existing settled-admission lifetime. This is
                // positive settlement evidence; unknown attempts never expire.
                super::admission_journal::clear(state, peer_id)?;
            } else {
                let mut ledger = lock_admission_ledger();
                if let Some(envelope) = attempt.envelope {
                    let settled_at = Instant::now().checked_sub(settled_age.unwrap_or_default()).unwrap_or_else(Instant::now);
                    ledger.record_settled(*peer_id, settled_at);
                    if let Some(AdmissionRecord::Settled { recovered, delivered, .. }) = ledger.entries.get_mut(peer_id) {
                        *recovered = true;
                        *delivered = attempt.proof_delivered;
                    }
                    ledger.attach_envelope(peer_id, envelope);
                } else {
                    ledger.record_dispatch_unknown(
                        *peer_id,
                        attempt.payment_hash,
                        attempt.amount_msat,
                        Instant::now(),
                    );
                }
                if let Some(quote) = attempt.quote {
                    ledger.quotes.insert(*peer_id, quote);
                }
            }
        }
    }
    Ok(())
}

/// How many times a proof re-send reclassifies after the connection it was
/// classified against was replaced, before giving up without paying.
const RECLASSIFY_ATTEMPTS: u8 = 2;

async fn first_contact_admission(
    state: &AppState,
    peer_id: &NodeId,
    kind: u16,
    cap: Option<u64>,
    charge: &mut FirstContactCharge,
    debit: &Debit,
    readmit: Option<&mut Readmit<'_>>,
) -> Result<(), ApiError> {
    first_contact_admission_at(state, peer_id, kind, cap, charge, debit, readmit, RECLASSIFY_ATTEMPTS).await
}

/// [`first_contact_admission`] with `reclassify` re-classifications left.
#[allow(clippy::too_many_arguments)]
async fn first_contact_admission_at(
    state: &AppState,
    peer_id: &NodeId,
    kind: u16,
    cap: Option<u64>,
    charge: &mut FirstContactCharge,
    debit: &Debit,
    mut readmit: Option<&mut Readmit<'_>>,
    reclassify: u8,
) -> Result<(), ApiError> {
    // The stateless quote signs a chat price, including when cached or recovered.
    if kind != konsensus_core::kind::KIND_CHAT {
        return Err(ApiError::BadRequest("first contact must be a chat message".into()));
    }
    // 0b. Idempotence guard (now race-free under the per-peer lock): if we
    //     already SETTLED an admission payment to this peer within the TTL, do
    //     not pay again — re-send the proof envelope (best-effort) and let the
    //     caller resume polling for the session. This is the fix for the
    //     post-settlement retry double-pay: session-poll timeout → compose
    //     error → user retries → without this guard the stranger pays full
    //     admission on every retry.
    recover_admission_attempt(state, peer_id).await?;
    // 0a. A proof that went out on an OLDER connection (a flap, a reconnect, a
    //     restart that reloaded the journal) was consumed there and cannot admit
    //     us on this one: the recipient admits per connection, and its replay
    //     table (durable) refuses the old proof, so re-sending it could only end
    //     in a 502. As in `readmit_then_pay`, forget it and pay this connection's
    //     admission once. A proof that never went out is kept and delivered
    //     below (`SettledWithProof`), never paid for twice.
    let connected_since = state.transport.connected_since(peer_id).await;
    let paid_on_live = state.transport.admission_paid_on_connection(peer_id).await;
    let coverage = lock_admission_ledger().settled_coverage(peer_id, connected_since, paid_on_live, Instant::now());
    if coverage == SettledCoverage::Consumed {
        reconcile_admission_budget(state, peer_id, debit.reservation().as_ref()).await?;
        super::admission_journal::clear(state, peer_id)?;
        lock_admission_ledger().quotes.remove(peer_id);
    }
    if let Some((quoted_kind, price)) = lock_admission_ledger().quotes.get(peer_id) {
        if *quoted_kind == kind {
            charge.message_price = Some(*price);
        }
    }
    let prior = lock_admission_ledger().prior_admission(peer_id, Instant::now());
    match prior {
        PriorAdmission::None => {
            if state.transport.admission_paid_on_connection(peer_id).await {
                return Err(ApiError::PaymentUnresolved("admission already settled on this connection; cached proof expired, refusing a second payment".into()));
            }
        }
        PriorAdmission::InFlight {
            payment_hash,
            amount_msat,
        } => {
            charge.reserved_msat = amount_msat;
            tracing::info!(
                peer = %peer_id,
                %payment_hash,
                "admission retry: resuming already-dispatched admission payment (no second invoice)"
            );
            let updates = SettlementUpdates::subscribe(state.lightning.as_ref());
            let initial = PaymentDetails {
                payment_hash,
                preimage: None,
                amount_msat,
                status: PaymentStatus::InFlight,
                direction: PaymentDirection::Outgoing,
                timestamp: 0,
                memo: Some("konsensus admission retry".into()),
                fee_msat: None,
            };
            let settled = await_admission_settlement(state, peer_id, updates, initial).await?;
            charge.prior_settled_msat = settled.amount_msat;
            charge.reserved_msat = 0;
            deliver_settled_admission(state, peer_id, settled).await?;
            return Ok(());
        }
        PriorAdmission::DispatchUnknown {
            payment_hash,
            amount_msat,
        } => {
            charge.reserved_msat = amount_msat;
            // A prior attempt may have dispatched this payment but never confirmed
            // it (pay_invoice errored). PROBE the backend before deciding — never
            // pay a fresh invoice while the first may still settle, and never brick
            // the peer permanently (review finding #1, 2026-07-07).
            tracing::info!(
                peer = %peer_id, %payment_hash,
                "admission retry: probing a possibly-dispatched admission payment"
            );
            let updates = SettlementUpdates::subscribe(state.lightning.as_ref());
            match state.lightning.get_payment_status(&payment_hash).await {
                Ok(details) if details.status == PaymentStatus::Settled => {
                    lock_admission_ledger().promote_to_inflight(
                        *peer_id,
                        payment_hash.clone(),
                        amount_msat,
                    );
                    let settled =
                        await_admission_settlement(state, peer_id, updates, details).await?;
                    charge.prior_settled_msat = settled.amount_msat;
                    charge.reserved_msat = 0;
                    deliver_settled_admission(state, peer_id, settled).await?;
                    return Ok(());
                }
                Ok(details)
                    if matches!(
                        details.status,
                        PaymentStatus::Pending | PaymentStatus::InFlight
                    ) =>
                {
                    // Backend confirms it — promote to a durable (no-TTL) in-flight
                    // guard so a still-pending HTLC cannot silently expire and be
                    // re-paid, then resume polling.
                    lock_admission_ledger().promote_to_inflight(
                        *peer_id,
                        payment_hash.clone(),
                        amount_msat,
                    );
                    let initial = PaymentDetails {
                        payment_hash,
                        preimage: None,
                        amount_msat,
                        status: PaymentStatus::InFlight,
                        direction: PaymentDirection::Outgoing,
                        timestamp: 0,
                        memo: Some("konsensus admission retry".into()),
                        fee_msat: None,
                    };
                    let settled =
                        await_admission_settlement(state, peer_id, updates, initial).await?;
                    charge.prior_settled_msat = settled.amount_msat;
                    charge.reserved_msat = 0;
                    deliver_settled_admission(state, peer_id, settled).await?;
                    return Ok(());
                }
                Ok(details) => {
                    if details.payment_hash != payment_hash
                        || details.amount_msat != amount_msat
                        || details.direction != PaymentDirection::Outgoing
                    {
                        return Err(ApiError::PaymentUnresolved(
                            "admission retry returned mismatched payment".into(),
                        ));
                    }
                    super::admission_journal::clear_failed(state, peer_id)?;
                    charge.reserved_msat = 0;
                    // Terminal failed/expired — the payment did NOT go through.
                    // Clear the guard so a retry can pay a fresh admission invoice.
                    lock_admission_ledger().clear_tracked(peer_id, &payment_hash);
                    return Err(ApiError::Lightning(format!(
                        "a possibly-dispatched admission payment to {peer_id} did not go through \
                         ({:?}); the guard is cleared — retry to pay a fresh admission invoice",
                        details.status
                    )));
                }
                Err(_) => {
                    // Backend does not recognize the hash or is unreachable: we
                    // cannot confirm dispatch. Keep the durable reservation:
                    // absence of a record does not prove non-dispatch.
                    return Err(ApiError::PaymentUnresolved(format!(
                        "admission payment to {peer_id} could not be confirmed; not paying a second invoice"
                    )));
                }
            }
        }
        PriorAdmission::SettledWithProof(mut envelope) => {
            // The proof's coverage was classified against `connected_since`.
            // If that connection was replaced since, the classification is
            // stale: the proof may have been consumed on the old connection,
            // and marking the replacement paid for it would block the
            // admission the replacement needs. Classify again on the live one.
            if state.transport.connected_since(peer_id).await != connected_since {
                if reclassify == 0 {
                    return Err(ApiError::PaymentUnresolved(format!(
                        "the connection to {peer_id} kept changing while re-sending an already-paid \
                         admission proof; nothing was re-sent and no second payment was made — retry shortly"
                    )));
                }
                tracing::info!(peer = %peer_id, "admission retry: connection replaced after classification; reclassifying");
                return Box::pin(first_contact_admission_at(
                    state, peer_id, kind, cap, charge, debit, readmit, reclassify - 1,
                )).await;
            }
            report_readmission_settlement(state, peer_id, envelope.payment_proof.amount_msat)?;
            charge.prior_settled_msat = envelope.payment_proof.amount_msat;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_millis().min(u64::MAX as u128) as u64;
            envelope.refresh_for_resend(&state.identity, now)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            if let Some(mut attempt) = super::admission_journal::load(state, peer_id)? {
                attempt.envelope = Some(*envelope.clone());
                super::admission_journal::save(state, peer_id, &attempt)?;
            }
            lock_admission_ledger().attach_envelope(peer_id, *envelope.clone());
            // Re-deliver the already-paid proof. If the target already consumed
            // this payment hash (envelope arrived the first time), its replay
            // table rejects the duplicate — harmless to us, and we are already
            // promoted there. If the first delivery was lost after settlement,
            // this re-send is exactly the heal that makes the payment count.
            //
            // The generation it was classified against is the one marked paid
            // and the only one the proof goes out on. If it was replaced after
            // the check above, the mark is ignored and the send is refused as
            // NotConnected: a replacement is never marked paid for this proof.
            let since = connected_since;
            if let Some(since) = since {
                state.transport.mark_admission_paid(peer_id, since).await;
            }
            send_admission_proof(state, peer_id, since, &envelope, |e| {
                // Do NOT swallow this into Ok: if re-delivery fails we cannot
                // claim the envelope was delivered (review finding #5,
                // 2026-07-07). Return a precise error — the paid proof is safe in
                // the ledger, so a later retry re-sends it and never re-pays.
                tracing::warn!(
                    peer = %peer_id,
                    error = %e,
                    "admission retry: re-sending already-paid admission envelope failed \
                     (will NOT re-pay; a later retry re-sends the same proof)"
                );
                ApiError::PaymentUnresolved(format!(
                    "an already-paid admission proof for {peer_id} exists but re-delivering it \
                     failed ({e}) — no second payment was made; retry shortly"
                ))
            })
            .await?;
            tracing::info!(
                peer = %peer_id,
                "admission retry: re-sent already-paid admission envelope (no second payment)"
            );
            return Ok(());
        }
        PriorAdmission::SettledNoProof => {
            // Money moved but we never obtained a valid preimage to build the
            // proof (Lightning-backend contract violation). Never pay twice for
            // one admission: surface it as an ERROR, not `Ok` — without a proof
            // envelope the target can never promote us, so letting the caller
            // poll 25s for a session (and then claim "envelope delivered") would
            // be both futile and false (review finding, 2026-07-06).
            tracing::warn!(
                peer = %peer_id,
                "admission retry: a prior admission payment settled but no proof envelope \
                 is available (malformed preimage from backend) — refusing to pay again \
                 within the idempotence window"
            );
            return Err(ApiError::PaymentUnresolved(format!(
                "a prior admission payment to {peer_id} settled but no payment proof is \
                 available (the Lightning backend returned a malformed preimage) — refusing \
                 to pay admission again; reconcile the original payment with the backend"
            )));
        }
    }

    // 0c. ATOMIC capacity reservation (fail closed): we reached the paid path, so
    //     this peer has NO live guard. Reserve a slot in ONE locked operation so
    //     two concurrent NEW peers cannot both pass at MAX-1 and overrun the cap
    //     (review finding #2, 2026-07-07). The reservation is released by the RAII
    //     guard on any pre-dispatch failure, and replaced by a dispatch guard once
    //     we pay — so the capacity slot is never leaked nor double-counted.
    if !lock_admission_ledger().try_reserve(*peer_id, Instant::now()) {
        return Err(ApiError::Internal(
            "admission capacity reached: the node is already tracking the maximum number of \
             concurrent/recent first-contact admissions — retry shortly"
                .into(),
        ));
    }
    let mut reservation = ReservationGuard {
        peer: peer_id,
        committed: false,
    };

    // 1–3. The target's signed quote: the one the owner confirmed (cached by
    //      the quote route) if it is still valid on this connection generation,
    //      else a fresh one. Either way it is validated here, against the clock
    //      now. A quote from a prior generation is discarded (finding 5).
    //      Each quote keeps the generation that obtained it: captured before
    //      its request and required unchanged when the response arrives, then
    //      carried to dispatch. It is never recaptured (#111 review finding 1).
    let live_generation = state.transport.connected_since(peer_id).await;
    let (quote_generation, request_id, response) = match take_cached_quote(peer_id, live_generation) {
        Some((request_id, response)) => (live_generation, request_id, response),
        None => match request_generation_bound_quote(state, peer_id, kind, debit).await {
            Err(ApiError::TooManyRequests(_)) => {
                // Retry only a bound prepayment refusal, once, after the source
                // cooldown, as a new request bound to its own generation.
                tokio::time::sleep(ADMISSION_QUOTE_WINDOW).await;
                request_generation_bound_quote(state, peer_id, kind, debit).await?
            }
            other => other?,
        },
    };
    let AdmissionQuote { invoice, admission_msat, message_price, expires_at_unix } =
        validate_admission_invoice(state, peer_id, &request_id, &response).await?;
    // G1: the caller reserved the aggregate cap once before this invoice was
    // requested and resolves that same reservation once with the actual total.
    // See docs/v2/F1-CAPPED-FIRST-CONTACT.md; never debit only the message.
    // The target is authoritative for BOTH prices. A stale local price cannot
    // spuriously reject a stranger or cause an additional unchecked payment.
    let admission_all_in = admission_msat.checked_add(debit.fee_limit(state, admission_msat)).ok_or_else(|| ApiError::PriceCapExceeded("admission debit overflow".into()))?;
    let message_all_in = message_price.checked_add(debit.fee_limit(state, message_price)).ok_or_else(|| ApiError::PriceCapExceeded("message debit overflow".into()))?;
    if let Err(error) = super::caps::first_contact_total(
        admission_all_in,
        message_all_in,
        cap.or(Some(ADMISSION_MAX_MSAT)),
    ) {
        if readmit.is_none() { return Err(error); }
        // Nothing was paid. Keep this very quote, bound to the generation that
        // obtained it: the owner's quote read shows it, and a send under a cap
        // that fits pays exactly this invoice without asking the target again.
        cache_quote(*peer_id, request_id, response, expires_at_unix, quote_generation);
        return Err(ApiError::PriceCapExceeded(format!(
            "{peer_id} asks {admission_msat} msat for admission again plus {message_price} msat \
             for this message, {} msat all-in with routing fees, more than the {} msat left \
             under the confirmed cap; no invoice was paid. Ask for the admission quote and \
             send again under a cap that fits.",
            admission_all_in.saturating_add(message_all_in), cap.unwrap_or(ADMISSION_MAX_MSAT),
        )).with_reason(READMISSION_REQUIRED));
    }
    // The admission fee ceiling is recorded only at the wallet dispatch boundary
    // below (#127 follow-up): generation checks and grant reservation can still
    // refuse with nothing given to the wallet, so they must not report it.
    charge.message_price = Some(message_price);
    let admission_fee_ceiling = debit.fee_limit(state, admission_msat);
    // Generation must still match before we reserve or pay.
    if state.transport.connected_since(peer_id).await != quote_generation {
        return Err(quote_generation_changed(peer_id));
    }
    // A re-admission reserves the fresh message all-in (replacing the prior
    // message reservation) plus admission+fee against the grant before anything
    // is dispatched; the owner's key is not metered. A refusal here leaves
    // nothing requested on our wallet or paid (Codex #111 finding 3).
    let readmission_event = readmit.as_ref().map(|r| super::admission_journal::ReadmissionSettlement {
        budget_msat: r.parent.contact_budget(&peer_id.to_hex()), reported: false,
    });
    let readmission_fee_counter = readmit.as_ref().map(|r| r.fee_ceiling);
    let debit: &Debit = match readmit.as_mut() {
        Some(r) => {
            let reserved = r.reserved.insert(r.parent.reserve_quoted_readmission(
                &peer_id.to_hex(),
                if r.reprice_message { message_all_in } else { 0 },
                admission_all_in,
            )?);
            if r.reprice_message && r.parent.is_metered() {
                charge.message_reserved_all_in = Some(message_all_in);
            }
            reserved
        }
        None => debit,
    };

    // Re-check after the reservation (the grant lock may have waited).
    if state.transport.connected_since(peer_id).await != quote_generation {
        if let Some(r) = readmit.as_ref().and_then(|r| r.reserved.as_ref()) {
            r.released(&peer_id.to_hex());
        }
        return Err(quote_generation_changed(peer_id));
    }
    // 4. Record a DispatchUnknown guard from the BOLT11 payment hash BEFORE
    //    dispatching, then pay. This closes the ambiguous-dispatch window (review
    //    finding #4) WITHOUT the permanent-brick hazard (review finding #1,
    //    2026-07-07): DispatchUnknown carries the hash so a retry can PROBE it, and
    //    unknown dispatch never expires. Recording it commits the capacity reservation (the slot is
    //    now a DispatchUnknown with its own lifecycle, no longer released on drop).
    let bolt11_payment_hash = hex::encode(invoice.payment_hash());
    let mut attempt = super::admission_journal::Attempt {
            dispatch_started: false,
            previous_attempt: super::admission_journal::load(state, peer_id)?.map(Box::new),
            operation: charge.operation.as_ref().map(|op| op.reservation_link(readmission_event.is_some())),
            max_routing_fee_msat: Some(admission_fee_ceiling),
            payment_hash: bolt11_payment_hash.clone(),
            amount_msat: admission_msat,
            quote: Some((kind, message_price)),
            envelope: None,
            settled_at_unix: None,
            original_reservation: debit.reservation(),
            message_may_have_dispatched: false,
            readmission: readmission_event.clone(),
            proof_delivered: false,
        };
    super::admission_journal::save(state, peer_id, &attempt)?;
    lock_admission_ledger()
        .quotes
        .insert(*peer_id, (kind, message_price));
    lock_admission_ledger().record_dispatch_unknown(
        *peer_id,
        bolt11_payment_hash.clone(),
        admission_msat,
        Instant::now(),
    );
    if let Some(operation) = &charge.operation {
        if let Err(error) = operation.admission_started(bolt11_payment_hash.clone(), admission_msat, readmission_event.is_some(), debit).await {
            // Keep the durable false dispatch marker until recovery can also
            // checkpoint the operation; an I/O error may have committed SQL.
            lock_admission_ledger().clear_tracked(peer_id, &bolt11_payment_hash);
            return Err(error);
        }
    }
    // Last generation check, before the durable dispatch marker: a reconnect
    // while the journal was written backs out exactly like a wallet refusal.
    if state.transport.connected_since(peer_id).await != quote_generation {
        super::admission_journal::mark_undispatched(state, peer_id, &bolt11_payment_hash)?;
        if let Some(operation) = &charge.operation { operation.admission_not_dispatched().await?; }
        super::admission_journal::clear_failed(state, peer_id)?;
        lock_admission_ledger().clear_tracked(peer_id, &bolt11_payment_hash);
        return Err(quote_generation_changed(peer_id));
    }
    // No await separates this durable dispatch marker from the guarded wallet
    // call below. Cancellation while admission_started awaited leaves false.
    attempt.dispatch_started = true;
    attempt.previous_attempt = None;
    super::admission_journal::save(state, peer_id, &attempt)?;
    if let Some(event) = readmission_event {
        lock_admission_ledger().readmissions.insert(*peer_id, event);
    } else {
        lock_admission_ledger().readmissions.remove(peer_id);
    }
    reservation.committed = true;
    charge.reserved_msat = admission_msat;

    // Only positively proven non-dispatch releases the durable reservation.
    charge.current_dispatch = true;
    // Dispatch boundary: this ceiling is the one given to the wallet. Report it
    // on errors from here on; earlier refusals leave charge.fee_ceiling_msat at 0.
    charge.fee_ceiling_msat = admission_fee_ceiling;
    if let Some(counter) = readmission_fee_counter {
        counter.fetch_add(admission_fee_ceiling, std::sync::atomic::Ordering::Relaxed);
    }
    let updates = SettlementUpdates::subscribe(state.lightning.as_ref());
    let dispatched = match debit.dispatch(state.lightning.pay_invoice_with_fee_limit(&response.bolt11, admission_fee_ceiling)).await {
        Ok(result) => result,
        Err(error @ ApiError::BudgetExceeded(_)) => {
            super::admission_journal::mark_undispatched(state, peer_id, &bolt11_payment_hash)?;
            if let Some(operation) = &charge.operation { operation.admission_not_dispatched().await?; }
            super::admission_journal::clear_failed(state, peer_id)?;
            lock_admission_ledger().clear_tracked(peer_id, &bolt11_payment_hash);
            charge.reserved_msat = 0;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let details = match dispatched {
        Ok(details) => details,
        Err(LightningError::NotReady) => {
            super::admission_journal::mark_undispatched(state, peer_id, &bolt11_payment_hash)?;
            if let Some(operation) = &charge.operation { operation.admission_not_dispatched().await?; }
            super::admission_journal::clear_failed(state, peer_id)?;
            lock_admission_ledger().clear_tracked(peer_id, &bolt11_payment_hash);
            charge.reserved_msat = 0;
            return Err(ApiError::NotReady);
        }
        Err(LightningError::PaymentNotDispatched(reason)) => {
            super::admission_journal::mark_undispatched(state, peer_id, &bolt11_payment_hash)?;
            if let Some(operation) = &charge.operation { operation.admission_not_dispatched().await?; }
            super::admission_journal::clear_failed(state, peer_id)?;
            lock_admission_ledger().clear_tracked(peer_id, &bolt11_payment_hash);
            charge.reserved_msat = 0;
            return Err(ApiError::NotDispatched(reason));
        }
        Err(error) => return Err(ApiError::PaymentUnresolved(format!(
            "admission dispatch outcome unknown for {bolt11_payment_hash}; retry will reconcile the same invoice: {error}"
        ))),
    };

    // pay_invoice returned Ok — dispatch is CONFIRMED. Promote the guard to a
    // durable (no-TTL) InFlight so a still-pending HTLC cannot silently expire and
    // be re-paid, then poll to terminal settlement.
    lock_admission_ledger().promote_to_inflight(
        *peer_id,
        bolt11_payment_hash.clone(),
        admission_msat,
    );

    // Ensure the polled details carry the payment hash we guarded on: some
    // backends return an empty hash on the dispatch response even though the
    // BOLT11 hash is authoritative.
    let details = if details.payment_hash.is_empty() {
        PaymentDetails {
            payment_hash: bolt11_payment_hash.clone(),
            ..details
        }
    } else {
        details
    };

    if details.payment_hash != bolt11_payment_hash
        || details.amount_msat != admission_msat
        || details.direction != PaymentDirection::Outgoing
    {
        return Err(ApiError::PaymentUnresolved(
            "admission backend returned mismatched payment details".into(),
        ));
    }
    let settled = await_admission_settlement(state, peer_id, updates, details).await?;
    if settled.payment_hash != bolt11_payment_hash
        || settled.amount_msat != admission_msat
        || settled.direction != PaymentDirection::Outgoing
    {
        return Err(ApiError::PaymentUnresolved(
            "admission settlement identity mismatch".into(),
        ));
    }
    if let Some(operation) = &charge.operation { operation.admission_settled(&settled).await?; }
    debit.record_payment(&peer_id.to_hex(), &settled);
    charge.settled_msat = admission_msat;
    deliver_settled_admission(state, peer_id, settled).await
}

/// Per-compose invariants shared by every room member's fan-out future.
///
/// These values are identical for all members of a single room compose, so we
/// bundle them once instead of threading each through the per-member helper.
struct RoomFanoutCtx<'a> {
    debit: &'a Debit,
    readmission: &'a Readmission,
    sender: NodeId,
    room_recipient: Recipient,
    plaintext: &'a str,
    references: &'a [MessageId],
    kind: u16,
}

/// Result of fanning a room message out to a single member.
///
/// Produced by [`compose_room_member`] for each reachable member. The shared,
/// order-sensitive bookkeeping (which member's envelope becomes the canonical
/// `message_id`, the single WebSocket broadcast) is reconciled by the caller
/// *after* the bounded-concurrency fan-out completes, so individual member
/// futures never touch shared state and can run in parallel safely.
struct RoomMemberOutcome {
    envelope: Option<konsensus_core::UkmEnvelope>,
    receipt: MemberPaymentOutcome,
    delivered: bool,
}

impl RoomMemberOutcome {
    fn stopped(member: NodeId, status: &'static str, amount: u64, reason: String) -> Self {
        Self { envelope: None, delivered: false, receipt: MemberPaymentOutcome {
            recipient: member.to_hex(), status, amount_msat: amount, message_id: None, reason: Some(reason),
        } }
    }
}

/// Compose, pay, encrypt, store, and deliver a room message for **one** member.
///
/// This is the per-member body of the room fan-out, extracted so it can be run
/// under a bounded-concurrency limiter. Payment semantics are unchanged: every
/// member is independently gated (Principle 2) — each gets its own E2EE
/// ciphertext, its own Lightning payment proof, and its own signed envelope.
///
/// Always reports this member's payment outcome. The caller has already
/// excluded self and checked every price against the confirmed room budget.
/// A settled payment remains settled even when proof or storage fails.
async fn compose_room_member(
    state: &AppState,
    ctx: &RoomFanoutCtx<'_>,
    member: NodeId,
    price_msat: u64,
) -> RoomMemberOutcome {

    // Encrypt via Double Ratchet for this specific member.
    let ratchet_msg = match state.session_manager.encrypt(&member, ctx.plaintext.as_bytes()).await {
        Ok(msg) => msg,
        Err(e) => {
            tracing::warn!(
                peer = %member,
                error = %e,
                "skipping room member: E2EE session not established"
            );
            return RoomMemberOutcome::stopped(member, "refused", 0, "E2EE session unavailable; nothing paid".into());
        }
    };
    let ciphertext = ratchet_message_to_bytes(&ratchet_msg);

    // Create payment proof — requests invoice from recipient's wallet (Principle 2).
    // Preserve refused vs unresolved payment state for every member.
    let mut admission = FirstContactCharge::default();
    let (payment_hash, preimage_bytes, amount_msat) =
        match create_metered_payment_proof(state, price_msat, &member, ctx.debit, ctx.readmission, Some(ctx.kind), &mut admission).await.map_err(|error| admission.error(error)) {
            Ok(proof) => proof,
            Err(e) => {
                tracing::warn!(
                    peer = %member,
                    error = %e,
                    "skipping room member: payment proof unavailable (offline?)"
                );
                state.audit_log.membrane().outbound_refused(&e, Some(&Recipient::Node(member)), Some(ctx.kind), None);
                return match e {
                    ApiError::PaymentUnresolved(_) if admission.readmission_blocks_message => {
                        ctx.debit.settled(&member.to_hex(), admission.settled_msat.saturating_sub(admission.readmission_msat));
                        RoomMemberOutcome::stopped(member, "unknown", 0, "Admission outcome unresolved; message was not dispatched; do not retry".into())
                    },
                    ApiError::PaymentUnresolved(_) => RoomMemberOutcome::stopped(member, "unknown", price_msat, "Payment outcome unresolved; do not retry".into()),
                    ApiError::PaymentProofUnavailable { amount_msat, reason } => RoomMemberOutcome::stopped(member, "settled", amount_msat.saturating_sub(admission.readmission_msat), reason),
                    _ => RoomMemberOutcome::stopped(member, "refused", 0, "Payment was not dispatched or was confirmed failed".into()),
                };
            }
        };

    let proof = konsensus_core::PaymentProof::new(payment_hash, preimage_bytes, amount_msat);
    let amount_msat = amount_msat.saturating_add(admission.settled_msat.saturating_sub(admission.readmission_msat));

    // Build and sign envelope.
    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        ctx.kind,
        ctx.sender,
        ctx.room_recipient,
        ciphertext,
        proof,
    )
    .references(ctx.references.to_vec())
    .build();

    let sig = state.identity.sign(&envelope.signable_bytes());
    envelope.signature = konsensus_core::Signature::from_ed25519(&sig);

    // Store.
    if let Err(e) = state.storage.store_message(&envelope).await {
        tracing::warn!(peer = %member, error = %e, "failed to store room message");
        return RoomMemberOutcome::stopped(member, "settled", amount_msat, "Payment settled but message storage failed".into());
    }

    // Cache plaintext (encrypted at rest) for API retrieval.
    if let Some(ref cipher) = state.plaintext_cipher {
        match cipher.encrypt(ctx.plaintext.as_bytes()) {
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

    if let Err(e) = state.storage.prepare_delivery(&envelope.id, &member).await {
        return RoomMemberOutcome::stopped(member, "settled", amount_msat, format!("Cannot persist delivery: {e}"));
    }
    // Deliver or queue — try sending directly to avoid TOCTOU race.
    {
        let mut ts = state.send_timestamps.lock().await;
        if ts.len() < MAX_SEND_TIMESTAMPS {
            ts.insert(envelope.id, std::time::Instant::now());
        }
    }
    let delivered = state.transport.send(&member, &envelope).await.is_ok();

    RoomMemberOutcome {
        receipt: MemberPaymentOutcome { recipient: member.to_hex(), status: "settled", amount_msat,
            message_id: Some(envelope.id.to_hex()), reason: None },
        envelope: Some(envelope), delivered,
    }
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
    auth: MeteredSpend,
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
    if req.is_room && crate::calls::is_call_kind(req.kind) {
        return Err(ApiError::BadRequest("calls are 1:1; a room cannot be called".into()).with_reason("call_room"));
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
        if req.operation_id.is_some() {
            return Err(ApiError::BadRequest("operation_id for rooms requires per-member operations (slice 4)".into()));
        }
        // ── Room compose: encrypt + pay + deliver to each member individually ──
        let room_id = konsensus_core::RoomId::parse(&req.recipient)
            .map_err(|e| ApiError::BadRequest(format!("invalid room ID: {e}")))?;
        let room_recipient = Recipient::Room(room_id);

        // DBH2 / ROOM-FANOUT-STREAM: get_room_members() is now UNBOUNDED (the old
        // LIMIT 10000 was a silent-truncation fail-open). This compose path is the
        // heavier fan-out — it encrypts (Double Ratchet) AND requests a Lightning
        // invoice per member in the loop below — so collecting the full member set
        // into a single Vec and iterating is the worst-case memory/latency cliff on a
        // very large room. Tracked follow-up ROOM-FANOUT-STREAM (TASK_QUEUE.md, Track
        // DBH) replaces this collect-then-send with chunked/streamed per-member
        // delivery + backpressure. Bounded by present mesh size until then.
        let members = state
            .storage
            .get_room_members(&room_id)
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))?;

        if members.is_empty() {
            return Err(ApiError::BadRequest("room has no members".into()));
        }

        // Bounded fan-out guard (HARD-12 / ROOM-FANOUT-STREAM interim).
        //
        // Room compose performs one payment + encrypt + deliver per member. A
        // single request to an oversized room would amplify into an unbounded
        // number of Lightning operations and a multi-minute synchronous HTTP
        // request. Reject with explicit back-pressure rather than processing it.
        if members.len() > MAX_ROOM_FANOUT_MEMBERS {
            state.audit_log.record(
                "room_compose_rejected_too_large",
                &sender.to_hex(),
                Some(serde_json::json!({
                    "kind": req.kind,
                    "room_id": req.recipient,
                    "member_count": members.len(),
                    "max_members": MAX_ROOM_FANOUT_MEMBERS,
                })),
            );
            return Err(ApiError::BadRequest(format!(
                "room too large for synchronous fan-out: {} members (max {MAX_ROOM_FANOUT_MEMBERS}) — \
                 split the room or wait for streamed room delivery",
                members.len()
            )));
        }

        let current_block_height = if !state.lightning.money_ready().await { 0 } else { match state.chain.get_block_height().await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, "failed to get block height for room compose, using fallback 0");
                0
            }
        }};

        let mut prices = Vec::new();
        for member in members.iter().filter(|m| *m != state.identity.node_id()) {
            prices.push((*member, quoted_price(&state, member, req.kind, current_block_height).await?));
        }
        let debit_prices = prices.iter().map(|(peer, price)|
            super::caps::all_in(&state, *price, req.max_routing_fee_msat).map(|total| (*peer, total))
        ).collect::<Result<Vec<_>, _>>()?;
        let max_routing_fee_msat = debit_prices.iter().zip(&prices)
            .try_fold(0u64, |sum, ((_, total), (_, principal))| sum.checked_add(total - principal))
            .ok_or_else(|| ApiError::PriceCapExceeded("room routing fee total overflow".into()))?;
        super::caps::check_room(&debit_prices, req.max_total_msat, req.max_recipient_msat.as_ref()).map_err(|e| e.with_routing_fee(max_routing_fee_msat))?;
        // G1: the whole fan-out is one call against a budget grant, debited
        // before any member's invoice is requested.
        let debit = auth.debit(
            &state,
            debit_prices
                .iter()
                .map(|(member, price)| Charge {
                    recipient: member.to_hex(),
                    amount_msat: *price,
                })
                .collect(),
        ).map_err(|e| e.with_routing_fee(max_routing_fee_msat))?.with_fee_limit(req.max_routing_fee_msat);

        // Fan out to members with bounded parallelism. Each member future is
        // fully independent (its own payment proof + envelope — Principle 2 is
        // unchanged) and touches no shared state; we keep the original index so
        // the canonical `message_id` and the single WS broadcast stay
        // deterministic regardless of completion order.
        use futures::stream::StreamExt;
        // Rooms keep fail-closed capped re-admission (Some(0)) until a
        // member-scoped remaining budget exists — refuse before any quote.
        let readmission = Readmission::for_cap(
            if req.max_total_msat.is_some() || req.max_recipient_msat.is_some() {
                Some(0)
            } else {
                None
            },
        );
        let ctx = RoomFanoutCtx {
            debit: &debit,
            readmission: &readmission,
            sender,
            room_recipient,
            plaintext: req.plaintext.as_str(),
            references: &references,
            kind: req.kind,
        };
        let mut outcomes: Vec<(usize, RoomMemberOutcome)> = futures::stream::iter(
            prices.into_iter().enumerate(),
        )
        .map(|(idx, (member, price))| {
            let state = &state;
            let ctx = &ctx;
            async move {
                let result = compose_room_member(state, ctx, member, price).await;
                (idx, result)
            }
        })
        .buffer_unordered(MAX_ROOM_FANOUT_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;

        // Restore deterministic ordering: the canonical message + WS broadcast
        // is the lowest-indexed member that succeeded, matching the old
        // first-success-wins behaviour.
        outcomes.sort_by_key(|(idx, _)| *idx);

        // Resolve each member's reservation from its terminal outcome. An
        // Unknown message payments keep their price reserved. If only a separate
        // admission was dispatched, compose_room_member already released this debit.
        for (_idx, outcome) in &outcomes {
            let r = &outcome.receipt;
            match r.status {
                "settled" => debit.settled(&r.recipient, r.amount_msat),
                "refused" => debit.released(&r.recipient),
                _ => {}
            }
        }

        let mut any_delivered = false;
        let mut total_amount_msat: u64 = 0;
        let mut first_message_id: Option<String> = None;

        for (_idx, outcome) in &outcomes {
            total_amount_msat = total_amount_msat.saturating_add(outcome.receipt.amount_msat);
            any_delivered |= outcome.delivered;

            if let Some(envelope) = outcome.envelope.as_ref().filter(|_| first_message_id.is_none()) {
                first_message_id = Some(envelope.id.to_hex());

                // Broadcast to WS once (with plaintext — we composed this message).
                if let Err(e) = state.ws_broadcast.send(Arc::new(crate::state::WsMessage {
                    envelope: envelope.clone(),
                    plaintext: Some(req.plaintext.clone()),
                })) {
                    tracing::debug!(
                        error = %e,
                        "no WebSocket clients connected for room compose broadcast"
                    );
                }
            }
        }

        // Even when every member is refused/unknown, return every outcome.
        let message_id = first_message_id.unwrap_or_default();

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
            operation_id: None, state: "untracked".into(), accepted: false, payment_hash: None, retry_allowed: false,
            max_routing_fee_msat: max_routing_fee_msat.saturating_add(readmission.fee_ceiling_msat()),
            member_outcomes: Some(outcomes.into_iter().map(|(_, o)| o.receipt).collect()),
            message_id,
            delivered: any_delivered,
            amount_msat: total_amount_msat,
            readmission_msat: readmission.paid_msat(),
        }))
    } else {
        super::operations::compose(auth, state, req, references).await
    }
}

pub(super) async fn compose_peer(
    auth: MeteredSpend, state: Arc<AppState>, req: ComposeRequest,
    references: Vec<MessageId>, operation: super::operations::Operation,
) -> Result<Json<ComposeResponse>, ApiError> {
    let sender = *state.identity.node_id();
        // ── Peer compose: existing single-recipient path ──
        let peer_id = NodeId::from_hex(&req.recipient)
            .map_err(|e| ApiError::BadRequest(format!("invalid recipient: {e}")))?;
        // Calls: a reused call id, or an answer/ICE/hangup for no live call,
        // is refused here, before any quote or payment.
        if crate::calls::is_call_kind(req.kind) {
            crate::calls::admit_outgoing(&peer_id, req.kind, &req.plaintext)?;
        }
        let _admission_guard = acquire_peer_admission_lock(&peer_id).await.ok_or_else(||
            ApiError::Internal("too many concurrent peer sends".into()))?;
        reconcile_admission_budget(&state, &peer_id, None).await?;
        let mut admission = FirstContactCharge { operation: Some(operation.clone()), ..Default::default() };
        let recipient = Recipient::Node(peer_id);

        let height = if state.lightning.money_ready().await { state.chain.get_block_height().await.unwrap_or(0) } else { 0 };
        let mut price_msat = quoted_price(&state, &peer_id, req.kind, height).await?;
        // A call offer pays the callee's own call price, asked of it just now.
        if req.kind == konsensus_core::kind::KIND_CALL_INVITE {
            price_msat = super::caps::payable(crate::calls::peer_call_price(&state, &peer_id).await?);
        }
        let mut cap = req.max_total_msat;
        if let Some(per) = &req.max_recipient_msat {
            let recipient_cap = *per.get(&peer_id.to_hex()).ok_or_else(|| ApiError::PriceCapExceeded("recipient cap missing".into()))?;
            cap = Some(cap.map_or(recipient_cap, |total| total.min(recipient_cap)));
        }
        let first_contact = !state.session_manager.has_session(&peer_id).await;
        // G1 × F1 (#85): an aggregate cap alone never lets a budget pay a
        // stranger. A paired caller also needs the owner's one-time
        // confirmation for exactly this recipient (a first-contact grant,
        // consumed here), which bounds the cap. The owner's own key is not
        // metered (the #80 caps still apply).
        let confirmation = if first_contact { auth.take_first_contact(&state, &peer_id.to_hex())? } else { None };
        if let Some(confirmed) = &confirmation {
            cap = Some(cap.map_or(confirmed.max_total_msat, |asked| asked.min(confirmed.max_total_msat)));
        }
        if !first_contact {
            super::caps::check_payment(&state, price_msat, req.max_routing_fee_msat, cap)?;
        } else if cap.is_none() {
            auth.refuse_unpriced("first contact requires an aggregate cap")?;
        }

        // Reject budget limits before advancing the ratchet or requesting an invoice.
        let peer_key = peer_id.to_hex();
        let debit = auth.debit_operation(&state, vec![Charge {
            recipient: peer_key.clone(),
            amount_msat: if first_contact { cap.unwrap_or(ADMISSION_MAX_MSAT) } else { super::caps::all_in(&state, price_msat, req.max_routing_fee_msat)? },
        }], confirmation, cap, &operation)
            .map_err(|e| e.with_routing_fee(state.lightning.routing_fee_policy().ceiling(price_msat, req.max_routing_fee_msat)))?
            .with_fee_limit(req.max_routing_fee_msat);
        let debit = debit.with_operation(operation.clone());
        if let Err(error) = operation.attach_debit(&debit).await {
            // No payment/invoice future has been polled under this debit.
            debit.released(&peer_key);
            return Err(error);
        }
        let result = async {

        // Encrypt via Double Ratchet.
        //
        // For an already-sessioned/whitelisted/privileged peer this succeeds on
        // the first call and the path is byte-identical to before. The ONLY new
        // behaviour is for a `price_open` STRANGER: the target withholds its X3DH
        // prekey until we pay our way in, so `encrypt` fails with no session. In
        // that specific case we run the sender-side first-contact admission
        // (settled recipient-priced admission invoice + signed admission
        // envelope → the target's gate → promote-on-paid → prekey released →
        // session), then retry the encrypt once. Retries after a settled
        // payment are idempotent (AdmissionLedger): they re-send the paid
        // proof, never pay a second time.
        let ratchet_msg = match state
            .session_manager
            .encrypt(&peer_id, req.plaintext.as_bytes())
            .await
        {
            Ok(msg) => msg,
            Err(e) => {
                // Only bootstrap admission for the no-session, connected-stranger
                // case. If a session already exists (some other encrypt failure)
                // or the peer is offline, surface the original error unchanged.
                //
                // If a previously live session disappeared, fail closed: that
                // call reserved only the message, not an admission aggregate.
                let no_session = !state.session_manager.has_session(&peer_id).await;
                let connected = state.transport.is_connected(&peer_id).await;
                if !(first_contact && no_session && connected) {
                    return Err(ApiError::BadRequest(format!(
                        "E2EE encryption failed (session may not be established): {e}"
                    )));
                }

                tracing::info!(
                    peer = %peer_id,
                    "no E2EE session with connected peer — attempting paid first-contact admission"
                );
                if let Err(error) = first_contact_admission(&state, &peer_id, req.kind, cap, &mut admission, &debit, None).await {
                    if matches!(lock_admission_ledger().prior_admission(&peer_id, Instant::now()), PriorAdmission::None) {
                        admission.reserved_msat = 0;
                    }
                    return Err(error);
                }
                reconcile_admission_budget(&state, &peer_id, debit.reservation().as_ref()).await?;
                if let Some(target_price) = admission.message_price {
                    price_msat = target_price;
                } else {
                    // A resumed admission may belong to another kind. Never
                    // substitute this node's own price for the target's quote.
                    price_msat = state.peer_prices.get_fresh_discounted_peer_price(
                        &peer_id, req.kind, height, MAX_PRICE_AGE,
                    ).await.map(super::caps::payable).ok_or_else(|| ApiError::Lightning(
                        "prior admission is paid, but the target quote for this kind is unknown".into()
                    ))?;
                }

                // Poll for the session the target establishes after promotion via
                // the existing prekey/self-heal path, until we can SEND on it. An
                // X3DH acceptor holds a session before it has a sending chain: that
                // needs the initiator's RatchetInit. Waiting on `has_session` alone
                // raced it (payer-higher order: we are the acceptor) and failed the
                // encrypt below after a consumed admission.
                let mut waited = Duration::ZERO;
                while !state.session_manager.can_send(&peer_id).await {
                    if waited >= ADMISSION_SESSION_TIMEOUT {
                        return Err(ApiError::Internal(format!(
                            "first-contact admission payment for {peer_id} settled and a signed \
                             proof is held, but the E2EE session did not establish within {}s \
                             (the proof envelope may still need re-delivery) — retry the message \
                             shortly; the retry is guarded by admission idempotence and will NOT \
                             pay admission again",
                            ADMISSION_SESSION_TIMEOUT.as_secs()
                        )));
                    }
                    tokio::time::sleep(ADMISSION_SESSION_POLL_INTERVAL).await;
                    waited += ADMISSION_SESSION_POLL_INTERVAL;
                }

                // Session is up — retry the encrypt exactly once.
                state
                    .session_manager
                    .encrypt(&peer_id, req.plaintext.as_bytes())
                    .await
                    .map_err(|e| {
                        ApiError::BadRequest(format!(
                            "E2EE encryption failed after admission (session may not be \
                             established): {e}"
                        ))
                    })?
            }
        };
        super::caps::first_contact_total(
            super::caps::all_in(&state, admission.settled_msat, req.max_routing_fee_msat)?,
            super::caps::all_in(&state, price_msat, req.max_routing_fee_msat)?, cap)?;
        let ciphertext = ratchet_message_to_bytes(&ratchet_msg);

        let draft = konsensus_core::UkmEnvelopeBuilder::new(
            req.kind, sender, recipient, ciphertext,
            konsensus_core::PaymentProof::new([0; 32], [0; 32], 0),
        ).references(references).build();
        operation.draft(draft, price_msat,
            debit.fee_limit(&state, price_msat).saturating_add(admission.fee_ceiling_msat),
            admission.settled_msat.saturating_sub(admission.readmission_msat)).await?;

        // Create payment proof — requests invoice from recipient's wallet (Principle 2).
        if let Some(mut attempt) = super::admission_journal::load(&state, &peer_id)? {
            if attempt.original_reservation == debit.reservation() {
                attempt.message_may_have_dispatched = true;
                super::admission_journal::save(&state, &peer_id, &attempt)?;
            }
        }
        admission.current_dispatch = true;
        // Quoted capped re-admission is priced only for single-recipient chat.
        // Other kinds keep Some(0) refuse-before-quote when a cap is present.
        let readmission_cap = if req.kind == konsensus_core::kind::KIND_CHAT {
            cap
        } else {
            cap.map(|_| 0)
        };
        let readmission = Readmission { lock_held: true, ..Readmission::for_cap(readmission_cap) };
        let (payment_hash, preimage_bytes, amount_msat) =
            create_metered_payment_proof(&state, price_msat, &peer_id, &debit, &readmission, Some(req.kind), &mut admission).await?;
        admission.message_settled = amount_msat;
        let proof =
            konsensus_core::PaymentProof::new(payment_hash, preimage_bytes, amount_msat);

        let envelope = operation.settled_envelope(proof, debit.fee_limit(&state, amount_msat).saturating_add(admission.fee_ceiling_msat)).await?;

        if let Some(expected) = konsensus_core::expected_reply_kind(req.kind) {
            let Recipient::Node(peer) = envelope.recipient else {
                return Err(ApiError::BadRequest("web request recipient must be a node".into()));
            };
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            state
                .storage
                .record_outgoing_web_request(
                    &envelope.payment_proof.payment_hash,
                    konsensus_core::OutstandingWebRequest {
                        request_id: envelope.id,
                        peer,
                        expected_reply_kind: expected,
                        expires_at_ms: now_ms.saturating_add(konsensus_core::OUTSTANDING_TTL_MS),
                    },
                )
                .await
                .map_err(|e| ApiError::Internal(format!("record web request: {e}")))?;
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
                        tracing::warn!(msg_id = %envelope.id, error = %e, "failed to cache compose plaintext");
                    }
                }
                Err(e) => {
                    tracing::warn!(msg_id = %envelope.id, error = %e, "failed to encrypt compose plaintext");
                }
            }
        }

        // The paid transaction already queued this envelope. Do not insert again:
        // a concurrent flusher may already have received its ACK.
        // Deliver via transport; keep queued until ACK.
        // Try sending directly — avoids TOCTOU race where peer disconnects
        // between an is_connected check and the actual send.
        {
            let mut ts = state.send_timestamps.lock().await;
            if ts.len() < MAX_SEND_TIMESTAMPS {
                ts.insert(envelope.id, std::time::Instant::now());
            }
        }
        let delivered = operation.resend().await?;

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
            operation_id: Some(operation.id.clone()), state: "sent".into(), accepted: false,
            payment_hash: Some(hex::encode(payment_hash)), retry_allowed: true,
            max_routing_fee_msat: debit.fee_limit(&state, admission.message_authorized.unwrap_or(price_msat)).saturating_add(admission.fee_ceiling_msat),
            member_outcomes: None,
            message_id: envelope.id.to_hex(),
            delivered,
            amount_msat: admission.settled_msat.saturating_sub(admission.readmission_msat) + amount_msat,
            readmission_msat: readmission.paid_msat(),
        }))
        }.await;
        let result = result.map_err(|error| admission.error(error));
        match &result {
            Ok(response) => debit.settled(&peer_key, response.0.amount_msat),
            Err(ApiError::PaymentUnresolved(_)) if admission.readmission_blocks_message => debit.settled(&peer_key, admission.settled_msat.saturating_sub(admission.readmission_msat)),
            Err(ApiError::PaymentUnresolved(_)) if admission.current_dispatch => {},
            Err(ApiError::PaymentProofUnavailable { amount_msat, .. }) => debit.settled(&peer_key, amount_msat.saturating_sub(admission.readmission_msat)),
            Err(_) => debit.released(&peer_key),
        }
        let message_msat = admission.message_authorized.unwrap_or(price_msat);
        result.map_err(|e| e.with_routing_fee(debit.fee_limit(&state, message_msat).saturating_add(admission.fee_ceiling_msat)))
}

#[cfg(test)]
mod admission_invoice_clock_tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;
    /// Attempt issued at NOW, live until NOW + EXPIRY_SECS.
    const ATTEMPT_END: u64 = NOW + 60;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn check(created: u64, relative_expiry: u64, now: u64, attempt_end: Option<u64>) -> bool {
        admission_invoice_time_valid(
            secs(created),
            Some(secs(created.saturating_add(relative_expiry))),
            relative_expiry,
            secs(now),
            attempt_end,
        )
    }

    #[test]
    fn timestamp_up_to_skew_is_accepted() {
        // Invoice stamped +5 s still fits the attempt (short relative TTL).
        assert!(check(NOW + 5, 50, NOW, Some(ATTEMPT_END)));
        assert!(check(NOW, 60, NOW, Some(ATTEMPT_END)));
    }

    #[test]
    fn timestamp_beyond_skew_is_refused() {
        assert!(!check(NOW + 6, 50, NOW, Some(ATTEMPT_END)));
    }

    #[test]
    fn expired_invoice_is_refused() {
        // Created in the past; relative TTL already elapsed on the payer clock.
        assert!(!check(NOW - 60, 60, NOW, Some(ATTEMPT_END)));
        // Exactly at expiry is expired (`now >= expiry`).
        assert!(!check(NOW - 30, 30, NOW, Some(ATTEMPT_END)));
    }

    #[test]
    fn expiry_beyond_attempt_end_is_refused() {
        // Fresh 60 s TTL issued one second into the attempt overruns the end.
        assert!(!check(NOW + 1, 60, NOW + 1, Some(ATTEMPT_END)));
    }

    #[test]
    fn skew_does_not_extend_attempt_window() {
        // +5 s timestamp with a 60 s TTL would expire at NOW+65 > attempt end.
        assert!(!check(NOW + 5, 60, NOW, Some(ATTEMPT_END)));
    }

    #[test]
    fn skew_does_not_keep_expired_invoice_payable() {
        let created = NOW - 10;
        let relative = 10; // expired exactly at NOW
        assert!(!admission_invoice_time_valid(
            secs(created),
            Some(secs(created + relative)),
            relative,
            secs(NOW),
            Some(ATTEMPT_END),
        ));
        // Even if created looks slightly in the future of a *wrong* now, expiry
        // vs the injected payer clock stays strict.
        assert!(!admission_invoice_time_valid(
            secs(NOW + 1),
            Some(secs(NOW)), // already expired at payer now
            60,
            secs(NOW),
            Some(ATTEMPT_END),
        ));
    }

    #[test]
    fn relative_ttl_above_cap_is_refused() {
        assert!(!check(NOW, 61, NOW, Some(ATTEMPT_END)));
    }

    #[test]
    fn missing_attempt_end_is_refused() {
        assert!(!check(NOW, 50, NOW, None));
    }
}

#[cfg(test)]
mod settlement_tests {
    use super::*;
    use konsensus_core::traits::lightning::PaymentDirection;
    use konsensus_lightning::MockLightningProvider;

    /// The core (c)-gap fix: an in-flight keysend that settles a few polls later
    /// must resolve to a settled proof — not error out. This is the historic
    /// "compose 502s while the sats actually move and the message never
    /// delivers" bug, reproduced against the mock's deferred-settlement knob.
    #[tokio::test(start_paused = true)]
    async fn await_settlement_polls_inflight_to_settled() {
        let mock = Arc::new(MockLightningProvider::new());
        mock.defer_next_keysend_settlement(2).await;
        let lightning: Arc<dyn LightningProvider> = mock;

        let pubkey = format!("02{}", "ab".repeat(32)); // 66 hex chars
        let initial = lightning.keysend(&pubkey, 5_000, None).await.unwrap();
        assert_eq!(initial.status, PaymentStatus::InFlight);
        assert!(!initial.payment_hash.is_empty());
        assert!(initial.preimage.is_none());

        let settled = await_settlement(
            &lightning,
            SettlementUpdates::subscribe(lightning.as_ref()),
            initial,
            "keysend",
        )
        .await
        .expect("in-flight payment should poll through to Settled");
        assert_eq!(settled.status, PaymentStatus::Settled);
        assert!(
            settled.preimage.is_some(),
            "settled payment must reveal the preimage"
        );
    }

    /// An already-settled payment passes through immediately.
    #[tokio::test(start_paused = true)]
    async fn await_settlement_passes_through_settled() {
        let lightning: Arc<dyn LightningProvider> = Arc::new(MockLightningProvider::new());
        let pubkey = format!("03{}", "cd".repeat(32));
        let settled = lightning.keysend(&pubkey, 5_000, None).await.unwrap();
        assert_eq!(settled.status, PaymentStatus::Settled);

        let out = await_settlement(
            &lightning,
            SettlementUpdates::subscribe(lightning.as_ref()),
            settled,
            "keysend",
        )
        .await
        .unwrap();
        assert_eq!(out.status, PaymentStatus::Settled);
    }

    /// Double-pay guard: a dispatched-but-untrackable payment (no hash) must
    /// surface an error, NOT silently allow the caller to re-dispatch via another
    /// path. The error names the double-pay risk.
    #[tokio::test(start_paused = true)]
    async fn await_settlement_refuses_untrackable_inflight() {
        let lightning: Arc<dyn LightningProvider> = Arc::new(MockLightningProvider::new());
        let inflight = PaymentDetails {
            payment_hash: String::new(),
            preimage: None,
            amount_msat: 1_000,
            status: PaymentStatus::InFlight,
            direction: PaymentDirection::Outgoing,
            timestamp: 0,
            memo: None,
            fee_msat: None,
        };
        let err = await_settlement(
            &lightning,
            SettlementUpdates::subscribe(lightning.as_ref()),
            inflight,
            "keysend",
        )
        .await
        .expect_err("untrackable in-flight payment must error, not settle");
        assert!(
            format!("{err}").contains("double payment"),
            "expected the double-pay guard message, got: {err}"
        );
    }

    /// REAL-LATENCY: without update hints the first re-checks come fast
    /// (50, 100, 200 ms ...), not after a fixed 2 s.
    #[tokio::test(start_paused = true)]
    async fn await_settlement_backs_off_from_a_fast_first_recheck() {
        let mock = Arc::new(MockLightningProvider::new());
        mock.defer_next_keysend_settlement(2).await;
        let lightning: Arc<dyn LightningProvider> = mock;
        let initial = lightning
            .keysend(&format!("02{}", "ef".repeat(32)), 5_000, None)
            .await
            .unwrap();
        let started = tokio::time::Instant::now();
        let settled = await_settlement(
            &lightning,
            SettlementUpdates::subscribe(lightning.as_ref()),
            initial,
            "keysend",
        )
        .await
        .unwrap();
        assert_eq!(settled.status, PaymentStatus::Settled);
        assert_eq!(
            started.elapsed(),
            Duration::from_millis(350),
            "third poll at 50+100+200 ms"
        );
    }

    async fn deferred_keysend(mock: &MockLightningProvider, polls: u32) -> PaymentDetails {
        mock.defer_next_keysend_settlement(polls).await;
        let initial = mock
            .keysend(&format!("02{}", "aa".repeat(32)), 5_000, None)
            .await
            .unwrap();
        assert_eq!(initial.status, PaymentStatus::InFlight);
        initial
    }

    async fn let_run() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    /// REAL-LATENCY: the backend's hint for this payment ends the wait at
    /// once; a hint for another payment does not.
    #[tokio::test(start_paused = true)]
    async fn await_settlement_wakes_on_this_payments_update_hint() {
        let mock = Arc::new(MockLightningProvider::new());
        let initial = deferred_keysend(&mock, 0).await;
        let hash = initial.payment_hash.clone();
        let lightning: Arc<dyn LightningProvider> = mock.clone();
        let started = tokio::time::Instant::now();
        let waiting = tokio::spawn(async move {
            await_settlement(
                &lightning,
                SettlementUpdates::subscribe(lightning.as_ref()),
                initial,
                "keysend",
            )
            .await
        });
        let_run().await;
        mock.hint_outgoing(&"bb".repeat(32));
        let_run().await;
        // The next status read would report Settled: no read happened.
        assert!(
            !waiting.is_finished(),
            "another payment's hint is not a reason to poll"
        );

        mock.hint_outgoing(&hash);
        let settled = waiting.await.unwrap().unwrap();
        assert_eq!(settled.status, PaymentStatus::Settled);
        assert!(
            started.elapsed() < PAYMENT_POLL_INITIAL,
            "woken by the hint, not the timer"
        );
    }

    // Match node.rs -> AppState.lightning: RecoveringLightning wraps the backend;
    // CircuitBreakerLightning is only on the separate inbound gate verifier.
    async fn recovered_lightning(
        mock: Arc<MockLightningProvider>,
        initially_offline: bool,
    ) -> Arc<dyn LightningProvider> {
        let mut offline = initially_offline;
        let lightning = Arc::new(
            konsensus_lightning::RecoveringLightning::new(
                move || {
                    let unavailable = std::mem::take(&mut offline);
                    let backend = mock.clone();
                    async move {
                        if unavailable {
                            Err(LightningError::ChainSourceUnavailable {
                                network: "bitcoin".into(),
                                service: "localhost".into(),
                                attempts: 1,
                                elapsed_ms: 0,
                                cause: "unavailable".into(),
                            })
                        } else {
                            Ok(backend as Arc<dyn LightningProvider>)
                        }
                    }
                },
                Default::default(),
            )
            .await
            .unwrap(),
        );
        assert!(lightning.outgoing_payment_updates().is_none());
        let_run().await;
        if initially_offline {
            assert!(!lightning.money_ready().await);
            assert!(lightning.outgoing_payment_updates().is_none());
            tokio::time::advance(Duration::from_secs(5)).await;
            let_run().await;
        }
        assert!(lightning.money_ready().await);
        lightning
    }

    /// Missing wrapper delegation or lazy subscription loses the dispatch hint.
    /// Also exercise subscription to the live backend after offline recovery.
    #[tokio::test(start_paused = true)]
    async fn production_wrapper_dispatch_hint_wakes_settlement() {
        for initially_offline in [false, true] {
            let mock = Arc::new(MockLightningProvider::new());
            let lightning = recovered_lightning(mock.clone(), initially_offline).await;
            let updates = SettlementUpdates::subscribe(lightning.as_ref());
            mock.defer_next_keysend_settlement(0).await;
            mock.hint_during_next_deferred_keysend();
            let initial = lightning
                .keysend(&format!("02{}", "aa".repeat(32)), 5_000, None)
                .await
                .unwrap();
            assert_eq!(initial.status, PaymentStatus::InFlight);
            let started = tokio::time::Instant::now();
            let settled = await_settlement(&lightning, updates, initial, "keysend")
                .await
                .unwrap();
            assert_eq!(settled.status, PaymentStatus::Settled);
            assert_eq!(started.elapsed(), Duration::ZERO, "hint must bypass timer");
            lightning.shutdown().await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn production_wrapper_hint_is_not_proof_or_a_timeout_extension() {
        let mock = Arc::new(MockLightningProvider::new());
        let lightning = recovered_lightning(mock.clone(), false).await;
        for polls in [1, u32::MAX] {
            let updates = SettlementUpdates::subscribe(lightning.as_ref());
            mock.defer_next_keysend_settlement(polls).await;
            mock.hint_during_next_deferred_keysend();
            let initial = lightning
                .keysend(&format!("02{}", "aa".repeat(32)), 5_000, None)
                .await
                .unwrap();
            let started = tokio::time::Instant::now();
            let result = await_settlement(&lightning, updates, initial, "keysend").await;
            if polls == 1 {
                assert_eq!(result.unwrap().status, PaymentStatus::Settled);
                assert_eq!(started.elapsed(), Duration::from_millis(100));
            } else {
                assert!(matches!(result, Err(ApiError::PaymentUnresolved(_))));
                assert!(started.elapsed() >= PAYMENT_SETTLE_TIMEOUT);
                assert!(started.elapsed() < PAYMENT_SETTLE_TIMEOUT + PAYMENT_POLL_INTERVAL);
            }
        }
        lightning.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn production_wrapper_retired_backend_stream_closes_and_poll_uses_timer() {
        use futures::{FutureExt, StreamExt};

        let old_backend = Arc::new(MockLightningProvider::new());
        let old_lightning = recovered_lightning(old_backend.clone(), false).await;
        let updates = SettlementUpdates::subscribe(old_lightning.as_ref());
        let mut closure_probe = old_lightning
            .outgoing_payment_updates()
            .expect("ready wrapper must forward hints");
        old_lightning.shutdown().await.unwrap();
        assert!(old_lightning.outgoing_payment_updates().is_none());
        drop(old_backend);
        assert_eq!(
            closure_probe.next().now_or_never(),
            Some(None),
            "subscription must not keep the retired backend alive"
        );

        // Recovery never rebuilds an initialized backend. Simulate a node restart
        // with a new wrapper; an old subscription must not prevent timer polling.
        let mock = Arc::new(MockLightningProvider::new());
        let lightning = recovered_lightning(mock.clone(), true).await;
        mock.defer_next_keysend_settlement(2).await;
        let initial = lightning
            .keysend(&format!("02{}", "aa".repeat(32)), 5_000, None)
            .await
            .unwrap();
        let started = tokio::time::Instant::now();
        let settled = await_settlement(&lightning, updates, initial, "keysend")
            .await
            .unwrap();
        assert_eq!(settled.status, PaymentStatus::Settled);
        assert_eq!(started.elapsed(), Duration::from_millis(350));
        lightning.shutdown().await.unwrap();
    }

    /// #108 review: a backend may settle and emit its terminal hint while the
    /// dispatch call is still returning its earlier `InFlight` snapshot. The
    /// subscription is taken before dispatch, so that hint is buffered and the
    /// first status re-read happens at once, not after the 50 ms timer.
    #[tokio::test(start_paused = true)]
    async fn hint_fired_during_dispatch_is_not_lost() {
        let mock = Arc::new(MockLightningProvider::new());
        let lightning: Arc<dyn LightningProvider> = mock.clone();

        // As the dispatch paths do: subscribe, then dispatch.
        let updates = SettlementUpdates::subscribe(lightning.as_ref());
        mock.hint_during_next_deferred_keysend();
        let initial = deferred_keysend(&mock, 0).await;
        let started = tokio::time::Instant::now();
        let settled = await_settlement(&lightning, updates, initial, "keysend")
            .await
            .unwrap();
        assert_eq!(settled.status, PaymentStatus::Settled);
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "woken by the buffered hint"
        );

        // Control: the pre-fix order (subscribe after dispatch) misses the same
        // hint and sits out the fallback timer, so this test detects the bug.
        mock.hint_during_next_deferred_keysend();
        let initial = deferred_keysend(&mock, 0).await;
        let started = tokio::time::Instant::now();
        let late = SettlementUpdates::subscribe(lightning.as_ref());
        await_settlement(&lightning, late, initial, "keysend")
            .await
            .unwrap();
        assert_eq!(started.elapsed(), PAYMENT_POLL_INITIAL);
    }

    /// The early hint only wakes the poll: a payment still in flight at the
    /// re-read keeps waiting on the timer; nothing is decided from the hint.
    #[tokio::test(start_paused = true)]
    async fn hint_fired_during_dispatch_is_not_settlement() {
        let mock = Arc::new(MockLightningProvider::new());
        let lightning: Arc<dyn LightningProvider> = mock.clone();
        let updates = SettlementUpdates::subscribe(lightning.as_ref());
        mock.hint_during_next_deferred_keysend();
        let initial = deferred_keysend(&mock, 1).await;
        let started = tokio::time::Instant::now();
        let settled = await_settlement(&lightning, updates, initial, "keysend")
            .await
            .unwrap();
        assert_eq!(settled.status, PaymentStatus::Settled);
        assert_eq!(
            started.elapsed(),
            PAYMENT_POLL_INITIAL * 2,
            "second re-read on the timer"
        );
    }

    /// A hint is never proof: it only triggers a status re-read, and a payment
    /// still reported in flight keeps waiting (and times out unresolved).
    #[tokio::test(start_paused = true)]
    async fn await_settlement_update_hint_is_not_settlement() {
        let mock = Arc::new(MockLightningProvider::new());
        let initial = deferred_keysend(&mock, 1).await;
        let hash = initial.payment_hash.clone();
        let lightning: Arc<dyn LightningProvider> = mock.clone();
        let waiting = tokio::spawn(async move {
            await_settlement(
                &lightning,
                SettlementUpdates::subscribe(lightning.as_ref()),
                initial,
                "keysend",
            )
            .await
        });
        let_run().await;
        mock.hint_outgoing(&hash);
        let_run().await;
        assert!(
            !waiting.is_finished(),
            "the re-read said in flight: keep waiting"
        );
        mock.hint_outgoing(&hash);
        let started = tokio::time::Instant::now();
        assert_eq!(
            waiting.await.unwrap().unwrap().status,
            PaymentStatus::Settled
        );
        assert!(started.elapsed() < PAYMENT_POLL_INITIAL);

        let initial = deferred_keysend(&mock, u32::MAX).await;
        let hash = initial.payment_hash.clone();
        let lightning: Arc<dyn LightningProvider> = mock.clone();
        let started = tokio::time::Instant::now();
        let waiting = tokio::spawn(async move {
            await_settlement(
                &lightning,
                SettlementUpdates::subscribe(lightning.as_ref()),
                initial,
                "keysend",
            )
            .await
        });
        let_run().await;
        mock.hint_outgoing(&hash);
        let err = waiting.await.unwrap().expect_err("never settled");
        assert!(matches!(err, ApiError::PaymentUnresolved(_)), "{err}");
        assert!(started.elapsed() >= PAYMENT_SETTLE_TIMEOUT);
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use konsensus_core::identity::NodeIdentity;

    #[test]
    fn reconnect_during_compose_retains_prior_spend_and_unresolved_attempt() {
        let mut charge = FirstContactCharge { reserved_msat: 7000, settled_msat: 7000, ..Default::default() };
        charge.include_attempt(FirstContactCharge { reserved_msat: 7000, current_dispatch: true, ..Default::default() });
        assert_eq!(charge.settled_msat, 7000);
        assert!(matches!(charge.error(ApiError::Lightning("pending second admission".into())), ApiError::PaymentUnresolved(_)));
        let mut settled = FirstContactCharge { reserved_msat: 7000, settled_msat: 7000, ..Default::default() };
        settled.include_attempt(FirstContactCharge { reserved_msat: 7000, settled_msat: 7000, ..Default::default() });
        assert!(matches!(settled.error(ApiError::Internal("message failed".into())), ApiError::PaymentProofUnavailable { amount_msat: 14000, .. }));
    }

    /// The admission amount must come from OUR pricing (peer-announced if fresh,
    /// else our own engine), floored at the invoice minimum — never a caller
    /// value. A stranger must not be able to name their own admission price.
    #[test]
    fn admission_amount_re_derived_from_pricing_not_caller() {
        // Peer announced a fresh price → use it (above the floor).
        assert_eq!(derive_admission_msat(Some(5_000), 2_000), 5_000);
        // No fresh peer price → fall back to our own engine.
        assert_eq!(derive_admission_msat(None, 2_000), 2_000);
        // Sub-minimum peer price is floored up to the invoice minimum.
        assert_eq!(
            derive_admission_msat(Some(1), 0),
            MIN_INVOICE_AMOUNT_MSAT,
            "sub-sat prices must round up to the invoice minimum"
        );
        // Sub-minimum own price is also floored.
        assert_eq!(derive_admission_msat(None, 0), MIN_INVOICE_AMOUNT_MSAT);
        // The derived amount is always at least the floor.
        for peer in [None, Some(0u64), Some(1), Some(999), Some(1_000), Some(50_000)] {
            for own in [0u64, 1, 999, 1_000, 7_777] {
                assert!(
                    derive_admission_msat(peer, own) >= MIN_INVOICE_AMOUNT_MSAT,
                    "admission amount must never drop below MIN_INVOICE_AMOUNT_MSAT"
                );
            }
        }
    }

    /// The admission invoice-request purpose MUST equal the reserved string the
    /// target recognizes for an unprivileged peer (`session_handler`), or the
    /// target drops the request and the stranger can never be admitted.
    #[test]
    fn admission_invoice_purpose_matches_reserved() {
        assert_eq!(
            ADMISSION_INVOICE_PURPOSE, "konsensus:admission",
            "must match session_handler::ADMISSION_INVOICE_PURPOSE byte-for-byte"
        );
    }

    /// Build a signed admission envelope the way `first_contact_admission` does
    /// (valid proof, non-empty sentinel) for ledger tests.
    fn test_admission_envelope(
        sender_identity: &NodeIdentity,
        peer: NodeId,
    ) -> konsensus_core::UkmEnvelope {
        let preimage = [7u8; 32];
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        let proof = konsensus_core::PaymentProof::new(hash, preimage, 1_000);
        let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
            konsensus_core::kind::KIND_CHAT,
            *sender_identity.node_id(),
            Recipient::Node(peer),
            ADMISSION_ENVELOPE_MARKER.to_vec(),
            proof,
        )
        .build();
        let sig = sender_identity.sign(&envelope.signable_bytes());
        envelope.signature = konsensus_core::Signature::from_ed25519(&sig);
        envelope
    }

    /// THE idempotence invariant (the #324 pre-merge fix): once an admission
    /// payment to a peer has settled, a retry within the TTL must never lead
    /// back to the paid path — with the proof envelope it re-sends
    /// (`SettledWithProof`), without it it refuses to double-pay
    /// (`SettledNoProof`) — and only TTL expiry re-opens paying (`None`).
    #[test]
    fn admission_ledger_settled_retry_never_pays_twice() {
        let (_m, identity) = NodeIdentity::generate().expect("generate identity");
        let (_m2, peer_identity) = NodeIdentity::generate().expect("generate identity");
        let peer = *peer_identity.node_id();

        let mut ledger = AdmissionLedger::default();
        let base = Instant::now();

        // Before any payment: paying is required.
        assert_eq!(
            ledger.prior_admission(&peer, base),
            PriorAdmission::None,
            "no settlement recorded — the paid path must run"
        );

        // Settlement recorded (money moved) but envelope not yet built: a retry
        // in this window must NOT pay again even though there is no proof yet.
        ledger.record_settled(peer, base);
        assert_eq!(
            ledger.prior_admission(&peer, base + Duration::from_secs(1)),
            PriorAdmission::SettledNoProof,
            "settled-without-proof must suppress a second payment"
        );

        // Envelope attached: a retry re-sends the paid proof.
        let envelope = test_admission_envelope(&identity, peer);
        ledger.attach_envelope(&peer, envelope.clone());
        match ledger.prior_admission(&peer, base + Duration::from_secs(2)) {
            PriorAdmission::SettledWithProof(resend) => {
                assert_eq!(
                    *resend, envelope,
                    "retry must re-send the EXACT paid envelope (same proof, same signature)"
                );
            }
            other => panic!("expected SettledWithProof, got {other:?}"),
        }

        // Just inside the TTL boundary: still suppressed.
        assert_ne!(
            ledger.prior_admission(
                &peer,
                base + ADMISSION_SETTLED_TTL - Duration::from_secs(1)
            ),
            PriorAdmission::None,
            "within the TTL a retry must never re-pay"
        );

        // Past the TTL: suppression expires — a genuinely new admission (e.g.
        // after the target lost our promotion) is allowed to pay again.
        assert_eq!(
            ledger.prior_admission(&peer, base + ADMISSION_SETTLED_TTL),
            PriorAdmission::None,
            "TTL expiry must re-open the paid path"
        );

        // A different peer is unaffected by this peer's settlement.
        let (_m3, other_identity) = NodeIdentity::generate().expect("generate identity");
        assert_eq!(
            ledger.prior_admission(other_identity.node_id(), base + Duration::from_secs(1)),
            PriorAdmission::None,
            "idempotence is per-peer"
        );
    }

    /// The CONCURRENT double-pay guard (2026-07-06 review blocking finding):
    /// simultaneous admission attempts to the same peer must serialize on the
    /// per-peer lock so exactly ONE pays and the rest observe the recorded
    /// settlement and take the resend path.
    ///
    /// Exercises the exact production sequence from `first_contact_admission`
    /// (acquire per-peer lock → read ledger → pay-if-None → record settlement)
    /// against the REAL `acquire_peer_admission_lock` + global ledger — the full
    /// function needs a live `AppState`, so the paid path is a counter with a
    /// simulated settlement latency inside the critical section (the latency is
    /// what makes the unguarded version reliably double-pay).
    /// Serializes the two tests that mutate the PROCESS-GLOBAL admission lock
    /// map to their capacity, so parallel execution cannot flake them (or other
    /// `acquire_peer_admission_lock` callers) by filling the shared map.
    static ADMISSION_GLOBAL_TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // Holds a std mutex across await purely to serialize global-state tests on
    // the single-threaded test runtime — not a production pattern.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn admission_concurrent_callers_pay_exactly_once() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let _serial = ADMISSION_GLOBAL_TEST_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        let (_m, peer_identity) = NodeIdentity::generate().expect("generate identity");
        let peer = *peer_identity.node_id(); // fresh id — no cross-test collisions
        let payments = Arc::new(AtomicU32::new(0));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let payments = Arc::clone(&payments);
            handles.push(tokio::spawn(async move {
                // 0a. serialize per peer (the fix under test)
                let _guard = acquire_peer_admission_lock(&peer).await.expect("admission lock available in test");
                // 0b. race-free ledger read under the lock (bind first: the
                // std MutexGuard must drop before the await below, same as
                // production)
                let prior = lock_admission_ledger().prior_admission(&peer, Instant::now());
                match prior {
                    PriorAdmission::None => {
                        // paid path: settlement takes real time — without the
                        // per-peer lock every concurrent task lands here
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        payments.fetch_add(1, Ordering::SeqCst);
                        lock_admission_ledger().record_settled(peer, Instant::now());
                    }
                    // resume / probe / resend / refuse paths: no payment
                    PriorAdmission::InFlight { .. }
                    | PriorAdmission::DispatchUnknown { .. }
                    | PriorAdmission::SettledWithProof(_)
                    | PriorAdmission::SettledNoProof => {}
                }
            }));
        }
        for handle in handles {
            handle.await.expect("admission task panicked");
        }

        assert_eq!(
            payments.load(Ordering::SeqCst),
            1,
            "concurrent admission attempts to one peer must pay EXACTLY once"
        );
    }

    /// A CONFIRMED in-flight admission payment (no TTL) suppresses a fresh invoice
    /// and is only cleared by a terminal failed/expired result on the same hash.
    #[test]
    fn admission_ledger_inflight_retry_never_pays_fresh_invoice() {
        let (_m, peer_identity) = NodeIdentity::generate().expect("generate identity");
        let peer = *peer_identity.node_id();
        let mut ledger = AdmissionLedger::default();
        let base = Instant::now();
        let payment_hash = "ab".repeat(32);

        ledger.promote_to_inflight(peer, payment_hash.clone(), 7_000);
        // No TTL: still in-flight far past ADMISSION_SETTLED_TTL.
        assert_eq!(
            ledger.prior_admission(&peer, base + ADMISSION_SETTLED_TTL + Duration::from_secs(60)),
            PriorAdmission::InFlight {
                payment_hash: payment_hash.clone(),
                amount_msat: 7_000,
            },
            "a confirmed in-flight payment has no TTL and must keep suppressing a fresh invoice"
        );

        // Wrong hash must not clear the guard.
        ledger.clear_tracked(&peer, &"cd".repeat(32));
        assert!(matches!(
            ledger.prior_admission(&peer, base + Duration::from_secs(2)),
            PriorAdmission::InFlight { .. }
        ));

        // A terminal failed/expired result for the same hash re-opens the paid path.
        ledger.clear_tracked(&peer, &payment_hash);
        assert_eq!(
            ledger.prior_admission(&peer, base + Duration::from_secs(3)),
            PriorAdmission::None,
            "terminal failed/expired in-flight payment may reopen admission"
        );
    }

    /// A DispatchUnknown guard (pay_invoice may or may not have dispatched):
    /// carries the hash so a retry can PROBE it, suppresses a fresh invoice within
    /// without expiry. A missing backend record cannot prove non-dispatch.
    #[test]
    fn admission_ledger_dispatch_unknown_never_expires_without_evidence() {
        let (_m, peer_identity) = NodeIdentity::generate().expect("generate identity");
        let peer = *peer_identity.node_id();
        let mut ledger = AdmissionLedger::default();
        let base = Instant::now();
        let payment_hash = "ab".repeat(32);

        ledger.record_dispatch_unknown(peer, payment_hash.clone(), 11_000, base);
        assert_eq!(
            ledger.prior_admission(&peer, base + Duration::from_secs(1)),
            PriorAdmission::DispatchUnknown {
                payment_hash: payment_hash.clone(),
                amount_msat: 11_000,
            },
            "DispatchUnknown must carry the hash so a retry can probe it (not re-pay)"
        );

        ledger.prune(base + ADMISSION_SETTLED_TTL * 100);
        assert!(matches!(ledger.prior_admission(&peer, base + ADMISSION_SETTLED_TTL * 100), PriorAdmission::DispatchUnknown { .. }),
            "elapsed time is not proof of non-dispatch");

        // A confirmed probe promotes it to a durable (no-TTL) InFlight guard.
        ledger.record_dispatch_unknown(peer, payment_hash.clone(), 11_000, base);
        ledger.promote_to_inflight(peer, payment_hash.clone(), 11_000);
        assert_eq!(
            ledger.prior_admission(&peer, base + ADMISSION_SETTLED_TTL + Duration::from_secs(1)),
            PriorAdmission::InFlight {
                payment_hash,
                amount_msat: 11_000,
            },
            "a probe-confirmed payment promotes to no-TTL InFlight (must not silently expire)"
        );
    }

    /// Atomic reservation: `try_reserve` inserts a capacity hold under the lock,
    /// `release_reservation` frees ONLY a bare reservation, and a committed
    /// dispatch/settled guard is never released by it.
    #[test]
    fn admission_reservation_is_atomic_and_release_only_frees_reservations() {
        let (_m, peer_identity) = NodeIdentity::generate().expect("generate identity");
        let peer = *peer_identity.node_id();
        let mut ledger = AdmissionLedger::default();
        let base = Instant::now();

        assert!(ledger.try_reserve(peer, base), "fresh peer reserves");
        assert!(
            ledger.try_reserve(peer, base),
            "same peer's own reservation is reusable (retry adds no slot)"
        );
        assert_eq!(ledger.entries.len(), 1, "no double-count for one peer");
        // A bare reservation reads as None (retry re-drives the paid path).
        assert_eq!(ledger.prior_admission(&peer, base), PriorAdmission::None);

        // release frees the reservation.
        ledger.release_reservation(&peer);
        assert_eq!(ledger.entries.len(), 0, "release frees a bare reservation");

        // But release must NOT free a committed guard.
        ledger.record_settled(peer, base);
        ledger.release_reservation(&peer);
        assert_ne!(
            ledger.prior_admission(&peer, base + Duration::from_secs(1)),
            PriorAdmission::None,
            "release_reservation must never drop a settled guard"
        );
    }

    /// Regression for Codex review finding after ae36b69: first attempt
    /// dispatches a trackable admission payment, settlement polling times out,
    /// and a second compose retries. The second attempt must observe the
    /// in-flight ledger state and poll/resume the original payment hash instead
    /// of paying another invoice.
    #[allow(clippy::await_holding_lock)] // test-only global-state serialization guard
    #[tokio::test]
    async fn admission_inflight_timeout_retry_does_not_pay_again() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let _serial = ADMISSION_GLOBAL_TEST_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        let (_m, peer_identity) = NodeIdentity::generate().expect("generate identity");
        let peer = *peer_identity.node_id();
        let payments = Arc::new(AtomicU32::new(0));
        let resumes = Arc::new(AtomicU32::new(0));
        let payment_hash = "ef".repeat(32);

        // First call: exact critical sequence up to the timeout boundary
        // (lock -> ledger read -> pay -> record in-flight). It then returns an
        // error to the caller without settlement, leaving the in-flight guard in
        // place for retry.
        {
            let _guard = acquire_peer_admission_lock(&peer).await.expect("admission lock available in test");
            assert_eq!(
                lock_admission_ledger().prior_admission(&peer, Instant::now()),
                PriorAdmission::None
            );
            payments.fetch_add(1, Ordering::SeqCst);
            // Production flow: record DispatchUnknown pre-pay, then promote to
            // confirmed InFlight once pay_invoice returns Ok.
            lock_admission_ledger().record_dispatch_unknown(
                peer,
                payment_hash.clone(),
                9_000,
                Instant::now(),
            );
            lock_admission_ledger().promote_to_inflight(peer, payment_hash.clone(), 9_000);
        }

        // Retry: under the same real per-peer lock, the ledger read must take
        // the in-flight resume path, not the paid path.
        {
            let _guard = acquire_peer_admission_lock(&peer).await.expect("admission lock available in test");
            match lock_admission_ledger().prior_admission(&peer, Instant::now()) {
                PriorAdmission::InFlight {
                    payment_hash: seen,
                    amount_msat,
                } => {
                    assert_eq!(seen, payment_hash);
                    assert_eq!(amount_msat, 9_000);
                    resumes.fetch_add(1, Ordering::SeqCst);
                }
                other => panic!("expected in-flight retry guard, got {other:?}"),
            }
        }

        assert_eq!(
            payments.load(Ordering::SeqCst),
            1,
            "retry after in-flight timeout must not pay a second invoice"
        );
        assert_eq!(
            resumes.load(Ordering::SeqCst),
            1,
            "retry must resume the original payment hash"
        );

        // Cleanup the process-global ledger so this test's in-flight guard does
        // not live for the rest of the test binary.
        lock_admission_ledger().clear_tracked(&peer, &payment_hash);
    }

    /// `prune` drops ONLY expired entries and never a live one (review finding
    /// #1, 2026-07-07). A fresh settled guard cannot be evicted and repaid inside
    /// its TTL, even under ledger pressure.
    #[test]
    fn admission_ledger_prune_never_evicts_a_live_guard() {
        let mut ledger = AdmissionLedger::default();
        let base = Instant::now();

        // A fresh settled guard for the peer we care about.
        let (_m, peer_identity) = NodeIdentity::generate().expect("generate identity");
        let peer = *peer_identity.node_id();
        ledger.record_settled(peer, base);

        // Fill far past the cap with OTHER fresh settled guards (synthetic ids).
        for i in 0..(ADMISSION_LEDGER_MAX_ENTRIES + 50) {
            let mut raw = [0u8; 32];
            raw[..8].copy_from_slice(&(i as u64).to_le_bytes());
            raw[8] = 0xff; // avoid colliding with `peer`
            ledger.record_settled(NodeId::from_bytes(raw), base + Duration::from_millis(i as u64));
        }

        // Prune at a time still inside TTL: our fresh guard MUST survive.
        ledger.prune(base + Duration::from_secs(1));
        assert_ne!(
            ledger.prior_admission(&peer, base + Duration::from_secs(1)),
            PriorAdmission::None,
            "a non-expired settled guard must NEVER be evicted (would allow repay inside TTL)"
        );

        // Expired entries ARE dropped.
        let (_m2, expired_identity) = NodeIdentity::generate().expect("generate identity");
        let expired_peer = *expired_identity.node_id();
        ledger.record_settled(expired_peer, base);
        ledger.prune(base + ADMISSION_SETTLED_TTL + Duration::from_secs(1));
        assert!(
            !ledger.entries.contains_key(&expired_peer),
            "expired settlement must be pruned"
        );
    }

    /// Capacity is enforced at admission time, fail-closed, not by silent
    /// eviction (review finding #1/#2, 2026-07-07). When the ledger is full of
    /// LIVE guards, a NEW peer is refused while an EXISTING guarded peer's retry
    /// still proceeds. Covers all-settled, all-in-flight, and all-untrackable.
    #[test]
    fn admission_ledger_capacity_fails_closed_for_new_peer() {
        for mode in ["settled", "inflight", "dispatch_unknown", "reserved"] {
            let mut ledger = AdmissionLedger::default();
            let base = Instant::now();

            // Fill exactly to the cap with live guards of this kind.
            let mut first_peer = None;
            for i in 0..ADMISSION_LEDGER_MAX_ENTRIES {
                let mut raw = [0u8; 32];
                raw[..8].copy_from_slice(&(i as u64).to_le_bytes());
                let p = NodeId::from_bytes(raw);
                if i == 0 {
                    first_peer = Some(p);
                }
                match mode {
                    "settled" => ledger.record_settled(p, base),
                    "inflight" => ledger.promote_to_inflight(p, format!("{i:064x}"), 1_000),
                    "dispatch_unknown" => {
                        ledger.record_dispatch_unknown(p, format!("{i:064x}"), 1_000, base)
                    }
                    // A bare reservation also holds a slot (atomic reserve).
                    _ => assert!(ledger.try_reserve(p, base)),
                }
            }
            assert_eq!(ledger.entries.len(), ADMISSION_LEDGER_MAX_ENTRIES);

            // A brand-new peer's reserve is refused (fail closed — no live guard evicted).
            let (_m, new_identity) = NodeIdentity::generate().expect("generate identity");
            assert!(
                !ledger.try_reserve(*new_identity.node_id(), base + Duration::from_secs(1)),
                "mode {mode}: a new peer must be refused when the ledger is full of live guards"
            );

            // An already-guarded peer may still proceed (its retry reuses its slot).
            assert!(
                ledger.try_reserve(first_peer.unwrap(), base + Duration::from_secs(1)),
                "mode {mode}: an existing-guard peer must not be blocked by capacity"
            );
            assert_eq!(
                ledger.entries.len(),
                ADMISSION_LEDGER_MAX_ENTRIES,
                "mode {mode}: a refused new peer + a reused existing peer must not grow the ledger"
            );
        }
    }

    /// The per-peer admission lock map is hard-capped: once it is full of ACTIVE
    /// (held) locks, a new distinct peer is refused rather than growing the map
    /// past the cap (review finding #3, 2026-07-07). An existing peer always gets
    /// its lock so a retry can serialize.
    #[allow(clippy::await_holding_lock)] // test-only global-state serialization guard
    #[tokio::test]
    async fn admission_lock_map_hard_caps_distinct_peers() {
        let _serial = ADMISSION_GLOBAL_TEST_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        // Hold a lock for every slot so idle-pruning frees nothing.
        let mut held = Vec::new();
        let mut first_peer = None;
        for i in 0..ADMISSION_LEDGER_MAX_ENTRIES {
            let mut raw = [0u8; 32];
            raw[..8].copy_from_slice(&(i as u64).to_le_bytes());
            raw[8] = 0xa5; // distinct namespace from other tests
            let p = NodeId::from_bytes(raw);
            if i == 0 {
                first_peer = Some(p);
            }
            held.push(
                acquire_peer_admission_lock(&p)
                    .await
                    .expect("initial fill acquires"),
            );
        }

        // New distinct peer (different namespace): refused (map full of held locks).
        let mut new_raw = [0u8; 32];
        new_raw[8] = 0x5a;
        assert!(
            acquire_peer_admission_lock(&NodeId::from_bytes(new_raw))
                .await
                .is_none(),
            "a new distinct peer must be refused when the lock map is full of active locks"
        );

        // Existing peer: its (already-held) lock is still handed out so a retry
        // can serialize behind the holder — acquire in a task since it will block.
        let existing = first_peer.unwrap();
        let waiter = tokio::spawn(async move { acquire_peer_admission_lock(&existing).await });
        // Give the waiter a moment to prove it did not return None immediately.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !waiter.is_finished(),
            "an existing peer's retry must wait on its held lock, not be refused"
        );
        drop(held); // release all held locks; the waiter now acquires
        assert!(
            waiter.await.expect("waiter task").is_some(),
            "existing-peer retry must acquire once the holder releases"
        );
    }

    /// The target sets the admission price (recipient-priced); we accept it only
    /// strictly-positive and up to the cap. Rejecting 0 stops a free-admission
    /// invoice; the cap bounds a malicious target draining a stranger.
    #[test]
    fn admission_price_cap_bounds_target_invoice() {
        assert!(!admission_price_acceptable(0), "zero-price admission is a free lane — reject");
        assert!(admission_price_acceptable(1), "any positive price is acceptable");
        assert!(admission_price_acceptable(MIN_INVOICE_AMOUNT_MSAT));
        assert!(admission_price_acceptable(ADMISSION_MAX_MSAT), "cap boundary is inclusive");
        assert!(
            !admission_price_acceptable(ADMISSION_MAX_MSAT + 1),
            "above the cap a malicious invoice must be refused"
        );
    }

    /// The signed admission envelope has the admission-floor kind, is addressed to
    /// the target peer, and carries a valid signature over its signable bytes —
    /// exactly the outer envelope the receiver gate-checks before any decrypt.
    #[test]
    fn admission_envelope_shape_and_signature() {
        let (_m, sender_id) = NodeIdentity::generate().expect("generate identity");
        let sender = *sender_id.node_id();
        let (_m2, peer_id) = NodeIdentity::generate().expect("generate identity");
        let peer = *peer_id.node_id();

        // Same construction as first_contact_admission: non-empty sentinel
        // payload + a VALID payment proof (hash == SHA-256(preimage)) so the
        // envelope survives the receiver's `validate()` gate-first step.
        let preimage = [1u8; 32];
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        let proof = konsensus_core::PaymentProof::new(hash, preimage, 1_000);
        let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
            konsensus_core::kind::KIND_CHAT,
            sender,
            Recipient::Node(peer),
            ADMISSION_ENVELOPE_MARKER.to_vec(),
            proof,
        )
        .build();
        let sig = sender_id.sign(&envelope.signable_bytes());
        envelope.signature = konsensus_core::Signature::from_ed25519(&sig);

        assert_eq!(
            envelope.kind,
            konsensus_core::kind::KIND_CHAT,
            "admission envelope must use the KIND_CHAT admission floor"
        );
        assert_eq!(
            envelope.recipient,
            Recipient::Node(peer),
            "admission envelope must be addressed to the target peer"
        );
        assert!(
            !envelope.ciphertext.is_empty(),
            "admission payload MUST be non-empty or the receiver's validate() \
             drops it before promote-on-paid (the-fool CRITICAL, 2026-07-01)"
        );
        // The receive-side gate's FIRST step is validate(); it must accept the
        // admission envelope (non-empty ciphertext + matching id + valid
        // preimage). This is the regression guard for the empty-ciphertext bug.
        assert!(
            envelope.validate().is_ok(),
            "admission envelope must pass UkmEnvelope::validate() (receiver's \
             first gate step) — else the stranger pays and is never admitted"
        );
        // The signature is non-zero and verifies against the sender's key over
        // the exact signable bytes.
        assert_ne!(
            envelope.signature.as_bytes(),
            &[0u8; 64],
            "signature must be filled in, not the zero placeholder"
        );
        sender_id
            .verify(&envelope.signable_bytes(), &sig)
            .expect("admission envelope signature must verify against the sender key");
    }
}

#[cfg(test)]
mod reviewer_same_connection_ttl {
    use super::*;

    #[test]
    fn same_connection_settlement_still_prevents_repayment_after_ttl() {
        let peer = NodeId::from_bytes([173; 32]);
        let connected_at = Instant::now();
        let settled_at = connected_at + Duration::from_secs(1);
        let mut ledger = AdmissionLedger::default();
        ledger.record_settled(peer, settled_at);
        ledger.set_delivered(&peer, true);
        assert_eq!(ledger.settled_coverage(
            &peer, Some(connected_at), false, settled_at + ADMISSION_SETTLED_TTL - Duration::from_secs(1)
        ), SettledCoverage::Covered);
        assert_eq!(ledger.settled_coverage(
            &peer, Some(connected_at), false, settled_at + ADMISSION_SETTLED_TTL
        ), SettledCoverage::Covered, "same connection must not reopen admission payment solely because 15 minutes passed");
    }

    /// Review P1 (#100): a proof that never went out is unspent. However the
    /// settlement time compares to the live connection, it is delivered, never
    /// paid for again; only a proof that went out on an earlier connection
    /// authorizes another admission.
    #[test]
    fn only_a_sent_proof_on_an_earlier_connection_authorizes_another_payment() {
        let peer = NodeId::from_bytes([174; 32]);
        let settled_at = Instant::now();
        let replacement = settled_at + Duration::from_secs(1);
        let mut ledger = AdmissionLedger::default();
        assert_eq!(ledger.settled_coverage(&peer, Some(replacement), true, replacement), SettledCoverage::Covered, "the live flag wins");
        assert_eq!(ledger.settled_coverage(&peer, Some(replacement), false, replacement), SettledCoverage::NoRecord);
        ledger.record_settled(peer, settled_at);
        assert_eq!(ledger.settled_coverage(&peer, Some(replacement), false, replacement), SettledCoverage::Unsent);
        assert!(ledger.entries.contains_key(&peer), "unsent proof evidence is kept");
        assert_eq!(ledger.settled_coverage(&peer, Some(replacement), true, replacement), SettledCoverage::Covered);
        ledger.set_delivered(&peer, true);
        assert_eq!(ledger.settled_coverage(&peer, Some(settled_at), false, replacement), SettledCoverage::Covered);
        assert_eq!(ledger.settled_coverage(&peer, Some(replacement), false, replacement), SettledCoverage::Consumed);
        assert_eq!(ledger.settled_coverage(&peer, Some(replacement), false, replacement), SettledCoverage::NoRecord);
    }
}
