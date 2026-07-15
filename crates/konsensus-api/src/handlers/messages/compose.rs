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
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use konsensus_core::traits::lightning::{
    LightningProvider, PaymentDetails, PaymentDirection, PaymentStatus,
};
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

/// Interval between settlement-status polls.
const PAYMENT_POLL_INTERVAL: Duration = Duration::from_secs(2);

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
async fn await_settlement(
    lightning: &Arc<dyn LightningProvider>,
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
        // path — that would risk paying twice. Surface as retryable.
        return Err(ApiError::Lightning(format!(
            "{method} dispatched but returned no payment hash to confirm settlement — \
             not retrying to avoid a double payment; the message can be re-sent once the wallet settles"
        )));
    }

    let mut waited = Duration::ZERO;
    loop {
        tokio::time::sleep(PAYMENT_POLL_INTERVAL).await;
        waited += PAYMENT_POLL_INTERVAL;

        let details = lightning
            .get_payment_status(&initial.payment_hash)
            .await
            .map_err(|e| {
                ApiError::Lightning(format!("{method}: failed to poll payment status: {e}"))
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
                if waited >= PAYMENT_SETTLE_TIMEOUT {
                    return Err(ApiError::Lightning(format!(
                        "{method} payment still in flight after {}s — not retrying to avoid a double payment",
                        PAYMENT_SETTLE_TIMEOUT.as_secs()
                    )));
                }
            }
        }
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
            Ok(KeysendOutcome::Settled(proof)) => return Ok(proof),
            Ok(KeysendOutcome::NotDispatched) => {
                tracing::warn!(
                    peer = %peer_id,
                    "keysend unavailable (not dispatched) — falling back to invoice-request flow"
                );
                // Safe to fall through: no HTLC was dispatched.
            }
            Err(e) => {
                // The keysend WAS dispatched but did not settle. Falling back to
                // the invoice flow here would risk paying the recipient twice for
                // one message, so surface the error instead of re-dispatching.
                tracing::warn!(
                    peer = %peer_id,
                    error = %e,
                    "keysend dispatched but did not settle — NOT falling back (double-pay guard)"
                );
                return Err(e);
            }
        }
    }

    // Invoice-request fallback (only reached when keysend was not dispatched).
    create_payment_proof_via_invoice(state, payment_amount_msat, peer_id).await
}

/// Attempt a keysend (spontaneous) payment to a peer's Lightning node.
///
/// * `Ok(KeysendOutcome::Settled(proof))` — the HTLC settled.
/// * `Ok(KeysendOutcome::NotDispatched)` — the `keysend` call failed before any
///   HTLC went out; the caller may safely fall back to the invoice flow.
/// * `Err(_)` — the keysend WAS dispatched but did not settle (failed, expired,
///   timed out, or untrackable). The caller must NOT fall back to another
///   payment path, or it risks paying the recipient twice.
async fn try_keysend(
    state: &AppState,
    ln_pubkey: &str,
    amount_msat: u64,
    peer_id: &NodeId,
) -> Result<KeysendOutcome, ApiError> {
    let details = match state
        .lightning
        .keysend(ln_pubkey, amount_msat, Some("konsensus message"))
        .await
    {
        Ok(details) => details,
        Err(e) => {
            // The send itself failed — no HTLC was dispatched, so it is safe to
            // fall back to the invoice flow without risking a double payment.
            tracing::warn!(peer = %peer_id, error = %e, "keysend not dispatched");
            return Ok(KeysendOutcome::NotDispatched);
        }
    };

    // Dispatched: from here we must not re-dispatch by another path. Poll the
    // in-flight payment to terminal settlement.
    let settled = await_settlement(&state.lightning, details, "keysend").await?;

    let preimage_hex = settled.preimage.ok_or_else(|| {
        ApiError::Lightning("keysend settled but no preimage returned".into())
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

    // Pay the recipient's invoice, then poll the in-flight payment to terminal
    // settlement (it commonly returns Pending/InFlight before the preimage is
    // known; treating that as failure dropped settling messages).
    let details = state
        .lightning
        .pay_invoice(&response.bolt11)
        .await
        .map_err(|e| ApiError::Lightning(format!("failed to pay recipient invoice: {e}")))?;

    let details = await_settlement(&state.lightning, details, "invoice payment").await?;

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

/// How long to wait for the target to promote us to privileged and complete the
/// X3DH handshake after a settled first-contact admission payment. The promotion
/// (`msg_handler.rs:257`) and the prekey/self-heal path that follows are async on
/// the target, so we poll our own session store rather than block a single RPC.
const ADMISSION_SESSION_TIMEOUT: Duration = Duration::from_secs(25);

/// Interval between session-establishment polls after a first-contact admission.
const ADMISSION_SESSION_POLL_INTERVAL: Duration = Duration::from_secs(1);

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
    /// if the backend knows it, or clear + reopen once the bounded TTL lets it.
    /// Never silently re-pays inside the window (review finding #1, 2026-07-07).
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

/// Record of one admission attempt to one peer.
#[derive(Debug, Clone)]
enum AdmissionRecord {
    /// Atomic capacity hold, taken under the ledger lock BEFORE the invoice
    /// round-trip so parallel distinct-peer admissions cannot overrun the cap
    /// (review finding #2, 2026-07-07). Released on pre-dispatch failure; replaced
    /// by `DispatchUnknown` once we pay. The short TTL backstops a panic leak.
    Reserved { started_at: Instant },
    /// Payment MAY be dispatched; carries the BOLT11 hash so a retry can probe it.
    /// Bounded TTL so a never-dispatched attempt cannot brick a peer forever.
    DispatchUnknown {
        started_at: Instant,
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
        /// The signed admission envelope, attached once built. Kept so a retry can
        /// re-deliver the PROOF without re-paying (heals settled-but-envelope-lost).
        envelope: Option<Box<konsensus_core::UkmEnvelope>>,
    },
}

/// Sender-side ledger of first-contact admission attempts.
///
/// This is the money-path idempotence guard for [`first_contact_admission`]:
/// one reserved/in-flight/settled admission per peer, no matter how many times
/// the caller retries. In-process only (an entry does not survive a node
/// restart): the worst case after a restart is one extra admission payment,
/// bounded by [`ADMISSION_MAX_MSAT`] — the same bound as any first contact.
/// Methods take `now` explicitly so TTL behaviour is unit-testable.
#[derive(Debug, Default)]
struct AdmissionLedger {
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
    /// `Reserved` hold). Carries the BOLT11 hash so a retry can probe it; bounded
    /// TTL so a never-dispatched attempt cannot brick the peer forever.
    fn record_dispatch_unknown(
        &mut self,
        peer: NodeId,
        payment_hash: String,
        amount_msat: u64,
        now: Instant,
    ) {
        self.entries.insert(
            peer,
            AdmissionRecord::DispatchUnknown {
                started_at: now,
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
                envelope: None,
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
                started_at,
                payment_hash,
                amount_msat,
            }) if now.saturating_duration_since(*started_at) < ADMISSION_SETTLED_TTL => {
                PriorAdmission::DispatchUnknown {
                    payment_hash: payment_hash.clone(),
                    amount_msat: *amount_msat,
                }
            }
            Some(AdmissionRecord::Settled {
                settled_at,
                envelope,
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
    /// double-pay); `Settled` and `DispatchUnknown` expire only after their bounded
    /// TTLs; `Reserved` expires after a short backstop TTL. Capacity is enforced at
    /// admission time by [`Self::try_reserve`], never by evicting a live guard.
    fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, e| match e {
            AdmissionRecord::InFlight { .. } => true,
            AdmissionRecord::Reserved { started_at } => {
                now.saturating_duration_since(*started_at) < ADMISSION_RESERVED_TTL
            }
            AdmissionRecord::DispatchUnknown { started_at, .. } => {
                now.saturating_duration_since(*started_at) < ADMISSION_SETTLED_TTL
            }
            AdmissionRecord::Settled { settled_at, .. } => {
                now.saturating_duration_since(*settled_at) < ADMISSION_SETTLED_TTL
            }
        });
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
async fn await_admission_settlement(
    state: &AppState,
    peer_id: &NodeId,
    initial: PaymentDetails,
) -> Result<PaymentDetails, ApiError> {
    match initial.status {
        PaymentStatus::Settled => return Ok(initial),
        PaymentStatus::Failed | PaymentStatus::Expired => {
            if !initial.payment_hash.is_empty() {
                lock_admission_ledger().clear_tracked(peer_id, &initial.payment_hash);
            }
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

    let mut waited = Duration::ZERO;
    loop {
        tokio::time::sleep(PAYMENT_POLL_INTERVAL).await;
        waited += PAYMENT_POLL_INTERVAL;

        let details = state
            .lightning
            .get_payment_status(&initial.payment_hash)
            .await
            .map_err(|e| {
                ApiError::Lightning(format!(
                    "admission invoice: failed to poll payment status: {e}"
                ))
            })?;

        match details.status {
            PaymentStatus::Settled => return Ok(details),
            PaymentStatus::Failed | PaymentStatus::Expired => {
                lock_admission_ledger().clear_tracked(peer_id, &initial.payment_hash);
                return Err(ApiError::Lightning(format!(
                    "admission invoice payment failed: {:?}",
                    details.status
                )));
            }
            PaymentStatus::Pending | PaymentStatus::InFlight => {
                if waited >= PAYMENT_SETTLE_TIMEOUT {
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

/// Record a settled admission, build its signed proof envelope, attach it to the
/// ledger, and deliver it. The settlement is recorded before proof construction
/// so any malformed-preimage/backend-contract error still suppresses re-pay.
async fn deliver_settled_admission(
    state: &AppState,
    peer_id: &NodeId,
    settled: PaymentDetails,
) -> Result<(), ApiError> {
    lock_admission_ledger().record_settled(*peer_id, Instant::now());

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

    state
        .transport
        .send(peer_id, &envelope)
        .await
        .map_err(|e| {
            ApiError::Internal(format!(
                "admission payment settled but delivering the admission envelope failed \
             (a retry will re-send the paid proof, not pay again): {e}"
            ))
        })?;

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
async fn first_contact_admission(state: &AppState, peer_id: &NodeId) -> Result<(), ApiError> {
    // 0a. Serialize per peer FIRST: without this, two concurrent composes to
    //     the same no-session peer both read `PriorAdmission::None` below and
    //     both pay (concurrent double-pay). Held for the whole attempt; every
    //     awaited step inside carries its own timeout, so the wait is bounded.
    //     Fails closed when at concurrent-admission capacity for a new peer.
    let _admission_guard = match acquire_peer_admission_lock(peer_id).await {
        Some(guard) => guard,
        None => {
            return Err(ApiError::Internal(
                "admission capacity reached: too many concurrent first-contact admissions to \
                 distinct peers — retry shortly"
                    .into(),
            ));
        }
    };

    // 0b. Idempotence guard (now race-free under the per-peer lock): if we
    //     already SETTLED an admission payment to this peer within the TTL, do
    //     not pay again — re-send the proof envelope (best-effort) and let the
    //     caller resume polling for the session. This is the fix for the
    //     post-settlement retry double-pay: session-poll timeout → compose
    //     error → user retries → without this guard the stranger pays full
    //     admission on every retry.
    let prior = lock_admission_ledger().prior_admission(peer_id, Instant::now());
    match prior {
        PriorAdmission::None => {} // fall through to the paid path below
        PriorAdmission::InFlight {
            payment_hash,
            amount_msat,
        } => {
            tracing::info!(
                peer = %peer_id,
                %payment_hash,
                "admission retry: resuming already-dispatched admission payment (no second invoice)"
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
            let settled = await_admission_settlement(state, peer_id, initial).await?;
            return deliver_settled_admission(state, peer_id, settled).await;
        }
        PriorAdmission::DispatchUnknown {
            payment_hash,
            amount_msat,
        } => {
            // A prior attempt may have dispatched this payment but never confirmed
            // it (pay_invoice errored). PROBE the backend before deciding — never
            // pay a fresh invoice while the first may still settle, and never brick
            // the peer permanently (review finding #1, 2026-07-07).
            tracing::info!(
                peer = %peer_id, %payment_hash,
                "admission retry: probing a possibly-dispatched admission payment"
            );
            match state.lightning.get_payment_status(&payment_hash).await {
                Ok(details) if details.status == PaymentStatus::Settled => {
                    lock_admission_ledger()
                        .promote_to_inflight(*peer_id, payment_hash.clone(), amount_msat);
                    let settled = await_admission_settlement(state, peer_id, details).await?;
                    return deliver_settled_admission(state, peer_id, settled).await;
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
                    lock_admission_ledger()
                        .promote_to_inflight(*peer_id, payment_hash.clone(), amount_msat);
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
                    let settled = await_admission_settlement(state, peer_id, initial).await?;
                    return deliver_settled_admission(state, peer_id, settled).await;
                }
                Ok(details) => {
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
                    // cannot confirm dispatch. Stay fail-closed within the bounded
                    // DispatchUnknown TTL (prune reopens the paid path after it)
                    // rather than risk a double payment.
                    return Err(ApiError::Lightning(format!(
                        "a possibly-dispatched admission payment to {peer_id} could not be \
                         confirmed with the backend; not paying a second invoice within the \
                         idempotence window ({}s) — retry shortly",
                        ADMISSION_SETTLED_TTL.as_secs()
                    )));
                }
            }
        }
        PriorAdmission::SettledWithProof(envelope) => {
            // Re-deliver the already-paid proof. If the target already consumed
            // this payment hash (envelope arrived the first time), its replay
            // table rejects the duplicate — harmless to us, and we are already
            // promoted there. If the first delivery was lost after settlement,
            // this re-send is exactly the heal that makes the payment count.
            if let Err(e) = state.transport.send(peer_id, &envelope).await {
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
                return Err(ApiError::Internal(format!(
                    "an already-paid admission proof for {peer_id} exists but re-delivering it \
                     failed ({e}) — no second payment was made; retry shortly"
                )));
            }
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
            return Err(ApiError::Lightning(format!(
                "a prior admission payment to {peer_id} settled but no payment proof is \
                 available (the Lightning backend returned a malformed preimage) — refusing \
                 to pay admission again; investigate the backend or retry after the \
                 idempotence window ({}s) expires",
                ADMISSION_SETTLED_TTL.as_secs()
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

    // 1. Request the reserved admission invoice. The requested amount is a hint
    //    only — the target re-prices from its own engine (recipient-priced).
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

    let request_id = uuid::Uuid::new_v4().to_string();
    let (tx, rx) = oneshot::channel::<InvoiceResponseData>();
    {
        let mut requests = state.invoice_requests.lock().await;
        if requests.len() >= MAX_PENDING_INVOICE_REQUESTS {
            return Err(ApiError::Internal(
                "Too many pending invoice requests — try again shortly".into(),
            ));
        }
        requests.insert(request_id.clone(), tx);
    }
    let frame = Frame::RequestInvoice {
        request_id: request_id.clone(),
        amount_msat: requested_msat,
        purpose: ADMISSION_INVOICE_PURPOSE.into(),
    };
    let frame_bytes = frame
        .to_bytes()
        .map_err(|e| ApiError::Internal(format!("frame serialization error: {e}")))?;
    if let Err(e) = state.transport.send_raw_frame(peer_id, &frame_bytes).await {
        state.invoice_requests.lock().await.remove(&request_id);
        return Err(ApiError::Internal(format!(
            "failed to send admission invoice request: {e}"
        )));
    }

    // 2. Await the target's repriced BOLT11.
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
        .map_err(|_| {
            ApiError::Lightning("target could not create an admission invoice".into())
        })?;

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

    // 4. Record a DispatchUnknown guard from the BOLT11 payment hash BEFORE
    //    dispatching, then pay. This closes the ambiguous-dispatch window (review
    //    finding #4) WITHOUT the permanent-brick hazard (review finding #1,
    //    2026-07-07): DispatchUnknown carries the hash so a retry can PROBE it, and
    //    it has a bounded TTL so a payment that never dispatched cannot block the
    //    peer forever. Recording it commits the capacity reservation (the slot is
    //    now a DispatchUnknown with its own lifecycle, no longer released on drop).
    let bolt11_payment_hash = hex::encode(invoice.payment_hash());
    lock_admission_ledger().record_dispatch_unknown(
        *peer_id,
        bolt11_payment_hash.clone(),
        admission_msat,
        Instant::now(),
    );
    reservation.committed = true;

    // Pay the invoice (its route hints reach the target over any topology).
    let details = state
        .lightning
        .pay_invoice(&response.bolt11)
        .await
        .map_err(|e| {
            // pay_invoice errored: leave the DispatchUnknown guard in place
            // (bounded TTL). A retry PROBES the hash — resumes if the backend
            // dispatched it, or clears + reopens if it did not.
            ApiError::Lightning(format!(
                "failed to pay admission invoice (a retry will probe this payment hash before \
                 paying again): {e}"
            ))
        })?;

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
            payment_hash: bolt11_payment_hash,
            ..details
        }
    } else {
        details
    };

    let settled = await_admission_settlement(state, peer_id, details).await?;
    deliver_settled_admission(state, peer_id, settled).await
}

/// Per-compose invariants shared by every room member's fan-out future.
///
/// These values are identical for all members of a single room compose, so we
/// bundle them once instead of threading each through the per-member helper.
struct RoomFanoutCtx<'a> {
    sender: NodeId,
    room_recipient: Recipient,
    plaintext: &'a str,
    references: &'a [MessageId],
    kind: u16,
    current_block_height: u64,
}

/// Result of fanning a room message out to a single member.
///
/// Produced by [`compose_room_member`] for each reachable member. The shared,
/// order-sensitive bookkeeping (which member's envelope becomes the canonical
/// `message_id`, the single WebSocket broadcast) is reconciled by the caller
/// *after* the bounded-concurrency fan-out completes, so individual member
/// futures never touch shared state and can run in parallel safely.
struct RoomMemberOutcome {
    /// The composed-and-stored envelope for this member.
    envelope: konsensus_core::UkmEnvelope,
    /// Amount paid to this member, in millisatoshis.
    amount_msat: u64,
    /// Whether the envelope was delivered directly (vs. queued for later).
    delivered: bool,
}

/// Compose, pay, encrypt, store, and deliver a room message for **one** member.
///
/// This is the per-member body of the room fan-out, extracted so it can be run
/// under a bounded-concurrency limiter. Payment semantics are unchanged: every
/// member is independently gated (Principle 2) — each gets its own E2EE
/// ciphertext, its own Lightning payment proof, and its own signed envelope.
///
/// Returns `Ok(None)` when the member should be skipped gracefully (self, no
/// E2EE session, payment proof unavailable / offline, or a storage error) — the
/// same skip conditions the original serial loop handled with `continue`.
/// Returns `Err` only for a hard pricing-engine failure, matching the original
/// behaviour where such an error aborted the whole compose.
async fn compose_room_member(
    state: &AppState,
    ctx: &RoomFanoutCtx<'_>,
    member: NodeId,
) -> Result<Option<RoomMemberOutcome>, ApiError> {
    // Don't send to self.
    if &member == state.identity.node_id() {
        return Ok(None);
    }

    // Encrypt via Double Ratchet for this specific member.
    let ratchet_msg = match state.session_manager.encrypt(&member, ctx.plaintext.as_bytes()).await {
        Ok(msg) => msg,
        Err(e) => {
            tracing::warn!(
                peer = %member,
                error = %e,
                "skipping room member: E2EE session not established"
            );
            return Ok(None);
        }
    };
    let ciphertext = ratchet_message_to_bytes(&ratchet_msg);

    // Get price for this member. The plasticity trust discount (if any) is
    // applied exactly once inside the cache's single choke point
    // (`get_fresh_discounted_peer_price`) — never re-applied here. This keeps
    // the room fan-out on the same money-path invariant as the peer compose
    // path (HARD-13): one base price, one discount, no compounding drift.
    let price_msat = match state
        .peer_prices
        .get_fresh_discounted_peer_price(
            &member,
            ctx.kind,
            ctx.current_block_height,
            MAX_PRICE_AGE,
        )
        .await
    {
        Some(discounted_price) => discounted_price,
        None => state
            .pricing
            .get_price_msat(ctx.kind)
            .await
            .map_err(|e| ApiError::Internal(format!("pricing error: {e}")))?,
    };

    // Create payment proof — requests invoice from recipient's wallet (Principle 2).
    // For room messages, skip offline members gracefully (they'll get it when they reconnect).
    let (payment_hash, preimage_bytes, amount_msat) =
        match create_payment_proof(state, price_msat, &member).await {
            Ok(proof) => proof,
            Err(e) => {
                tracing::warn!(
                    peer = %member,
                    error = %e,
                    "skipping room member: payment proof unavailable (offline?)"
                );
                return Ok(None);
            }
        };

    let proof = konsensus_core::PaymentProof::new(payment_hash, preimage_bytes, amount_msat);

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
        return Ok(None);
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

    // Deliver or queue — try sending directly to avoid TOCTOU race.
    let delivered = match state.transport.send(&member, &envelope).await {
        Ok(()) => {
            // Record send timestamp for STDP latency measurement.
            let mut ts = state.send_timestamps.lock().await;
            if ts.len() < MAX_SEND_TIMESTAMPS {
                ts.insert(envelope.id, std::time::Instant::now());
            }
            drop(ts);
            true
        }
        Err(_) => {
            if let Err(qe) = state.storage.queue_pending_delivery(&envelope.id, &member).await {
                tracing::warn!(peer = %member, error = %qe, "failed to queue pending room delivery");
            }
            false
        }
    };

    Ok(Some(RoomMemberOutcome {
        envelope,
        amount_msat,
        delivered,
    }))
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

        let current_block_height = match state.chain.get_block_height().await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, "failed to get block height for room compose, using fallback 0");
                0
            }
        };

        // Fan out to members with bounded parallelism. Each member future is
        // fully independent (its own payment proof + envelope — Principle 2 is
        // unchanged) and touches no shared state; we keep the original index so
        // the canonical `message_id` and the single WS broadcast stay
        // deterministic regardless of completion order.
        use futures::stream::StreamExt;
        let ctx = RoomFanoutCtx {
            sender,
            room_recipient,
            plaintext: req.plaintext.as_str(),
            references: &references,
            kind: req.kind,
            current_block_height,
        };
        let mut outcomes: Vec<(usize, RoomMemberOutcome)> = futures::stream::iter(
            members.iter().copied().enumerate(),
        )
        .map(|(idx, member)| {
            let state = &state;
            let ctx = &ctx;
            async move {
                let result = compose_room_member(state, ctx, member).await;
                (idx, result)
            }
        })
        .buffer_unordered(MAX_ROOM_FANOUT_CONCURRENCY)
        // A hard pricing-engine error aborts the whole compose, mirroring the
        // original serial loop's `?` propagation.
        .map(|(idx, result)| result.map(|opt| opt.map(|outcome| (idx, outcome))))
        .collect::<Vec<Result<Option<(usize, RoomMemberOutcome)>, ApiError>>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, ApiError>>()?
        .into_iter()
        .flatten()
        .collect();

        // Restore deterministic ordering: the canonical message + WS broadcast
        // is the lowest-indexed member that succeeded, matching the old
        // first-success-wins behaviour.
        outcomes.sort_by_key(|(idx, _)| *idx);

        let mut any_delivered = false;
        let mut total_amount_msat: u64 = 0;
        let mut first_message_id: Option<String> = None;

        for (_idx, outcome) in &outcomes {
            total_amount_msat = total_amount_msat.saturating_add(outcome.amount_msat);
            any_delivered |= outcome.delivered;

            if first_message_id.is_none() {
                first_message_id = Some(outcome.envelope.id.to_hex());

                // Broadcast to WS once (with plaintext — we composed this message).
                if let Err(e) = state.ws_broadcast.send(Arc::new(crate::state::WsMessage {
                    envelope: outcome.envelope.clone(),
                    plaintext: Some(req.plaintext.clone()),
                })) {
                    tracing::debug!(
                        error = %e,
                        "no WebSocket clients connected for room compose broadcast"
                    );
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
                // TOCTOU note: `has_session` is re-read here, separate from the
                // failed `encrypt` above. `encrypt` returns NoSession ONLY when the
                // session map has no entry (it stays present through ratchet
                // rotation), so a transient failure on a live session keeps
                // has_session==true and takes the byte-identical path. The only
                // residual race is a concurrent session removal (e.g. a
                // decrypt-failure teardown) landing between encrypt and this
                // re-check, which would trigger one recipient-priced admission
                // invoice payment to a peer we just had a session with — bounded
                // (once per ADMISSION_SETTLED_TTL by the AdmissionLedger, and
                // serialized by the per-peer admission lock), connected-only, and
                // fail-closed (no free lane, no double-pay). Acceptable; a future
                // refinement could re-confirm no-session inside a single lock.
                let no_session = !state.session_manager.has_session(&peer_id).await;
                let connected = state.transport.is_connected(&peer_id).await;
                if !(no_session && connected) {
                    return Err(ApiError::BadRequest(format!(
                        "E2EE encryption failed (session may not be established): {e}"
                    )));
                }

                tracing::info!(
                    peer = %peer_id,
                    "no E2EE session with connected peer — attempting paid first-contact admission"
                );
                first_contact_admission(&state, &peer_id).await?;

                // Poll for the session the target establishes after promotion via
                // the existing prekey/self-heal path.
                let mut waited = Duration::ZERO;
                while !state.session_manager.has_session(&peer_id).await {
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
            .get_fresh_discounted_peer_price(
                &peer_id,
                req.kind,
                current_block_height,
                MAX_PRICE_AGE,
            )
            .await
        {
            Some(discounted) => {
                // The plasticity trust discount the peer offered us (based on our
                // synaptic weight in their routing table) was already applied
                // exactly once inside the cache. `discount` is read here for
                // observability only — it is NOT re-applied to the price.
                let discount = state.peer_prices.get_trust_discount(&peer_id).await;
                tracing::debug!(
                    peer = %peer_id,
                    kind = req.kind,
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

        let settled = await_settlement(&lightning, initial, "keysend")
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

        let out = await_settlement(&lightning, settled, "keysend").await.unwrap();
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
        let err = await_settlement(&lightning, inflight, "keysend")
            .await
            .expect_err("untrackable in-flight payment must error, not settle");
        assert!(
            format!("{err}").contains("double payment"),
            "expected the double-pay guard message, got: {err}"
        );
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use konsensus_core::identity::NodeIdentity;

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
    /// its bounded TTL, and — crucially — EXPIRES so a never-dispatched attempt
    /// cannot brick the peer forever (review finding #1, 2026-07-07).
    #[test]
    fn admission_ledger_dispatch_unknown_is_pollable_and_bounded() {
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

        // Bounded: after the TTL the guard expires so the peer is not bricked.
        assert_eq!(
            ledger.prior_admission(&peer, base + ADMISSION_SETTLED_TTL),
            PriorAdmission::None,
            "DispatchUnknown must EXPIRE — a never-dispatched attempt cannot brick a peer forever"
        );

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
