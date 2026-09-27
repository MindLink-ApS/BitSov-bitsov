//! Membrane (N2) — every admission decision at the payment gate, observable.
//!
//! The whitepaper's membrane is "a bounded doorway, not a wall": a stranger is
//! admitted by a settled, recipient-bound, single-use payment, and abuse becomes a
//! paid, signed, locally provable event. This module makes each decision at that
//! doorway readable by the owner's own client, and nothing more:
//!
//! - Every inbound gate verdict (admitted by settlement, or refused with a reason
//!   code) and every outbound refusal of our own sends (`price_cap_exceeded`,
//!   `budget_exceeded`) becomes one [`MembraneEvent`].
//! - Events go to `/ws` as `{"type":"membrane", ...}` and into a bounded
//!   in-memory ring buffer ([`MEMBRANE_CAPACITY`]) read by
//!   `GET /api/v1/membrane` (read scope). Nothing here is written to disk; the
//!   existing audit log stays the only persistent record. There is no export
//!   route, and events are never gossiped.
//! - An event never carries plaintext, ciphertext, signatures, nonces, payment
//!   hashes or preimages: only amounts, a kind, a reason code and a time.
//! - The counterparty is named only when the gate had **verified the sender's
//!   signature** before deciding. A refusal decided earlier (malformed envelope,
//!   closed-mesh check, stale timestamp, bad signature) carries no identity,
//!   because the claimed sender is unproven and naming it would let anyone put
//!   words in someone else's mouth.
//!
//! The ring lives on [`AuditLog`](crate::audit::AuditLog) because it is emitted
//! at exactly the places the audit entries are written, and so every component
//! that already holds the audit log (API state, the node's receive loop) can emit
//! without a new dependency being threaded through.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::broadcast;

use konsensus_core::gate::GateRejection;
use konsensus_core::{Recipient, UkmEnvelope};

use crate::error::ApiError;

/// `/status` capability: `GET /api/v1/membrane` and `/ws` `membrane` events.
pub const CAPABILITY: &str = "membrane_v1";

/// Ring-buffer bound. Oldest events are dropped first.
pub const MEMBRANE_CAPACITY: usize = 500;

/// `/ws` fan-out buffer. A lagging socket skips events (it can re-read the ring).
const BROADCAST_CAPACITY: usize = 256;

/// Which way the energy was trying to cross.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// A peer's envelope arriving at this node's payment gate.
    Inbound,
    /// This node's own send, refused before any payment left.
    Outbound,
}

/// The decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Passed every gate check; stored and acknowledged.
    Admitted,
    /// Refused; nothing stored.
    Refused,
}

/// Machine reason code. Stable strings; the app keys its wording on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    /// Admitted by a settled payment.
    Settled,
    /// Envelope carried no payment at all.
    Unpaid,
    /// Paid less than the price this node requires for the kind.
    InsufficientPayment,
    /// The payment is not settled at this node's Lightning backend.
    NotSettled,
    /// Settlement did not match the envelope proof (amount, hash, direction, recipient).
    SettlementMismatch,
    /// Settlement could not be checked (backend down). Fail-closed.
    SettlementUnavailable,
    /// The settled payment already bought another message.
    ProofReused,
    /// Nonce already seen.
    Replay,
    /// Timestamp too old or too far in the future.
    Stale,
    /// Signature did not verify.
    BadSignature,
    /// Structurally invalid envelope.
    InvalidEnvelope,
    /// Closed mesh: sender is not a contact and the door is invite-only.
    InviteOnly,
    /// This node has no price for the kind.
    NotPriceable,
    /// The node could not decide (pricing or nonce store failed). Fail-closed.
    NodeError,
    /// Outbound: the recipient's price is above the cap the client confirmed.
    PriceCapExceeded,
    /// Outbound: a paired client's budget grant refused the debit (G1).
    BudgetExceeded,
}

/// One admission decision. Serialized as the `/ws` event and the ring entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MembraneEvent {
    /// Always `"membrane"`, so `/ws` clients can tell it from a message.
    #[serde(rename = "type")]
    pub event_type: &'static str,
    /// Monotonic per node run (starts at 1). Not persisted.
    pub seq: u64,
    /// Decision time, unix milliseconds.
    pub at: u64,
    /// Inbound (a peer at our door) or outbound (our send at theirs).
    pub direction: Direction,
    /// Admitted or refused.
    pub verdict: Verdict,
    /// Why.
    pub code: Code,
    /// Message kind, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<u16>,
    /// Node id (hex) or room id. Inbound: only when the sender's signature was
    /// verified before the decision. Local to this node; never gossiped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterparty: Option<String>,
    /// Inbound admission from a sender that is not a contact.
    pub first_contact: bool,
    /// The price the gate required, when the gate stated it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_msat: Option<u64>,
    /// The amount the envelope carried (inbound) — settled when admitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paid_msat: Option<u64>,
    /// Outbound: the cap the client confirmed for this send.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_msat: Option<u64>,
}

/// Map a gate rejection to its code, the price it states, and whether the
/// sender's signature was verified before the gate decided.
///
/// The ordering mirrors `PaymentGate::verify`: integrity → closed mesh →
/// freshness → **signature** → nonce → price → settlement → proof reuse.
#[must_use]
pub fn classify(rejection: &GateRejection) -> (Code, Option<u64>, bool) {
    match rejection {
        GateRejection::InvalidEnvelope(_) => (Code::InvalidEnvelope, None, false),
        GateRejection::NotWhitelisted(_) => (Code::InviteOnly, None, false),
        GateRejection::MessageTooOld { .. } | GateRejection::MessageFromFuture { .. } => {
            (Code::Stale, None, false)
        }
        GateRejection::InvalidSignature(_) => (Code::BadSignature, None, false),
        GateRejection::ReplayDetected => (Code::Replay, None, true),
        GateRejection::NonceCheckFailed(_) | GateRejection::PricingFailed(_) => {
            (Code::NodeError, None, true)
        }
        GateRejection::InsufficientPayment {
            required_msat,
            paid_msat,
        } => {
            let code = if *paid_msat == 0 {
                Code::Unpaid
            } else {
                Code::InsufficientPayment
            };
            (code, Some(*required_msat), true)
        }
        GateRejection::KindNotPriceable(_) => (Code::NotPriceable, None, true),
        GateRejection::PaymentNotSettled(_) => (Code::NotSettled, None, true),
        GateRejection::PaymentSettlementMismatch(_) | GateRejection::RecipientMismatch { .. } => {
            (Code::SettlementMismatch, None, true)
        }
        GateRejection::LightningUnavailable(_) => (Code::SettlementUnavailable, None, true),
        GateRejection::PaymentProofReused { .. } => (Code::ProofReused, None, true),
    }
}

/// The outbound membrane code for an API error, if it is a membrane refusal.
#[must_use]
pub fn outbound_code(err: &ApiError) -> Option<Code> {
    match err {
        ApiError::PriceCapExceeded(_) => Some(Code::PriceCapExceeded),
        _ => None,
    }
}

fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

fn sender_hex(envelope: &UkmEnvelope) -> String {
    envelope.sender.to_hex()
}

/// Admission and refusal counts since the node started (not persisted).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Totals {
    /// Inbound admissions.
    pub admitted: u64,
    /// Inbound admissions from non-contacts.
    pub first_contacts: u64,
    /// Inbound refusals.
    pub refused: u64,
    /// Outbound refusals of our own sends.
    pub outbound_refused: u64,
}

#[derive(Default)]
struct Ring {
    events: VecDeque<Arc<MembraneEvent>>,
    totals: Totals,
}

/// Bounded, in-memory membrane log with a `/ws` fan-out.
pub struct Membrane {
    ring: Mutex<Ring>,
    seq: AtomicU64,
    capacity: usize,
    tx: broadcast::Sender<Arc<MembraneEvent>>,
}

impl Default for Membrane {
    fn default() -> Self {
        Self::with_capacity(MEMBRANE_CAPACITY)
    }
}

impl Membrane {
    /// A membrane log holding at most `capacity` events (at least 1).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            ring: Mutex::new(Ring::default()),
            seq: AtomicU64::new(1),
            capacity: capacity.max(1),
            tx,
        }
    }

    /// The ring bound.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Subscribe to new events (for `/ws`).
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<MembraneEvent>> {
        self.tx.subscribe()
    }

    /// An inbound envelope passed the gate. `first_contact` = sender is not a contact.
    pub fn admitted(&self, envelope: &UkmEnvelope, first_contact: bool) -> Arc<MembraneEvent> {
        self.push(|seq| MembraneEvent {
            event_type: "membrane",
            seq,
            at: now_ms(),
            direction: Direction::Inbound,
            verdict: Verdict::Admitted,
            code: Code::Settled,
            kind: Some(envelope.kind),
            counterparty: Some(sender_hex(envelope)),
            first_contact,
            required_msat: None,
            paid_msat: Some(envelope.payment_proof.amount_msat),
            cap_msat: None,
        })
    }

    /// An inbound envelope was refused by the gate.
    pub fn refused(&self, envelope: &UkmEnvelope, rejection: &GateRejection) -> Arc<MembraneEvent> {
        let (code, required_msat, sender_verified) = classify(rejection);
        self.push(|seq| MembraneEvent {
            event_type: "membrane",
            seq,
            at: now_ms(),
            direction: Direction::Inbound,
            verdict: Verdict::Refused,
            code,
            kind: Some(envelope.kind),
            counterparty: sender_verified.then(|| sender_hex(envelope)),
            first_contact: false,
            required_msat,
            paid_msat: Some(envelope.payment_proof.amount_msat),
            cap_msat: None,
        })
    }

    /// One of our own sends was refused before any payment left.
    /// Returns `None` (and records nothing) for errors that are not membrane refusals.
    pub fn outbound_refused(
        &self,
        err: &ApiError,
        recipient: &str,
        kind: u16,
        cap_msat: Option<u64>,
    ) -> Option<Arc<MembraneEvent>> {
        let code = outbound_code(err)?;
        Some(self.push(|seq| MembraneEvent {
            event_type: "membrane",
            seq,
            at: now_ms(),
            direction: Direction::Outbound,
            verdict: Verdict::Refused,
            code,
            kind: Some(kind),
            counterparty: Some(recipient.to_owned()),
            first_contact: false,
            required_msat: None,
            paid_msat: None,
            cap_msat,
        }))
    }

    fn push(&self, build: impl FnOnce(u64) -> MembraneEvent) -> Arc<MembraneEvent> {
        let mut ring = self
            .ring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // seq is taken under the lock so ring order == seq order.
        let event = Arc::new(build(self.seq.fetch_add(1, Ordering::Relaxed)));
        match (event.direction, event.verdict) {
            (Direction::Inbound, Verdict::Admitted) => {
                ring.totals.admitted += 1;
                if event.first_contact {
                    ring.totals.first_contacts += 1;
                }
            }
            (Direction::Inbound, Verdict::Refused) => ring.totals.refused += 1,
            (Direction::Outbound, _) => ring.totals.outbound_refused += 1,
        }
        if ring.events.len() >= self.capacity {
            ring.events.pop_front();
        }
        ring.events.push_back(Arc::clone(&event));
        drop(ring);
        // No subscribers is normal (no client connected).
        let _ = self.tx.send(Arc::clone(&event));
        event
    }

    /// Newest-first events with `at > since` (if given), at most `limit`,
    /// plus the running totals.
    #[must_use]
    pub fn read(&self, since: Option<u64>, limit: usize) -> (Vec<Arc<MembraneEvent>>, Totals) {
        let ring = self
            .ring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let events = ring
            .events
            .iter()
            .rev()
            .filter(|e| match since {
                Some(s) => e.at > s,
                None => true,
            })
            .take(limit)
            .cloned()
            .collect();
        (events, ring.totals)
    }
}

/// Counterparty string for an outbound recipient (node hex or room id).
#[must_use]
pub fn recipient_label(recipient: &Recipient) -> Option<String> {
    match recipient {
        Recipient::Node(id) => Some(id.to_hex()),
        Recipient::Room(id) => Some(id.to_string()),
        Recipient::Broadcast => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_core::types::NodeId;
    use konsensus_core::{PaymentProof, UkmEnvelopeBuilder};
    use sha2::{Digest, Sha256};

    const PREIMAGE: [u8; 32] = [0xA7; 32];

    fn envelope(amount_msat: u64) -> UkmEnvelope {
        let hash: [u8; 32] = Sha256::digest(PREIMAGE).into();
        UkmEnvelopeBuilder::new(
            1,
            NodeId::from_bytes([0x11; 32]),
            Recipient::Node(NodeId::from_bytes([0x22; 32])),
            b"SECRET-CIPHERTEXT-BYTES".to_vec(),
            PaymentProof::new(hash, PREIMAGE, amount_msat),
        )
        .build()
    }

    #[test]
    fn ring_is_bounded_and_keeps_newest() {
        let m = Membrane::with_capacity(3);
        let env = envelope(20_000);
        for _ in 0..10 {
            m.admitted(&env, false);
        }
        let (events, totals) = m.read(None, usize::MAX);
        assert_eq!(events.len(), 3, "ring never exceeds its capacity");
        assert_eq!(
            events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![10, 9, 8],
            "newest first; oldest dropped"
        );
        assert_eq!(totals.admitted, 10, "totals keep counting past the ring");
    }

    #[test]
    fn default_capacity_is_the_documented_bound() {
        let m = Membrane::default();
        let env = envelope(1);
        for _ in 0..(MEMBRANE_CAPACITY + 50) {
            m.refused(&env, &GateRejection::ReplayDetected);
        }
        assert_eq!(m.read(None, usize::MAX).0.len(), MEMBRANE_CAPACITY);
    }

    #[test]
    fn read_honours_limit_and_since() {
        let m = Membrane::with_capacity(10);
        let env = envelope(5);
        let first = m.admitted(&env, true);
        m.admitted(&env, false);
        assert_eq!(m.read(None, 1).0.len(), 1);
        let (after, _) = m.read(Some(first.at.saturating_sub(1)), 10);
        assert_eq!(after.len(), 2);
        let (none, _) = m.read(Some(u64::MAX), 10);
        assert!(none.is_empty());
    }

    #[test]
    fn refusal_names_sender_only_after_signature_verified() {
        let m = Membrane::with_capacity(10);
        let env = envelope(0);
        let unverified = [
            GateRejection::InvalidEnvelope("x".into()),
            GateRejection::NotWhitelisted(env.sender),
            GateRejection::MessageTooOld {
                age_ms: 1,
                max_ms: 0,
            },
            GateRejection::MessageFromFuture {
                ahead_ms: 1,
                max_ms: 0,
            },
            GateRejection::InvalidSignature("x".into()),
        ];
        for r in &unverified {
            assert!(
                m.refused(&env, r).counterparty.is_none(),
                "{r} must not name a sender"
            );
        }
        let verified = [
            GateRejection::ReplayDetected,
            GateRejection::InsufficientPayment {
                required_msat: 20_000,
                paid_msat: 0,
            },
            GateRejection::PaymentNotSettled("x".into()),
            GateRejection::PaymentProofReused {
                payment_hash: "ab".into(),
            },
        ];
        for r in &verified {
            assert_eq!(
                m.refused(&env, r).counterparty.as_deref(),
                Some(env.sender.to_hex().as_str()),
                "{r} was decided after the signature check"
            );
        }
    }

    #[test]
    fn unpaid_and_insufficient_carry_the_missing_price() {
        let m = Membrane::with_capacity(10);
        let unpaid = m.refused(
            &envelope(0),
            &GateRejection::InsufficientPayment {
                required_msat: 20_000,
                paid_msat: 0,
            },
        );
        assert_eq!(unpaid.code, Code::Unpaid);
        assert_eq!(unpaid.required_msat, Some(20_000));
        let short = m.refused(
            &envelope(5_000),
            &GateRejection::InsufficientPayment {
                required_msat: 20_000,
                paid_msat: 5_000,
            },
        );
        assert_eq!(short.code, Code::InsufficientPayment);
        assert_eq!(short.paid_msat, Some(5_000));
    }

    #[test]
    fn events_never_carry_payment_secrets_or_payload() {
        let m = Membrane::with_capacity(10);
        let env = envelope(20_000);
        let events = [
            m.admitted(&env, true),
            m.refused(
                &env,
                &GateRejection::PaymentProofReused {
                    payment_hash: hex::encode(env.payment_proof.payment_hash),
                },
            ),
            m.refused(&env, &GateRejection::ReplayDetected),
        ];
        let forbidden = [
            hex::encode(PREIMAGE),
            hex::encode(env.payment_proof.payment_hash),
            hex::encode(&env.ciphertext),
            "SECRET-CIPHERTEXT".to_string(),
            hex::encode(env.signature.to_ed25519().to_bytes()),
            env.id.to_hex(),
        ];
        for e in events {
            let json = serde_json::to_string(e.as_ref()).unwrap();
            for secret in &forbidden {
                assert!(
                    !json.contains(secret.as_str()),
                    "membrane event leaked {secret}: {json}"
                );
            }
            for key in [
                "preimage",
                "payment_hash",
                "ciphertext",
                "signature",
                "nonce",
                "plaintext",
            ] {
                assert!(
                    !json.contains(key),
                    "membrane event has field {key}: {json}"
                );
            }
        }
    }

    #[test]
    fn outbound_only_for_membrane_errors() {
        let m = Membrane::with_capacity(10);
        assert!(m
            .outbound_refused(&ApiError::BadRequest("x".into()), "ab", 1, None)
            .is_none());
        let e = m
            .outbound_refused(
                &ApiError::PriceCapExceeded("x".into()),
                "ab",
                1,
                Some(30_000),
            )
            .unwrap();
        assert_eq!(
            (e.direction, e.code, e.cap_msat),
            (Direction::Outbound, Code::PriceCapExceeded, Some(30_000))
        );
        assert_eq!(m.read(None, 10).1.outbound_refused, 1);
    }

    #[tokio::test]
    async fn subscribers_receive_the_ws_shape() {
        let m = Membrane::with_capacity(10);
        let mut rx = m.subscribe();
        m.admitted(&envelope(20_000), true);
        let got = rx.recv().await.unwrap();
        let v = serde_json::to_value(got.as_ref()).unwrap();
        assert_eq!(v["type"], "membrane");
        assert_eq!(v["verdict"], "admitted");
        assert_eq!(v["code"], "settled");
        assert_eq!(v["first_contact"], true);
        assert_eq!(v["paid_msat"], 20_000);
    }
}
