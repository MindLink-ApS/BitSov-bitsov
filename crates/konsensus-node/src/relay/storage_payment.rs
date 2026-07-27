//! R3 SEAM-A — the storage-payment capability token.
//!
//! [`VerifiedStoragePayment`] is a capability token proving a depositor's storage
//! payment settled to this relay. Its fields are module-private, so the only way
//! to obtain one is [`VerifiedStoragePayment::from_message_gate`] — built from a
//! kind-601 deposit UKM whose payment the message `PaymentGate` has ALREADY
//! verified (settled, incoming/recipient-bound to this relay, preimage-matched,
//! single-use in the durable `payment_receipts` store) before the relay dispatch
//! runs. Under the D1 (Q2-fold) model the relay engine itself never calls a
//! Lightning backend: settlement verification is wholly the gate's job, so "the
//! relay never verifies payments — the gate does" holds at the type level.

use konsensus_core::types::NodeId;

/// Proof that a depositor's storage payment settled to this relay. Constructible
/// ONLY via [`VerifiedStoragePayment::from_message_gate`] (fields module-private).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedStoragePayment {
    payment_hash: [u8; 32],
    /// The settled amount as the message gate cross-checked it (a verified lower
    /// bound on what settled; never an unverified caller claim).
    amount_msat: u64,
    /// The authenticated depositor this settlement is bound to (the UKM sender).
    depositor: NodeId,
}

impl VerifiedStoragePayment {
    pub(crate) fn amount_msat(&self) -> u64 {
        self.amount_msat
    }
    pub(crate) fn depositor(&self) -> &NodeId {
        &self.depositor
    }
    pub(crate) fn payment_hash(&self) -> &[u8; 32] {
        &self.payment_hash
    }

    /// D1 Q2-fold mint: build a token from the kind-601 deposit UKM's OWN payment,
    /// which the message `PaymentGate` has ALREADY verified — settled, **incoming
    /// to this relay** (recipient-bound to `our_node_id`), preimage-matched, and
    /// **single-use in the durable `payment_receipts` store** — before this
    /// dispatch runs. The message gate IS an equivalent settlement verifier, so a
    /// gate-passed payment is settlement-proven; folding it as the storage rent
    /// means ONE settled HTLC, consumed ONCE in ONE durable replay store (the
    /// gate's), with no separate relay-side settlement check or replay store, and
    /// so no double-claim and no restart-replay gap (operator decision D1).
    ///
    /// `amount_msat` is the depositor's signed, gate-cross-checked claim
    /// (`verify_settlement` proved backend-settled ≥ this claim ≥ the kind-601
    /// price floor), so it is a verified LOWER BOUND on what actually settled —
    /// safe to floor-check in `validate_deposit`. `depositor` MUST be the
    /// authenticated UKM sender. CALL ONLY from the relay-control dispatch with a
    /// gate-passed kind-601 envelope — never speculatively.
    ///
    /// Load-bearing invariant (the-fool 2026-06-21): the gate performs the
    /// settled / incoming / recipient-bound / amount checks above ONLY when
    /// `payment_gate.verify_lightning_settlement` is on. That is FORCED on for
    /// every non-Mock (production) backend — `Config::validate()` hard-bails a
    /// non-Mock backend with settlement off (tested:
    /// `tests/config.rs::validate_rejects_settlement_off_on_non_mock_backend`) —
    /// so a real relay always inherits full settlement verification. Only a
    /// Mock-backed (test) relay can run with it off.
    pub(crate) fn from_message_gate(
        payment_hash: [u8; 32],
        amount_msat: u64,
        depositor: NodeId,
    ) -> Self {
        Self {
            payment_hash,
            amount_msat,
            depositor,
        }
    }
}
