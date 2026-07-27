//! R3 SEAM-A — Tier-2 relay engine core (store-and-forward), wire-independent.
//!
//! This is the pure, storage-agnostic core of the ciphertext-only relay: the
//! deposit-authorization validator, the binding-registration rate-cap, and the
//! value types they operate on. It is **inert** until the gated `kind`-600+
//! dispatch (SEAM-B, Route B per `docs/v2/RELAY_ENGINE_BUILD_PLAN.md`) calls it,
//! and the whole relay role is opt-in behind `[relay].enabled` (default-off), so
//! nothing here runs on a node that has not enabled the relay.
//!
//! Two the-fool findings (RELAY_ENGINE_BUILD_PLAN §6) are baked in:
//!
//! * **FINDING 1 — no unpaid binding-state floods.** [`register_allowed`] caps
//!   `RelayRegister` per-peer (cooldown) and globally (binding count), so a peer
//!   cannot create unbounded binding state for free.
//! * **FINDING 2 — deposit-authorization is NOT message-admission.**
//!   [`validate_deposit`] decides only whether the relay may *hold* a ciphertext
//!   envelope (the depositor paid for storage, or is whitelist-sponsored by the
//!   recipient). It deliberately does **not** inspect the sender→recipient
//!   message `payment_proof`. "Payment is the connection" for the *message* is
//!   re-enforced by the recipient running `PaymentGate::verify` on **drain** (see
//!   [`DrainItem`]). The relay's depositor-whitelist is storage-sponsorship, never
//!   message-admission authority.
//!
//! The relay never decrypts: every value here is an envelope plaintext field or
//! opaque ciphertext metadata (size). No key material, no plaintext body.

// SEAM-A is the engine core; its callers (the gated dispatch + the real
// `RelayBindingStore` impl) land in SEAM-B/SEAM-C. Until then these items have
// no non-test caller. This allow is removed when SEAM-B wires the dispatch.
#![allow(dead_code)]

pub(crate) mod dispatch;
mod engine;
mod storage_payment;

use std::collections::HashMap;

use konsensus_core::types::{MessageId, NodeId};
use tokio::time::Instant;

pub(crate) use engine::RelayEngine;
pub(crate) use storage_payment::VerifiedStoragePayment;
pub(crate) use store::{open_durable_pool, InMemoryRelayStore, RelayBindingStore, SqliteRelayStore};

/// Per-peer cooldown on `RelayRegister` (FINDING 1). Mirrors the
/// `session_handler` admission-invoice cooldown: a peer may open a binding, but
/// not loop registrations to spam binding-state creation.
pub(crate) const RELAY_REGISTER_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);

/// Operator-set relay policy (the terms a relay advertises + enforces). Values
/// are caps; a deposit/register is measured against the tighter of policy and
/// per-binding limits.
#[derive(Debug, Clone)]
pub(crate) struct RelayPolicy {
    /// Hard ceiling on any binding's hold duration.
    pub max_ttl_secs: u32,
    /// Hard ceiling on any single binding's stored bytes.
    pub max_quota_bytes: u64,
    /// Global ceiling on the number of live bindings this relay holds
    /// (FINDING 1: bounds total binding state).
    pub max_bindings: usize,
    /// Storage price floor (msat per byte-day), chain-anchored by the caller.
    pub min_msat_per_byte_day: u64,
    /// Message kinds the relay will hold. Real-time signalling (400-499) and
    /// non-direct recipients are refused by the caller before reaching here; this
    /// is the positive allow-list.
    pub allowed_kinds: Vec<u16>,
    /// Max held items a single DRAIN may return (egress amplification cap,
    /// the-fool 2026-06-21): one flat-priced drain UKM must not pull unbounded
    /// ciphertext egress. A recipient drains in bounded batches, re-draining
    /// after acking.
    pub max_drain_batch: usize,
    /// Per-depositor sub-quota (bytes): the most a SINGLE authenticated depositor
    /// may hold under one recipient's binding (D2). Whitelist membership is not
    /// infinite trust — without this, one sponsored depositor could fill a
    /// recipient's whole `quota_bytes` and starve every other depositor. The
    /// effective cap is `min(max_bytes_per_depositor, binding.quota_bytes)`.
    pub max_bytes_per_depositor: u64,
}

impl RelayPolicy {
    fn kind_allowed(&self, kind: u16) -> bool {
        self.allowed_kinds.contains(&kind)
    }

    /// Conservative default policy for the inert, default-off relay (SEAM-B
    /// seam-1). Operator-configurable policy + chain-anchored `min_msat_per_byte_day`
    /// and D1 size·ttl gate pricing arrive in a later seam; these caps only bound
    /// register/ack state for a relay that is not yet enabled in production.
    pub(crate) fn inert_default() -> Self {
        Self {
            max_ttl_secs: 7 * 24 * 3600,
            max_quota_bytes: 16 * 1024 * 1024,
            max_bindings: 1024,
            min_msat_per_byte_day: 1,
            max_bytes_per_depositor: 4 * 1024 * 1024,
            allowed_kinds: vec![
                konsensus_core::kind::KIND_CHAT,
                konsensus_core::kind::KIND_FILE_REF,
            ],
            max_drain_batch: 64,
        }
    }
}

/// A read view of an established binding (what `RelayRegister` opened). The real
/// persisted form is a `RelayBindingStore` row (SEAM-C migration); this is the
/// minimal shape the validator needs.
#[derive(Debug, Clone)]
pub(crate) struct RelayBindingView {
    /// The offline recipient this binding holds mail for.
    pub recipient: NodeId,
    /// Absolute byte ceiling for this binding.
    pub quota_bytes: u64,
    /// Bytes already held under this binding.
    pub held_bytes: u64,
    /// Max hold duration the recipient requested (capped again by policy).
    pub ttl_max_secs: u32,
    /// Blake3 Merkle root over the recipient's published depositor list. A
    /// `Whitelisted` deposit must prove inclusion under this root.
    pub depositor_whitelist_root: [u8; 32],
}

/// How a depositor is authorized to place an envelope (RELAY_PROTOCOL §1).
#[derive(Debug, Clone)]
pub(crate) enum DepositProof {
    /// The depositor paid the relay separately for storage. Carries a
    /// [`VerifiedStoragePayment`] — a token the dispatch can mint ONLY after
    /// Lightning settlement verification (SEAM-A hardening), so a bare preimage
    /// can no longer authorize a hold.
    Prepaid(VerifiedStoragePayment),
    /// The depositor is in the recipient's published whitelist (the recipient
    /// sponsors the storage). Storage-sponsorship only — NOT message-admission.
    /// `depositor` MUST equal the authenticated UKM sender (checked in
    /// [`validate_deposit`]) so a stolen/shared Merkle proof cannot let another
    /// peer consume sponsored storage.
    Whitelisted {
        depositor: NodeId,
        merkle_path: Vec<[u8; 32]>,
        whitelist_root: [u8; 32],
    },
}

/// Why a deposit was refused. Every variant is a *hold* refusal; none of these
/// concern the sender→recipient message gate (that is the recipient's at drain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DepositReject {
    /// No `RelayRegister` binding for this recipient (DoS layer 1).
    NoBinding,
    /// Envelope recipient does not match the binding's recipient.
    RecipientMismatch,
    /// Requested TTL exceeds policy or binding ceiling.
    TtlTooLong,
    /// Holding this envelope would exceed the binding's byte quota.
    QuotaExceeded,
    /// Kind not in the relay's allow-list (e.g. real-time signalling).
    KindNotAllowed,
    /// The verified storage payment / whitelisted proof is not bound to the
    /// authenticated UKM sender (a stolen settlement or Merkle proof).
    DepositorMismatch,
    /// The settled storage amount is below the policy-derived floor for this
    /// envelope's size + TTL.
    StorageFloorNotMet,
    /// `Whitelisted` inclusion proof did not verify under the binding's root.
    WhitelistNotProven,
}

/// Validate whether the relay may **hold** an envelope. Pure — no I/O, no
/// storage, no wire types. The caller (SEAM-B dispatch) extracts the fields from
/// the inbound `kind`-601 UKM.
///
/// FINDING 2: an `Ok(())` means "authorized to HOLD", NOT "message admitted".
/// The message's payment-is-the-connection guarantee is re-checked by the
/// recipient at drain ([`DrainItem`]); this function never inspects the
/// sender→recipient `payment_proof`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_deposit(
    binding: Option<&RelayBindingView>,
    envelope_recipient: &NodeId,
    envelope_kind: u16,
    envelope_size: u64,
    deposit_proof: &DepositProof,
    ttl_secs: u32,
    authenticated_depositor: &NodeId,
    policy: &RelayPolicy,
) -> Result<(), DepositReject> {
    // DoS layer 1: a binding must exist.
    let binding = binding.ok_or(DepositReject::NoBinding)?;
    if &binding.recipient != envelope_recipient {
        return Err(DepositReject::RecipientMismatch);
    }
    // TTL bounded by the tighter of policy and the recipient's request.
    if ttl_secs > policy.max_ttl_secs || ttl_secs > binding.ttl_max_secs {
        return Err(DepositReject::TtlTooLong);
    }
    if !policy.kind_allowed(envelope_kind) {
        return Err(DepositReject::KindNotAllowed);
    }
    // Quota: tighter of policy ceiling and this binding's quota. Overflow-safe —
    // compute remaining headroom instead of `held + size` (which could wrap).
    let effective_quota = binding.quota_bytes.min(policy.max_quota_bytes);
    if envelope_size > effective_quota.saturating_sub(binding.held_bytes) {
        return Err(DepositReject::QuotaExceeded);
    }
    // Authorization: settlement-verified prepay OR recipient-sponsored whitelist.
    // Both MUST be bound to the authenticated UKM sender.
    match deposit_proof {
        DepositProof::Prepaid(payment) => {
            // The settlement token is bound to the depositor who presented it.
            if payment.depositor() != authenticated_depositor {
                return Err(DepositReject::DepositorMismatch);
            }
            // The settled amount must cover the policy-derived storage floor for
            // THIS envelope's size + TTL — never a caller-supplied amount.
            let floor = storage_floor_msat(envelope_size, ttl_secs, policy.min_msat_per_byte_day);
            if payment.amount_msat() < floor {
                return Err(DepositReject::StorageFloorNotMet);
            }
        }
        DepositProof::Whitelisted {
            depositor,
            merkle_path,
            whitelist_root,
        } => {
            // Bind the sponsorship to the authenticated sender: a stolen/shared
            // Merkle proof must not let another peer consume sponsored storage.
            if depositor != authenticated_depositor {
                return Err(DepositReject::DepositorMismatch);
            }
            // The proof must be against THIS binding's published root, and the
            // inclusion path must verify. Storage-sponsorship only.
            if whitelist_root != &binding.depositor_whitelist_root
                || !verify_merkle_inclusion(depositor, merkle_path, whitelist_root)
            {
                return Err(DepositReject::WhitelistNotProven);
            }
        }
    }
    Ok(())
}

/// Policy-derived storage floor for an envelope: `size · ttl_secs · rate`
/// (msat per byte-day) prorated over a day, rounded up. u128 math so a large
/// size·ttl product cannot overflow before the divide.
fn storage_floor_msat(size: u64, ttl_secs: u32, min_msat_per_byte_day: u64) -> u64 {
    const SECS_PER_DAY: u128 = 86_400;
    let numer = (size as u128)
        .saturating_mul(ttl_secs as u128)
        .saturating_mul(min_msat_per_byte_day as u128);
    let floor = numer.div_ceil(SECS_PER_DAY);
    floor.min(u64::MAX as u128) as u64
}

/// One held envelope handed to the recipient on drain. FINDING 2: the recipient
/// MUST run `PaymentGate::verify(&envelope, .., Some(self_node_id))` on this
/// before treating the message as admitted — the relay holding it proves only
/// that storage was paid for, never that the sender→recipient payment settled.
/// The relay never bypasses the gate; this struct is transport.
#[derive(Debug, Clone)]
pub(crate) struct DrainItem {
    /// The original sealed envelope, byte-identical to deposit. Opaque ciphertext.
    pub envelope_bytes: Vec<u8>,
    /// The held envelope's own `MessageId` (`UkmEnvelope.id`), captured at deposit
    /// from the parsed inner envelope. The recipient acks by THIS id — the only
    /// handle it keeps after a drain re-injects the envelope (it never learns the
    /// relay's internal `sequence`). Ack deletes by matching this field (seam-4).
    pub message_id: MessageId,
    /// Monotonic per-binding sequence so an adversarial relay cannot silently
    /// drop or reorder held mail (THREAT_MODEL §6). Internal ordering guard —
    /// retained for drop/reorder detection; deletion is by `message_id`.
    pub sequence: u64,
    /// The authenticated depositor (the kind-601 UKM sender) this hold is charged
    /// to. The store sums held bytes by this field to enforce the per-depositor
    /// sub-quota (D2); it is the single source of truth, so ack/prune reclaim a
    /// depositor's share automatically. Not egress data — the recipient reads it
    /// from the re-injected envelope's own sender.
    pub depositor: NodeId,
    /// When the relay accepted the deposit.
    pub deposit_received_at: u64,
    /// Unix seconds after which this hold no longer consumes quota and must not
    /// be returned by drain. This is priced by `ttl_secs` at deposit time.
    pub expires_at: u64,
}

/// FINDING 1: may `peer` open a new binding now? Enforces a per-peer cooldown and
/// a global binding cap so registration cannot create unpaid binding state in a
/// loop. On allow, records `now`. Pure (clock injected) → unit-testable.
pub(crate) fn register_allowed(
    last_register: &mut HashMap<NodeId, Instant>,
    current_binding_count: usize,
    peer: &NodeId,
    now: Instant,
    policy: &RelayPolicy,
) -> Result<(), RegisterReject> {
    if current_binding_count >= policy.max_bindings {
        return Err(RegisterReject::GlobalCapReached);
    }
    if let Some(last) = last_register.get(peer) {
        if now.duration_since(*last) < RELAY_REGISTER_COOLDOWN {
            return Err(RegisterReject::RateLimited);
        }
    }
    last_register.insert(*peer, now);
    Ok(())
}

/// Why a `RelayRegister` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegisterReject {
    /// Within [`RELAY_REGISTER_COOLDOWN`] of this peer's last registration.
    RateLimited,
    /// The relay already holds `policy.max_bindings` bindings.
    GlobalCapReached,
}

/// Verify a Blake3 binary-Merkle inclusion proof: folding `leaf` with each
/// sibling in `path` (order-independent via sorted pairing) must reach `root`.
/// Leaf = blake3(depositor NodeId bytes). Pure.
fn verify_merkle_inclusion(depositor: &NodeId, path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    let mut acc: [u8; 32] = blake3::hash(depositor.as_bytes()).into();
    for sibling in path {
        // Sorted pairing makes the proof independent of left/right position,
        // so the path need not carry direction bits.
        let mut hasher = blake3::Hasher::new();
        if acc <= *sibling {
            hasher.update(&acc);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(&acc);
        }
        acc = hasher.finalize().into();
    }
    &acc == root
}

mod store;

#[cfg(test)]
mod tests;
