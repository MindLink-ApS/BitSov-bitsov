//! R3 SEAM-B1 — relay engine operational layer (wire- and handler-independent).
//!
//! Composes the merged primitives — the hardened `validate_deposit`, the
//! `RelayBindingStore`, and the `register_allowed` cap — into the relay-side
//! operations a node performs when acting as a Tier-2 relay: a recipient opens a
//! binding (register), and a depositor places ciphertext for an offline
//! recipient (deposit).
//!
//! It takes already-parsed fields; the SEAM-B dispatch (the live `msg_handler`
//! touch) extracts them from kind-600+ gated UKMs and calls these methods,
//! gated behind `[relay].enabled` (default-off). Inert until then.
//!
//! Doctrine preserved: the relay never decrypts (envelopes are opaque bytes);
//! storage is settlement-paid or whitelist-sponsored, bound to the authenticated
//! peer; deposit authorization is NOT message admission — the recipient
//! re-verifies the message gate when it drains (a separate, recipient-side step).

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use konsensus_core::types::{MessageId, NodeId};
use tokio::sync::Mutex;
use tokio::time::Instant;

use super::storage_payment::VerifiedStoragePayment;
use super::store::{RelayBinding, RelayBindingStore, RelayStoreError};
use super::{
    register_allowed, validate_deposit, DepositProof, DepositReject, DrainItem, RegisterReject,
    RelayPolicy,
};

/// A relay operation failure — the union of the layered checks, so a caller
/// (the dispatch) can map each to the right `RelayDepositReject`/`...` wire reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RelayOpError {
    Register(RegisterReject),
    Deposit(DepositReject),
    Store(RelayStoreError),
}

/// How a depositor authorized a deposit, in wire (unverified) form. The engine
/// turns this into a verified [`DepositProof`] before holding.
#[derive(Debug, Clone)]
pub(crate) enum DepositAuth {
    /// D1 (Q2-fold) in-band path: the kind-601 UKM's OWN payment — already
    /// verified by the message `PaymentGate` (settled, recipient-bound to this
    /// relay, single-use in the durable store) — IS the storage rent. No second
    /// settlement check, no second replay store, no double-claim, no restart gap.
    /// `amount_msat` is the gate-cross-checked signed claim (a verified lower
    /// bound on what settled). The depositor is the authenticated UKM sender.
    GateSettled {
        amount_msat: u64,
        payment_hash: [u8; 32],
    },
    /// The depositor claims recipient-sponsored whitelist membership.
    Whitelisted {
        merkle_path: Vec<[u8; 32]>,
        whitelist_root: [u8; 32],
    },
}

/// The relay-side engine: binding store + per-peer register cooldowns + operator
/// policy. Methods take `&self` (interior mutability via the store and mutexes).
///
/// The engine holds no `LightningProvider`: under the D1 (Q2-fold) deposit model
/// settlement is verified wholly by the message `PaymentGate` before dispatch, so
/// the relay engine never calls a Lightning backend — "the relay never verifies
/// payments, the gate does" is structural here.
pub(crate) struct RelayEngine {
    store: Arc<dyn RelayBindingStore>,
    policy: RelayPolicy,
    /// Per-peer last-register time (FINDING 1 cooldown).
    register_cooldowns: Mutex<HashMap<NodeId, Instant>>,
}

impl RelayEngine {
    pub(crate) fn new(store: Arc<dyn RelayBindingStore>, policy: RelayPolicy) -> Self {
        Self {
            store,
            policy,
            register_cooldowns: Mutex::new(HashMap::new()),
        }
    }

    /// A recipient (`registrant`) opens a binding asking this relay to hold mail
    /// for it. Rate-capped per peer and globally (FINDING 1) so registration
    /// cannot create unpaid binding state in a loop.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn handle_register(
        &self,
        registrant: NodeId,
        binding_id: [u8; 16],
        quota_bytes: u64,
        ttl_max_secs: u32,
        depositor_whitelist_root: [u8; 32],
        created_at: u64,
        now: Instant,
    ) -> Result<(), RelayOpError> {
        // Advisory fast-reject: a cheap snapshot cap check + the per-peer
        // cooldown (FINDING 1). The cap here can be stale by the time we insert,
        // so the store re-checks it authoritatively under the insert lock below.
        let count = self.store.binding_count().await;
        {
            let mut cds = self.register_cooldowns.lock().await;
            register_allowed(&mut cds, count, &registrant, now, &self.policy)
                .map_err(RelayOpError::Register)?;
        }
        self.store
            .register_binding(
                RelayBinding {
                    binding_id,
                    recipient: registrant,
                    quota_bytes,
                    held_bytes: 0,
                    ttl_max_secs,
                    depositor_whitelist_root,
                    created_at,
                },
                self.policy.max_bindings,
            )
            .await
            // The store's atomic cap loss surfaces as the same reject the
            // advisory check would have produced, so the wire reply is identical
            // whichever layer caught it.
            .map_err(|e| match e {
                RelayStoreError::CapExceeded => {
                    RelayOpError::Register(RegisterReject::GlobalCapReached)
                }
                other => RelayOpError::Store(other),
            })?;
        Ok(())
    }

    /// An authenticated `depositor` places a sealed envelope for the offline
    /// `binding_recipient`. The storage payment (Prepaid) is settlement-verified
    /// and replay-checked here; `validate_deposit` then binds the proof to the
    /// depositor, enforces the policy storage floor, quota, TTL and kind, and the
    /// store holds the ciphertext. Returns the assigned hold sequence.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn handle_deposit(
        &self,
        depositor: NodeId,
        binding_recipient: NodeId,
        message_id: MessageId,
        envelope_bytes: Vec<u8>,
        envelope_kind: u16,
        ttl_secs: u32,
        auth: DepositAuth,
        deposit_received_at: u64,
    ) -> Result<u64, RelayOpError> {
        // Turn the wire authorization into a verified proof.
        let proof = match auth {
            // D1: fold the gate-verified deposit payment as the rent — no second
            // settlement call, no `storage_replay` touch. `validate_deposit` then
            // enforces the byte-day floor against this gate-cross-checked amount.
            DepositAuth::GateSettled {
                amount_msat,
                payment_hash,
            } => DepositProof::Prepaid(VerifiedStoragePayment::from_message_gate(
                payment_hash,
                amount_msat,
                depositor,
            )),
            DepositAuth::Whitelisted {
                merkle_path,
                whitelist_root,
            } => DepositProof::Whitelisted {
                depositor,
                merkle_path,
                whitelist_root,
            },
        };

        if let Err(e) = self
            .store
            .prune_expired(&binding_recipient, deposit_received_at)
            .await
        {
            if e != RelayStoreError::BindingNotFound {
                return Err(RelayOpError::Store(e));
            }
        }

        let binding = self.store.get_binding(&binding_recipient).await;
        let view = binding.as_ref().map(RelayBinding::as_view);
        let size = envelope_bytes.len() as u64;
        validate_deposit(
            view.as_ref(),
            &binding_recipient,
            envelope_kind,
            size,
            &proof,
            ttl_secs,
            &depositor,
            &self.policy,
        )
        .map_err(RelayOpError::Deposit)?;

        self.store
            .hold_envelope(
                &binding_recipient,
                message_id,
                depositor,
                envelope_bytes,
                self.policy.max_bytes_per_depositor,
                deposit_received_at,
                deposit_received_at.saturating_add(ttl_secs as u64),
            )
            .await
            .map_err(RelayOpError::Store)
    }

    /// A recipient drains up to `max` held envelopes from ITS OWN binding. The
    /// caller (dispatch) passes the authenticated UKM sender as `recipient`, so a
    /// peer can only ever fetch its own held mail (the store is keyed by
    /// recipient). Returns opaque ciphertext items in sequence order.
    ///
    /// FINDING 2: these items are NOT admitted here. The recipient MUST re-run
    /// `PaymentGate::verify` on each held envelope's sender→recipient
    /// `payment_proof` before treating the message as received — a separate,
    /// recipient-side step. The relay holding an item proves only that storage
    /// was paid for, never that the message settled.
    pub(crate) async fn handle_drain_request(
        &self,
        recipient: NodeId,
        max: usize,
        now: u64,
    ) -> Vec<DrainItem> {
        // Egress cap (the-fool 2026-06-21): bound the batch so one flat-priced
        // drain UKM cannot pull unbounded ciphertext egress. The recipient
        // re-drains after acking the returned items.
        let max = max.min(self.policy.max_drain_batch);
        self.store.list_held(&recipient, max, now).await
    }

    /// A recipient acknowledges held items (by `MessageId` — the handle it keeps
    /// after a drain re-injects the envelope; seam-4) so the relay deletes them
    /// and frees quota. Keyed by the authenticated recipient, so a peer can only
    /// ack its own binding's items. Idempotent; returns the number deleted.
    pub(crate) async fn handle_ack(
        &self,
        recipient: NodeId,
        message_ids: &[MessageId],
    ) -> Result<usize, RelayOpError> {
        self.store
            .ack_delete(&recipient, message_ids)
            .await
            .map_err(RelayOpError::Store)
    }

    /// A recipient revokes its OWN binding (kind-604 unregister): the relay drops
    /// all its held mail and frees the slot. Keyed by the authenticated recipient
    /// (§0) — a peer can only unregister its own binding. Registration without a
    /// matching revoke would be a TRAP (no exit); revocability is a doctrine
    /// requirement. Errors `BindingNotFound` if there is nothing to revoke (a
    /// reject, never a silent success). The per-peer register cooldown is left
    /// intact so register/unregister cannot be cycled to bypass it.
    pub(crate) async fn handle_unregister(&self, registrant: NodeId) -> Result<(), RelayOpError> {
        self.store
            .remove_binding(&registrant)
            .await
            .map_err(RelayOpError::Store)
    }

    /// Current number of live bindings (for metrics / the global cap).
    pub(crate) async fn binding_count(&self) -> usize {
        self.store.binding_count().await
    }
}

#[cfg(test)]
mod tests;
