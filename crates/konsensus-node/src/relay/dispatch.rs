//! R3 SEAM-B (dispatch) — relay-control routing in the live receive path.
//!
//! **Route B (operator decision D3):** relay control rides kind-600+ paid UKMs
//! over the existing message path — no new wire side door. By the time this runs,
//! the receive-path gate (`msg_handler::run`) has ALREADY verified the control
//! UKM settled, recipient-bound to this relay, single-use, and charged
//! `KindCategory::Storage` pricing. So this dispatch adds **zero** admission
//! authority — it is pure post-payment routing.
//!
//! **Custody:** the intercept fires BEFORE `store_message`/`decrypt_and_process`,
//! so a relay-control UKM is never stored as a message and never fed to the
//! Double-Ratchet ("host the box, never the plaintext"). The control body lives
//! in `envelope.ciphertext`, parsed STRUCTURALLY (length-checked,
//! `deny_unknown_fields`, fail-closed) — never decrypted.
//!
//! **Keystone invariant (§0) — AUTHENTICATED-SENDER-ONLY:** every op scopes its
//! tenant identity to the gate-authenticated `envelope.sender` (the gate recovers
//! the Ed25519 key *from* `sender` and verifies the signature). The dispatch
//! NEVER reads a binding-owner / recipient / depositor NodeId from the body for
//! authorization — body NodeId fields are destinations, never authority.
//!
//! **Seam scope:** REGISTER (600), DEPOSIT (601), ACK (602), and DRAIN (603) are
//! wired here. UNREGISTER (604) needs net-new store removal and remains STAGED,
//! rejected until a later seam. Inert unless `[relay] enabled` (default-off): the
//! `msg_handler` intercept only runs when the engine is `Some`, which is
//! constructed only when enabled.

use std::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use tracing::warn;

use konsensus_core::kind;
use konsensus_core::types::{NodeId, Recipient};
use konsensus_core::{MessageId, UkmEnvelope};
use konsensus_message::wire::Frame;

use super::engine::{DepositAuth, RelayEngine};

const MAX_RELAY_WHITELIST_PROOF_DEPTH: usize = 64;

/// Max `MessageId`s a single kind-602 ACK may carry. A recipient acks what it
/// drained, and a drain returns at most `policy.max_drain_batch` (default 64)
/// items, so a legitimate ack is small; this caps an attacker (a paying one —
/// the body arrives in a gate-settled UKM) from forcing an oversized
/// `message_ids` Vec + the `HashSet` `ack_delete` builds from it. Generous at
/// 16× the default drain batch.
const MAX_RELAY_ACK_IDS: usize = 1024;

/// Deserialize the ACK `message_ids` capped at [`MAX_RELAY_ACK_IDS`]. Mirrors
/// `konsensus_core::envelope::bounded_references` (HARD-1 doctrine, wire.rs):
/// the visitor counts as it pushes and aborts at `cap + 1`, so it NEVER
/// pre-allocates a `Vec` from the attacker-declared array length — the parse
/// itself is bounded, not just the post-parse `.len()`. Bounding the 16 MiB
/// outer frame is necessary but not sufficient: a frame full of 67-byte hex ids
/// would otherwise materialize ~250k `MessageId`s before any count check.
fn bounded_ack_ids<'de, D>(deserializer: D) -> Result<Vec<MessageId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct AckIdVisitor;

    impl<'de> Visitor<'de> for AckIdVisitor {
        type Value = Vec<MessageId>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a list of at most {MAX_RELAY_ACK_IDS} ack message ids")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<MessageId>, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out: Vec<MessageId> = Vec::new();
            while let Some(item) = seq.next_element::<MessageId>()? {
                if out.len() >= MAX_RELAY_ACK_IDS {
                    return Err(de::Error::custom(format!(
                        "ack message_ids exceeds maximum of {MAX_RELAY_ACK_IDS} entries"
                    )));
                }
                out.push(item);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(AckIdVisitor)
}

/// kind-600 REGISTER body. `binding_id`/`depositor_whitelist_root` are carried as
/// length-validated byte vectors (structural parse, no fixed-size serde array
/// surprises); the handler converts them to `[u8; N]` and rejects any other
/// length. There is intentionally NO owner NodeId field — the binding owner is
/// the authenticated `envelope.sender` (§0).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    binding_id: Vec<u8>,
    quota_bytes: u64,
    ttl_max_secs: u32,
    depositor_whitelist_root: Vec<u8>,
    created_at: u64,
}

/// kind-602 ACK body — `MessageId`s of the caller's OWN held items to delete
/// (seam-4). The recipient acks by the `UkmEnvelope.id` a prior drain re-injected
/// to it — the only handle it has (it never learns the relay's internal
/// sequence). No identity field; the binding is scoped to `envelope.sender` (§0).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AckBody {
    /// Capped at [`MAX_RELAY_ACK_IDS`] DURING parse by [`bounded_ack_ids`] — the
    /// streaming visitor aborts at `cap + 1` so the relay never materializes an
    /// attacker-sized `Vec` (validate-DURING-allocate, not after).
    #[serde(deserialize_with = "bounded_ack_ids")]
    message_ids: Vec<MessageId>,
}

/// kind-601 DEPOSIT body. `binding_recipient` is the offline DESTINATION the mail
/// is for — a routing field, NOT authority (the authorized depositor is the
/// authenticated `envelope.sender`, §0). `inner_envelope_bytes` is the original
/// sealed sender→recipient envelope, held OPAQUE (never decrypted by the relay);
/// it keeps its own payment_proof so the recipient re-verifies the message gate
/// at drain (FINDING-2). Absent `whitelist` ⇒ the PAID path: the kind-601 UKM's
/// own gate-verified payment is the storage rent (D1 Q2-fold). `inner_kind` is
/// a compatibility mirror only: dispatch parses the actual `inner_envelope_bytes`
/// and rejects if the claimed kind diverges, so policy never trusts a body claim.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DepositBody {
    binding_recipient: Vec<u8>,
    inner_envelope_bytes: Vec<u8>,
    inner_kind: u16,
    ttl_secs: u32,
    #[serde(default)]
    whitelist: Option<WhitelistAuth>,
}

/// Recipient-sponsored (whitelist) deposit auth — storage-sponsorship, NEVER
/// message-admission. Bound in `validate_deposit` to the authenticated sender.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WhitelistAuth {
    merkle_path: Vec<Vec<u8>>,
    whitelist_root: Vec<u8>,
}

/// kind-603 DRAIN body — how many held items to pull this batch (egress-capped
/// by the engine at `policy.max_drain_batch`). Re-draw after acking.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainBody {
    max: usize,
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Convert a length-validated 32-byte vec, or `None` on any other length.
fn to_32(v: &[u8]) -> Option<[u8; 32]> {
    v.try_into().ok()
}

/// Route a gate-passed relay-control UKM to the engine and return the reply
/// frame(s) to send back to the sender. Pure (no transport dependency) so the
/// routing + scoping is unit-testable without a live connection; `msg_handler`
/// sends the returned frames. All ops are scoped to `envelope.sender`.
pub(crate) async fn handle_relay_control(
    engine: &RelayEngine,
    envelope: &UkmEnvelope,
    relay_node_id: &NodeId,
) -> Vec<(NodeId, Frame)> {
    let sender = envelope.sender;
    let id = envelope.id;

    match envelope.recipient {
        Recipient::Node(node) if node == *relay_node_id => {}
        Recipient::Node(node) => {
            return reply(
                sender,
                reject(
                    id,
                    format!(
                        "relay control recipient mismatch: addressed to {node}, relay is {relay_node_id}"
                    ),
                ),
            )
        }
        _ => {
            return reply(
                sender,
                reject(id, "relay control: outer recipient must be this relay node".into()),
            )
        }
    }

    match envelope.kind {
        kind::KIND_RELAY_REGISTER => {
            let body: RegisterBody = match serde_json::from_slice(&envelope.ciphertext) {
                Ok(b) => b,
                Err(e) => return reply(sender, reject(id, format!("relay register body: {e}"))),
            };
            let binding_id: [u8; 16] = match body.binding_id.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    return reply(
                        sender,
                        reject(id, "relay register: binding_id must be 16 bytes".into()),
                    )
                }
            };
            let whitelist_root: [u8; 32] = match body.depositor_whitelist_root.as_slice().try_into()
            {
                Ok(a) => a,
                Err(_) => {
                    return reply(
                        sender,
                        reject(
                            id,
                            "relay register: depositor_whitelist_root must be 32 bytes".into(),
                        ),
                    )
                }
            };
            match engine
                .handle_register(
                    sender, // §0: owner is the authenticated sender, never a body field
                    binding_id,
                    body.quota_bytes,
                    body.ttl_max_secs,
                    whitelist_root,
                    body.created_at,
                    Instant::now(),
                )
                .await
            {
                Ok(()) => reply(sender, Frame::MessageAck { id }),
                Err(e) => reply(sender, reject(id, format!("relay register: {e:?}"))),
            }
        }
        kind::KIND_RELAY_ACK => {
            // `bounded_ack_ids` caps `message_ids` DURING parse (aborts at
            // cap + 1), so an oversized ack fails here as a parse error — no
            // attacker-sized Vec is ever materialized.
            let body: AckBody = match serde_json::from_slice(&envelope.ciphertext) {
                Ok(b) => b,
                Err(e) => return reply(sender, reject(id, format!("relay ack body: {e}"))),
            };
            match engine.handle_ack(sender, &body.message_ids).await {
                Ok(_count) => reply(sender, Frame::MessageAck { id }),
                Err(e) => reply(sender, reject(id, format!("relay ack: {e:?}"))),
            }
        }
        kind::KIND_RELAY_DEPOSIT => {
            let body: DepositBody = match serde_json::from_slice(&envelope.ciphertext) {
                Ok(b) => b,
                Err(e) => return reply(sender, reject(id, format!("relay deposit body: {e}"))),
            };
            let recipient = match to_32(&body.binding_recipient) {
                Some(a) => NodeId::from_bytes(a),
                None => {
                    return reply(
                        sender,
                        reject(
                            id,
                            "relay deposit: binding_recipient must be 32 bytes".into(),
                        ),
                    )
                }
            };
            let inner_envelope: UkmEnvelope =
                match serde_json::from_slice(&body.inner_envelope_bytes) {
                    Ok(env) => env,
                    Err(e) => {
                        return reply(
                            sender,
                            reject(
                                id,
                                format!("relay deposit: inner envelope parse failed: {e}"),
                            ),
                        )
                    }
                };
            // seam-4: the held item is keyed by its own `MessageId` (the recipient
            // acks by it). Bind that id to the ciphertext so the stored key IS the
            // canonical blake3(ciphertext‖nonce) — a depositor cannot plant a
            // forged/colliding id to strand quota or evict another deposit's hold
            // under this binding. This is an integrity check on the ack key only;
            // the inner sender→recipient PAYMENT is the recipient's to re-verify at
            // drain (FINDING-2) — the relay never does that admission work.
            if inner_envelope.id
                != MessageId::compute(&inner_envelope.ciphertext, &inner_envelope.nonce)
            {
                return reply(
                    sender,
                    reject(
                        id,
                        "relay deposit: inner envelope id must be blake3(ciphertext‖nonce)".into(),
                    ),
                );
            }
            if inner_envelope.kind != body.inner_kind {
                return reply(
                    sender,
                    reject(
                        id,
                        "relay deposit: inner_kind must match serialized inner envelope".into(),
                    ),
                );
            }
            if inner_envelope.recipient != Recipient::Node(recipient) {
                return reply(
                    sender,
                    reject(
                        id,
                        "relay deposit: inner envelope recipient must match binding_recipient"
                            .into(),
                    ),
                );
            }
            let auth = match body.whitelist {
                Some(w) => {
                    if w.merkle_path.len() > MAX_RELAY_WHITELIST_PROOF_DEPTH {
                        return reply(
                            sender,
                            reject(
                                id,
                                format!(
                                    "relay deposit: merkle_path exceeds {MAX_RELAY_WHITELIST_PROOF_DEPTH}"
                                ),
                            ),
                        );
                    }
                    let root = match to_32(&w.whitelist_root) {
                        Some(a) => a,
                        None => {
                            return reply(
                                sender,
                                reject(id, "relay deposit: whitelist_root must be 32 bytes".into()),
                            )
                        }
                    };
                    let mut path = Vec::with_capacity(w.merkle_path.len());
                    for h in &w.merkle_path {
                        match to_32(h) {
                            Some(a) => path.push(a),
                            None => {
                                return reply(
                                    sender,
                                    reject(
                                        id,
                                        "relay deposit: merkle_path node must be 32 bytes".into(),
                                    ),
                                )
                            }
                        }
                    }
                    DepositAuth::Whitelisted {
                        merkle_path: path,
                        whitelist_root: root,
                    }
                }
                // PAID path (D1 Q2-fold): the kind-601 UKM's OWN gate-verified
                // payment IS the storage rent — one settled HTLC, one durable
                // replay store (the message gate's). `validate_deposit` enforces
                // the byte-day floor against this gate-cross-checked amount.
                None => DepositAuth::GateSettled {
                    amount_msat: envelope.payment_proof.amount_msat,
                    payment_hash: envelope.payment_proof.payment_hash,
                },
            };
            match engine
                .handle_deposit(
                    sender, // §0: depositor is the authenticated sender, never a body field
                    recipient,
                    inner_envelope.id, // seam-4: held by its own MessageId for ack
                    body.inner_envelope_bytes,
                    inner_envelope.kind,
                    body.ttl_secs,
                    auth,
                    unix_secs(),
                )
                .await
            {
                Ok(_seq) => reply(sender, Frame::MessageAck { id }),
                Err(e) => reply(sender, reject(id, format!("relay deposit: {e:?}"))),
            }
        }
        kind::KIND_RELAY_DRAIN => {
            let body: DrainBody = match serde_json::from_slice(&envelope.ciphertext) {
                Ok(b) => b,
                Err(e) => return reply(sender, reject(id, format!("relay drain body: {e}"))),
            };
            // FINDING-2 (DOCTRINE-CRITICAL): the relay RETURNS held ciphertext; it
            // never admits. Each held envelope is re-injected to the drainer as a
            // normal `Frame::Message`, byte-identical to deposit (its original
            // sender→recipient `payment_proof` intact), so the recipient's OWN gate
            // re-verifies it (settled + recipient-bound-to-recipient + single-use).
            // The relay is pure transport across the offline hop — a held item whose
            // inner proof is unsettled/short/mis-addressed is rejected at the
            // recipient's gate, never by the relay. Egress is capped in the engine.
            let items = engine
                .handle_drain_request(sender, body.max, unix_secs())
                .await;
            let mut out: Vec<(NodeId, Frame)> = Vec::with_capacity(items.len());
            for item in items {
                match serde_json::from_slice::<UkmEnvelope>(&item.envelope_bytes) {
                    Ok(env) => out.push((sender, Frame::Message(Box::new(env)))),
                    Err(e) => {
                        // A held item that doesn't deserialize to a UkmEnvelope
                        // cannot be re-injected through the gate; skip it
                        // (fail-closed, never crash). The depositor supplied
                        // malformed bytes; the recipient simply never receives it.
                        warn!(
                            sequence = item.sequence,
                            error = %e,
                            "skipping undeserializable held envelope at drain"
                        );
                    }
                }
            }
            if out.is_empty() {
                // Nothing deliverable — ack so the drainer knows the drain ran.
                out.push((sender, Frame::MessageAck { id }));
            }
            out
        }
        kind::KIND_RELAY_UNREGISTER => {
            // §0: the binding owner is the authenticated sender; revoking its own
            // binding needs no body. Killing the registration trap = revocability.
            match engine.handle_unregister(sender).await {
                Ok(()) => reply(sender, Frame::MessageAck { id }),
                Err(e) => reply(sender, reject(id, format!("relay unregister: {e:?}"))),
            }
        }
        other => reply(sender, reject(id, format!("unsupported relay kind {other}"))),
    }
}

fn reply(peer: NodeId, frame: Frame) -> Vec<(NodeId, Frame)> {
    vec![(peer, frame)]
}

fn reject(id: MessageId, reason: String) -> Frame {
    Frame::MessageReject { id, reason }
}

#[cfg(test)]
mod tests;
