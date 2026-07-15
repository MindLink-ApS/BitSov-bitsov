use super::*;
use crate::relay::store::RelayBindingStore;
use crate::relay::{InMemoryRelayStore, RelayEngine, RelayPolicy};
use konsensus_core::types::{NodeId, PaymentProof, Recipient, RoomId};
use konsensus_core::{UkmEnvelope, UkmEnvelopeBuilder};
use std::sync::Arc;

fn node(b: u8) -> NodeId {
    NodeId::from_bytes([b; 32])
}

fn relay_node() -> NodeId {
    node(9)
}

fn setup() -> (RelayEngine, Arc<InMemoryRelayStore>) {
    let store = Arc::new(InMemoryRelayStore::new());
    let eng = RelayEngine::new(store.clone(), RelayPolicy::inert_default());
    (eng, store)
}

/// Build a relay-control UKM. The dispatch runs AFTER the gate, so it reads only
/// `kind` / `sender` / `id` / `ciphertext`; the (dummy) proof/signature are never
/// re-checked here.
fn ctrl(kind: u16, sender: NodeId, ciphertext: Vec<u8>) -> UkmEnvelope {
    ctrl_to(kind, sender, Recipient::Node(relay_node()), ciphertext)
}

fn ctrl_to(kind: u16, sender: NodeId, recipient: Recipient, ciphertext: Vec<u8>) -> UkmEnvelope {
    let proof = PaymentProof::new([1u8; 32], [2u8; 32], 100);
    UkmEnvelopeBuilder::new(kind, sender, recipient, ciphertext, proof).build()
}

async fn dispatch(eng: &RelayEngine, env: &UkmEnvelope) -> Vec<(NodeId, Frame)> {
    handle_relay_control(eng, env, &relay_node()).await
}

fn register_body(binding_id: Vec<u8>, root: Vec<u8>) -> Vec<u8> {
    serde_json::to_vec(&RegisterBody {
        binding_id,
        quota_bytes: 100_000,
        ttl_max_secs: 3600,
        depositor_whitelist_root: root,
        created_at: 1,
    })
    .unwrap()
}

fn is_ack(replies: &[(NodeId, Frame)], to: NodeId) -> bool {
    matches!(replies, [(peer, Frame::MessageAck { .. })] if *peer == to)
}

fn is_reject(replies: &[(NodeId, Frame)], to: NodeId) -> bool {
    matches!(replies, [(peer, Frame::MessageReject { .. })] if *peer == to)
}

#[tokio::test]
async fn register_acks_and_creates_binding_scoped_to_sender() {
    let (eng, store) = setup();
    let a = node(1);
    let env = ctrl(
        kind::KIND_RELAY_REGISTER,
        a,
        register_body(vec![0u8; 16], vec![0u8; 32]),
    );
    let replies = dispatch(&eng, &env).await;
    assert!(is_ack(&replies, a), "register should ack to the sender");
    // The binding is owned by the AUTHENTICATED sender (§0), readable at that key.
    let binding = store.get_binding(&a).await;
    assert!(
        binding.is_some(),
        "binding created under the sender's NodeId"
    );
    assert_eq!(binding.unwrap().recipient, a);
}

#[tokio::test]
async fn register_owner_is_sender_not_a_body_field_t_auth() {
    // Two distinct senders register. Each binding is keyed by its own
    // authenticated sender — the body carries no owner NodeId, so neither peer
    // can open a binding owned by the other (AUTHENTICATED-SENDER-ONLY, §0).
    let (eng, store) = setup();
    let a = node(1);
    let b = node(2);
    let body = register_body(vec![0u8; 16], vec![0u8; 32]);
    assert!(is_ack(
        &dispatch(&eng, &ctrl(kind::KIND_RELAY_REGISTER, a, body.clone())).await,
        a
    ));
    assert!(is_ack(
        &dispatch(&eng, &ctrl(kind::KIND_RELAY_REGISTER, b, body)).await,
        b
    ));
    assert_eq!(store.get_binding(&a).await.unwrap().recipient, a);
    assert_eq!(store.get_binding(&b).await.unwrap().recipient, b);
}

#[tokio::test]
async fn ack_is_idempotent_within_own_binding() {
    let (eng, _store) = setup();
    let a = node(1);
    // Open the binding first — ack is scoped to the sender's OWN binding; without
    // one the engine returns BindingNotFound (a reject, not a silent success).
    assert!(is_ack(
        &dispatch(
            &eng,
            &ctrl(
                kind::KIND_RELAY_REGISTER,
                a,
                register_body(vec![0u8; 16], vec![0u8; 32]),
            ),
        )
        .await,
        a
    ));
    // Acking MessageIds that aren't held is a no-op success (idempotent delete).
    let body = serde_json::to_vec(&AckBody {
        message_ids: vec![
            MessageId::from_bytes([1u8; 32]),
            MessageId::from_bytes([2u8; 32]),
        ],
    })
    .unwrap();
    let replies = dispatch(&eng, &ctrl(kind::KIND_RELAY_ACK, a, body)).await;
    assert!(is_ack(&replies, a));
}

// An ack carrying more than MAX_RELAY_ACK_IDS message_ids fails DURING parse
// (the bounded_ack_ids streaming visitor aborts at cap + 1, never materializing
// an attacker-sized Vec — Codex #2 / HARD-1 doctrine). The boundary value
// (exactly the cap) parses and is accepted.
#[tokio::test]
async fn ack_rejects_oversized_message_ids_t_cap() {
    let (eng, _store) = setup();
    let a = node(1);
    // Open a binding so the cap — not BindingNotFound — is what fires.
    assert!(is_ack(
        &dispatch(
            &eng,
            &ctrl(
                kind::KIND_RELAY_REGISTER,
                a,
                register_body(vec![0u8; 16], vec![0u8; 32]),
            ),
        )
        .await,
        a
    ));
    let ids = |n: usize| -> Vec<u8> {
        serde_json::to_vec(&AckBody {
            message_ids: (0..n)
                .map(|i| MessageId::from_bytes([(i % 256) as u8; 32]))
                .collect(),
        })
        .unwrap()
    };
    // One over the cap → reject.
    let over = ctrl(kind::KIND_RELAY_ACK, a, ids(MAX_RELAY_ACK_IDS + 1));
    assert!(is_reject(&dispatch(&eng, &over).await, a));
    // Exactly the cap → still accepted (idempotent no-op; none are held).
    let at_cap = ctrl(kind::KIND_RELAY_ACK, a, ids(MAX_RELAY_ACK_IDS));
    assert!(is_ack(&dispatch(&eng, &at_cap).await, a));
}

#[tokio::test]
async fn malformed_register_body_is_rejected_not_panicked() {
    let (eng, _store) = setup();
    let a = node(1);
    let replies = dispatch(
        &eng,
        &ctrl(kind::KIND_RELAY_REGISTER, a, b"not json".to_vec()),
    )
    .await;
    assert!(
        is_reject(&replies, a),
        "garbage body must reject, never panic"
    );
}

#[tokio::test]
async fn wrong_length_binding_id_is_rejected() {
    let (eng, _store) = setup();
    let a = node(1);
    // binding_id is 8 bytes, not 16 — structural length check fails closed.
    let replies = dispatch(
        &eng,
        &ctrl(
            kind::KIND_RELAY_REGISTER,
            a,
            register_body(vec![0u8; 8], vec![0u8; 32]),
        ),
    )
    .await;
    assert!(is_reject(&replies, a));
}

/// T-REVOKE (seam-6) — a recipient revokes its OWN binding (kind-604). After the
/// revoke the binding is gone: a deposit addressed to it now rejects (no binding),
/// so registration is no longer a trap. Revoking nothing is a reject, never a
/// silent success.
#[tokio::test]
async fn unregister_revokes_own_binding_t_revoke() {
    let (eng, _store) = setup();
    let a = node(1);
    register(&eng, a).await;
    // A deposit to a's binding would be held while the binding exists (covered by
    // deposit tests). Revoke it.
    assert!(
        is_ack(&dispatch(&eng, &ctrl(kind::KIND_RELAY_UNREGISTER, a, b"{}".to_vec())).await, a),
        "unregister of own binding acks"
    );
    // The binding is gone: a deposit addressed to a now rejects (no binding).
    let dep = ctrl(
        kind::KIND_RELAY_DEPOSIT,
        node(2),
        deposit_body(a, inner_envelope_bytes(a, 0, 10), 0, 3600),
    );
    assert!(
        is_reject(&dispatch(&eng, &dep).await, node(2)),
        "deposit after revoke rejects — binding really gone"
    );
    // Revoking again rejects (nothing to revoke), never a silent success.
    assert!(is_reject(
        &dispatch(&eng, &ctrl(kind::KIND_RELAY_UNREGISTER, a, b"{}".to_vec())).await,
        a
    ));
}

/// §0: unregister is scoped to the authenticated sender — revoking a's binding
/// never touches b's.
#[tokio::test]
async fn unregister_scoped_to_sender_t_auth() {
    let (eng, _store) = setup();
    let a = node(1);
    let b = node(2);
    register(&eng, a).await;
    register(&eng, b).await;
    assert!(is_ack(
        &dispatch(&eng, &ctrl(kind::KIND_RELAY_UNREGISTER, a, b"{}".to_vec())).await,
        a
    ));
    // b's binding is intact: a deposit addressed to b is still held.
    let dep = ctrl(
        kind::KIND_RELAY_DEPOSIT,
        node(7),
        deposit_body(b, inner_envelope_bytes(b, 0, 10), 0, 3600),
    );
    assert!(
        is_ack(&dispatch(&eng, &dep).await, node(7)),
        "b's binding survives a's unregister"
    );
}

#[tokio::test]
async fn unsupported_storage_kind_is_rejected() {
    let (eng, _store) = setup();
    let a = node(1);
    // 650 is Storage-category (600-699) but not a defined relay-control kind.
    let replies = dispatch(&eng, &ctrl(650, a, b"{}".to_vec())).await;
    assert!(is_reject(&replies, a));
}

#[tokio::test]
async fn relay_control_requires_outer_recipient_to_be_this_relay_node() {
    let (eng, _store) = setup();
    let a = node(1);
    let body = register_body(vec![0u8; 16], vec![0u8; 32]);

    let wrong_node = ctrl_to(
        kind::KIND_RELAY_REGISTER,
        a,
        Recipient::Node(node(8)),
        body.clone(),
    );
    assert!(is_reject(&dispatch(&eng, &wrong_node).await, a));

    let room = ctrl_to(
        kind::KIND_RELAY_REGISTER,
        a,
        Recipient::Room(RoomId::new()),
        body,
    );
    assert!(is_reject(&dispatch(&eng, &room).await, a));
}

// ── kind-601 DEPOSIT (D1 Q2-fold) ────────────────────────────────────────────

fn deposit_body(recipient: NodeId, inner: Vec<u8>, inner_kind: u16, ttl: u32) -> Vec<u8> {
    serde_json::to_vec(&DepositBody {
        binding_recipient: recipient.as_bytes().to_vec(),
        inner_envelope_bytes: inner,
        inner_kind,
        ttl_secs: ttl,
        whitelist: None,
    })
    .unwrap()
}

fn inner_envelope_bytes(recipient: NodeId, kind: u16, payload_len: usize) -> Vec<u8> {
    let inner = UkmEnvelopeBuilder::new(
        kind,
        node(7),
        Recipient::Node(recipient),
        vec![7u8; payload_len],
        PaymentProof::new([3u8; 32], [4u8; 32], 100),
    )
    .build();
    serde_json::to_vec(&inner).unwrap()
}

fn inner_envelope_bytes_to(recipient: Recipient, kind: u16, payload_len: usize) -> Vec<u8> {
    let inner = UkmEnvelopeBuilder::new(
        kind,
        node(7),
        recipient,
        vec![7u8; payload_len],
        PaymentProof::new([3u8; 32], [4u8; 32], 100),
    )
    .build();
    serde_json::to_vec(&inner).unwrap()
}

async fn register(eng: &RelayEngine, r: NodeId) {
    assert!(is_ack(
        &dispatch(
            eng,
            &ctrl(
                kind::KIND_RELAY_REGISTER,
                r,
                register_body(vec![0u8; 16], vec![0u8; 32]),
            ),
        )
        .await,
        r
    ));
}

#[tokio::test]
async fn deposit_paid_meets_floor_is_held() {
    let (eng, store) = setup();
    let depositor = node(1);
    let recipient = node(2);
    register(&eng, recipient).await;
    // ctrl()'s payment is 100 msat; serialized inner size · ttl stays below 100.
    let env = ctrl(
        kind::KIND_RELAY_DEPOSIT,
        depositor,
        deposit_body(recipient, inner_envelope_bytes(recipient, 0, 10), 0, 3600),
    );
    let replies = dispatch(&eng, &env).await;
    assert!(is_ack(&replies, depositor));
    assert_eq!(store.list_held(&recipient, 10, 0).await.len(), 1);
}

#[tokio::test]
async fn deposit_below_storage_floor_is_rejected() {
    let (eng, store) = setup();
    let depositor = node(1);
    let recipient = node(2);
    register(&eng, recipient).await;
    // 100_000 bytes · ttl 3600 · rate 1 / 86400 ⇒ floor ≈ 4167 msat > the 100 paid.
    let env = ctrl(
        kind::KIND_RELAY_DEPOSIT,
        depositor,
        deposit_body(
            recipient,
            inner_envelope_bytes(recipient, 0, 100_000),
            0,
            3600,
        ),
    );
    assert!(is_reject(&dispatch(&eng, &env).await, depositor));
    assert_eq!(store.list_held(&recipient, 10, 0).await.len(), 0);
}

#[tokio::test]
async fn deposit_without_binding_is_rejected() {
    let (eng, _store) = setup();
    let depositor = node(1);
    let recipient = node(2); // never registered
    let env = ctrl(
        kind::KIND_RELAY_DEPOSIT,
        depositor,
        deposit_body(recipient, inner_envelope_bytes(recipient, 0, 10), 0, 3600),
    );
    assert!(is_reject(&dispatch(&eng, &env).await, depositor));
}

/// T-PAY1 — the D1 in-band path folds the deposit UKM's OWN gate-verified payment
/// as the rent: it does NOT run a second settlement check. The mock backend has
/// no record of ctrl()'s payment_hash, yet the deposit is held — proving the
/// relay trusts the (already-gate-verified) payment and queries Lightning ZERO
/// extra times (one settled HTLC, no second replay store).
#[tokio::test]
async fn deposit_gate_settled_skips_second_settlement_check_t_pay1() {
    let (eng, store) = setup();
    let depositor = node(1);
    let recipient = node(2);
    register(&eng, recipient).await;
    // ctrl()'s payment_hash ([1u8;32]) is unknown to the relay's backend; the old
    // Prepaid path would NotFound-reject it. GateSettled accepts it.
    let env = ctrl(
        kind::KIND_RELAY_DEPOSIT,
        depositor,
        deposit_body(recipient, inner_envelope_bytes(recipient, 0, 10), 0, 3600),
    );
    assert!(is_ack(&dispatch(&eng, &env).await, depositor));
    assert_eq!(store.list_held(&recipient, 10, 0).await.len(), 1);
}

#[tokio::test]
async fn deposit_disallowed_inner_kind_is_rejected() {
    let (eng, _store) = setup();
    let depositor = node(1);
    let recipient = node(2);
    register(&eng, recipient).await;
    // inner_kind 999 is not in the inert default allow-list ([CHAT=0, FILE_REF=200]).
    let env = ctrl(
        kind::KIND_RELAY_DEPOSIT,
        depositor,
        deposit_body(
            recipient,
            inner_envelope_bytes(recipient, 999, 10),
            999,
            3600,
        ),
    );
    assert!(is_reject(&dispatch(&eng, &env).await, depositor));
}

#[tokio::test]
async fn deposit_rejects_claimed_kind_bypass_against_inner_envelope() {
    let (eng, _store) = setup();
    let depositor = node(1);
    let recipient = node(2);
    register(&eng, recipient).await;
    // Regression: depositor may not claim allowed kind=0 while the serialized
    // inner envelope is actually disallowed kind=999.
    let env = ctrl(
        kind::KIND_RELAY_DEPOSIT,
        depositor,
        deposit_body(recipient, inner_envelope_bytes(recipient, 999, 10), 0, 3600),
    );
    assert!(is_reject(&dispatch(&eng, &env).await, depositor));
}

#[tokio::test]
async fn deposit_inner_recipient_must_match_binding_recipient() {
    let (eng, _store) = setup();
    let depositor = node(1);
    let recipient = node(2);
    register(&eng, recipient).await;
    let env = ctrl(
        kind::KIND_RELAY_DEPOSIT,
        depositor,
        deposit_body(recipient, inner_envelope_bytes(node(3), 0, 10), 0, 3600),
    );
    assert!(is_reject(&dispatch(&eng, &env).await, depositor));
}

#[tokio::test]
async fn deposit_rejects_oversized_whitelist_merkle_path_before_engine() {
    let (eng, _store) = setup();
    let depositor = node(1);
    let recipient = node(2);
    register(&eng, recipient).await;
    let body = serde_json::to_vec(&DepositBody {
        binding_recipient: recipient.as_bytes().to_vec(),
        inner_envelope_bytes: inner_envelope_bytes(recipient, 0, 10),
        inner_kind: 0,
        ttl_secs: 3600,
        whitelist: Some(WhitelistAuth {
            merkle_path: vec![vec![0u8; 32]; MAX_RELAY_WHITELIST_PROOF_DEPTH + 1],
            whitelist_root: vec![0u8; 32],
        }),
    })
    .unwrap();
    let env = ctrl(kind::KIND_RELAY_DEPOSIT, depositor, body);
    assert!(is_reject(&dispatch(&eng, &env).await, depositor));
}

// ── kind-603 DRAIN (FINDING-2 re-injection) ──────────────────────────────────

fn setup_drain_cap(batch: usize) -> (RelayEngine, Arc<InMemoryRelayStore>) {
    let store = Arc::new(InMemoryRelayStore::new());
    let mut p = RelayPolicy::inert_default();
    p.max_drain_batch = batch;
    (RelayEngine::new(store.clone(), p), store)
}

/// A real sealed sender→recipient envelope (kind 0), as a depositor would hand it
/// to the relay — serialized with serde_json (the envelope wire codec).
fn inner_envelope(sender: NodeId, recipient: NodeId) -> UkmEnvelope {
    let proof = PaymentProof::new([3u8; 32], [4u8; 32], 50);
    UkmEnvelopeBuilder::new(0, sender, Recipient::Node(recipient), b"sealed-ct".to_vec(), proof)
        .build()
}

fn drain_body(max: usize) -> Vec<u8> {
    serde_json::to_vec(&DrainBody { max }).unwrap()
}

async fn deposit_envelope(eng: &RelayEngine, depositor: NodeId, recipient: NodeId, inner: &UkmEnvelope) {
    let bytes = serde_json::to_vec(inner).unwrap();
    let env = ctrl(
        kind::KIND_RELAY_DEPOSIT,
        depositor,
        deposit_body(recipient, bytes, 0, 3600),
    );
    assert!(is_ack(&dispatch(eng, &env).await, depositor), "deposit ack");
}

/// T-DRAIN1 (DOCTRINE KEYSTONE) — the relay re-injects the held envelope to the
/// drainer as a `Frame::Message`, **byte-identical to deposit** (its original
/// sender→recipient `payment_proof` intact). The relay never strips/alters the
/// proof, so the recipient's OWN gate re-verifies the real inner payment — the
/// relay is pure transport, never an admitter.
#[tokio::test]
async fn drain_reinjects_held_envelope_byte_identical_t_drain1() {
    let (eng, _store) = setup();
    let original_sender = node(5);
    let recipient = node(2);
    register(&eng, recipient).await;
    let inner = inner_envelope(original_sender, recipient);
    deposit_envelope(&eng, node(1), recipient, &inner).await;

    // The recipient drains (kind-603 sender = recipient).
    let replies = dispatch(&eng, &ctrl(kind::KIND_RELAY_DRAIN, recipient, drain_body(10))).await;
    match replies.as_slice() {
        [(peer, Frame::Message(env))] => {
            assert_eq!(*peer, recipient, "re-injected to the drainer");
            assert_eq!(**env, inner, "held envelope returned byte-identical (proof intact)");
            assert_eq!(env.payment_proof, inner.payment_proof, "inner proof preserved");
        }
        other => panic!("expected one re-injected Frame::Message, got {other:?}"),
    }
}

/// T-ACK (seam-4) — the recipient acks by the `MessageId` a drain re-injected to
/// it (its only handle; it never learns the relay's internal sequence). The relay
/// deletes the held item by that id and frees quota, so a re-drain is empty. This
/// closes the FINDING (ack-by-sequence was impossible: the recipient never sees
/// the sequence).
#[tokio::test]
async fn drain_then_ack_by_message_id_frees_quota_t_ack() {
    let (eng, store) = setup();
    let recipient = node(2);
    register(&eng, recipient).await;
    let inner = inner_envelope(node(5), recipient);
    deposit_envelope(&eng, node(1), recipient, &inner).await;

    // Drain → the recipient receives the envelope and reads its id.
    let drained = dispatch(&eng, &ctrl(kind::KIND_RELAY_DRAIN, recipient, drain_body(10))).await;
    let acked_id = match drained.as_slice() {
        [(_, Frame::Message(env))] => env.id,
        other => panic!("expected one drained Frame::Message, got {other:?}"),
    };
    assert_eq!(store.list_held(&recipient, 10, unix_secs()).await.len(), 1);

    // Ack by that MessageId (kind-602, sender = recipient = binding owner).
    let ack = serde_json::to_vec(&AckBody {
        message_ids: vec![acked_id],
    })
    .unwrap();
    let replies = dispatch(&eng, &ctrl(kind::KIND_RELAY_ACK, recipient, ack)).await;
    assert!(is_ack(&replies, recipient), "ack-by-MessageId acks");

    // The held item is gone and its quota freed; a re-drain returns nothing.
    assert!(store.list_held(&recipient, 10, unix_secs()).await.is_empty());
    let redrain = dispatch(&eng, &ctrl(kind::KIND_RELAY_DRAIN, recipient, drain_body(10))).await;
    assert!(is_ack(&redrain, recipient), "post-ack re-drain is empty");
}

#[tokio::test]
async fn drain_egress_is_capped() {
    let (eng, _store) = setup_drain_cap(2);
    let recipient = node(2);
    register(&eng, recipient).await;
    for _ in 0..3 {
        deposit_envelope(&eng, node(1), recipient, &inner_envelope(node(5), recipient)).await;
    }
    // Ask for 10 but the egress cap (2) bounds it.
    let replies = dispatch(&eng, &ctrl(kind::KIND_RELAY_DRAIN, recipient, drain_body(10))).await;
    assert!(replies.len() <= 2, "drain egress capped at max_drain_batch");
    assert!(replies
        .iter()
        .all(|(_, f)| matches!(f, Frame::Message(_))));
}

#[tokio::test]
async fn drain_empty_binding_acks() {
    let (eng, _store) = setup();
    let recipient = node(2);
    register(&eng, recipient).await;
    let replies = dispatch(&eng, &ctrl(kind::KIND_RELAY_DRAIN, recipient, drain_body(10))).await;
    assert!(is_ack(&replies, recipient), "empty drain acks");
}

#[tokio::test]
async fn deposit_rejects_undeserializable_inner_envelope() {
    let (eng, _store) = setup();
    let recipient = node(2);
    register(&eng, recipient).await;
    // #284 hardening: malformed inner bytes are rejected at deposit time, so
    // quota cannot be stranded by an item that can never re-enter the gate.
    let env = ctrl(
        kind::KIND_RELAY_DEPOSIT,
        node(1),
        deposit_body(recipient, vec![7u8; 10], 0, 3600),
    );
    assert!(is_reject(&dispatch(&eng, &env).await, node(1)));
}

/// seam-4: the hold (and the recipient's ack) is keyed on the inner envelope's
/// own `MessageId`. A depositor cannot plant an envelope whose `id` field is not
/// the canonical blake3(ciphertext‖nonce) — that would let a forged/colliding id
/// strand quota or evict another deposit's hold under the binding.
#[tokio::test]
async fn deposit_rejects_forged_inner_envelope_id() {
    let (eng, store) = setup();
    let depositor = node(1);
    let recipient = node(2);
    register(&eng, recipient).await;
    let mut inner = UkmEnvelopeBuilder::new(
        0,
        node(7),
        Recipient::Node(recipient),
        vec![7u8; 10],
        PaymentProof::new([3u8; 32], [4u8; 32], 100),
    )
    .build();
    inner.id = MessageId::from_bytes([0xFF; 32]); // forged: ≠ blake3(ct‖nonce)
    let env = ctrl(
        kind::KIND_RELAY_DEPOSIT,
        depositor,
        deposit_body(recipient, serde_json::to_vec(&inner).unwrap(), 0, 3600),
    );
    assert!(is_reject(&dispatch(&eng, &env).await, depositor));
    assert!(store.list_held(&recipient, 10, unix_secs()).await.is_empty());
}

#[tokio::test]
async fn drain_scoped_to_sender_t_auth() {
    let (eng, _store) = setup();
    let r1 = node(2);
    let r2 = node(3);
    register(&eng, r1).await;
    register(&eng, r2).await;
    deposit_envelope(&eng, node(1), r1, &inner_envelope(node(5), r1)).await;
    // r2 drains: cannot see r1's held mail (store keyed by authenticated sender).
    let replies = dispatch(&eng, &ctrl(kind::KIND_RELAY_DRAIN, r2, drain_body(10))).await;
    assert!(is_ack(&replies, r2), "r2 has no holds → empty ack, never r1's mail");
}
