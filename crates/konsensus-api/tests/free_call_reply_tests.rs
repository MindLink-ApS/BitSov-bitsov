//! Receiving side of free call replies (`[calls] call_reply_free_v1`): the
//! caller's node accepts an answer, or a declined hangup, at no charge only
//! when it replies to the caller's own ringing offer to that exact peer and
//! call, and only while the switch is on. Every other shape meets the price
//! floor exactly as before.

use konsensus_api::calls;
use konsensus_core::kind::{KIND_CALL_ANSWER, KIND_CALL_HANGUP, KIND_CALL_INVITE, KIND_ICE_CANDIDATE};
use konsensus_core::payloads::call::{free_reply_reference, is_free_reply_shape, CallRefusal, Phase, Side};
use konsensus_core::{MessageId, NodeId, NodeIdentity, PaymentProof, Recipient, UkmEnvelope, UkmEnvelopeBuilder};
use konsensus_storage::{SqliteStorage, Storage};
use serde_json::json;
use sha2::{Digest, Sha256};

const CALL: &str = "0123456789abcdef0123456789abcdef";
const OTHER_CALL: &str = "fedcba9876543210fedcba9876543210";

struct Fx {
    store: SqliteStorage,
    own: NodeId,
    callee: NodeIdentity,
}

/// This node placed `CALL` to the callee: the offer was paid, its id bound,
/// and the call is ringing.
async fn ringing() -> Fx {
    let store = SqliteStorage::in_memory().await.unwrap();
    let own = *NodeIdentity::generate().unwrap().1.node_id();
    let (_, callee) = NodeIdentity::generate().unwrap();
    let offer = json!({"v": 1, "call_id": CALL, "sdp": "offer", "media": "audio"}).to_string();
    calls::reserve_outgoing(&store, &own, callee.node_id(), KIND_CALL_INVITE, &offer, "offer-op", "offer-hash")
        .await
        .unwrap();
    calls::commit_outgoing(&store, callee.node_id(), &offer, "offer-op", "offer-hash").await.unwrap();
    store.call_offer_bind(callee.node_id(), CALL, &MessageId::from_bytes([4; 32])).await.unwrap();
    let entry = store.call_get(callee.node_id(), CALL).await.unwrap().unwrap();
    assert_eq!((entry.side, entry.phase), (Side::Caller, Phase::Ringing));
    Fx { store, own, callee }
}

fn proof(amount_msat: u64) -> PaymentProof {
    let preimage = [9u8; 32];
    PaymentProof::new(Sha256::digest(preimage).into(), preimage, amount_msat)
}

fn reply(from: &NodeIdentity, to: &NodeId, kind: u16, amount_msat: u64, references: Vec<MessageId>) -> UkmEnvelope {
    let mut envelope = UkmEnvelopeBuilder::new(kind, *from.node_id(), Recipient::Node(*to), b"sealed".to_vec(), proof(amount_msat))
        .references(references)
        .build();
    envelope.signature = konsensus_core::Signature::from_ed25519(&from.sign(&envelope.signable_bytes()));
    envelope
}

fn now() -> u64 {
    calls::now_ms()
}

async fn bound(fx: &Fx, enabled: bool, envelope: &UkmEnvelope, at: u64) -> bool {
    calls::free_reply_bound(enabled, &fx.store, envelope, at).await.unwrap()
}

#[tokio::test]
async fn offer_bound_answer_and_decline_are_free_only_for_our_ringing_offer() {
    let fx = ringing().await;
    let reference = free_reply_reference(CALL);
    let answer = reply(&fx.callee, &fx.own, KIND_CALL_ANSWER, 0, vec![reference]);
    let decline = reply(&fx.callee, &fx.own, KIND_CALL_HANGUP, 0, vec![reference]);
    assert!(is_free_reply_shape(&answer) && is_free_reply_shape(&decline));
    assert!(bound(&fx, true, &answer, now()).await, "the callee's answer to our ringing offer is free");
    assert!(bound(&fx, true, &decline, now()).await, "the callee's decline of our ringing offer is free");

    // Off: never free, whatever the shape.
    assert!(!bound(&fx, false, &answer, now()).await);
    assert!(!bound(&fx, false, &decline, now()).await);

    // Wrong peer, wrong call, other kinds, any payment, extra references.
    let (_, stranger) = NodeIdentity::generate().unwrap();
    assert!(!bound(&fx, true, &reply(&stranger, &fx.own, KIND_CALL_ANSWER, 0, vec![reference]), now()).await);
    assert!(!bound(&fx, true, &reply(&fx.callee, &fx.own, KIND_CALL_ANSWER, 0, vec![free_reply_reference(OTHER_CALL)]), now()).await);
    assert!(!bound(&fx, true, &reply(&fx.callee, &fx.own, KIND_CALL_ANSWER, 0, vec![MessageId::from_bytes([4; 32])]), now()).await);
    assert!(!bound(&fx, true, &reply(&fx.callee, &fx.own, KIND_ICE_CANDIDATE, 0, vec![reference]), now()).await);
    assert!(!bound(&fx, true, &reply(&fx.callee, &fx.own, KIND_CALL_INVITE, 0, vec![reference]), now()).await);
    assert!(!bound(&fx, true, &reply(&fx.callee, &fx.own, KIND_CALL_ANSWER, 1_000, vec![reference]), now()).await);
    assert!(!bound(&fx, true, &reply(&fx.callee, &fx.own, KIND_CALL_ANSWER, 0, vec![reference, reference]), now()).await);
    assert!(!bound(&fx, true, &reply(&fx.callee, &fx.own, KIND_CALL_ANSWER, 0, vec![]), now()).await);

    // Late: after the ring window the offer is no longer outstanding.
    let entry = fx.store.call_get(fx.callee.node_id(), CALL).await.unwrap().unwrap();
    assert!(!bound(&fx, true, &answer, entry.deadline_ms + 1).await, "a reply after the ring window is not free");
}

#[tokio::test]
async fn a_reply_after_the_call_left_ringing_or_without_a_bound_offer_is_not_free() {
    // Once answered, neither a second answer nor a decline is free.
    let fx = ringing().await;
    let answer = reply(&fx.callee, &fx.own, KIND_CALL_ANSWER, 0, vec![free_reply_reference(CALL)]);
    calls::admit_incoming(&fx.store, &fx.own, fx.callee.node_id(), KIND_CALL_ANSWER,
        Some(&json!({"v": 1, "call_id": CALL, "sdp": "answer"}).to_string())).await.unwrap();
    assert!(!bound(&fx, true, &answer, now()).await, "a second answer is not free");
    assert!(!bound(&fx, true, &reply(&fx.callee, &fx.own, KIND_CALL_HANGUP, 0, vec![free_reply_reference(CALL)]), now()).await);

    // A ringing row whose paid offer was never bound is not ours to reply to.
    let store = SqliteStorage::in_memory().await.unwrap();
    let own = *NodeIdentity::generate().unwrap().1.node_id();
    let (_, callee) = NodeIdentity::generate().unwrap();
    let offer = json!({"v": 1, "call_id": CALL, "sdp": "offer", "media": "audio"}).to_string();
    calls::reserve_outgoing(&store, &own, callee.node_id(), KIND_CALL_INVITE, &offer, "op", "hash").await.unwrap();
    calls::commit_outgoing(&store, callee.node_id(), &offer, "op", "hash").await.unwrap();
    let unbound = Fx { store, own, callee };
    let answer = reply(&unbound.callee, &unbound.own, KIND_CALL_ANSWER, 0, vec![free_reply_reference(CALL)]);
    assert!(!bound(&unbound, true, &answer, now()).await);

    // No call at all: an unsolicited reply is not free.
    let store = SqliteStorage::in_memory().await.unwrap();
    let nobody = Fx { store, own, callee: NodeIdentity::generate().unwrap().1 };
    let answer = reply(&nobody.callee, &nobody.own, KIND_CALL_ANSWER, 0, vec![free_reply_reference(CALL)]);
    assert!(!bound(&nobody, true, &answer, now()).await);

    // On the callee's own side the row is not an offer this node made.
    let store = SqliteStorage::in_memory().await.unwrap();
    let (_, caller) = NodeIdentity::generate().unwrap();
    calls::admit_incoming(&store, &own, caller.node_id(), KIND_CALL_INVITE,
        Some(&json!({"v": 1, "call_id": CALL, "sdp": "offer", "media": "audio"}).to_string())).await.unwrap();
    let callee_side = Fx { store, own, callee: caller };
    let answer = reply(&callee_side.callee, &callee_side.own, KIND_CALL_ANSWER, 0, vec![free_reply_reference(CALL)]);
    assert!(!bound(&callee_side, true, &answer, now()).await);
}

#[tokio::test]
async fn a_free_reply_payload_must_be_exactly_the_bound_answer_or_decline() {
    let fx = ringing().await;
    let reference = free_reply_reference(CALL);
    let answer = reply(&fx.callee, &fx.own, KIND_CALL_ANSWER, 0, vec![reference]);
    let decline = reply(&fx.callee, &fx.own, KIND_CALL_HANGUP, 0, vec![reference]);
    let text = |v: serde_json::Value| v.to_string();
    assert_eq!(calls::check_free_reply(&fx.store, &answer,
        Some(&text(json!({"v": 1, "call_id": CALL, "sdp": "answer"})))).await, Ok(()));
    assert_eq!(calls::check_free_reply(&fx.store, &decline,
        Some(&text(json!({"v": 1, "call_id": CALL, "reason": "declined"})))).await, Ok(()));
    // Another call id inside, any other hangup reason, or no readable payload.
    assert!(calls::check_free_reply(&fx.store, &answer,
        Some(&text(json!({"v": 1, "call_id": OTHER_CALL, "sdp": "answer"})))).await.is_err());
    for reason in ["hangup", "busy", "unpaid"] {
        assert!(calls::check_free_reply(&fx.store, &decline,
            Some(&text(json!({"v": 1, "call_id": CALL, "reason": reason})))).await.is_err(), "{reason}");
    }
    assert_eq!(calls::check_free_reply(&fx.store, &answer, None).await, Err(CallRefusal::Invalid("undecryptable")));
    // A paid reply is not checked here: it took the ordinary path.
    let paid = reply(&fx.callee, &fx.own, KIND_CALL_HANGUP, 1_000, vec![]);
    assert_eq!(calls::check_free_reply(&fx.store, &paid,
        Some(&text(json!({"v": 1, "call_id": CALL, "reason": "hangup"})))).await, Ok(()));
}

#[tokio::test]
async fn a_free_answer_that_raced_the_ring_window_is_withdrawn_after_decryption() {
    // Bound at the gate while ringing; the window closes before admission.
    let fx = ringing().await;
    let answer = reply(&fx.callee, &fx.own, KIND_CALL_ANSWER, 0, vec![free_reply_reference(CALL)]);
    assert!(bound(&fx, true, &answer, now()).await);
    let mut entry = fx.store.call_get(fx.callee.node_id(), CALL).await.unwrap().unwrap();
    entry.deadline_ms = now().saturating_sub(1);
    fx.store.call_put(fx.callee.node_id(), CALL, &entry).await.unwrap();
    assert!(calls::check_free_reply(&fx.store, &answer,
        Some(&json!({"v": 1, "call_id": CALL, "sdp": "answer"}).to_string())).await.is_err());
    assert!(!bound(&fx, true, &answer, now()).await);
}
