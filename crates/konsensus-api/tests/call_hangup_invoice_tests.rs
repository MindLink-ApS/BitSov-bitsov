//! Receiving side of call-bound hangups (`[calls] call_hangup_invoice_v1`):
//! the recipient issues a hangup invoice only while the call is live here for
//! that pair, and a hangup paid through such an invoice is delivered even if
//! the call ended here between the invoice and the hangup. A hangup paid any
//! other way for an ended call is refused exactly as before.

use konsensus_api::calls;
use konsensus_core::kind::{KIND_CALL_ANSWER, KIND_CALL_HANGUP, KIND_CALL_INVITE};
use konsensus_core::payloads::call::{CallRefusal, HangupReason, Phase, Side, HANGUP_INVOICE_SEQ, TOMBSTONE_MS};
use konsensus_core::{NodeId, NodeIdentity, PaymentProof, Recipient, UkmEnvelope, UkmEnvelopeBuilder};
use konsensus_storage::{SqliteStorage, Storage};
use serde_json::json;
use sha2::{Digest, Sha256};

const CALL: &str = "0123456789abcdef0123456789abcdef";

struct Fx {
    store: SqliteStorage,
    own: NodeId,
    caller: NodeIdentity,
}

/// This node is the callee of `CALL`, answered and live.
async fn live_callee() -> Fx {
    let store = SqliteStorage::in_memory().await.unwrap();
    let own = *NodeIdentity::generate().unwrap().1.node_id();
    let (_, caller) = NodeIdentity::generate().unwrap();
    let peer = *caller.node_id();
    let offer = json!({"v": 1, "call_id": CALL, "sdp": "offer", "media": "audio"}).to_string();
    calls::admit_incoming(&store, &own, &peer, KIND_CALL_INVITE, Some(&offer)).await.unwrap();
    let ringing = store.call_get(&peer, CALL).await.unwrap().unwrap().device_fetched(calls::now_ms()).unwrap();
    store.call_put(&peer, CALL, &ringing).await.unwrap();
    let answer = json!({"v": 1, "call_id": CALL, "sdp": "answer"}).to_string();
    calls::reserve_outgoing(&store, &own, &peer, KIND_CALL_ANSWER, &answer, "answer-op", "answer-hash").await.unwrap();
    calls::commit_outgoing(&store, &peer, &answer, "answer-op", "answer-hash").await.unwrap();
    let entry = store.call_get(&peer, CALL).await.unwrap().unwrap();
    assert_eq!((entry.side, entry.phase), (Side::Callee, Phase::Live));
    Fx { store, own, caller }
}

/// The callee's node ended the call on its own (as media detach does).
async fn end_here(fx: &Fx) {
    let peer = *fx.caller.node_id();
    let entry = fx.store.call_get(&peer, CALL).await.unwrap().unwrap();
    let ended = konsensus_core::payloads::call::CallEntry {
        phase: Phase::Ended, end_reason: Some(HangupReason::Hangup),
        deadline_ms: calls::now_ms() + TOMBSTONE_MS, ..entry
    };
    fx.store.call_put(&peer, CALL, &ended).await.unwrap();
}

fn hangup(fx: &Fx, preimage: [u8; 32]) -> UkmEnvelope {
    let proof = PaymentProof::new(Sha256::digest(preimage).into(), preimage, 1_000);
    let mut envelope = UkmEnvelopeBuilder::new(KIND_CALL_HANGUP, *fx.caller.node_id(), Recipient::Node(fx.own), b"sealed".to_vec(), proof)
        .build();
    envelope.signature = konsensus_core::Signature::from_ed25519(&fx.caller.sign(&envelope.signable_bytes()));
    envelope
}

fn plaintext() -> String {
    json!({"v": 1, "call_id": CALL, "reason": "hangup"}).to_string()
}

#[tokio::test]
async fn a_hangup_invoice_is_issued_only_while_the_call_is_live_here() {
    let fx = live_callee().await;
    let peer = *fx.caller.node_id();
    let retain = calls::validate_call_hangup_invoice(&fx.store, &peer, CALL, Side::Caller).await.unwrap();
    assert!(retain >= calls::now_ms() + TOMBSTONE_MS - 1_000, "the binding outlives a resent hangup");
    // Only the other side of the call may ask, for this pair and call.
    assert_eq!(calls::validate_call_hangup_invoice(&fx.store, &peer, CALL, Side::Callee).await, Err(CallRefusal::WrongSide));
    let stranger = *NodeIdentity::generate().unwrap().1.node_id();
    assert_eq!(calls::validate_call_hangup_invoice(&fx.store, &stranger, CALL, Side::Caller).await, Err(CallRefusal::UnknownCall));
    assert_eq!(calls::validate_call_hangup_invoice(&fx.store, &peer, "fedcba9876543210fedcba9876543210", Side::Caller).await,
        Err(CallRefusal::UnknownCall));
    end_here(&fx).await;
    assert_eq!(calls::validate_call_hangup_invoice(&fx.store, &peer, CALL, Side::Caller).await, Err(CallRefusal::UnknownCall));
}

#[tokio::test]
async fn a_bound_hangup_for_a_call_that_ended_after_its_invoice_is_delivered() {
    let fx = live_callee().await;
    let peer = *fx.caller.node_id();
    let bound = hangup(&fx, [1; 32]);
    fx.store.record_call_block_invoice(&peer, CALL, HANGUP_INVOICE_SEQ, &bound.payment_proof.payment_hash, calls::now_ms() + TOMBSTONE_MS)
        .await.unwrap();
    end_here(&fx).await;
    let before = fx.store.call_get(&peer, CALL).await.unwrap();
    let devices = calls::devices::Devices::default();
    let admitted = devices.admit(&fx.store, &fx.own, &bound, Some(&plaintext()), calls::now_ms(), calls::now_ms).await;
    assert_eq!(admitted.map(|s| s.call_id), Ok(CALL.to_string()), "this node accepted it by issuing the invoice");
    assert_eq!(fx.store.call_get(&peer, CALL).await.unwrap(), before, "the ended call is unchanged");

    // Paid any other way (keysend, a generic invoice, a block invoice), a
    // hangup for an ended call is refused as before.
    let unbound = hangup(&fx, [2; 32]);
    let refused = devices.admit(&fx.store, &fx.own, &unbound, Some(&plaintext()), calls::now_ms(), calls::now_ms).await;
    assert_eq!(refused.unwrap_err(), CallRefusal::UnknownCall);
    let block_bound = hangup(&fx, [3; 32]);
    fx.store.record_call_block_invoice(&peer, CALL, 0, &block_bound.payment_proof.payment_hash, calls::now_ms() + TOMBSTONE_MS)
        .await.unwrap();
    let refused = devices.admit(&fx.store, &fx.own, &block_bound, Some(&plaintext()), calls::now_ms(), calls::now_ms).await;
    assert_eq!(refused.unwrap_err(), CallRefusal::UnknownCall);
}

#[tokio::test]
async fn a_bound_hangup_for_a_live_call_ends_it_once() {
    let fx = live_callee().await;
    let peer = *fx.caller.node_id();
    let bound = hangup(&fx, [1; 32]);
    fx.store.record_call_block_invoice(&peer, CALL, HANGUP_INVOICE_SEQ, &bound.payment_proof.payment_hash, calls::now_ms() + TOMBSTONE_MS)
        .await.unwrap();
    let devices = calls::devices::Devices::default();
    devices.admit(&fx.store, &fx.own, &bound, Some(&plaintext()), calls::now_ms(), calls::now_ms).await.unwrap();
    let entry = fx.store.call_get(&peer, CALL).await.unwrap().unwrap();
    assert_eq!((entry.phase, entry.end_reason), (Phase::Ended, Some(HangupReason::Hangup)));
    // No second invoice can be issued for the same call.
    assert_eq!(calls::validate_call_hangup_invoice(&fx.store, &peer, CALL, Side::Caller).await, Err(CallRefusal::UnknownCall));

    // The same hangup admitted again changes nothing: the call stays ended,
    // exactly as the first admission left it, and its binding is not added to.
    let again = devices.admit(&fx.store, &fx.own, &bound, Some(&plaintext()), calls::now_ms() + 1, || calls::now_ms() + 1).await;
    assert_eq!(again.map(|s| s.call_id), Ok(CALL.to_string()));
    assert_eq!(fx.store.call_get(&peer, CALL).await.unwrap(), Some(entry.clone()), "a second admission reopened or rewrote the call");
    assert_eq!(fx.store.call_block_invoice_count(&peer, CALL, HANGUP_INVOICE_SEQ).await.unwrap(), 1);
    // Another hangup, not paid through that binding, is refused.
    let other = hangup(&fx, [2; 32]);
    let refused = devices.admit(&fx.store, &fx.own, &other, Some(&plaintext()), calls::now_ms() + 1, || calls::now_ms() + 1).await;
    assert_eq!(refused.unwrap_err(), CallRefusal::UnknownCall);
    assert_eq!(fx.store.call_get(&peer, CALL).await.unwrap(), Some(entry));
}
