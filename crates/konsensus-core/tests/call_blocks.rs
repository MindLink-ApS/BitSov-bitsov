use konsensus_core::payloads::call::{
    self as calls, CallEntry, CallRefusal, CallSignal, HangupReason, Phase,
};

fn answered() -> CallEntry {
    let ringing = calls::receive(None, 400, 0).unwrap();
    let pending = calls::reserve(Some(ringing), 401, "answer", "hash", 1_000).unwrap();
    calls::commit(pending, "answer", 1_000)
}

#[test]
fn call_blocks_on_time_extend_fixed_boundaries_and_expose_due_time() {
    let entry = answered();
    assert!(
        !entry.media_admitted(1_000),
        "an answer never pays the caller's first block"
    );
    assert_eq!(entry.next_block_due_ms(), Some(1_000));
    let first = calls::receive_block(Some(entry), 0, 1_000).unwrap();
    assert_eq!(first.paid_until_ms, Some(61_000));
    assert_eq!(first.next_block_due_ms(), Some(41_000));
    assert!(first.media_admitted(71_000));
    assert!(!first.media_admitted(71_001));
    let second = calls::receive_block(Some(first), 1, 41_000).unwrap();
    assert_eq!(second.paid_until_ms, Some(121_000));
    assert_eq!(second.next_block_due_ms(), Some(101_000));
}

#[test]
fn call_blocks_late_within_grace_do_not_move_the_interval_anchor() {
    let first = calls::receive_block(Some(answered()), 0, 2_000).unwrap();
    let late = calls::receive_block(Some(first), 1, 71_000).unwrap();
    assert_eq!(late.paid_until_ms, Some(121_000));
}

#[test]
fn call_blocks_expiry_ends_unpaid_and_preserves_the_tombstone() {
    let first = calls::receive_block(Some(answered()), 0, 1_000).unwrap();
    assert!(calls::receive_block(Some(first.clone()), 1, 71_001).is_err());
    let ended = first.at(71_001).unwrap();
    assert_eq!(ended.phase, Phase::Ended);
    assert_eq!(ended.end_reason, Some(HangupReason::Unpaid));
    assert!(!ended.media_admitted(71_001));
    assert_eq!(
        calls::receive(Some(ended), 400, 71_001),
        Err(CallRefusal::Replayed)
    );
    let never_paid = answered().at(11_001).unwrap();
    assert_eq!(never_paid.end_reason, Some(HangupReason::Unpaid));
}

#[test]
fn call_blocks_refuse_duplicates_gaps_early_unknown_ended_and_wrong_side() {
    assert!(calls::receive_block(None, 0, 1_000).is_err());
    let ringing = calls::receive(None, 400, 0).unwrap();
    assert!(calls::receive_block(Some(ringing), 0, 1_000).is_err());
    let first = calls::receive_block(Some(answered()), 0, 1_000).unwrap();
    for (seq, at) in [(0, 41_000), (2, 41_000), (u32::MAX, 41_000), (1, 40_999)] {
        assert!(calls::receive_block(Some(first.clone()), seq, at).is_err());
    }
    let ended = calls::receive(Some(first), 403, 2_000).unwrap();
    assert!(calls::receive_block(Some(ended), 1, 41_000).is_err());
    let own = calls::commit(
        calls::reserve(None, 400, "offer", "hash", 0).unwrap(),
        "offer",
        0,
    );
    let caller = calls::receive(Some(own), 401, 1_000).unwrap();
    assert!(calls::receive_block(Some(caller), 0, 1_000).is_err());
}

#[test]
fn call_blocks_have_strict_bounded_payloads() {
    let id = "0123456789abcdef0123456789abcdef";
    assert_eq!(
        CallSignal::parse(404, &format!(r#"{{"call_id":"{id}","seq":0}}"#))
            .unwrap()
            .seq,
        Some(0)
    );
    for body in [
        format!(r#"{{"call_id":"{id}"}}"#),
        format!(r#"{{"call_id":"{id}","seq":-1}}"#),
        format!(r#"{{"call_id":"{id}","seq":4294967296}}"#),
        format!(r#"{{"call_id":"{id}","seq":0,"sdp":"v=0"}}"#),
        format!(r#"{{"v":1,"call_id":"{id}","seq":0,"extra":true}}"#),
        r#"{"call_id":"INVALID","seq":0}"#.to_string(),
    ] {
        assert!(CallSignal::parse(404, &body).is_err(), "{body}");
    }
    assert!(CallSignal::parse(403, &format!(r#"{{"v":1,"call_id":"{id}","seq":0}}"#)).is_err());
}

#[test]
fn call_blocks_outgoing_reservations_settle_once_and_cannot_revive_expiry() {
    let own = calls::commit(
        calls::reserve(None, 400, "offer", "hash", 0).unwrap(),
        "offer",
        0,
    );
    let entry = calls::receive(Some(own), 401, 1_000).unwrap();
    let pending = calls::reserve_block(Some(entry.clone()), 0, "block", "hash", 1_000).unwrap();
    assert_eq!(calls::release(pending.clone(), "block"), Some(entry));
    let first = calls::commit(pending.clone(), "block", 1_000);
    assert_eq!(first.paid_until_ms, Some(61_000));
    assert_eq!(calls::commit(first.clone(), "block", 2_000), first);
    let expired = pending.at(11_001).unwrap();
    assert_eq!(calls::commit(expired, "block", 11_001).phase, Phase::Ended);
}

#[test]
fn unpaid_hangup_notification_never_reopens_an_ended_call() {
    let ended = answered().at(11_001).unwrap();
    let pending = calls::reserve_unpaid_hangup(Some(ended), "timeout", "hash").unwrap();
    let ended = calls::commit(pending, "timeout", 11_002);
    assert_eq!(ended.phase, Phase::Ended);
    assert!(!ended.media_admitted(11_002));
    assert!(calls::reserve_unpaid_hangup(Some(answered()), "timeout", "hash").is_err());
}

#[test]
fn paid_call_block_count_is_bounded() {
    let mut entry = answered();
    for seq in 0..240 {
        let due = entry.next_block_due_ms().unwrap();
        entry = calls::receive_block(Some(entry), seq, due).unwrap();
    }
    assert_eq!(entry.paid_until_ms, Some(14_401_000));
    assert_eq!(entry.next_block_due_ms(), None);
    assert!(calls::receive_block(Some(entry), 240, 14_381_000).is_err());
}

#[test]
fn call_blocks_expired_pending_can_reconcile_but_cannot_pay_again() {
    let own = calls::commit(
        calls::reserve(None, 400, "offer", "hash", 0).unwrap(),
        "offer",
        0,
    );
    let entry = calls::receive(Some(own), 401, 1_000).unwrap();
    let pending = calls::reserve_block(Some(entry), 0, "block", "hash", 1_000).unwrap();
    assert!(
        calls::reserve_block(Some(pending.clone()), 0, "block", "hash", 11_001).is_ok(),
        "same operation can reconcile an old payment"
    );
    assert!(
        calls::validate_outgoing_block(&pending, 0, 11_001).is_err(),
        "positive nonpayment evidence cannot authorize a new expired charge"
    );
    assert!(calls::validate_outgoing_block(&pending, 0, 11_000).is_ok());
}
