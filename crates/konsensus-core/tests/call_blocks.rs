use konsensus_core::payloads::call::{
    self as calls, CallEntry, CallRefusal, CallSignal, HangupReason, Phase,
};

fn answered() -> CallEntry {
    let ringing = calls::receive(None, 400, None, 0).unwrap().device_fetched(0).unwrap();
    let pending = calls::reserve(Some(ringing), 401, "answer", "hash", 1_000).unwrap();
    calls::commit(pending, "answer", 1_000).unwrap()
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
fn block_zero_allows_initial_round_trips_without_granting_unpaid_media() {
    let entry = answered();
    assert_eq!(entry.deadline_ms, 31_000);
    assert_eq!(entry.next_block_due_ms(), Some(1_000));
    assert!(!entry.media_admitted(25_000));
    let paid = calls::receive_block(Some(entry.clone()), 0, 31_000).unwrap();
    assert_eq!(paid.paid_until_ms, Some(61_000));
    assert_eq!(paid.next_block_due_ms(), Some(41_000));
    assert_eq!(calls::receive_block(Some(entry), 0, 31_001).unwrap().paid_until_ms, Some(91_001));
}

#[test]
fn unpaid_hangup_is_admitted_after_local_expiry_without_changing_the_tombstone() {
    let ended = CallEntry { side: calls::Side::Caller, ..answered().at(31_001).unwrap() };
    assert_eq!(ended.phase, Phase::Ended);
    assert_eq!(ended.end_reason, Some(HangupReason::Unpaid));
    let notified = calls::receive(Some(ended.clone()), 403, Some(HangupReason::Unpaid), 32_000).unwrap();
    assert_eq!(notified, CallEntry { unpaid_notice_used: true, ..ended.clone() });
    assert_eq!(calls::receive(Some(notified), 403, Some(HangupReason::Unpaid), 32_001), Err(CallRefusal::UnknownCall));
    assert!(calls::receive(Some(ended.clone()), 402, None, 32_000).is_err());
    assert!(calls::receive_block(Some(ended.clone()), 0, 32_000).is_err());
    let other_end = CallEntry { end_reason: Some(HangupReason::Hangup), ..ended };
    assert!(calls::receive(Some(other_end), 403, None, 32_000).is_err());
    assert!(calls::receive(None, 403, None, 32_000).is_err());
}

#[test]
fn call_blocks_expiry_ends_unpaid_and_preserves_the_tombstone() {
    let first = calls::receive_block(Some(answered()), 0, 1_000).unwrap();
    assert_eq!(calls::receive_block(Some(first.clone()), 1, 71_001).unwrap().paid_until_ms, Some(131_001));
    let ended = first.at(71_001).unwrap();
    assert_eq!(ended.phase, Phase::Ended);
    assert_eq!(ended.end_reason, Some(HangupReason::Unpaid));
    assert!(!ended.media_admitted(71_001));
    assert_eq!(
        calls::receive(Some(ended), 400, None, 71_001),
        Err(CallRefusal::Replayed)
    );
    let never_paid = answered().at(31_001).unwrap();
    assert_eq!(never_paid.end_reason, Some(HangupReason::Unpaid));
}

#[test]
fn call_blocks_refuse_duplicates_gaps_early_unknown_ended_and_wrong_side() {
    assert!(calls::receive_block(None, 0, 1_000).is_err());
    let ringing = calls::receive(None, 400, None, 0).unwrap().device_fetched(0).unwrap();
    assert!(calls::receive_block(Some(ringing), 0, 1_000).is_err());
    let first = calls::receive_block(Some(answered()), 0, 1_000).unwrap();
    for (seq, at) in [(0, 41_000), (2, 41_000), (u32::MAX, 41_000), (1, 40_999)] {
        assert!(calls::receive_block(Some(first.clone()), seq, at).is_err());
    }
    let ended = calls::receive(Some(first), 403, None, 2_000).unwrap();
    assert!(calls::receive_block(Some(ended), 1, 41_000).is_err());
    let own = calls::commit(
        calls::reserve(None, 400, "offer", "hash", 0).unwrap(),
        "offer",
        0,
    ).unwrap();
    let caller = calls::receive(Some(own), 401, None, 1_000).unwrap();
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
fn call_blocks_outgoing_reservations_settle_once_and_honour_late_payment() {
    let own = calls::commit(
        calls::reserve(None, 400, "offer", "hash", 0).unwrap(),
        "offer",
        0,
    ).unwrap();
    let entry = calls::receive(Some(own), 401, None, 1_000).unwrap();
    let pending = calls::reserve_block(Some(entry.clone()), 0, "block", "hash", 1_000).unwrap();
    assert_eq!(calls::release(pending.clone(), "block"), Some(entry));
    let first = calls::commit(pending.clone(), "block", 1_000).unwrap();
    assert_eq!(first.paid_until_ms, Some(61_000));
    assert_eq!(calls::commit(first.clone(), "block", 2_000).unwrap(), first);
    let expired = pending.at(31_001).unwrap();
    assert_eq!(calls::commit(expired, "block", 31_001).unwrap().paid_until_ms, Some(91_001));
}

#[test]
fn live_block_commit_not_due_retains_the_reservation() {
    let caller = CallEntry { side: calls::Side::Caller, ..answered() };
    let first = calls::commit(
        calls::reserve_block(Some(caller), 0, "first", "hash", 1_000).unwrap(),
        "first", 1_000,
    ).unwrap();
    let pending = calls::reserve_block(Some(first), 1, "renewal", "hash", 41_000).unwrap();
    // A delayed grant for block zero moves its boundary while block one is
    // paying. A backwards clock step can make the same reservation NotDue.
    for (paid_until_ms, deadline_ms, now) in [(Some(91_000), 101_000, 41_001), (Some(61_000), 71_000, 40_999)] {
        let pending = CallEntry { paid_until_ms, deadline_ms, ..pending.clone() };
        assert_eq!(calls::commit(pending.clone(), "renewal", now), Err(CallRefusal::NotDue));
        assert_eq!(calls::reserve_block(Some(pending.clone()), 1, "second-payment", "hash", 71_000), Err(CallRefusal::InFlight));
        let committed = calls::commit(pending, "renewal", 71_000).unwrap();
        assert_eq!(committed.next_block_seq, 2);
        assert!(committed.pending.is_none());
    }
}

#[test]
fn unpaid_hangup_notification_never_reopens_an_ended_call() {
    let ended = answered().at(31_001).unwrap();
    let pending = calls::reserve_unpaid_hangup(Some(ended), "timeout", "hash").unwrap();
    let ended = calls::commit(pending, "timeout", 31_002).unwrap();
    assert_eq!(ended.phase, Phase::Ended);
    assert!(!ended.media_admitted(31_002));
    assert_eq!(calls::reserve_unpaid_hangup(Some(ended), "second", "hash2"), Err(CallRefusal::UnknownCall));
    assert!(calls::reserve_unpaid_hangup(Some(answered()), "timeout", "hash").is_err());
}

#[test]
fn unpaid_hangup_cannot_be_reserved_by_the_caller() {
    let ended = CallEntry { side: calls::Side::Caller, ..answered().at(31_001).unwrap() };
    assert_eq!(calls::reserve_unpaid_hangup(Some(ended), "timeout", "hash"), Err(CallRefusal::UnknownCall));
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
    ).unwrap();
    let entry = calls::receive(Some(own), 401, None, 1_000).unwrap();
    let pending = calls::reserve_block(Some(entry), 0, "block", "hash", 1_000).unwrap();
    assert!(
        calls::reserve_block(Some(pending.clone()), 0, "block", "hash", 31_001).is_ok(),
        "same operation can reconcile an old payment"
    );
    assert!(
        calls::validate_outgoing_block(&pending, 0, 31_001).is_err(),
        "positive nonpayment evidence cannot authorize a new expired charge"
    );
    assert!(calls::validate_outgoing_block(&pending, 0, 31_000).is_ok());
}

#[test]
fn unpaid_notice_reservation_retries_and_definite_nonpayment_release() {
    let ended = answered().at(31_001).unwrap();
    let pending = calls::reserve_unpaid_hangup(Some(ended.clone()), "notice", "hash").unwrap();
    assert!(pending.unpaid_notice_used);
    assert_eq!(calls::reserve_unpaid_hangup(Some(pending.clone()), "notice", "hash"), Ok(pending.clone()));
    assert_eq!(calls::reserve_unpaid_hangup(Some(pending.clone()), "other", "hash"), Err(CallRefusal::InFlight));
    assert_eq!(calls::release(pending.clone(), "notice"), Some(ended));
    let committed = calls::commit(pending, "notice", 32_000).unwrap();
    assert!(committed.unpaid_notice_used);
    assert_eq!(calls::release(committed.clone(), "notice"), Some(committed));
}

#[test]
fn late_block_resumes_at_window_boundary_without_pending_unpaid_notice_ending_it() {
    let ended = answered().at(31_001).unwrap();
    let pending = calls::reserve_unpaid_hangup(Some(ended), "notice", "hash").unwrap();
    let resumed = calls::receive_block(Some(pending), 0, 91_000).unwrap();
    assert_eq!(resumed.phase, Phase::Live);
    assert_eq!(resumed.paid_until_ms, Some(151_000));
    assert_eq!(resumed.next_block_seq, 1);
    assert!(resumed.media_admitted(150_999));
    let committed = calls::commit(resumed, "notice", 91_001).unwrap();
    assert_eq!(committed.phase, Phase::Live);
    assert_eq!(committed.paid_until_ms, Some(151_000));
    assert!(committed.pending.is_none());
}

#[test]
fn late_block_outside_resume_window_or_wrong_seq_never_grants_media() {
    let ended = answered().at(31_001).unwrap();
    assert!(calls::receive_block(Some(ended.clone()), 0, 91_001).is_err());
    assert!(calls::receive_block(Some(ended.clone()), 1, 32_000).is_err());
    assert!(calls::receive_block(Some(CallEntry { end_reason: Some(HangupReason::Hangup), ..ended }), 0, 32_000).is_err());
}

#[test]
fn block_invoice_cutoff_is_independent_of_settlement_grace() {
    let live = answered();
    assert!(calls::validate_block_invoice(&live, 0, 16_000).is_ok());
    assert!(calls::validate_block_invoice(&live, 0, 16_001).is_err());
    assert!(calls::validate_block_invoice(&live, 1, 1_000).is_err());
    assert!(calls::validate_block_invoice(&live.at(31_001).unwrap(), 0, 31_001).is_err());
}

#[test]
fn delayed_unpaid_notice_cannot_revoke_a_settled_interval() {
    let caller = CallEntry { side: calls::Side::Caller, ..answered() };
    let pending = calls::reserve_block(Some(caller), 0, "block", "hash", 1_000).unwrap();
    let paid = calls::commit(pending, "block", 32_000).unwrap();
    assert!(calls::receive(Some(paid), 403, Some(HangupReason::Unpaid), 32_001).is_err());
}

#[test]
fn very_late_outgoing_settlement_still_delivers_for_callee_reconciliation() {
    let caller = CallEntry { side: calls::Side::Caller, ..answered() };
    let pending = calls::reserve_block(Some(caller), 0, "block", "hash", 1_000).unwrap();
    let now = 31_000 + calls::TOMBSTONE_MS + 1;
    // The replay sweep may reclaim the row; the independent outbox journal
    // still delivers its settled envelope for callee reconciliation.
    assert!(pending.clone().at(now).is_none());
    // A commit racing the sweep also clears the reservation without service.
    let paid = calls::commit(pending, "block", now).unwrap();
    assert!(paid.pending.is_none(), "paid envelope can leave for reconciliation");
    assert_eq!(paid.next_block_seq, 0);
    assert!(!paid.media_admitted(now));
}
