use konsensus_api::compound_readiness::{evaluate, ReadContext};
use serde_json::{json, Value};

const GROUPS: &[&str] = &[
    "owner_setup",
    "authority_consent",
    "receiving_reply",
    "aggregate_history",
    "aggregate_enforcement",
    "exact_hold",
    "durable_compound",
    "introduction_sequencing",
    "callee_signals",
    "lifecycle_recovery",
    "platform_connection",
];
const DECISIONS: &[&str] = &[
    "profile_selection",
    "aggregate_policy",
    "exact_hold_consent",
    "callee_terms",
    "custody_setup",
    "approval_intent",
    "platform_scope",
];
const CHECKS: &[&str] = &[
    "owner_route",
    "custody",
    "device_key",
    "device_approvals",
    "enrollment",
    "independent_approval",
    "peer_trust",
    "recipient_admission",
    "reply_authority",
    "reverse_admission",
    "sender_receiving",
    "chain",
    "payment",
    "liquidity",
    "exact_hold_consent",
    "terms_current",
    "microphone",
    "callee_authority",
    "live_ring",
    "stage_authority",
];
fn compatible() -> Value {
    let mut v = json!({
        "schema": {"name":"compound_readiness", "major":1, "minor":0},
        "required_extensions":[],
        "profile":{"name":"named_contact_compound", "revision":1, "finalized":true, "manifest":{}},
        "node_binding":{"node_id":"selected-node", "build":"fixture"},
        "connection_binding":{"generation":7,"request_id":"read-1","client_context":"client-a"},
        "network":"signet",
        "capabilities":{}, "decisions":{},
        "observation":{"valid_for_ms":1000},
        "context":{"requested_stage":"introduction","operation_id":"operation-a","role":"caller", "recipient":"peer-b", "policy_revision":"policy-1",
            "enrollment_epoch":3,"terms_revision":"terms-1","operation":"active",
            "warm":false,"warm_provenance":null},
        "prerequisites":{}, "authority_refs":[],
        "accounting":{"history":"complete","unresolved_obligations":false,"policy_revision":"policy-1"},
        "stage_result_refs":{"introduction":{"state":"not_attempted","reference":null},
            "reply":{"state":"unknown","reference":null},
            "receiving":{"state":"unknown","reference":null}},
        "optional_diagnostics":{}
    });
    for group in GROUPS {
        v["capabilities"][group] = json!({"revision":1,"support":"supported"});
        v["profile"]["manifest"][group] = json!(1);
    }
    for decision in DECISIONS {
        v["decisions"][decision] = json!(true);
    }
    for check in CHECKS {
        v["prerequisites"][check] = json!({"state":"ready","reason":"satisfied","expires_at_ms":null,"parent_expires_at_ms":null});
    }
    for timed in ["enrollment", "live_ring", "callee_authority"] {
        v["prerequisites"][timed]["expires_at_ms"] = json!(500);
    }
    v
}
fn call_ready() -> Value {
    let mut v = compatible();
    v["context"]["requested_stage"] = json!("call");
    v["stage_result_refs"]["introduction"] = json!({"state":"confirmed","reference":"intro-1"});
    v
}
fn context(v: &Value) -> ReadContext {
    ReadContext {
        authenticated_node_id: "selected-node".into(),
        connection_binding: serde_json::from_value(v["connection_binding"].clone()).unwrap(),
        context: serde_json::from_value(v["context"].clone()).unwrap(),
        receipt_age_ms: Some(0),
        now_ms: Some(100),
        clock_valid: true,
    }
}
fn read(v: &Value, ctx: &ReadContext) -> Value {
    serde_json::to_value(evaluate(&serde_json::to_vec(v).unwrap(), ctx)).unwrap()
}
fn report(v: &Value) -> Value {
    read(v, &context(v))
}
fn blocked(r: &Value, reason: &str) {
    assert!(
        r["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["reason"] == reason),
        "missing {reason}: {r}"
    );
    assert_eq!(r["authorizes_dispatch"], false);
}
fn set_check(v: &mut Value, name: &str, state: &str, reason: &str) {
    v["prerequisites"][name]["state"] = json!(state);
    v["prerequisites"][name]["reason"] = json!(reason);
}

#[test]
fn c01_complete_closure_can_prepare_but_observation_is_not_consent() {
    let mut v = compatible();
    set_check(&mut v, "stage_authority", "needs_owner", "consent_required");
    let before = v.clone();
    let r = report(&v);
    assert_eq!(r["implemented"], true);
    assert_eq!(r["stages"]["introduction"]["can_prepare"], true);
    assert_eq!(r["stages"]["introduction"]["can_request_approval"], true);
    assert_eq!(r["stages"]["introduction"]["can_attempt_stage"], false);
    assert_eq!(r["authorizes_dispatch"], false);
    assert_eq!(r["revalidation_required"], true);
    assert_eq!(v, before);
}
#[test]
fn c02_additive_minor_and_explicit_optional_diagnostic() {
    let mut v = compatible();
    v["schema"]["minor"] = json!(9);
    v["optional_diagnostics"]["future_label"] = json!({"display":"informational"});
    assert_eq!(report(&v)["stages"], report(&compatible())["stages"]);
}
#[test]
fn c03_setup_receive_reply_and_answer_remain_separate() {
    let mut v = compatible();
    set_check(
        &mut v,
        "recipient_admission",
        "pending",
        "admission_pending",
    );
    set_check(
        &mut v,
        "reply_authority",
        "needs_owner",
        "reply_authority_missing",
    );
    let r = report(&v);
    assert_eq!(r["stages"]["setup"]["can_prepare"], true);
    assert_eq!(r["stages"]["introduction"]["state"], "pending");
    let mut callee = v.clone();
    callee["context"]["role"] = json!("callee");
    callee["context"]["requested_stage"] = json!("reply");
    callee["stage_result_refs"]["reply"] = json!({"state":"not_attempted","reference":null});
    callee["context"]["recipient"] = json!("peer-a");
    callee["connection_binding"]["client_context"] = json!("client-b");
    let b = report(&callee);
    assert_eq!(b["stages"]["reply"]["state"], "needs_owner");
    assert_eq!(r["stages"]["answer"]["can_attempt_stage"], false);
    assert_eq!(r["stage_result_refs"]["reply"]["state"], "unknown");
}
#[test]
fn c04_owner_setting_off_is_read_only() {
    let mut v = compatible();
    set_check(&mut v, "device_approvals", "needs_owner", "setting_off");
    let before = v.clone();
    for _ in 0..3 {
        blocked(&report(&v), "setting_off");
    }
    assert_eq!(v, before);
    assert_eq!(report(&v)["implemented"], true);
    assert_eq!(report(&v)["stages"]["introduction"]["state"], "needs_owner");
}
#[test]
fn c05_shorter_parent_expiry_wins_without_refresh_extension() {
    let mut v = compatible();
    v["prerequisites"]["enrollment"]["expires_at_ms"] = json!(220);
    v["prerequisites"]["enrollment"]["parent_expires_at_ms"] = json!(150);
    for (now, allowed) in [(149, true), (150, false), (151, false)] {
        let mut ctx = context(&v);
        ctx.now_ms = Some(now);
        let r = read(&v, &ctx);
        assert_eq!(r["stages"]["introduction"]["can_prepare"], allowed);
        if !allowed {
            blocked(&r, "expired");
        }
    }
}
#[test]
fn c06_warm_contact_retains_provenance() {
    let mut v = compatible();
    v["context"]["warm"] = json!(true);
    v["context"]["warm_provenance"] = json!("prior-introduction");
    let r = report(&v);
    assert_eq!(r["context"]["warm"], true);
    assert_eq!(r["context"]["warm_provenance"], "prior-introduction");
    assert_eq!(r["stage_result_refs"]["reply"]["state"], "unknown");
}
#[test]
fn i01_rc24_shaped_status_is_unavailable() {
    let v = json!({"status":"ok","node_version":"0.3.0-rc24","api_capabilities":["device_approvals_v1"]});
    let r = read(&v, &context(&compatible()));
    assert_eq!(r["implemented"], false);
    blocked(&r, "invalid_envelope");
}
#[test]
fn i02_every_enforcement_dependency_is_required() {
    for group in GROUPS {
        let mut v = call_ready();
        v["node_binding"]["build"] = json!("99.0.0");
        v["capabilities"].as_object_mut().unwrap().remove(*group);
        let r = report(&v);
        assert_eq!(r["implemented"], false, "{group}");
        blocked(&r, "missing_dependency");
        assert_eq!(r["stages"]["call"]["can_prepare"], false, "{group}");
    }
}
#[test]
fn i03_unknown_missing_malformed_and_contradictory_fields_refuse() {
    let good = compatible();
    let mut variants = Vec::new();
    let mut v = good.clone();
    v["schema"]["major"] = json!(2);
    variants.push(v);
    let mut v = good.clone();
    v.as_object_mut().unwrap().remove("accounting");
    variants.push(v);
    let mut v = good.clone();
    v["capabilities"]["exact_hold"]["support"] = json!("maybe");
    variants.push(v);
    let mut v = good.clone();
    v["required_extensions"] = json!(["future_authority"]);
    variants.push(v);
    let mut v = good.clone();
    set_check(&mut v, "enrollment", "ready", "revoked");
    variants.push(v);
    let mut v = good.clone();
    v["profile"]["manifest"]
        .as_object_mut()
        .unwrap()
        .remove("aggregate_enforcement");
    variants.push(v);
    for v in variants {
        assert_eq!(report(&v)["stages"]["call"]["can_prepare"], false, "{v}");
    }
}
#[test]
fn i04_network_and_authenticated_node_binding_refuse() {
    for network in [
        Value::Null,
        json!(""),
        json!("unknown"),
        json!("other"),
        json!("bitcoin"),
        json!("regtest"),
        json!({"error":"unavailable"}),
    ] {
        let mut v = call_ready();
        v["network"] = network;
        let r = report(&v);
        assert_eq!(r["stages"]["call"]["can_prepare"], false);
    }
    let mut v = call_ready();
    v.as_object_mut().unwrap().remove("network");
    assert_eq!(report(&v)["stages"]["setup"]["can_prepare"], false);
    let mut v = call_ready();
    v["node_binding"]["node_id"] = json!("other-node");
    blocked(&report(&v), "binding_changed");
}
#[test]
fn i05_late_generation_node_client_and_terms_cannot_publish() {
    let v = compatible();
    let old = context(&v);
    for field in ["generation", "request_id", "client_context"] {
        let mut changed = v.clone();
        changed["connection_binding"][field] = if field == "generation" {
            json!(8)
        } else {
            json!("replacement")
        };
        blocked(&read(&changed, &old), "binding_changed");
    }
    for field in [
        "recipient",
        "role",
        "policy_revision",
        "enrollment_epoch",
        "terms_revision",
    ] {
        let mut changed = v.clone();
        changed["context"][field] = match field {
            "role" => json!("callee"),
            "enrollment_epoch" => json!(4),
            _ => json!("changed"),
        };
        blocked(&read(&changed, &old), "binding_changed");
    }
}
#[test]
fn i06_paired_reader_without_authorized_setup_route_stops() {
    let mut v = compatible();
    v["context"]["role"] = json!("reader");
    set_check(&mut v, "owner_route", "unknown", "owner_route_unavailable");
    set_check(&mut v, "custody", "unknown", "custody_unverified");
    let r = report(&v);
    blocked(&r, "owner_route_unavailable");
    assert_eq!(r["stages"]["introduction"]["can_attempt_stage"], false);
}
#[test]
fn i07_revoked_enrollment_and_same_device_v1_refuse() {
    for (check, reason) in [
        ("enrollment", "revoked"),
        ("independent_approval", "independent_owner_required"),
    ] {
        let mut v = compatible();
        set_check(&mut v, check, "refused", reason);
        let r = report(&v);
        blocked(&r, reason);
        assert_eq!(r["stages"]["introduction"]["can_prepare"], false);
    }
}
#[test]
fn i08_unknown_history_obligations_and_introduction_need_reconciliation() {
    for history in ["unknown", "partial"] {
        let mut v = compatible();
        v["accounting"]["history"] = json!(history);
        blocked(&report(&v), "reconciliation_required");
    }
    let mut v = compatible();
    v["accounting"]["unresolved_obligations"] = json!(true);
    blocked(&report(&v), "reconciliation_required");
    for outcome in ["pending", "unknown", "refused"] {
        let mut v = compatible();
        v["stage_result_refs"]["introduction"]["state"] = json!(outcome);
        let r = report(&v);
        blocked(&r, "introduction_unconfirmed");
        assert_eq!(r["stage_result_refs"]["introduction"]["state"], outcome);
    }
}
#[test]
fn i09_reply_authority_is_not_answer_authority() {
    let mut v = compatible();
    v["context"]["role"] = json!("callee");
    set_check(
        &mut v,
        "reply_authority",
        "refused",
        "reply_authority_missing",
    );
    set_check(&mut v, "reverse_admission", "pending", "admission_pending");
    let r = report(&v);
    assert_eq!(r["stages"]["answer"]["can_prepare"], true);
    assert_eq!(r["stages"]["reply"]["can_prepare"], false);
    assert_eq!(r["stage_result_refs"]["reply"]["state"], "unknown");
}
#[test]
fn i10_exact_hold_and_changed_terms_need_explicit_consent() {
    for reason in ["separate_confirmation_required", "terms_changed"] {
        let mut v = compatible();
        set_check(&mut v, "exact_hold_consent", "needs_owner", reason);
        let r = report(&v);
        blocked(&r, reason);
        assert_eq!(r["stages"]["call"]["can_prepare"], false);
    }
}
#[test]
fn i11_expired_ring_and_terminal_operation_stay_closed() {
    let mut v = compatible();
    v["context"]["role"] = json!("callee");
    v["prerequisites"]["live_ring"]["expires_at_ms"] = json!(100);
    blocked(&report(&v), "expired");
    for terminal in ["cancelled", "closed"] {
        let mut v = compatible();
        v["context"]["operation"] = json!(terminal);
        let r = report(&v);
        blocked(&r, "terminal_operation");
        assert_eq!(r["stages"]["call"]["can_attempt_stage"], false);
    }
}
#[test]
fn i12_downgrade_stops_new_stages_and_preserves_existing_evidence() {
    let mut v = compatible();
    v["capabilities"]["durable_compound"]["support"] = json!("unsupported");
    v["accounting"]["unresolved_obligations"] = json!(true);
    let r = report(&v);
    blocked(&r, "missing_dependency");
    assert_eq!(r["stage_result_refs"], v["stage_result_refs"]);
    assert_eq!(r["accounting"], v["accounting"]);
}
#[test]
fn i13_untrusted_peer_fact_blocks_without_new_trust_channel() {
    let mut v = compatible();
    set_check(&mut v, "peer_trust", "unknown", "peer_unverified");
    blocked(&report(&v), "peer_unverified");
    assert_eq!(report(&v)["stages"]["call"]["can_prepare"], false);
}
#[test]
fn i14_healthy_api_does_not_attest_platform_or_payment_readiness() {
    for check in ["microphone", "device_key", "chain", "liquidity", "payment"] {
        let mut v = compatible();
        set_check(&mut v, check, "unknown", "component_unavailable");
        let r = report(&v);
        blocked(&r, "component_unavailable");
        assert_eq!(r["stages"]["call"]["can_prepare"], false, "{check}");
    }
}
#[test]
fn i15_each_required_owner_decision_refuses_the_profile() {
    for decision in DECISIONS {
        let mut v = call_ready();
        v["decisions"][decision] = json!(false);
        let r = report(&v);
        blocked(&r, "owner_decision_required");
        assert_eq!(r["stages"]["call"]["can_prepare"], false, "{decision}");
    }
}
#[test]
fn i16_expired_unknown_and_rollback_time_cannot_extend_authority() {
    let v = call_ready();
    for (age, now, valid) in [
        (Some(999), Some(100), true),
        (Some(1000), Some(100), true),
        (None, Some(100), true),
        (Some(0), None, true),
        (Some(0), Some(100), false),
    ] {
        let mut ctx = context(&v);
        ctx.receipt_age_ms = age;
        ctx.now_ms = now;
        ctx.clock_valid = valid;
        let r = read(&v, &ctx);
        assert_eq!(r["stages"]["call"]["can_prepare"], age == Some(999));
        if age != Some(999) {
            blocked(&r, "freshness_unknown");
        }
    }
}
#[test]
fn dependency_counter_test_is_not_masked_by_network_or_owner_gates() {
    let mut v = call_ready();
    let r = report(&v);
    assert_eq!(r["stages"]["call"]["can_prepare"], true);
    v["capabilities"]["aggregate_enforcement"]["support"] = json!("unsupported");
    let r = report(&v);
    assert_eq!(r["stages"]["call"]["can_prepare"], false);
    blocked(&r, "missing_dependency");
}
#[test]
fn bounded_parser_rejects_unmarked_fields_oversize_and_missing_freshness() {
    let mut v = compatible();
    v["unmarked_extension"] = json!(true);
    blocked(&report(&v), "invalid_envelope");
    let mut v = compatible();
    v["optional_diagnostics"]["large"] = json!("x".repeat(32769));
    blocked(&report(&v), "invalid_envelope");
    let mut v = compatible();
    v["observation"]["valid_for_ms"] = Value::Null;
    blocked(&report(&v), "freshness_unknown");
}

#[test]
fn authority_observation_cannot_cross_stage_context() {
    let mut v = compatible();
    v["authority_refs"] = json!(["introduction-authority"]);
    v["prerequisites"]["stage_authority"]["expires_at_ms"] = json!(500);
    let r = report(&v);
    assert_eq!(r["stages"]["introduction"]["can_attempt_stage"], true);
    assert_eq!(r["stages"]["call"]["can_attempt_stage"], false);
    v["stage_result_refs"]["introduction"] = json!({"state":"confirmed","reference":"intro-1"});
    let r = report(&v);
    assert_eq!(r["stages"]["call"]["can_prepare"], true);
    assert_eq!(r["stages"]["call"]["can_request_approval"], false);
    assert_eq!(r["stages"]["call"]["can_attempt_stage"], false);
}

#[test]
fn changed_terms_prevent_introduction_and_reply_attempts() {
    for (role, stage) in [("caller", "introduction"), ("callee", "reply")] {
        let mut v = compatible();
        v["context"]["role"] = json!(role);
        v["context"]["requested_stage"] = json!(stage);
        v["authority_refs"] = json!(["stage-authority"]);
        v["prerequisites"]["stage_authority"]["expires_at_ms"] = json!(500);
        v["stage_result_refs"][stage] = json!({"state":"not_attempted","reference":null});
        assert_eq!(report(&v)["stages"][stage]["can_attempt_stage"], true);
        set_check(&mut v, "terms_current", "refused", "terms_changed");
        assert_eq!(report(&v)["stages"][stage]["can_prepare"], false);
        assert_eq!(report(&v)["stages"][stage]["can_attempt_stage"], false);
    }
}

#[test]
fn duplicate_semantic_map_keys_refuse_instead_of_replacing_evidence() {
    let v = compatible();
    let bytes = serde_json::to_string(&v).unwrap();
    let needle = "\"aggregate_enforcement\":{\"revision\":1,\"support\":\"supported\"}";
    assert_eq!(bytes.matches(needle).count(), 1);
    let duplicate = format!(
        "\"aggregate_enforcement\":{{\"revision\":1,\"support\":\"unsupported\"}},{needle}"
    );
    let bytes = bytes.replace(needle, &duplicate);
    let r = serde_json::to_value(evaluate(bytes.as_bytes(), &context(&v))).unwrap();
    blocked(&r, "invalid_envelope");
    assert_eq!(r["implemented"], false);
}

#[test]
fn unknown_effective_expiry_cannot_borrow_a_later_authority_deadline() {
    for check in ["enrollment", "live_ring", "callee_authority"] {
        let mut v = compatible();
        v["context"]["role"] = json!("callee");
        v["context"]["requested_stage"] = json!("answer");
        v["authority_refs"] = json!(["answer-authority"]);
        for timed in [
            "stage_authority",
            "enrollment",
            "live_ring",
            "callee_authority",
        ] {
            v["prerequisites"][timed]["expires_at_ms"] = json!(500);
        }
        assert_eq!(report(&v)["stages"]["answer"]["can_attempt_stage"], true);
        v["prerequisites"][check]["expires_at_ms"] = Value::Null;
        let r = report(&v);
        assert_eq!(r["stages"]["answer"]["can_attempt_stage"], false, "{check}");
        blocked(&r, "freshness_unknown");
    }
}

#[test]
fn requested_stage_and_operation_identity_invalidate_old_observations() {
    let v = compatible();
    let old = context(&v);
    for (field, value) in [
        ("requested_stage", "call"),
        ("operation_id", "replacement-operation"),
    ] {
        let mut changed = v.clone();
        changed["context"][field] = json!(value);
        blocked(&read(&changed, &old), "binding_changed");
    }
}

#[test]
fn approval_request_needs_an_operation_identity() {
    let mut v = compatible();
    v["context"]["operation_id"] = Value::Null;
    let r = report(&v);
    assert_eq!(r["stages"]["introduction"]["can_prepare"], true);
    assert_eq!(r["stages"]["introduction"]["can_request_approval"], false);
    assert_eq!(r["stages"]["introduction"]["can_attempt_stage"], false);
}

#[test]
fn absent_terms_revision_prevents_stage_preparation() {
    let mut v = compatible();
    v["context"]["terms_revision"] = Value::Null;
    assert_eq!(report(&v)["stages"]["introduction"]["can_prepare"], false);
    assert_eq!(report(&v)["stages"]["call"]["can_prepare"], false);
}

#[test]
fn message_outcome_uncertainty_or_resolution_cannot_start_another_attempt() {
    for (role, stage) in [("caller", "introduction"), ("callee", "reply")] {
        for outcome in ["pending", "unknown", "confirmed", "refused"] {
            let mut v = compatible();
            v["context"]["role"] = json!(role);
            v["context"]["requested_stage"] = json!(stage);
            v["authority_refs"] = json!(["message-authority"]);
            v["prerequisites"]["stage_authority"]["expires_at_ms"] = json!(500);
            v["stage_result_refs"][stage] = json!({"state":outcome,"reference":"existing-attempt"});
            let r = report(&v);
            assert_eq!(
                r["stages"][stage]["can_attempt_stage"], false,
                "{stage}: {outcome}"
            );
            assert_eq!(r["stages"][stage]["can_request_approval"], false);
            assert_eq!(
                r["stage_result_refs"][stage]["reference"],
                "existing-attempt"
            );
        }
    }
}

#[test]
fn not_attempted_is_explicit_and_never_inferred_from_missing_receipts() {
    for (role, stage) in [("caller", "introduction"), ("callee", "reply")] {
        let mut v = compatible();
        v["context"]["role"] = json!(role);
        v["context"]["requested_stage"] = json!(stage);
        v["authority_refs"] = json!(["message-authority"]);
        v["prerequisites"]["stage_authority"]["expires_at_ms"] = json!(500);
        v["stage_result_refs"][stage] = json!({"state":"not_attempted","reference":null});
        assert_eq!(report(&v)["stages"][stage]["can_attempt_stage"], true);
        v["stage_result_refs"][stage] = json!({"state":"unknown","reference":null});
        let r = report(&v);
        assert_eq!(r["stages"][stage]["can_attempt_stage"], false);
        blocked(&r, "reconciliation_required");
    }
}

#[test]
fn positional_arrays_cannot_replace_named_contract_groups() {
    for (field, array) in [
        ("schema", json!(["compound_readiness", 1, 0])),
        ("node_binding", json!(["selected-node", "fixture"])),
        ("connection_binding", json!([7, "read-1", "client-a"])),
        ("observation", json!([1000])),
        ("accounting", json!(["complete", false, "policy-1"])),
    ] {
        let mut v = compatible();
        let current = context(&v);
        v[field] = array;
        let r = read(&v, &current);
        assert_eq!(r["implemented"], false, "{field}");
        blocked(&r, "invalid_envelope");
    }
}

const ATTEMPT_STAGES: &[&str] = &["introduction", "reply", "call", "answer"];

fn attempt_ready(stage: &str) -> Value {
    let mut v = if stage == "call" {
        call_ready()
    } else {
        compatible()
    };
    v["context"]["requested_stage"] = json!(stage);
    if ["reply", "answer"].contains(&stage) {
        v["context"]["role"] = json!("callee");
    }
    if stage == "reply" {
        v["stage_result_refs"]["reply"] = json!({"state":"not_attempted","reference":null});
    }
    v["authority_refs"] = json!(["stage-authority"]);
    v["prerequisites"]["stage_authority"]["expires_at_ms"] = json!(500);
    v
}

fn assert_attempt_blocker(
    v: &Value,
    stage: &str,
    state: &str,
    reason: &str,
    dependency: Option<&str>,
    next_action: &str,
    can_request_approval: bool,
) {
    let r = report(v);
    assert_eq!(r["implemented"], true);
    assert_eq!(r["stages"][stage]["can_prepare"], true);
    assert_eq!(r["stages"][stage]["can_attempt_stage"], false);
    assert_eq!(r["stages"][stage]["state"], state);
    assert_eq!(
        r["stages"][stage]["can_request_approval"],
        can_request_approval
    );
    let blockers: Vec<_> = r["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|b| b["stage"] == stage)
        .cloned()
        .collect();
    assert_eq!(
        blockers,
        vec![
            json!({"stage":stage,"reason":reason,"dependency":dependency,"next_action":next_action})
        ]
    );
    assert_eq!(r["authorizes_dispatch"], false);
    assert_eq!(r["revalidation_required"], true);
}

#[test]
fn attempt_ready_authority_keeps_each_selected_stage_eligible() {
    for stage in ATTEMPT_STAGES {
        let r = report(&attempt_ready(stage));
        assert_eq!(r["stages"][stage]["state"], "ready");
        assert_eq!(r["stages"][stage]["can_prepare"], true);
        assert_eq!(r["stages"][stage]["can_request_approval"], true);
        assert_eq!(r["stages"][stage]["can_attempt_stage"], true);
        assert_eq!(r["authorizes_dispatch"], false);
        assert_eq!(r["revalidation_required"], true);
    }
}

#[test]
fn attempt_expired_authority_requests_refresh() {
    for stage in ATTEMPT_STAGES {
        for expiry in [99, 100] {
            let mut v = attempt_ready(stage);
            v["prerequisites"]["stage_authority"]["expires_at_ms"] = json!(expiry);
            assert_attempt_blocker(
                &v,
                stage,
                "refused",
                "expired",
                Some("stage_authority"),
                "refresh",
                true,
            );
        }
    }
}

#[test]
fn attempt_expired_parent_authority_requests_refresh() {
    for stage in ATTEMPT_STAGES {
        for expiry in [99, 100] {
            let mut v = attempt_ready(stage);
            v["prerequisites"]["stage_authority"]["parent_expires_at_ms"] = json!(expiry);
            assert_attempt_blocker(
                &v,
                stage,
                "refused",
                "expired",
                Some("stage_authority"),
                "refresh",
                true,
            );
        }
    }
}

#[test]
fn attempt_untimed_authority_requests_freshness() {
    for stage in ATTEMPT_STAGES {
        for parent in [Value::Null, json!(500)] {
            let mut v = attempt_ready(stage);
            v["prerequisites"]["stage_authority"]["expires_at_ms"] = Value::Null;
            v["prerequisites"]["stage_authority"]["parent_expires_at_ms"] = parent;
            assert_attempt_blocker(
                &v,
                stage,
                "unknown",
                "freshness_unknown",
                Some("stage_authority"),
                "refresh",
                true,
            );
        }
    }
}

#[test]
fn attempt_missing_authority_remains_unknown() {
    for stage in ATTEMPT_STAGES {
        let mut v = attempt_ready(stage);
        v["prerequisites"]
            .as_object_mut()
            .unwrap()
            .remove("stage_authority");
        assert_attempt_blocker(
            &v,
            stage,
            "unknown",
            "prerequisite_unknown",
            Some("stage_authority"),
            "check_compatibility",
            true,
        );
    }
}

#[test]
fn attempt_missing_authority_references_remains_unknown() {
    for stage in ATTEMPT_STAGES {
        let mut v = attempt_ready(stage);
        v["authority_refs"] = json!([]);
        assert_attempt_blocker(
            &v,
            stage,
            "unknown",
            "prerequisite_unknown",
            Some("authority_consent"),
            "check_compatibility",
            true,
        );
    }
}

#[test]
fn attempt_missing_operation_identity_reports_context_change() {
    for stage in ATTEMPT_STAGES {
        let mut v = attempt_ready(stage);
        v["context"]["operation_id"] = Value::Null;
        assert_attempt_blocker(
            &v,
            stage,
            "unknown",
            "binding_changed",
            None,
            "reconnect",
            false,
        );
    }
}

#[test]
fn attempt_unselected_stage_reports_context_change() {
    for stage in ATTEMPT_STAGES {
        let mut v = attempt_ready(stage);
        v["context"]["requested_stage"] = json!("setup");
        assert_attempt_blocker(
            &v,
            stage,
            "unknown",
            "binding_changed",
            None,
            "reconnect",
            false,
        );
    }
}

#[test]
fn attempt_explicit_consent_requirement_preserves_owner_action() {
    for stage in ATTEMPT_STAGES {
        let mut v = attempt_ready(stage);
        set_check(&mut v, "stage_authority", "needs_owner", "consent_required");
        v["authority_refs"] = json!([]);
        v["prerequisites"]["stage_authority"]["expires_at_ms"] = Value::Null;
        assert_attempt_blocker(
            &v,
            stage,
            "needs_owner",
            "consent_required",
            Some("stage_authority"),
            "request_owner",
            true,
        );
    }
}

#[test]
fn attempt_observed_authority_failure_preserves_its_reason() {
    for stage in ATTEMPT_STAGES {
        for (state, reason, action) in [
            ("pending", "admission_pending", "wait"),
            ("refused", "revoked", "check_compatibility"),
            ("unknown", "prerequisite_unknown", "check_compatibility"),
        ] {
            let mut v = attempt_ready(stage);
            set_check(&mut v, "stage_authority", state, reason);
            assert_attempt_blocker(
                &v,
                stage,
                state,
                reason,
                Some("stage_authority"),
                action,
                true,
            );
        }
    }
}

#[test]
fn attempt_independent_failures_keep_each_reason() {
    let mut v = attempt_ready("introduction");
    v["context"]["operation_id"] = Value::Null;
    v["authority_refs"] = json!([]);
    v["prerequisites"]["stage_authority"]["expires_at_ms"] = json!(100);
    let r = report(&v);
    assert_eq!(r["stages"]["introduction"]["state"], "refused");
    assert_eq!(r["stages"]["introduction"]["can_prepare"], true);
    assert_eq!(r["stages"]["introduction"]["can_request_approval"], false);
    assert_eq!(r["stages"]["introduction"]["can_attempt_stage"], false);
    let reasons: Vec<_> = r["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|b| b["stage"] == "introduction")
        .map(|b| b["reason"].as_str().unwrap())
        .collect();
    assert_eq!(
        reasons,
        vec!["binding_changed", "prerequisite_unknown", "expired"]
    );
    assert_eq!(r["authorizes_dispatch"], false);
}
