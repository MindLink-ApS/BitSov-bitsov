//! App–node contract goldens (#437, M6): the owner-only `GET /api/v1/status`
//! STUN fields and the call invite / call-state responses the app consumes,
//! rendered by the live handlers with fixed inputs and compared field by field
//! with the JSON fixtures under `tests/fixtures/contract/`. The app repo reads
//! the same fixtures, so a drift on either side fails here first.
//!
//! Every fixture is one envelope, `{"request", "status", "body"}`, where
//! `body` is the handler's JSON exactly as served, except for the fields in
//! [`MASKS`]: node-generated ids and timestamps are replaced by a typed
//! placeholder *after* their shape was checked, so a mask never hides a
//! missing field, a `null` that became a value, or a value of the wrong type.
//! Client-supplied ids (operation ids, call ids) are fixed test inputs and are
//! kept literally. The contract is documented in `docs/v2/API_CALLS.md`.
//!
//! `UPDATE_GOLDENS=1 cargo test -p konsensus-api --test contract_goldens`
//! rewrites the fixtures from the live handlers (keys sorted); review the diff
//! as an API change.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use konsensus_api::handlers::introduction::IntroductionSettings;
use konsensus_api::AppState;
use konsensus_core::payloads::call::{CallEntry, Pending, Phase, Side};
use konsensus_core::NodeId;
use konsensus_storage::{OutboxOperation, SqliteStorage, Storage};
use serde_json::{json, Map, Value};
use tower::ServiceExt;

/// Directory of the fixtures, shared with the app repo.
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/contract");

/// What a mask hides, and the shape it still checks before hiding it.
#[derive(Clone, Copy, Debug)]
enum Mask {
    /// Lower-case hex string of exactly `n` characters: node ids, message
    /// ids, payment hashes, Lightning pubkeys. Placeholder `<hex{n}>`.
    Hex(usize),
    /// Non-negative integer: uptimes, counters. Placeholder `<uint>`.
    Uint,
    /// Unix time in milliseconds: a non-negative integer of at least
    /// 10^12 (so a switch to seconds fails the check instead of hiding
    /// behind the mask). Placeholder `<unix_ms>`.
    UnixMs,
}

impl Mask {
    fn placeholder(self) -> Value {
        match self {
            Mask::Hex(n) => Value::String(format!("<hex{n}>")),
            Mask::Uint => Value::String("<uint>".into()),
            Mask::UnixMs => Value::String("<unix_ms>".into()),
        }
    }

    /// `Ok` when `value` has the masked shape. `null` is never masked: it
    /// stays `null` in the fixture, so nullability is part of the contract.
    fn check(self, value: &Value) -> Result<(), String> {
        match (self, value) {
            (Mask::Hex(n), Value::String(s))
                if s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
            {
                Ok(())
            }
            (Mask::Uint, Value::Number(x)) if x.is_u64() => Ok(()),
            (Mask::UnixMs, Value::Number(x))
                if x.as_u64().is_some_and(|ms| ms >= 1_000_000_000_000) =>
            {
                Ok(())
            }
            _ => Err(format!("expected {self:?}, got {value}")),
        }
    }
}

/// The documented mask: JSON pointers over the envelope; `*` matches every
/// array index or object key at that level. A pointer that resolves to
/// nothing masks nothing (the fixture then records the field as absent).
const MASKS: &[(&str, Mask)] = &[
    // GET /api/v1/status
    ("/body/node_id", Mask::Hex(64)),
    ("/body/connected_peer_ids/*", Mask::Hex(64)),
    ("/body/lightning_node_pubkey", Mask::Hex(66)),
    ("/body/uptime_secs", Mask::Uint),
    // POST /api/v1/messages/compose (call invite)
    ("/body/message_id", Mask::Hex(64)),
    ("/body/payment_hash", Mask::Hex(64)),
    // GET /api/v1/calls?peer=
    ("/body/*/created", Mask::UnixMs),
    ("/body/*/next_block_due_ms", Mask::UnixMs),
    // GET /api/v1/pricing/peers/:id/call
    ("/body/peer_id", Mask::Hex(64)),
];

fn apply_mask(
    value: &mut Value,
    segments: &[&str],
    mask: Mask,
    at: &str,
    errors: &mut Vec<String>,
) {
    let Some((head, rest)) = segments.split_first() else {
        if value.is_null() {
            return;
        }
        match mask.check(value) {
            Ok(()) => *value = mask.placeholder(),
            Err(e) => errors.push(format!("{at}: {e}")),
        }
        return;
    };
    match (value, *head) {
        (Value::Array(items), "*") => {
            for (i, item) in items.iter_mut().enumerate() {
                apply_mask(item, rest, mask, &format!("{at}/{i}"), errors);
            }
        }
        (Value::Object(fields), "*") => {
            for (k, item) in fields.iter_mut() {
                apply_mask(item, rest, mask, &format!("{at}/{k}"), errors);
            }
        }
        (Value::Array(items), key) => {
            if let Some(item) = key.parse::<usize>().ok().and_then(|i| items.get_mut(i)) {
                apply_mask(item, rest, mask, &format!("{at}/{key}"), errors);
            }
        }
        (Value::Object(fields), key) => {
            if let Some(item) = fields.get_mut(key) {
                apply_mask(item, rest, mask, &format!("{at}/{key}"), errors);
            }
        }
        _ => {}
    }
}

/// The envelope with every [`MASKS`] field replaced by its placeholder.
fn masked(mut envelope: Value) -> Value {
    let mut errors = Vec::new();
    for (pointer, mask) in MASKS {
        let segments: Vec<&str> = pointer.trim_start_matches('/').split('/').collect();
        apply_mask(&mut envelope, &segments, *mask, "", &mut errors);
    }
    assert!(
        errors.is_empty(),
        "masked fields with the wrong shape:\n{}",
        errors.join("\n")
    );
    envelope
}

/// Keys sorted at every level, so regenerated fixtures diff cleanly.
fn canonical(value: Value) -> Value {
    match value {
        Value::Object(fields) => {
            let mut sorted: Vec<(String, Value)> = fields.into_iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = Map::new();
            for (k, v) in sorted {
                out.insert(k, canonical(v));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonical).collect()),
        other => other,
    }
}

/// Field-by-field differences between the fixture and the live rendering,
/// one line per path, so one run shows every drift.
fn diff(at: &str, expected: &Value, actual: &Value, out: &mut Vec<String>) {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            for (k, ev) in e {
                match a.get(k) {
                    Some(av) => diff(&format!("{at}/{k}"), ev, av, out),
                    None => out.push(format!(
                        "{at}/{k}: missing from the live response (fixture has {ev})"
                    )),
                }
            }
            for (k, av) in a {
                if !e.contains_key(k) {
                    out.push(format!(
                        "{at}/{k}: not in the fixture (live response has {av})"
                    ));
                }
            }
        }
        (Value::Array(e), Value::Array(a)) => {
            if e.len() != a.len() {
                out.push(format!(
                    "{at}: fixture has {} entries, live response has {}",
                    e.len(),
                    a.len()
                ));
            }
            for (i, (ev, av)) in e.iter().zip(a).enumerate() {
                diff(&format!("{at}/{i}"), ev, av, out);
            }
        }
        _ if expected != actual => {
            out.push(format!("{at}: fixture {expected}, live response {actual}"))
        }
        _ => {}
    }
}

fn update_goldens() -> bool {
    std::env::var("UPDATE_GOLDENS").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// Compare the live `(status, body)` of `request` with fixture `name`, or
/// rewrite the fixture with `UPDATE_GOLDENS=1`.
fn check_golden(name: &str, request: &str, status: StatusCode, body: Value) {
    let live = canonical(masked(json!({
        "request": request,
        "status": status.as_u16(),
        "body": body,
    })));
    let path = std::path::Path::new(FIXTURES).join(format!("{name}.json"));
    if update_goldens() {
        std::fs::create_dir_all(FIXTURES).unwrap();
        let mut text = serde_json::to_string_pretty(&live).unwrap();
        text.push('\n');
        std::fs::write(&path, text).unwrap();
        eprintln!("wrote {}", path.display());
    }
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}; run with UPDATE_GOLDENS=1 to create it",
            path.display()
        )
    });
    let expected: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut diffs = Vec::new();
    diff("", &expected, &live, &mut diffs);
    assert!(
        diffs.is_empty(),
        "{name}: live response differs from {}:\n{}\n\n\
         If the change is intended, regenerate with UPDATE_GOLDENS=1 and update docs/v2/API_CALLS.md; \
         the app repo consumes the same fixtures.",
        path.display(),
        diffs.join("\n"),
    );
}

async fn render(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", common::auth_header(state));
    let req = match body {
        Some(json) => req
            .header("content-type", "application/json")
            .body(Body::from(json.to_string()))
            .unwrap(),
        None => req.body(Body::empty()).unwrap(),
    };
    // Each request takes a fresh router over the same state.
    let response = common::test_router(Arc::clone(state))
        .oneshot(req)
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

fn call_id(n: u128) -> String {
    format!("{n:032x}")
}

// ── GET /api/v1/status: stun_url / stun_source for own, configured, absent ──

/// Own responder with a dialable advertised host: `stun_url` names it.
#[tokio::test]
async fn status_stun_own_matches_golden() {
    let state = Arc::new(AppState {
        stun_port: Some(3478),
        introduction: IntroductionSettings::fixed(Some("regtest"), Some("node.example.org:9000")),
        ..(*common::test_state()).clone()
    });
    let (status, body) = render(&state, "GET", "/api/v1/status", None).await;
    // Pinned before the mask hides it: the value, not only the shape.
    assert_eq!(body["node_id"], state.identity.node_id().to_hex());
    check_golden("status_stun_own", "GET /api/v1/status", status, body);
}

/// No responder and no dialable host: neither `stun_port` nor `stun_url`.
#[tokio::test]
async fn status_stun_absent_matches_golden() {
    let state = Arc::new(AppState {
        stun_port: None,
        max_call_minutes: 60,
        introduction: IntroductionSettings::fixed(Some("regtest"), None),
        ..(*common::test_state()).clone()
    });
    let (status, body) = render(&state, "GET", "/api/v1/status", None).await;
    assert_eq!(body["node_id"], state.identity.node_id().to_hex());
    check_golden("status_stun_absent", "GET /api/v1/status", status, body);
}

/// Own responder without a dialable host, but a valid `[network]
/// stun_server`: `stun_url` names the configured server, `stun_source` is
/// `configured` (#426).
#[tokio::test]
async fn status_stun_configured_matches_golden() {
    let state = Arc::new(AppState {
        stun_port: Some(3478),
        introduction: IntroductionSettings::fixed(Some("regtest"), None),
        configured_stun_server: Some("stun.example.org:3478".into()),
        ..(*common::test_state()).clone()
    });
    let (status, body) = render(&state, "GET", "/api/v1/status", None).await;
    assert_eq!(body["node_id"], state.identity.node_id().to_hex());
    check_golden("status_stun_configured", "GET /api/v1/status", status, body);
}

// ── Calls: invite (compose), refusal, open calls, call price ─────────────────

/// One node with a contact (E2EE session, connected, keysend pubkey known)
/// whose callee answers every call price query with 10 000 msat.
async fn call_fixture() -> (
    Arc<AppState>,
    Arc<SqliteStorage>,
    NodeId,
    tokio::task::JoinHandle<()>,
) {
    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let mut state = common::test_state_with_lightning_and_storage(wallet, store.clone());
    let peer = common::setup_e2ee_session(&state.session_manager).await;
    state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(peer, format!("02{}", "ab".repeat(32)));
    let transport = Arc::new(common::ConnectedStubTransport::new(
        vec![peer],
        state.invoice_requests.clone(),
    ));
    Arc::get_mut(&mut state).unwrap().transport = transport;
    let prices = state.peer_prices.clone();
    let answering = tokio::spawn(async move {
        loop {
            prices.update_kind_price(peer, 400, 10_000, 850_000).await;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    });
    (state, store, peer, answering)
}

/// The call flow the app drives: price the call, send the invite, see the
/// call in the open-calls view, and the fixed refusal when a call id is
/// reused. One test, because the steps build on each other.
#[tokio::test]
async fn call_invite_and_call_state_match_goldens() {
    let (state, store, peer, answering) = call_fixture().await;
    let peer_hex = peer.to_hex();

    // The callee's live call price, asked before inviting.
    let (status, body) = render(
        &state,
        "GET",
        &format!("/api/v1/pricing/peers/{peer_hex}/call"),
        None,
    )
    .await;
    assert_eq!(
        body["peer_id"], peer_hex,
        "the requested peer, before the mask hides it"
    );
    check_golden(
        "peer_call_price",
        "GET /api/v1/pricing/peers/:id/call",
        status,
        body,
    );

    // The invite: paid at the quoted price and dispatched.
    let call = call_id(0xca11);
    let operation = "6f1d2b1e-7a5c-4c9f-9d8e-1f2a3b4c5d6e";
    let offer = format!(r#"{{"v":1,"call_id":"{call}","media":"audio","sdp":"v=0"}}"#);
    let invite = json!({
        "operation_id": operation,
        "recipient": peer_hex,
        "kind": 400,
        "plaintext": offer,
        "wait_ack_ms": 0,
    });
    let (status, body) = render(&state, "POST", "/api/v1/messages/compose", Some(invite)).await;
    check_golden(
        "call_invite_accepted",
        "POST /api/v1/messages/compose (kind 400)",
        status,
        body,
    );

    // A new operation reusing that call id: the documented non-dispatch refusal.
    let reuse = json!({
        "operation_id": "0b5e8a2d-3c4f-4e6a-8b7c-9d0e1f2a3b4c",
        "recipient": peer_hex,
        "kind": 400,
        "plaintext": offer,
        "wait_ack_ms": 0,
    });
    let (status, body) = render(&state, "POST", "/api/v1/messages/compose", Some(reuse)).await;
    check_golden(
        "call_invite_refused_call_id_used",
        "POST /api/v1/messages/compose (kind 400)",
        status,
        body,
    );

    // Open calls: the ringing invite above, plus a live incoming call and an
    // ended call whose offer payment is still unresolved (bound to its journal
    // row, so `created` is that operation's time). Unresolved first, then id.
    let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
    let in_an_hour = now + 3_600_000;
    store
        .call_put(
            &peer,
            &call_id(0xa11ce),
            &CallEntry {
                phase: Phase::Live,
                side: Side::Callee,
                deadline_ms: in_an_hour,
                pending: None,
                paid_until_ms: None,
                next_block_seq: 0,
                end_reason: None,
                unpaid_notice_used: false,
            },
        )
        .await
        .unwrap();
    let unresolved = "2d7c6b5a-4938-4f2e-9a1b-0c9d8e7f6a5b";
    let mut op = OutboxOperation::prepared(
        unresolved.into(),
        peer_hex.clone(),
        400,
        "offer-hash".into(),
    );
    op.state = "payment_unknown".into();
    op.created_at = 1_790_000_000_000;
    assert!(store.insert_outbox_operation(&op).await.unwrap());
    store
        .call_put(
            &peer,
            &call_id(0xdead),
            &CallEntry {
                phase: Phase::Ended,
                side: Side::Caller,
                deadline_ms: in_an_hour,
                paid_until_ms: None,
                next_block_seq: 0,
                end_reason: None,
                unpaid_notice_used: false,
                pending: Some(Pending {
                    operation_id: unresolved.into(),
                    kind: 400,
                    request_hash: "offer-hash".into(),
                }),
            },
        )
        .await
        .unwrap();
    let (status, body) = render(
        &state,
        "GET",
        &format!("/api/v1/calls?peer={peer_hex}"),
        None,
    )
    .await;
    assert_eq!(
        body[0]["created"], 1_790_000_000_000_u64,
        "the bound journal row's time, before the mask hides it"
    );
    check_golden(
        "calls_open_by_peer",
        "GET /api/v1/calls?peer=<node-id>",
        status,
        body,
    );

    // A valid peer with no calls, and a malformed peer.
    let stranger = NodeId::from_bytes([7; 32]).to_hex();
    let (status, body) = render(
        &state,
        "GET",
        &format!("/api/v1/calls?peer={stranger}"),
        None,
    )
    .await;
    check_golden(
        "calls_open_by_peer_empty",
        "GET /api/v1/calls?peer=<node-id>",
        status,
        body,
    );
    let (status, body) = render(&state, "GET", "/api/v1/calls?peer=not-a-node-id", None).await;
    check_golden(
        "calls_invalid_peer",
        "GET /api/v1/calls?peer=not-a-node-id",
        status,
        body,
    );

    answering.abort();
}

// ── The mask itself ──────────────────────────────────────────────────────────

/// A mask hides a value only after checking its shape; `null` stays `null`.
#[test]
fn mask_checks_shape_before_hiding() {
    let ok = masked(
        json!({"body": {"node_id": "ab".repeat(32), "uptime_secs": 42, "lightning_node_pubkey": null}}),
    );
    assert_eq!(ok["body"]["node_id"], "<hex64>");
    assert_eq!(ok["body"]["uptime_secs"], "<uint>");
    assert!(
        ok["body"]["lightning_node_pubkey"].is_null(),
        "null is part of the contract, not masked"
    );
    let calls = masked(json!({"body": [{"created": 1_790_000_000_000_u64}, {"created": null}]}));
    assert_eq!(calls["body"][0]["created"], "<unix_ms>");
    assert!(calls["body"][1]["created"].is_null());
    for bad in [
        json!({"body": {"node_id": "AB".repeat(32)}}),
        json!({"body": {"node_id": "ab".repeat(31)}}),
        json!({"body": {"uptime_secs": -1}}),
        json!({"body": {"uptime_secs": "42"}}),
        json!({"body": [{"created": 1.5}]}),
        json!({"body": [{"created": 1_790_000_000}]}), // seconds, not milliseconds
        json!({"body": [{"created": "1790000000000"}]}),
    ] {
        let shape = std::panic::catch_unwind(|| masked(bad.clone()));
        assert!(shape.is_err(), "{bad} must be rejected, not hidden");
    }
}

/// The comparison reports every differing path, including missing and extra
/// fields and array length, in one run.
#[test]
fn diff_reports_every_drift() {
    let fixture = json!({"status": 200, "body": {"a": 1, "b": [1, 2], "c": null}});
    let live = json!({"status": 400, "body": {"a": 1, "b": [1], "d": true}});
    let mut out = Vec::new();
    diff("", &fixture, &live, &mut out);
    assert_eq!(out.len(), 4, "{out:?}");
    assert!(out.iter().any(|l| l.starts_with("/status:")), "{out:?}");
    assert!(out.iter().any(|l| l.starts_with("/body/b:")), "{out:?}");
    assert!(out.iter().any(|l| l.starts_with("/body/c:")), "{out:?}");
    assert!(out.iter().any(|l| l.starts_with("/body/d:")), "{out:?}");
    let mut same = Vec::new();
    diff("", &fixture, &fixture, &mut same);
    assert!(same.is_empty());
}
