//! Calls review (#131, Codex FAIL at 34a722d): the reviewer's five probes as
//! regressions, asserting the fixed behaviour, plus restart, recovery, bounds
//! and price-query rate limiting. Real SQLite call state throughout.

mod common;

use std::sync::Arc;

use axum::{body::Body, http::Request};
use konsensus_api::calls;
use konsensus_core::payloads::call::{CallEntry, CallSignal, Phase, Side, BURN_MIN_MS, MAX_BURNED_PER_PEER, MAX_OPEN_CALLS_PER_PEER, TOMBSTONE_MS};
use konsensus_core::traits::lightning::LightningProvider;
use konsensus_core::{NodeId, PaymentProof, Recipient, UkmEnvelopeBuilder};
use konsensus_storage::{SqliteStorage, Storage};
use tower::ServiceExt;

fn body(kind: u16, id: &str) -> String {
    let extra = match kind {
        400 => r#","media":"audio","sdp":"v=0""#,
        401 => r#","sdp":"v=0""#,
        402 => r#","candidate":"x""#,
        _ => "",
    };
    format!(r#"{{"v":1,"call_id":"{id}"{extra}}}"#)
}

fn id(n: usize) -> String {
    format!("{n:032x}")
}

async fn sqlite_state(wallet: Arc<konsensus_lightning::MockLightningProvider>) -> Arc<konsensus_api::AppState> {
    let mut state = common::test_state_with_lightning(wallet);
    Arc::get_mut(&mut state).unwrap().storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    state
}

async fn compose(state: &Arc<konsensus_api::AppState>, op: &str, peer: &NodeId, kind: u16, plaintext: &str) -> serde_json::Value {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", common::auth_header(state))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"operation_id": op, "recipient": peer.to_hex(), "kind": kind, "plaintext": plaintext, "wait_ack_ms": 0}).to_string(),
        ))
        .unwrap();
    let response = common::test_router(Arc::clone(state)).oneshot(req).await.unwrap();
    serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
}

/// Probe `failed_unpaid_compose_burns_id_and_accepts_answer`, fixed: an unpaid
/// offer does not burn its id, a same-operation retry gets the same answer, and
/// no answer is accepted for it.
#[tokio::test]
async fn an_unpaid_offer_burns_nothing_and_accepts_no_answer() {
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let state = sqlite_state(wallet.clone()).await;
    let peer = NodeId::from_bytes([81; 32]);
    let call = id(0x8100);
    let op = uuid::Uuid::new_v4().to_string();
    let first = compose(&state, &op, &peer, 400, &body(400, &call)).await;
    println!("offer: {first}");
    let reason = first["reason"].as_str().unwrap().to_string();
    assert!(["call_needs_contact", "call_price_unknown"].contains(&reason.as_str()), "{first}");
    assert!(wallet.list_payments(100).await.unwrap().is_empty());
    let retry = compose(&state, &op, &peer, 400, &body(400, &call)).await;
    assert_eq!(retry["reason"], reason.as_str(), "same operation, same refusal, not call_id_used: {retry}");
    assert!(calls::admit_incoming(state.storage.as_ref(), &peer, 401, Some(&body(401, &call))).await.is_err());
    // Released: the id was never sent, so another operation may offer it.
    assert!(calls::reserve_outgoing(state.storage.as_ref(), &peer, 400, &body(400, &call), "other-op").await.is_ok());
}

/// Probe `unpaid_failed_answer_advances_call_and_blocks_retry`, fixed: the call
/// keeps ringing, and the answer can be retried.
#[tokio::test]
async fn an_unpaid_answer_leaves_the_call_ringing_and_retryable() {
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let state = sqlite_state(wallet.clone()).await;
    let peer = NodeId::from_bytes([84; 32]);
    let call = id(0x8400);
    calls::admit_incoming(state.storage.as_ref(), &peer, 400, Some(&body(400, &call))).await.unwrap();
    let op = uuid::Uuid::new_v4().to_string();
    let first = compose(&state, &op, &peer, 401, &body(401, &call)).await;
    println!("answer: {first}");
    assert_ne!(first["reason"], "call_not_live", "{first}");
    assert!(wallet.list_payments(100).await.unwrap().is_empty());
    let retry = compose(&state, &op, &peer, 401, &body(401, &call)).await;
    assert_eq!(retry["reason"], first["reason"], "{retry}");
    let entry = state.storage.call_get(&peer, &call).await.unwrap().unwrap();
    assert_eq!((entry.phase, entry.pending), (Phase::Ringing, None));
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Offer and hang up `n` calls from `peer`, one at a time (ids `from..from+n`).
async fn burn(store: &SqliteStorage, peer: &NodeId, from: usize, n: usize) {
    for i in from..from + n {
        calls::admit_incoming(store, peer, 400, Some(&body(400, &id(i)))).await.unwrap();
        calls::admit_incoming(store, peer, 403, Some(&body(403, &id(i)))).await.unwrap();
    }
}

/// Probe `unexpired_burned_id_is_readmitted_under_capacity_pressure`, still
/// fixed: under pressure, an id burned less than `BURN_MIN_MS` ago is never
/// dropped; the pair is refused instead. Fable N3: that refusal is per pair,
/// not node-wide, and ended calls never count against open ones.
#[tokio::test]
async fn young_burned_ids_are_never_dropped_and_only_block_their_own_pair() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([80; 32]);
    burn(&store, &peer, 0, MAX_BURNED_PER_PEER as usize).await;
    let err = calls::admit_incoming(&store, &peer, 400, Some(&body(400, &id(100_000)))).await.unwrap_err();
    assert_eq!(err.to_string(), "too many calls tracked; try again later");
    assert!(calls::admit_incoming(&store, &peer, 400, Some(&body(400, &id(0)))).await.is_err(), "burned id stays burned");
    assert!(store.call_get(&peer, &id(0)).await.unwrap().is_some(), "nothing young was evicted");
    // Another pair is unaffected, and so is our own call to someone else.
    let other = NodeId::from_bytes([79; 32]);
    calls::admit_incoming(&store, &other, 400, Some(&body(400, &id(100_001)))).await.unwrap();
    calls::reserve_outgoing(&store, &NodeId::from_bytes([78; 32]), 400, &body(400, &id(100_002)), "op-elsewhere").await.unwrap();
}

/// Fable N3: past `BURN_MIN_MS`, the oldest burned ids of a pair make room for
/// a new call instead of blocking the pair for the rest of the day; younger
/// ones stay burned.
#[tokio::test]
async fn burned_ids_older_than_the_minimum_make_room_oldest_first() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([77; 32]);
    let now = now_ms();
    // 255 calls that ended more than BURN_MIN_MS ago (oldest = id 0) ...
    for i in 0..MAX_BURNED_PER_PEER as usize - 1 {
        let ended = now - BURN_MIN_MS - 60_000 * (MAX_BURNED_PER_PEER - i as u64);
        let entry = CallEntry { side: Side::Callee, phase: Phase::Ended, deadline_ms: ended + TOMBSTONE_MS, pending: None };
        store.call_put(&peer, &id(i), &entry).await.unwrap();
    }
    // ... and one that just ended.
    let young = MAX_BURNED_PER_PEER as usize - 1;
    burn(&store, &peer, young, 1).await;
    calls::admit_incoming(&store, &peer, 400, Some(&body(400, &id(1_000)))).await.unwrap();
    assert!(store.call_get(&peer, &id(0)).await.unwrap().is_none(), "the oldest burned id made room");
    assert!(store.call_get(&peer, &id(1)).await.unwrap().is_some(), "only as many as needed");
    assert!(calls::admit_incoming(&store, &peer, 400, Some(&body(400, &id(young)))).await.is_err(), "the young id stays burned");
    assert!(calls::admit_incoming(&store, &peer, 400, Some(&body(400, &id(1)))).await.is_err(), "an old id not needed for room stays burned");
}

/// Fable N3: open calls have their own small bound, and ending one frees it.
#[tokio::test]
async fn open_calls_are_bounded_per_peer_and_freed_by_hangup() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([76; 32]);
    for i in 0..MAX_OPEN_CALLS_PER_PEER as usize {
        calls::admit_incoming(&store, &peer, 400, Some(&body(400, &id(i)))).await.unwrap();
    }
    let next = id(MAX_OPEN_CALLS_PER_PEER as usize);
    assert!(calls::admit_incoming(&store, &peer, 400, Some(&body(400, &next))).await.is_err());
    calls::admit_incoming(&store, &peer, 403, Some(&body(403, &id(0)))).await.unwrap();
    calls::admit_incoming(&store, &peer, 400, Some(&body(400, &next))).await.unwrap();
}

/// Fable N2: one operation id pays for one signal of one call. Reusing it for
/// another call id is refused before any reservation, whether the first
/// request is still reserved or already in the journal.
#[tokio::test]
async fn an_operation_id_reused_for_another_call_is_refused_before_reserving() {
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let state = sqlite_state(wallet.clone()).await;
    let store = state.storage.as_ref();
    let peer = NodeId::from_bytes([75; 32]);
    // Still reserved under the operation.
    calls::reserve_outgoing(store, &peer, 400, &body(400, &id(1)), "op-reused").await.unwrap();
    calls::reserve_outgoing(store, &peer, 400, &body(400, &id(1)), "op-reused").await.unwrap();
    let err = calls::reserve_outgoing(store, &peer, 400, &body(400, &id(2)), "op-reused").await.unwrap_err();
    assert!(format!("{err:?}").contains("operation_mismatch"), "{err:?}");
    assert!(store.call_get(&peer, &id(2)).await.unwrap().is_none());
    // In the journal (the first request was refused and released).
    let op = uuid::Uuid::new_v4().to_string();
    let first = compose(&state, &op, &peer, 400, &body(400, &id(3))).await;
    assert!(first["reason"].is_string(), "{first}");
    let second = compose(&state, &op, &peer, 400, &body(400, &id(4))).await;
    assert_eq!(second["code"], "operation_mismatch", "{second}");
    assert!(store.call_get(&peer, &id(4)).await.unwrap().is_none(), "no reservation for the second call");
    assert!(calls::admit_incoming(store, &peer, 401, Some(&body(401, &id(4)))).await.is_err(), "nothing to answer");
    assert!(wallet.list_payments(100).await.unwrap().is_empty());
}

/// Probe `unrelated_price_response_satisfies_call_quote`, fixed: only a kind-400
/// answer after the query counts.
#[tokio::test]
async fn an_unrelated_price_response_is_not_a_call_quote() {
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let mut state = common::test_state_with_lightning(wallet);
    let peer = NodeId::from_bytes([82; 32]);
    let transport = Arc::new(common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone()));
    Arc::get_mut(&mut state).unwrap().transport = transport;
    state.peer_prices.update_kind_price(peer, 400, 10_000, 100).await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let update = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        state.peer_prices.update_kind_price(peer, 0, 2_000, 100).await;
    };
    let (price, ()) = tokio::join!(calls::peer_call_price(&state, &peer), update);
    let err = price.unwrap_err();
    assert!(format!("{err:?}").contains("call_price_unknown"), "{err:?}");
    // A real kind-400 answer after the query does count.
    let answer = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        state.peer_prices.update_kind_price(peer, 400, 12_000, 100).await;
    };
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    let (price, ()) = tokio::join!(calls::peer_call_price(&state, &peer), answer);
    assert_eq!(price.unwrap(), 12_000);
}

/// Fable follow-up: concurrent quotes to one peer send one `PriceQuery`.
#[tokio::test]
async fn price_queries_to_one_peer_are_rate_limited() {
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let mut state = common::test_state_with_lightning(wallet);
    let peer = NodeId::from_bytes([85; 32]);
    let transport = Arc::new(common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone()));
    Arc::get_mut(&mut state).unwrap().transport = Arc::clone(&transport) as _;
    let answer = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        state.peer_prices.update_kind_price(peer, 400, 10_000, 100).await;
    };
    let (a, b, c, ()) = tokio::join!(calls::peer_call_price(&state, &peer), calls::peer_call_price(&state, &peer), calls::peer_call_price(&state, &peer), answer);
    assert_eq!((a.unwrap(), b.unwrap(), c.unwrap()), (10_000, 10_000, 10_000));
    let queries = transport.raw_frames.lock().unwrap().iter()
        .filter(|f| matches!(konsensus_message::wire::Frame::from_bytes(f), Ok(konsensus_message::wire::Frame::PriceQuery { kind: 400 })))
        .count();
    assert_eq!(queries, 1);
}

/// Fable N4: a price query that could not be sent does not hold the peer's
/// query slot: it fails at once, and the next quote sends its own query.
#[tokio::test]
async fn a_price_query_that_was_not_sent_does_not_hold_the_slot() {
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let mut state = common::test_state_with_lightning(wallet);
    let peer = NodeId::from_bytes([74; 32]);
    // The default stub cannot send raw frames.
    let started = std::time::Instant::now();
    let err = calls::peer_call_price(&state, &peer).await.unwrap_err();
    assert!(format!("{err:?}").contains("call_price_unknown"), "{err:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(1), "no wait for an unsent query");
    let transport = Arc::new(common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone()));
    Arc::get_mut(&mut state).unwrap().transport = Arc::clone(&transport) as _;
    let answer = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        state.peer_prices.update_kind_price(peer, 400, 10_000, 100).await;
    };
    let (price, ()) = tokio::join!(calls::peer_call_price(&state, &peer), answer);
    assert_eq!(price.unwrap(), 10_000);
    let queries = transport.raw_frames.lock().unwrap().iter()
        .filter(|f| matches!(konsensus_message::wire::Frame::from_bytes(f), Ok(konsensus_message::wire::Frame::PriceQuery { kind: 400 })))
        .count();
    assert_eq!(queries, 1, "within the 2 s window, the retry still asked");
}

/// Probe `rejected_stored_call_signal_reaches_ws_through_resync`, fixed: once
/// the receive path withdraws a refused signal, resync cannot deliver it, and
/// the receipt no longer counts as accepted.
#[tokio::test]
async fn a_refused_signal_is_not_delivered_by_resync_or_counted_accepted() {
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let mut state = sqlite_state(wallet).await;
    let cipher = Arc::new(konsensus_crypto::plaintext_cache::PlaintextCacheCipher::new(&[1; 32]));
    Arc::get_mut(&mut state).unwrap().plaintext_cipher = Some(cipher.clone());
    let peer = NodeId::from_bytes([83; 32]);
    let text = body(402, &id(0x8300));
    let env = UkmEnvelopeBuilder::new(402, peer, Recipient::Node(*state.identity.node_id()), vec![], PaymentProof::new([2; 32], [3; 32], 1000)).build();
    // As the receive path leaves it: paid acceptance stored, plaintext cached.
    assert!(matches!(state.storage.accept_paid_envelope(&env).await.unwrap(), konsensus_storage::PaidAcceptance::Accepted));
    state.storage.store_message_plaintext(&env.id, &cipher.encrypt(text.as_bytes()).unwrap()).await.unwrap();
    assert!(calls::admit_incoming(state.storage.as_ref(), &peer, 402, Some(&text)).await.is_err());
    state.storage.reject_accepted_envelope(&env).await.unwrap();
    assert!(state.storage.get_message(&env.id).await.unwrap().is_none());
    assert!(!state.storage.is_paid_envelope_accepted(&env).await.unwrap(), "no duplicate-ACK path");
    // A resend of the same paid envelope is not re-accepted.
    assert!(!matches!(state.storage.accept_paid_envelope(&env).await.unwrap(), konsensus_storage::PaidAcceptance::Accepted | konsensus_storage::PaidAcceptance::AlreadyAccepted));
    let mut ws = state.ws_broadcast.subscribe();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/resync")
        .header("authorization", common::auth_header(&state))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"phase": "fulfill", "peer_id": peer.to_hex(), "message_ids": [env.id.to_hex()]}).to_string()))
        .unwrap();
    let response = common::test_router(state).oneshot(req).await.unwrap();
    assert!(response.status().is_success() || response.status().is_client_error());
    assert!(ws.try_recv().is_err(), "refused signal must not reach WS");
}

/// Codex P2: a restart keeps burned ids and live calls.
#[tokio::test]
async fn call_state_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sqlite");
    let peer = NodeId::from_bytes([86; 32]);
    let (theirs, mine) = (id(1), id(2));
    {
        let store = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
        calls::admit_incoming(&store, &peer, 400, Some(&body(400, &theirs))).await.unwrap();
        calls::admit_incoming(&store, &peer, 403, Some(&body(403, &theirs))).await.unwrap();
        calls::reserve_outgoing(&store, &peer, 400, &body(400, &mine), "op-mine").await.unwrap();
        calls::commit_outgoing(&store, &peer, &body(400, &mine), "op-mine").await;
        store.pool().close().await;
    }
    let store = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    assert!(calls::admit_incoming(&store, &peer, 400, Some(&body(400, &theirs))).await.is_err(), "burned id after restart");
    assert!(calls::admit_incoming(&store, &peer, 401, Some(&body(401, &mine))).await.is_ok(), "our paid offer still rings");
}

/// Codex P1/P2: recovery settles what a crash left, from the operation journal.
#[tokio::test]
async fn recovery_commits_paid_releases_unpaid_and_keeps_ambiguous() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([87; 32]);
    for (n, state) in [(1, Some("acked")), (2, Some("prepared")), (3, Some("payment_unknown")), (4, None)] {
        let op = format!("00000000-0000-4000-8000-00000000000{n}");
        calls::reserve_outgoing(&store, &peer, 400, &body(400, &id(n)), &op).await.unwrap();
        if let Some(state) = state {
            let mut row = konsensus_storage::OutboxOperation::prepared(op.clone(), peer.to_hex(), 400, "h".into());
            assert!(store.insert_outbox_operation(&row).await.unwrap());
            row.state = state.into();
            assert!(store.update_outbox_operation(&row).await.unwrap());
        }
    }
    assert_eq!(calls::recover(&store).await.unwrap(), (1, 2));
    assert_eq!(store.call_get(&peer, &id(1)).await.unwrap().unwrap().phase, Phase::Ringing);
    assert!(store.call_get(&peer, &id(2)).await.unwrap().is_none());
    let kept = store.call_get(&peer, &id(3)).await.unwrap().unwrap();
    assert_eq!((kept.phase, kept.pending.map(|p| p.kind)), (Phase::Reserved, Some(400)));
    assert!(store.call_get(&peer, &id(4)).await.unwrap().is_none());
    // The kept one resolves when its same-operation retry finds it paid.
    let _ = CallSignal::parse(400, &body(400, &id(3))).unwrap();
}
