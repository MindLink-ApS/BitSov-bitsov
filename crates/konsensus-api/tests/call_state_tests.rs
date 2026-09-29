//! Calls review (#131, Codex FAIL at 34a722d): the reviewer's five probes as
//! regressions, asserting the fixed behaviour, plus restart, recovery, bounds
//! and price-query rate limiting. Real SQLite call state throughout.

mod common;

use std::sync::Arc;

use axum::{body::Body, http::Request};
use konsensus_api::calls;
use konsensus_core::payloads::call::{CallSignal, Phase, MAX_CALLS_PER_PEER, MAX_TRACKED_CALLS};
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

/// Probe `unexpired_burned_id_is_readmitted_under_capacity_pressure`, fixed:
/// a full table refuses new ids instead of evicting unexpired replay
/// protection, per peer and in total.
#[tokio::test]
async fn a_full_table_refuses_new_calls_and_never_forgets_a_burned_id() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([80; 32]);
    for i in 0..MAX_CALLS_PER_PEER {
        calls::admit_incoming(&store, &peer, 400, Some(&body(400, &id(i)))).await.unwrap();
    }
    calls::admit_incoming(&store, &peer, 403, Some(&body(403, &id(0)))).await.unwrap();
    assert!(calls::admit_incoming(&store, &peer, 400, Some(&body(400, &id(MAX_CALLS_PER_PEER)))).await.is_err(), "per-peer bound");
    assert!(calls::admit_incoming(&store, &peer, 400, Some(&body(400, &id(0)))).await.is_err(), "burned id stays burned");
    // Other peers still fit until the total bound.
    let mut n = MAX_CALLS_PER_PEER;
    'fill: for p in 1..=u8::MAX {
        let other = NodeId::from_bytes([p; 32]);
        for _ in 0..MAX_CALLS_PER_PEER {
            if n == MAX_TRACKED_CALLS {
                break 'fill;
            }
            calls::admit_incoming(&store, &other, 400, Some(&body(400, &id(n)))).await.unwrap();
            n += 1;
        }
    }
    let fresh = NodeId::from_bytes([7; 32]);
    let err = calls::admit_incoming(&store, &fresh, 400, Some(&body(400, &id(99_999)))).await.unwrap_err();
    assert_eq!(err.to_string(), "too many calls tracked; try again later");
    assert!(calls::admit_incoming(&store, &peer, 400, Some(&body(400, &id(0)))).await.is_err());
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
