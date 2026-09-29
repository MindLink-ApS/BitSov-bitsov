//! This node's 1:1 call state (kinds 400-403), shared by the compose path
//! (outgoing) and the receive path (incoming). The rules are the pure
//! transitions in [`konsensus_core::payloads::call`]; the state is stored
//! durably (`call_state`), so a restart keeps used ids, live calls and our
//! reserved signals.
//!
//! Outgoing: `reserve` (before any quote or payment, bound to the operation
//! id) → `commit` (once the payment settled, before dispatch) → `resolve`
//! (after compose returns: release a definite nonpayment, keep an ambiguous
//! one for a same-operation retry). `recover` settles or releases what a crash
//! left, before the receive and outbox workers start.
//!
//! Read-modify-write is serialised by one process-wide async lock; the
//! backing store is one node's database.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use konsensus_core::payloads::call::{self as rules, CallEntry, CallRefusal, CallSignal, Settlement};
use konsensus_core::types::NodeId;
use konsensus_storage::Storage;

use crate::error::ApiError;
use crate::state::AppState;

/// How long to wait for the callee's own answer to a call price query.
const PRICE_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// A call price answer older than this is not a quote.
const PRICE_ANSWER_MAX_AGE: Duration = Duration::from_secs(60);
/// At most one `PriceQuery` per peer this often; callers inside the window
/// wait for that query's answer instead of sending another (Fable follow-up).
const PRICE_QUERY_MIN_INTERVAL: Duration = Duration::from_secs(2);

fn lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Whether `kind` is 1:1 call signalling (400-403).
pub fn is_call_kind(kind: u16) -> bool {
    (konsensus_core::kind::KIND_CALL_INVITE..=konsensus_core::kind::KIND_CALL_HANGUP).contains(&kind)
}

type Store<'a> = &'a dyn Storage;

async fn current(store: Store<'_>, peer: &NodeId, call_id: &str, now: u64) -> Result<Option<CallEntry>, konsensus_storage::StorageError> {
    Ok(store.call_get(peer, call_id).await?.and_then(|e| e.at(now)))
}

async fn write(store: Store<'_>, peer: &NodeId, call_id: &str, entry: Option<&CallEntry>) -> Result<(), konsensus_storage::StorageError> {
    match entry {
        Some(e) => store.call_put(peer, call_id, e).await,
        None => store.call_delete(peer, call_id).await,
    }
}

/// Room for a new call id. Open calls must fit their bounds and are never
/// evicted. Burned ids have their own bounds: past one, the oldest ids burned
/// for at least `BURN_MIN_MS` make room, so ended calls cannot block a pair or
/// the node for the whole tombstone (Fable N3); younger ones are never
/// dropped, and if they alone fill a bound the call is refused.
async fn room(store: Store<'_>, peer: &NodeId, now: u64) -> Result<(), CallRefusal> {
    let unavailable = |_: konsensus_storage::StorageError| CallRefusal::Invalid("call state unavailable");
    let counts = store.call_counts(peer, now).await.map_err(unavailable)?;
    rules::has_room(&counts)?;
    let until = rules::evictable_until(now);
    let excess = rules::burned_excess(counts.burned_peer, rules::MAX_BURNED_PER_PEER);
    let mut freed = 0;
    if excess > 0 {
        freed = store.call_evict_burned(Some(peer), until, now, excess).await.map_err(unavailable)?;
        if freed < excess {
            return Err(CallRefusal::Full);
        }
    }
    let excess = rules::burned_excess(counts.burned_total.saturating_sub(freed), rules::MAX_BURNED_CALLS);
    if excess > 0 && store.call_evict_burned(None, until, now, excess).await.map_err(unavailable)? < excess {
        return Err(CallRefusal::Full);
    }
    Ok(())
}

/// Admit a signal this node received (after the payment gate). A refusal
/// means it must not reach the app (the caller also withdraws the stored message).
pub async fn admit_incoming(store: Store<'_>, peer: &NodeId, kind: u16, plaintext: Option<&str>) -> Result<CallSignal, CallRefusal> {
    let signal = CallSignal::parse(kind, plaintext.ok_or(CallRefusal::Invalid("undecryptable"))?)?;
    let _g = lock().lock().await;
    let now = now_ms();
    let unavailable = |_| CallRefusal::Invalid("call state unavailable");
    let entry = current(store, peer, &signal.call_id, now).await.map_err(unavailable)?;
    if entry.is_none() {
        room(store, peer, now).await?;
    }
    let next = rules::receive(entry, kind, now)?;
    write(store, peer, &signal.call_id, Some(&next)).await.map_err(unavailable)?;
    Ok(signal)
}

fn refused(e: CallRefusal) -> ApiError {
    let reason = match e {
        CallRefusal::Replayed => "call_id_used",
        CallRefusal::Full => "call_busy",
        CallRefusal::InFlight => "call_signal_in_flight",
        CallRefusal::Invalid(_) | CallRefusal::NotCallKind => "call_signal_invalid",
        _ => "call_not_live",
    };
    ApiError::BadRequest(e.to_string()).with_reason(reason)
}

/// Reserve one of our signals under `operation_id`, before any quote or payment.
/// An operation id already reserving a signal for another call is refused
/// (Fable N2): one operation pays for one signal of one call.
pub async fn reserve_outgoing(store: Store<'_>, peer: &NodeId, kind: u16, plaintext: &str, operation_id: &str) -> Result<(), ApiError> {
    let signal = CallSignal::parse(kind, plaintext).map_err(refused)?;
    let _g = lock().lock().await;
    let now = now_ms();
    let storage = |e: konsensus_storage::StorageError| ApiError::Internal(format!("call state: {e}"));
    let elsewhere = store.call_pending().await.map_err(storage)?.into_iter().any(|(p, call_id, e)| {
        e.pending.is_some_and(|x| x.operation_id == operation_id) && (p != *peer || call_id != signal.call_id)
    });
    if elsewhere {
        return Err(ApiError::OperationConflict("operation_mismatch"));
    }
    let entry = current(store, peer, &signal.call_id, now).await.map_err(storage)?;
    if entry.is_none() && kind == konsensus_core::kind::KIND_CALL_INVITE {
        room(store, peer, now).await.map_err(refused)?;
    }
    let next = rules::reserve(entry.clone(), kind, operation_id, now).map_err(refused)?;
    if entry.as_ref() != Some(&next) {
        write(store, peer, &signal.call_id, Some(&next)).await.map_err(storage)?;
    }
    Ok(())
}

async fn settle(store: Store<'_>, peer: &NodeId, call_id: &str, operation_id: &str, how: Settlement) -> Result<(), konsensus_storage::StorageError> {
    let _g = lock().lock().await;
    let now = now_ms();
    let Some(entry) = store.call_get(peer, call_id).await? else { return Ok(()) };
    if entry.pending.as_ref().is_none_or(|p| p.operation_id != operation_id) {
        return Ok(());
    }
    let next = match how {
        Settlement::Paid => Some(rules::commit(entry, operation_id, now)),
        Settlement::Unpaid => rules::release(entry, operation_id),
        Settlement::Ambiguous => return Ok(()),
    };
    write(store, peer, call_id, next.as_ref()).await
}

/// The reserved signal's payment settled: publish its transition before the
/// envelope goes out, so the peer's reply finds a paid call. Never fails the
/// send (money already moved): a store error is logged and `resolve` or
/// `recover` commits later from the operation journal.
pub async fn commit_outgoing(store: Store<'_>, peer: &NodeId, plaintext: &str, operation_id: &str) {
    let Ok(signal) = serde_json::from_str::<CallSignal>(plaintext) else { return };
    if let Err(e) = settle(store, peer, &signal.call_id, operation_id, Settlement::Paid).await {
        tracing::warn!(peer = %peer, error = %e, "call commit after settlement failed; recovery will retry");
    }
}

/// After compose returned (either way): read the operation journal and commit,
/// release (definite nonpayment) or keep (ambiguous) the reservation. A
/// journal entry for a different request (`request_hash`) never paid for this
/// signal: the reservation is released (Fable N2).
pub async fn resolve_outgoing(store: Store<'_>, peer: &NodeId, plaintext: &str, operation_id: &str, request_hash: &str) {
    let Ok(signal) = serde_json::from_str::<CallSignal>(plaintext) else { return };
    let state = match store.get_outbox_operation(operation_id).await {
        Ok(Some(op)) if op.request_hash != request_hash => None,
        Ok(op) => op.map(|o| o.state),
        Err(e) => {
            tracing::warn!(error = %e, "call reservation kept: operation state unreadable");
            return;
        }
    };
    let how = rules::settlement(state.as_deref());
    if let Err(e) = settle(store, peer, &signal.call_id, operation_id, how).await {
        tracing::warn!(peer = %peer, error = %e, "call reservation not resolved; recovery will retry");
    }
}

/// The background reconciler (`reconcile_operations`) resolved call operation
/// `op` without a compose request: commit or release its reservation exactly
/// as `resolve_outgoing` would, before the paid envelope is resent, so the
/// callee's answer finds a ringing call (Fable N1). Ambiguous stays reserved.
/// Never fails the sweep; a store error leaves it for the next one.
pub async fn settle_operation(store: Store<'_>, op: &konsensus_storage::OutboxOperation) {
    if !u16::try_from(op.kind).is_ok_and(is_call_kind) {
        return;
    }
    let Ok(peer) = NodeId::from_hex(&op.recipient) else { return };
    let how = rules::settlement(Some(&op.state));
    if how == Settlement::Ambiguous {
        return;
    }
    let pending = match store.call_pending().await {
        Ok(pending) => pending,
        Err(e) => {
            tracing::warn!(operation_id = %op.operation_id, error = %e, "call reservation not settled; next sweep retries");
            return;
        }
    };
    for (p, call_id, entry) in pending {
        if p == peer && entry.pending.is_some_and(|x| x.operation_id == op.operation_id) {
            if let Err(e) = settle(store, &peer, &call_id, &op.operation_id, how).await {
                tracing::warn!(operation_id = %op.operation_id, error = %e, "call reservation not settled; next sweep retries");
            }
        }
    }
}

/// Startup: settle or release every reservation a crash left, from the
/// operation journal. Ambiguous ones stay for a same-operation retry. Run
/// before the receive loop and the outbox resend start.
pub async fn recover(store: Store<'_>) -> Result<(usize, usize), konsensus_storage::StorageError> {
    let (mut committed, mut released) = (0, 0);
    for (peer, call_id, entry) in store.call_pending().await? {
        let Some(p) = entry.pending.clone() else { continue };
        let state = store.get_outbox_operation(&p.operation_id).await?.map(|o| o.state);
        let how = rules::settlement(state.as_deref());
        settle(store, &peer, &call_id, &p.operation_id, how).await?;
        match how {
            Settlement::Paid => committed += 1,
            Settlement::Unpaid => released += 1,
            Settlement::Ambiguous => {}
        }
    }
    Ok((committed, released))
}

fn last_query() -> &'static Mutex<HashMap<NodeId, Instant>> {
    static LAST: OnceLock<Mutex<HashMap<NodeId, Instant>>> = OnceLock::new();
    LAST.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The callee's current call-offer price (trust discount applied), answered
/// by the callee itself to a `PriceQuery` for kind 400. Only an answer *for
/// kind 400* that arrived after the query counts (Codex P2): another kind's
/// response refreshing the peer entry never satisfies it. Queries to one peer
/// are sent at most every 2 s; callers in between wait for that answer. The
/// sender never falls back to its own tariff: with no fresh answer, nothing
/// is paid.
pub async fn peer_call_price(state: &AppState, peer: &NodeId) -> Result<u64, ApiError> {
    let kind = konsensus_core::kind::KIND_CALL_INVITE;
    let unknown = || {
        ApiError::BadRequest(
            "their node did not answer with a call price (not connected, or this connection is not admitted yet: \
             send them a message first); nothing was paid"
                .into(),
        )
        .with_reason("call_price_unknown")
    };
    let now = Instant::now();
    // A query counts as asked only once it was sent (Fable N4): the slot is
    // claimed so concurrent callers share one frame, and given back if the
    // send fails, so nobody waits for an answer to a query never sent.
    let (asked, send) = {
        let mut last = last_query().lock().unwrap_or_else(|e| e.into_inner());
        match last.get(peer).copied().filter(|t| now.duration_since(*t) < PRICE_QUERY_MIN_INTERVAL) {
            Some(recent) => (recent, false),
            None => {
                if last.len() >= 4096 {
                    last.retain(|_, t| now.duration_since(*t) < PRICE_QUERY_MIN_INTERVAL);
                }
                last.insert(*peer, now);
                (now, true)
            }
        }
    };
    let still_asked = || last_query().lock().unwrap_or_else(|e| e.into_inner()).get(peer).is_some_and(|t| *t >= asked);
    if send {
        let sent = match (konsensus_message::Frame::PriceQuery { kind }).to_bytes() {
            Ok(frame) => state.transport.send_raw_frame(peer, &frame).await.map_err(|_| unknown()),
            Err(e) => Err(ApiError::Internal(format!("frame serialization error: {e}"))),
        };
        if let Err(e) = sent {
            let mut last = last_query().lock().unwrap_or_else(|e| e.into_inner());
            if last.get(peer) == Some(&asked) {
                last.remove(peer);
            }
            return Err(e);
        }
    }
    tokio::time::timeout(PRICE_QUERY_TIMEOUT, async {
        loop {
            if state.peer_prices.kind_answered_at(peer, kind).await.is_some_and(|at| at >= asked) {
                return Ok(());
            }
            if !send && !still_asked() {
                // The query we were sharing was never sent (and no newer one was).
                return Err(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| unknown())?
    .map_err(|()| unknown())?;
    let height = state.chain.get_block_height().await.unwrap_or(0);
    state.peer_prices.get_fresh_discounted_peer_price(peer, kind, height, PRICE_ANSWER_MAX_AGE).await.ok_or_else(unknown)
}
