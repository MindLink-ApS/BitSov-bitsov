//! This node's 1:1 call state (kinds 400-404), shared by the compose path
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

/// Whether `kind` is 1:1 call signalling (400-404).
pub fn is_call_kind(kind: u16) -> bool {
    (konsensus_core::kind::KIND_CALL_INVITE..=konsensus_core::kind::KIND_CALL_BLOCK).contains(&kind)
}

type Store<'a> = &'a dyn Storage;

/// Media-path admission for exactly this peer and call. Storage errors and
/// calls without a settled block fail closed. Time is Unix milliseconds.
pub async fn call_media_admitted(store: Store<'_>, peer: &NodeId, call_id: &str, now: u64) -> bool {
    store.call_get(peer, call_id).await.ok().flatten().is_some_and(|entry| entry.media_admitted(now))
}

/// End expired calls durably, retaining pending evidence and tombstones.
/// Only callee entries are returned for a best-effort 403 Unpaid notification.
pub async fn expire_calls(store: Store<'_>, now: u64) -> Result<Vec<(NodeId, String)>, konsensus_storage::StorageError> {
    let _g = lock().lock().await;
    let mut expired = Vec::new();
    for (peer, call_id, entry) in store.call_live().await? {
        if now <= entry.deadline_ms { continue; }
        // at() may discard a very old row; keep a tombstone until the next
        // ordinary replay sweep so a notification never opens a fresh call.
        let next = entry.clone().at(now).unwrap_or(rules::CallEntry {
            phase: rules::Phase::Ended,
            end_reason: Some(rules::HangupReason::Unpaid),
            deadline_ms: entry.deadline_ms.saturating_add(rules::TOMBSTONE_MS),
            ..entry
        });
        if let Err(error) = store.call_put(&peer, &call_id, &next).await {
            tracing::warn!(%error, "call expiry deferred");
            continue;
        }
        if next.side == rules::Side::Callee {
            expired.push((peer, call_id));
        }
    }
    Ok(expired)
}


/// A hold pins the owner's setting for that call, including across restart.
/// Owner-authorized calls without a grant use the current node setting.
pub(crate) fn call_max_minutes(state: &AppState, peer: &NodeId, id: &str) -> u16 {
    state.pairing.as_ref().and_then(|s| s.call_spend_status(&peer.to_hex(), id))
        .map_or(state.max_call_minutes, |s| s.max_call_minutes)
}

async fn expire_call_caps(state: &AppState, now: u64) -> Result<Vec<(NodeId, String)>, konsensus_storage::StorageError> {
    let _guard = lock().lock().await;
    let mut expired = Vec::new();
    for (peer, id, mut entry) in state.storage.call_live().await? {
        if entry.side != rules::Side::Caller || entry.phase != rules::Phase::Live { continue; }
        let minutes = u32::from(call_max_minutes(state, &peer, &id));
        let Some(until) = entry.paid_until_ms.filter(|_| entry.next_block_seq >= minutes) else { continue };
        let until = until.saturating_sub(u64::from(entry.next_block_seq - minutes) * rules::CALL_BLOCK_MS);
        if now < until { continue; }
        entry.phase = rules::Phase::Ended;
        entry.end_reason = Some(rules::HangupReason::DurationCap);
        entry.deadline_ms = until.saturating_add(rules::TOMBSTONE_MS);
        match state.storage.call_put(&peer, &id, &entry).await {
            Ok(()) => expired.push((peer, id)),
            Err(error) => tracing::warn!(%error, "call duration expiry deferred"),
        }
    }
    Ok(expired)
}

/// Timer maintenance: expiry is committed before any network operation.
/// Hangups use the ordinary paid compose path, never re-admit a disconnected
/// peer, and cannot restore media. A failed notification cannot prolong a call.
pub async fn maintain_calls(state: &std::sync::Arc<AppState>, now: u64) -> Result<(), konsensus_storage::StorageError> {
    use crate::handlers::messages::{compose_for, ComposeRequest};
    let mut expired: Vec<_> = expire_call_caps(state, now).await?.into_iter()
        .map(|(peer, id)| (peer, id, rules::HangupReason::DurationCap)).collect();
    match expire_calls(state.storage.as_ref(), now).await {
        Ok(calls) => expired.extend(calls.into_iter().map(|(peer, id)| (peer, id, rules::HangupReason::Unpaid))),
        Err(error) => tracing::warn!(%error, "call expiry sweep deferred"),
    }
    if let Err(error) = reconcile_call_spend(state, now).await {
        tracing::warn!(%error, "call spend maintenance deferred");
    }
    // No network wait in the expiry loop and no unbounded task/queue growth.
    static NOTIFICATIONS: OnceLock<std::sync::Arc<tokio::sync::Semaphore>> = OnceLock::new();
    let slots = NOTIFICATIONS.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(8)));
    for (peer, call_id, reason) in expired {
        let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let plaintext = serde_json::json!({"v": 1, "call_id": call_id, "reason": reason.as_str()}).to_string();
            let request = ComposeRequest {
                operation_id: Some(uuid::Uuid::new_v4().to_string()), wait_ack_ms: Some(0),
                max_routing_fee_msat: Some(0), max_total_msat: Some(1_000), max_recipient_msat: None,
                max_block_msat: None, max_hold_msat: None,
                recipient: peer.to_hex(), is_room: false, kind: konsensus_core::kind::KIND_CALL_HANGUP,
                plaintext, references: Vec::new(),
            };
            // Only this capped protocol termination uses internal authority;
            // it cannot spend the app's grant or start/readmit a connection.
            let result = tokio::time::timeout(Duration::from_secs(5),
                compose_for(crate::metered::MeteredSpend::call_timeout(&state), state.clone(), request)).await;
            if !matches!(result, Ok(Ok(_))) {
                tracing::debug!(%peer, "call ended; best-effort hangup notification failed");
            }
        });
    }
    Ok(())
}

/// End-path and restart cleanup. Missing, ended and expired call rows release
/// the unallocated hold. Child debits stay in the existing outbox recovery
/// journal until settlement is known. Errors retain liability for the sweep.
pub async fn reconcile_call_spend(state: &AppState, now: u64) -> Result<(), konsensus_storage::StorageError> {
    let Some(service) = &state.pairing else { return Ok(()) };
    let _guard = lock().lock().await;
    let mut first_error = None;
    for (reservation, terms) in service.call_spend_holds() {
        let result = async {
            let peer = NodeId::from_hex(&terms.peer).map_err(|e| konsensus_storage::StorageError::Serialization(e.to_string()))?;
            let entry = state.storage.call_get(&peer, &terms.call_id).await?.and_then(|e| e.at(now));
            // A pending block can still reopen an Unpaid call. Keep the unused
            // bundle through that bounded window; never recreate a closed hold
            // after settlement. Outside it only the child liability stays held.
            let can_resume = match entry.as_ref().filter(|e| e.side == rules::Side::Caller
                && e.phase == rules::Phase::Ended && e.end_reason == Some(rules::HangupReason::Unpaid)) {
                Some(e) => {
                    let resume_until = e.deadline_ms.saturating_sub(rules::TOMBSTONE_MS).saturating_add(rules::CALL_BLOCK_RESUME_MS);
                    if now <= resume_until && e.pending.as_ref().is_some_and(|p| p.kind == konsensus_core::kind::KIND_CALL_BLOCK) {
                        true
                    } else if e.next_block_seq > 0 && now <= resume_until.saturating_add(rules::CALL_BLOCK_MS).saturating_add(rules::CALL_BLOCK_GRACE_MS) {
                        // Settlement clears pending before delivery. A callee
                        // can grant a fresh interval near its resume boundary;
                        // allow that still-usable receipt to arrive, bounded by
                        // one interval plus grace and backed by the actual queue.
                        awaiting_block_grant(state, &peer, &terms.call_id, e.next_block_seq - 1).await?
                    } else { false }
                },
                None => false,
            };
            if !can_resume && entry.is_none_or(|e| e.phase == rules::Phase::Ended) {
                service.close_call_spend(&reservation).map_err(|e| konsensus_storage::StorageError::Serialization(e.to_string()))?;
            }
            Ok::<_, konsensus_storage::StorageError>(())
        }.await;
        if let Err(error) = result {
            tracing::warn!(%error, "call hold cleanup deferred");
            first_error.get_or_insert(error);
        }
    }
    if let Err(error) = service.prune_call_spend((now / 1000).min(i64::MAX as u64) as i64) {
        first_error.get_or_insert(konsensus_storage::StorageError::Serialization(error.to_string()));
    }
    if let Some(error) = first_error { return Err(error); }
    Ok(())
}

async fn awaiting_block_grant(state: &AppState, peer: &NodeId, call_id: &str, seq: u32) -> Result<bool, konsensus_storage::StorageError> {
    // A crash can also follow the local call commit but precede atomic queue
    // materialization. Its settled payment evidence is already in the journal.
    for op in state.storage.list_recoverable_operations().await? {
        if op.recipient == peer.to_hex() && matches!(op.state.as_str(), "paying" | "payment_unknown")
            && crate::handlers::messages::operations::settled_call_block(&op)? {
            match crate::handlers::messages::operations::call_block_binding(&op)? {
                Some((call, block)) if call == call_id && block == seq => return Ok(true),
                // Older unmaterialized rows cannot yet supply their cache. Keep
                // this peer's bounded allowance until recovery identifies them.
                None => return Ok(true),
                _ => {},
            }
        }
    }
    // Read the journal before the queue: materialization moves evidence
    // atomically from paying to paid+queued. The reverse order can miss both.
    for (id, _) in state.storage.get_pending_for_peer(peer).await? {
        let Some(op) = state.storage.get_outbox_operation_by_message(&id).await? else { continue };
        if op.kind != i64::from(konsensus_core::kind::KIND_CALL_BLOCK)
            || op.recipient != peer.to_hex() || !matches!(op.state.as_str(), "paid" | "sent") { continue; }
        let Some(envelope) = state.storage.get_message(&id).await? else { continue };
        if envelope.kind != konsensus_core::kind::KIND_CALL_BLOCK || envelope.sender != *state.identity.node_id()
            || envelope.recipient != konsensus_core::Recipient::Node(*peer) { continue; }
        // A paid queue row is sufficient even if a crash preceded first send.
        let (call, block) = match crate::handlers::messages::operations::call_block_binding(&op)? {
            Some(binding) => binding,
            None => {
                let cipher = state.plaintext_cipher.as_ref().ok_or_else(||
                    konsensus_storage::StorageError::Conversion("legacy paid block cipher unavailable".into()))?;
                cached_call_block_binding(state.storage.as_ref(), cipher, &id).await?
            },
        };
        if call == call_id && block == seq {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) async fn fail_outgoing(state: &AppState, peer: &NodeId, plaintext: &str) -> Result<(), konsensus_storage::StorageError> {
    let Ok(signal) = konsensus_core::wire_json::from_str::<CallSignal>(plaintext) else { return Ok(()) };
    let _guard = lock().lock().await;
    if let Some(mut entry) = state.storage.call_get(peer, &signal.call_id).await? {
        if entry.phase != rules::Phase::Ended {
            entry.phase = rules::Phase::Ended;
            entry.end_reason = Some(rules::HangupReason::Failed);
            entry.deadline_ms = now_ms().saturating_add(rules::TOMBSTONE_MS);
            state.storage.call_put(peer, &signal.call_id, &entry).await?;
        }
    }
    Ok(())
}

/// Reserve before sending the offer; block zero also supports already-answered
/// calls created before this slice. The call lock orders reservation with expiry.
pub(crate) async fn ensure_call_spend(auth: &crate::metered::MeteredSpend, state: &AppState,
    peer: &NodeId, signal: &CallSignal, terms: crate::spend_budget::CallSpendTerms) -> Result<(), ApiError> {
    if !auth.is_metered() { return Ok(()) }
    // Serialize capacity observations only with other new holds. A remote
    // wallet RPC must never stall block renewal, incoming media or hangup.
    static RESERVATIONS: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    let _reservation_guard = RESERVATIONS.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let channels = state.lightning.list_channels().await.map_err(|_| {
        ApiError::NotDispatched("call outbound liquidity unavailable".into()).with_reason("call_liquidity_unavailable")
    })?;
    let _guard = lock().lock().await;
    let entry = current(state.storage.as_ref(), peer, &signal.call_id, now_ms()).await
        .map_err(|e| ApiError::Storage(e.to_string()))?
        .ok_or_else(|| ApiError::BadRequest("call is not live".into()))?;
    if entry.side != rules::Side::Caller || entry.phase == rules::Phase::Ended {
        return Err(ApiError::BadRequest("caller reservation requires an open outgoing call".into()));
    }
    if state.pairing.as_ref().and_then(|s| s.call_spend_status(&peer.to_hex(), &signal.call_id)).is_some() {
        return Ok(());
    }
    if entry.next_block_seq != 0 {
        return Err(ApiError::BadRequest("call reservation missing after block zero; start a new call".into()));
    }
    // One active outbound channel must cover the hold. Do not infer spendable
    // capacity from wallet balance, channel size, or an unknown provider field.
    let capacity = channels.iter().filter(|c| c.active)
        .filter_map(|c| c.outbound_capacity_msat).max().unwrap_or(0);
    auth.reserve_call(state, terms, capacity)
}

/// Recovery may resend settled blocks, but a new charge needs a still-payable
/// interval. Recheck after reconciliation and after asking the callee's price.
pub(crate) async fn revalidate_outgoing_block(state: &AppState, peer: &NodeId, plaintext: &str) -> Result<u64, ApiError> {
    let (_guard, deadline) = block_dispatch_guard(state, peer, plaintext).await?;
    Ok(deadline)
}

/// Keep call transitions serialized until the wallet's first poll. The caller
/// must release this guard after that poll, including when it returns Pending.
pub(crate) async fn block_dispatch_guard(state: &AppState, peer: &NodeId, plaintext: &str) -> Result<(tokio::sync::MutexGuard<'static, ()>, u64), ApiError> {
    let signal = CallSignal::parse(konsensus_core::kind::KIND_CALL_BLOCK, plaintext).map_err(|e| refused(e, false))?;
    let guard = lock().lock().await;
    let entry = state.storage.call_get(peer, &signal.call_id).await
        .map_err(|_| ApiError::Internal("call state unavailable".into()))?
        .ok_or_else(|| refused(CallRefusal::UnknownCall, false))?;
    if signal.seq.is_some_and(|seq| seq >= u32::from(call_max_minutes(state, peer, &signal.call_id))) {
        return Err(ApiError::BadRequest("call duration cap reached".into()).with_reason("call_duration_cap"));
    }
    rules::validate_outgoing_block(&entry, signal.seq.ok_or_else(|| refused(CallRefusal::Sequence, false))?, now_ms())
        .map_err(|e| refused(e, false))?;
    Ok((guard, entry.deadline_ms))
}

pub(crate) async fn offer_dispatch_guard(store: Store<'_>, peer: &NodeId, plaintext: &str) -> Result<(tokio::sync::MutexGuard<'static, ()>, u64), ApiError> {
    let signal = CallSignal::parse(konsensus_core::kind::KIND_CALL_INVITE, plaintext).map_err(|e| refused(e, false))?;
    let guard = lock().lock().await;
    let entry = current(store, peer, &signal.call_id, now_ms()).await
        .map_err(|_| ApiError::Internal("call state unavailable".into()))?
        .ok_or_else(|| refused(CallRefusal::UnknownCall, false))?;
    if entry.side != rules::Side::Caller || !matches!(entry.phase, rules::Phase::Reserved | rules::Phase::Ringing) {
        return Err(refused(CallRefusal::UnknownCall, false));
    }
    Ok((guard, entry.deadline_ms))
}

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

/// A validated incoming block, holding the call lock through paid acceptance.
/// Dropping it without committing grants no media and changes no call state.
pub struct IncomingBlock<'a> {
    _guard: tokio::sync::MutexGuard<'static, ()>,
    store: Store<'a>,
    peer: NodeId,
    signal: CallSignal,
    next: Result<CallEntry, CallRefusal>,
}

impl IncomingBlock<'_> {
    /// Validated block identity for reconciliation if its paid commit fails.
    pub fn signal(&self) -> &CallSignal {
        &self.signal
    }

    pub fn refusal(&self) -> Option<&CallRefusal> { self.next.as_ref().err() }

    /// Publish only after the envelope's payment proof is accepted. Do not
    /// recheck time: expiry cannot race the admission decision under this lock.
    pub async fn commit(self) -> Result<CallSignal, konsensus_storage::StorageError> {
        let next = self.next.map_err(|e| konsensus_storage::StorageError::Conversion(e.to_string()))?;
        self.store.call_put(&self.peer, &self.signal.call_id, &next).await?;
        Ok(self.signal)
    }
}

/// Check a payment-validated block before consuming its nonce/payment proof.
/// Retain the guard through acceptance and commit. An unserviceable settled
/// block still consumes its proof and becomes an audited overpayment.
pub async fn prepare_incoming_block<'a>(store: Store<'a>, peer: &NodeId, plaintext: Option<&str>) -> Result<IncomingBlock<'a>, CallRefusal> {
    let signal = CallSignal::parse(konsensus_core::kind::KIND_CALL_BLOCK, plaintext.ok_or(CallRefusal::Invalid("undecryptable"))?)?;
    let guard = lock().lock().await;
    let now = now_ms();
    let entry = current(store, peer, &signal.call_id, now).await.map_err(|_| CallRefusal::Invalid("call state unavailable"))?;
    let next = rules::receive_block(entry, signal.seq.ok_or(CallRefusal::Invalid("missing seq"))?, now);
    Ok(IncomingBlock { _guard: guard, store, peer: *peer, signal, next })
}

/// Admit a signal this node (`own`) received from `peer` (after the payment
/// gate). A refusal means it must not reach the app (the caller also
/// withdraws the stored message). A meeting leg must come from the earlier
/// participant of its roster.
pub async fn admit_incoming(store: Store<'_>, own: &NodeId, peer: &NodeId, kind: u16, plaintext: Option<&str>) -> Result<CallSignal, CallRefusal> {
    let signal = CallSignal::parse(kind, plaintext.ok_or(CallRefusal::Invalid("undecryptable"))?)?;
    signal.check_leg(peer, own)?;
    let _g = lock().lock().await;
    let now = now_ms();
    let unavailable = |_| CallRefusal::Invalid("call state unavailable");
    let entry = current(store, peer, &signal.call_id, now).await.map_err(unavailable)?;
    // Only an offer opens a new call id; an unknown-id answer/ICE/hangup is
    // refused below and must never make room by evicting a burned id (Fable R2).
    if entry.is_none() && kind == konsensus_core::kind::KIND_CALL_INVITE {
        room(store, peer, now).await?;
    }
    let next = if kind == konsensus_core::kind::KIND_CALL_BLOCK {
        rules::receive_block(entry, signal.seq.ok_or(CallRefusal::Invalid("missing seq"))?, now)?
    } else {
        rules::receive(entry, kind, signal.reason, now)?
    };
    write(store, peer, &signal.call_id, Some(&next)).await.map_err(unavailable)?;
    Ok(signal)
}

fn refused(e: CallRefusal, new_operation: bool) -> ApiError {
    let reason = match e {
        CallRefusal::Replayed => "call_id_used",
        CallRefusal::Full => "call_busy",
        CallRefusal::InFlight => "call_signal_in_flight",
        CallRefusal::Invalid(_) | CallRefusal::NotCallKind => "call_signal_invalid",
        _ => "call_not_live",
    };
    let error = if new_operation {
        ApiError::NotDispatched(e.to_string())
    } else {
        ApiError::BadRequest(e.to_string())
    };
    error.with_reason(reason)
}

/// Reserve one of our signals under `operation_id` and the exact request
/// (`request_hash`), before any quote or payment. The operation id must be the
/// canonical one the journal uses. One operation reserves one signal of one
/// call for one request: the same id reserving another call (Fable N2) or the
/// same call with another payload (Codex delta2 #2) is refused without
/// touching the existing reservation. A meeting leg we (`own`) place must go
/// to a later participant of its roster.
pub async fn reserve_outgoing(
    store: Store<'_>,
    own: &NodeId,
    peer: &NodeId,
    kind: u16,
    plaintext: &str,
    operation_id: &str,
    request_hash: &str,
) -> Result<(), ApiError> {
    let storage =
        |e: konsensus_storage::StorageError| ApiError::Internal(format!("call state: {e}"));
    // Compose holds the operation lock through reservation and journal insertion.
    // Only a missing journal proves no earlier attempt dispatched: even an
    // expired offer can be retried while its previous payment is unresolved.
    let new_operation = store
        .get_outbox_operation(operation_id)
        .await
        .map_err(storage)?
        .is_none();
    let refused = |e| refused(e, new_operation);
    let signal = CallSignal::parse(kind, plaintext).map_err(refused)?;
    signal.check_leg(own, peer).map_err(refused)?;
    let _g = lock().lock().await;
    let now = now_ms();
    let taken = store
        .call_pending()
        .await
        .map_err(storage)?
        .into_iter()
        .any(|(p, call_id, e)| {
            e.pending.is_some_and(|x| {
                x.operation_id == operation_id
                    && (p != *peer
                        || call_id != signal.call_id
                        || !x.is(operation_id, request_hash))
            })
        });
    if taken {
        return Err(ApiError::OperationConflict("operation_mismatch"));
    }
    let entry = current(store, peer, &signal.call_id, now)
        .await
        .map_err(storage)?;
    if entry.is_none() && kind == konsensus_core::kind::KIND_CALL_INVITE {
        room(store, peer, now).await.map_err(refused)?;
    }
    let next = if kind == konsensus_core::kind::KIND_CALL_BLOCK {
        rules::reserve_block(entry.clone(), signal.seq.ok_or_else(|| refused(CallRefusal::Invalid("missing seq")))?, operation_id, request_hash, now)
    } else if kind == konsensus_core::kind::KIND_CALL_HANGUP && signal.reason == Some(rules::HangupReason::Unpaid) {
        rules::reserve_unpaid_hangup(entry.clone(), operation_id, request_hash)
    } else if kind == konsensus_core::kind::KIND_CALL_HANGUP && signal.reason == Some(rules::HangupReason::DurationCap) {
        rules::reserve_duration_hangup(entry.clone(), operation_id, request_hash)
    } else {
        rules::reserve(entry.clone(), kind, operation_id, request_hash, now)
    }.map_err(refused)?;
    if entry.as_ref() != Some(&next) {
        write(store, peer, &signal.call_id, Some(&next))
            .await
            .map_err(storage)?;
    }
    Ok(())
}

/// Commit or release the reservation of exactly this request; anything else
/// (another request's reservation, none at all) is left alone.
async fn settle(store: Store<'_>, peer: &NodeId, call_id: &str, operation_id: &str, request_hash: &str, how: Settlement) -> Result<(), konsensus_storage::StorageError> {
    let _g = lock().lock().await;
    let now = now_ms();
    let Some(entry) = store.call_get(peer, call_id).await? else { return Ok(()) };
    if !entry.pending.as_ref().is_some_and(|p| p.is(operation_id, request_hash)) {
        return Ok(());
    }
    // Preserve terminal failure across restart and same-operation retries. A
    // mere pre-dispatch release has no failed payment evidence and stays live.
    let failed = if how == Settlement::Unpaid {
        store.get_outbox_operation(operation_id).await?.is_some_and(|op| {
            op.recipient == peer.to_hex()
                && entry.pending.as_ref().is_some_and(|p| i64::from(p.kind) == op.kind)
                && (request_hash.is_empty() || op.request_hash == request_hash)
                && crate::handlers::messages::operations::definite_call_payment_failure(&op)
        })
    } else { false };
    let next = if failed && entry.phase != rules::Phase::Ended {
        Some(CallEntry { phase: rules::Phase::Ended, end_reason: Some(rules::HangupReason::Failed),
            pending: None, deadline_ms: now.saturating_add(rules::TOMBSTONE_MS), ..entry })
    } else { match how {
        Settlement::Paid => Some(rules::commit(entry, operation_id, now)
            .map_err(|e| konsensus_storage::StorageError::Conversion(format!("paid call transition refused: {e}")))?),
        Settlement::Unpaid => rules::release(entry, operation_id),
        Settlement::Ambiguous => return Ok(()),
    }};
    write(store, peer, call_id, next.as_ref()).await
}

/// Publish a paid call transition before queuing its envelope. A refused
/// transition or failed write retains the pending evidence and fails the send;
/// recovery can retry it without silently treating an ungranted block as sent.
pub async fn commit_outgoing(store: Store<'_>, peer: &NodeId, plaintext: &str, operation_id: &str, request_hash: &str) -> Result<(), konsensus_storage::StorageError> {
    let signal = konsensus_core::wire_json::from_str::<CallSignal>(plaintext)
        .map_err(|e| konsensus_storage::StorageError::Conversion(e.to_string()))?;
    settle(store, peer, &signal.call_id, operation_id, request_hash, Settlement::Paid).await
}

/// How the journal says this request's reservation ends. A journal entry of
/// another request (other payload, kind or recipient) never paid for it
/// (Fable N2 / R1): unpaid, and since `settle` only touches this request's own
/// reservation, never the winner's.
fn journal_settlement(op: Option<&konsensus_storage::OutboxOperation>, peer: &NodeId, kind: u16, request_hash: &str) -> Settlement {
    match op {
        Some(op) if op.request_hash != request_hash || op.kind != i64::from(kind) || op.recipient != peer.to_hex() => Settlement::Unpaid,
        op => rules::settlement(op.map(|o| o.state.as_str())),
    }
}

/// After compose returned (either way): read the operation journal and commit,
/// release (definite nonpayment) or keep (ambiguous) this request's reservation.
pub async fn resolve_outgoing(store: Store<'_>, peer: &NodeId, plaintext: &str, operation_id: &str, request_hash: &str) {
    let Ok(signal) = konsensus_core::wire_json::from_str::<CallSignal>(plaintext) else { return };
    // The reservation's own kind (an ICE reserves nothing; then this is moot).
    let kind = match store.call_get(peer, &signal.call_id).await {
        Ok(Some(CallEntry { pending: Some(p), .. })) => p.kind,
        _ => return,
    };
    let how = match store.get_outbox_operation(operation_id).await {
        Ok(op) => journal_settlement(op.as_ref(), peer, kind, request_hash),
        Err(e) => {
            tracing::warn!(error = %e, "call reservation kept: operation state unreadable");
            return;
        }
    };
    if let Err(e) = settle(store, peer, &signal.call_id, operation_id, request_hash, how).await {
        tracing::warn!(peer = %peer, error = %e, "call reservation not resolved; recovery will retry");
    }
}

/// The journal moved call operation `op` without the compose request that
/// reserved it: the background reconciler (Fable N1) or a same-operation
/// retry that reconciled an ambiguous payment (Codex delta2 #3). Commit (or,
/// with `release`, also release) that request's reservation, before the paid
/// envelope is (re)sent, so the callee's answer finds a ringing call. A retry
/// passes `release = false`: an unpaid operation it is about to pay again
/// keeps its reservation. Ambiguous stays reserved. Never fails the caller; a
/// store error leaves it for the next sweep or the compose resolve.
pub async fn settle_operation(store: Store<'_>, op: &konsensus_storage::OutboxOperation, release: bool) {
    if !u16::try_from(op.kind).is_ok_and(is_call_kind) {
        return;
    }
    let Ok(peer) = NodeId::from_hex(&op.recipient) else { return };
    let how = rules::settlement(Some(&op.state));
    if how == Settlement::Ambiguous || (how == Settlement::Unpaid && !release
        && !crate::handlers::messages::operations::definite_call_payment_failure(op)) {
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
        if p == peer && entry.pending.is_some_and(|x| x.is(&op.operation_id, &op.request_hash) && i64::from(x.kind) == op.kind) {
            if let Err(e) = settle(store, &peer, &call_id, &op.operation_id, &op.request_hash, how).await {
                tracing::warn!(operation_id = %op.operation_id, error = %e, "call reservation not settled; next sweep retries");
            }
        }
    }
}

/// Release every reservation of a durably abandoned operation. The caller
/// holds its operation lock and has already persisted the tombstone: a
/// cancelled POST may have reserved a signal before inserting any operation
/// metadata. Keep the pending row on write failure so a retry/sweep finds it.
pub(crate) async fn release_abandoned(store: Store<'_>, operation_id: &str) -> Result<(), konsensus_storage::StorageError> {
    let _g = lock().lock().await;
    for (peer, call_id, entry) in store.call_pending().await? {
        if entry.pending.as_ref().is_some_and(|p| p.operation_id == operation_id) {
            let next = rules::release(entry, operation_id);
            write(store, &peer, &call_id, next.as_ref()).await?;
        }
    }
    Ok(())
}

/// Startup: settle or release every reservation a crash left, from the
/// operation journal. Ambiguous ones stay for a same-operation retry. Run
/// before the receive loop and the outbox resend start.
pub async fn recover(store: Store<'_>) -> Result<(usize, usize), konsensus_storage::StorageError> {
    let (mut committed, mut released) = (0, 0);
    for (peer, call_id, entry) in store.call_pending().await? {
        let Some(p) = entry.pending.clone() else { continue };
        let op = store.get_outbox_operation(&p.operation_id).await?;
        // A legacy reservation without a request hash follows its operation.
        let hash = if p.request_hash.is_empty() { op.as_ref().map(|o| o.request_hash.clone()).unwrap_or_default() } else { p.request_hash.clone() };
        // Startup commits only if the journal row is this request: same
        // payload hash, kind and recipient (Fable R1).
        let how = journal_settlement(op.as_ref(), &peer, p.kind, &hash);
        settle(store, &peer, &call_id, &p.operation_id, &p.request_hash, how).await?;
        match how {
            Settlement::Paid => committed += 1,
            Settlement::Unpaid => released += 1,
            Settlement::Ambiguous => {}
        }
    }
    Ok((committed, released))
}

/// How long an incoming signal may stay held by a live handler before the
/// periodic sweep treats it as abandoned and withdraws it.
pub const HOLD_MAX_MS: u64 = 5 * 60 * 1000;

/// Hold an incoming call signal before its paid acceptance (Codex delta2 #4):
/// until released, it is invisible to history, resync and duplicate ACKs.
pub async fn hold_incoming(store: Store<'_>, envelope: &konsensus_core::UkmEnvelope) -> Result<bool, konsensus_storage::StorageError> {
    store.call_admission_hold(envelope, now_ms()).await
}

/// Withdraw held signals whose admission never finished (a refusal whose
/// cleanup failed, or a crash): message and plaintext deleted, receipt marked
/// application-rejected. `all` at startup, before the receive loop runs;
/// otherwise only holds older than [`HOLD_MAX_MS`].
pub async fn withdraw_held(store: Store<'_>, all: bool) -> Result<u64, konsensus_storage::StorageError> {
    let before = if all { u64::MAX } else { now_ms().saturating_sub(HOLD_MAX_MS) };
    store.call_admission_withdraw(before).await
}

fn last_query() -> &'static Mutex<HashMap<(NodeId, u16), Instant>> {
    static LAST: OnceLock<Mutex<HashMap<(NodeId, u16), Instant>>> = OnceLock::new();
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
    peer_call_kind_price(state, peer, konsensus_core::kind::KIND_CALL_INVITE).await
}

pub async fn peer_call_kind_price(state: &AppState, peer: &NodeId, kind: u16) -> Result<u64, ApiError> {
    if !matches!(kind, konsensus_core::kind::KIND_CALL_INVITE | konsensus_core::kind::KIND_CALL_BLOCK) {
        return Err(ApiError::BadRequest("not a call tariff kind".into()));
    }
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
        match last.get(&(*peer, kind)).copied().filter(|t| now.duration_since(*t) < PRICE_QUERY_MIN_INTERVAL) {
            Some(recent) => (recent, false),
            None => {
                if last.len() >= 4096 {
                    last.retain(|_, t| now.duration_since(*t) < PRICE_QUERY_MIN_INTERVAL);
                }
                if last.len() >= 4096 { return Err(unknown()); }
                last.insert((*peer, kind), now);
                (now, true)
            }
        }
    };
    let still_asked = || last_query().lock().unwrap_or_else(|e| e.into_inner()).get(&(*peer, kind)).is_some_and(|t| *t >= asked);
    if send {
        let sent = match (konsensus_message::Frame::PriceQuery { kind }).to_bytes() {
            Ok(frame) => state.transport.send_raw_frame(peer, &frame).await.map_err(|_| unknown()),
            Err(e) => Err(ApiError::Internal(format!("frame serialization error: {e}"))),
        };
        if let Err(e) = sent {
            let mut last = last_query().lock().unwrap_or_else(|e| e.into_inner());
            if last.get(&(*peer, kind)) == Some(&asked) {
                last.remove(&(*peer, kind));
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

/// Repeat the latest grant on duplicate delivery without extending it again.
/// Older blocks cannot change the already more advanced caller state.
pub async fn block_grant(store: Store<'_>, cipher: &konsensus_crypto::PlaintextCacheCipher, peer: &NodeId, id: &konsensus_core::MessageId) -> Result<Option<u64>, konsensus_storage::StorageError> {
    let unavailable = || konsensus_storage::StorageError::Conversion("paid call grant metadata unavailable".into());
    let cached = store.get_message_plaintext(id).await?.ok_or_else(unavailable)?;
    let plaintext = cipher.decrypt(&id.to_hex(), &cached).map_err(|_| unavailable())?;
    let signal = CallSignal::parse(konsensus_core::kind::KIND_CALL_BLOCK, std::str::from_utf8(&plaintext).map_err(|_| unavailable())?).map_err(|_| unavailable())?;
    let entry = store.call_get(peer, &signal.call_id).await?.ok_or_else(unavailable)?;
    if entry.side != rules::Side::Callee || entry.next_block_seq != signal.seq.ok_or_else(unavailable)?.saturating_add(1)
        || (entry.phase == rules::Phase::Ended && entry.end_reason != Some(rules::HangupReason::Unpaid)) { return Ok(None); }
    Ok(entry.paid_until_ms)
}

/// Only a grant from the recipient of our stored, paid block can adjust its
/// interval. It cannot open a new call or undo an explicit local/remote hangup.
pub async fn receive_block_grant(store: Store<'_>, cipher: &konsensus_crypto::PlaintextCacheCipher, own: &NodeId, peer: &NodeId,
    id: &konsensus_core::MessageId, paid_until_ms: u64,
) -> Result<(), konsensus_storage::StorageError> {
    if !store.is_pending_dispatched(id, peer, own).await? { return Ok(()); }
    let Some(envelope) = store.get_message(id).await? else { return Ok(()) };
    if envelope.kind != konsensus_core::kind::KIND_CALL_BLOCK || envelope.sender != *own
        || envelope.recipient != konsensus_core::Recipient::Node(*peer) { return Ok(()); }
    let mut op = store.get_outbox_operation_by_message(id).await?
        .ok_or_else(|| konsensus_storage::StorageError::Conversion("paid block operation unavailable".into()))?;
    let (call_id, seq) = match crate::handlers::messages::operations::call_block_binding(&op)? {
        Some(binding) => binding,
        None => {
            // Pending blocks drafted by an earlier build can recover from their
            // encrypted cache. Persist the binding before completing this ACK.
            let unavailable = || konsensus_storage::StorageError::Conversion("legacy paid block binding unavailable".into());
            let binding = cached_call_block_binding(store, cipher, id).await?;
            crate::handlers::messages::operations::bind_legacy_call_block(&mut op, binding.clone())?;
            if !store.update_outbox_operation(&op).await? { return Err(unavailable()); }
            binding
        },
    };
    let _guard = lock().lock().await;
    let Some(entry) = store.call_get(peer, &call_id).await? else { return Ok(()) };
    if entry.side != rules::Side::Caller || (entry.next_block_seq != seq && entry.next_block_seq != seq.saturating_add(1))
        || !(entry.phase == rules::Phase::Live || (entry.phase == rules::Phase::Ended && entry.end_reason == Some(rules::HangupReason::Unpaid))) {
        return Ok(());
    }
    // A repeated receipt is idempotent and cannot move a boundary backwards.
    if entry.paid_until_ms.is_some_and(|until| until > paid_until_ms) { return Ok(()); }
    let next = CallEntry { phase: rules::Phase::Live, paid_until_ms: Some(paid_until_ms),
        next_block_seq: seq.saturating_add(1), deadline_ms: paid_until_ms.saturating_add(rules::CALL_BLOCK_GRACE_MS),
        end_reason: None, unpaid_notice_used: false, ..entry };
    store.call_put(peer, &call_id, &next).await
}

async fn cached_call_block_binding(store: Store<'_>, cipher: &konsensus_crypto::PlaintextCacheCipher,
    id: &konsensus_core::MessageId,
) -> Result<(String, u32), konsensus_storage::StorageError> {
    let unavailable = || konsensus_storage::StorageError::Conversion("legacy paid block binding unavailable".into());
    let cached = store.get_message_plaintext(id).await?.ok_or_else(unavailable)?;
    let plaintext = cipher.decrypt(&id.to_hex(), &cached).map_err(|_| unavailable())?;
    let signal = CallSignal::parse(konsensus_core::kind::KIND_CALL_BLOCK,
        std::str::from_utf8(&plaintext).map_err(|_| unavailable())?).map_err(|_| unavailable())?;
    Ok((signal.call_id, signal.seq.ok_or_else(unavailable)?))
}
