//! Durable teardown and generation fencing for local media attachments.

use super::{lock, rules, Store};
use konsensus_core::NodeId;
use konsensus_storage::{call_media::PendingMediaDetach, Storage, StorageError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// A teardown request for one local media attachment generation.
pub struct MediaDetach {
    /// Shared with attachment publication; held until the durable write completes.
    pub generation: Arc<tokio::sync::Mutex<u64>>,
    pub expected_generation: u64,
    /// Admission loss alone may close an Unpaid resume window, never a Live row.
    pub only_unpaid: bool,
    /// Whether socket teardown may end a Live call before its paid deadline.
    pub may_hangup_live: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MediaDetachOutcome {
    Complete,
    PendingExpiry,
}

type AttachmentKey = (usize, NodeId, String);
struct AttachmentState {
    store: Weak<dyn Storage>,
    generation: u64,
    // None means a route still owns this attachment. Teardown records its
    // policy synchronously, including when its async notification never runs.
    stopped: Option<(bool, bool)>,
}
fn attachments() -> &'static Mutex<HashMap<AttachmentKey, AttachmentState>> {
    static ATTACHMENTS: OnceLock<Mutex<HashMap<AttachmentKey, AttachmentState>>> = OnceLock::new();
    ATTACHMENTS.get_or_init(|| Mutex::new(HashMap::new()))
}
fn key(store: Store<'_>, peer: NodeId, call_id: &str) -> AttachmentKey {
    (
        store as *const dyn Storage as *const () as usize,
        peer,
        call_id.into(),
    )
}

/// Arm crash recovery before the router exposes a new attachment. Publication
/// and replay use the same call lock, in addition to the router's generation lock.
pub async fn publish_media_attachment(
    store: &Arc<dyn Storage>,
    peer: &NodeId,
    call_id: &str,
) -> Result<u64, StorageError> {
    let _guard = lock().lock().await;
    if !store
        .call_get(peer, call_id)
        .await?
        .is_some_and(|entry| entry.media_admitted(super::now_ms()))
    {
        return Err(StorageError::Conversion(
            "call media no longer admitted".into(),
        ));
    }
    let generation = store.call_media_publish(peer, call_id).await?;
    // Storage may have waited beyond paid coverage. An armed record remains
    // recoverable even if no route can be exposed after that wait.
    if !store
        .call_get(peer, call_id)
        .await?
        .is_some_and(|entry| entry.media_admitted(super::now_ms()))
    {
        return Err(StorageError::Conversion(
            "call media coverage expired during publication".into(),
        ));
    }
    let mut active = attachments().lock().unwrap_or_else(|e| e.into_inner());
    active.retain(|_, state| state.store.strong_count() > 0);
    active.insert(
        key(store.as_ref(), *peer, call_id),
        AttachmentState {
            store: Arc::downgrade(store),
            generation,
            stopped: None,
        },
    );
    Ok(generation)
}

/// Retain teardown policy before scheduling any fallible asynchronous work.
pub fn stop_media_attachment(store: Store<'_>, peer: &NodeId, call_id: &str, detach: &MediaDetach) {
    let mut active = attachments().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(state) = active.get_mut(&key(store, *peer, call_id)) {
        if state.generation == detach.expected_generation {
            let previous = state.stopped.unwrap_or((true, true));
            state.stopped = Some((
                previous.0 && detach.only_unpaid,
                previous.1 && detach.may_hangup_live,
            ));
        }
    }
}

/// End a callee call only while its attachment generation is still current.
/// Preserve pending evidence and replay retention for ordinary reconciliation.
pub async fn detach_callee_media(
    store: Store<'_>,
    peer: &NodeId,
    call_id: &str,
    now: u64,
    detach: &MediaDetach,
) -> Result<MediaDetachOutcome, StorageError> {
    let generation = detach.generation.lock().await;
    if *generation != detach.expected_generation {
        return Ok(MediaDetachOutcome::Complete);
    }
    let _guard = lock().lock().await;
    let intent = PendingMediaDetach {
        peer: *peer,
        call_id: call_id.into(),
        generation: detach.expected_generation,
        only_unpaid: detach.only_unpaid,
        may_hangup_live: detach.may_hangup_live,
    };
    apply(store, now, &intent).await
}

// Caller holds the call lock throughout the durable fence, lifecycle write,
// and completion append. A lost completion is safe to replay after the write.
async fn apply(
    store: Store<'_>,
    now: u64,
    intent: &PendingMediaDetach,
) -> Result<MediaDetachOutcome, StorageError> {
    let current = store
        .call_media_generation(&intent.peer, &intent.call_id)
        .await?;
    if current.is_some_and(|generation| generation != intent.generation) {
        return Ok(MediaDetachOutcome::Complete);
    }
    if current.is_some() {
        if !store
            .call_media_has_pending(&intent.peer, &intent.call_id)
            .await?
        {
            return Ok(MediaDetachOutcome::Complete);
        }
        store.call_media_record_detach(intent, false).await?;
    }
    let (outcome, finalized) = update_call(store, now, intent).await?;
    if current.is_some() && finalized {
        store.call_media_record_detach(intent, true).await?;
        attachments()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key(store, intent.peer, &intent.call_id));
    }
    Ok(outcome)
}

async fn update_call(
    store: Store<'_>,
    now: u64,
    intent: &PendingMediaDetach,
) -> Result<(MediaDetachOutcome, bool), StorageError> {
    let Some(mut entry) = store.call_get(&intent.peer, &intent.call_id).await? else {
        return Ok((MediaDetachOutcome::Complete, true));
    };
    if entry.side != rules::Side::Callee {
        return Ok((MediaDetachOutcome::Complete, true));
    }
    // Maintenance owns expiry and its terminal notice; socket loss only closes resume.
    if entry.phase == rules::Phase::Live && now > entry.deadline_ms {
        if !intent.only_unpaid && entry.paid_until_ms != Some(0) {
            entry.paid_until_ms = Some(0);
            store
                .call_put(&intent.peer, &intent.call_id, &entry)
                .await?;
        }
        return Ok((MediaDetachOutcome::PendingExpiry, false));
    }
    if !((!intent.only_unpaid && intent.may_hangup_live && entry.phase == rules::Phase::Live)
        || (entry.phase == rules::Phase::Ended
            && entry.end_reason == Some(rules::HangupReason::Unpaid)))
    {
        // A paid Live row protected from transient admission loss still
        // needs its resume window closed after expiry, unless replaced first.
        return Ok((
            MediaDetachOutcome::Complete,
            entry.phase != rules::Phase::Live,
        ));
    }
    if entry.phase == rules::Phase::Ended {
        entry.paid_until_ms = Some(0);
    } else {
        entry.phase = rules::Phase::Ended;
        entry.end_reason = Some(rules::HangupReason::Hangup);
        entry.deadline_ms = entry
            .deadline_ms
            .max(now.saturating_add(rules::TOMBSTONE_MS));
    }
    store
        .call_put(&intent.peer, &intent.call_id, &entry)
        .await?;
    Ok((MediaDetachOutcome::Complete, true))
}

/// Whether an unresolved current attachment has no surviving socket here.
/// Payment admission holds the call lock through this final ownership snapshot;
/// invoice validation repeats the snapshot before publishing a payable invoice.
pub(super) async fn media_attachment_stopped(
    store: Store<'_>,
    peer: &NodeId,
    call_id: &str,
) -> Result<bool, StorageError> {
    if !store.call_media_has_pending(peer, call_id).await? {
        return Ok(false);
    }
    let current = store.call_media_generation(peer, call_id).await?;
    let active = attachments().lock().unwrap_or_else(|e| e.into_inner());
    let owns_socket = active
        .get(&key(store, *peer, call_id))
        .is_some_and(|state| {
            state.store.strong_count() > 0
                && Some(state.generation) == current
                && state.stopped.is_none()
        });
    Ok(!owns_socket)
}

/// Replay before startup accepts call work, and on each expiry tick. Startup
/// also recovers armed attachments whose detach callback was lost with the process.
/// Runtime leaves active routes alone and preserves policies during journal outages.
pub async fn replay_media_detaches(
    store: Store<'_>,
    now: u64,
    startup: bool,
) -> Result<(), StorageError> {
    let _guard = lock().lock().await;
    let mut after = 0;
    let mut failure = None;
    loop {
        let pending = store.call_media_pending(after, 256).await?;
        if pending.is_empty() {
            break;
        }
        for mut intent in pending {
            after = intent.generation;
            if startup {
                // Every socket owned by the previous process is now gone.
                // Keep the policy that protects non-overdue paid Live rows.
                intent.only_unpaid = false;
            } else {
                let active = attachments().lock().unwrap_or_else(|e| e.into_inner());
                if let Some(state) = active
                    .get(&key(store, intent.peer, &intent.call_id))
                    .filter(|s| s.store.strong_count() > 0 && s.generation == intent.generation)
                {
                    let Some((only_unpaid, may_hangup_live)) = state.stopped else {
                        continue;
                    };
                    intent.only_unpaid = only_unpaid;
                    intent.may_hangup_live = may_hangup_live;
                }
            }
            if let Err(error) = apply(store, now, &intent).await {
                tracing::warn!(%error, "call media detach replay failed");
                failure = Some(error);
            }
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
