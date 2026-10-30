//! Callee-only device wait. Bindings are volatile and bounded by existing call limits;
//! restart ends awaiting rows rather than guessing which old message owns one.

use std::{collections::HashMap, sync::Mutex};

use konsensus_core::{
    payloads::call::{self as rules, CallRefusal, CallSignal, Phase, Side},
    MessageId, NodeId, UkmEnvelope,
};
use konsensus_message::Frame;
use konsensus_storage::{CallInviteOutcome, Storage, StorageError};

pub const NOT_REACHABLE: &str = "call_not_reachable";

#[derive(Clone)]
struct Invite {
    peer: NodeId,
    call_id: String,
    deadline_ms: u64,
    waiting: bool,
    ack_pending: bool,
}

/// This node's current incoming invites, identified by envelope, not call id.
#[derive(Default)]
pub struct Devices {
    invites: Mutex<HashMap<MessageId, Invite>>,
}

impl Devices {
    /// Called only after the unchanged payment and admission gates. Register
    /// before lifting the message hold, so an app cannot fetch ahead of us.
    pub async fn admit(
        &self,
        store: &dyn Storage,
        own: &NodeId,
        envelope: &UkmEnvelope,
        plaintext: Option<&str>,
        arrived_ms: u64,
        clock: impl FnOnce() -> u64,
    ) -> Result<CallSignal, CallRefusal> {
        let signal = CallSignal::parse(
            envelope.kind,
            plaintext.ok_or(CallRefusal::Invalid("undecryptable"))?,
        )?;
        signal.check_leg(&envelope.sender, own)?;
        let _guard = super::lock().lock().await;
        let now_ms = clock();
        let unavailable = |_| CallRefusal::Invalid("call state unavailable");
        if envelope.kind == konsensus_core::kind::KIND_CALL_INVITE {
            // The registry shares the existing open-call bound. Ended calls
            // may have freed slots since the last sweep. A failed durable hold
            // remains here for retry and fails closed on storage availability.
            if self.invites.lock().unwrap_or_else(|e| e.into_inner()).len()
                >= rules::MAX_OPEN_CALLS as usize
            {
                rules::has_room(
                    &store
                        .call_counts(&envelope.sender, now_ms)
                        .await
                        .map_err(unavailable)?,
                )?;
                let tracked: Vec<_> = self
                    .invites
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .map(|(id, invite)| (*id, invite.clone()))
                    .collect();
                for (id, invite) in tracked {
                    let row = store
                        .call_get(&invite.peer, &invite.call_id)
                        .await
                        .map_err(unavailable)?;
                    if !invite.waiting
                        && !invite.ack_pending
                        && row
                            .and_then(|e| e.at(now_ms))
                            .is_none_or(|e| e.phase == Phase::Ended || e.side != Side::Callee)
                    {
                        self.invites
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&id);
                    }
                }
                if self.invites.lock().unwrap_or_else(|e| e.into_inner()).len()
                    >= rules::MAX_OPEN_CALLS as usize
                {
                    return Err(CallRefusal::Invalid("call state unavailable"));
                }
            }
        }

        super::admit_locked(
            store,
            &envelope.sender,
            envelope.kind,
            &signal,
            now_ms,
            arrived_ms,
        )
        .await?;
        if envelope.kind == konsensus_core::kind::KIND_CALL_INVITE {
            // A legitimately reused call id replaces its historical envelope
            // binding only after the normal replay/admission checks pass.
            self.invites
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|_, invite| {
                    invite.waiting
                        || invite.peer != envelope.sender
                        || invite.call_id != signal.call_id
                });
            self.invites
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(
                    envelope.id,
                    Invite {
                        peer: envelope.sender,
                        call_id: signal.call_id.clone(),
                        deadline_ms: arrived_ms.saturating_add(rules::DEVICE_WAIT_MS),
                        waiting: true,
                        ack_pending: false,
                    },
                );
            store
                .call_invite_set_outcome(&envelope.id, &envelope.sender, CallInviteOutcome::Pending)
                .await
                .map_err(unavailable)?;
        } else if envelope.kind == konsensus_core::kind::KIND_CALL_HANGUP {
            self.invites
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|_, invite| {
                    invite.peer != envelope.sender
                        || invite.call_id != signal.call_id
                        || invite.waiting
                        || invite.ack_pending
                });
        }
        store
            .call_admission_release(&envelope.id)
            .await
            .map_err(unavailable)?;
        Ok(signal)
    }

    /// An authenticated paired device fetched, or successfully streamed, this
    /// exact envelope. No peer I/O is performed on the device's request path.
    pub async fn fetched(
        &self,
        store: &dyn Storage,
        envelope: &UkmEnvelope,
        clock: impl FnOnce() -> u64,
    ) -> Result<(), StorageError> {
        if envelope.kind != konsensus_core::kind::KIND_CALL_INVITE {
            return Ok(());
        }
        let _guard = super::lock().lock().await;
        let now_ms = clock();
        let invite = self
            .invites
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&envelope.id)
            .cloned();
        let Some(invite) = invite.filter(|i| i.peer == envelope.sender) else {
            return Ok(());
        };
        if !invite.waiting {
            return Ok(());
        }
        let Some(row) = store.call_get(&invite.peer, &invite.call_id).await? else {
            return Ok(());
        };
        if row.side != Side::Callee
            || row.phase != Phase::AwaitingDevice
            || row.deadline_ms != invite.deadline_ms
            || now_ms >= row.deadline_ms
        {
            return Ok(());
        }
        let next = row.device_fetched(now_ms).expect("unexpired row");
        // One transaction: receipt and ringing row together, or neither. A failed
        // request leaves the invite awaiting; nothing can later ring it or report
        // it fetched, before or after a restart (Codex FAIL on #472).
        store.call_invite_deliver(&envelope.id, &invite.peer, &invite.call_id, &next).await?;
        let deadline_ms = next.deadline_ms;
        if let Some(tracked) = self
            .invites
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&envelope.id)
        {
            tracked.waiting = false;
            tracked.ack_pending = true;
            tracked.deadline_ms = deadline_ms;
        }
        Ok(())
    }

    /// Age rows before classifying a duplicate or streaming a retained invite.
    /// Missing/corrupt plaintext or call state never proves a live invite.
    pub async fn deliverable(
        &self,
        store: &dyn Storage,
        envelope: &UkmEnvelope,
        plaintext: Option<&str>,
        clock: impl FnOnce() -> u64,
    ) -> Result<bool, StorageError> {
        if envelope.kind != konsensus_core::kind::KIND_CALL_INVITE {
            return Ok(true);
        }
        let Some(signal) = plaintext.and_then(|text| CallSignal::parse(envelope.kind, text).ok())
        else {
            return Ok(false);
        };
        let _guard = super::lock().lock().await;
        let now_ms = clock();
        let tracked = self
            .invites
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&envelope.id)
            .cloned();
        let Some(invite) =
            tracked.filter(|i| i.peer == envelope.sender && i.call_id == signal.call_id)
        else {
            return Ok(false);
        };
        let row = store.call_get(&envelope.sender, &signal.call_id).await?;
        Ok(row.and_then(|e| e.at(now_ms)).is_some_and(|e| {
            e.side == Side::Callee
                && matches!(
                    e.phase,
                    Phase::AwaitingDevice | Phase::Ringing | Phase::Live
                )
                && match e.phase {
                    Phase::AwaitingDevice => invite.waiting && e.deadline_ms == invite.deadline_ms,
                    Phase::Ringing | Phase::Live => !invite.waiting,
                    _ => false,
                }
        }))
    }

    /// Expire waits before the existing call-state sweep. Return bounded
    /// control replies for the node's background writer, never a device GET.
    pub async fn sweep(
        &self,
        store: &dyn Storage,
        now_ms: u64,
    ) -> Result<Vec<(NodeId, Frame)>, StorageError> {
        let _guard = super::lock().lock().await;
        let due: Vec<_> = self
            .invites
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(_, invite)| {
                invite.ack_pending || invite.deadline_ms <= now_ms
            })
            .map(|(id, invite)| (*id, invite.clone()))
            .collect();
        let mut notices = Vec::with_capacity(due.len());
        for (id, invite) in due {
            let result: Result<(), StorageError> = async {
                let row = store.call_get(&invite.peer, &invite.call_id).await?;
                if invite.ack_pending {
                    notices.push((invite.peer, Frame::MessageAck { id, duplicate: false, paid_until_ms: None }));
                    if let Some(tracked) = self.invites.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&id) {
                        tracked.ack_pending = false;
                    }
                    if invite.deadline_ms > now_ms { return Ok(()); }
                }
                if invite.waiting {
                    // Capture before reholding: held envelopes become invisible.
                    // The hold is committed independently, so a failed deletion
                    // stays protected and the existing held-message sweep retries.
                    let envelope = store.get_message(&id).await?;
                    if let Some(envelope) = &envelope {
                        store.call_admission_rehold(envelope).await?;
                    }
                    store.call_invite_set_outcome(&id, &invite.peer, CallInviteOutcome::NotReachable).await?;
                    if let Some(row) = row.filter(|e| e.side == Side::Callee && e.phase == Phase::AwaitingDevice && e.deadline_ms == invite.deadline_ms) {
                        let ended = rules::CallEntry { phase: Phase::Ended, deadline_ms: row.deadline_ms.saturating_add(rules::TOMBSTONE_MS), ..row };
                        if let Err(e) = store.call_put(&invite.peer, &invite.call_id, &ended).await {
                            // It is already expired and held: reads age it to ended.
                            tracing::warn!(error = %e, "expired call tombstone will be aged on read");
                        }
                    }
                    if let Some(envelope) = envelope {
                        if let Err(e) = store.reject_accepted_envelope(&envelope).await {
                            tracing::warn!(error = %e, "expired call stays held until cleanup retries");
                        }
                    }
                    notices.push((
                        invite.peer,
                        Frame::MessageReject {
                            id,
                            reason: NOT_REACHABLE.into(),
                        },
                    ));
                } else if let Some(row) = row.filter(|e| e.side == Side::Callee && e.phase == Phase::Ringing && e.deadline_ms > now_ms) {
                    // Still ringing: keep the binding so another device can stream it.
                    if let Some(tracked) = self
                        .invites
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get_mut(&id)
                    {
                        tracked.deadline_ms = row.deadline_ms;
                    }
                    return Ok(());
                }
                // Answered, ended or rung out: the wait is over. Never write the
                // row here; live expiry and its Unpaid notice belong to
                // `expire_calls`, and reads age an unanswered row to ended.
                self.invites
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&id);
                Ok(())
            }
            .await;
            if let Err(e) = result {
                // One failing row must neither discard other callers' notices
                // nor remove the binding needed to retry this cleanup.
                tracing::warn!(error = %e, "call device expiry will retry");
            }
        }
        Ok(notices)
    }
}
