//! Callee-only device wait. Bindings are volatile and bounded by existing call limits;
//! restart ends awaiting rows rather than guessing which old message owns one.

use std::{collections::HashMap, sync::Mutex};

use konsensus_core::{
    payloads::call::{self as rules, CallRefusal, CallSignal, Phase, Side},
    MessageId, NodeId, UkmEnvelope,
};
use konsensus_message::Frame;
use konsensus_storage::{CallInviteExpiry, CallInviteOutcome, Storage, StorageError};

pub const NOT_REACHABLE: &str = "call_not_reachable";

#[derive(Clone)]
struct Invite {
    peer: NodeId,
    call_id: String,
    deadline_ms: u64,
    waiting: bool,
    ack_pending: bool,
    /// Earliest completed device stream write of this invite. It anchors the
    /// ring clock on every delivery path, and the sweep reconciles it before
    /// it may expire the wait.
    witnessed_ms: Option<u64>,
    /// Stream writes in flight. The sweep never expires a wait under one.
    sending: u32,
}

/// One device stream write of a waiting invite, armed under the call lock so
/// the sweep cannot expire the wait while it is in flight. Dropping it ends
/// the write; a completed write leaves its time as delivery evidence first.
pub struct StreamTicket<'a> {
    devices: &'a Devices,
    id: MessageId,
    armed: bool,
    written_ms: Option<u64>,
}

impl StreamTicket<'_> {
    /// The device received the invite at `at_ms`.
    pub fn written(&mut self, at_ms: u64) {
        self.written_ms = Some(at_ms);
    }
}

impl Drop for StreamTicket<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(tracked) = self.devices.invites.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&self.id) {
            tracked.sending = tracked.sending.saturating_sub(1);
            if let Some(at_ms) = self.written_ms.filter(|_| tracked.waiting) {
                // The actual completion time anchors the ring clock. Armed
                // before the deadline, it counts as delivered within the wait
                // even if the socket write finished just after it.
                tracked.witnessed_ms = Some(tracked.witnessed_ms.map_or(at_ms, |first| first.min(at_ms)));
            }
        }
    }
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
        if envelope.kind == konsensus_core::kind::KIND_CALL_INVITE
            && !rules::invite_fresh(envelope.timestamp, arrived_ms)
        {
            // Too old (or too far ahead) to ring inside the caller's answer
            // window: refuse it as not reachable, so the caller ends the call.
            // Record that outcome first, so withdrawal keeps it and a retry
            // replays the refusal instead of passing as delivered.
            store
                .call_invite_set_outcome(&envelope.id, &envelope.sender, CallInviteOutcome::NotReachable)
                .await
                .map_err(unavailable)?;
            return Err(CallRefusal::NotReachable);
        }
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
                        witnessed_ms: None,
                        sending: 0,
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
    ) -> Result<bool, StorageError> {
        if envelope.kind != konsensus_core::kind::KIND_CALL_INVITE {
            return Ok(true);
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
            // No binding: possibly expired while this request was reading the
            // invite. Only durable evidence decides; an invite that ended not
            // reachable, or still pending without a wait, is never handed out
            // (Codex FAIL on #472).
            return Ok(!matches!(
                store.call_invite_outcome(envelope).await?,
                Some(CallInviteOutcome::NotReachable | CallInviteOutcome::Pending)
            ));
        };
        if !invite.waiting {
            return Ok(true);
        }
        if store.call_invite_outcome(envelope).await? == Some(CallInviteOutcome::Fetched)
            && self.adopt(store, &envelope.id, &invite).await?
        {
            // An earlier delivery committed but its request was cancelled before
            // the registry saw it: adopt the durable state (Codex FAIL on #472).
            return Ok(true);
        }
        // The first device delivery starts the ring clock, whichever path
        // finally records it (Codex FAIL on #472).
        let at_ms = invite.witnessed_ms.map_or(now_ms, |first| first.min(now_ms));
        self.deliver(store, &envelope.id, &invite, at_ms).await
    }

    /// Start ringing from a delivery at `at_ms`. The receipt and the ringing
    /// row commit together or not at all, and only while the receipt is still
    /// pending; a delivery that committed first is adopted, never overwritten.
    /// Returns whether the invite is now delivered.
    async fn deliver(&self, store: &dyn Storage, id: &MessageId, invite: &Invite, at_ms: u64) -> Result<bool, StorageError> {
        let Some(row) = store.call_get(&invite.peer, &invite.call_id).await? else {
            return Ok(false);
        };
        // A stream write armed before the deadline is eligible even if it
        // completed after it; any other delivery must land within the wait.
        let witnessed = invite.witnessed_ms == Some(at_ms);
        if row.side != Side::Callee
            || row.phase != Phase::AwaitingDevice
            || row.deadline_ms != invite.deadline_ms
            || (at_ms >= row.deadline_ms && !witnessed)
        {
            return Ok(false);
        }
        let deadline_ms = row.deadline_ms;
        // A crossing write rings from its completion, bounded by the write
        // timeout the caller's answer window allows for.
        let start_ms = at_ms.min(deadline_ms.saturating_add(rules::DEVICE_WRITE_TIMEOUT_MS));
        let next = rules::CallEntry {
            deadline_ms: start_ms.saturating_add(rules::RING_TIMEOUT_MS),
            ..row.device_fetched(at_ms.min(deadline_ms.saturating_sub(1))).expect("unexpired row")
        };
        if store.call_invite_deliver(id, &invite.peer, &invite.call_id, &next).await? {
            self.delivered(id, next.deadline_ms);
            return Ok(true);
        }
        self.adopt(store, id, invite).await
    }

    /// Adopt a delivery another request committed: owe its ACK, and follow
    /// the stored ring deadline rather than any local snapshot. Only a row
    /// that is ringing or live proves one; a receipt alone never does.
    async fn adopt(&self, store: &dyn Storage, id: &MessageId, invite: &Invite) -> Result<bool, StorageError> {
        let row = store.call_get(&invite.peer, &invite.call_id).await?;
        let Some(row) = row.filter(|e| e.side == Side::Callee && matches!(e.phase, Phase::Ringing | Phase::Live)) else {
            return Ok(false);
        };
        self.delivered(id, row.deadline_ms);
        Ok(true)
    }

    /// Send a committed delivery's owed ACK now, from the sweep itself.
    fn take_ack(&self, id: &MessageId, peer: &NodeId, notices: &mut Vec<(NodeId, Frame)>) {
        if let Some(tracked) = self.invites.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id) {
            if std::mem::take(&mut tracked.ack_pending) {
                notices.push((*peer, Frame::MessageAck { id: *id, duplicate: false, paid_until_ms: None }));
            }
        }
    }

    /// Record a committed delivery: stop waiting and owe the caller its ACK.
    fn delivered(&self, id: &MessageId, deadline_ms: u64) {
        if let Some(tracked) = self.invites.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id) {
            tracked.waiting = false;
            tracked.ack_pending = true;
            tracked.deadline_ms = deadline_ms;
        }
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
        Ok(self.stream(store, envelope, plaintext, clock).await?.is_some())
    }

    /// [`Self::deliverable`] for a device stream about to write `envelope`.
    /// For a waiting invite the ticket is armed under the call lock, so the
    /// deadline sweep cannot expire the wait until the write has finished and
    /// left its evidence (Codex FAIL on #472).
    pub async fn stream(
        &self,
        store: &dyn Storage,
        envelope: &UkmEnvelope,
        plaintext: Option<&str>,
        clock: impl FnOnce() -> u64,
    ) -> Result<Option<StreamTicket<'_>>, StorageError> {
        let ticket = |armed| StreamTicket { devices: self, id: envelope.id, armed, written_ms: None };
        if envelope.kind != konsensus_core::kind::KIND_CALL_INVITE {
            return Ok(Some(ticket(false)));
        }
        let Some(signal) = plaintext.and_then(|text| CallSignal::parse(envelope.kind, text).ok())
        else {
            return Ok(None);
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
            return Ok(None);
        };
        let row = store.call_get(&envelope.sender, &signal.call_id).await?;
        let live = row.and_then(|e| e.at(now_ms)).is_some_and(|e| {
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
        });
        if !live {
            return Ok(None);
        }
        if invite.waiting {
            if let Some(tracked) = self.invites.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&envelope.id) {
                tracked.sending = tracked.sending.saturating_add(1);
            }
        }
        Ok(Some(ticket(invite.waiting)))
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
                invite.ack_pending
                    || invite.deadline_ms <= now_ms
                    || (invite.waiting && invite.witnessed_ms.is_some())
            })
            .map(|(id, _)| *id)
            .collect();
        let mut notices = Vec::with_capacity(due.len());
        for id in due {
            let result: Result<(), StorageError> = async {
                // Decide on the current entry, not the snapshot: a stream write
                // may have finished and left its evidence since. No write can
                // start meanwhile, as arming one needs the call lock held here.
                let Some(invite) = self.invites.lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned() else {
                    return Ok(());
                };
                let row = store.call_get(&invite.peer, &invite.call_id).await?;
                if invite.ack_pending {
                    notices.push((invite.peer, Frame::MessageAck { id, duplicate: false, paid_until_ms: None }));
                    if let Some(tracked) = self.invites.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&id) {
                        tracked.ack_pending = false;
                    }
                    if invite.deadline_ms > now_ms { return Ok(()); }
                }
                // Witnessed stream delivery is reconciled first: it rang the
                // call when the device received it, not when storage recovered.
                if invite.waiting {
                    if let Some(at_ms) = invite.witnessed_ms {
                        if self.deliver(store, &id, &invite, at_ms).await? {
                            self.take_ack(&id, &invite.peer, &mut notices);
                            return Ok(());
                        }
                    }
                }
                if invite.waiting && (invite.deadline_ms > now_ms || invite.sending > 0) {
                    return Ok(());
                }
                if invite.waiting {
                    // Capture before reholding: held envelopes become invisible.
                    let envelope = store.get_message(&id).await?;
                    // Expiry and delivery are decided by one storage transaction
                    // on the receipt: a delivery that committed first, even by a
                    // cancelled request, is acknowledged and never refused.
                    match store.call_invite_expire(&id, &invite.peer, &invite.call_id, invite.deadline_ms).await? {
                        CallInviteExpiry::Expired => {}
                        CallInviteExpiry::Delivered => {
                            if self.adopt(store, &id, &invite).await? {
                                self.take_ack(&id, &invite.peer, &mut notices);
                            }
                            return Ok(());
                        }
                        CallInviteExpiry::Gone => {
                            // Moved on without a delivery: no ACK, no refusal.
                            self.invites.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                            return Ok(());
                        }
                    }
                    // The hold is committed with the expiry, so a failed deletion
                    // stays protected and the existing held-message sweep retries.
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
