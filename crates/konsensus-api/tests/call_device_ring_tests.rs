//! #422: the callee starts the 60 s ring clock only when a paired device
//! fetches that invite. Time is an injected millisecond clock (the stored
//! grace deadline), never a sleep.

use konsensus_api::calls::{self, DeviceTook, Unfetched};
use konsensus_core::payloads::call::{
    Phase, DEVICE_RING_GRACE_MS, NOT_REACHABLE, RING_TIMEOUT_MS, TOMBSTONE_MS,
};
use konsensus_core::NodeId;
use konsensus_storage::{SqliteStorage, Storage};

fn offer(id: &str) -> String {
    format!(r#"{{"v":1,"call_id":"{id}","media":"audio","sdp":"v=0"}}"#)
}

fn id(n: usize) -> String {
    format!("{n:032x}")
}

fn own() -> NodeId {
    NodeId::from_bytes([0xee; 32])
}

async fn admitted(store: &SqliteStorage, n: usize) -> (NodeId, String, u64) {
    let peer = NodeId::from_bytes([0x42; 32]);
    let call = id(n);
    calls::admit_incoming(store, &own(), &peer, 400, Some(&offer(&call)))
        .await
        .unwrap();
    let waiting = store.call_get(&peer, &call).await.unwrap().unwrap();
    assert_eq!(waiting.phase, Phase::AwaitingDevice);
    let grace_end = waiting.deadline_ms;
    let invited_at = grace_end - DEVICE_RING_GRACE_MS;
    assert_ne!(
        grace_end,
        invited_at + RING_TIMEOUT_MS,
        "admitting the invite does not start the 60 s clock"
    );
    (peer, call, grace_end)
}

#[tokio::test]
async fn invite_with_no_device_is_not_reachable_and_the_ring_clock_never_starts() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let (peer, call, grace_end) = admitted(&store, 1).await;
    let invited_at = grace_end - DEVICE_RING_GRACE_MS;
    let early = grace_end - 1;

    assert_eq!(
        calls::conclude_unfetched(&store, &peer, &call, early)
            .await
            .unwrap(),
        Unfetched::Waiting {
            until_ms: grace_end
        },
    );
    let still = store.call_get(&peer, &call).await.unwrap().unwrap();
    assert_eq!(still.phase, Phase::AwaitingDevice);
    assert_eq!(
        still.deadline_ms, grace_end,
        "the ring deadline was not written"
    );

    let during = store.call_counts(&peer, early).await.unwrap();
    assert_eq!(
        (during.open_peer, during.burned_peer),
        (1, 0),
        "an invite waiting on a device still occupies one open slot"
    );

    assert_eq!(
        calls::conclude_unfetched(&store, &peer, &call, grace_end)
            .await
            .unwrap(),
        Unfetched::BecameNotReachable,
    );
    let missed = store.call_get(&peer, &call).await.unwrap().unwrap();
    assert_eq!(missed.phase, Phase::Unreachable);
    assert_eq!(missed.deadline_ms, grace_end + TOMBSTONE_MS);
    assert_ne!(
        missed.deadline_ms,
        invited_at + RING_TIMEOUT_MS + TOMBSTONE_MS,
        "a no-answer tombstone is not what was stored",
    );
    assert_eq!(NOT_REACHABLE, "not reachable");

    assert_eq!(
        calls::note_device_has_invite(&store, &peer, &call, grace_end)
            .await
            .unwrap(),
        DeviceTook::NotReachable,
    );
    assert_ne!(
        store.call_get(&peer, &call).await.unwrap().unwrap().phase,
        Phase::Ringing
    );
    assert_eq!(
        calls::conclude_unfetched(&store, &peer, &call, grace_end + 1)
            .await
            .unwrap(),
        Unfetched::AlreadyNotReachable,
    );

    let after = store.call_counts(&peer, grace_end).await.unwrap();
    assert_eq!(
        (after.open_peer, after.burned_peer),
        (0, 1),
        "not reachable burns the id and frees the open slot"
    );
    assert!(store
        .call_open_by_peer(&peer, grace_end)
        .await
        .unwrap()
        .is_empty());

    calls::admit_incoming(&store, &own(), &peer, 400, Some(&offer(&id(2))))
        .await
        .unwrap();
    assert_eq!(
        store.call_counts(&peer, grace_end).await.unwrap().open_peer,
        1,
        "a later invite is still admitted"
    );
}

#[tokio::test]
async fn a_device_fetch_starts_the_ring_clock_at_fetch_time() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let (peer, call, grace_end) = admitted(&store, 3).await;
    let invited_at = grace_end - DEVICE_RING_GRACE_MS;
    let fetch_at = invited_at + 4_000;
    assert!(fetch_at < grace_end);

    match calls::note_device_has_invite(&store, &peer, &call, fetch_at)
        .await
        .unwrap()
    {
        DeviceTook::Started { deadline_ms } => assert_eq!(deadline_ms, fetch_at + RING_TIMEOUT_MS),
        other => panic!("the first fetch starts the clock, got {other:?}"),
    }
    let ringing = store.call_get(&peer, &call).await.unwrap().unwrap();
    assert_eq!(ringing.phase, Phase::Ringing);
    assert_eq!(ringing.deadline_ms, fetch_at + RING_TIMEOUT_MS);
    assert_ne!(
        ringing.deadline_ms,
        invited_at + RING_TIMEOUT_MS,
        "the 60 s runs from the fetch"
    );
    assert_eq!(
        ringing
            .clone()
            .at(fetch_at + RING_TIMEOUT_MS - 1)
            .unwrap()
            .phase,
        Phase::Ringing
    );
    let no_answer = ringing.at(fetch_at + RING_TIMEOUT_MS).unwrap();
    assert_eq!(
        (no_answer.phase, no_answer.deadline_ms),
        (Phase::Ended, fetch_at + RING_TIMEOUT_MS + TOMBSTONE_MS)
    );

    assert_eq!(
        calls::conclude_unfetched(&store, &peer, &call, grace_end)
            .await
            .unwrap(),
        Unfetched::Ringing {
            deadline_ms: fetch_at + RING_TIMEOUT_MS
        },
    );
    assert_eq!(
        store.call_get(&peer, &call).await.unwrap().unwrap().phase,
        Phase::Ringing
    );
}

#[tokio::test]
async fn a_second_device_fetch_does_not_restart_the_ring_clock() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let (peer, call, grace_end) = admitted(&store, 4).await;
    let invited_at = grace_end - DEVICE_RING_GRACE_MS;
    let first_at = invited_at + 1_000;
    let second_at = first_at + 10_000;
    assert!(second_at < grace_end);

    let started = calls::note_device_has_invite(&store, &peer, &call, first_at)
        .await
        .unwrap();
    assert_eq!(
        started,
        DeviceTook::Started {
            deadline_ms: first_at + RING_TIMEOUT_MS
        }
    );

    let again = calls::note_device_has_invite(&store, &peer, &call, second_at)
        .await
        .unwrap();
    assert_eq!(
        again,
        DeviceTook::Already {
            deadline_ms: first_at + RING_TIMEOUT_MS
        }
    );
    assert_ne!(first_at + RING_TIMEOUT_MS, second_at + RING_TIMEOUT_MS);

    let stored = store.call_get(&peer, &call).await.unwrap().unwrap();
    assert_eq!(stored.phase, Phase::Ringing);
    assert_eq!(stored.deadline_ms, first_at + RING_TIMEOUT_MS);
}

/// Finding 2: a paid invite stays ringing under a grace-plus-60 s safety cap.
/// The caller's 60 s clock is stored when the ringing ack arrives, and a later
/// reservation does not drop that anchor.
#[tokio::test]
async fn caller_ring_deadline_anchors_at_the_ringing_ack() {
    use konsensus_core::payloads::call::{commit, release, reserve, Phase};
    let store = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([0x42; 32]);
    let call = id(7);
    let paid_at = calls::now_ms();
    let caller = commit(
        reserve(None, 400, "op", "h", paid_at).unwrap(),
        "op",
        paid_at,
    );
    assert_eq!(caller.phase, Phase::Ringing);
    assert!(!caller.ring_anchored);
    assert_eq!(
        caller.deadline_ms,
        paid_at + DEVICE_RING_GRACE_MS + RING_TIMEOUT_MS
    );
    store.call_put(&peer, &call, &caller).await.unwrap();
    let loaded = store.call_get(&peer, &call).await.unwrap().unwrap();
    assert!(!loaded.ring_anchored);
    assert_eq!(loaded.deadline_ms, caller.deadline_ms);

    let anchored_at = calls::now_ms();
    assert!(calls::note_caller_ringing(&store, &peer, &call).await.unwrap());
    let stored = store.call_get(&peer, &call).await.unwrap().unwrap();
    assert!(stored.ring_anchored);
    assert!(stored.deadline_ms >= anchored_at + RING_TIMEOUT_MS);
    assert!(stored.deadline_ms <= calls::now_ms() + RING_TIMEOUT_MS);

    let reserved = reserve(
        Some(stored.clone()),
        konsensus_core::kind::KIND_CALL_HANGUP,
        "hang",
        "h2",
        calls::now_ms(),
    )
    .unwrap();
    assert!(reserved.ring_anchored);
    assert_eq!(reserved.deadline_ms, stored.deadline_ms);
    store.call_put(&peer, &call, &reserved).await.unwrap();
    let roundtrip = store.call_get(&peer, &call).await.unwrap().unwrap();
    assert!(roundtrip.ring_anchored);
    assert!(roundtrip.pending.is_some());
    assert_eq!(roundtrip.deadline_ms, stored.deadline_ms);
    let released = release(roundtrip, "hang").unwrap();
    store.call_put(&peer, &call, &released).await.unwrap();

    assert!(!calls::note_caller_ringing(&store, &peer, &call)
        .await
        .unwrap());
    let again = store.call_get(&peer, &call).await.unwrap().unwrap();
    assert!(again.ring_anchored);
    assert_eq!(again.deadline_ms, stored.deadline_ms);
}

/// Finding 3: classification failure is not a success ack. A missing call row
/// is a storage error, and that error holds the retry.
#[tokio::test]
async fn invite_retry_holds_the_ack_when_classification_fails() {
    assert_eq!(
        calls::invite_retry_decision(Err(())),
        calls::InviteRetry::Hold
    );
    assert_eq!(
        calls::invite_retry_decision(Ok(calls::Unfetched::Waiting { until_ms: 1 })),
        calls::InviteRetry::Hold
    );
    assert!(matches!(
        calls::invite_retry_decision(Ok(calls::Unfetched::Ringing { deadline_ms: 1 })),
        calls::InviteRetry::Ack
    ));
    assert_eq!(
        calls::invite_retry_decision(Ok(calls::Unfetched::BecameNotReachable)),
        calls::InviteRetry::NotReachable
    );

    let store = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([9; 32]);
    let msg = konsensus_core::MessageId::from_bytes([3; 32]);
    let call = id(8);
    store.bind_call_invite(&msg, &peer, &call).await.unwrap();
    assert_eq!(
        store.call_invite_binding(&msg).await.unwrap(),
        Some((peer, call.clone()))
    );
    sqlx::query("DROP TABLE call_state")
        .execute(store.pool())
        .await
        .unwrap();
    assert!(calls::conclude_unfetched(&store, &peer, &call, 1)
        .await
        .is_err());
    assert_eq!(
        calls::invite_retry_decision(Err(())),
        calls::InviteRetry::Hold
    );
}

struct StallTransport {
    started: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
    sent: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl konsensus_core::traits::transport::MessageTransport for StallTransport {
    async fn send(
        &self,
        _peer: &NodeId,
        _envelope: &konsensus_core::UkmEnvelope,
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        Ok(())
    }

    async fn recv(&self) -> Result<konsensus_core::UkmEnvelope, konsensus_core::traits::transport::TransportError> {
        std::future::pending().await
    }

    async fn connect(
        &self,
        _peer: &NodeId,
        _addr: &str,
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        Ok(())
    }

    async fn disconnect(
        &self,
        _peer: &NodeId,
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        Ok(())
    }

    async fn is_connected(&self, _peer: &NodeId) -> bool {
        false
    }

    async fn connected_peers(&self) -> Vec<NodeId> {
        Vec::new()
    }

    async fn send_raw_frame(
        &self,
        _peer: &NodeId,
        _frame_bytes: &[u8],
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.started.notify_one();
        self.release.notified().await;
        self.sent
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// Finding 4: a ring notice returns while the caller socket write is still
/// blocked, so an inbox read is not stuck on that peer.
#[tokio::test]
async fn ring_notice_does_not_block_on_a_stalled_caller() {
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let sent = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let transport = std::sync::Arc::new(StallTransport {
        started: std::sync::Arc::clone(&started),
        release: std::sync::Arc::clone(&release),
        sent: std::sync::Arc::clone(&sent),
    }) as std::sync::Arc<dyn konsensus_core::traits::transport::MessageTransport>;
    let began = std::time::Instant::now();
    calls::notify_caller(
        transport,
        &NodeId::from_bytes([1; 32]),
        konsensus_core::MessageId::from_bytes([2; 32]),
        calls::CallerNotice::Ringing { duplicate: false },
    );
    assert!(began.elapsed() < std::time::Duration::from_millis(200));
    assert!(!sent.load(std::sync::atomic::Ordering::SeqCst));
    tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
        .await
        .unwrap();
    assert!(
        !sent.load(std::sync::atomic::Ordering::SeqCst),
        "the socket write is still blocked"
    );
    release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !sent.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
