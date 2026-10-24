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
