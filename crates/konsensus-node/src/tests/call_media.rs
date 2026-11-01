//! Router unit tests (M6 N2): refusals, rate cap, drop-oldest queues and the
//! app → peer pump, over a recording link and a stub admission.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use konsensus_api::call_media::{AttachRefusal, CallMediaPort, MediaFrame, MEDIA_QUEUE_FRAMES};
use konsensus_core::traits::transport::TransportError;
use konsensus_core::types::NodeId;
use konsensus_message::wire::MAX_CALL_MEDIA_BYTES;
use konsensus_message::{CallMediaEvent, Frame};

use super::{CallMediaAdmission, CallMediaRouter, MediaDrop, MediaLink, RateCap, MAX_BYTES_PER_SECOND, MAX_FRAMES_PER_SECOND,
    MEDIA_BURST_BYTES, MEDIA_BURST_FRAMES};

const CALL: &str = "0123456789abcdef0123456789abcdef";
const OTHER_CALL: &str = "fedcba9876543210fedcba9876543210";

fn peer() -> NodeId {
    NodeId::from_bytes([0x11; 32])
}

fn stranger() -> NodeId {
    NodeId::from_bytes([0x22; 32])
}

/// Admits exactly the `(peer, call_id)` pairs it was told to.
#[derive(Default)]
struct StubAdmission {
    admitted: Mutex<HashSet<(NodeId, String)>>,
}

impl StubAdmission {
    fn admit(&self, peer: NodeId, call_id: &str) {
        self.admitted.lock().unwrap().insert((peer, call_id.to_string()));
    }
    fn revoke(&self, peer: NodeId, call_id: &str) {
        self.admitted.lock().unwrap().remove(&(peer, call_id.to_string()));
    }
}

#[async_trait]
impl CallMediaAdmission for StubAdmission {
    async fn call_media_admitted(&self, peer: &NodeId, call_id: &str, _now_ms: u64) -> bool {
        self.admitted.lock().unwrap().contains(&(*peer, call_id.to_string()))
    }
}

/// Records what the router sends; `connected` peers route media.
#[derive(Default)]
struct RecordingLink {
    connected: Mutex<HashSet<NodeId>>,
    sent: Mutex<Vec<(NodeId, Vec<u8>)>>,
    busy: std::sync::atomic::AtomicBool,
    stalled: std::sync::atomic::AtomicBool,
    sending: tokio::sync::Notify,
    inbound: Mutex<Option<tokio::sync::mpsc::Receiver<CallMediaEvent>>>,
}

impl RecordingLink {
    fn sent_frames(&self) -> Vec<(NodeId, Frame)> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|(peer, bytes)| (*peer, Frame::from_bytes(bytes).unwrap()))
            .collect()
    }
}

#[async_trait]
impl MediaLink for RecordingLink {
    async fn peer_routes_media(&self, peer: &NodeId) -> bool {
        self.connected.lock().unwrap().contains(peer)
    }
    async fn send_call_media(&self, peer: &NodeId, frame_bytes: &[u8]) -> Result<(), TransportError> {
        if self.stalled.load(std::sync::atomic::Ordering::SeqCst) {
            self.sending.notify_one();
            return std::future::pending().await;
        }
        if self.busy.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(TransportError::Timeout("call media writer busy".into()));
        }
        self.sent.lock().unwrap().push((*peer, frame_bytes.to_vec()));
        Ok(())
    }
    async fn recv_call_media(&self) -> Option<CallMediaEvent> {
        let rx = self.inbound.lock().unwrap().take();
        match rx {
            Some(mut rx) => {
                let next = rx.recv().await;
                *self.inbound.lock().unwrap() = Some(rx);
                next
            }
            None => std::future::pending().await,
        }
    }
}

struct Fixture {
    router: Arc<CallMediaRouter>,
    link: Arc<RecordingLink>,
    admission: Arc<StubAdmission>,
}

fn fixture() -> Fixture {
    let link = Arc::new(RecordingLink::default());
    link.connected.lock().unwrap().insert(peer());
    let admission = Arc::new(StubAdmission::default());
    admission.admit(peer(), CALL);
    let router = CallMediaRouter::new(
        Arc::clone(&link) as Arc<dyn MediaLink>,
        Arc::clone(&admission) as Arc<dyn CallMediaAdmission>,
    );
    Fixture { router, link, admission }
}

fn event(from: NodeId, call_id: &str, seq: u32, privileged: bool) -> CallMediaEvent {
    CallMediaEvent { peer_id: from, call_id: call_id.to_string(), seq, data: vec![seq as u8; 160], privileged }
}

#[tokio::test]
async fn frames_for_unknown_calls_or_from_non_counterparties_are_dropped_without_reply() {
    let f = fixture();
    // Nothing attached yet: every frame is an unknown call.
    assert_eq!(f.router.inbound(event(peer(), CALL, 1, true)).await, Err(MediaDrop::UnknownCall));

    let attachment = f.router.attach(&peer(), CALL).await.unwrap();
    assert_eq!(f.router.inbound(event(peer(), OTHER_CALL, 1, true)).await, Err(MediaDrop::UnknownCall));
    assert_eq!(f.router.inbound(event(stranger(), CALL, 1, true)).await, Err(MediaDrop::UnknownCall));
    assert_eq!(f.router.inbound(event(peer(), CALL, 1, false)).await, Err(MediaDrop::Unprivileged));
    let oversize = CallMediaEvent { data: vec![0; MAX_CALL_MEDIA_BYTES + 1], ..event(peer(), CALL, 1, true) };
    assert_eq!(f.router.inbound(oversize).await, Err(MediaDrop::Oversize));

    // Dropped means dropped: nothing reached the app, nothing went back.
    assert!(attachment.from_node.try_pop().is_none());
    assert!(f.link.sent.lock().unwrap().is_empty());
    assert_eq!(f.router.dropped(MediaDrop::UnknownCall), 3);

    // The counterparty's frame, privileged, is the one that arrives.
    f.router.inbound(event(peer(), CALL, 9, true)).await.unwrap();
    assert_eq!(attachment.from_node.try_pop().unwrap(), MediaFrame { seq: 9, payload: vec![9; 160] });
}

#[tokio::test]
async fn same_call_id_routes_independently_for_each_peer() {
    let f = fixture();
    f.link.connected.lock().unwrap().insert(stranger());
    f.admission.admit(stranger(), CALL);
    let first = f.router.attach(&peer(), CALL).await.unwrap();
    let second = f.router.attach(&stranger(), CALL).await.expect("distinct peer, distinct route");
    assert_eq!(f.router.routed_calls(), 2);
    assert_eq!(f.router.attach(&stranger(), CALL).await.err(), Some(AttachRefusal::AlreadyAttached));
    f.router.inbound(event(peer(), CALL, 11, true)).await.unwrap();
    f.router.inbound(event(stranger(), CALL, 22, true)).await.unwrap();
    assert_eq!(first.from_node.try_pop().unwrap().seq, 11);
    assert_eq!(second.from_node.try_pop().unwrap().seq, 22);
    assert!(first.from_node.try_pop().is_none() && second.from_node.try_pop().is_none());
    drop(first);
    assert_eq!(f.router.routed_calls(), 1);
    assert!(!second.from_node.is_closed());
    f.router.inbound(event(stranger(), CALL, 23, true)).await.unwrap();
    assert_eq!(second.from_node.try_pop().unwrap().seq, 23);
    let replacement = f.router.attach(&peer(), CALL).await.unwrap();
    drop(second);
    assert_eq!(f.router.routed_calls(), 1);
    assert!(!replacement.from_node.is_closed());
    drop(replacement);
    assert_eq!(f.router.routed_calls(), 0);
}

#[tokio::test]
async fn attach_requires_an_admitted_call_and_a_media_capable_peer_once() {
    let f = fixture();
    assert_eq!(f.router.attach(&peer(), OTHER_CALL).await.err(), Some(AttachRefusal::NotAdmitted));
    assert_eq!(f.router.attach(&stranger(), CALL).await.err(), Some(AttachRefusal::NotAdmitted));
    assert_eq!(f.router.attach(&peer(), "not-a-call-id").await.err(), Some(AttachRefusal::NotAdmitted));

    // Admitted, but the peer is not connected (or runs an older node).
    f.admission.admit(stranger(), CALL);
    assert_eq!(f.router.attach(&stranger(), CALL).await.err(), Some(AttachRefusal::Unavailable));

    let first = f.router.attach(&peer(), CALL).await.unwrap();
    assert_eq!(first.peer, peer());
    assert_eq!(f.router.attach(&peer(), CALL).await.err(), Some(AttachRefusal::AlreadyAttached));
    assert_eq!(f.router.routed_calls(), 1);

    // Dropping the socket's attachment frees the call for the next socket.
    drop(first);
    assert_eq!(f.router.routed_calls(), 0);
    let second = f.router.attach(&peer(), CALL).await.unwrap();
    assert!(!second.from_node.is_closed());
}

#[tokio::test]
async fn media_stops_once_the_call_is_no_longer_admitted() {
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL).await.unwrap();
    f.router.inbound(event(peer(), CALL, 1, true)).await.unwrap();

    // Admission is revoked; the timer releases the route without another packet.
    f.admission.revoke(peer(), CALL);
    f.router.inbound(event(peer(), CALL, 2, true)).await.unwrap();
    tokio::time::sleep(super::ADMISSION_RECHECK + Duration::from_millis(100)).await;
    assert_eq!(f.router.inbound(event(peer(), CALL, 3, true)).await, Err(MediaDrop::UnknownCall));

    // The route is gone and the socket sees its queue end after what was queued.
    assert_eq!(f.router.routed_calls(), 0);
    assert_eq!(attachment.from_node.pop().await.map(|m| m.seq), Some(1));
    assert_eq!(attachment.from_node.pop().await.map(|m| m.seq), Some(2));
    assert_eq!(attachment.from_node.pop().await, None);
    assert!(attachment.to_node.is_closed());
    assert_eq!(f.router.inbound(event(peer(), CALL, 4, true)).await, Err(MediaDrop::UnknownCall));
}

/// 20 ms audio: one packet every 20 ms.
const AUDIO_TICK: Duration = Duration::from_millis(20);
/// A typical encoded 20 ms audio packet.
const AUDIO_BYTES: usize = 160;

/// Offer `count` packets of `bytes` spaced `every` apart from `*now`; returns
/// how many were admitted and leaves `*now` after the last one.
fn offer(cap: &mut RateCap, now: &mut Instant, count: u32, every: Duration, bytes: usize) -> u32 {
    let mut admitted = 0;
    for _ in 0..count {
        if cap.admit(*now, bytes) {
            admitted += 1;
        }
        *now += every;
    }
    admitted
}

#[test]
fn rate_cap_steady_audio_never_drops() {
    let start = Instant::now();
    let mut cap = RateCap::media(start);
    let mut now = start;
    let packets = 50 * 600; // ten minutes at 50 packets per second
    assert_eq!(offer(&mut cap, &mut now, packets, AUDIO_TICK, AUDIO_BYTES), packets);
}

#[test]
fn rate_cap_passes_a_catch_up_burst_after_a_path_stall() {
    let start = Instant::now();
    let mut cap = RateCap::media(start);
    let mut now = start;
    assert_eq!(offer(&mut cap, &mut now, 100, AUDIO_TICK, AUDIO_BYTES), 100, "two seconds of steady audio");
    // The path stalls for 1.5 s; the backlog (75 packets) then arrives at
    // once, and live audio carries on at 50 packets per second.
    now += Duration::from_millis(1500);
    assert_eq!(offer(&mut cap, &mut now, 75, Duration::ZERO, AUDIO_BYTES), 75, "the catch-up burst");
    assert_eq!(offer(&mut cap, &mut now, 100, AUDIO_TICK, AUDIO_BYTES), 100, "live audio after the burst");
}

#[test]
fn rate_cap_holds_a_sustained_overrun_to_the_frame_rate() {
    let start = Instant::now();
    let mut cap = RateCap::media(start);
    let mut now = start;
    let seconds = 60;
    let admitted = offer(&mut cap, &mut now, 150 * seconds, Duration::from_secs(1) / 150, AUDIO_BYTES);
    let sustained = MAX_FRAMES_PER_SECOND * seconds;
    assert!(admitted >= sustained, "admitted {admitted}, sustained {sustained}");
    assert!(admitted <= sustained + MEDIA_BURST_FRAMES, "admitted {admitted} exceeds rate plus burst");

    // At once, never more than the burst.
    let mut cap = RateCap::media(start);
    let mut now = start;
    assert_eq!(offer(&mut cap, &mut now, MEDIA_BURST_FRAMES + 50, Duration::ZERO, AUDIO_BYTES), MEDIA_BURST_FRAMES);
    assert!(!cap.admit(now, AUDIO_BYTES), "frame budget spent");
    assert!(cap.admit(now + Duration::from_millis(10), AUDIO_BYTES), "one frame refills in 10 ms");
    assert!(!cap.admit(now + Duration::from_millis(10), AUDIO_BYTES));
}

#[test]
fn rate_cap_bounds_bytes_the_same_way() {
    let start = Instant::now();
    let per_frame = MAX_CALL_MEDIA_BYTES;

    // At once: the byte burst passes, to the byte, and nothing more.
    let mut cap = RateCap::media(start);
    let fits = (MEDIA_BURST_BYTES as usize) / per_frame;
    for _ in 0..fits {
        assert!(cap.admit(start, per_frame));
    }
    assert!(!cap.admit(start, per_frame), "byte burst spent");
    assert!(!cap.admit(start, 1), "the byte budget is spent to the byte");
    assert!(cap.admit(start + Duration::from_secs(1), MAX_BYTES_PER_SECOND as usize), "one second refills the sustained rate");
    assert!(!cap.admit(start + Duration::from_secs(1), 1));

    // Sustained: 40 full packets per second (160 KiB/s) is held to 64 KiB/s.
    let mut cap = RateCap::media(start);
    let mut now = start;
    let seconds = 60u64;
    let admitted = offer(&mut cap, &mut now, 40 * seconds as u32, Duration::from_secs(1) / 40, per_frame) as u64;
    let bytes = admitted * per_frame as u64;
    let sustained = MAX_BYTES_PER_SECOND * seconds;
    assert!(bytes + per_frame as u64 >= sustained, "admitted {bytes} bytes, sustained {sustained}");
    assert!(bytes <= sustained + MEDIA_BURST_BYTES, "admitted {bytes} bytes exceeds rate plus burst");
}

#[test]
fn rate_cap_refusal_consumes_nothing() {
    let start = Instant::now();
    // A packet that would cross the byte budget is refused, but a smaller
    // one still fits: the refusal took neither bytes nor a frame.
    let mut cap = RateCap::new(2, 1000, 2, 1000, start);
    assert!(cap.admit(start, 900));
    assert!(!cap.admit(start, 200));
    assert!(cap.admit(start, 100));
    assert!(!cap.admit(start, 0), "frame budget spent");

    // A refusal for frames takes no bytes either.
    // Bytes refill at 1 byte per second here, so any byte credit a refused
    // packet took would still be missing a second later.
    let mut cap = RateCap::new(1, 1, 1, 1000, start);
    assert!(cap.admit(start, 0));
    for _ in 0..10 {
        assert!(!cap.admit(start, 100));
    }
    assert!(cap.admit(start + Duration::from_secs(1), 1000), "the refused packets took no bytes");
}

#[tokio::test]
async fn inbound_frames_over_the_cap_are_dropped() {
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL).await.unwrap();
    // The burst passes at once; credit refills in real time meanwhile, so
    // the cap may bite a little past the burst but never before it.
    let mut last_ok = None;
    let mut capped_at = None;
    for seq in 0..2 * MEDIA_BURST_FRAMES {
        match f.router.inbound(event(peer(), CALL, seq, true)).await {
            Ok(()) => last_ok = Some(seq),
            Err(reason) => {
                assert_eq!(reason, MediaDrop::RateCapped);
                capped_at = Some(seq);
                break;
            }
        }
    }
    let capped_at = capped_at.expect("a burst well past the cap is capped");
    assert!(capped_at >= MEDIA_BURST_FRAMES, "capped at {capped_at}, inside the burst");
    assert_eq!(f.router.dropped(MediaDrop::RateCapped), 1);
    // The queue kept the newest of what was admitted, never the capped one.
    let newest = std::iter::from_fn(|| attachment.from_node.try_pop()).last().unwrap();
    assert_eq!(Some(newest.seq), last_ok);
}

#[tokio::test]
async fn to_app_queue_drops_the_oldest_audio_rather_than_block() {
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL).await.unwrap();
    let total = MEDIA_QUEUE_FRAMES as u32 + 8;
    for seq in 0..total {
        f.router.inbound(event(peer(), CALL, seq, true)).await.unwrap();
    }
    assert_eq!(attachment.from_node.len(), MEDIA_QUEUE_FRAMES);
    assert_eq!(attachment.from_node.dropped(), 8);
    let seqs: Vec<u32> = std::iter::from_fn(|| attachment.from_node.try_pop()).map(|m| m.seq).collect();
    assert_eq!(seqs.first(), Some(&8), "the oldest eight were dropped");
    assert_eq!(seqs.last(), Some(&(total - 1)));
}

#[tokio::test]
async fn app_packets_go_to_the_peer_as_call_media_frames_in_order() {
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL).await.unwrap();
    for seq in 1..=10u32 {
        attachment.to_node.push(MediaFrame { seq, payload: vec![seq as u8; 100] }).unwrap();
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while f.link.sent.lock().unwrap().len() < 10 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("ten frames forwarded");
    let sent = f.link.sent_frames();
    for (i, (to, frame)) in sent.iter().enumerate() {
        assert_eq!(*to, peer());
        let seq = i as u32 + 1;
        assert!(
            matches!(frame, Frame::CallMedia { call_id, seq: s, data } if call_id == CALL && *s == seq && *data == vec![seq as u8; 100]),
            "{frame:?}"
        );
    }

    // A busy peer writer costs the packet, not the call.
    f.link.busy.store(true, std::sync::atomic::Ordering::SeqCst);
    attachment.to_node.push(MediaFrame { seq: 11, payload: vec![1] }).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while f.router.dropped(MediaDrop::PeerBusy) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("busy drop counted");
    f.link.busy.store(false, std::sync::atomic::Ordering::SeqCst);
    attachment.to_node.push(MediaFrame { seq: 12, payload: vec![2] }).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while f.link.sent.lock().unwrap().len() < 11 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the next packet still flows");
    assert!(matches!(f.link.sent_frames().last().unwrap().1, Frame::CallMedia { seq: 12, .. }));
    assert_eq!(f.router.routed_calls(), 1);
}

#[tokio::test]
async fn inbound_loop_routes_transport_events_until_shutdown() {
    let f = fixture();
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    *f.link.inbound.lock().unwrap() = Some(rx);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let worker = f.router.spawn(shutdown_rx);
    let attachment = f.router.attach(&peer(), CALL).await.unwrap();

    tx.send(event(peer(), CALL, 5, true)).await.unwrap();
    tx.send(event(stranger(), CALL, 6, true)).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), attachment.from_node.pop()).await.unwrap().map(|m| m.seq),
        Some(5)
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(attachment.from_node.try_pop().is_none(), "the stranger's frame went nowhere");

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(3), worker).await.unwrap().unwrap();
    assert_eq!(f.router.routed_calls(), 0);
    assert_eq!(attachment.from_node.pop().await, None, "shutdown ends every route");
}

#[tokio::test]
async fn production_admission_requires_paid_live_blocks_and_fails_closed() {
    use konsensus_core::payloads::call::{CallEntry, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let admission = super::PaidCallAdmission::new(store.clone());
    let live = CallEntry { side: Side::Caller, phase: Phase::Live, deadline_ms: 100_000,
        pending: None, paid_until_ms: None, next_block_seq: 0, end_reason: None, unpaid_notice_used: false };
    assert!(!admission.call_media_admitted(&peer(), CALL, 1_000).await);
    store.call_put(&peer(), CALL, &live).await.unwrap();
    assert!(!admission.call_media_admitted(&peer(), CALL, 1_000).await, "answered is not paid");
    let paid = CallEntry { paid_until_ms: Some(61_000), next_block_seq: 1, ..live };
    store.call_put(&peer(), CALL, &paid).await.unwrap();
    assert!(admission.call_media_admitted(&peer(), CALL, 71_000).await);
    assert!(!admission.call_media_admitted(&peer(), CALL, 71_001).await);
    assert!(!admission.call_media_admitted(&stranger(), CALL, 2_000).await);
    for phase in [Phase::Reserved, Phase::Ringing, Phase::Ended] {
        store.call_put(&peer(), CALL, &CallEntry { phase, ..paid.clone() }).await.unwrap();
        assert!(!admission.call_media_admitted(&peer(), CALL, 2_000).await);
    }
    sqlx::query("DROP TABLE call_state").execute(store.pool()).await.unwrap();
    assert!(!admission.call_media_admitted(&peer(), CALL, 2_000).await, "storage errors fail closed");
}

#[tokio::test]
async fn idle_route_is_released_without_another_media_packet() {
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL).await.unwrap();
    f.admission.revoke(peer(), CALL);
    tokio::time::timeout(Duration::from_millis(1600), async {
        while f.router.routed_calls() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("idle call was never rechecked");
    assert!(attachment.from_node.is_closed() && attachment.to_node.is_closed());
}

#[tokio::test]
async fn ended_call_releases_even_while_peer_write_is_stalled() {
    let f = fixture();
    f.link.stalled.store(true, std::sync::atomic::Ordering::SeqCst);
    let attachment = f.router.attach(&peer(), CALL).await.unwrap();
    attachment.to_node.push(MediaFrame { seq: 1, payload: vec![1] }).unwrap();
    tokio::time::timeout(Duration::from_secs(1), f.link.sending.notified()).await.unwrap();
    f.admission.revoke(peer(), CALL);
    tokio::time::timeout(Duration::from_millis(1600), async {
        while f.router.routed_calls() != 0 { tokio::time::sleep(Duration::from_millis(10)).await; }
    }).await.expect("peer write blocked admission recheck");
    assert!(attachment.from_node.is_closed() && attachment.to_node.is_closed());
}

#[tokio::test]
async fn idle_paid_route_expires_after_grace_without_media() {
    use konsensus_core::payloads::call::{CallEntry, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = super::now_ms();
    store.call_put(&peer(), CALL, &CallEntry {
        side: Side::Caller, phase: Phase::Live, deadline_ms: now + 200,
        pending: None, paid_until_ms: Some(now - 9_800), next_block_seq: 1, end_reason: None, unpaid_notice_used: false,
    }).await.unwrap();
    let f = fixture();
    let router = CallMediaRouter::new(f.link, Arc::new(super::PaidCallAdmission::new(store)));
    let attachment = router.attach(&peer(), CALL).await.unwrap();
    tokio::time::timeout(Duration::from_millis(1600), async {
        while router.routed_calls() != 0 { tokio::time::sleep(Duration::from_millis(10)).await; }
    }).await.expect("paid expiry was not rechecked without media");
    assert!(attachment.from_node.is_closed() && attachment.to_node.is_closed());
}
