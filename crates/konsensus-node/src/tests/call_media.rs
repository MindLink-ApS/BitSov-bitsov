//! Router unit tests (M6 N2): refusals, rate cap, drop-oldest queues and the
//! app → peer pump, over a recording link and a stub admission.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use konsensus_api::call_media::{
    AttachRefusal, CallMediaPort, MediaFrame, MediaLimits, BULK_QUEUE_FRAMES, MEDIA_QUEUE_FRAMES, PRIORITY_PACKET_BYTES,
    RESERVED_PRIORITY_BYTES, RESERVED_PRIORITY_FRAMES,
};
use konsensus_core::traits::transport::TransportError;
use konsensus_core::types::NodeId;
use konsensus_message::wire::MAX_CALL_MEDIA_BYTES;
use konsensus_message::{CallMediaEvent, Frame};

use super::{CallMediaAdmission, CallMediaRouter, MediaCap, MediaDrop, MediaLink, RateCap, MAX_BYTES_PER_SECOND, MAX_FRAMES_PER_SECOND};

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
    send_delay_ms: std::sync::atomic::AtomicU64,
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
        let delay = self.send_delay_ms.load(std::sync::atomic::Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
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

    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();
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
    let first = f.router.attach(&peer(), CALL, None).await.unwrap();
    let second = f.router.attach(&stranger(), CALL, None).await.expect("distinct peer, distinct route");
    assert_eq!(f.router.routed_calls(), 2);
    assert_eq!(f.router.attach(&stranger(), CALL, None).await.err(), Some(AttachRefusal::AlreadyAttached));
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
    let replacement = f.router.attach(&peer(), CALL, None).await.unwrap();
    drop(second);
    assert_eq!(f.router.routed_calls(), 1);
    assert!(!replacement.from_node.is_closed());
    drop(replacement);
    assert_eq!(f.router.routed_calls(), 0);
}

#[tokio::test]
async fn attach_requires_an_admitted_call_and_a_media_capable_peer_once() {
    let f = fixture();
    assert_eq!(f.router.attach(&peer(), OTHER_CALL, None).await.err(), Some(AttachRefusal::NotAdmitted));
    assert_eq!(f.router.attach(&stranger(), CALL, None).await.err(), Some(AttachRefusal::NotAdmitted));
    assert_eq!(f.router.attach(&peer(), "not-a-call-id", None).await.err(), Some(AttachRefusal::NotAdmitted));

    // Admitted, but the peer is not connected (or runs an older node).
    f.admission.admit(stranger(), CALL);
    assert_eq!(f.router.attach(&stranger(), CALL, None).await.err(), Some(AttachRefusal::Unavailable));

    let first = f.router.attach(&peer(), CALL, None).await.unwrap();
    assert_eq!(first.peer, peer());
    assert_eq!(f.router.attach(&peer(), CALL, None).await.err(), Some(AttachRefusal::AlreadyAttached));
    assert_eq!(f.router.routed_calls(), 1);

    // Dropping the socket's attachment frees the call for the next socket.
    drop(first);
    assert_eq!(f.router.routed_calls(), 0);
    let second = f.router.attach(&peer(), CALL, None).await.unwrap();
    assert!(!second.from_node.is_closed());
}

#[tokio::test]
async fn media_stops_once_the_call_is_no_longer_admitted() {
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();
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

#[test]
fn rate_cap_bounds_frames_and_bytes_per_second() {
    let start = Instant::now();
    let mut cap = RateCap::media(start);
    for _ in 0..MAX_FRAMES_PER_SECOND {
        assert!(cap.admit(start, 160));
    }
    assert!(!cap.admit(start, 160), "frame cap");
    assert!(!cap.admit(start + Duration::from_millis(999), 160), "still the same window");
    assert!(cap.admit(start + Duration::from_secs(1), 160), "a new window");

    let mut cap = RateCap::media(start);
    let per_frame = MAX_CALL_MEDIA_BYTES;
    let fits = (MAX_BYTES_PER_SECOND as usize) / per_frame;
    for _ in 0..fits {
        assert!(cap.admit(start, per_frame));
    }
    assert!(!cap.admit(start, per_frame), "byte cap");
    assert!(!cap.admit(start, 1), "the byte budget is spent to the byte");
    assert!(cap.admit(start + Duration::from_secs(1), per_frame));

    // Under the byte cap, a packet that would cross it is refused but a
    // smaller one still fits; the refusal counted nothing.
    let mut cap = RateCap::new(10, 1000, start);
    assert!(cap.admit(start, 900));
    assert!(!cap.admit(start, 200));
    assert!(cap.admit(start, 100));
}

const TIER: MediaLimits = MediaLimits { max_frames_per_second: 160, max_bytes_per_second: 256 * 1024, drop_bulk_over_share: true };

#[test]
fn media_cap_with_only_audio_is_the_rate_cap_it_always_was() {
    let start = Instant::now();
    let mut cap = MediaCap::new(MediaLimits::default(), start);
    let mut old = RateCap::media(start);
    // Sizes every audio packet can have, in a pattern that crosses both caps
    // and a window boundary.
    for i in 0..1000u64 {
        let now = start + Duration::from_millis(i * 3);
        let size = [28, 58, 97, 161, 512][i as usize % 5];
        assert_eq!(cap.admit(now, size), old.admit(now, size), "packet {i}");
    }
}

#[test]
fn media_cap_keeps_the_reservation_free_whatever_order_packets_arrive_in() {
    let start = Instant::now();
    let limits = MediaLimits::default();
    let mut cap = MediaCap::new(limits, start);
    let mut bulk = 0u64;
    while cap.admit(start, MAX_CALL_MEDIA_BYTES) {
        bulk += 1;
    }
    assert_eq!(bulk, limits.bulk_bytes_per_second() / MAX_CALL_MEDIA_BYTES as u64);
    assert!(bulk * MAX_CALL_MEDIA_BYTES as u64 + RESERVED_PRIORITY_BYTES <= MAX_BYTES_PER_SECOND);
    // A burst at the start of the window leaves a full second of audio.
    for packet in 0..50 {
        assert!(cap.admit(start + Duration::from_millis(packet * 20), 161), "audio packet {packet}");
    }
    assert!(!cap.admit(start + Duration::from_millis(999), MAX_CALL_MEDIA_BYTES), "bulk stays refused");

    // Small bulk packets hit the frame share instead of the byte share.
    let mut cap = MediaCap::new(limits, start);
    let mut bulk = 0;
    while cap.admit(start, PRIORITY_PACKET_BYTES + 1) {
        bulk += 1;
    }
    assert_eq!(bulk, MAX_FRAMES_PER_SECOND - RESERVED_PRIORITY_FRAMES);
    for packet in 0..RESERVED_PRIORITY_FRAMES {
        assert!(cap.admit(start, 161), "audio packet {packet}");
    }
    assert!(!cap.admit(start, 161), "the whole frame cap still holds");

    // A new window gives the bulk share back, and a refusal counted nothing.
    assert!(cap.admit(start + Duration::from_secs(1), MAX_CALL_MEDIA_BYTES));
}

#[test]
fn media_cap_at_the_higher_limits_carries_what_the_default_refuses() {
    let start = Instant::now();
    let mut wide = MediaCap::new(TIER, start);
    let mut narrow = MediaCap::new(MediaLimits::default(), start);
    let (mut wide_bulk, mut narrow_bulk) = (0, 0);
    for _ in 0..100 {
        wide_bulk += u32::from(wide.admit(start, MAX_CALL_MEDIA_BYTES));
        narrow_bulk += u32::from(narrow.admit(start, MAX_CALL_MEDIA_BYTES));
    }
    assert_eq!(wide_bulk, 61, "(256 - 12) KiB in 4 KiB packets");
    assert_eq!(narrow_bulk, 13, "(64 - 12) KiB in 4 KiB packets");
    for _ in 0..50 {
        assert!(wide.admit(start, 161));
    }
}

fn sized_event(seq: u32, len: usize) -> CallMediaEvent {
    CallMediaEvent { peer_id: peer(), call_id: CALL.to_string(), seq, data: vec![seq as u8; len], privileged: true }
}

#[tokio::test]
async fn inbound_bulk_cannot_spend_the_budget_audio_needs() {
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();
    let mut refused = 0;
    for seq in 0..40 {
        if f.router.inbound(sized_event(seq, MAX_CALL_MEDIA_BYTES)).await == Err(MediaDrop::RateCapped) {
            refused += 1;
        }
    }
    assert!(refused > 0, "more than the bulk share was offered");
    // A second of audio, with the socket taking it at the rate it comes.
    let mut audio = Vec::new();
    for seq in 100..150 {
        f.router.inbound(sized_event(seq, 161)).await.unwrap_or_else(|why| panic!("audio {seq}: {why:?}"));
        audio.push(attachment.from_node.try_pop().unwrap().seq);
    }
    // The socket got the audio ahead of the bulk backlog and the queue evicted none of it.
    assert_eq!(audio, (100..150).collect::<Vec<u32>>());
    assert_eq!(attachment.from_node.priority_dropped(), 0);
    let bulk: Vec<u32> = std::iter::from_fn(|| attachment.from_node.try_pop()).map(|p| p.seq).collect();
    assert!(!bulk.is_empty() && bulk.len() <= BULK_QUEUE_FRAMES);
}

#[tokio::test]
async fn outbound_audio_goes_ahead_of_queued_bulk_and_keeps_its_budget() {
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();
    // Hold the pump in one send so a backlog forms behind it.
    f.link.stalled.store(true, std::sync::atomic::Ordering::SeqCst);
    let sending = f.link.sending.notified();
    attachment.to_node.push(MediaFrame { seq: 0, payload: vec![0; 160] }).unwrap();
    tokio::time::timeout(Duration::from_secs(3), sending).await.expect("pump is sending");
    for seq in 1000..1040 {
        attachment.to_node.push(MediaFrame { seq, payload: vec![1; MAX_CALL_MEDIA_BYTES] }).unwrap();
    }
    for seq in 1..=(MEDIA_QUEUE_FRAMES as u32) {
        attachment.to_node.push(MediaFrame { seq, payload: vec![2; 161] }).unwrap();
    }
    assert_eq!(attachment.to_node.priority_dropped(), 0, "bulk evicted no audio");
    assert_eq!(attachment.to_node.len(), MEDIA_QUEUE_FRAMES + BULK_QUEUE_FRAMES);
    assert!(attachment.to_node.dropped() > 0);
    // The stalled send itself never returns here, so check the order the
    // queue will hand out: all audio, then the newest bulk.
    let order: Vec<u32> = std::iter::from_fn(|| attachment.to_node.try_pop()).map(|p| p.seq).collect();
    assert_eq!(&order[..MEDIA_QUEUE_FRAMES], (1..=MEDIA_QUEUE_FRAMES as u32).collect::<Vec<_>>().as_slice());
    assert_eq!(order[MEDIA_QUEUE_FRAMES..].len(), BULK_QUEUE_FRAMES);
    assert_eq!(*order.last().unwrap(), 1039);
}

#[tokio::test]
async fn configured_limits_reach_routes_in_both_directions_and_the_socket() {
    let link = Arc::new(RecordingLink::default());
    link.connected.lock().unwrap().insert(peer());
    let admission = Arc::new(StubAdmission::default());
    admission.admit(peer(), CALL);
    let router = CallMediaRouter::with_limits(
        Arc::clone(&link) as Arc<dyn MediaLink>,
        Arc::clone(&admission) as Arc<dyn CallMediaAdmission>,
        TIER,
    );
    let attachment = router.attach(&peer(), CALL, None).await.unwrap();
    assert_eq!(attachment.limits, TIER, "the socket's budget is the route's");

    // Inbound: 150 small packets pass where the default stops at 100.
    for seq in 0..150 {
        router.inbound(sized_event(seq, 100)).await.unwrap_or_else(|why| panic!("{seq}: {why:?}"));
        attachment.from_node.try_pop();
    }
    assert_eq!(router.dropped(MediaDrop::RateCapped), 0);

    // Outbound: the same count reaches the peer.
    for seq in 0..150 {
        attachment.to_node.push(MediaFrame { seq, payload: vec![3; 100] }).unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while link.sent.lock().unwrap().len() <= seq as usize {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("forwarded");
    }
    assert_eq!(router.dropped(MediaDrop::RateCapped), 0);
}

#[tokio::test]
async fn the_default_router_keeps_the_fixed_limits() {
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();
    assert_eq!(attachment.limits, MediaLimits::default());
}

#[tokio::test]
async fn inbound_frames_over_the_cap_are_dropped() {
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();
    for seq in 0..MAX_FRAMES_PER_SECOND {
        f.router.inbound(event(peer(), CALL, seq, true)).await.unwrap();
    }
    assert_eq!(f.router.inbound(event(peer(), CALL, 999, true)).await, Err(MediaDrop::RateCapped));
    assert_eq!(f.router.dropped(MediaDrop::RateCapped), 1);
    // The queue kept the newest of what was admitted, never the capped one.
    let newest = std::iter::from_fn(|| attachment.from_node.try_pop()).last().unwrap();
    assert_eq!(newest.seq, MAX_FRAMES_PER_SECOND - 1);
}

#[tokio::test]
async fn to_app_queue_drops_the_oldest_audio_rather_than_block() {
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();
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
    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();
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
    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();

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
    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();
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
    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();
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
    let attachment = router.attach(&peer(), CALL, None).await.unwrap();
    tokio::time::timeout(Duration::from_millis(1600), async {
        while router.routed_calls() != 0 { tokio::time::sleep(Duration::from_millis(10)).await; }
    }).await.expect("paid expiry was not rechecked without media");
    assert!(attachment.from_node.is_closed() && attachment.to_node.is_closed());
}

/// Captures this thread's log output; the runtime in these tests is
/// single-threaded, so the router's tasks log into it too.
#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn capture_logs() -> (LogBuf, tracing::subscriber::DefaultGuard) {
    let buf = LogBuf::default();
    let sub = tracing_subscriber::fmt().with_writer(buf.clone()).with_ansi(false).with_max_level(tracing::Level::INFO).finish();
    let guard = tracing::subscriber::set_default(sub);
    (buf, guard)
}

fn summaries(buf: &LogBuf) -> Vec<String> {
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    text.lines().filter(|l| l.contains("call media route summary")).map(str::to_string).collect()
}

fn field(line: &str, name: &str) -> String {
    let key = format!(" {name}=");
    let rest = &line[line.find(&key).unwrap_or_else(|| panic!("{name} in {line}")) + key.len()..];
    rest.split(' ').next().unwrap().trim_matches('"').to_string()
}

#[tokio::test]
async fn route_summary_counts_inbound_and_ends_detached() {
    let (logs, _guard) = capture_logs();
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();
    let total = MAX_FRAMES_PER_SECOND + 3;
    for seq in 0..total {
        let _ = f.router.inbound(event(peer(), CALL, seq, true)).await;
    }
    assert!(summaries(&logs).is_empty(), "nothing is logged until the route ends");
    drop(attachment);

    let lines = summaries(&logs);
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = &lines[0];
    assert_eq!(field(line, "call_id"), CALL);
    assert_eq!(field(line, "in_forwarded"), MAX_FRAMES_PER_SECOND.to_string());
    assert_eq!(field(line, "in_rate_capped"), "3");
    assert_eq!(field(line, "in_evicted"), (MAX_FRAMES_PER_SECOND as usize - MEDIA_QUEUE_FRAMES).to_string());
    assert_eq!(field(line, "in_not_admitted"), "0");
    assert_eq!(field(line, "out_forwarded"), "0");
    assert_eq!(field(line, "out_evicted"), "0");
    assert_eq!(field(line, "end_reason"), "detached");
    // Counts only: no packet bytes in the line.
    assert!(!line.contains("payload") && !line.contains("data="));
}

#[tokio::test]
async fn route_summary_counts_outbound_and_writer_wait() {
    let (logs, _guard) = capture_logs();
    let f = fixture();
    f.link.send_delay_ms.store(25, std::sync::atomic::Ordering::SeqCst);
    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();
    for seq in 0..4u32 {
        attachment.to_node.push(MediaFrame { seq, payload: vec![0xAB; 50] }).unwrap();
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while f.link.sent.lock().unwrap().len() < 4 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("four frames forwarded");
    drop(attachment);

    let lines = summaries(&logs);
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = &lines[0];
    assert_eq!(field(line, "out_forwarded"), "4");
    assert_eq!(field(line, "out_rate_capped"), "0");
    assert_eq!(field(line, "in_forwarded"), "0");
    let wait_us: u64 = field(line, "longest_writer_wait_us").parse().unwrap();
    assert!(wait_us >= 25_000, "{wait_us}");
}

#[tokio::test]
async fn route_summary_counts_outbound_rate_cap() {
    let (logs, _guard) = capture_logs();
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();
    let total = MAX_FRAMES_PER_SECOND + 5;
    for seq in 0..total {
        attachment.to_node.push(MediaFrame { seq, payload: vec![1; 10] }).unwrap();
        // Let the pump take each packet so the queue never evicts.
        while !attachment.to_node.is_empty() {
            tokio::task::yield_now().await;
        }
    }
    drop(attachment);
    let lines = summaries(&logs);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(field(&lines[0], "out_forwarded"), MAX_FRAMES_PER_SECOND.to_string());
    assert_eq!(field(&lines[0], "out_rate_capped"), "5");
    assert_eq!(field(&lines[0], "out_evicted"), "0");
}

#[tokio::test]
async fn route_summary_is_logged_once_and_names_admission_end() {
    let (logs, _guard) = capture_logs();
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL, None).await.unwrap();
    f.router.inbound(event(peer(), CALL, 1, true)).await.unwrap();
    f.admission.revoke(peer(), CALL);
    tokio::time::timeout(Duration::from_millis(1600), async {
        while f.router.routed_calls() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("route released");
    // Detaching afterwards ends nothing new and logs nothing more.
    drop(attachment);

    let lines = summaries(&logs);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(field(&lines[0], "end_reason"), "not_admitted");
    assert_eq!(field(&lines[0], "in_forwarded"), "1");
}

#[tokio::test(start_paused = true)]
async fn stale_attachment_gives_way_and_its_late_drop_preserves_the_replacement() {
    let f = fixture();
    let client = konsensus_api::auth::PairingBinding {
        client_id: "call-client".into(), epoch: 1, fingerprint: "identity".into(),
    };
    let other = konsensus_api::auth::PairingBinding { client_id: "other-client".into(), ..client.clone() };
    let old = f.router.attach(&peer(), CALL, Some(&client)).await.unwrap();
    tokio::time::advance(Duration::from_secs(16)).await;
    assert_eq!(f.router.attach(&peer(), CALL, Some(&other)).await.err(), Some(AttachRefusal::AlreadyAttached));
    assert!(!old.to_node.is_closed(), "another client must never retire this route");
    let replacement = f.router.attach(&peer(), CALL, Some(&client)).await
        .expect("a stale socket must give way to its client's reattach");
    assert!(old.to_node.is_closed() && old.from_node.is_closed());
    drop(old);
    assert_eq!(f.router.routed_calls(), 1);
    f.router.inbound(event(peer(), CALL, 90, true)).await.unwrap();
    assert_eq!(replacement.from_node.pop().await.unwrap().seq, 90);
}

#[tokio::test(start_paused = true)]
async fn received_pong_or_read_keeps_an_attachment_live() {
    let f = fixture();
    let first = f.router.attach(&peer(), CALL, None).await.unwrap();
    tokio::time::advance(Duration::from_secs(10)).await;
    first.activity.received();
    tokio::time::advance(Duration::from_secs(6)).await;
    assert_eq!(f.router.attach(&peer(), CALL, None).await.err(), Some(AttachRefusal::AlreadyAttached));
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(f.router.attach(&peer(), CALL, None).await.is_ok());
}


#[tokio::test]
async fn callee_detach_ends_the_call_and_preserves_paid_evidence() {
    use konsensus_core::payloads::call::{self as rules, CallEntry, HangupReason, Pending, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = super::now_ms();
    let paid = CallEntry {
        side: Side::Callee, phase: Phase::Live, deadline_ms: now + 70_000,
        pending: Some(Pending { operation_id: "pending-signal".into(), kind: 402, request_hash: "request".into() }),
        paid_until_ms: Some(now + 60_000), next_block_seq: 1,
        end_reason: None, unpaid_notice_used: false,
    };
    store.call_put(&peer(), CALL, &paid).await.unwrap();
    let f = fixture();
    let router = CallMediaRouter::new(f.link, Arc::new(super::PaidCallAdmission::new(store.clone())));
    let attachment = router.attach(&peer(), CALL, None).await.unwrap();
    drop(attachment);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if store.call_get(&peer(), CALL).await.unwrap().unwrap().phase == Phase::Ended { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("callee detach must end durable admission");
    let ended = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(ended.end_reason, Some(HangupReason::Hangup));
    assert_eq!(ended.pending, paid.pending, "pending settlement evidence remains");
    assert_eq!(ended.paid_until_ms, paid.paid_until_ms);
    assert_eq!(ended.next_block_seq, 1);
    assert!(ended.deadline_ms >= now + rules::TOMBSTONE_MS);
    assert!(rules::validate_block_invoice(&ended, 1, now + 40_000).is_err());
    assert!(rules::receive_block(Some(ended), 1, now + 40_000).is_err(), "late payment cannot reopen media");
    assert_eq!(router.attach(&peer(), CALL, None).await.err(), Some(AttachRefusal::NotAdmitted));
}

#[tokio::test]
async fn caller_detach_keeps_the_existing_paid_deadline() {
    use konsensus_core::payloads::call::{CallEntry, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = super::now_ms();
    let paid = CallEntry {
        side: Side::Caller, phase: Phase::Live, deadline_ms: now + 70_000,
        pending: None, paid_until_ms: Some(now + 60_000), next_block_seq: 1,
        end_reason: None, unpaid_notice_used: false,
    };
    store.call_put(&peer(), CALL, &paid).await.unwrap();
    let f = fixture();
    let router = CallMediaRouter::new(f.link, Arc::new(super::PaidCallAdmission::new(store.clone())));
    drop(router.attach(&peer(), CALL, None).await.unwrap());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap().unwrap(), paid);
}


#[tokio::test]
async fn callee_detach_after_unpaid_expiry_prevents_late_resume() {
    use konsensus_core::payloads::call::{self as rules, CallEntry, HangupReason, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = super::now_ms();
    let paid = CallEntry {
        side: Side::Callee, phase: Phase::Live, deadline_ms: now + 70_000,
        pending: None, paid_until_ms: Some(now + 60_000), next_block_seq: 1,
        end_reason: None, unpaid_notice_used: false,
    };
    store.call_put(&peer(), CALL, &paid).await.unwrap();
    let f = fixture();
    let router = CallMediaRouter::new(f.link, Arc::new(super::PaidCallAdmission::new(store.clone())));
    let attachment = router.attach(&peer(), CALL, None).await.unwrap();
    konsensus_api::calls::expire_calls(store.as_ref(), paid.deadline_ms + 1).await.unwrap();
    let expired = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(expired.end_reason, Some(HangupReason::Unpaid));
    drop(attachment);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let ended = store.call_get(&peer(), CALL).await.unwrap().unwrap();
            if rules::receive_block(Some(ended), 1, paid.deadline_ms + 2).is_err() { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("a detached expired callee must not resume on late settlement");
    let ended = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(ended.end_reason, Some(HangupReason::Unpaid));
    assert_eq!(ended.deadline_ms, expired.deadline_ms, "retain the longer tombstone");
    assert_eq!(ended.paid_until_ms, Some(0), "resume is durably closed");
}

#[tokio::test]
async fn old_callee_attachment_drop_keeps_its_replacement_live() {
    use konsensus_core::payloads::call::{CallEntry, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = super::now_ms();
    let paid = CallEntry {
        side: Side::Callee, phase: Phase::Live, deadline_ms: now + 70_000,
        pending: None, paid_until_ms: Some(now + 60_000), next_block_seq: 1,
        end_reason: None, unpaid_notice_used: false,
    };
    store.call_put(&peer(), CALL, &paid).await.unwrap();
    let f = fixture();
    let router = CallMediaRouter::new(f.link, Arc::new(super::PaidCallAdmission::new(store.clone())));
    let old = router.attach(&peer(), CALL, None).await.unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(16)).await;
    tokio::time::resume();
    let replacement = router.attach(&peer(), CALL, None).await.unwrap();
    drop(old);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap().unwrap(), paid);
    assert!(!replacement.to_node.is_closed());
    assert_eq!(router.routed_calls(), 1);
}


#[tokio::test]
async fn callee_detach_retries_a_failed_state_write() {
    use konsensus_core::payloads::call::{CallEntry, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let (logs, _guard) = capture_logs();
    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = super::now_ms();
    store.call_put(&peer(), CALL, &CallEntry {
        side: Side::Callee, phase: Phase::Live, deadline_ms: now + 70_000,
        pending: None, paid_until_ms: Some(now + 60_000), next_block_seq: 1,
        end_reason: None, unpaid_notice_used: false,
    }).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_detach BEFORE UPDATE ON call_state BEGIN SELECT RAISE(ABORT, 'temporary write failure'); END")
        .execute(store.pool()).await.unwrap();
    let f = fixture();
    let router = CallMediaRouter::new(f.link, Arc::new(super::PaidCallAdmission::new(store.clone())));
    drop(router.attach(&peer(), CALL, None).await.unwrap());
    tokio::time::timeout(Duration::from_secs(2), async {
        while !String::from_utf8_lossy(&logs.0.lock().unwrap()).contains("call media detachment state update failed") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("the injected write failure was reached");
    sqlx::query("DROP TRIGGER fail_detach").execute(store.pool()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while store.call_get(&peer(), CALL).await.unwrap().unwrap().phase != Phase::Ended {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("detachment must survive a temporary storage failure");
}

#[tokio::test]
async fn reconnect_before_detach_retry_keeps_the_replacement_live() {
    use konsensus_core::payloads::call::{CallEntry, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let (logs, _guard) = capture_logs();
    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = super::now_ms();
    let paid = CallEntry {
        side: Side::Callee, phase: Phase::Live, deadline_ms: now + 70_000,
        pending: None, paid_until_ms: Some(now + 60_000), next_block_seq: 1,
        end_reason: None, unpaid_notice_used: false,
    };
    store.call_put(&peer(), CALL, &paid).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_detach BEFORE UPDATE ON call_state BEGIN SELECT RAISE(ABORT, 'temporary write failure'); END")
        .execute(store.pool()).await.unwrap();
    let f = fixture();
    let router = CallMediaRouter::new(f.link.clone(), Arc::new(super::PaidCallAdmission::new(store.clone())));
    drop(router.attach(&peer(), CALL, None).await.unwrap());
    tokio::time::timeout(Duration::from_secs(2), async {
        while !String::from_utf8_lossy(&logs.0.lock().unwrap()).contains("call media detachment state update failed") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("the old attachment's write failed before reconnect");
    let replacement = router.attach(&peer(), CALL, None).await.unwrap();
    sqlx::query("DROP TRIGGER fail_detach").execute(store.pool()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap().unwrap(), paid,
        "an old attachment's storage retry must not end its replacement");
    assert!(!replacement.to_node.is_closed() && !replacement.from_node.is_closed());
    router.inbound(event(peer(), CALL, 90, true)).await.unwrap();
    assert_eq!(replacement.from_node.pop().await.unwrap().seq, 90);
    replacement.to_node.push(MediaFrame { seq: 91, payload: vec![1; 160] }).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while f.link.sent_frames().is_empty() { tokio::task::yield_now().await; }
    }).await.expect("replacement media must still reach the peer");
}

#[tokio::test]
async fn drop_after_not_admitted_prevents_late_resume() {
    use konsensus_core::payloads::call::{self as rules, CallEntry, HangupReason, Pending, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = super::now_ms();
    let paid = CallEntry {
        side: Side::Callee, phase: Phase::Live, deadline_ms: now + 70_000,
        pending: Some(Pending { operation_id: "pending-signal".into(), kind: 403, request_hash: "request".into() }),
        paid_until_ms: Some(now + 60_000), next_block_seq: 1,
        end_reason: None, unpaid_notice_used: false,
    };
    store.call_put(&peer(), CALL, &paid).await.unwrap();
    let f = fixture();
    let router = CallMediaRouter::new(f.link, Arc::new(super::PaidCallAdmission::new(store.clone())));
    let attachment = router.attach(&peer(), CALL, None).await.unwrap();
    konsensus_api::calls::expire_calls(store.as_ref(), paid.deadline_ms + 1).await.unwrap();
    let expired = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(expired.end_reason, Some(HangupReason::Unpaid));
    tokio::time::timeout(Duration::from_secs(2), async {
        while router.routed_calls() != 0 { tokio::time::sleep(Duration::from_millis(10)).await; }
    }).await.expect("the admission monitor removes the route before socket drop");
    assert!(attachment.to_node.is_closed() && attachment.from_node.is_closed());
    drop(attachment);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let ended = store.call_get(&peer(), CALL).await.unwrap().unwrap();
            if rules::receive_block(Some(ended), 1, paid.deadline_ms + 2).is_err() { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("socket drop after admission loss must still end the resume window");
    let ended = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert!(rules::receive_block(Some(ended.clone()), 1, paid.deadline_ms + 2).is_err());
    assert_eq!(ended.pending, paid.pending);
    assert_eq!(ended.paid_until_ms, Some(0), "resume is durably closed");
    assert_eq!(ended.next_block_seq, paid.next_block_seq);
    assert_eq!(ended.end_reason, Some(HangupReason::Unpaid));
    assert_eq!(ended.deadline_ms, expired.deadline_ms);
}

async fn transient_read_error_then_socket_drop(overdue: bool) {
    use konsensus_api::calls::MediaDetach;
    use konsensus_core::payloads::call::{self as rules, CallEntry, Pending, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};

    struct ObservedAdmission {
        paid: super::PaidCallAdmission,
        completed: tokio::sync::Semaphore,
    }
    #[async_trait]
    impl CallMediaAdmission for ObservedAdmission {
        async fn call_media_admitted(&self, peer: &NodeId, call_id: &str, now: u64) -> bool {
            self.paid.call_media_admitted(peer, call_id, now).await
        }
        async fn media_detached(&self, peer: &NodeId, call_id: &str, detach: MediaDetach) {
            self.paid.media_detached(peer, call_id, detach).await;
            self.completed.add_permits(1);
        }
    }

    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = super::now_ms();
    let mut paid = CallEntry {
        side: Side::Callee, phase: Phase::Live, deadline_ms: now + 70_000,
        pending: Some(Pending { operation_id: "pending-signal".into(), kind: 403, request_hash: "request".into() }),
        paid_until_ms: Some(now + 60_000), next_block_seq: 1,
        end_reason: None, unpaid_notice_used: false,
    };
    store.call_put(&peer(), CALL, &paid).await.unwrap();
    let admission = Arc::new(ObservedAdmission {
        paid: super::PaidCallAdmission::new(store.clone()), completed: tokio::sync::Semaphore::new(0),
    });
    let f = fixture();
    let router = CallMediaRouter::new(f.link, admission.clone());
    let attachment = router.attach(&peer(), CALL, None).await.unwrap();
    if overdue {
        paid.deadline_ms = now - 1;
        paid.paid_until_ms = Some(now - 10_001);
        store.call_put(&peer(), CALL, &paid).await.unwrap();
    }
    sqlx::query("ALTER TABLE call_state RENAME TO unavailable_call_state")
        .execute(store.pool()).await.unwrap();
    assert!(store.call_get(&peer(), CALL).await.is_err());
    tokio::time::timeout(Duration::from_secs(2), attachment.from_node.closed())
        .await.expect("the admission read failure closes the media queues");
    assert_eq!(router.routed_calls(), 0);
    assert!(attachment.to_node.is_closed());
    // Match the media handler releasing its attachment when a queue closes.
    drop(attachment);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    sqlx::query("ALTER TABLE unavailable_call_state RENAME TO call_state")
        .execute(store.pool()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(6), admission.completed.acquire_many(2))
        .await.expect("both teardown notifications finish after storage recovers")
        .unwrap().forget();
    let stored = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    if overdue {
        let mut closed = paid;
        closed.paid_until_ms = Some(0);
        assert_eq!(stored, closed, "overdue socket cleanup only closes resume");
        assert_eq!(rules::receive_block(Some(stored), 1, super::now_ms()), Err(rules::CallRefusal::UnknownCall),
            "overdue socket cleanup keeps settlement closed");
    } else {
        assert_eq!(stored, paid, "read recovery and socket cleanup preserve the paid live row");
        assert!(stored.media_admitted(super::now_ms()));
        let replacement = router.attach(&peer(), CALL, None).await.unwrap();
        assert!(!replacement.to_node.is_closed() && !replacement.from_node.is_closed());
    }
}

#[tokio::test]
async fn admission_read_error_and_socket_drop_preserve_a_paid_live_callee() {
    transient_read_error_then_socket_drop(false).await;
}

#[tokio::test]
async fn admission_read_error_and_socket_drop_mark_an_overdue_live_callee() {
    transient_read_error_then_socket_drop(true).await;
}

#[tokio::test]
async fn callee_detach_stops_retrying_a_persistent_state_write_failure() {
    use konsensus_core::payloads::call::{CallEntry, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let (logs, _guard) = capture_logs();
    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = super::now_ms();
    let paid = CallEntry {
        side: Side::Callee, phase: Phase::Live, deadline_ms: now + 70_000,
        pending: None, paid_until_ms: Some(now + 60_000), next_block_seq: 1,
        end_reason: None, unpaid_notice_used: false,
    };
    store.call_put(&peer(), CALL, &paid).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_detach BEFORE UPDATE ON call_state BEGIN SELECT RAISE(ABORT, 'persistent write failure'); END")
        .execute(store.pool()).await.unwrap();
    let f = fixture();
    let router = CallMediaRouter::new(f.link, Arc::new(super::PaidCallAdmission::new(store.clone())));
    drop(router.attach(&peer(), CALL, None).await.unwrap());
    tokio::time::sleep(Duration::from_millis(6500)).await;
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert_eq!(text.matches("call media detachment state update failed").count(), 5,
        "persistent failures must stop after five attempts");
    assert!(text.contains("call media detachment retries exhausted"));
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap().unwrap(), paid);
}

#[tokio::test]
async fn reconnect_waits_for_an_in_progress_detach_write() {
    use konsensus_api::calls::{self, MediaDetach};
    use konsensus_core::payloads::call::{CallEntry, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};

    struct ObservedAdmission {
        paid: super::PaidCallAdmission,
        detaching: tokio::sync::Notify,
    }
    #[async_trait]
    impl CallMediaAdmission for ObservedAdmission {
        async fn call_media_admitted(&self, peer: &NodeId, call_id: &str, now: u64) -> bool {
            self.paid.call_media_admitted(peer, call_id, now).await
        }
        async fn media_detached(&self, peer: &NodeId, call_id: &str, detach: MediaDetach) {
            self.detaching.notify_one();
            self.paid.media_detached(peer, call_id, detach).await;
        }
    }

    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = super::now_ms();
    store.call_put(&peer(), CALL, &CallEntry {
        side: Side::Callee, phase: Phase::Live, deadline_ms: now + 70_000,
        pending: None, paid_until_ms: Some(now + 60_000), next_block_seq: 1,
        end_reason: None, unpaid_notice_used: false,
    }).await.unwrap();
    let admission = Arc::new(ObservedAdmission {
        paid: super::PaidCallAdmission::new(store.clone()), detaching: tokio::sync::Notify::new(),
    });
    let f = fixture();
    let router = CallMediaRouter::new(f.link, admission.clone());
    let attachment = router.attach(&peer(), CALL, None).await.unwrap();
    let body = format!(r#"{{"call_id":"{CALL}","seq":1}}"#);
    // A paid-block decision holds the same call lock as teardown writes.
    let incoming = calls::prepare_incoming_block(store.as_ref(), &peer(), Some(&body), &[7; 32]).await.unwrap();
    drop(attachment);
    admission.detaching.notified().await;
    let remote = peer();
    let mut reconnect = Box::pin(router.attach(&remote, CALL, None));
    let early = tokio::time::timeout(Duration::from_millis(50), &mut reconnect).await;
    drop(incoming);
    let result = match early {
        Ok(result) => result,
        Err(_) => tokio::time::timeout(Duration::from_secs(2), reconnect).await.unwrap(),
    };
    assert_eq!(result.err(), Some(AttachRefusal::NotAdmitted),
        "reconnect must recheck admission after the in-progress detach commits");
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap().unwrap().phase, Phase::Ended);
}


#[tokio::test]
async fn unpaid_media_cut_keeps_reason_and_refuses_settled_block() {
    use konsensus_core::payloads::call::{self as rules, CallEntry, HangupReason, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    for socket_drop in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("calls.db");
        let store = Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
        let now = super::now_ms();
        let paid = CallEntry {
            side: Side::Callee, phase: Phase::Live, deadline_ms: now + 70_000,
            pending: None, paid_until_ms: Some(now + 60_000), next_block_seq: 1,
            end_reason: None, unpaid_notice_used: false,
        };
        store.call_put(&peer(), CALL, &paid).await.unwrap();
        let f = fixture();
        let router = CallMediaRouter::new(f.link, Arc::new(super::PaidCallAdmission::new(store.clone())));
        let attachment = router.attach(&peer(), CALL, None).await.unwrap();
        let expired = CallEntry {
            phase: Phase::Ended, end_reason: Some(HangupReason::Unpaid),
            deadline_ms: now - 1 + rules::TOMBSTONE_MS, paid_until_ms: Some(now - 10_001),
            ..paid
        };
        assert!(rules::receive_block(Some(expired.clone()), 1, now).is_ok(), "fixture starts resumable");
        store.call_put(&peer(), CALL, &expired).await.unwrap();
        let mut attachment = Some(attachment);
        if socket_drop { drop(attachment.take()); }
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let ended = store.call_get(&peer(), CALL).await.unwrap().unwrap();
                if rules::receive_block(Some(ended), 1, super::now_ms()).is_err() { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("media removal must durably close the resume window");
        assert_eq!(router.routed_calls(), 0);
        let ended = store.call_get(&peer(), CALL).await.unwrap().unwrap();
        assert_eq!(ended.phase, Phase::Ended);
        assert_eq!(ended.end_reason, Some(HangupReason::Unpaid));
        assert_eq!(ended.paid_until_ms, Some(0));
        assert_eq!(ended.deadline_ms, expired.deadline_ms);
        assert_eq!(ended.next_block_seq, expired.next_block_seq);
        assert!(ended.replay_until_ms() >= now + rules::BURN_MIN_MS);
        let reopened = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
        let persisted = reopened.call_get(&peer(), CALL).await.unwrap().unwrap();
        assert_eq!(persisted, ended);
        assert!(rules::receive_block(Some(persisted.clone()), 1, super::now_ms()).is_err());
        assert!(rules::receive_block(Some(persisted), 1, now + rules::CALL_BLOCK_RESUME_MS + 1).is_err());
        assert_eq!(router.attach(&peer(), CALL, None).await.err(), Some(AttachRefusal::NotAdmitted));
        drop(attachment);
    }
}

#[tokio::test]
async fn unpaid_detach_preserves_minimum_burn_lifetime() {
    use konsensus_api::calls::{detach_callee_media, MediaDetach};
    use konsensus_core::payloads::call::{self as rules, CallEntry, HangupReason, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let store = SqliteStorage::in_memory().await.unwrap();
    let now = super::now_ms();
    let expired = CallEntry {
        side: Side::Callee, phase: Phase::Ended, deadline_ms: now + rules::TOMBSTONE_MS,
        pending: None, paid_until_ms: Some(now - rules::CALL_BLOCK_GRACE_MS), next_block_seq: 1,
        end_reason: Some(HangupReason::Unpaid), unpaid_notice_used: false,
    };
    store.call_put(&peer(), CALL, &expired).await.unwrap();
    let detach = MediaDetach {
        generation: Arc::new(tokio::sync::Mutex::new(1)), expected_generation: 1, only_unpaid: true, may_hangup_live: true,
    };
    detach_callee_media(&store, &peer(), CALL, now, &detach).await.unwrap();
    let before_minimum = now + rules::BURN_MIN_MS - 1;
    assert_eq!(store.call_evict_burned(Some(&peer()), rules::evictable_until(before_minimum), before_minimum, 1).await.unwrap(), 0,
        "media cut must not make the call id evictable before the minimum burn interval");
    let ended = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(ended.deadline_ms, expired.deadline_ms);
    assert_eq!(ended.end_reason, expired.end_reason);
    assert!(rules::receive_block(Some(ended), 1, now).is_err());
    let minimum = now + rules::BURN_MIN_MS;
    assert_eq!(store.call_evict_burned(Some(&peer()), rules::evictable_until(minimum), minimum, 1).await.unwrap(), 1);
}

#[tokio::test]
async fn socket_drop_after_paid_deadline_preserves_unpaid() {
    use konsensus_api::calls::{detach_callee_media, MediaDetach, MediaDetachOutcome};
    use konsensus_core::payloads::call::{self as rules, CallEntry, HangupReason, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = super::now_ms();
    let paid = CallEntry {
        side: Side::Callee, phase: Phase::Live, deadline_ms: now - 1,
        pending: None, paid_until_ms: Some(now - 10_001), next_block_seq: 1,
        end_reason: None, unpaid_notice_used: false,
    };
    store.call_put(&peer(), CALL, &paid).await.unwrap();
    let mut detach = MediaDetach {
        generation: Arc::new(tokio::sync::Mutex::new(1)), expected_generation: 1, only_unpaid: true, may_hangup_live: true,
    };
    let cut = now;
    assert_eq!(detach_callee_media(store.as_ref(), &peer(), CALL, cut, &detach).await.unwrap(), MediaDetachOutcome::PendingExpiry);
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap(), Some(paid.clone()),
        "admission loss alone never changes a stored Live row");
    detach.only_unpaid = false;
    assert_eq!(detach_callee_media(store.as_ref(), &peer(), CALL, cut, &detach).await.unwrap(), MediaDetachOutcome::PendingExpiry);
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap(), Some(CallEntry { paid_until_ms: Some(0), ..paid.clone() }),
        "ordinary socket close closes resume while leaving expiry and its notice to maintenance");
    let admission = super::PaidCallAdmission::new(store.clone());
    let remote = peer();
    let mut retry = tokio::spawn(async move { admission.media_detached(&remote, CALL, detach).await; });
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut retry).await.is_err(),
        "pending expiry must retain the bounded retry");
    assert_eq!(konsensus_api::calls::expire_calls(store.as_ref(), cut).await.unwrap(), vec![(peer(), CALL.to_string())],
        "maintenance must still return the terminal notice");
    tokio::time::timeout(Duration::from_secs(2), retry).await.expect("retry closes resume after maintenance")
        .expect("detach retry task completes");
    let ended = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(ended.end_reason, Some(HangupReason::Unpaid), "payment expiry precedes the socket close");
    assert_eq!(ended.phase, Phase::Ended);
    assert_eq!(ended.paid_until_ms, Some(0));
    assert_eq!(ended.deadline_ms, paid.deadline_ms + rules::TOMBSTONE_MS);
    assert_eq!(ended.next_block_seq, paid.next_block_seq);
    assert!(rules::receive_block(Some(ended), 1, cut).is_err());
}

// Recovery must remain possible after the bounded callback has returned.
#[tokio::test]
async fn durable_detach_replays_after_exhausted_writes() {
    durable_detach_recovery(false).await;
}

#[tokio::test]
async fn durable_detach_replays_after_restart() {
    durable_detach_recovery(true).await;
}

async fn durable_detach_recovery(restart: bool) {
    use konsensus_api::calls;
    use konsensus_core::payloads::call::{self as rules, CallEntry, HangupReason, Pending, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("detach.sqlite");
    let store = Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
    let now = super::now_ms();
    let paid = CallEntry {
        side: Side::Callee, phase: Phase::Live, deadline_ms: now + 70_000,
        pending: Some(Pending { operation_id: "signal".into(), kind: 403, request_hash: "binding".into() }),
        paid_until_ms: Some(now + 60_000), next_block_seq: 1,
        end_reason: None, unpaid_notice_used: false,
    };
    store.call_put(&peer(), CALL, &paid).await.unwrap();
    let mut operation = konsensus_storage::OutboxOperation::prepared("signal".into(), peer().to_hex(), 403, "binding".into());
    operation.state = "paying".into();
    assert!(store.insert_outbox_operation(&operation).await.unwrap());
    sqlx::query("CREATE TRIGGER unavailable_detach BEFORE UPDATE ON call_state BEGIN SELECT RAISE(ABORT, 'write unavailable'); END")
        .execute(store.pool()).await.unwrap();
    let f = fixture();
    let router = CallMediaRouter::new(f.link, Arc::new(super::PaidCallAdmission::new(store.clone())));
    drop(router.attach(&peer(), CALL, None).await.unwrap());
    tokio::time::sleep(Duration::from_millis(6500)).await;
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap().unwrap(), paid);
    sqlx::query("DROP TRIGGER unavailable_detach").execute(store.pool()).await.unwrap();
    drop(router);
    let store = if restart {
        drop(store);
        Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap())
    } else { store };
    if restart { calls::recover(store.as_ref()).await.unwrap(); }
    else { calls::expire_calls(store.as_ref(), now).await.unwrap(); }
    let ended = store.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(ended.phase, Phase::Ended, "replay must end detached media after storage recovers");
    assert_eq!(ended.end_reason, Some(HangupReason::Hangup));
    assert_eq!(ended.pending, paid.pending);
    assert_eq!(ended.next_block_seq, 1);
    assert_eq!(ended.paid_until_ms, paid.paid_until_ms);
    assert!(rules::receive_block(Some(ended.clone()), 1, now).is_err());
    calls::recover(store.as_ref()).await.unwrap();
    calls::expire_calls(store.as_ref(), now + 1000).await.unwrap();
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap().unwrap(), ended, "repeated replay must preserve all evidence");
}

#[tokio::test]
async fn durable_detach_startup_recovers_before_any_callback() {
    use konsensus_api::calls;
    use konsensus_core::payloads::call::{CallEntry, HangupReason, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("orphan.sqlite");
    let store = Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
    let now = super::now_ms();
    let paid = CallEntry {
        side: Side::Callee, phase: Phase::Live, deadline_ms: now + 70_000,
        pending: None, paid_until_ms: Some(now + 60_000), next_block_seq: 1,
        end_reason: None, unpaid_notice_used: false,
    };
    store.call_put(&peer(), CALL, &paid).await.unwrap();
    let f = fixture();
    let router = CallMediaRouter::new(f.link, Arc::new(super::PaidCallAdmission::new(store.clone())));
    let attachment = router.attach(&peer(), CALL, None).await.unwrap();
    let (shutdown, rx) = tokio::sync::watch::channel(false);
    let running = router.spawn(rx);
    shutdown.send(true).unwrap();
    running.await.unwrap();
    drop(attachment);
    drop(router);
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap().unwrap(), paid);
    drop(store);
    let reopened = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    calls::recover(&reopened).await.unwrap();
    let ended = reopened.call_get(&peer(), CALL).await.unwrap().unwrap();
    assert_eq!(ended.phase, Phase::Ended, "startup must recover a lost attachment without a detach callback");
    assert_eq!(ended.end_reason, Some(HangupReason::Hangup));
    assert_eq!(ended.next_block_seq, 1);
    calls::recover(&reopened).await.unwrap();
    assert_eq!(reopened.call_get(&peer(), CALL).await.unwrap().unwrap(), ended);
}

#[tokio::test]
#[ignore = "requires BITSOV_TEST_POSTGRES_URL pointing to a disposable PostgreSQL server"]
async fn durable_detach_postgres_replays_exhaustion_and_restart() {
    use konsensus_api::calls;
    use konsensus_core::payloads::call::{self as rules, CallEntry, HangupReason, Phase, Side};
    use konsensus_storage::{PostgresStorage, Storage};
    let url = std::env::var("BITSOV_TEST_POSTGRES_URL").unwrap();
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let name = format!("detach_retry_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {name}")).execute(&admin).await.unwrap();
    let db_url = format!("{}/{name}", url.rsplit_once('/').unwrap().0);
    for (restart, call_id) in [(false, CALL), (true, OTHER_CALL)] {
        let (logs, _trace) = capture_logs();
        let store = Arc::new(PostgresStorage::connect(&db_url).await.unwrap());
        let control = sqlx::PgPool::connect(&db_url).await.unwrap();
        let now = super::now_ms();
        let paid = CallEntry {
            side: Side::Callee, phase: Phase::Live, deadline_ms: now + 70_000,
            pending: None, paid_until_ms: Some(now + 60_000), next_block_seq: 1,
            end_reason: None, unpaid_notice_used: false,
        };
        store.call_put(&peer(), call_id, &paid).await.unwrap();
        sqlx::raw_sql("CREATE FUNCTION fail_detach_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'write unavailable'; END $$; CREATE TRIGGER fail_detach BEFORE UPDATE ON call_state FOR EACH ROW EXECUTE FUNCTION fail_detach_write();")
            .execute(&control).await.unwrap();
        let f = fixture();
        let router = CallMediaRouter::new(f.link, Arc::new(super::PaidCallAdmission::new(store.clone())));
        drop(router.attach(&peer(), call_id, None).await.unwrap());
        tokio::time::timeout(Duration::from_secs(10), async {
            while !String::from_utf8_lossy(&logs.0.lock().unwrap()).contains("call media detachment retries exhausted") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("the bounded callback must exhaust its lifecycle retries");
        let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.matches("call media detachment state update failed").count(), 5);
        assert_eq!(store.call_get(&peer(), call_id).await.unwrap().unwrap(), paid);
        let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM call_media_detach_intents WHERE event = 'detach' AND call_id = $1")
            .bind(call_id).fetch_one(&control).await.unwrap();
        assert_eq!(attempts, 1, "one durable intent covers all five failed lifecycle writes");
        sqlx::raw_sql("DROP TRIGGER fail_detach ON call_state; DROP FUNCTION fail_detach_write();").execute(&control).await.unwrap();
        drop(router);
        let store = if restart { drop(store); Arc::new(PostgresStorage::connect(&db_url).await.unwrap()) } else { store };
        if restart { calls::recover(store.as_ref()).await.unwrap(); }
        else { calls::expire_calls(store.as_ref(), now).await.unwrap(); }
        let ended = store.call_get(&peer(), call_id).await.unwrap().unwrap();
        assert_eq!(ended.phase, Phase::Ended);
        assert_eq!(ended.end_reason, Some(HangupReason::Hangup));
        assert_eq!(ended.next_block_seq, 1);
        assert_eq!(ended.paid_until_ms, paid.paid_until_ms);
        assert!(rules::receive_block(Some(ended.clone()), 1, now).is_err());
        calls::recover(store.as_ref()).await.unwrap();
        assert_eq!(store.call_get(&peer(), call_id).await.unwrap().unwrap(), ended);
        control.close().await;
    }
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)")).execute(&admin).await.unwrap();
    admin.close().await;
}

#[tokio::test]
async fn durable_detach_unavailable_publication_refuses_the_socket() {
    use konsensus_core::payloads::call::{CallEntry, Phase, Side};
    use konsensus_storage::{SqliteStorage, Storage};
    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = super::now_ms();
    let paid = CallEntry {
        side: Side::Callee, phase: Phase::Live, deadline_ms: now + 70_000,
        pending: None, paid_until_ms: Some(now + 60_000), next_block_seq: 1,
        end_reason: None, unpaid_notice_used: false,
    };
    store.call_put(&peer(), CALL, &paid).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_publish BEFORE INSERT ON call_media_detach_intents BEGIN SELECT RAISE(ABORT, 'journal unavailable'); END")
        .execute(store.pool()).await.unwrap();
    let f = fixture();
    let router = CallMediaRouter::new(f.link, Arc::new(super::PaidCallAdmission::new(store.clone())));
    assert_eq!(router.attach(&peer(), CALL, None).await.err(), Some(AttachRefusal::Unavailable));
    assert_eq!(router.routed_calls(), 0);
    assert_eq!(store.call_get(&peer(), CALL).await.unwrap().unwrap(), paid);
}
