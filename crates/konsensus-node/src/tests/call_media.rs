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
    let attachment = f.router.attach(&peer(), CALL).await.unwrap();
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
    let attachment = f.router.attach(&peer(), CALL).await.unwrap();
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
    let attachment = router.attach(&peer(), CALL).await.unwrap();
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
    let attachment = f.router.attach(&peer(), CALL).await.unwrap();
    assert_eq!(attachment.limits, MediaLimits::default());
}

#[tokio::test]
async fn inbound_frames_over_the_cap_are_dropped() {
    let f = fixture();
    let attachment = f.router.attach(&peer(), CALL).await.unwrap();
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
