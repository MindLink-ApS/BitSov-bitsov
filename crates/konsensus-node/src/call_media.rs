//! Per-call media router (M6 N2, #428): the node is the cell.
//!
//! Call media flows app → own node → peer node → peer app. This module is
//! the node in the middle of that path:
//!
//! - packets from the owner's app (the media socket in `konsensus-api`)
//!   become `Frame::CallMedia` on the Noise link to the call's counterparty;
//! - `Frame::CallMedia` from a peer node is handed to the socket of the call
//!   it names, and to nothing else.
//!
//! A frame is forwarded only while media for `(peer, call_id)` is admitted
//! ([`CallMediaAdmission`]) and only between the call's two ends: a frame
//! for an unknown call, from a node that is not the call's counterparty, or
//! for a call that is no longer admitted is dropped, counted and logged at
//! a bounded rate, and never answered.
//!
//! Each direction of each call is capped by its [`MediaLimits`]: by default
//! [`MAX_FRAMES_PER_SECOND`] and [`MAX_BYTES_PER_SECOND`], or what the operator
//! set under `[calls]`. Token buckets may bank two seconds of credit so a
//! backlog released after a short path stall passes while a sustained overrun
//! does not. Packets over the cap are dropped. Packets larger than
//! audio may use only what the cap leaves after a reservation for small
//! packets, so they can never spend the budget audio needs ([`MediaCap`]).
//! This changes no price and no admission: a call is admitted and paid the
//! same whatever it carries. Queues are bounded and drop the **oldest** packet
//! rather than block: stale audio is worth less than fresh audio and nothing
//! upstream ever waits on a slow consumer. Towards the peer, a packet waits at most
//! `CALL_MEDIA_WRITE_DEADLINE` for the connection's writer (a bulk frame in
//! flight holds it) and is dropped past that, so audio never queues behind
//! bulk data for longer than that bound.
//!
//! Admission uses N1's settled-block check: the stored call must be live
//! and within paid-until plus grace. A per-route timer checks even idle calls
//! or a stalled peer write, releasing the route when admission ends.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use konsensus_api::call_media::{
    is_bulk_payload, AttachRefusal, CallMediaPort, MediaActivity, MediaAttachment, MediaFrame, MediaLimits, MediaQueue,
    MEDIA_QUEUE_FRAMES,
};
#[cfg(test)]
use konsensus_api::call_media::{DEFAULT_MAX_BYTES_PER_SECOND, DEFAULT_MAX_FRAMES_PER_SECOND};
use konsensus_api::calls::{MediaDetach, MediaDetachOutcome};
use konsensus_core::traits::transport::{MessageTransport, TransportError};
use konsensus_core::types::NodeId;
use konsensus_message::wire::{is_call_id, CALL_MEDIA_CAPABILITY, MAX_CALL_MEDIA_BYTES};
use konsensus_message::{CallMediaEvent, Frame, NoiseTransport};
use konsensus_storage::Storage;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Packets per second one direction of one call may carry unless the operator
/// set otherwise. 20 ms audio is 50 packets per second; this leaves room for a
/// 10 ms codec or a burst.
#[cfg(test)]
pub const MAX_FRAMES_PER_SECOND: u32 = DEFAULT_MAX_FRAMES_PER_SECOND;
/// Bytes per second one direction of one call may carry (payload bytes) unless
/// the operator set otherwise.
#[cfg(test)]
pub const MAX_BYTES_PER_SECOND: u64 = DEFAULT_MAX_BYTES_PER_SECOND;
/// Default packet burst: two seconds' worth, to catch up after a path stall.
#[cfg(test)]
pub const MEDIA_BURST_FRAMES: u32 = 2 * MAX_FRAMES_PER_SECOND;
/// Default payload byte burst: two seconds' worth.
#[cfg(test)]
pub const MEDIA_BURST_BYTES: u64 = 2 * MAX_BYTES_PER_SECOND;
/// Calls this node routes media for at once (sockets attached).
pub const MAX_ROUTED_CALLS: usize = 64;
/// How long a positive admission answer is trusted before it is re-read.
/// Media stops at most this long after the call ends; N1's grace is 10 s.
pub const ADMISSION_RECHECK: Duration = Duration::from_secs(1);
/// At most one warning per drop reason this often; the rest are counted.
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(10);
const DETACH_ATTEMPTS: usize = 5;

/// Whether media for `(peer, call_id)` may flow right now. `now_ms` is Unix
/// milliseconds. Production uses N1's settled-block admission.
#[async_trait]
pub trait CallMediaAdmission: Send + Sync {
    async fn call_media_admitted(&self, peer: &NodeId, call_id: &str, now_ms: u64) -> bool;
    /// Notify admission when the current local attachment has closed.
    async fn media_detached(&self, _peer: &NodeId, _call_id: &str, _detach: MediaDetach) {}
}

/// Production admission: N1's live call and settled paid-block boundary.
/// Unknown calls, ringing/ended calls and storage errors all fail closed.
pub struct PaidCallAdmission {
    storage: Arc<dyn Storage>,
}

impl PaidCallAdmission {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl CallMediaAdmission for PaidCallAdmission {
    async fn call_media_admitted(&self, peer: &NodeId, call_id: &str, now_ms: u64) -> bool {
        konsensus_api::calls::call_media_admitted(self.storage.as_ref(), peer, call_id, now_ms).await
    }

    async fn media_detached(&self, peer: &NodeId, call_id: &str, detach: MediaDetach) {
        for attempt in 1..=DETACH_ATTEMPTS {
            match konsensus_api::calls::detach_callee_media(self.storage.as_ref(), peer, call_id, now_ms(), &detach).await {
                Ok(MediaDetachOutcome::Complete) => return,
                Ok(MediaDetachOutcome::PendingExpiry) => {},
                Err(error) => warn!(%error, attempt, "call media detachment state update failed"),
            }
            if attempt < DETACH_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        warn!(call_id, "call media detachment retries exhausted");
    }
}

/// The peer link as the router uses it: implemented by [`NoiseTransport`];
/// tests substitute a recording link.
#[async_trait]
pub trait MediaLink: Send + Sync {
    /// Whether `peer` is connected and advertised [`CALL_MEDIA_CAPABILITY`].
    async fn peer_routes_media(&self, peer: &NodeId) -> bool;
    /// Write one encoded `Frame::CallMedia`, bounded by the media deadline.
    async fn send_call_media(&self, peer: &NodeId, frame_bytes: &[u8]) -> Result<(), TransportError>;
    /// The next media frame a peer sent, or `None` at shutdown.
    async fn recv_call_media(&self) -> Option<CallMediaEvent>;
}

#[async_trait]
impl MediaLink for NoiseTransport {
    async fn peer_routes_media(&self, peer: &NodeId) -> bool {
        // `ConnectedPeerInfo` renders capabilities with `{:?}`.
        let wanted = format!("{:?}", konsensus_message::Capability::Custom(CALL_MEDIA_CAPABILITY.to_string()));
        self.peer_info(peer)
            .await
            .is_some_and(|info| info.capabilities.contains(&wanted))
    }

    async fn send_call_media(&self, peer: &NodeId, frame_bytes: &[u8]) -> Result<(), TransportError> {
        NoiseTransport::send_call_media(self, peer, frame_bytes).await
    }

    async fn recv_call_media(&self) -> Option<CallMediaEvent> {
        NoiseTransport::recv_call_media(self).await
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Why a packet was dropped. Never answered to the peer; counted and logged
/// at a bounded rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaDrop {
    /// No socket is attached to this peer and call id.
    UnknownCall,
    /// The sending connection is neither privileged nor one we paid on.
    Unprivileged,
    /// The call is no longer admitted (ended, expired or unpaid).
    NotAdmitted,
    /// Over the per-call, per-direction rate cap.
    RateCapped,
    /// Larger than one media frame may be.
    Oversize,
    /// The socket for this call closed meanwhile.
    SocketClosed,
    /// The peer connection's writer was busy past the media deadline.
    PeerBusy,
    /// Not connected to the peer.
    NotConnected,
    /// The frame could not be encoded (never for a capped payload).
    Encode,
}

impl MediaDrop {
    fn as_str(self) -> &'static str {
        match self {
            MediaDrop::UnknownCall => "unknown_call",
            MediaDrop::Unprivileged => "unprivileged",
            MediaDrop::NotAdmitted => "not_admitted",
            MediaDrop::RateCapped => "rate_capped",
            MediaDrop::Oversize => "oversize",
            MediaDrop::SocketClosed => "socket_closed",
            MediaDrop::PeerBusy => "peer_busy",
            MediaDrop::NotConnected => "not_connected",
            MediaDrop::Encode => "encode",
        }
    }
}

/// Token units per packet or byte: credit is kept in millionths so that
/// refill over any elapsed time is exact enough without floating point.
const CREDIT_UNIT: u64 = 1_000_000;

/// One direction's cap as a token bucket: credit refills at `frame_rate`
/// packets and `byte_rate` payload bytes per second, up to `frame_burst`
/// and `byte_burst`, and each admitted packet spends one packet and its
/// bytes. The bucket starts full.
#[derive(Debug, Clone)]
pub struct RateCap {
    last: Instant,
    /// Packet credit, in [`CREDIT_UNIT`]ths of a packet.
    frame_credit: u64,
    /// Byte credit, in [`CREDIT_UNIT`]ths of a byte.
    byte_credit: u64,
    frame_rate: u64,
    byte_rate: u64,
    frame_cap: u64,
    byte_cap: u64,
}

impl RateCap {
    pub fn new(frame_rate: u32, byte_rate: u64, frame_burst: u32, byte_burst: u64, now: Instant) -> Self {
        let frame_cap = u64::from(frame_burst).saturating_mul(CREDIT_UNIT);
        let byte_cap = byte_burst.saturating_mul(CREDIT_UNIT);
        Self {
            last: now,
            frame_credit: frame_cap,
            byte_credit: byte_cap,
            frame_rate: u64::from(frame_rate),
            byte_rate,
            frame_cap,
            byte_cap,
        }
    }

    /// The default media caps.
    #[cfg(test)]
    pub fn media(now: Instant) -> Self {
        Self::new(MAX_FRAMES_PER_SECOND, MAX_BYTES_PER_SECOND, MEDIA_BURST_FRAMES, MEDIA_BURST_BYTES, now)
    }

    /// Whether a packet of `bytes` payload bytes fits the credit now.
    /// A refused packet spends nothing.
    #[cfg(test)]
    pub fn admit(&mut self, now: Instant, bytes: usize) -> bool {
        self.refill(now);
        if !self.fits(bytes) {
            return false;
        }
        self.take(bytes);
        true
    }

    fn refill(&mut self, now: Instant) {
        if now <= self.last {
            return;
        }
        let elapsed = now.duration_since(self.last).as_nanos();
        self.last = now;
        // rate per second × elapsed ns × CREDIT_UNIT / 1e9 ns.
        let earned = |rate: u64| -> u64 {
            let units = elapsed.saturating_mul(u128::from(rate)) / (1_000_000_000 / u128::from(CREDIT_UNIT));
            u64::try_from(units).unwrap_or(u64::MAX)
        };
        self.frame_credit = self.frame_credit.saturating_add(earned(self.frame_rate)).min(self.frame_cap);
        self.byte_credit = self.byte_credit.saturating_add(earned(self.byte_rate)).min(self.byte_cap);
    }

    fn fits(&self, bytes: usize) -> bool {
        self.frame_credit >= CREDIT_UNIT && self.byte_credit >= (bytes as u64).saturating_mul(CREDIT_UNIT)
    }

    fn take(&mut self, bytes: usize) {
        self.frame_credit -= CREDIT_UNIT;
        self.byte_credit -= (bytes as u64).saturating_mul(CREDIT_UNIT);
    }
}

/// One direction's cap with room kept for small packets: every packet counts
/// against the whole budget, and a bulk packet must also fit the bulk share,
/// which leaves the reservation free whatever order packets arrive in. With
/// no bulk packets this is exactly [`RateCap`] over the whole budget.
#[derive(Debug, Clone)]
pub struct MediaCap {
    total: RateCap,
    bulk: RateCap,
}

impl MediaCap {
    pub fn new(limits: MediaLimits, now: Instant) -> Self {
        Self {
            total: RateCap::new(
                limits.max_frames_per_second, limits.max_bytes_per_second,
                limits.max_frames_per_second.saturating_mul(2), limits.max_bytes_per_second.saturating_mul(2), now,
            ),
            bulk: RateCap::new(
                limits.bulk_frames_per_second(), limits.bulk_bytes_per_second(),
                limits.bulk_frames_per_second().saturating_mul(2), limits.bulk_bytes_per_second().saturating_mul(2), now,
            ),
        }
    }

    /// Whether a packet of `bytes` payload bytes fits the credit now.
    /// A refused packet spends nothing from either bucket.
    pub fn admit(&mut self, now: Instant, bytes: usize) -> bool {
        self.total.refill(now);
        self.bulk.refill(now);
        let bulk = is_bulk_payload(bytes);
        if !self.total.fits(bytes) || (bulk && !self.bulk.fits(bytes)) {
            return false;
        }
        self.total.take(bytes);
        if bulk {
            self.bulk.take(bytes);
        }
        true
    }
}

/// Bounded logging of drops: the first of a reason is a warning, then at
/// most one per [`DROP_LOG_INTERVAL`] with the count suppressed meanwhile.
#[derive(Default)]
struct DropLog {
    entries: Mutex<HashMap<MediaDrop, (Instant, u64)>>,
    total: Mutex<HashMap<MediaDrop, u64>>,
}

impl DropLog {
    fn note(&self, reason: MediaDrop, peer: Option<&NodeId>, call_id: &str) {
        let now = Instant::now();
        *self.total.lock().unwrap_or_else(|e| e.into_inner()).entry(reason).or_insert(0) += 1;
        let suppressed = {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            match entries.get_mut(&reason) {
                Some((last, suppressed)) if now.duration_since(*last) < DROP_LOG_INTERVAL => {
                    *suppressed += 1;
                    return;
                }
                Some((last, suppressed)) => {
                    *last = now;
                    std::mem::take(suppressed)
                }
                None => {
                    entries.insert(reason, (now, 0));
                    0
                }
            }
        };
        // The call id is bounded hex (checked at decode) and the peer is the
        // authenticated node id: nothing peer-chosen beyond that is logged.
        match peer {
            Some(peer) => warn!(reason = reason.as_str(), peer = %peer, call_id, suppressed, "call media packet dropped"),
            None => warn!(reason = reason.as_str(), call_id, suppressed, "call media packet dropped"),
        }
    }

    #[cfg(test)]
    fn count(&self, reason: MediaDrop) -> u64 {
        self.total.lock().unwrap_or_else(|e| e.into_inner()).get(&reason).copied().unwrap_or(0)
    }
}

/// Why a route ended, for the one summary line logged at its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndReason {
    /// Admission ended: the call ended, expired or is no longer paid.
    NotAdmitted,
    /// The app's socket detached.
    Detached,
    /// The router stopped.
    Shutdown,
}

impl EndReason {
    fn as_str(self) -> &'static str {
        match self {
            EndReason::NotAdmitted => "not_admitted",
            EndReason::Detached => "detached",
            EndReason::Shutdown => "shutdown",
        }
    }
}

/// Packet counts for one direction of one call. Relaxed atomics: each is a
/// plain tally, read once when the route ends.
#[derive(Default)]
struct DirectionCounts {
    forwarded: AtomicU64,
    rate_capped: AtomicU64,
    not_admitted: AtomicU64,
}

impl DirectionCounts {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Per-route media counters. `outbound` is app → peer, `inbound` is peer →
/// app. Counts only; no packet content is ever kept or logged.
#[derive(Default)]
struct RouteCounts {
    outbound: DirectionCounts,
    inbound: DirectionCounts,
    /// Longest time one outbound send waited on the peer writer, in microseconds.
    longest_writer_wait_us: AtomicU64,
}

/// One routed call: a socket's two queues and the inbound cap.
struct Route {
    call_id: String,
    generation: Arc<tokio::sync::Mutex<u64>>,
    generation_id: u64,
    counts: RouteCounts,
    /// Set by the first `end`, so the summary line is logged once.
    ended: AtomicBool,
    /// Keep socket-drop notification available after admission removed the route.
    admission_ended: AtomicBool,
    peer: NodeId,
    client: Option<konsensus_api::auth::PairingBinding>,
    activity: Arc<MediaActivity>,
    /// From the peer, to the app's socket.
    to_app: Arc<MediaQueue>,
    /// From the app's socket, to the peer.
    from_app: Arc<MediaQueue>,
    inbound_cap: Mutex<MediaCap>,
    /// When admission was last confirmed.
    admitted_at: Mutex<Instant>,
    pump: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Route {
    fn end(&self, reason: EndReason) {
        if !self.ended.swap(true, Ordering::AcqRel) {
            self.log_summary(reason);
        }
        self.to_app.close();
        self.from_app.close();
        if let Some(pump) = self.pump.lock().unwrap_or_else(|e| e.into_inner()).take() {
            pump.abort();
        }
    }

    /// One INFO line at the end of the route: per-direction totals, the
    /// longest writer wait and why it ended. The call id is bounded hex.
    fn log_summary(&self, reason: EndReason) {
        let c = &self.counts;
        let get = |v: &AtomicU64| v.load(Ordering::Relaxed);
        info!(
            call_id = %self.call_id,
            out_forwarded = get(&c.outbound.forwarded),
            out_rate_capped = get(&c.outbound.rate_capped),
            out_evicted = self.from_app.dropped(),
            out_not_admitted = get(&c.outbound.not_admitted),
            in_forwarded = get(&c.inbound.forwarded),
            in_rate_capped = get(&c.inbound.rate_capped),
            in_evicted = self.to_app.dropped(),
            in_not_admitted = get(&c.inbound.not_admitted),
            longest_writer_wait_us = get(&c.longest_writer_wait_us),
            end_reason = reason.as_str(),
            "call media route summary"
        );
    }
}

type AttachmentGenerations = HashMap<(NodeId, String), Weak<tokio::sync::Mutex<u64>>>;

/// The router: one [`Route`] per call with a socket attached.
pub struct CallMediaRouter {
    link: Arc<dyn MediaLink>,
    admission: Arc<dyn CallMediaAdmission>,
    limits: MediaLimits,
    routes: Mutex<HashMap<(NodeId, String), Arc<Route>>>,
    generations: Mutex<AttachmentGenerations>,
    drops: DropLog,
    me: Weak<Self>,
}

impl CallMediaRouter {
    /// A router with the default limits.
    #[cfg(test)]
    pub fn new(link: Arc<dyn MediaLink>, admission: Arc<dyn CallMediaAdmission>) -> Arc<Self> {
        Self::with_limits(link, admission, MediaLimits::default())
    }

    /// A router whose routes are capped by `limits` (`[calls]` in the config).
    pub fn with_limits(
        link: Arc<dyn MediaLink>,
        admission: Arc<dyn CallMediaAdmission>,
        limits: MediaLimits,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            link,
            admission,
            limits,
            routes: Mutex::new(HashMap::new()),
            generations: Mutex::new(HashMap::new()),
            drops: DropLog::default(),
            me: me.clone(),
        })
    }

    /// Drain the transport's media channel into the routes until shutdown.
    pub fn spawn(self: &Arc<Self>, mut shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        let router = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = router.link.recv_call_media() => {
                        let Some(event) = event else { break };
                        let _ = router.inbound(event).await;
                    }
                    _ = shutdown.changed() => break,
                }
            }
            let routes: Vec<Arc<Route>> = router.routes().drain().map(|(_, r)| r).collect();
            let ended = routes.len();
            for route in routes {
                route.end(EndReason::Shutdown);
            }
            info!(ended, remaining = router.routed_calls(), "call media router stopped");
        })
    }

    fn routes(&self) -> std::sync::MutexGuard<'_, HashMap<(NodeId, String), Arc<Route>>> {
        self.routes.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Calls with a socket attached.
    pub fn routed_calls(&self) -> usize {
        self.routes().len()
    }

    /// Packets dropped so far for `reason`.
    #[cfg(test)]
    pub fn dropped(&self, reason: MediaDrop) -> u64 {
        self.drops.count(reason)
    }

    /// A `Frame::CallMedia` from `event.peer_id`: to the socket of that call
    /// or nowhere. The reason a packet went nowhere is returned for the
    /// caller's accounting; the peer is never told.
    pub async fn inbound(&self, event: CallMediaEvent) -> Result<(), MediaDrop> {
        let CallMediaEvent { peer_id, call_id, seq, data, privileged } = event;
        let refuse = |reason: MediaDrop| {
            self.drops.note(reason, Some(&peer_id), &call_id);
            Err(reason)
        };
        let Some(route) = self.routes().get(&(peer_id, call_id.clone())).cloned() else {
            return refuse(MediaDrop::UnknownCall);
        };
        if !privileged {
            return refuse(MediaDrop::Unprivileged);
        }
        if data.len() > MAX_CALL_MEDIA_BYTES {
            return refuse(MediaDrop::Oversize);
        }
        if !self.still_admitted(&route, &call_id).await {
            DirectionCounts::bump(&route.counts.inbound.not_admitted);
            self.end_route(&call_id, &route, EndReason::NotAdmitted);
            return refuse(MediaDrop::NotAdmitted);
        }
        if !route.inbound_cap.lock().unwrap_or_else(|e| e.into_inner()).admit(Instant::now(), data.len()) {
            DirectionCounts::bump(&route.counts.inbound.rate_capped);
            return refuse(MediaDrop::RateCapped);
        }
        match route.to_app.push(MediaFrame { seq, payload: data }) {
            Ok(0) => {
                DirectionCounts::bump(&route.counts.inbound.forwarded);
                Ok(())
            }
            Ok(evicted) => {
                DirectionCounts::bump(&route.counts.inbound.forwarded);
                debug!(peer = %peer_id, call_id, evicted, "call media: app socket slow; oldest packet dropped");
                Ok(())
            }
            Err(_) => refuse(MediaDrop::SocketClosed),
        }
    }

    /// Admission, re-read at most every [`ADMISSION_RECHECK`].
    async fn still_admitted(&self, route: &Route, call_id: &str) -> bool {
        let now = Instant::now();
        let last = *route.admitted_at.lock().unwrap_or_else(|e| e.into_inner());
        if now.duration_since(last) < ADMISSION_RECHECK {
            return true;
        }
        if self.admission.call_media_admitted(&route.peer, call_id, now_ms()).await {
            *route.admitted_at.lock().unwrap_or_else(|e| e.into_inner()) = now;
            true
        } else {
            false
        }
    }

    /// Stop routing `call_id` if `route` is still its route.
    fn end_route(&self, call_id: &str, route: &Arc<Route>, reason: EndReason) {
        let key = (route.peer, call_id.to_string());
        let removed = {
            let mut routes = self.routes();
            match routes.get(&key) {
                Some(current) if Arc::ptr_eq(current, route) => {
                    if reason == EndReason::NotAdmitted {
                        route.admission_ended.store(true, Ordering::Release);
                    }
                    routes.remove(&key).is_some()
                }
                _ => false,
            }
        };
        route.end(reason);
        if removed {
            debug!(peer = %route.peer, call_id, "call media route ended");
        }
        let notify = match reason {
            EndReason::Detached => removed || route.admission_ended.load(Ordering::Acquire),
            EndReason::NotAdmitted => removed,
            EndReason::Shutdown => false,
        };
        if notify {
            let admission = Arc::clone(&self.admission);
            let peer = route.peer;
            let call_id = call_id.to_string();
            let detach = MediaDetach {
                generation: Arc::clone(&route.generation), expected_generation: route.generation_id,
                only_unpaid: reason == EndReason::NotAdmitted,
                may_hangup_live: !route.admission_ended.load(Ordering::Acquire),
            };
            tokio::spawn(async move { admission.media_detached(&peer, &call_id, detach).await; });
        }
    }

    /// The app → peer direction of one call: pop, cap, admit, send.
    async fn pump(self: Arc<Self>, call_id: String, route: Arc<Route>) {
        let forward = async {
            let mut cap = MediaCap::new(self.limits, Instant::now());
            while let Some(frame) = route.from_app.pop().await {
                let now = Instant::now();
                if !cap.admit(now, frame.payload.len()) {
                    DirectionCounts::bump(&route.counts.outbound.rate_capped);
                    self.drops.note(MediaDrop::RateCapped, Some(&route.peer), &call_id);
                    continue;
                }
                if !self.still_admitted(&route, &call_id).await {
                    DirectionCounts::bump(&route.counts.outbound.not_admitted);
                    self.drops.note(MediaDrop::NotAdmitted, Some(&route.peer), &call_id);
                    self.end_route(&call_id, &route, EndReason::NotAdmitted);
                    break;
                }
                let bytes = match Frame::call_media(&call_id, frame.seq, frame.payload).and_then(|f| f.to_bytes()) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        self.drops.note(MediaDrop::Encode, Some(&route.peer), &call_id);
                        continue;
                    }
                };
                let sent_at = Instant::now();
                let sent = self.link.send_call_media(&route.peer, &bytes).await;
                let waited = u64::try_from(sent_at.elapsed().as_micros()).unwrap_or(u64::MAX);
                route.counts.longest_writer_wait_us.fetch_max(waited, Ordering::Relaxed);
                match sent {
                    Ok(()) => DirectionCounts::bump(&route.counts.outbound.forwarded),
                    Err(TransportError::Timeout(_)) => self.drops.note(MediaDrop::PeerBusy, Some(&route.peer), &call_id),
                    Err(_) => self.drops.note(MediaDrop::NotConnected, Some(&route.peer), &call_id),
                }
            }
        };
        let monitor = async {
            let mut recheck = tokio::time::interval_at(
                tokio::time::Instant::now() + ADMISSION_RECHECK,
                ADMISSION_RECHECK,
            );
            recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                recheck.tick().await;
                // Do not rely on a packet arriving, or on its admission cache:
                // this timer must also run while the peer writer is stalled.
                if !self.admission.call_media_admitted(&route.peer, &call_id, now_ms()).await {
                    self.drops.note(MediaDrop::NotAdmitted, Some(&route.peer), &call_id);
                    break;
                }
                *route.admitted_at.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
            }
        };
        tokio::select! {
            biased;
            _ = monitor => self.end_route(&call_id, &route, EndReason::NotAdmitted),
            _ = forward => {},
        }

    }
}

#[async_trait]
impl CallMediaPort for CallMediaRouter {
    async fn attach(&self, peer: &NodeId, call_id: &str, client: Option<&konsensus_api::auth::PairingBinding>) -> Result<MediaAttachment, AttachRefusal> {
        if !is_call_id(call_id) || !self.admission.call_media_admitted(peer, call_id, now_ms()).await {
            return Err(AttachRefusal::NotAdmitted);
        }
        if !self.link.peer_routes_media(peer).await {
            debug!(peer = %peer, call_id, "call media: peer not connected or does not route media");
            return Err(AttachRefusal::Unavailable);
        }
        let me = self.me.upgrade().ok_or(AttachRefusal::Unavailable)?;
        let generation = {
            let mut generations = self.generations.lock().unwrap_or_else(|e| e.into_inner());
            generations.retain(|_, generation| generation.strong_count() > 0);
            let key = (*peer, call_id.to_string());
            match generations.get(&key).and_then(Weak::upgrade) {
                Some(generation) => generation,
                None => {
                    let generation = Arc::new(tokio::sync::Mutex::new(0_u64));
                    generations.insert(key, Arc::downgrade(&generation));
                    generation
                }
            }
        };
        // Order reconnect with every detach attempt, including its storage write.
        let mut current_generation = generation.lock().await;
        if !self.admission.call_media_admitted(peer, call_id, now_ms()).await {
            return Err(AttachRefusal::NotAdmitted);
        }
        let generation_id = current_generation.checked_add(1).ok_or(AttachRefusal::Unavailable)?;
        let now = Instant::now();
        let route = Arc::new(Route {
            call_id: call_id.to_string(),
            generation: Arc::clone(&generation),
            generation_id,
            counts: RouteCounts::default(),
            ended: AtomicBool::new(false),
            admission_ended: AtomicBool::new(false),
            peer: *peer,
            client: client.cloned(),
            activity: MediaActivity::new(),
            to_app: MediaQueue::new(MEDIA_QUEUE_FRAMES),
            from_app: MediaQueue::new(MEDIA_QUEUE_FRAMES),
            inbound_cap: Mutex::new(MediaCap::new(self.limits, now)),
            admitted_at: Mutex::new(now),
            pump: Mutex::new(None),
        });
        {
            let mut routes = self.routes();
            let key = (*peer, call_id.to_string());
            if let Some(current) = routes.get(&key) {
                if current.client.as_ref() != client || !current.activity.is_stale() {
                    return Err(AttachRefusal::AlreadyAttached);
                }
                // Close both queues and abort the old pump before publishing
                // its replacement. A late old-socket drop cannot remove it.
                current.end(EndReason::Detached);
            }
            if routes.len() >= MAX_ROUTED_CALLS && !routes.contains_key(&key) {
                warn!(call_id, max = MAX_ROUTED_CALLS, "call media: too many routed calls");
                return Err(AttachRefusal::Unavailable);
            }
            *current_generation = generation_id;
            routes.insert(key, Arc::clone(&route));
        }
        let pump = tokio::spawn(Arc::clone(&me).pump(call_id.to_string(), Arc::clone(&route)));
        *route.pump.lock().unwrap_or_else(|e| e.into_inner()) = Some(pump);
        info!(peer = %peer, call_id, "call media route attached");

        let release = {
            let router = Arc::downgrade(&me);
            let route = Arc::clone(&route);
            let call_id = call_id.to_string();
            move || {
                if let Some(router) = router.upgrade() {
                    router.end_route(&call_id, &route, EndReason::Detached);
                }
            }
        };
        Ok(MediaAttachment::new(*peer, Arc::clone(&route.from_app), Arc::clone(&route.to_app), Arc::clone(&route.activity), release)
            .with_limits(self.limits))
    }
}

#[cfg(test)]
#[path = "tests/call_media.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/call_media_two_node.rs"]
mod two_node;
