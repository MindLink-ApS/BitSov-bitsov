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
//! Each direction of each call is held to [`MAX_FRAMES_PER_SECOND`] and
//! [`MAX_BYTES_PER_SECOND`] sustained by a token bucket that may bank up to
//! [`MEDIA_BURST_FRAMES`] and [`MEDIA_BURST_BYTES`]: a backlog released at
//! once after a short stall on the path passes, a sustained overrun does
//! not, and packets over the cap are dropped. Queues are
//! bounded and drop the **oldest** packet rather than block: stale audio is
//! worth less than fresh audio and nothing upstream ever waits on a slow
//! consumer. Towards the peer, a packet waits at most
//! `CALL_MEDIA_WRITE_DEADLINE` for the connection's writer (a bulk frame in
//! flight holds it) and is dropped past that, so audio never queues behind
//! bulk data for longer than that bound.
//!
//! Admission uses N1's settled-block check: the stored call must be live
//! and within paid-until plus grace. A per-route timer checks even idle calls
//! or a stalled peer write, releasing the route when admission ends.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use konsensus_api::call_media::{
    AttachRefusal, CallMediaPort, MediaActivity, MediaAttachment, MediaFrame, MediaQueue, MEDIA_QUEUE_FRAMES,
};
use konsensus_core::traits::transport::{MessageTransport, TransportError};
use konsensus_core::types::NodeId;
use konsensus_message::wire::{is_call_id, CALL_MEDIA_CAPABILITY, MAX_CALL_MEDIA_BYTES};
use konsensus_message::{CallMediaEvent, Frame, NoiseTransport};
use konsensus_storage::Storage;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Packets per second one direction of one call may carry. 20 ms audio is
/// 50 packets per second; this leaves room for a 10 ms codec or a burst.
pub const MAX_FRAMES_PER_SECOND: u32 = 100;
/// Bytes per second one direction of one call may carry (payload bytes).
pub const MAX_BYTES_PER_SECOND: u64 = 64 * 1024;
/// Packets one direction may carry at once when it has been under the rate:
/// two seconds' worth, so the backlog of a short stall on the path catches up
/// instead of being dropped.
pub const MEDIA_BURST_FRAMES: u32 = 2 * MAX_FRAMES_PER_SECOND;
/// Payload bytes one direction may carry at once; two seconds' worth.
pub const MEDIA_BURST_BYTES: u64 = 2 * MAX_BYTES_PER_SECOND;
/// Calls this node routes media for at once (sockets attached).
pub const MAX_ROUTED_CALLS: usize = 64;
/// How long a positive admission answer is trusted before it is re-read.
/// Media stops at most this long after the call ends; N1's grace is 10 s.
pub const ADMISSION_RECHECK: Duration = Duration::from_secs(1);
/// At most one warning per drop reason this often; the rest are counted.
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Whether media for `(peer, call_id)` may flow right now. `now_ms` is Unix
/// milliseconds. Production uses N1's settled-block admission.
#[async_trait]
pub trait CallMediaAdmission: Send + Sync {
    async fn call_media_admitted(&self, peer: &NodeId, call_id: &str, now_ms: u64) -> bool;
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

    /// The media caps.
    pub fn media(now: Instant) -> Self {
        Self::new(MAX_FRAMES_PER_SECOND, MAX_BYTES_PER_SECOND, MEDIA_BURST_FRAMES, MEDIA_BURST_BYTES, now)
    }

    /// Whether a packet of `bytes` payload bytes fits the credit now.
    /// A refused packet spends nothing.
    pub fn admit(&mut self, now: Instant, bytes: usize) -> bool {
        self.refill(now);
        let need_bytes = (bytes as u64).saturating_mul(CREDIT_UNIT);
        if self.frame_credit < CREDIT_UNIT || self.byte_credit < need_bytes {
            return false;
        }
        self.frame_credit -= CREDIT_UNIT;
        self.byte_credit -= need_bytes;
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

/// One routed call: a socket's two queues and the inbound cap.
struct Route {
    peer: NodeId,
    client: Option<konsensus_api::auth::PairingBinding>,
    activity: Arc<MediaActivity>,
    /// From the peer, to the app's socket.
    to_app: Arc<MediaQueue>,
    /// From the app's socket, to the peer.
    from_app: Arc<MediaQueue>,
    inbound_cap: Mutex<RateCap>,
    /// Packets dropped over the rate cap, from the peer and from the app.
    rate_capped_in: AtomicU64,
    rate_capped_out: AtomicU64,
    /// When admission was last confirmed.
    admitted_at: Mutex<Instant>,
    pump: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Route {
    fn end(&self) {
        self.to_app.close();
        self.from_app.close();
        if let Some(pump) = self.pump.lock().unwrap_or_else(|e| e.into_inner()).take() {
            pump.abort();
        }
    }
}

/// The router: one [`Route`] per call with a socket attached.
pub struct CallMediaRouter {
    link: Arc<dyn MediaLink>,
    admission: Arc<dyn CallMediaAdmission>,
    routes: Mutex<HashMap<(NodeId, String), Arc<Route>>>,
    drops: DropLog,
    me: Weak<Self>,
}

impl CallMediaRouter {
    pub fn new(link: Arc<dyn MediaLink>, admission: Arc<dyn CallMediaAdmission>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            link,
            admission,
            routes: Mutex::new(HashMap::new()),
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
                route.end();
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
            self.end_route(&call_id, &route);
            return refuse(MediaDrop::NotAdmitted);
        }
        if !route.inbound_cap.lock().unwrap_or_else(|e| e.into_inner()).admit(Instant::now(), data.len()) {
            route.rate_capped_in.fetch_add(1, Ordering::Relaxed);
            return refuse(MediaDrop::RateCapped);
        }
        match route.to_app.push(MediaFrame { seq, payload: data }) {
            Ok(0) => Ok(()),
            Ok(evicted) => {
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
    fn end_route(&self, call_id: &str, route: &Arc<Route>) {
        let key = (route.peer, call_id.to_string());
        let removed = {
            let mut routes = self.routes();
            match routes.get(&key) {
                Some(current) if Arc::ptr_eq(current, route) => routes.remove(&key).is_some(),
                _ => false,
            }
        };
        route.end();
        if removed {
            info!(
                peer = %route.peer,
                call_id,
                rate_capped_in = route.rate_capped_in.load(Ordering::Relaxed),
                rate_capped_out = route.rate_capped_out.load(Ordering::Relaxed),
                "call media route ended"
            );
        }
    }

    /// The app → peer direction of one call: pop, cap, admit, send.
    async fn pump(self: Arc<Self>, call_id: String, route: Arc<Route>) {
        let forward = async {
            let mut cap = RateCap::media(Instant::now());
            while let Some(frame) = route.from_app.pop().await {
                let now = Instant::now();
                if !cap.admit(now, frame.payload.len()) {
                    route.rate_capped_out.fetch_add(1, Ordering::Relaxed);
                    self.drops.note(MediaDrop::RateCapped, Some(&route.peer), &call_id);
                    continue;
                }
                if !self.still_admitted(&route, &call_id).await {
                    self.drops.note(MediaDrop::NotAdmitted, Some(&route.peer), &call_id);
                    self.end_route(&call_id, &route);
                    break;
                }
                let bytes = match Frame::call_media(&call_id, frame.seq, frame.payload).and_then(|f| f.to_bytes()) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        self.drops.note(MediaDrop::Encode, Some(&route.peer), &call_id);
                        continue;
                    }
                };
                match self.link.send_call_media(&route.peer, &bytes).await {
                    Ok(()) => {}
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
            _ = monitor => self.end_route(&call_id, &route),
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
        let now = Instant::now();
        let route = Arc::new(Route {
            peer: *peer,
            client: client.cloned(),
            activity: MediaActivity::new(),
            to_app: MediaQueue::new(MEDIA_QUEUE_FRAMES),
            from_app: MediaQueue::new(MEDIA_QUEUE_FRAMES),
            inbound_cap: Mutex::new(RateCap::media(now)),
            rate_capped_in: AtomicU64::new(0),
            rate_capped_out: AtomicU64::new(0),
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
                current.end();
            }
            if routes.len() >= MAX_ROUTED_CALLS && !routes.contains_key(&key) {
                warn!(call_id, max = MAX_ROUTED_CALLS, "call media: too many routed calls");
                return Err(AttachRefusal::Unavailable);
            }
            routes.insert(key, Arc::clone(&route));
        }
        let pump = tokio::spawn(Arc::clone(&me).pump(call_id.to_string(), Arc::clone(&route)));
        *route.pump.lock().unwrap_or_else(|e| e.into_inner()) = Some(pump);
        info!(peer = %peer, call_id, "call media route attached");

        let release = {
            let router = Arc::downgrade(&me);
            let route = Arc::downgrade(&route);
            let call_id = call_id.to_string();
            move || {
                if let (Some(router), Some(route)) = (router.upgrade(), route.upgrade()) {
                    router.end_route(&call_id, &route);
                }
            }
        };
        Ok(MediaAttachment::new(*peer, Arc::clone(&route.from_app), Arc::clone(&route.to_app), Arc::clone(&route.activity), release))
    }
}

#[cfg(test)]
#[path = "tests/call_media.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/call_media_two_node.rs"]
mod two_node;
