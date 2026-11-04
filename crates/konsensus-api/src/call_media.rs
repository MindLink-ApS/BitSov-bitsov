//! The app side of node-routed call media (M6 N2, #428): the owner's media
//! socket and the seam the node's call media router plugs into.
//!
//! Media flows app → own node → peer node → peer app; apps never send media
//! to each other. The app reaches its own node here, over an authenticated
//! binary WebSocket per call, `GET /api/v1/calls/:call_id/media?peer=<hex>`.
//! Each binary message is one packet: `seq` (u32, big-endian) followed by
//! the codec payload, at most [`MAX_MEDIA_PAYLOAD_BYTES`]. The node turns it
//! into a `Frame::CallMedia` on the Noise link to the peer, and delivers the
//! peer's packets back on the same socket in the same form.
//!
//! The socket is owner-scoped (the token's subject is this node), bound to a
//! live pairing (a paired device, re-checked while the socket is open) and
//! needs `spend`: the scope that places and answers paid calls. It opens only
//! while the router admits media for `(peer, call_id)`; the router closes it
//! once the call is no longer admitted.
//!
//! The router itself (per-call queues, rate caps, forwarding) lives in the
//! node crate and implements [`CallMediaPort`]; this crate only holds the
//! bounded drop-oldest [`MediaQueue`] both sides share, the [`MediaLimits`]
//! the operator configured, and the socket.
//!
//! Larger packets never get in the way of small ones. A packet of at most
//! [`PRIORITY_PACKET_BYTES`] rides the priority lane and a larger one the
//! bulk lane. The node reads no payload to tell them apart: it goes by the
//! size it already sees. Audio is small, so a call that only carries audio
//! never touches the bulk lane and behaves as if the lane did not exist.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use konsensus_core::types::NodeId;
use serde::Deserialize;
use tokio::sync::{watch, Notify};
use tracing::{debug, warn};

use crate::auth;
use crate::state::AppState;

/// Largest payload of one app packet, the same cap as the peer frame.
pub const MAX_MEDIA_PAYLOAD_BYTES: usize = konsensus_message::wire::MAX_CALL_MEDIA_BYTES;

/// Bytes of the sequence header in front of every socket message.
pub const SEQ_HEADER_BYTES: usize = 4;

/// Packets a queue holds before it drops the oldest: at 20 ms per packet
/// this is 640 ms of audio, more than any jitter buffer wants.
pub const MEDIA_QUEUE_FRAMES: usize = 32;

/// Largest payload that rides the priority lane. One 20 ms Opus or mu-law
/// packet is far smaller (161 bytes at most), and so is a sealed one.
pub const PRIORITY_PACKET_BYTES: usize = 512;

/// Bulk packets a queue holds before it drops the oldest bulk packet. Stale
/// bulk data is worth little: at the default byte cap this is about a second.
pub const BULK_QUEUE_FRAMES: usize = 16;

/// Packets per second one direction of one call may carry, by default.
pub const DEFAULT_MAX_FRAMES_PER_SECOND: u32 = 100;

/// Payload bytes per second one direction of one call may carry, by default.
pub const DEFAULT_MAX_BYTES_PER_SECOND: u64 = 64 * 1024;

/// Packets per second the bulk lane leaves for the priority lane: 20 ms audio
/// is 50, and this leaves room for its control packets.
pub const RESERVED_PRIORITY_FRAMES: u32 = 60;

/// Bytes per second the bulk lane leaves for the priority lane: 60 packets of
/// the largest audio frame (mu-law, 161 bytes) and their headers.
pub const RESERVED_PRIORITY_BYTES: u64 = 12 * 1024;

/// What one direction of one routed call may carry per second. The same
/// values bound the router and the owner's socket. Configured on the node;
/// the defaults are the fixed limits every node has always applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaLimits {
    pub max_frames_per_second: u32,
    pub max_bytes_per_second: u64,
    /// What the socket does when bulk packets pass their share: drop them and
    /// stay up, or (the default, and what nodes have always done past the
    /// budget) count them and close at the budget.
    pub drop_bulk_over_share: bool,
}

impl Default for MediaLimits {
    fn default() -> Self {
        Self {
            max_frames_per_second: DEFAULT_MAX_FRAMES_PER_SECOND,
            max_bytes_per_second: DEFAULT_MAX_BYTES_PER_SECOND,
            drop_bulk_over_share: false,
        }
    }
}

impl MediaLimits {
    /// Packets per second bulk packets may use: what the reservation leaves.
    pub fn bulk_frames_per_second(&self) -> u32 {
        self.max_frames_per_second.saturating_sub(RESERVED_PRIORITY_FRAMES)
    }

    /// Bytes per second bulk packets may use: what the reservation leaves.
    pub fn bulk_bytes_per_second(&self) -> u64 {
        self.max_bytes_per_second.saturating_sub(RESERVED_PRIORITY_BYTES)
    }

    /// The value of [`MEDIA_LIMITS_HEADER`]: none at the default rates.
    pub fn advertised(&self) -> Option<String> {
        (self.max_frames_per_second != DEFAULT_MAX_FRAMES_PER_SECOND
            || self.max_bytes_per_second != DEFAULT_MAX_BYTES_PER_SECOND)
            .then(|| format!("{} {}", self.max_frames_per_second, self.max_bytes_per_second))
    }
}

/// Tells the owner's app, in the socket's handshake answer, what this node
/// allows when its operator raised the limits: `<messages> <bytes>` per second,
/// per direction. Absent means the defaults, so the answer of a node with no
/// new config is what it always was. It changes nothing the node enforces.
pub const MEDIA_LIMITS_HEADER: &str = "x-bitsov-media-limits";

/// Whether a payload of `len` bytes rides the bulk lane.
pub fn is_bulk_payload(len: usize) -> bool {
    len > PRIORITY_PACKET_BYTES
}

/// One media packet between app and node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaFrame {
    pub seq: u32,
    pub payload: Vec<u8>,
}

impl MediaFrame {
    /// The socket form: `seq` big-endian, then the payload.
    pub fn to_ws_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SEQ_HEADER_BYTES + self.payload.len());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a socket message; `None` when it is shorter than the header or
    /// its payload exceeds [`MAX_MEDIA_PAYLOAD_BYTES`].
    pub fn from_ws_bytes(bytes: &[u8]) -> Option<Self> {
        let (head, payload) = bytes.split_at_checked(SEQ_HEADER_BYTES)?;
        if payload.len() > MAX_MEDIA_PAYLOAD_BYTES {
            return None;
        }
        Some(Self {
            seq: u32::from_be_bytes(head.try_into().ok()?),
            payload: payload.to_vec(),
        })
    }
}

/// The queue was closed: the call ended or the socket went away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed;

struct QueueState {
    frames: VecDeque<MediaFrame>,
    capacity: usize,
    bulk: VecDeque<MediaFrame>,
    bulk_capacity: usize,
    closed: bool,
    dropped: u64,
    bulk_dropped: u64,
}

impl QueueState {
    /// Priority packets first, then bulk, each lane in order.
    fn next(&mut self) -> Option<MediaFrame> {
        self.frames.pop_front().or_else(|| self.bulk.pop_front())
    }
}

/// A bounded packet queue that drops the **oldest** packet when full, so a
/// slow consumer costs stale audio, never a blocked producer and never
/// unbounded memory. Closing it wakes the consumer with `None`.
///
/// Two lanes, each with its own bound: a bulk packet can only evict another
/// bulk packet, and the consumer takes every priority packet first, so bulk
/// data can neither push audio out of the queue nor make it wait in line.
pub struct MediaQueue {
    state: Mutex<QueueState>,
    notify: Notify,
    closed: watch::Sender<bool>,
}

impl MediaQueue {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueueState {
                frames: VecDeque::with_capacity(capacity.max(1)),
                capacity: capacity.max(1),
                bulk: VecDeque::new(),
                bulk_capacity: BULK_QUEUE_FRAMES.min(capacity.max(1)),
                closed: false,
                dropped: 0,
                bulk_dropped: 0,
            }),
            notify: Notify::new(),
            closed: watch::channel(false).0,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Append `frame`, evicting the oldest packet if the queue is full.
    /// Returns how many packets were dropped to make room (0 or 1).
    pub fn push(&self, frame: MediaFrame) -> Result<usize, Closed> {
        let dropped = {
            let mut q = self.lock();
            if q.closed {
                return Err(Closed);
            }
            if is_bulk_payload(frame.payload.len()) {
                let dropped = if q.bulk.len() >= q.bulk_capacity {
                    q.bulk.pop_front();
                    q.bulk_dropped += 1;
                    1
                } else {
                    0
                };
                q.bulk.push_back(frame);
                dropped
            } else {
                let dropped = if q.frames.len() >= q.capacity {
                    q.frames.pop_front();
                    q.dropped += 1;
                    1
                } else {
                    0
                };
                q.frames.push_back(frame);
                dropped
            }
        };
        self.notify.notify_one();
        Ok(dropped)
    }

    /// The next packet, waiting for one; `None` once the queue is closed
    /// and drained.
    pub async fn pop(&self) -> Option<MediaFrame> {
        loop {
            {
                let mut q = self.lock();
                if let Some(frame) = q.next() {
                    return Some(frame);
                }
                if q.closed {
                    return None;
                }
            }
            self.notify.notified().await;
        }
    }

    /// The next packet if one is queued.
    pub fn try_pop(&self) -> Option<MediaFrame> {
        self.lock().next()
    }

    /// Stop accepting packets; queued ones can still be popped.
    pub fn close(&self) {
        self.lock().closed = true;
        self.closed.send_replace(true);
        self.notify.notify_waiters();
        self.notify.notify_one();
    }

    /// Wait for termination independently of queued packets or socket I/O.
    pub async fn closed(&self) {
        let _ = self.closed.subscribe().wait_for(|closed| *closed).await;
    }

    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }

    pub fn len(&self) -> usize {
        let q = self.lock();
        q.frames.len() + q.bulk.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Packets evicted so far to make room.
    pub fn dropped(&self) -> u64 {
        let q = self.lock();
        q.dropped + q.bulk_dropped
    }

    /// Priority packets evicted so far: only other priority packets can do that.
    pub fn priority_dropped(&self) -> u64 {
        self.lock().dropped
    }
}

/// Why the router refused to attach a socket to a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachRefusal {
    /// No live, admitted call `(peer, call_id)` on this node.
    NotAdmitted,
    /// A socket is already attached to this call.
    AlreadyAttached,
    /// The peer is not connected, does not route call media, or the node
    /// is out of room.
    Unavailable,
}

/// An app socket's two ends of one call, handed out by [`CallMediaPort::attach`].
/// Dropping it detaches the socket from the router.
pub struct MediaAttachment {
    /// The call's counterparty.
    pub peer: NodeId,
    /// Packets from the app, for the router to forward to the peer.
    pub to_node: Arc<MediaQueue>,
    /// Packets from the peer, for the socket to deliver to the app.
    pub from_node: Arc<MediaQueue>,
    /// What the socket may take from the app per second.
    pub limits: MediaLimits,
    release: Option<Box<dyn FnOnce() + Send>>,
}

impl MediaAttachment {
    /// `release` runs once, when the attachment is dropped.
    pub fn new(
        peer: NodeId,
        to_node: Arc<MediaQueue>,
        from_node: Arc<MediaQueue>,
        release: impl FnOnce() + Send + 'static,
    ) -> Self {
        Self { peer, to_node, from_node, limits: MediaLimits::default(), release: Some(Box::new(release)) }
    }

    /// The same attachment, bounded by `limits` instead of the defaults.
    pub fn with_limits(mut self, limits: MediaLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl Drop for MediaAttachment {
    fn drop(&mut self) {
        self.to_node.close();
        self.from_node.close();
        if let Some(release) = self.release.take() {
            release();
        }
    }
}

/// What the node's call media router offers the socket: one attachment per
/// admitted call.
#[async_trait]
pub trait CallMediaPort: Send + Sync {
    /// Attach the owner's socket to call `call_id` with `peer`, if the call
    /// is admitted for media right now.
    async fn attach(&self, peer: &NodeId, call_id: &str) -> Result<MediaAttachment, AttachRefusal>;
}

/// Query parameters of the media socket.
#[derive(Deserialize)]
pub struct MediaParams {
    /// JWT, for local tooling only; apps send it as the `bitsov.jwt.<token>`
    /// subprotocol like `/api/v1/ws`.
    #[serde(default)]
    pub token: Option<String>,
    /// The call's counterparty (64 lowercase hex).
    #[serde(default)]
    pub peer: Option<String>,
}

/// `GET /api/v1/calls/:call_id/media` — the owner's binary media socket.
async fn media_handler(
    _local: crate::local_read::LocalConnection,
    State(state): State<Arc<AppState>>,
    Path(call_id): Path<String>,
    Query(params): Query<MediaParams>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(token) = crate::ws::extract_ws_token(params.token.as_deref(), &headers) else {
        warn!("call media socket refused: missing token");
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    };
    let claims = match auth::validate_token(&token, &state.jwt_secret) {
        Ok(claims) => claims,
        Err(e) => {
            warn!(error = %e, "call media socket refused: invalid token");
            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        }
    };
    // Bound to the paired device: a token without a live pairing binding
    // (the owner's own key, a loopback token) does not open media.
    match auth::check_pairing_binding(&state, &claims) {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::FORBIDDEN, "paired device required").into_response(),
        Err(_) => return (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
    }
    if !claims.scp.contains(&auth::Scope::Spend) {
        warn!(node_id = %claims.sub, "call media socket refused: token lacks the spend scope");
        return (StatusCode::FORBIDDEN, "token lacks required scope: spend").into_response();
    }
    if claims.sub != state.identity.node_id().to_hex() {
        return (StatusCode::FORBIDDEN, "owner media socket").into_response();
    }
    if !konsensus_message::wire::is_call_id(&call_id) {
        return (StatusCode::BAD_REQUEST, "invalid call id").into_response();
    }
    let Some(peer) = params.peer.as_deref().and_then(|p| NodeId::from_hex(p).ok()) else {
        return (StatusCode::BAD_REQUEST, "invalid peer id").into_response();
    };
    let Some(port) = state.call_media.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "call media is not available on this node").into_response();
    };
    let attachment = match port.attach(&peer, &call_id).await {
        Ok(attachment) => attachment,
        Err(AttachRefusal::NotAdmitted) => {
            debug!(peer = %peer, "call media socket refused: call not admitted");
            return (StatusCode::FORBIDDEN, "call media not admitted").into_response();
        }
        Err(AttachRefusal::AlreadyAttached) => {
            return (StatusCode::CONFLICT, "a media socket is already attached to this call").into_response();
        }
        Err(AttachRefusal::Unavailable) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "the peer does not route call media right now").into_response();
        }
    };
    debug!(node_id = %claims.sub, peer = %peer, "call media socket attached");
    let advertised = attachment.limits.advertised();
    let mut response = ws
        .max_message_size(SEQ_HEADER_BYTES + MAX_MEDIA_PAYLOAD_BYTES)
        .max_frame_size(SEQ_HEADER_BYTES + MAX_MEDIA_PAYLOAD_BYTES)
        .protocols([crate::ws::WS_PROTOCOL])
        .on_upgrade(move |socket| handle_media(socket, state, claims, attachment))
        .into_response();
    if let Some(value) = advertised.and_then(|value| HeaderValue::from_str(&value).ok()) {
        response.headers_mut().insert(MEDIA_LIMITS_HEADER, value);
    }
    response
}

/// Keepalive ping interval, as on `/api/v1/ws`.
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(45);

/// How often the token and pairing are re-checked while the socket is open.
const AUTH_RECHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Applies to every explicit socket send, including pong, keepalive and close.
const SOCKET_WRITE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

/// What the socket does with one message from the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ingress {
    Accept,
    /// A bulk packet over the bulk share: dropped, the socket stays up.
    DropBulk,
    /// Over the budget: the socket closes.
    Close,
}

struct IngressBudget {
    limits: MediaLimits,
    start: tokio::time::Instant,
    messages: u32,
    bytes: usize,
    bulk_messages: u32,
    bulk_bytes: usize,
    over_messages: u32,
    over_bytes: usize,
}

impl IngressBudget {
    fn new(limits: MediaLimits) -> Self {
        Self {
            limits,
            start: tokio::time::Instant::now(),
            messages: 0,
            bytes: 0,
            bulk_messages: 0,
            bulk_bytes: 0,
            over_messages: 0,
            over_bytes: 0,
        }
    }

    /// Every message counts against the budget and the socket closes past it.
    /// With `drop_bulk_over_share`, bulk packets count against their own share
    /// instead, so a burst of them can never cost the socket: audio catching up
    /// after a stall has the whole budget to itself, and bulk over its share is
    /// dropped. The socket closes for bulk only if it passes the whole budget
    /// again on top (a flood, not a burst). The router still caps what goes on.
    fn admit(&mut self, message: &Message) -> Ingress {
        if self.start.elapsed() >= std::time::Duration::from_secs(1) {
            *self = Self::new(self.limits);
        }
        // Count every message before parsing/copying application payloads.
        let bytes = match message {
            Message::Binary(data) | Message::Ping(data) | Message::Pong(data) => data.len(),
            Message::Text(text) => text.len(),
            Message::Close(frame) => frame.as_ref().map_or(0, |frame| 2 + frame.reason.len()),
        };
        let max_messages = self.limits.max_frames_per_second;
        let max_bytes = usize::try_from(self.limits.max_bytes_per_second).unwrap_or(usize::MAX);
        if self.limits.drop_bulk_over_share
            && matches!(message, Message::Binary(_))
            && is_bulk_payload(bytes.saturating_sub(SEQ_HEADER_BYTES))
        {
            let share_bytes = usize::try_from(self.limits.bulk_bytes_per_second()).unwrap_or(usize::MAX);
            if self.bulk_messages >= self.limits.bulk_frames_per_second()
                || self.bulk_bytes.saturating_add(bytes) > share_bytes
            {
                self.over_messages += 1;
                self.over_bytes = self.over_bytes.saturating_add(bytes);
                return if self.over_messages <= max_messages && self.over_bytes <= max_bytes {
                    Ingress::DropBulk
                } else {
                    Ingress::Close
                };
            }
            self.bulk_messages += 1;
            self.bulk_bytes += bytes;
            return Ingress::Accept;
        }
        self.messages += 1;
        self.bytes = self.bytes.saturating_add(bytes);
        if self.messages <= max_messages && self.bytes <= max_bytes {
            Ingress::Accept
        } else {
            Ingress::Close
        }
    }
}

async fn socket_send(socket: &mut WebSocket, message: Message) -> bool {
    matches!(tokio::time::timeout(SOCKET_WRITE_DEADLINE, socket.send(message)).await, Ok(Ok(())))
}

async fn handle_media(mut socket: WebSocket, state: Arc<AppState>, claims: auth::Claims, attachment: MediaAttachment) {
    // Keep these futures outside the I/O loop: a pending send cannot suspend
    // revocation, expiry or route termination. Cancelling socket I/O is safe
    // here because this socket is dropped, never reused by another handler.
    let close = tokio::select! {
        biased;
        _ = attachment.from_node.closed() => false,
        _ = attachment.to_node.closed() => false,
        _ = async {
            let mut recheck = tokio::time::interval(AUTH_RECHECK_INTERVAL);
            loop {
                recheck.tick().await;
                if !stream_authorized(&state, &claims) { break; }
            }
        } => false,
        close = media_io(&mut socket, &attachment.from_node, &attachment.to_node, attachment.limits) => close,
    };
    // Release the route before any best-effort close handshake. A write
    // failure/timeout drops immediately, with no attempt to reuse the socket.
    drop(attachment);
    if close {
        let _ = socket_send(&mut socket, Message::Close(None)).await;
    }
}

/// Returns false when a failed/timed-out write requires an immediate drop.
async fn media_io(socket: &mut WebSocket, from_node: &MediaQueue, to_node: &MediaQueue, limits: MediaLimits) -> bool {
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.tick().await;
    let mut ingress = IngressBudget::new(limits);
    let mut malformed: u64 = 0;
    loop {
        tokio::select! {
            frame = from_node.pop() => {
                let Some(frame) = frame else { return true };
                if !socket_send(socket, Message::Binary(frame.to_ws_bytes())).await {
                    return false;
                }
            }
            msg = socket.recv() => {
                let msg = match msg {
                    Some(Ok(msg)) => msg,
                    Some(Err(_)) | None => return false,
                };
                match ingress.admit(&msg) {
                    Ingress::Accept => {}
                    Ingress::DropBulk => continue,
                    Ingress::Close => {
                        debug!("call media socket: ingress budget exhausted");
                        return true;
                    }
                }
                match msg {
                    Message::Binary(bytes) => match MediaFrame::from_ws_bytes(&bytes) {
                        Some(frame) => {
                            if to_node.push(frame).is_err() { return true; }
                        }
                        None => {
                            malformed += 1;
                            if malformed == 1 {
                                warn!(len = bytes.len(), "call media socket: malformed packet dropped (further ones counted only)");
                            }
                        }
                    },
                    // Tungstenite queues and flushes the automatic pong on
                    // the next read/write; no explicit response is needed.
                    Message::Ping(_) => {}
                    // This is a binary media protocol. Text consumes the same
                    // ingress budget but never JSON parsing or a text reply.
                    Message::Text(_) | Message::Pong(_) => {}
                    Message::Close(_) => return true,
                }
            }
            _ = keepalive.tick() => {
                if !socket_send(socket, Message::Ping(vec![0x6b, 0x61])).await { return false; }
            }
        }
    }
}

fn stream_authorized(state: &Arc<AppState>, claims: &auth::Claims) -> bool {
    claims.exp > chrono::Utc::now().timestamp()
        && claims.scp.contains(&auth::Scope::Spend)
        && matches!(auth::check_pairing_binding(state, claims), Ok(Some(_)))
}

/// Registers the owner media socket.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/calls/:call_id/media", get(media_handler))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(seq: u32) -> MediaFrame {
        MediaFrame { seq, payload: vec![seq as u8; 3] }
    }

    #[test]
    fn ws_bytes_round_trip_and_cap() {
        let f = MediaFrame { seq: 0x0102_0304, payload: vec![9, 8, 7] };
        let bytes = f.to_ws_bytes();
        assert_eq!(bytes, vec![1, 2, 3, 4, 9, 8, 7]);
        assert_eq!(MediaFrame::from_ws_bytes(&bytes), Some(f));
        // An empty payload is a packet; a short header is not.
        assert_eq!(MediaFrame::from_ws_bytes(&[0, 0, 0, 5]), Some(MediaFrame { seq: 5, payload: vec![] }));
        assert_eq!(MediaFrame::from_ws_bytes(&[0, 0, 0]), None);
        let at_cap = [vec![0; 4], vec![1; MAX_MEDIA_PAYLOAD_BYTES]].concat();
        assert!(MediaFrame::from_ws_bytes(&at_cap).is_some());
        let over = [vec![0; 4], vec![1; MAX_MEDIA_PAYLOAD_BYTES + 1]].concat();
        assert!(MediaFrame::from_ws_bytes(&over).is_none());
    }

    #[tokio::test]
    async fn queue_drops_the_oldest_when_full_and_never_blocks() {
        let q = MediaQueue::new(3);
        for seq in 1..=3 {
            assert_eq!(q.push(frame(seq)), Ok(0));
        }
        assert_eq!(q.push(frame(4)), Ok(1), "one evicted");
        assert_eq!(q.push(frame(5)), Ok(1));
        assert_eq!(q.len(), 3);
        assert_eq!(q.dropped(), 2);
        let seqs: Vec<u32> = std::iter::from_fn(|| q.try_pop()).map(|f| f.seq).collect();
        assert_eq!(seqs, vec![3, 4, 5], "the newest audio survives");
    }

    fn sized(seq: u32, len: usize) -> MediaFrame {
        MediaFrame { seq, payload: vec![seq as u8; len] }
    }

    #[test]
    fn the_default_limits_are_the_fixed_limits_nodes_have_always_applied() {
        let limits = MediaLimits::default();
        assert_eq!(limits.max_frames_per_second, 100);
        assert_eq!(limits.max_bytes_per_second, 64 * 1024);
        assert_eq!(MEDIA_QUEUE_FRAMES, 32);
        // 50 audio packets a second and their control packets fit the reservation...
        let (frames, bytes) = (RESERVED_PRIORITY_FRAMES, RESERVED_PRIORITY_BYTES);
        assert!(frames >= 51);
        assert!(bytes >= u64::from(frames) * (161 + SEQ_HEADER_BYTES as u64));
        // ...and every audio packet rides the priority lane.
        assert!(!is_bulk_payload(161));
        assert!(!is_bulk_payload(PRIORITY_PACKET_BYTES));
        assert!(is_bulk_payload(PRIORITY_PACKET_BYTES + 1));
    }

    #[test]
    fn only_raised_limits_are_advertised() {
        assert_eq!(MediaLimits::default().advertised(), None);
        assert_eq!(MediaLimits { drop_bulk_over_share: true, ..Default::default() }.advertised(), None);
        let raised = MediaLimits { max_frames_per_second: 160, max_bytes_per_second: 262_144, drop_bulk_over_share: false };
        assert_eq!(raised.advertised().as_deref(), Some("160 262144"));
    }

    #[test]
    fn a_bulk_packet_never_evicts_audio_and_audio_leaves_first() {
        let q = MediaQueue::new(MEDIA_QUEUE_FRAMES);
        for seq in 0..10 {
            q.push(sized(seq, 160)).unwrap();
        }
        // Far more bulk than either lane holds.
        for seq in 100..200 {
            q.push(sized(seq, MAX_MEDIA_PAYLOAD_BYTES)).unwrap();
        }
        assert_eq!(q.priority_dropped(), 0, "bulk data cost no audio packet");
        assert_eq!(q.dropped(), 100 - BULK_QUEUE_FRAMES as u64);
        // Audio that arrives after the bulk backlog still leaves before it.
        q.push(sized(10, 160)).unwrap();
        let seqs: Vec<u32> = std::iter::from_fn(|| q.try_pop()).map(|f| f.seq).collect();
        let audio: Vec<u32> = (0..=10).collect();
        assert_eq!(&seqs[..11], &audio[..]);
        // The newest bulk packets survive, in order.
        let bulk: Vec<u32> = (200 - BULK_QUEUE_FRAMES as u32..200).collect();
        assert_eq!(&seqs[11..], &bulk[..]);
    }

    #[test]
    fn audio_alone_behaves_exactly_as_one_queue() {
        let q = MediaQueue::new(MEDIA_QUEUE_FRAMES);
        for seq in 0..(MEDIA_QUEUE_FRAMES as u32 + 5) {
            let evicted = q.push(sized(seq, 161)).unwrap();
            assert_eq!(evicted, usize::from(seq >= MEDIA_QUEUE_FRAMES as u32));
        }
        assert_eq!(q.len(), MEDIA_QUEUE_FRAMES);
        assert_eq!(q.dropped(), 5);
        let seqs: Vec<u32> = std::iter::from_fn(|| q.try_pop()).map(|f| f.seq).collect();
        assert_eq!(seqs, (5..(MEDIA_QUEUE_FRAMES as u32 + 5)).collect::<Vec<_>>());
    }

    fn binary(payload: usize) -> Message {
        Message::Binary(vec![0; SEQ_HEADER_BYTES + payload])
    }

    #[tokio::test]
    async fn the_socket_budget_for_audio_is_unchanged_at_the_defaults() {
        let mut budget = IngressBudget::new(MediaLimits::default());
        for _ in 0..100 {
            assert_eq!(budget.admit(&binary(161)), Ingress::Accept);
        }
        assert_eq!(budget.admit(&binary(161)), Ingress::Close, "the 101st message closes, as it always has");

        // Small messages at a large size close on bytes the same way.
        let mut budget = IngressBudget::new(MediaLimits { max_frames_per_second: 1000, max_bytes_per_second: 1000, drop_bulk_over_share: false });
        assert_eq!(budget.admit(&binary(500)), Ingress::Accept);
        assert_eq!(budget.admit(&binary(500)), Ingress::Close);

        // Large messages close at the budget too unless the operator chose otherwise.
        let mut budget = IngressBudget::new(MediaLimits::default());
        for _ in 0..15 {
            assert_eq!(budget.admit(&binary(MAX_MEDIA_PAYLOAD_BYTES)), Ingress::Accept);
        }
        assert_eq!(budget.admit(&binary(MAX_MEDIA_PAYLOAD_BYTES)), Ingress::Close);
    }

    const DROP_BULK: MediaLimits = MediaLimits {
        max_frames_per_second: DEFAULT_MAX_FRAMES_PER_SECOND,
        max_bytes_per_second: DEFAULT_MAX_BYTES_PER_SECOND,
        drop_bulk_over_share: true,
    };

    #[tokio::test]
    async fn a_burst_of_bulk_packets_is_dropped_and_leaves_audio_its_budget() {
        let limits = DROP_BULK;
        let mut budget = IngressBudget::new(limits);
        let mut accepted = 0u64;
        let mut dropped = 0;
        for _ in 0..16 {
            match budget.admit(&binary(MAX_MEDIA_PAYLOAD_BYTES)) {
                Ingress::Accept => accepted += 1,
                Ingress::DropBulk => dropped += 1,
                Ingress::Close => panic!("a burst must not close the socket"),
            }
        }
        assert!(accepted * (MAX_MEDIA_PAYLOAD_BYTES + SEQ_HEADER_BYTES) as u64 <= limits.bulk_bytes_per_second());
        assert!(dropped > 0, "the bulk share is smaller than the burst");
        // A full second of audio still fits on top of the burst.
        for _ in 0..50 {
            assert_eq!(budget.admit(&binary(161)), Ingress::Accept);
        }
    }

    #[tokio::test]
    async fn audio_catching_up_after_a_stall_is_not_closed_by_the_bulk_in_its_window() {
        // A stalled second's audio arrives with the next one's, and video in between.
        let mut budget = IngressBudget::new(DROP_BULK);
        for _ in 0..40 {
            assert_eq!(budget.admit(&binary(1000)), Ingress::Accept);
        }
        for _ in 0..100 {
            assert_eq!(budget.admit(&binary(161)), Ingress::Accept);
        }
        assert_eq!(budget.admit(&binary(161)), Ingress::Close, "audio alone still has its limit");

        // The default mode closes on the same traffic, as it always has.
        let mut budget = IngressBudget::new(MediaLimits::default());
        let mut closed = false;
        for _ in 0..40 {
            closed |= budget.admit(&binary(1000)) == Ingress::Close;
        }
        for _ in 0..100 {
            closed |= budget.admit(&binary(161)) == Ingress::Close;
        }
        assert!(closed);
    }

    #[tokio::test]
    async fn a_flood_of_bulk_packets_still_closes_the_socket() {
        let mut budget = IngressBudget::new(DROP_BULK);
        let mut outcome = Ingress::Accept;
        let mut sent = 0;
        while outcome != Ingress::Close && sent < 1000 {
            outcome = budget.admit(&binary(MAX_MEDIA_PAYLOAD_BYTES));
            sent += 1;
        }
        assert_eq!(outcome, Ingress::Close);
        assert!(sent < 40, "closed after about two budgets, took {sent}");
    }

    #[tokio::test]
    async fn configured_limits_widen_the_socket_budget() {
        let limits = MediaLimits { max_frames_per_second: 160, max_bytes_per_second: 256 * 1024, drop_bulk_over_share: false };
        let mut budget = IngressBudget::new(limits);
        for _ in 0..60 {
            assert_eq!(budget.admit(&binary(MAX_MEDIA_PAYLOAD_BYTES)), Ingress::Accept);
        }
        for _ in 0..50 {
            assert_eq!(budget.admit(&binary(161)), Ingress::Accept);
        }
        // The default budget refuses the same traffic.
        let mut budget = IngressBudget::new(MediaLimits::default());
        let mut refused = false;
        for _ in 0..60 {
            refused |= budget.admit(&binary(MAX_MEDIA_PAYLOAD_BYTES)) != Ingress::Accept;
        }
        assert!(refused);
    }

    #[tokio::test]
    async fn pop_waits_for_a_push_and_ends_on_close() {
        let q = MediaQueue::new(4);
        let waiter = {
            let q = Arc::clone(&q);
            tokio::spawn(async move { q.pop().await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!waiter.is_finished(), "pop waits while empty");
        q.push(frame(1)).unwrap();
        assert_eq!(waiter.await.unwrap(), Some(frame(1)));

        q.push(frame(2)).unwrap();
        q.close();
        assert_eq!(q.push(frame(3)), Err(Closed));
        assert_eq!(q.pop().await, Some(frame(2)), "queued packets drain after close");
        assert_eq!(q.pop().await, None);
        assert!(q.is_closed());
    }

    #[test]
    fn dropping_an_attachment_closes_both_queues_and_releases() {
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (to_node, from_node) = (MediaQueue::new(2), MediaQueue::new(2));
        let flag = Arc::clone(&released);
        let attachment = MediaAttachment::new(
            NodeId::from_bytes([1; 32]),
            Arc::clone(&to_node),
            Arc::clone(&from_node),
            move || flag.store(true, std::sync::atomic::Ordering::SeqCst),
        );
        drop(attachment);
        assert!(to_node.is_closed() && from_node.is_closed());
        assert!(released.load(std::sync::atomic::Ordering::SeqCst));
    }
}
