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
//! bounded drop-oldest [`MediaQueue`] both sides share and the socket.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use konsensus_core::types::NodeId;
use serde::Deserialize;
use tokio::sync::Notify;
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
    closed: bool,
    dropped: u64,
}

/// A bounded packet queue that drops the **oldest** packet when full, so a
/// slow consumer costs stale audio, never a blocked producer and never
/// unbounded memory. Closing it wakes the consumer with `None`.
pub struct MediaQueue {
    state: Mutex<QueueState>,
    notify: Notify,
}

impl MediaQueue {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueueState {
                frames: VecDeque::with_capacity(capacity.max(1)),
                capacity: capacity.max(1),
                closed: false,
                dropped: 0,
            }),
            notify: Notify::new(),
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
            let dropped = if q.frames.len() >= q.capacity {
                q.frames.pop_front();
                q.dropped += 1;
                1
            } else {
                0
            };
            q.frames.push_back(frame);
            dropped
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
                if let Some(frame) = q.frames.pop_front() {
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
        self.lock().frames.pop_front()
    }

    /// Stop accepting packets; queued ones can still be popped.
    pub fn close(&self) {
        self.lock().closed = true;
        self.notify.notify_waiters();
        self.notify.notify_one();
    }

    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }

    pub fn len(&self) -> usize {
        self.lock().frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Packets evicted so far to make room.
    pub fn dropped(&self) -> u64 {
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
        Self { peer, to_node, from_node, release: Some(Box::new(release)) }
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
    ws.protocols([crate::ws::WS_PROTOCOL])
        .on_upgrade(move |socket| handle_media(socket, state, claims, attachment))
        .into_response()
}

/// Keepalive ping interval, as on `/api/v1/ws`.
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(45);

/// How often the token and pairing are re-checked while the socket is open.
const AUTH_RECHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

async fn handle_media(mut socket: WebSocket, state: Arc<AppState>, claims: auth::Claims, attachment: MediaAttachment) {
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.tick().await;
    let mut recheck = tokio::time::interval(AUTH_RECHECK_INTERVAL);
    recheck.tick().await;
    let mut malformed: u64 = 0;

    loop {
        tokio::select! {
            // The peer's packets, to the app.
            frame = attachment.from_node.pop() => {
                match frame {
                    Some(frame) => {
                        if socket.send(Message::Binary(frame.to_ws_bytes())).await.is_err() {
                            debug!("call media socket closed by the app");
                            break;
                        }
                    }
                    None => {
                        // The router ended the call's media.
                        let _ = socket.send(Message::Close(None)).await;
                        break;
                    }
                }
            }

            // The app's packets, to the node.
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Binary(bytes))) => match MediaFrame::from_ws_bytes(&bytes) {
                        Some(frame) => {
                            if attachment.to_node.push(frame).is_err() {
                                let _ = socket.send(Message::Close(None)).await;
                                break;
                            }
                        }
                        None => {
                            malformed += 1;
                            if malformed == 1 {
                                warn!(len = bytes.len(), "call media socket: malformed or oversize packet dropped (further ones counted only)");
                            }
                        }
                    },
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(val) = konsensus_core::wire_json::from_str::<serde_json::Value>(&text) {
                            if val.get("type").and_then(|t| t.as_str()) == Some("ping")
                                && socket.send(Message::Text(r#"{"type":"pong"}"#.to_string())).await.is_err()
                            {
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        debug!("call media socket closed");
                        break;
                    }
                    Some(Err(e)) => {
                        debug!(error = %e, "call media socket error");
                        break;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                }
            }

            // Revocation, rebinding or expiry closes an open socket.
            _ = recheck.tick() => {
                if !stream_authorized(&state, &claims) {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            }

            _ = keepalive.tick() => {
                if socket.send(Message::Ping(vec![0x6b, 0x61])).await.is_err() {
                    break;
                }
            }
        }
    }
    if malformed > 0 {
        debug!(malformed, "call media socket: malformed packets dropped");
    }
    // Dropping the attachment detaches the call from the router.
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
