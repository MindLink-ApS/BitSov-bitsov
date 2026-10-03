//! Bounded, connection-local replies. The dispatcher never waits for socket I/O.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

const REPLY_CAPACITY: usize = 8;
const REPLY_DEADLINE: Duration = Duration::from_secs(1);
const MAX_REPLY_BYTES: usize = 4096;
// Only the quote-first discovery service uses larger replies. The signed,
// hex-encoded snapshot (24 KiB decoded) plus an 8 KiB invoice fits in one Noise
// record. The same queue capacity, write deadline and close-on-failure apply.
const MAX_PEER_EXCHANGE_REPLY_BYTES: usize = 60_000;

pub(super) struct Connection {
    outbound: bool,
    state: Mutex<PeerConnection>,
    replies: mpsc::Sender<Vec<u8>>,
    socket: socket2::Socket,
    closed: AtomicBool,
    pub(super) admission_paid: AtomicBool,
    pub(super) connected_at: Instant,
}

impl Connection {
    pub(super) fn new(
        state: PeerConnection,
        peer: NodeId,
        peers: PeerMap,
        outbound: bool,
    ) -> Result<Arc<Self>, TransportError> {
        let socket = socket2::SockRef::from(state.writer.as_ref())
            .try_clone()
            .map_err(|e| TransportError::Other(e.to_string()))?;
        let (replies, mut rx) = mpsc::channel::<Vec<u8>>(REPLY_CAPACITY);
        let connected_at = state.connected_at;
        let conn = Arc::new(Self {
            outbound,
            admission_paid: AtomicBool::new(false),
            connected_at,
            state: Mutex::new(state),
            replies,
            socket,
            closed: AtomicBool::new(false),
        });
        let weak = Arc::downgrade(&conn);
        let peers = Arc::downgrade(&peers);
        tokio::spawn(async move {
            while let Some(bytes) = rx.recv().await {
                let Some(conn) = weak.upgrade() else { break };
                let result = tokio::time::timeout(REPLY_DEADLINE, async {
                    let mut state = conn.lock().await;
                    if conn.closed.load(Ordering::Acquire) {
                        return Err(TransportError::NotConnected(peer.to_hex()));
                    }
                    let encrypted = state
                        .noise
                        .encrypt(&bytes)
                        .map_err(|e| TransportError::NoiseError(e.to_string()))?;
                    write_noise_message(&mut state.writer, &encrypted)
                        .await
                        .map_err(|e| TransportError::Other(e.to_string()))
                })
                .await;
                if !matches!(result, Ok(Ok(()))) {
                    if let Some(peers) = peers.upgrade() {
                        conn.remove(&peer, &peers).await;
                    } else {
                        conn.close();
                    }
                    break;
                }
            }
        });
        Ok(conn)
    }

    /// Both endpoints select the lower NodeId as initiator when opposite
    /// directions collide. A sole connection is accepted in either direction.
    /// Rejected candidates never publish a reader or PeerConnected event.
    pub(super) async fn register(self: &Arc<Self>, local: &NodeId, peer: &NodeId, peers: &PeerMap) -> bool {
        let mut peers = peers.write().await;
        if let Some(old) = peers.get(peer) {
            if !old.is_closed() && prefer_existing_direction(local, peer, old.outbound, self.outbound) {
                self.close();
                return false;
            }
        }
        if let Some(old) = peers.insert(*peer, Arc::clone(self)) { old.close(); }
        true
    }

    pub(super) async fn lock(&self) -> tokio::sync::MutexGuard<'_, PeerConnection> {
        self.state.lock().await
    }

    /// Closed (replaced, removed or failed). Read under [`Self::lock`] so a
    /// writer never writes to a connection closed before it got the lock.
    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }

    pub(super) async fn remove(self: &Arc<Self>, peer: &NodeId, peers: &PeerMap) {
        self.close();
        let mut peers = peers.write().await;
        if peers
            .get(peer)
            .is_some_and(|current| Arc::ptr_eq(current, self))
        {
            peers.remove(peer);
        }
    }
}

impl NoiseTransport {
    /// Queue a bounded control reply without waiting for the peer's write lock or
    /// socket. Backpressure closes this connection; every write has a deadline.
    pub async fn enqueue_control_frame(
        &self,
        peer: &NodeId,
        frame: &Frame,
    ) -> Result<(), TransportError> {
        let conn = self
            .peers
            .read()
            .await
            .get(peer)
            .cloned()
            .ok_or_else(|| TransportError::NotConnected(peer.to_hex()))?;
        let bytes = frame
            .to_bytes()
            .map_err(|e| TransportError::WireProtocol(e.to_string()))?;
        let max_bytes = match frame {
            Frame::PeerExchangeQuote { .. } | Frame::PeerExchangeResponse { .. } => MAX_PEER_EXCHANGE_REPLY_BYTES,
            _ => MAX_REPLY_BYTES,
        };
        if bytes.len() > max_bytes
            || conn.closed.load(Ordering::Acquire)
            || conn.replies.try_send(bytes).is_err()
        {
            conn.remove(peer, &self.peers).await;
            return Err(TransportError::Other(
                "control reply backpressure: connection closed".into(),
            ));
        }
        Ok(())
    }
}


// Only opposite-direction duplicates are arbitrated. A fresh handshake in the
// same direction can replace a stale socket after a remote restart.
fn prefer_existing_direction(local: &NodeId, peer: &NodeId, old_outbound: bool, new_outbound: bool) -> bool {
    old_outbound != new_outbound && old_outbound == (local.as_bytes() < peer.as_bytes())
}

#[cfg(test)]
mod duplicate_direction_tests {
    use super::*;

    #[test]
    fn crossed_registrations_choose_the_same_socket_in_either_order() {
        let a = super::super::tests::make_identity(super::super::tests::TEST_MNEMONIC_A);
        let b = super::super::tests::make_identity(super::super::tests::TEST_MNEMONIC_B);
        let (low, high) = if a.node_id().as_bytes() < b.node_id().as_bytes() { (a.node_id(), b.node_id()) } else { (b.node_id(), a.node_id()) };
        // Low keeps its outbound; High keeps the matching inbound, regardless
        // of which socket completed registration first on each side.
        assert!(prefer_existing_direction(low, high, true, false));
        assert!(!prefer_existing_direction(low, high, false, true));
        assert!(prefer_existing_direction(high, low, false, true));
        assert!(!prefer_existing_direction(high, low, true, false));
        assert!(!prefer_existing_direction(low, high, true, true));
        assert!(!prefer_existing_direction(high, low, false, false));
    }
}
