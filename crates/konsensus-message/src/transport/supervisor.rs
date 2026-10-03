//! Local reconnect policy. Keepalives belong to each connection, not this task.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use konsensus_core::types::NodeId;
use konsensus_crypto::SessionManager;
use tokio::time::Instant;
use tracing::{debug, warn};

use super::{
    handshake::connect_to_peer, NoiseTransport, TransportCtx, HANDSHAKE_TIMEOUT,
    RECONNECT_MAX_DELAY, RECONNECT_MIN_DELAY,
};

pub(super) type SupervisionMap = Arc<Mutex<HashMap<NodeId, Supervision>>>;

pub(super) struct Supervision {
    addr: SocketAddr,
    interest: Arc<Mutex<Interest>>,
    task: tokio::task::AbortHandle,
}

#[derive(Clone, Default)]
struct Interest {
    contact: bool,
    operation: Weak<()>,
    quote_until: Option<Instant>,
}

impl Interest {
    fn wanted(&self, session: bool) -> bool {
        self.contact
            || session
            || self.operation.strong_count() > 0
            || self.quote_until.is_some_and(|until| until > Instant::now())
    }
}

// The map lock serializes retirement with every reason acquisition. A caller
// either retains this worker or observes that it has already retired.
fn retire_if_unwanted(
    entries: &SupervisionMap,
    peer: &NodeId,
    interest: &Arc<Mutex<Interest>>,
    session: bool,
) -> bool {
    let mut entries = entries.lock().unwrap();
    if interest.lock().unwrap().wanted(session) {
        return false;
    }
    if entries
        .get(peer)
        .is_some_and(|e| Arc::ptr_eq(&e.interest, interest))
    {
        entries.remove(peer);
    }
    true
}

impl NoiseTransport {
    /// Local diagnostic snapshot for reconnect failures. No network I/O, secrets,
    /// or writer lock; fields are sampled independently, not an atomic status.
    pub async fn reconnect_diagnostics(&self, peer: &NodeId) -> String {
        let connection = self.peers.read().await.get(peer).map(|conn| {
            (
                conn.connected_at,
                conn.is_closed(),
                conn.admission_paid
                    .load(std::sync::atomic::Ordering::Acquire),
            )
        });
        let supervision = self.supervision.lock().unwrap().get(peer).map(|entry| {
            let interest = entry.interest.lock().unwrap();
            (
                entry.addr,
                entry.task.is_finished(),
                interest.contact,
                interest.operation.strong_count(),
                interest
                    .quote_until
                    .map(|until| until.saturating_duration_since(Instant::now())),
            )
        });
        let dial = self
            .dial_locks
            .lock()
            .unwrap()
            .get(peer)
            .and_then(Weak::upgrade);
        let dial_present = dial.is_some();
        let dial_locked = dial.as_ref().is_some_and(|lock| lock.try_lock().is_err());
        format!(
            "peer={peer}, connection(generation,closed,paid)={connection:?}, \
             supervision(endpoint,finished,contact,operations,quote_remaining)={supervision:?}, \
             dial_present={dial_present}, dial_locked={dial_locked}"
        )
    }

    pub(super) async fn is_whitelisted(&self, peer: &NodeId) -> bool {
        self.whitelist.read().await.contains(peer)
    }

    /// The session owner supplies only a weak reference. Supervision reads live
    /// session existence on every retry and never promotes a Noise connection.
    pub fn set_reconnect_sessions(&self, sessions: &Arc<SessionManager>) {
        *self.reconnect_sessions.write().unwrap() = Some(Arc::downgrade(sessions));
    }

    /// Contacts reconnect regardless of the legacy startup auto_connect flag.
    pub fn start_supervisor(&self, peers: Vec<(NodeId, SocketAddr)>) {
        for (peer, addr) in peers {
            self.supervise_single_peer(peer, addr);
        }
    }

    pub fn supervise_single_peer(&self, peer: NodeId, addr: SocketAddr) {
        self.track_peer(peer, addr, true);
    }

    pub(super) fn stop_supervising(&self, peer: &NodeId) {
        if let Some(entry) = self.supervision.lock().unwrap().remove(peer) {
            entry.task.abort();
        }
    }

    pub(super) fn retain_reconnect(&self, peer: &NodeId) -> Option<Arc<()>> {
        let entries = self.supervision.lock().unwrap();
        let mut interest = entries.get(peer)?.interest.lock().unwrap();
        let handle = interest.operation.upgrade().unwrap_or_else(|| Arc::new(()));
        interest.operation = Arc::downgrade(&handle);
        Some(handle)
    }

    pub(super) fn extend_reconnect(&self, peer: &NodeId, duration: Duration) {
        if let Some(entry) = self.supervision.lock().unwrap().get(peer) {
            let mut interest = entry.interest.lock().unwrap();
            let until = Instant::now() + duration;
            interest.quote_until = Some(interest.quote_until.map_or(until, |old| old.max(until)));
        }
    }

    pub(super) fn track_peer(&self, peer: NodeId, addr: SocketAddr, contact: bool) {
        if *self.shutdown.borrow() {
            return;
        }
        // Persisted inbound-only contacts use 0.0.0.0:0. Never dial a sentinel.
        if addr.port() == 0 || addr.ip().is_unspecified() {
            self.stop_supervising(&peer);
            return;
        }
        let mut entries = self.supervision.lock().unwrap();
        if let Some(entry) = entries.get(&peer) {
            if entry.addr == addr {
                entry.interest.lock().unwrap().contact |= contact;
                return; // Idempotent: no competing supervisors for one peer.
            }
        }
        let interest = entries
            .remove(&peer)
            .map(|old| {
                old.task.abort();
                Arc::new(Mutex::new(old.interest.lock().unwrap().clone()))
            })
            .unwrap_or_default();
        interest.lock().unwrap().contact |= contact;
        let ctx = TransportCtx {
            dial_locks: Arc::clone(&self.dial_locks),
            identity: Arc::clone(&self.identity),
            config: self.config.clone(),
            whitelist: Arc::clone(&self.whitelist),
            peers: Arc::clone(&self.peers),
            banned_peers: Arc::clone(&self.banned_peers),
            incoming_tx: self.incoming_tx.clone(),
            control_tx: self.control_tx.clone(),
            cookie_keyring: Arc::clone(&self.cookie_keyring),
            shutdown: self.shutdown.subscribe(),
        };
        let mut shutdown = self.shutdown.subscribe();
        let sessions = Arc::clone(&self.reconnect_sessions);
        let entries_weak = Arc::downgrade(&self.supervision);
        let worker_interest = Arc::clone(&interest);
        let task = tokio::spawn(async move {
            let stopped = *shutdown.borrow();
            let run = async {
                if stopped {
                    return;
                }
                let mut backoff = RECONNECT_MIN_DELAY;
                loop {
                    if ctx.peers.read().await.contains_key(&peer) {
                        backoff = RECONNECT_MIN_DELAY;
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                    let manager = sessions.read().unwrap().as_ref().and_then(Weak::upgrade);
                    let session = match manager {
                        Some(manager) => manager.has_session(&peer).await,
                        None => false,
                    };
                    let Some(entries) = entries_weak.upgrade() else {
                        break;
                    };
                    if retire_if_unwanted(&entries, &peer, &worker_interest, session) {
                        break;
                    }
                    drop(entries);
                    let banned = ctx
                        .banned_peers
                        .read()
                        .await
                        .get(&peer)
                        .is_some_and(|until| *until > std::time::Instant::now());
                    if banned {
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(RECONNECT_MAX_DELAY);
                        continue;
                    }
                    // Bound the whole dial, including the TCP connect. Cancellation
                    // (contact removal/shutdown) also cancels an in-flight handshake.
                    let result = tokio::time::timeout(
                        HANDSHAKE_TIMEOUT * 3,
                        connect_to_peer(&peer, &addr, &ctx),
                    )
                    .await;
                    if !matches!(result, Ok(Ok(()))) {
                        warn!(%peer, ?result, "supervisor: dial failed");
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(RECONNECT_MAX_DELAY);
                    }
                }
            };
            tokio::select! {
                _ = run => {},
                _ = shutdown.changed() => {},
            }
            if let Some(entries) = entries_weak.upgrade() {
                let mut entries = entries.lock().unwrap();
                if entries
                    .get(&peer)
                    .is_some_and(|e| Arc::ptr_eq(&e.interest, &worker_interest))
                {
                    entries.remove(&peer);
                }
            }
            debug!(%peer, "supervisor: stopped");
        });
        entries.insert(
            peer,
            Supervision {
                addr,
                interest,
                task: task.abort_handle(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_prevents_late_supervision_and_dials() {
        use konsensus_core::traits::transport::MessageTransport;
        let identity = super::super::tests::make_identity(super::super::tests::TEST_MNEMONIC_A);
        let peer = *identity.node_id();
        let transport = NoiseTransport::new(
            identity,
            super::super::TransportConfig {
                admission_mode: super::super::ReachabilityMode::PriceOpen,
                ..Default::default()
            },
        );
        // No receiver exists yet: shutdown must still remain visible to new tasks.
        transport.shutdown();
        transport.supervise_single_peer(peer, "127.0.0.1:9735".parse().unwrap());
        assert!(transport.supervision.lock().unwrap().is_empty());
        let error = transport
            .connect(&peer, "127.0.0.1:9735")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("shut down"));
    }

    #[tokio::test]
    async fn acquiring_interest_before_retirement_keeps_worker_and_removal_cancels_it() {
        let identity = super::super::tests::make_identity(super::super::tests::TEST_MNEMONIC_A);
        let peer = *identity.node_id();
        let transport = NoiseTransport::new(identity, Default::default());
        let interest = Arc::new(Mutex::new(Interest::default()));
        // A dormant worker lets us exercise retirement atomically without sockets.
        let worker = tokio::spawn(std::future::pending::<()>());
        transport.supervision.lock().unwrap().insert(
            peer,
            Supervision {
                addr: "127.0.0.1:9735".parse().unwrap(),
                interest: interest.clone(),
                task: worker.abort_handle(),
            },
        );
        let operation = transport.retain_reconnect(&peer).unwrap();
        assert!(!retire_if_unwanted(
            &transport.supervision,
            &peer,
            &interest,
            false
        ));
        drop(operation);
        transport.supervise_single_peer(peer, "127.0.0.1:9735".parse().unwrap());
        assert!(!retire_if_unwanted(
            &transport.supervision,
            &peer,
            &interest,
            false
        ));
        transport.stop_supervising(&peer);
        assert!(worker.await.unwrap_err().is_cancelled());
        assert!(transport.supervision.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_reasons_expire_without_turning_strangers_into_contacts() {
        let mut interest = Interest::default();
        assert!(!interest.wanted(false));
        assert!(interest.wanted(true));
        let operation = Arc::new(());
        interest.operation = Arc::downgrade(&operation);
        assert!(interest.wanted(false));
        drop(operation);
        assert!(!interest.wanted(false));
        interest.quote_until = Some(Instant::now() + Duration::from_secs(60));
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(interest.wanted(false));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(!interest.wanted(false));
        interest.contact = true;
        assert!(interest.wanted(false));
    }
}
