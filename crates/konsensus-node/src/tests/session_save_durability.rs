//! A store write can finish after the future that asked for it is dropped, as a sqlx
//! query does on its worker. These tests hold such a write open over real SQLite, drop
//! the caller, and check that it cannot land on top of a newer send chain.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use konsensus_core::{NodeId, NodeIdentity};
use konsensus_crypto::{SessionManager, SessionStore};
use tokio::sync::Notify;

type StoreResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Real SQLite underneath. When armed, the next write runs on a task of its own, as on
/// a database worker, and waits for the gate: dropping the caller does not cancel it.
struct GatedStore {
    inner: Arc<crate::StorageSessionAdapter>,
    armed: AtomicBool,
    queued: Notify,
    gate: Arc<Notify>,
    worker: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[async_trait::async_trait]
impl SessionStore for GatedStore {
    async fn save_session(&self, peer: &NodeId, state: &[u8]) -> StoreResult<()> {
        if self.armed.swap(false, Ordering::SeqCst) {
            let (inner, gate, peer, state) = (Arc::clone(&self.inner), Arc::clone(&self.gate), *peer, state.to_vec());
            let (done, finished) = tokio::sync::oneshot::channel();
            let worker = tokio::spawn(async move {
                gate.notified().await;
                let saved = inner.save_session(&peer, &state).await.map_err(|e| e.to_string());
                let _ = done.send(saved);
            });
            *self.worker.lock().unwrap() = Some(worker);
            self.queued.notify_one();
            return finished.await.unwrap().map_err(Into::into);
        }
        self.inner.save_session(peer, state).await
    }
    async fn load_session(&self, peer: &NodeId) -> StoreResult<Option<Vec<u8>>> {
        self.inner.load_session(peer).await
    }
    async fn delete_session(&self, peer: &NodeId) -> StoreResult<()> {
        if self.armed.swap(false, Ordering::SeqCst) {
            let (inner, gate, peer) = (Arc::clone(&self.inner), Arc::clone(&self.gate), *peer);
            let (done, finished) = tokio::sync::oneshot::channel();
            let worker = tokio::spawn(async move {
                gate.notified().await;
                let deleted = inner.delete_session(&peer).await.map_err(|e| e.to_string());
                let _ = done.send(deleted);
            });
            *self.worker.lock().unwrap() = Some(worker);
            self.queued.notify_one();
            return finished.await.unwrap().map_err(Into::into);
        }
        self.inner.delete_session(peer).await
    }
    async fn list_sessions(&self) -> StoreResult<Vec<NodeId>> {
        self.inner.list_sessions().await
    }
}

struct Lane {
    store: Arc<GatedStore>,
    identity: Arc<NodeIdentity>,
    sender: Arc<SessionManager>,
    receiver: SessionManager,
    our_id: NodeId,
    peer: NodeId,
    _dir: tempfile::TempDir,
}

async fn lane() -> Lane {
    let dir = tempfile::tempdir().unwrap();
    let storage: Arc<dyn konsensus_storage::Storage> = Arc::new(
        konsensus_storage::SqliteStorage::open(dir.path().join("node.sqlite").to_str().unwrap()).await.unwrap(),
    );
    let store = Arc::new(GatedStore {
        inner: Arc::new(crate::StorageSessionAdapter { storage }),
        armed: AtomicBool::new(false),
        queued: Notify::new(),
        gate: Arc::new(Notify::new()),
        worker: std::sync::Mutex::new(None),
    });
    let identity = Arc::new(NodeIdentity::generate().unwrap().1);
    let other = Arc::new(NodeIdentity::generate().unwrap().1);
    let (our_id, peer) = (*identity.node_id(), *other.node_id());
    let sender = Arc::new(SessionManager::with_store(Arc::clone(&identity), store.clone()));
    let receiver = SessionManager::new(other);
    let init = sender.initiate_session(&peer, &receiver.prekey_bundle().await).await.unwrap();
    receiver.accept_session(&our_id, &init).await.unwrap();
    Lane { store, identity, sender, receiver, our_id, peer, _dir: dir }
}

impl Lane {
    /// Finish the held write, whether or not anything still waits for it.
    async fn release_worker(&self) {
        self.store.gate.notify_one();
        let worker = self.store.worker.lock().unwrap().take().expect("a write was held");
        worker.await.unwrap();
    }

    /// The node after a restart, reading what reached the database.
    async fn restarted(&self) -> SessionManager {
        let restarted = SessionManager::with_store(Arc::clone(&self.identity), self.store.clone());
        restarted.restore_sessions().await;
        restarted
    }
}

/// A send is dropped with its save held on the worker. A second send follows. Whatever
/// order the two reach the database in, the restored chain must not repeat a position
/// that left this node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_send_cannot_rewind_a_newer_send_chain() {
    let net = lane().await;
    let first = net.sender.encrypt(&net.peer, b"saved").await.unwrap();
    assert_eq!(net.receiver.decrypt(&net.our_id, &first).await.unwrap(), b"saved");

    net.store.armed.store(true, Ordering::SeqCst);
    let dropped = tokio::spawn({
        let (sender, peer) = (Arc::clone(&net.sender), net.peer);
        async move { sender.encrypt(&peer, b"dropped").await }
    });
    net.store.queued.notified().await;
    dropped.abort();
    assert!(dropped.await.unwrap_err().is_cancelled());

    let second = tokio::spawn({
        let (sender, peer) = (Arc::clone(&net.sender), net.peer);
        async move { sender.encrypt(&peer, b"second").await }
    });
    // Give the second send every chance to overtake the held write.
    tokio::time::sleep(Duration::from_millis(500)).await;
    net.release_worker().await;
    let second = second.await.unwrap().unwrap();
    assert_eq!(net.receiver.decrypt(&net.our_id, &second).await.unwrap(), b"second");

    let restarted = net.restarted().await;
    let next = restarted.encrypt(&net.peer, b"after the restart").await.unwrap();
    assert!(
        next.header.message_number > second.header.message_number,
        "position {} was already used; the restored chain gives {}",
        second.header.message_number,
        next.header.message_number
    );
    assert_eq!(net.receiver.decrypt(&net.our_id, &next).await.unwrap(), b"after the restart");
}

/// The same with a dropped receive: its save must not rewind the send chain either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_receive_cannot_rewind_a_newer_send_chain() {
    let net = lane().await;
    let first = net.sender.encrypt(&net.peer, b"first").await.unwrap();
    net.receiver.decrypt(&net.our_id, &first).await.unwrap();
    let incoming = net.receiver.encrypt(&net.our_id, b"reply").await.unwrap();

    net.store.armed.store(true, Ordering::SeqCst);
    let dropped = tokio::spawn({
        let (sender, peer) = (Arc::clone(&net.sender), net.peer);
        async move { sender.decrypt(&peer, &incoming).await }
    });
    net.store.queued.notified().await;
    dropped.abort();
    assert!(dropped.await.unwrap_err().is_cancelled());

    let sent = tokio::spawn({
        let (sender, peer) = (Arc::clone(&net.sender), net.peer);
        async move { sender.encrypt(&peer, b"sent").await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    net.release_worker().await;
    let sent = sent.await.unwrap().unwrap();

    let restarted = net.restarted().await;
    let next = restarted.encrypt(&net.peer, b"after the restart").await.unwrap();
    assert!(
        (next.header.dh_public, next.header.message_number) != (sent.header.dh_public, sent.header.message_number),
        "the restored chain repeats a position that left"
    );
    assert!(
        next.header.dh_public != sent.header.dh_public || next.header.message_number > sent.header.message_number,
        "the restored chain went backwards"
    );
}

/// A dropped removal with its delete held must not take a newer session with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_removal_cannot_delete_a_newer_session() {
    let net = lane().await;
    let first = net.sender.encrypt(&net.peer, b"first").await.unwrap();
    net.receiver.decrypt(&net.our_id, &first).await.unwrap();

    net.store.armed.store(true, Ordering::SeqCst);
    let dropped = tokio::spawn({
        let (sender, peer) = (Arc::clone(&net.sender), net.peer);
        async move { sender.remove_session(&peer).await }
    });
    net.store.queued.notified().await;
    dropped.abort();
    assert!(dropped.await.unwrap_err().is_cancelled());

    let far_end = SessionManager::new(Arc::new(NodeIdentity::generate().unwrap().1));
    let bundle = far_end.prekey_bundle().await;
    let installed = tokio::spawn({
        let (sender, peer) = (Arc::clone(&net.sender), net.peer);
        async move {
            sender.initiate_session(&peer, &bundle).await.unwrap();
            sender.encrypt(&peer, b"on the new session").await.unwrap()
        }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    net.release_worker().await;
    let sent = installed.await.unwrap();

    let restarted = net.restarted().await;
    assert!(restarted.has_session(&net.peer).await, "the newer session was deleted");
    let next = restarted.encrypt(&net.peer, b"after the restart").await.unwrap();
    assert_eq!(next.header.dh_public, sent.header.dh_public, "the newer session is the one restored");
    assert!(next.header.message_number > sent.header.message_number);
}
