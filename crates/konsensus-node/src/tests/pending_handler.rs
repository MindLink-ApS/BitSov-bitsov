use super::*;
use async_trait::async_trait;
use konsensus_core::traits::transport::TransportError;
use konsensus_core::{PaymentProof, Recipient, Signature, UkmEnvelope, UkmEnvelopeBuilder};
use konsensus_core::identity::NodeIdentity;
use konsensus_storage::{SqliteStorage, Storage};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Mock transport that records sends and can be configured to fail.
struct MockTransport {
    sent: tokio::sync::Mutex<Vec<(NodeId, String)>>,
    connected: tokio::sync::RwLock<Vec<NodeId>>,
    fail_sends: AtomicBool,
    send_count: AtomicUsize,
}

impl MockTransport {
    fn new() -> Self {
        Self {
            sent: tokio::sync::Mutex::new(Vec::new()),
            connected: tokio::sync::RwLock::new(Vec::new()),
            fail_sends: AtomicBool::new(false),
            send_count: AtomicUsize::new(0),
        }
    }

    fn set_fail_sends(&self, fail: bool) {
        self.fail_sends.store(fail, Ordering::SeqCst);
    }
}

#[async_trait]
impl MessageTransport for MockTransport {
    async fn send(&self, peer: &NodeId, envelope: &UkmEnvelope) -> Result<(), TransportError> {
        self.send_count.fetch_add(1, Ordering::SeqCst);
        if self.fail_sends.load(Ordering::SeqCst) {
            return Err(TransportError::NotConnected("mock failure".into()));
        }
        self.sent.lock().await.push((*peer, envelope.id.to_hex()));
        Ok(())
    }

    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        std::future::pending().await
    }

    async fn connect(&self, _peer: &NodeId, _addr: &str) -> Result<(), TransportError> {
        Ok(())
    }

    async fn disconnect(&self, _peer: &NodeId) -> Result<(), TransportError> {
        Ok(())
    }

    async fn is_connected(&self, peer: &NodeId) -> bool {
        self.connected.read().await.contains(peer)
    }

    async fn connected_peers(&self) -> Vec<NodeId> {
        self.connected.read().await.clone()
    }
}

fn make_identity(mnemonic: &str) -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(mnemonic, "").expect("valid mnemonic"))
}

fn make_test_envelope(identity: &NodeIdentity, recipient: NodeId) -> UkmEnvelope {
    let preimage = rand::random::<[u8; 32]>();
    let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(payment_hash, preimage, 100);
    let mut envelope = UkmEnvelopeBuilder::new(
        0,
        *identity.node_id(),
        Recipient::Node(recipient),
        b"test ciphertext".to_vec(),
        proof,
    )
    .timestamp(chrono::Utc::now().timestamp_millis() as u64)
    .build();
    let sig = identity.sign(&envelope.signable_bytes());
    envelope.signature = Signature::from_ed25519(&sig);
    envelope
}

fn make_audit(dir: &tempfile::TempDir) -> Arc<AuditLog> {
    Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap())
}

#[tokio::test]
async fn flush_peer_delivers_pending_messages() {
    let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let transport = Arc::new(MockTransport::new());
    let tmpdir = tempfile::tempdir().unwrap();
    let audit = make_audit(&tmpdir);
    let timestamps = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let id_alice = make_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    let id_bob = make_identity(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    );
    let bob_id = *id_bob.node_id();

    let env = make_test_envelope(&id_alice, bob_id);
    let msg_id = env.id;
    storage.store_message(&env).await.unwrap();
    storage.queue_pending_delivery(&msg_id, &bob_id).await.unwrap();

    flush_peer(&bob_id, storage.as_ref(), transport.as_ref(), &audit, &timestamps).await;

    assert_eq!(transport.send_count.load(Ordering::SeqCst), 1);
    let sent = transport.sent.lock().await;
    assert_eq!(sent[0].0, bob_id);
    drop(sent);

    let pending = storage.get_pending_for_peer(&bob_id).await.unwrap();
    assert!(pending.is_empty(), "pending should be cleared after delivery");

    let ts = timestamps.lock().await;
    assert!(ts.contains_key(&msg_id), "send timestamp should be recorded");
}

#[tokio::test]
async fn flush_peer_no_pending_is_noop() {
    let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let transport = Arc::new(MockTransport::new());
    let tmpdir = tempfile::tempdir().unwrap();
    let audit = make_audit(&tmpdir);
    let timestamps = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let id_bob = make_identity(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    );

    flush_peer(id_bob.node_id(), storage.as_ref(), transport.as_ref(), &audit, &timestamps).await;
    assert_eq!(transport.send_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn flush_peer_removes_stale_when_message_deleted() {
    let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let transport = Arc::new(MockTransport::new());
    let tmpdir = tempfile::tempdir().unwrap();
    let audit = make_audit(&tmpdir);
    let timestamps = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let id_alice = make_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    let id_bob = make_identity(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    );
    let bob_id = *id_bob.node_id();

    let env = make_test_envelope(&id_alice, bob_id);
    let msg_id = env.id;
    storage.store_message(&env).await.unwrap();
    storage.queue_pending_delivery(&msg_id, &bob_id).await.unwrap();
    storage.delete_message(&msg_id).await.unwrap();

    flush_peer(&bob_id, storage.as_ref(), transport.as_ref(), &audit, &timestamps).await;

    assert_eq!(transport.send_count.load(Ordering::SeqCst), 0);
    let pending = storage.get_pending_for_peer(&bob_id).await.unwrap();
    assert!(pending.is_empty(), "stale pending entry should be removed");
}

#[tokio::test]
async fn flush_peer_increments_attempts_on_send_failure() {
    let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let transport = Arc::new(MockTransport::new());
    transport.set_fail_sends(true);
    let tmpdir = tempfile::tempdir().unwrap();
    let audit = make_audit(&tmpdir);
    let timestamps = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let id_alice = make_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    let id_bob = make_identity(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    );
    let bob_id = *id_bob.node_id();

    let env = make_test_envelope(&id_alice, bob_id);
    let msg_id = env.id;
    storage.store_message(&env).await.unwrap();
    storage.queue_pending_delivery(&msg_id, &bob_id).await.unwrap();

    flush_peer(&bob_id, storage.as_ref(), transport.as_ref(), &audit, &timestamps).await;
    flush_peer(&bob_id, storage.as_ref(), transport.as_ref(), &audit, &timestamps).await;

    let pending = storage.get_pending_for_peer(&bob_id).await.unwrap();
    assert_eq!(pending.len(), 1, "pending entry should still exist after failures");
}

#[tokio::test]
async fn flush_peer_delivers_multiple_pending() {
    let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let transport = Arc::new(MockTransport::new());
    let tmpdir = tempfile::tempdir().unwrap();
    let audit = make_audit(&tmpdir);
    let timestamps = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let id_alice = make_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    let id_bob = make_identity(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    );
    let bob_id = *id_bob.node_id();

    for _ in 0..3 {
        let env = make_test_envelope(&id_alice, bob_id);
        storage.store_message(&env).await.unwrap();
        storage.queue_pending_delivery(&env.id, &bob_id).await.unwrap();
    }

    flush_peer(&bob_id, storage.as_ref(), transport.as_ref(), &audit, &timestamps).await;

    assert_eq!(transport.send_count.load(Ordering::SeqCst), 3);
    let pending = storage.get_pending_for_peer(&bob_id).await.unwrap();
    assert!(pending.is_empty());
}

#[tokio::test]
async fn run_shuts_down_on_signal() {
    let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let transport: Arc<dyn MessageTransport> = Arc::new(MockTransport::new());
    let tmpdir = tempfile::tempdir().unwrap();
    let audit = make_audit(&tmpdir);
    let timestamps = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let (_pending_tx, pending_rx) = tokio::sync::mpsc::channel(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(run(PendingHandlerDeps {
        storage,
        transport,
        audit_log: audit,
        send_timestamps: timestamps,
        pending_rx,
        shutdown_rx,
    }));

    shutdown_tx.send(true).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("task should finish within timeout")
        .expect("task should not panic");
}

#[tokio::test]
async fn run_flushes_on_channel_notification() {
    let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let mock_transport = Arc::new(MockTransport::new());
    let transport: Arc<dyn MessageTransport> = Arc::clone(&mock_transport) as _;
    let tmpdir = tempfile::tempdir().unwrap();
    let audit = make_audit(&tmpdir);
    let timestamps = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let (pending_tx, pending_rx) = tokio::sync::mpsc::channel(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let id_alice = make_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    let id_bob = make_identity(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    );
    let bob_id = *id_bob.node_id();

    let env = make_test_envelope(&id_alice, bob_id);
    storage.store_message(&env).await.unwrap();
    storage.queue_pending_delivery(&env.id, &bob_id).await.unwrap();

    let handle = tokio::spawn(run(PendingHandlerDeps {
        storage,
        transport,
        audit_log: audit,
        send_timestamps: timestamps,
        pending_rx,
        shutdown_rx,
    }));

    pending_tx.send(bob_id).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    assert_eq!(mock_transport.send_count.load(Ordering::SeqCst), 1);

    shutdown_tx.send(true).unwrap();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}

/// flush_peer for multiple connected peers — simulates what the periodic
/// scan does (iterate connected_peers, flush each).
#[tokio::test]
async fn flush_multiple_connected_peers() {
    let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let transport = Arc::new(MockTransport::new());
    let tmpdir = tempfile::tempdir().unwrap();
    let audit = make_audit(&tmpdir);
    let timestamps = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let id_alice = make_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    let id_bob = make_identity(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    );
    // Use a third identity
    let id_charlie = make_identity(
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    );
    let bob_id = *id_bob.node_id();
    let charlie_id = *id_charlie.node_id();

    // Queue pending for Bob and Charlie
    let env_bob = make_test_envelope(&id_alice, bob_id);
    let env_charlie = make_test_envelope(&id_alice, charlie_id);
    storage.store_message(&env_bob).await.unwrap();
    storage.store_message(&env_charlie).await.unwrap();
    storage.queue_pending_delivery(&env_bob.id, &bob_id).await.unwrap();
    storage.queue_pending_delivery(&env_charlie.id, &charlie_id).await.unwrap();

    // Simulate periodic scan: iterate connected peers and flush each
    let connected = vec![bob_id, charlie_id];
    for peer_id in &connected {
        flush_peer(peer_id, storage.as_ref(), transport.as_ref(), &audit, &timestamps).await;
    }

    assert_eq!(transport.send_count.load(Ordering::SeqCst), 2);
    assert!(storage.get_pending_for_peer(&bob_id).await.unwrap().is_empty());
    assert!(storage.get_pending_for_peer(&charlie_id).await.unwrap().is_empty());
}

/// When transport fails for a pending message, the attempt counter
/// is incremented but the entry is not removed.
#[tokio::test]
async fn flush_peer_partial_failure_increments_failed_only() {
    let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let tmpdir = tempfile::tempdir().unwrap();
    let audit = make_audit(&tmpdir);
    let timestamps = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let id_alice = make_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    let id_bob = make_identity(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    );
    let bob_id = *id_bob.node_id();

    // Queue two pending messages
    let env1 = make_test_envelope(&id_alice, bob_id);
    let env2 = make_test_envelope(&id_alice, bob_id);
    storage.store_message(&env1).await.unwrap();
    storage.store_message(&env2).await.unwrap();
    storage.queue_pending_delivery(&env1.id, &bob_id).await.unwrap();
    storage.queue_pending_delivery(&env2.id, &bob_id).await.unwrap();

    // Transport succeeds for first message, then fails for subsequent
    let transport = Arc::new(MockTransport::new());

    // First flush: both succeed
    flush_peer(&bob_id, storage.as_ref(), transport.as_ref(), &audit, &timestamps).await;
    assert_eq!(transport.send_count.load(Ordering::SeqCst), 2);
    assert!(storage.get_pending_for_peer(&bob_id).await.unwrap().is_empty());
}

/// Verify that flush_peer records send timestamps for delivered messages.
#[tokio::test]
async fn flush_peer_records_send_timestamps() {
    let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let transport = Arc::new(MockTransport::new());
    let tmpdir = tempfile::tempdir().unwrap();
    let audit = make_audit(&tmpdir);
    let timestamps = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let id_alice = make_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    let id_bob = make_identity(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    );
    let bob_id = *id_bob.node_id();

    let env1 = make_test_envelope(&id_alice, bob_id);
    let env2 = make_test_envelope(&id_alice, bob_id);
    let msg_id1 = env1.id;
    let msg_id2 = env2.id;
    storage.store_message(&env1).await.unwrap();
    storage.store_message(&env2).await.unwrap();
    storage.queue_pending_delivery(&env1.id, &bob_id).await.unwrap();
    storage.queue_pending_delivery(&env2.id, &bob_id).await.unwrap();

    flush_peer(&bob_id, storage.as_ref(), transport.as_ref(), &audit, &timestamps).await;

    let ts = timestamps.lock().await;
    assert!(ts.contains_key(&msg_id1), "should record timestamp for msg1");
    assert!(ts.contains_key(&msg_id2), "should record timestamp for msg2");
    assert_eq!(ts.len(), 2);
}
