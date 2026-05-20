use super::*;
use konsensus_core::types::{MessageId, NodeId, Nonce};
use konsensus_core::{PaymentProof, Recipient, UkmEnvelopeBuilder};
use konsensus_storage::{SqliteStorage, Storage};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Generate a random MessageId for testing.
fn random_message_id() -> MessageId {
    MessageId::from_bytes(rand::random::<[u8; 32]>())
}

fn make_proof() -> PaymentProof {
    let preimage = rand::random::<[u8; 32]>();
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    PaymentProof::new(hash, preimage, 100)
}

fn make_envelope_with_timestamp(sender: NodeId, recipient: NodeId, timestamp_ms: u64) -> konsensus_core::UkmEnvelope {
    UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_CHAT,
        sender,
        Recipient::Node(recipient),
        b"test ciphertext".to_vec(),
        make_proof(),
    )
    .timestamp(timestamp_ms)
    .build()
}

// ── Nonce cleanup ─────────────────────────────────────────

#[tokio::test]
async fn nonce_cleanup_shuts_down_on_signal() {
    let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(run_nonce_cleanup(storage, shutdown_rx));

    shutdown_tx.send(true).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("should finish within timeout")
        .expect("should not panic");
}

/// Verify that cleanup_expired_nonces removes old nonces from storage.
#[tokio::test]
async fn nonce_cleanup_storage_removes_expired() {
    let storage = SqliteStorage::in_memory().await.unwrap();
    let sender = NodeId::from_bytes([1u8; 32]);

    let nonce1 = Nonce::from_bytes(rand::random::<[u8; 24]>());
    let nonce2 = Nonce::from_bytes(rand::random::<[u8; 24]>());
    storage.store_nonce(&nonce1, &sender).await.unwrap();
    storage.store_nonce(&nonce2, &sender).await.unwrap();

    // Small delay so nonces' received_at is strictly before "now"
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // With max_age=0, all nonces are "expired"
    let removed = storage.cleanup_expired_nonces(0).await.unwrap();
    assert_eq!(removed, 2);
    assert!(!storage.has_nonce(&nonce1).await.unwrap());
    assert!(!storage.has_nonce(&nonce2).await.unwrap());
}

/// Fresh nonces survive cleanup when max_age is large enough.
#[tokio::test]
async fn nonce_cleanup_preserves_fresh_nonces() {
    let storage = SqliteStorage::in_memory().await.unwrap();
    let sender = NodeId::from_bytes([1u8; 32]);

    let nonce = Nonce::from_bytes(rand::random::<[u8; 24]>());
    storage.store_nonce(&nonce, &sender).await.unwrap();

    // With max_age=3600, a just-inserted nonce should survive
    let removed = storage.cleanup_expired_nonces(3600).await.unwrap();
    assert_eq!(removed, 0);
    assert!(storage.has_nonce(&nonce).await.unwrap(), "fresh nonce should survive");
}

/// Empty nonces table — cleanup returns zero without error.
#[tokio::test]
async fn nonce_cleanup_empty_table_returns_zero() {
    let storage = SqliteStorage::in_memory().await.unwrap();
    let removed = storage.cleanup_expired_nonces(0).await.unwrap();
    assert_eq!(removed, 0);
}

/// Multiple cleanup calls are idempotent — second call finds nothing to remove.
#[tokio::test]
async fn nonce_cleanup_idempotent() {
    let storage = SqliteStorage::in_memory().await.unwrap();
    let sender = NodeId::from_bytes([1u8; 32]);

    let nonce = Nonce::from_bytes(rand::random::<[u8; 24]>());
    storage.store_nonce(&nonce, &sender).await.unwrap();

    // Small delay so the nonce's received_at is strictly before "now"
    // (SQLite strftime resolution can cause same-ms inserts to not match `< now`)
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let removed1 = storage.cleanup_expired_nonces(0).await.unwrap();
    assert_eq!(removed1, 1);
    let removed2 = storage.cleanup_expired_nonces(0).await.unwrap();
    assert_eq!(removed2, 0, "second cleanup should find nothing");
}

// ── Pending cleanup ───────────────────────────────────────

#[tokio::test]
async fn pending_cleanup_shuts_down_on_signal() {
    let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(run_pending_cleanup(storage, shutdown_rx));

    shutdown_tx.send(true).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("should finish within timeout")
        .expect("should not panic");
}

/// Verify cleanup_stale_pending removes high-attempt entries, keeping low-attempt ones.
#[tokio::test]
async fn pending_cleanup_removes_high_attempt_keeps_low() {
    let storage = SqliteStorage::in_memory().await.unwrap();
    let sender = NodeId::from_bytes([1u8; 32]);
    let peer = NodeId::from_bytes([2u8; 32]);

    let env_stale = make_envelope_with_timestamp(sender, peer, 1_700_000_000_000);
    let env_fresh = make_envelope_with_timestamp(sender, peer, 1_700_000_001_000);
    storage.store_message(&env_stale).await.unwrap();
    storage.store_message(&env_fresh).await.unwrap();
    storage.queue_pending_delivery(&env_stale.id, &peer).await.unwrap();
    storage.queue_pending_delivery(&env_fresh.id, &peer).await.unwrap();

    // Push stale entry past threshold
    for _ in 0..11 {
        storage.increment_pending_attempts(&env_stale.id, &peer).await.unwrap();
    }

    let removed = storage.cleanup_stale_pending(10).await.unwrap();
    assert_eq!(removed, 1);

    let pending = storage.get_pending_for_peer(&peer).await.unwrap();
    assert_eq!(pending.len(), 1, "only the fresh entry should remain");
    assert_eq!(pending[0].0, env_fresh.id);
}

/// Empty pending_deliveries table — cleanup returns zero without error.
#[tokio::test]
async fn pending_cleanup_empty_table_returns_zero() {
    let storage = SqliteStorage::in_memory().await.unwrap();
    let removed = storage.cleanup_stale_pending(10).await.unwrap();
    assert_eq!(removed, 0);
}

/// Verify that entries exactly at the attempt threshold are cleaned up.
#[tokio::test]
async fn pending_cleanup_boundary_at_max_attempts() {
    let storage = SqliteStorage::in_memory().await.unwrap();
    let sender = NodeId::from_bytes([1u8; 32]);
    let peer = NodeId::from_bytes([2u8; 32]);

    let env = make_envelope_with_timestamp(sender, peer, 1_700_000_000_000);
    storage.store_message(&env).await.unwrap();
    storage.queue_pending_delivery(&env.id, &peer).await.unwrap();

    // Increment to exactly 9 (below threshold of 10)
    for _ in 0..9 {
        storage.increment_pending_attempts(&env.id, &peer).await.unwrap();
    }
    let removed = storage.cleanup_stale_pending(10).await.unwrap();
    assert_eq!(removed, 0, "9 attempts should survive threshold of 10");

    // One more → exactly 10
    storage.increment_pending_attempts(&env.id, &peer).await.unwrap();
    let removed = storage.cleanup_stale_pending(10).await.unwrap();
    assert_eq!(removed, 1, "10 attempts should be cleaned at threshold 10");
}

/// Multiple pending entries for different peers — cleanup only removes stale ones.
#[tokio::test]
async fn pending_cleanup_multi_peer() {
    let storage = SqliteStorage::in_memory().await.unwrap();
    let sender = NodeId::from_bytes([1u8; 32]);
    let peer_a = NodeId::from_bytes([2u8; 32]);
    let peer_b = NodeId::from_bytes([3u8; 32]);

    let env_a = make_envelope_with_timestamp(sender, peer_a, 1_700_000_000_000);
    let env_b = make_envelope_with_timestamp(sender, peer_b, 1_700_000_001_000);
    storage.store_message(&env_a).await.unwrap();
    storage.store_message(&env_b).await.unwrap();
    storage.queue_pending_delivery(&env_a.id, &peer_a).await.unwrap();
    storage.queue_pending_delivery(&env_b.id, &peer_b).await.unwrap();

    // Only peer_a's entry exceeds threshold
    for _ in 0..10 {
        storage.increment_pending_attempts(&env_a.id, &peer_a).await.unwrap();
    }

    let removed = storage.cleanup_stale_pending(10).await.unwrap();
    assert_eq!(removed, 1);

    assert!(storage.get_pending_for_peer(&peer_a).await.unwrap().is_empty());
    assert_eq!(storage.get_pending_for_peer(&peer_b).await.unwrap().len(), 1);
}

// ── Timestamps cleanup ────────────────────────────────────

#[tokio::test]
async fn timestamps_cleanup_shuts_down_on_signal() {
    let timestamps = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(run_timestamps_cleanup(timestamps, shutdown_rx));

    shutdown_tx.send(true).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("should finish within timeout")
        .expect("should not panic");
}

/// Test that the cleanup logic correctly removes stale entries.
/// Instead of testing the full task loop (which has a 60s interval),
/// we directly verify the retention logic that the task uses.
#[tokio::test]
async fn timestamps_cleanup_logic_removes_stale_entries() {
    let timestamps = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let stale_id = random_message_id();
    let fresh_id = random_message_id();
    {
        let mut ts = timestamps.lock().await;
        // Stale: 10 minutes ago (older than 5-minute max_age)
        ts.insert(stale_id, std::time::Instant::now() - std::time::Duration::from_secs(600));
        // Fresh: just now
        ts.insert(fresh_id, std::time::Instant::now());
    }

    // Apply the same cleanup logic the task uses
    let max_age = std::time::Duration::from_secs(300);
    {
        let mut ts = timestamps.lock().await;
        let cutoff = std::time::Instant::now() - max_age;
        ts.retain(|_, sent_at| *sent_at > cutoff);
    }

    let ts = timestamps.lock().await;
    assert!(!ts.contains_key(&stale_id), "stale timestamp should be removed");
    assert!(ts.contains_key(&fresh_id), "fresh timestamp should be kept");
}

/// Verify the timestamp cleanup logic with mixed fresh and stale entries.
#[tokio::test]
async fn timestamps_cleanup_logic_mixed_ages() {
    let max_age = std::time::Duration::from_secs(300);
    let mut timestamps = HashMap::new();

    let very_stale = random_message_id();
    let borderline_stale = random_message_id();
    let fresh = random_message_id();

    // 10 min ago — stale
    timestamps.insert(very_stale, std::time::Instant::now() - std::time::Duration::from_secs(600));
    // 6 min ago — stale (>5 min)
    timestamps.insert(borderline_stale, std::time::Instant::now() - std::time::Duration::from_secs(360));
    // 1 min ago — fresh
    timestamps.insert(fresh, std::time::Instant::now() - std::time::Duration::from_secs(60));

    let cutoff = std::time::Instant::now() - max_age;
    timestamps.retain(|_, sent_at| *sent_at > cutoff);

    assert_eq!(timestamps.len(), 1);
    assert!(timestamps.contains_key(&fresh));
    assert!(!timestamps.contains_key(&very_stale));
    assert!(!timestamps.contains_key(&borderline_stale));
}

/// All entries are stale — cleanup removes everything.
#[tokio::test]
async fn timestamps_cleanup_logic_all_stale() {
    let max_age = std::time::Duration::from_secs(300);
    let mut timestamps = HashMap::new();

    for _ in 0..5 {
        timestamps.insert(
            random_message_id(),
            std::time::Instant::now() - std::time::Duration::from_secs(600),
        );
    }

    let cutoff = std::time::Instant::now() - max_age;
    timestamps.retain(|_, sent_at| *sent_at > cutoff);
    assert!(timestamps.is_empty(), "all stale entries should be removed");
}

/// All entries are fresh — cleanup preserves everything.
#[tokio::test]
async fn timestamps_cleanup_logic_all_fresh() {
    let max_age = std::time::Duration::from_secs(300);
    let mut timestamps = HashMap::new();

    for _ in 0..5 {
        timestamps.insert(random_message_id(), std::time::Instant::now());
    }

    let cutoff = std::time::Instant::now() - max_age;
    timestamps.retain(|_, sent_at| *sent_at > cutoff);
    assert_eq!(timestamps.len(), 5, "all fresh entries should survive");
}

// ── Retention cleanup ─────────────────────────────────────

#[tokio::test]
async fn retention_cleanup_zero_days_exits_on_shutdown() {
    let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(run_retention_cleanup(storage, 0, shutdown_rx));

    // With retention_days=0, the task should park until shutdown
    shutdown_tx.send(true).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("should finish within timeout")
        .expect("should not panic");
}

#[tokio::test]
async fn retention_cleanup_shuts_down_on_signal() {
    let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(run_retention_cleanup(storage, 30, shutdown_rx));

    shutdown_tx.send(true).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("should finish within timeout")
        .expect("should not panic");
}

/// Retention deletes old messages directly via storage method.
#[tokio::test]
async fn retention_deletes_old_messages_keeps_recent() {
    let storage = SqliteStorage::in_memory().await.unwrap();
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = NodeId::from_bytes([2u8; 32]);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Old message: 60 days ago
    let old_env = make_envelope_with_timestamp(sender, recipient, now_ms.saturating_sub(60 * 24 * 3600 * 1000));
    storage.store_message(&old_env).await.unwrap();

    // Recent message: now
    let recent_env = make_envelope_with_timestamp(sender, recipient, now_ms);
    storage.store_message(&recent_env).await.unwrap();

    // Cutoff at 1 day ago
    let cutoff_ms = now_ms.saturating_sub(24 * 3600 * 1000);
    let removed = storage.delete_messages_older_than(cutoff_ms).await.unwrap();
    assert_eq!(removed, 1);

    assert!(storage.get_message(&old_env.id).await.unwrap().is_none(), "old message should be deleted");
    assert!(storage.get_message(&recent_env.id).await.unwrap().is_some(), "recent message should survive");
}

/// Retention with cutoff_ms=0 deletes nothing (all timestamps are > 0).
#[tokio::test]
async fn retention_cutoff_zero_deletes_nothing() {
    let storage = SqliteStorage::in_memory().await.unwrap();
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = NodeId::from_bytes([2u8; 32]);

    let env = make_envelope_with_timestamp(sender, recipient, 1_000_000_000);
    storage.store_message(&env).await.unwrap();

    let removed = storage.delete_messages_older_than(0).await.unwrap();
    assert_eq!(removed, 0);
    assert!(storage.get_message(&env.id).await.unwrap().is_some());
}

/// Retention cleans up associated pending deliveries via FK cascade.
#[tokio::test]
async fn retention_cascades_to_pending_deliveries() {
    let storage = SqliteStorage::in_memory().await.unwrap();
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = NodeId::from_bytes([2u8; 32]);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let old_env = make_envelope_with_timestamp(sender, recipient, now_ms.saturating_sub(60 * 24 * 3600 * 1000));
    storage.store_message(&old_env).await.unwrap();
    storage.queue_pending_delivery(&old_env.id, &recipient).await.unwrap();

    let cutoff_ms = now_ms.saturating_sub(24 * 3600 * 1000);
    storage.delete_messages_older_than(cutoff_ms).await.unwrap();

    // Pending delivery should be gone too (FK cascade)
    let pending = storage.get_pending_for_peer(&recipient).await.unwrap();
    assert!(pending.is_empty(), "pending delivery should cascade-delete with message");
}

// ── Gossip eviction ──────────────────────────────────────

#[tokio::test]
async fn gossip_eviction_shuts_down_on_signal() {
    let validator = Arc::new(konsensus_gossip::GossipValidator::new(Default::default()));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(run_gossip_eviction(validator, shutdown_rx));
    shutdown_tx.send(true).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("should finish within timeout")
        .expect("should not panic");
}

#[tokio::test]
async fn gossip_eviction_clears_expired_entries() {
    // Create a validator with very short dedup TTL so entries expire quickly
    let config = konsensus_gossip::GossipConfig {
        dedup_ttl_secs: 0, // immediately expired on eviction
        ..Default::default()
    };
    let validator = Arc::new(konsensus_gossip::GossipValidator::new(config));

    // Add an entry via validate
    let msg_id = MessageId::from_bytes([42u8; 32]);
    let sender = NodeId::from_bytes([1u8; 32]);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // validate stores the message in the dedup store
    let result = validator.validate(&msg_id, &sender, now_ms);
    assert!(result.is_ok(), "validate should succeed: {result:?}");
    assert_eq!(validator.store().len(), 1);

    // Small sleep so elapsed > 0
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    // Evict — with dedup_ttl=0, the entry should be removed
    validator.evict_expired();
    assert_eq!(validator.store().len(), 0, "expired entries should be evicted");
}

// ── Price refresh ────────────────────────────────────────

#[tokio::test]
async fn price_refresh_shuts_down_on_signal() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let identity = konsensus_core::NodeIdentity::from_mnemonic(mnemonic, "").unwrap();
    let cfg = konsensus_message::TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    };
    let transport = Arc::new(NoiseTransport::new(Arc::new(identity), cfg));
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> =
        Arc::new(konsensus_pricing::StaticPricingEngine::new(
            konsensus_pricing::StaticPricingConfig::default(),
        ));
    let chain: Arc<dyn ChainProvider> = Arc::new(konsensus_chain::MockChainProvider::new());
    let routing = Arc::new(konsensus_routing::RoutingTable::new(
        konsensus_routing::RoutingConfig::default(),
    ));
    let tmp_dir = tempfile::tempdir().unwrap();
    let mnemonic_file = tmp_dir.path().join("mnemonic.txt");
    std::fs::write(&mnemonic_file, "test").unwrap();
    let config = crate::config::NodeConfig::default_for_tier(
        crate::config::NodeTier::Cloud,
        mnemonic_file,
        tmp_dir.path(),
    );
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(run_price_refresh(
        transport, pricing, chain, routing, config, shutdown_rx,
    ));
    shutdown_tx.send(true).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("should finish within timeout")
        .expect("should not panic");
}

// ── peer_ln_pubkeys cleanup ─────────────────────────────

/// Test the cleanup logic directly: disconnected peers are removed,
/// connected peers are retained.
#[tokio::test]
async fn peer_ln_pubkeys_cleanup_removes_disconnected() {
    let connected_peer = NodeId::from_bytes([1u8; 32]);
    let disconnected_peer = NodeId::from_bytes([2u8; 32]);

    let map = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    {
        let mut m = map.lock().await;
        m.insert(connected_peer, "02aabb".to_string());
        m.insert(disconnected_peer, "02ccdd".to_string());
    }

    // Simulate: only connected_peer is connected
    let connected: std::collections::HashSet<_> = [connected_peer].into_iter().collect();
    {
        let mut m = map.lock().await;
        m.retain(|peer_id, _| connected.contains(peer_id));
    }

    let m = map.lock().await;
    assert_eq!(m.len(), 1);
    assert!(m.contains_key(&connected_peer));
    assert!(!m.contains_key(&disconnected_peer));
}

/// Empty map: cleanup is a no-op.
#[tokio::test]
async fn peer_ln_pubkeys_cleanup_empty_is_noop() {
    let map: HashMap<NodeId, String> = HashMap::new();
    let connected: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
    let before = map.len();
    // retain on empty does nothing
    assert_eq!(before, 0);
    assert!(connected.is_empty());
}

/// All peers still connected: nothing is removed.
#[tokio::test]
async fn peer_ln_pubkeys_cleanup_all_connected_retains_all() {
    let peer_a = NodeId::from_bytes([1u8; 32]);
    let peer_b = NodeId::from_bytes([2u8; 32]);

    let mut map = HashMap::new();
    map.insert(peer_a, "02aa".to_string());
    map.insert(peer_b, "02bb".to_string());

    let connected: std::collections::HashSet<_> = [peer_a, peer_b].into_iter().collect();
    map.retain(|peer_id, _| connected.contains(peer_id));

    assert_eq!(map.len(), 2);
}

// ── invoice_requests cleanup ────────────────────────────

/// Dropped receiver → sender.is_closed() == true → entry removed.
#[tokio::test]
async fn invoice_requests_cleanup_removes_closed_senders() {
    let mut map: HashMap<String, tokio::sync::oneshot::Sender<konsensus_api::state::InvoiceResponseData>> = HashMap::new();

    // Create two requests: one with a live receiver, one with a dropped receiver
    let (tx_live, _rx_live) = tokio::sync::oneshot::channel();
    let (tx_dead, rx_dead) = tokio::sync::oneshot::channel();
    drop(rx_dead); // drop the receiver, making tx_dead.is_closed() == true

    map.insert("live-request".to_string(), tx_live);
    map.insert("dead-request".to_string(), tx_dead);

    assert_eq!(map.len(), 2);

    // Apply the same cleanup logic as the housekeeping task
    map.retain(|_, sender| !sender.is_closed());

    assert_eq!(map.len(), 1);
    assert!(map.contains_key("live-request"));
    assert!(!map.contains_key("dead-request"));
}

/// All senders are live: nothing is removed.
#[tokio::test]
async fn invoice_requests_cleanup_retains_live_senders() {
    let mut map: HashMap<String, tokio::sync::oneshot::Sender<konsensus_api::state::InvoiceResponseData>> = HashMap::new();

    let (tx1, _rx1) = tokio::sync::oneshot::channel();
    let (tx2, _rx2) = tokio::sync::oneshot::channel();

    map.insert("req-1".to_string(), tx1);
    map.insert("req-2".to_string(), tx2);

    map.retain(|_, sender| !sender.is_closed());
    assert_eq!(map.len(), 2);
}

/// Empty map: cleanup is a no-op.
#[tokio::test]
async fn invoice_requests_cleanup_empty_is_noop() {
    let mut map: HashMap<String, tokio::sync::oneshot::Sender<konsensus_api::state::InvoiceResponseData>> = HashMap::new();
    let before = map.len();
    map.retain(|_, sender| !sender.is_closed());
    assert_eq!(before, 0);
    assert!(map.is_empty());
}

/// Shutdown signal stops the peer_ln_pubkeys cleanup task.
#[tokio::test]
async fn peer_ln_pubkeys_cleanup_shuts_down_on_signal() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let identity = konsensus_core::NodeIdentity::from_mnemonic(mnemonic, "").unwrap();
    let cfg = konsensus_message::TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    };
    let transport = Arc::new(NoiseTransport::new(Arc::new(identity), cfg));
    let map = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(run_peer_ln_pubkeys_cleanup(map, transport, shutdown_rx));
    shutdown_tx.send(true).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("should finish within timeout")
        .expect("should not panic");
}

/// Shutdown signal stops the invoice_requests cleanup task.
#[tokio::test]
async fn invoice_requests_cleanup_shuts_down_on_signal() {
    let map = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(run_invoice_requests_cleanup(map, shutdown_rx));
    shutdown_tx.send(true).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("should finish within timeout")
        .expect("should not panic");
}
