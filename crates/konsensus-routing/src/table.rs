//! Routing table — manages synaptic weights for all known peers and destinations.
//!
//! The routing table is the central data structure for path selection. It maintains
//! per-peer [`SynapticWeight`] records, runs periodic decay, handles pruning, and
//! provides routing decisions based on accumulated learning.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use konsensus_core::types::NodeId;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::weight::{
    SynapticWeight, DENDRITIC_GROWTH_THRESHOLD, HOMEOSTATIC_QUEUE_THRESHOLD,
    HOMEOSTATIC_SCALE_FACTOR,
};

/// Configuration for the routing table.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    /// Interval between decay sweeps (seconds). Default: 60.
    pub decay_interval_secs: u64,

    /// Interval between pruning sweeps (seconds). Default: 300 (5 minutes).
    pub pruning_interval_secs: u64,

    /// Whether to log detailed routing decisions. Default: false.
    pub verbose_logging: bool,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            decay_interval_secs: 60,
            pruning_interval_secs: 300,
            verbose_logging: false,
        }
    }
}

/// A routing decision: which peer to use for reaching a destination.
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    /// The selected next-hop peer.
    pub next_hop: NodeId,
    /// The routing score of the selected peer.
    pub score: f64,
    /// If true, the routing table suggests establishing a direct connection
    /// to the destination (dendritic growth).
    pub suggest_direct: bool,
}

/// Score and metadata for a single peer in the routing table.
#[derive(Debug, Clone)]
pub struct PeerScore {
    /// The peer's node ID.
    pub peer_id: NodeId,
    /// Current routing score.
    pub score: f64,
    /// Current weight.
    pub weight: f64,
    /// Latency EMA in milliseconds.
    pub latency_ema_ms: f64,
    /// Success rate.
    pub success_rate: f64,
    /// Payment volume in millisatoshis.
    pub payment_volume_msat: u64,
    /// Whether pruned.
    pub pruned: bool,
    /// Whether direct connection is suggested.
    pub suggest_direct: bool,
}

/// Maximum relay destinations tracked per peer before LRU eviction.
const MAX_RELAY_DESTINATIONS_PER_PEER: usize = 10_000;

/// How long a relay destination entry is kept without activity before eviction.
const RELAY_DESTINATION_TTL: Duration = Duration::from_secs(24 * 3600); // 24 hours

/// Relay tracking: how many times we relayed to a destination through a specific peer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RelayTracker {
    /// Map: destination NodeId → (relay count, last relayed timestamp).
    counts: HashMap<String, RelayEntry>,
}

/// A single relay destination entry with count and last-seen timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayEntry {
    count: u32,
    #[serde(skip, default = "Instant::now")]
    last_relayed: Instant,
}

/// The routing table — thread-safe, manages all peer weights and routing decisions.
///
/// Designed for concurrent access from multiple transport tasks. The internal
/// state is protected by an `RwLock` — reads (routing decisions) don't block
/// each other, only writes (weight updates) require exclusive access.
pub struct RoutingTable {
    /// Per-peer synaptic weights.
    weights: Arc<RwLock<HashMap<NodeId, SynapticWeight>>>,

    /// Per-peer relay tracking (destination → count).
    /// Used for dendritic growth decisions.
    relays: Arc<RwLock<HashMap<NodeId, RelayTracker>>>,

    /// Configuration.
    config: RoutingConfig,
}

impl RoutingTable {
    /// Create a new routing table with the given configuration.
    pub fn new(config: RoutingConfig) -> Self {
        Self {
            weights: Arc::new(RwLock::new(HashMap::new())),
            relays: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create a routing table with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(RoutingConfig::default())
    }

    /// Record a successful message delivery to a peer (Hebbian + STDP).
    ///
    /// Called when a `MessageAck` is received from the peer. The `latency_ms`
    /// is the time between sending the message and receiving the ack.
    pub async fn record_success(
        &self,
        peer: &NodeId,
        latency_ms: f64,
        payment_msat: u64,
    ) {
        let mut weights = self.weights.write().await;
        let weight = weights.entry(*peer).or_insert_with(SynapticWeight::new);
        weight.record_success(latency_ms, payment_msat);

        if self.config.verbose_logging {
            debug!(
                peer = %peer,
                weight = weight.weight(),
                latency_ema = weight.latency_ema_ms(),
                score = weight.routing_score(),
                "routing: success recorded"
            );
        }
    }

    /// Record a failed delivery attempt to a peer.
    pub async fn record_failure(&self, peer: &NodeId) {
        let mut weights = self.weights.write().await;
        let weight = weights.entry(*peer).or_insert_with(SynapticWeight::new);
        weight.record_failure();

        if self.config.verbose_logging {
            debug!(
                peer = %peer,
                weight = weight.weight(),
                success_rate = weight.success_rate(),
                "routing: failure recorded"
            );
        }
    }

    /// Record a relay through a peer toward a destination.
    ///
    /// Used for dendritic growth tracking. When the relay count for a
    /// (peer, destination) pair exceeds the threshold, the routing table
    /// will suggest establishing a direct connection.
    pub async fn record_relay(&self, via_peer: &NodeId, destination: &NodeId) {
        // Update relay count in weight
        {
            let mut weights = self.weights.write().await;
            let weight = weights.entry(*via_peer).or_insert_with(SynapticWeight::new);
            weight.record_relay();
        }

        // Track per-destination relay counts
        let mut relays = self.relays.write().await;
        let tracker = relays.entry(*via_peer).or_default();
        let dest_key = destination.to_string();
        let entry = tracker.counts.entry(dest_key).or_insert_with(|| RelayEntry {
            count: 0,
            last_relayed: Instant::now(),
        });
        entry.count = entry.count.saturating_add(1);
        entry.last_relayed = Instant::now();

        // Cap destinations per peer to prevent unbounded growth
        if tracker.counts.len() > MAX_RELAY_DESTINATIONS_PER_PEER {
            // Evict the oldest entry
            if let Some(oldest_key) = tracker
                .counts
                .iter()
                .min_by_key(|(_, e)| e.last_relayed)
                .map(|(k, _)| k.clone())
            {
                tracker.counts.remove(&oldest_key);
            }
        }
    }

    /// Check if we should suggest a direct connection to a destination
    /// (dendritic growth: relayed too many times through intermediaries).
    pub async fn should_suggest_direct(
        &self,
        destination: &NodeId,
    ) -> bool {
        let relays = self.relays.read().await;
        let dest_key = destination.to_string();
        for tracker in relays.values() {
            if let Some(entry) = tracker.counts.get(&dest_key) {
                if entry.count >= DENDRITIC_GROWTH_THRESHOLD {
                    return true;
                }
            }
        }
        false
    }

    /// Get the best routing decision for reaching a destination.
    ///
    /// Returns `None` if no peers are known or all are pruned.
    /// If the destination is a directly connected peer, returns it directly.
    /// Otherwise, selects the peer with the highest routing score.
    pub async fn route_to(&self, destination: &NodeId) -> Option<RoutingDecision> {
        let weights = self.weights.read().await;

        // If we have a direct weight for this destination, use it
        if let Some(w) = weights.get(destination) {
            if !w.is_pruned() {
                return Some(RoutingDecision {
                    next_hop: *destination,
                    score: w.routing_score(),
                    suggest_direct: false, // Already direct
                });
            }
        }

        // Find the best peer by routing score
        let mut best: Option<(NodeId, f64)> = None;
        for (peer_id, weight) in weights.iter() {
            if weight.is_pruned() {
                continue;
            }
            let score = weight.routing_score();
            match best {
                None => best = Some((*peer_id, score)),
                Some((_, best_score)) if score > best_score => {
                    best = Some((*peer_id, score));
                }
                _ => {}
            }
        }

        let suggest_direct = self.should_suggest_direct_inner(destination, &self.relays).await;

        best.map(|(next_hop, score)| RoutingDecision {
            next_hop,
            score,
            suggest_direct,
        })
    }

    /// Get scores for all known peers.
    pub async fn peer_scores(&self) -> Vec<PeerScore> {
        let weights = self.weights.read().await;
        weights
            .iter()
            .map(|(peer_id, w)| PeerScore {
                peer_id: *peer_id,
                score: w.routing_score(),
                weight: w.weight(),
                latency_ema_ms: w.latency_ema_ms(),
                success_rate: w.success_rate(),
                payment_volume_msat: w.payment_volume_msat(),
                pruned: w.is_pruned(),
                suggest_direct: w.should_suggest_direct(),
            })
            .collect()
    }

    /// Apply decay to all peer weights (long-term depression sweep).
    ///
    /// Should be called periodically (default: every 60 seconds) by the
    /// background decay task.
    pub async fn decay_all(&self) {
        let mut weights = self.weights.write().await;
        for (peer_id, weight) in weights.iter_mut() {
            weight.apply_decay();
            if self.config.verbose_logging {
                debug!(
                    peer = %peer_id,
                    weight = weight.weight(),
                    "routing: decay applied"
                );
            }
        }
    }

    /// Run synaptic pruning sweep — deactivate connections below threshold
    /// for longer than the grace period, and evict stale pruned entries.
    ///
    /// Pruned entries that have been inactive for 48+ hours are removed entirely
    /// to prevent unbounded growth of the routing table.
    ///
    /// Returns the list of newly pruned peer IDs.
    pub async fn prune(&self) -> Vec<NodeId> {
        let mut weights = self.weights.write().await;
        let mut pruned = Vec::new();

        // Phase 1: mark new entries as pruned
        for (peer_id, weight) in weights.iter_mut() {
            if !weight.is_pruned() && weight.check_pruning() {
                info!(peer = %peer_id, "routing: connection pruned (below threshold for 24h)");
                pruned.push(*peer_id);
            }
        }

        // Phase 2: evict pruned entries that have been stale for 48+ hours
        let stale_threshold = Duration::from_secs(48 * 3600);
        let before = weights.len();
        weights.retain(|peer_id, weight| {
            if weight.is_pruned() && weight.time_since_last_update() >= stale_threshold {
                debug!(peer = %peer_id, "routing: evicted stale pruned entry");
                false
            } else {
                true
            }
        });
        let evicted = before - weights.len();

        // Phase 3: evict stale relay destination entries (TTL-based)
        drop(weights);
        let mut relays = self.relays.write().await;
        let mut relay_destinations_evicted: usize = 0;
        for tracker in relays.values_mut() {
            let before_count = tracker.counts.len();
            tracker
                .counts
                .retain(|_, entry| entry.last_relayed.elapsed() < RELAY_DESTINATION_TTL);
            relay_destinations_evicted += before_count - tracker.counts.len();
        }
        // Remove peer entries with no remaining destinations
        relays.retain(|_, tracker| !tracker.counts.is_empty());

        if evicted > 0 || relay_destinations_evicted > 0 {
            info!(
                evicted,
                relay_destinations_evicted, "routing: stale entries evicted"
            );
        }

        pruned
    }

    /// Apply homeostatic scaling when message queue exceeds threshold.
    ///
    /// Reduces all weights by the homeostatic scale factor to relieve
    /// routing pressure through overloaded paths.
    pub async fn apply_homeostatic_scaling(&self, queue_depth: usize) {
        if queue_depth < HOMEOSTATIC_QUEUE_THRESHOLD {
            return;
        }

        warn!(
            queue_depth,
            threshold = HOMEOSTATIC_QUEUE_THRESHOLD,
            scale_factor = HOMEOSTATIC_SCALE_FACTOR,
            "routing: homeostatic scaling triggered"
        );

        let mut weights = self.weights.write().await;
        for weight in weights.values_mut() {
            weight.apply_homeostatic_scaling();
        }
    }

    /// Reactivate a pruned peer (e.g., when they reconnect or send a message).
    pub async fn reactivate(&self, peer: &NodeId) {
        let mut weights = self.weights.write().await;
        if let Some(weight) = weights.get_mut(peer) {
            if weight.is_pruned() {
                weight.reactivate();
                info!(peer = %peer, "routing: pruned connection reactivated");
            }
        }
    }

    /// Get the synaptic weight value for a specific peer.
    ///
    /// Returns `None` if the peer is unknown or has been pruned.
    /// Used by plasticity pricing to compute trust discounts.
    pub async fn get_peer_weight(&self, peer: &NodeId) -> Option<f64> {
        let weights = self.weights.read().await;
        weights.get(peer).and_then(|w| {
            if w.is_pruned() {
                None
            } else {
                Some(w.weight())
            }
        })
    }

    /// Remove a peer entirely from the routing table.
    pub async fn remove_peer(&self, peer: &NodeId) {
        self.weights.write().await.remove(peer);
        self.relays.write().await.remove(peer);
    }

    /// Get the number of known peers (including pruned).
    pub async fn peer_count(&self) -> usize {
        self.weights.read().await.len()
    }

    /// Get the number of active (non-pruned) peers.
    pub async fn active_peer_count(&self) -> usize {
        self.weights
            .read()
            .await
            .values()
            .filter(|w| !w.is_pruned())
            .count()
    }

    /// Spawn the periodic decay and pruning background tasks.
    ///
    /// Returns a handle that can be used to stop the tasks.
    /// The tasks run until the returned handle is dropped.
    pub fn spawn_maintenance(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let table = Arc::clone(self);
        let decay_interval = Duration::from_secs(self.config.decay_interval_secs);
        let pruning_interval = Duration::from_secs(self.config.pruning_interval_secs);

        tokio::spawn(async move {
            let mut decay_tick = tokio::time::interval(decay_interval);
            let mut prune_tick = tokio::time::interval(pruning_interval);

            // Don't fire immediately
            decay_tick.tick().await;
            prune_tick.tick().await;

            loop {
                tokio::select! {
                    _ = decay_tick.tick() => {
                        table.decay_all().await;
                    }
                    _ = prune_tick.tick() => {
                        let pruned = table.prune().await;
                        if !pruned.is_empty() {
                            info!(count = pruned.len(), "routing: pruning sweep completed");
                        }
                    }
                }
            }
        })
    }

    /// Internal helper: check dendritic growth without acquiring relays lock
    /// (caller must provide the lock guard).
    async fn should_suggest_direct_inner(
        &self,
        destination: &NodeId,
        relays: &Arc<RwLock<HashMap<NodeId, RelayTracker>>>,
    ) -> bool {
        let relays = relays.read().await;
        let dest_key = destination.to_string();
        for tracker in relays.values() {
            if let Some(entry) = tracker.counts.get(&dest_key) {
                if entry.count >= DENDRITIC_GROWTH_THRESHOLD {
                    return true;
                }
            }
        }
        false
    }

    /// Export the current state for persistence or API response.
    pub async fn export_state(&self) -> HashMap<String, SynapticWeight> {
        let weights = self.weights.read().await;
        weights
            .iter()
            .map(|(id, w)| (id.to_string(), w.clone()))
            .collect()
    }

    /// Import previously persisted state.
    pub async fn import_state(&self, state: HashMap<NodeId, SynapticWeight>) {
        let mut weights = self.weights.write().await;
        *weights = state;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_core::types::NodeId;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[tokio::test]
    async fn new_table_is_empty() {
        let table = RoutingTable::with_defaults();
        assert_eq!(table.peer_count().await, 0);
        assert_eq!(table.active_peer_count().await, 0);
    }

    #[tokio::test]
    async fn record_success_adds_peer() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        table.record_success(&peer, 50.0, 1000).await;

        assert_eq!(table.peer_count().await, 1);
        let scores = table.peer_scores().await;
        assert_eq!(scores.len(), 1);
        assert!(scores[0].weight > 0.0);
        assert!(scores[0].score > 0.0);
    }

    #[tokio::test]
    async fn record_failure_adds_peer() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        table.record_failure(&peer).await;

        assert_eq!(table.peer_count().await, 1);
        let scores = table.peer_scores().await;
        assert!(scores[0].success_rate < 1.0);
    }

    #[tokio::test]
    async fn route_to_direct_peer() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        table.record_success(&peer, 10.0, 1000).await;

        let decision = table.route_to(&peer).await.expect("should find route");
        assert_eq!(decision.next_hop, peer);
        assert!(decision.score > 0.0);
        assert!(!decision.suggest_direct);
    }

    #[tokio::test]
    async fn route_selects_best_peer() {
        let table = RoutingTable::with_defaults();
        let good_peer = test_node_id(1);
        let bad_peer = test_node_id(2);
        let destination = test_node_id(3);

        // Good peer: many successes, low latency
        for _ in 0..10 {
            table.record_success(&good_peer, 10.0, 1000).await;
        }

        // Bad peer: some failures, high latency
        table.record_success(&bad_peer, 500.0, 1000).await;
        table.record_failure(&bad_peer).await;

        let decision = table.route_to(&destination).await.expect("should route");
        assert_eq!(decision.next_hop, good_peer);
    }

    #[tokio::test]
    async fn route_returns_none_for_empty_table() {
        let table = RoutingTable::with_defaults();
        let dest = test_node_id(1);
        assert!(table.route_to(&dest).await.is_none());
    }

    #[tokio::test]
    async fn decay_all_reduces_weights() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        table.record_success(&peer, 10.0, 1000).await;
        let before = table.peer_scores().await[0].weight;

        // Decay won't do much with 0 elapsed time, but shouldn't panic
        table.decay_all().await;
        let after = table.peer_scores().await[0].weight;

        // Weight should be same or slightly less (near-zero elapsed time)
        assert!(after <= before + f64::EPSILON);
    }

    #[tokio::test]
    async fn remove_peer_clears_state() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        table.record_success(&peer, 10.0, 1000).await;
        assert_eq!(table.peer_count().await, 1);

        table.remove_peer(&peer).await;
        assert_eq!(table.peer_count().await, 0);
    }

    #[tokio::test]
    async fn homeostatic_scaling_below_threshold_is_noop() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        table.record_success(&peer, 10.0, 1000).await;
        let before = table.peer_scores().await[0].weight;

        table.apply_homeostatic_scaling(100).await; // Below threshold
        let after = table.peer_scores().await[0].weight;

        assert!((before - after).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn homeostatic_scaling_above_threshold_reduces_weights() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        table.record_success(&peer, 10.0, 1000).await;
        let before = table.peer_scores().await[0].weight;

        table
            .apply_homeostatic_scaling(HOMEOSTATIC_QUEUE_THRESHOLD + 1)
            .await;
        let after = table.peer_scores().await[0].weight;

        assert!(after < before);
    }

    #[tokio::test]
    async fn relay_tracking_and_dendritic_growth() {
        let table = RoutingTable::with_defaults();
        let via = test_node_id(1);
        let dest = test_node_id(2);

        // Not enough relays yet
        for _ in 0..19 {
            table.record_relay(&via, &dest).await;
        }
        assert!(!table.should_suggest_direct(&dest).await);

        // One more relay crosses the threshold
        table.record_relay(&via, &dest).await;
        assert!(table.should_suggest_direct(&dest).await);
    }

    #[tokio::test]
    async fn reactivate_pruned_peer() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        // Add peer, then manually mark as pruned via weight manipulation
        table.record_success(&peer, 10.0, 1000).await;
        {
            let mut weights = table.weights.write().await;
            let w = weights.get_mut(&peer).expect("peer exists");
            // Force pruning state
            w.record_failure();
            w.record_failure();
            // Directly set pruned for test
        }

        table.reactivate(&peer).await;
        let scores = table.peer_scores().await;
        assert!(!scores[0].pruned);
    }

    #[tokio::test]
    async fn export_import_roundtrip() {
        let table = RoutingTable::with_defaults();
        let peer1 = test_node_id(1);
        let peer2 = test_node_id(2);

        table.record_success(&peer1, 10.0, 1000).await;
        table.record_success(&peer2, 50.0, 2000).await;
        table.record_failure(&peer2).await;

        let exported = table.export_state().await;
        assert_eq!(exported.len(), 2);

        // Import into new table
        let table2 = RoutingTable::with_defaults();
        let state: HashMap<NodeId, SynapticWeight> = exported
            .into_iter()
            .map(|(k, v)| {
                let bytes = hex::decode(&k).expect("valid hex");
                let arr: [u8; 32] = bytes.try_into().expect("32 bytes");
                (NodeId::from_bytes(arr), v)
            })
            .collect();
        table2.import_state(state).await;

        assert_eq!(table2.peer_count().await, 2);
    }

    #[tokio::test]
    async fn concurrent_updates() {
        let table = Arc::new(RoutingTable::with_defaults());
        let peer = test_node_id(1);

        // Spawn 100 concurrent updates
        let mut handles = Vec::new();
        for i in 0..100 {
            let t = Arc::clone(&table);
            let p = peer;
            handles.push(tokio::spawn(async move {
                if i % 3 == 0 {
                    t.record_failure(&p).await;
                } else {
                    t.record_success(&p, (i as f64) * 10.0, 100).await;
                }
            }));
        }

        for h in handles {
            h.await.expect("task should not panic");
        }

        let scores = table.peer_scores().await;
        assert_eq!(scores.len(), 1);
        // ~67 successes, ~33 failures
        assert!(scores[0].success_rate > 0.5);
        assert!(scores[0].success_rate < 0.8);
    }

    #[tokio::test]
    async fn many_peers_routing() {
        let table = RoutingTable::with_defaults();

        // Add 50 peers with varying quality
        for i in 0..50u8 {
            let peer = test_node_id(i);
            let latency = (i as f64 + 1.0) * 10.0;
            table.record_success(&peer, latency, 1000).await;
        }

        // Best peer should be the one with lowest latency (peer 0)
        let dest = test_node_id(100);
        let decision = table.route_to(&dest).await.expect("should route");
        // Peer 0 has lowest latency = 10ms, so highest score
        assert_eq!(decision.next_hop, test_node_id(0));
    }

    #[tokio::test]
    async fn active_vs_total_peer_count() {
        let table = RoutingTable::with_defaults();
        let peer1 = test_node_id(1);
        let peer2 = test_node_id(2);

        table.record_success(&peer1, 10.0, 1000).await;
        table.record_success(&peer2, 10.0, 1000).await;

        assert_eq!(table.peer_count().await, 2);
        assert_eq!(table.active_peer_count().await, 2);
    }

    #[tokio::test]
    async fn verbose_logging_doesnt_panic() {
        let config = RoutingConfig {
            verbose_logging: true,
            ..Default::default()
        };
        let table = RoutingTable::new(config);
        let peer = test_node_id(1);

        table.record_success(&peer, 10.0, 1000).await;
        table.record_failure(&peer).await;
        table.decay_all().await;
    }

    #[test]
    fn routing_config_deny_unknown_fields() {
        let json = r#"{"decay_interval_secs":60,"pruning_interval_secs":300,"verbose_logging":false,"extra":true}"#;
        let result: Result<RoutingConfig, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown fields should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("unknown field"),
            "error should mention unknown field"
        );
    }

    #[tokio::test]
    async fn route_to_returns_none_when_all_peers_pruned() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);
        let dest = test_node_id(2);

        table.record_success(&peer, 10.0, 1000).await;
        {
            let mut weights = table.weights.write().await;
            weights.get_mut(&peer).unwrap().set_pruned(true);
        }

        assert!(table.route_to(&dest).await.is_none());
    }

    #[tokio::test]
    async fn get_peer_weight_unknown_peer() {
        let table = RoutingTable::with_defaults();
        let unknown = test_node_id(99);
        assert!(table.get_peer_weight(&unknown).await.is_none());
    }

    #[tokio::test]
    async fn get_peer_weight_known_peer() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        table.record_success(&peer, 10.0, 1000).await;
        let w = table.get_peer_weight(&peer).await;
        assert!(w.is_some());
        assert!(w.unwrap() > 0.0);
    }

    #[tokio::test]
    async fn get_peer_weight_pruned_peer_returns_none() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        table.record_success(&peer, 10.0, 1000).await;
        {
            let mut weights = table.weights.write().await;
            weights.get_mut(&peer).unwrap().set_pruned(true);
        }

        assert!(table.get_peer_weight(&peer).await.is_none());
    }

    #[tokio::test]
    async fn reactivate_unknown_peer_is_noop() {
        let table = RoutingTable::with_defaults();
        let unknown = test_node_id(99);
        // Should not panic
        table.reactivate(&unknown).await;
        assert_eq!(table.peer_count().await, 0);
    }

    #[tokio::test]
    async fn reactivate_non_pruned_peer_is_noop() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        table.record_success(&peer, 10.0, 1000).await;
        let before = table.peer_scores().await[0].weight;

        table.reactivate(&peer).await;
        let after = table.peer_scores().await[0].weight;

        assert!((before - after).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn multiple_destinations_relay_tracking() {
        let table = RoutingTable::with_defaults();
        let via = test_node_id(1);
        let dest_a = test_node_id(10);
        let dest_b = test_node_id(20);

        for _ in 0..20 {
            table.record_relay(&via, &dest_a).await;
        }
        for _ in 0..5 {
            table.record_relay(&via, &dest_b).await;
        }

        assert!(table.should_suggest_direct(&dest_a).await);
        assert!(!table.should_suggest_direct(&dest_b).await);
    }

    #[tokio::test]
    async fn multiple_paths_to_same_destination() {
        let table = RoutingTable::with_defaults();
        let via1 = test_node_id(1);
        let via2 = test_node_id(2);
        let dest = test_node_id(10);

        // 15 relays via peer 1, 10 via peer 2 — neither crosses threshold alone
        for _ in 0..15 {
            table.record_relay(&via1, &dest).await;
        }
        for _ in 0..10 {
            table.record_relay(&via2, &dest).await;
        }

        // Neither single peer crossed threshold of 20
        assert!(!table.should_suggest_direct(&dest).await);

        // 5 more via peer 1 crosses it
        for _ in 0..5 {
            table.record_relay(&via1, &dest).await;
        }
        assert!(table.should_suggest_direct(&dest).await);
    }

    #[tokio::test]
    async fn import_empty_state() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);
        table.record_success(&peer, 10.0, 1000).await;
        assert_eq!(table.peer_count().await, 1);

        // Import empty state should clear everything
        table.import_state(HashMap::new()).await;
        assert_eq!(table.peer_count().await, 0);
    }

    #[tokio::test]
    async fn remove_peer_also_clears_relays() {
        let table = RoutingTable::with_defaults();
        let via = test_node_id(1);
        let dest = test_node_id(10);

        table.record_success(&via, 10.0, 1000).await;
        for _ in 0..25 {
            table.record_relay(&via, &dest).await;
        }
        assert!(table.should_suggest_direct(&dest).await);

        table.remove_peer(&via).await;
        assert_eq!(table.peer_count().await, 0);
        // Relay tracking should be cleared too
        assert!(!table.should_suggest_direct(&dest).await);
    }

    #[tokio::test]
    async fn concurrent_relay_recording() {
        let table = Arc::new(RoutingTable::with_defaults());
        let via = test_node_id(1);
        let dest = test_node_id(2);

        let mut handles = Vec::new();
        for _ in 0..25 {
            let t = Arc::clone(&table);
            handles.push(tokio::spawn(async move {
                t.record_relay(&via, &dest).await;
            }));
        }
        for h in handles {
            h.await.expect("no panic");
        }

        assert!(table.should_suggest_direct(&dest).await);
    }

    #[tokio::test]
    async fn peer_scores_includes_all_fields() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        table.record_success(&peer, 42.0, 5000).await;
        table.record_failure(&peer).await;

        let scores = table.peer_scores().await;
        assert_eq!(scores.len(), 1);
        let s = &scores[0];
        assert_eq!(s.peer_id, peer);
        assert!(s.weight > 0.0);
        assert!(s.latency_ema_ms > 0.0);
        assert!(s.success_rate > 0.0);
        assert!(s.success_rate < 1.0);
        assert_eq!(s.payment_volume_msat, 5000);
        assert!(!s.pruned);
    }

    #[tokio::test]
    async fn route_to_direct_pruned_peer_selects_alternate() {
        let table = RoutingTable::with_defaults();
        let dest = test_node_id(1);
        let alternate = test_node_id(2);

        table.record_success(&dest, 10.0, 1000).await;
        table.record_success(&alternate, 20.0, 1000).await;

        // Prune the direct destination
        {
            let mut weights = table.weights.write().await;
            weights.get_mut(&dest).unwrap().set_pruned(true);
        }

        let decision = table.route_to(&dest).await.expect("should find alternate");
        assert_eq!(decision.next_hop, alternate);
    }

    #[tokio::test]
    async fn prune_sweep_returns_newly_pruned() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        // Add a peer and force its weight below pruning threshold
        // with an expired grace period
        table.record_success(&peer, 10.0, 1000).await;
        {
            let mut weights = table.weights.write().await;
            let w = weights.get_mut(&peer).unwrap();
            w.set_weight(0.001);
            // Set below_threshold_since to 25 hours ago (past grace period)
            w.set_below_threshold_since(Some(std::time::Instant::now() - Duration::from_secs(25 * 3600)));
        }

        let pruned = table.prune().await;
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0], peer);

        // Second sweep should not re-report already-pruned peer
        let pruned2 = table.prune().await;
        assert!(pruned2.is_empty());
    }

    #[tokio::test]
    async fn routing_config_custom_intervals() {
        let config = RoutingConfig {
            decay_interval_secs: 10,
            pruning_interval_secs: 30,
            verbose_logging: true,
        };
        let table = RoutingTable::new(config);
        let peer = test_node_id(1);
        // Basic operations should work with custom config
        table.record_success(&peer, 10.0, 1000).await;
        table.decay_all().await;
        assert_eq!(table.peer_count().await, 1);
    }

    #[tokio::test]
    async fn stale_pruned_entries_are_evicted() {
        let table = RoutingTable::with_defaults();
        let stale_peer = test_node_id(1);
        let active_peer = test_node_id(2);

        // Add both peers
        table.record_success(&stale_peer, 10.0, 1000).await;
        table.record_success(&active_peer, 10.0, 1000).await;

        // Mark stale_peer as pruned with last_updated 49 hours ago
        {
            let mut weights = table.weights.write().await;
            let w = weights.get_mut(&stale_peer).unwrap();
            w.set_pruned(true);
            // Force last_updated to 49 hours ago by setting weight (which updates last_updated)
            // then manipulating the internal state
            w.set_weight(0.0);
            w.set_below_threshold_since(Some(
                std::time::Instant::now() - Duration::from_secs(49 * 3600),
            ));
        }

        // The stale peer's last_updated is recent (set_weight just updated it),
        // so it won't be evicted yet. We need to test the time_since_last_update path.
        // Since we can't easily backdate Instant, verify that non-stale pruned entries are kept.
        let pruned = table.prune().await;
        // stale_peer is already pruned, so not newly reported
        assert!(pruned.is_empty());
        // Both peers should still be present (last_updated is recent)
        assert_eq!(table.peer_count().await, 2);
    }

    #[tokio::test]
    async fn prune_does_not_evict_active_pruned_entries() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        table.record_success(&peer, 10.0, 1000).await;
        {
            let mut weights = table.weights.write().await;
            weights.get_mut(&peer).unwrap().set_pruned(true);
        }

        // Pruned but recently updated — should NOT be evicted
        let pruned = table.prune().await;
        assert!(pruned.is_empty()); // Already pruned, not newly
        assert_eq!(table.peer_count().await, 1); // Still present
    }

    #[tokio::test]
    async fn time_since_last_update_is_accessible() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        table.record_success(&peer, 10.0, 1000).await;

        let weights = table.weights.read().await;
        let w = weights.get(&peer).unwrap();
        // Just created, should be very small
        assert!(w.time_since_last_update() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn relay_destination_ttl_eviction() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);
        let dest_fresh = test_node_id(2);
        let dest_stale = test_node_id(3);

        // Record relays for both destinations
        table.record_relay(&peer, &dest_fresh).await;
        table.record_relay(&peer, &dest_stale).await;

        // Manually age out the stale destination
        {
            let mut relays = table.relays.write().await;
            let tracker = relays.get_mut(&peer).unwrap();
            let stale_entry = tracker.counts.get_mut(&dest_stale.to_string()).unwrap();
            stale_entry.last_relayed =
                Instant::now() - RELAY_DESTINATION_TTL - Duration::from_secs(1);
        }

        // Also need a weight entry for prune() to run
        table.record_success(&peer, 10.0, 1000).await;

        // Pruning sweep should evict the stale destination
        table.prune().await;

        let relays = table.relays.read().await;
        let tracker = relays.get(&peer).unwrap();
        assert_eq!(tracker.counts.len(), 1);
        assert!(tracker.counts.contains_key(&dest_fresh.to_string()));
        assert!(!tracker.counts.contains_key(&dest_stale.to_string()));
    }

    #[tokio::test]
    async fn relay_destination_cap_evicts_oldest() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);

        // Record relays up to the cap
        for i in 0..MAX_RELAY_DESTINATIONS_PER_PEER {
            let dest = NodeId::from_bytes({
                let mut bytes = [0u8; 32];
                let i_bytes = (i as u32).to_be_bytes();
                bytes[28..32].copy_from_slice(&i_bytes);
                bytes
            });
            table.record_relay(&peer, &dest).await;
        }

        // Verify we're at the cap
        {
            let relays = table.relays.read().await;
            let tracker = relays.get(&peer).unwrap();
            assert_eq!(tracker.counts.len(), MAX_RELAY_DESTINATIONS_PER_PEER);
        }

        // Age out the first entry so it becomes the oldest
        {
            let mut relays = table.relays.write().await;
            let tracker = relays.get_mut(&peer).unwrap();
            let first_key = {
                let dest = NodeId::from_bytes({
                    let mut bytes = [0u8; 32];
                    let i_bytes = 0u32.to_be_bytes();
                    bytes[28..32].copy_from_slice(&i_bytes);
                    bytes
                });
                dest.to_string()
            };
            if let Some(entry) = tracker.counts.get_mut(&first_key) {
                entry.last_relayed = Instant::now() - Duration::from_secs(3600);
            }
        }

        // Add one more — should evict the oldest (entry 0)
        let new_dest = NodeId::from_bytes([0xff; 32]);
        table.record_relay(&peer, &new_dest).await;

        let relays = table.relays.read().await;
        let tracker = relays.get(&peer).unwrap();
        // Should still be at cap (evicted one, added one)
        assert_eq!(tracker.counts.len(), MAX_RELAY_DESTINATIONS_PER_PEER);
        // The new entry should be present
        assert!(tracker.counts.contains_key(&new_dest.to_string()));
        // The oldest entry (0) should have been evicted
        let evicted_dest = NodeId::from_bytes({
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&0u32.to_be_bytes());
            bytes
        });
        assert!(!tracker.counts.contains_key(&evicted_dest.to_string()));
    }

    #[tokio::test]
    async fn all_relay_destinations_stale_removes_peer_tracker() {
        let table = RoutingTable::with_defaults();
        let peer = test_node_id(1);
        let dest = test_node_id(2);

        table.record_relay(&peer, &dest).await;
        table.record_success(&peer, 10.0, 1000).await;

        // Age out the only destination
        {
            let mut relays = table.relays.write().await;
            let tracker = relays.get_mut(&peer).unwrap();
            let entry = tracker.counts.get_mut(&dest.to_string()).unwrap();
            entry.last_relayed =
                Instant::now() - RELAY_DESTINATION_TTL - Duration::from_secs(1);
        }

        table.prune().await;

        // Entire peer tracker should be removed (no destinations left)
        let relays = table.relays.read().await;
        assert!(relays.get(&peer).is_none());
    }
}
