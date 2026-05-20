//! Gossip deduplication store.
//!
//! Tracks seen [`MessageId`]s with TTL-based expiry to prevent infinite
//! re-broadcast loops while bounding memory usage.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use konsensus_core::types::{MessageId, NodeId};

/// Entry in the dedup store.
struct SeenEntry {
    /// Original sender of this gossip message.
    sender: NodeId,
    /// When we first saw this message.
    seen_at: Instant,
}

/// In-memory deduplication store for gossip messages.
///
/// Thread-safe via internal [`Mutex`]. Each entry is timestamped and
/// automatically eligible for eviction after `ttl_secs`.
///
/// # Memory budget
///
/// Each entry is ~72 bytes (32-byte MessageId key + 32-byte NodeId + Instant).
/// At 60 messages/sender/hour with 100 senders and 2-hour TTL, worst case is
/// ~12,000 entries = ~864 KB. Well within budget for any node.
pub struct GossipStore {
    entries: Mutex<HashMap<MessageId, SeenEntry>>,
    ttl_secs: u64,
}

impl GossipStore {
    /// Create a new store with the given TTL for deduplication entries.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl_secs,
        }
    }

    /// Check whether a message has already been seen.
    pub fn is_seen(&self, id: &MessageId) -> bool {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.contains_key(id)
    }

    /// Mark a message as seen. Idempotent — re-marking an existing ID is a no-op.
    pub fn mark_seen(&self, id: MessageId, sender: NodeId) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.entry(id).or_insert(SeenEntry {
            sender,
            seen_at: Instant::now(),
        });
    }

    /// Remove entries older than the configured TTL.
    ///
    /// Should be called periodically (e.g., every 5 minutes) to bound memory.
    pub fn evict_expired(&self) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let ttl = std::time::Duration::from_secs(self.ttl_secs);
        let before = entries.len();
        entries.retain(|_, entry| entry.seen_at.elapsed() < ttl);
        let evicted = before - entries.len();
        if evicted > 0 {
            tracing::debug!(evicted, remaining = entries.len(), "gossip store eviction");
        }
    }

    /// Number of entries currently in the store.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the original sender of a gossip message, if seen.
    pub fn get_sender(&self, id: &MessageId) -> Option<NodeId> {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.get(id).map(|e| e.sender)
    }
}
