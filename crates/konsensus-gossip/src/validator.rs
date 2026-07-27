//! Gossip message validation: deduplication, timestamp freshness, and rate limiting.
//!
//! The validator is the gatekeeper for gossip messages. It ensures:
//! 1. **Deduplication** — each message is processed at most once.
//! 2. **Freshness** — messages must be recent (within [`GossipConfig::max_age_secs`]).
//! 3. **Not from future** — messages too far in the future are rejected.
//! 4. **Rate limiting** — each sender is capped per rolling window.
//!
//! Signature verification is done at the transport/node layer (it requires
//! access to the sender's Ed25519 public key), not here.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use konsensus_core::types::{MessageId, NodeId};
use thiserror::Error;

use crate::store::GossipStore;
use crate::{DEFAULT_DEDUP_TTL_SECS, DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_GOSSIP_PER_SENDER_PER_HOUR};

/// Errors from gossip validation.
#[derive(Debug, Error)]
pub enum GossipError {
    /// Message has already been seen (duplicate).
    #[error("duplicate gossip message: {0}")]
    Duplicate(String),

    /// Message timestamp is too old.
    #[error("gossip message too old: age {age_secs}s exceeds max {max_secs}s")]
    TooOld { age_secs: u64, max_secs: u64 },

    /// Message timestamp is too far in the future.
    #[error("gossip message from future: {ahead_secs}s ahead (max {max_secs}s)")]
    FromFuture { ahead_secs: u64, max_secs: u64 },

    /// Sender has exceeded their rate limit.
    #[error("sender {sender} rate-limited: {count}/{max} messages in window")]
    RateLimited {
        sender: String,
        count: u32,
        max: u32,
    },
}

/// Per-sender rate limit tracker.
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

/// Configuration for the gossip validator.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Maximum gossip messages accepted per sender per window.
    pub max_per_sender_per_hour: u32,
    /// Maximum age of a gossip message before rejection (seconds).
    pub max_age_secs: u64,
    /// Maximum allowed clock skew into the future (seconds).
    pub max_future_secs: u64,
    /// TTL for deduplication entries (seconds).
    pub dedup_ttl_secs: u64,
    /// Rate limit window duration.
    pub rate_limit_window: Duration,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            max_per_sender_per_hour: DEFAULT_MAX_GOSSIP_PER_SENDER_PER_HOUR,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            max_future_secs: 300, // 5 minutes clock skew tolerance
            dedup_ttl_secs: DEFAULT_DEDUP_TTL_SECS,
            rate_limit_window: Duration::from_secs(3600),
        }
    }
}

/// Validates gossip messages for deduplication, freshness, and rate limiting.
///
/// Thread-safe — all internal state is behind [`Mutex`].
pub struct GossipValidator {
    store: GossipStore,
    rate_limits: Mutex<HashMap<NodeId, RateLimitEntry>>,
    config: GossipConfig,
}

impl GossipValidator {
    /// Create a new validator with the given configuration.
    pub fn new(config: GossipConfig) -> Self {
        let store = GossipStore::new(config.dedup_ttl_secs);
        Self {
            store,
            rate_limits: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Validate a gossip message.
    ///
    /// Checks (in order):
    /// 1. Deduplication — reject if already seen.
    /// 2. Timestamp freshness — reject if too old or too far in the future.
    /// 3. Rate limit — reject if sender has exceeded their quota.
    ///
    /// On success, the message is marked as seen in the dedup store and the
    /// sender's rate limit counter is incremented.
    ///
    /// # Arguments
    /// * `id` — The gossip message's [`MessageId`].
    /// * `sender` — The original sender's [`NodeId`] (from the envelope).
    /// * `timestamp_ms` — The message's Unix timestamp in milliseconds.
    pub fn validate(
        &self,
        id: &MessageId,
        sender: &NodeId,
        timestamp_ms: u64,
    ) -> Result<(), GossipError> {
        // 1. Deduplication
        if self.store.is_seen(id) {
            return Err(GossipError::Duplicate(id.to_hex()));
        }

        // 2. Timestamp freshness
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if timestamp_ms > now_ms {
            let ahead_ms = timestamp_ms - now_ms;
            let ahead_secs = ahead_ms / 1000;
            if ahead_secs > self.config.max_future_secs {
                return Err(GossipError::FromFuture {
                    ahead_secs,
                    max_secs: self.config.max_future_secs,
                });
            }
        } else {
            let age_ms = now_ms - timestamp_ms;
            let age_secs = age_ms / 1000;
            if age_secs > self.config.max_age_secs {
                return Err(GossipError::TooOld {
                    age_secs,
                    max_secs: self.config.max_age_secs,
                });
            }
        }

        // 3. Rate limit
        {
            let mut limits = self.rate_limits.lock().unwrap_or_else(|p| p.into_inner());
            let entry = limits.entry(*sender).or_insert(RateLimitEntry {
                count: 0,
                window_start: Instant::now(),
            });

            // Reset window if expired
            if entry.window_start.elapsed() >= self.config.rate_limit_window {
                entry.count = 0;
                entry.window_start = Instant::now();
            }

            if entry.count >= self.config.max_per_sender_per_hour {
                return Err(GossipError::RateLimited {
                    sender: sender.to_hex(),
                    count: entry.count,
                    max: self.config.max_per_sender_per_hour,
                });
            }

            entry.count += 1;
        }

        // All checks passed — mark as seen
        self.store.mark_seen(*id, *sender);

        Ok(())
    }

    /// Evict expired entries from both the dedup store and the rate limiter.
    ///
    /// Removes rate-limit entries whose window has expired, bounding memory
    /// usage when many distinct senders have been seen over time.
    pub fn evict_expired(&self) {
        self.store.evict_expired();
        self.evict_expired_rate_limits();
    }

    /// Remove rate-limit entries whose window has fully elapsed.
    ///
    /// Without this, the rate_limits map grows monotonically with distinct
    /// senders. With periodic eviction, only active senders consume memory.
    fn evict_expired_rate_limits(&self) {
        let mut limits = self.rate_limits.lock().unwrap_or_else(|p| p.into_inner());
        let window = self.config.rate_limit_window;
        let before = limits.len();
        limits.retain(|_, entry| entry.window_start.elapsed() < window);
        let evicted = before - limits.len();
        if evicted > 0 {
            tracing::debug!(evicted, remaining = limits.len(), "rate limit eviction");
        }
    }

    /// Access the underlying dedup store (for metrics/debugging).
    pub fn store(&self) -> &GossipStore {
        &self.store
    }

    /// Number of senders currently tracked in the rate limiter.
    pub fn tracked_senders(&self) -> usize {
        self.rate_limits
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    /// Get the gossip config.
    pub fn config(&self) -> &GossipConfig {
        &self.config
    }
}
