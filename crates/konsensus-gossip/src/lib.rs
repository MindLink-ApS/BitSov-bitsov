#![forbid(unsafe_code)]
#![doc = "Gossip protocol for public data propagation across the BitSov mesh."]
//!
//! Gossip enables nodes to share public information (web manifests, pricing
//! tables, node capabilities) with all connected peers. Messages propagate
//! through the mesh via re-broadcast, with deduplication preventing loops.
//!
//! # Design principles
//!
//! - **Public data only** — gossip is for data the sender wants widely known.
//!   Private content uses direct E2EE messaging.
//! - **Rate-limited, not payment-gated** — gossip bypasses the payment gate
//!   but is capped at [`DEFAULT_MAX_GOSSIP_PER_SENDER_PER_HOUR`] messages per
//!   sender per hour to prevent abuse.
//! - **Signed** — every gossip message carries an Ed25519 signature from the
//!   originator, verifiable by any node in the mesh.
//! - **Time-bounded** — messages older than [`DEFAULT_MAX_AGE_SECS`] are rejected.
//! - **Deduplicated** — the [`GossipStore`] tracks seen message IDs so each
//!   message is processed at most once per node.

mod store;
mod validator;

pub use store::GossipStore;
pub use validator::{GossipConfig, GossipValidator, GossipError};

/// Default maximum gossip messages per sender per hour.
pub const DEFAULT_MAX_GOSSIP_PER_SENDER_PER_HOUR: u32 = 60;

/// Default maximum age for gossip messages (1 hour).
pub const DEFAULT_MAX_AGE_SECS: u64 = 3600;

/// Default TTL for deduplication entries (2 hours — ensures we don't
/// re-accept a message that arrives late via a longer path).
pub const DEFAULT_DEDUP_TTL_SECS: u64 = 7200;

#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_core::types::{MessageId, NodeId};
    use std::time::Duration;

    // ── GossipStore tests ─────────────────────────────────────────────

    #[test]
    fn store_marks_seen_and_deduplicates() {
        let store = GossipStore::new(DEFAULT_DEDUP_TTL_SECS);
        let id = MessageId::from_bytes([1u8; 32]);
        let sender = NodeId::from_bytes([2u8; 32]);

        assert!(!store.is_seen(&id), "fresh store should not have seen the ID");
        store.mark_seen(id, sender);
        assert!(store.is_seen(&id), "should be seen after mark_seen");
    }

    #[test]
    fn store_evicts_expired_entries() {
        let store = GossipStore::new(0); // 0-second TTL = immediate expiry
        let id = MessageId::from_bytes([3u8; 32]);
        let sender = NodeId::from_bytes([4u8; 32]);

        store.mark_seen(id, sender);
        // With 0 TTL, eviction should remove it
        store.evict_expired();
        assert!(!store.is_seen(&id), "expired entry should be evicted");
    }

    #[test]
    fn store_len_reflects_entries() {
        let store = GossipStore::new(DEFAULT_DEDUP_TTL_SECS);
        assert_eq!(store.len(), 0);

        let id1 = MessageId::from_bytes([5u8; 32]);
        let id2 = MessageId::from_bytes([6u8; 32]);
        let sender = NodeId::from_bytes([7u8; 32]);

        store.mark_seen(id1, sender);
        assert_eq!(store.len(), 1);

        store.mark_seen(id2, sender);
        assert_eq!(store.len(), 2);

        // Duplicate should not increase len
        store.mark_seen(id1, sender);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn store_is_empty_when_fresh() {
        let store = GossipStore::new(DEFAULT_DEDUP_TTL_SECS);
        assert!(store.is_empty());
    }

    // ── GossipValidator tests ─────────────────────────────────────────

    #[test]
    fn validator_accepts_fresh_message() {
        let config = GossipConfig::default();
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([10u8; 32]);
        let id = MessageId::from_bytes([11u8; 32]);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let result = validator.validate(&id, &sender, now_ms);
        assert!(result.is_ok(), "fresh message should be accepted");
    }

    #[test]
    fn validator_rejects_duplicate() {
        let config = GossipConfig::default();
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([20u8; 32]);
        let id = MessageId::from_bytes([21u8; 32]);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        validator.validate(&id, &sender, now_ms).unwrap();
        let result = validator.validate(&id, &sender, now_ms);
        assert!(matches!(result, Err(GossipError::Duplicate(_))));
    }

    #[test]
    fn validator_rejects_stale_message() {
        let config = GossipConfig {
            max_age_secs: 60,
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([30u8; 32]);
        let id = MessageId::from_bytes([31u8; 32]);
        // 2 minutes ago
        let old_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - 120_000;

        let result = validator.validate(&id, &sender, old_ts);
        assert!(matches!(result, Err(GossipError::TooOld { .. })));
    }

    #[test]
    fn validator_rejects_future_message() {
        let config = GossipConfig::default();
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([40u8; 32]);
        let id = MessageId::from_bytes([41u8; 32]);
        // 10 minutes in the future
        let future_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 600_000;

        let result = validator.validate(&id, &sender, future_ts);
        assert!(matches!(result, Err(GossipError::FromFuture { .. })));
    }

    #[test]
    fn validator_enforces_rate_limit() {
        let config = GossipConfig {
            max_per_sender_per_hour: 3,
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([50u8; 32]);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // First 3 should succeed
        for i in 0u8..3 {
            let id = MessageId::from_bytes([60 + i; 32]);
            validator.validate(&id, &sender, now_ms).unwrap();
        }

        // 4th should be rate-limited
        let id4 = MessageId::from_bytes([70u8; 32]);
        let result = validator.validate(&id4, &sender, now_ms);
        assert!(matches!(result, Err(GossipError::RateLimited { .. })));
    }

    #[test]
    fn validator_rate_limit_per_sender() {
        let config = GossipConfig {
            max_per_sender_per_hour: 2,
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender_a = NodeId::from_bytes([80u8; 32]);
        let sender_b = NodeId::from_bytes([81u8; 32]);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Sender A: 2 messages
        for i in 0u8..2 {
            let id = MessageId::from_bytes([90 + i; 32]);
            validator.validate(&id, &sender_a, now_ms).unwrap();
        }

        // Sender A is now rate-limited
        let id_a3 = MessageId::from_bytes([99u8; 32]);
        assert!(validator.validate(&id_a3, &sender_a, now_ms).is_err());

        // Sender B should still be allowed
        let id_b1 = MessageId::from_bytes([100u8; 32]);
        assert!(validator.validate(&id_b1, &sender_b, now_ms).is_ok());
    }

    #[test]
    fn validator_rate_limit_window_resets() {
        let config = GossipConfig {
            max_per_sender_per_hour: 2,
            rate_limit_window: Duration::from_millis(50),
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([110u8; 32]);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Fill the rate limit
        for i in 0u8..2 {
            let id = MessageId::from_bytes([120 + i; 32]);
            validator.validate(&id, &sender, now_ms).unwrap();
        }

        // Sleep past the window
        std::thread::sleep(Duration::from_millis(60));

        // Should be allowed again after window reset
        let id_new = MessageId::from_bytes([130u8; 32]);
        assert!(validator.validate(&id_new, &sender, now_ms).is_ok());
    }

    #[test]
    fn validator_evict_expired_cleans_store() {
        let config = GossipConfig {
            dedup_ttl_secs: 0, // immediate expiry
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([140u8; 32]);
        let id = MessageId::from_bytes([141u8; 32]);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        validator.validate(&id, &sender, now_ms).unwrap();
        assert_eq!(validator.store().len(), 1);

        validator.evict_expired();
        assert_eq!(validator.store().len(), 0);
    }

    #[test]
    fn store_multiple_senders_tracked_independently() {
        let store = GossipStore::new(DEFAULT_DEDUP_TTL_SECS);
        let id = MessageId::from_bytes([150u8; 32]);
        let sender_a = NodeId::from_bytes([151u8; 32]);
        let sender_b = NodeId::from_bytes([152u8; 32]);

        // Same message ID from different senders — both tracked
        store.mark_seen(id, sender_a);
        // mark_seen with same ID but different sender should be idempotent
        // (we dedup by MessageId, not by sender)
        store.mark_seen(id, sender_b);
        assert_eq!(store.len(), 1, "same message ID should be deduplicated regardless of sender");
    }

    #[test]
    fn config_default_values() {
        let config = GossipConfig::default();
        assert_eq!(config.max_per_sender_per_hour, DEFAULT_MAX_GOSSIP_PER_SENDER_PER_HOUR);
        assert_eq!(config.max_age_secs, DEFAULT_MAX_AGE_SECS);
        assert_eq!(config.dedup_ttl_secs, DEFAULT_DEDUP_TTL_SECS);
        assert_eq!(config.max_future_secs, 300);
    }

    // ── Rate limit eviction tests ────────────────────────────────────

    #[test]
    fn evict_expired_cleans_stale_rate_limit_entries() {
        let config = GossipConfig {
            max_per_sender_per_hour: 100,
            rate_limit_window: Duration::from_millis(50),
            dedup_ttl_secs: 0,
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([160u8; 32]);
        let id = MessageId::from_bytes([161u8; 32]);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        validator.validate(&id, &sender, now_ms).unwrap();
        assert_eq!(validator.tracked_senders(), 1);

        // Wait for the rate limit window to expire
        std::thread::sleep(Duration::from_millis(60));

        validator.evict_expired();
        assert_eq!(validator.tracked_senders(), 0, "expired rate limit entry should be evicted");
    }

    #[test]
    fn evict_expired_keeps_active_rate_limit_entries() {
        let config = GossipConfig {
            max_per_sender_per_hour: 100,
            rate_limit_window: Duration::from_secs(3600),
            dedup_ttl_secs: 0,
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([162u8; 32]);
        let id = MessageId::from_bytes([163u8; 32]);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        validator.validate(&id, &sender, now_ms).unwrap();
        validator.evict_expired();
        assert_eq!(validator.tracked_senders(), 1, "active rate limit entry should survive eviction");
    }

    #[test]
    fn evict_expired_handles_mixed_stale_and_active() {
        let config = GossipConfig {
            max_per_sender_per_hour: 100,
            rate_limit_window: Duration::from_millis(50),
            dedup_ttl_secs: 0,
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Sender A — will expire
        let sender_a = NodeId::from_bytes([164u8; 32]);
        let id_a = MessageId::from_bytes([165u8; 32]);
        validator.validate(&id_a, &sender_a, now_ms).unwrap();

        // Wait for A's window to expire
        std::thread::sleep(Duration::from_millis(60));

        // Sender B — still active
        let sender_b = NodeId::from_bytes([166u8; 32]);
        let id_b = MessageId::from_bytes([167u8; 32]);
        validator.validate(&id_b, &sender_b, now_ms).unwrap();

        assert_eq!(validator.tracked_senders(), 2);
        validator.evict_expired();
        assert_eq!(validator.tracked_senders(), 1, "only stale sender should be evicted");
    }

    // ── Boundary condition tests ─────────────────────────────────────

    #[test]
    fn validator_accepts_message_exactly_at_max_age_boundary() {
        let config = GossipConfig {
            max_age_secs: 60,
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([170u8; 32]);
        let id = MessageId::from_bytes([171u8; 32]);
        // Exactly 60 seconds ago (boundary: age_secs == max_age_secs)
        // age_ms = 60_000, age_secs = 60, which is NOT > 60, so it should pass
        let boundary_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - 60_000;

        let result = validator.validate(&id, &sender, boundary_ts);
        assert!(result.is_ok(), "message exactly at max_age boundary should be accepted");
    }

    #[test]
    fn validator_rejects_message_one_second_past_max_age() {
        let config = GossipConfig {
            max_age_secs: 60,
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([172u8; 32]);
        let id = MessageId::from_bytes([173u8; 32]);
        // 61 seconds ago — just past the boundary
        let past_boundary_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - 61_000;

        let result = validator.validate(&id, &sender, past_boundary_ts);
        assert!(matches!(result, Err(GossipError::TooOld { age_secs: 61, max_secs: 60 })));
    }

    #[test]
    fn validator_accepts_message_exactly_at_max_future_boundary() {
        let config = GossipConfig {
            max_future_secs: 300,
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([174u8; 32]);
        let id = MessageId::from_bytes([175u8; 32]);
        // Exactly 300 seconds in the future (boundary: ahead_secs == max_future_secs)
        // ahead_ms = 300_000, ahead_secs = 300, which is NOT > 300, so it should pass
        let boundary_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 300_000;

        let result = validator.validate(&id, &sender, boundary_ts);
        assert!(result.is_ok(), "message exactly at max_future boundary should be accepted");
    }

    #[test]
    fn validator_rejects_message_one_second_past_max_future() {
        let config = GossipConfig {
            max_future_secs: 300,
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([176u8; 32]);
        let id = MessageId::from_bytes([177u8; 32]);
        // 301 seconds in the future — just past the boundary
        let future_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 301_000;

        let result = validator.validate(&id, &sender, future_ts);
        assert!(matches!(result, Err(GossipError::FromFuture { max_secs: 300, .. })));
    }

    #[test]
    fn validator_accepts_message_slightly_in_future_within_tolerance() {
        let config = GossipConfig::default();
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([178u8; 32]);
        let id = MessageId::from_bytes([179u8; 32]);
        // 10 seconds in the future — well within 300s tolerance
        let future_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 10_000;

        let result = validator.validate(&id, &sender, future_ts);
        assert!(result.is_ok(), "message slightly in the future should be accepted");
    }

    // ── Store get_sender tests ───────────────────────────────────────

    #[test]
    fn store_get_sender_returns_correct_sender() {
        let store = GossipStore::new(DEFAULT_DEDUP_TTL_SECS);
        let id = MessageId::from_bytes([180u8; 32]);
        let sender = NodeId::from_bytes([181u8; 32]);

        assert!(store.get_sender(&id).is_none(), "unknown ID should return None");
        store.mark_seen(id, sender);
        assert_eq!(store.get_sender(&id), Some(sender), "should return the original sender");
    }

    #[test]
    fn store_get_sender_preserves_first_sender_on_duplicate_mark() {
        let store = GossipStore::new(DEFAULT_DEDUP_TTL_SECS);
        let id = MessageId::from_bytes([182u8; 32]);
        let sender_first = NodeId::from_bytes([183u8; 32]);
        let sender_second = NodeId::from_bytes([184u8; 32]);

        store.mark_seen(id, sender_first);
        store.mark_seen(id, sender_second); // or_insert = no-op
        assert_eq!(store.get_sender(&id), Some(sender_first), "first sender should be preserved");
    }

    // ── Rate limit exact boundary tests ──────────────────────────────

    #[test]
    fn validator_rate_limit_exactly_at_max_succeeds() {
        let config = GossipConfig {
            max_per_sender_per_hour: 3,
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([185u8; 32]);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Send exactly max_per_sender_per_hour messages
        for i in 0u8..3 {
            let id = MessageId::from_bytes([186 + i; 32]);
            let result = validator.validate(&id, &sender, now_ms);
            assert!(result.is_ok(), "message {i} of 3 should succeed");
        }

        // The max+1 th message fails
        let id_over = MessageId::from_bytes([200u8; 32]);
        let result = validator.validate(&id_over, &sender, now_ms);
        match result {
            Err(GossipError::RateLimited { count, max, .. }) => {
                assert_eq!(count, 3);
                assert_eq!(max, 3);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn validator_rate_limit_max_one_allows_single_message() {
        let config = GossipConfig {
            max_per_sender_per_hour: 1,
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([201u8; 32]);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let id1 = MessageId::from_bytes([202u8; 32]);
        assert!(validator.validate(&id1, &sender, now_ms).is_ok());

        let id2 = MessageId::from_bytes([203u8; 32]);
        assert!(matches!(validator.validate(&id2, &sender, now_ms), Err(GossipError::RateLimited { .. })));
    }

    // ── Concurrent access test ───────────────────────────────────────

    #[test]
    fn validator_concurrent_access_is_safe() {
        use std::sync::Arc;
        use std::thread;

        let config = GossipConfig {
            max_per_sender_per_hour: 1000,
            ..Default::default()
        };
        let validator = Arc::new(GossipValidator::new(config));
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let mut handles = Vec::new();
        // 8 threads, each sending 10 unique messages from a unique sender
        for t in 0u8..8 {
            let v = Arc::clone(&validator);
            handles.push(thread::spawn(move || {
                let sender = NodeId::from_bytes([t; 32]);
                let mut accepted = 0u32;
                for i in 0u8..10 {
                    // Unique message IDs per thread+message
                    let mut id_bytes = [0u8; 32];
                    id_bytes[0] = t;
                    id_bytes[1] = i;
                    let id = MessageId::from_bytes(id_bytes);
                    if v.validate(&id, &sender, now_ms).is_ok() {
                        accepted += 1;
                    }
                }
                accepted
            }));
        }

        let total_accepted: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        // 8 threads * 10 unique messages each = 80 total
        assert_eq!(total_accepted, 80, "all unique messages should be accepted across threads");
        assert_eq!(validator.tracked_senders(), 8, "all 8 senders should be tracked");
    }

    // ── Timestamp edge cases ─────────────────────────────────────────

    #[test]
    fn validator_accepts_message_with_current_timestamp() {
        let config = GossipConfig {
            max_age_secs: 1,    // very tight window
            max_future_secs: 1, // very tight window
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([210u8; 32]);
        let id = MessageId::from_bytes([211u8; 32]);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let result = validator.validate(&id, &sender, now_ms);
        assert!(result.is_ok(), "message with current timestamp should always be accepted");
    }

    #[test]
    fn validator_zero_max_age_rejects_even_recent_messages() {
        let config = GossipConfig {
            max_age_secs: 0, // reject everything that isn't from the future or exact now
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([212u8; 32]);
        let id = MessageId::from_bytes([213u8; 32]);
        // 1 second ago
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - 1_000;

        let result = validator.validate(&id, &sender, ts);
        assert!(matches!(result, Err(GossipError::TooOld { .. })));
    }

    #[test]
    fn validator_zero_max_future_rejects_any_future_message() {
        let config = GossipConfig {
            max_future_secs: 0, // reject everything from the future
            ..Default::default()
        };
        let validator = GossipValidator::new(config);
        let sender = NodeId::from_bytes([214u8; 32]);
        let id = MessageId::from_bytes([215u8; 32]);
        // 2 seconds in the future
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 2_000;

        let result = validator.validate(&id, &sender, ts);
        assert!(matches!(result, Err(GossipError::FromFuture { .. })));
    }
}
