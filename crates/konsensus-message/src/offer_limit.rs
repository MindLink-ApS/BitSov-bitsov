//! Rate limit for eager prekey offers (PSI-SPEED).
//!
//! A paid first contact used to wait for the 15 s E2EE self-heal tick before
//! either side offered its X3DH prekey. The eager path offers right away: the
//! payee as soon as a settled payment promotes the payer's connection, the
//! payer right after its admission proof goes out. Each eager offer costs a
//! prekey serialization and a frame, and the trigger (a paid admission) is in
//! the remote's hands, so every eager offer passes this limiter first:
//!
//! - at most one per peer per [`PER_PEER_COOLDOWN`], and
//! - at most [`GLOBAL_MAX`] per [`GLOBAL_WINDOW`] across all peers,
//!
//! so a flood of paid admissions cannot drive unbounded offers. A refused
//! offer costs only latency: the periodic self-heal still offers on its tick.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use konsensus_core::types::NodeId;

/// One eager offer per peer inside this window (matches the session
/// negotiation cooldown: a second offer inside it would be throttled anyway).
pub const PER_PEER_COOLDOWN: Duration = Duration::from_secs(10);

/// Window of the node-wide cap.
pub const GLOBAL_WINDOW: Duration = Duration::from_secs(1);

/// Eager offers allowed per [`GLOBAL_WINDOW`], across all peers.
pub const GLOBAL_MAX: u32 = 16;

/// Per-peer entries kept before cooled-down ones are evicted.
const MAX_ENTRIES: usize = 10_000;

/// Admits or refuses eager prekey offers. See the module docs.
#[derive(Debug)]
pub struct EagerOfferLimiter {
    last: HashMap<NodeId, Instant>,
    window_start: Option<Instant>,
    in_window: u32,
}

impl Default for EagerOfferLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl EagerOfferLimiter {
    pub fn new() -> Self {
        Self { last: HashMap::new(), window_start: None, in_window: 0 }
    }

    /// `true` (and the offer is counted) if an eager offer to `peer` may go
    /// out at `now`; `false` if the peer is cooling down or the node-wide cap
    /// for this window is spent.
    pub fn allow(&mut self, peer: &NodeId, now: Instant) -> bool {
        if self
            .last
            .get(peer)
            .is_some_and(|last| now.saturating_duration_since(*last) < PER_PEER_COOLDOWN)
        {
            return false;
        }
        match self.window_start {
            Some(start) if now.saturating_duration_since(start) < GLOBAL_WINDOW => {
                if self.in_window >= GLOBAL_MAX {
                    return false;
                }
            }
            _ => {
                self.window_start = Some(now);
                self.in_window = 0;
            }
        }
        if self.last.len() >= MAX_ENTRIES {
            self.last.retain(|_, t| now.saturating_duration_since(*t) < PER_PEER_COOLDOWN);
        }
        self.in_window += 1;
        self.last.insert(*peer, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u16) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[..2].copy_from_slice(&n.to_be_bytes());
        NodeId::from_bytes(bytes)
    }

    #[test]
    fn one_offer_per_peer_per_cooldown() {
        let mut limiter = EagerOfferLimiter::new();
        let t0 = Instant::now();
        assert!(limiter.allow(&peer(1), t0));
        assert!(!limiter.allow(&peer(1), t0 + Duration::from_secs(9)));
        assert!(limiter.allow(&peer(1), t0 + PER_PEER_COOLDOWN));
    }

    #[test]
    fn a_flood_of_distinct_peers_is_capped_per_window() {
        let mut limiter = EagerOfferLimiter::new();
        let t0 = Instant::now();
        let allowed = (0..1_000u16).filter(|n| limiter.allow(&peer(*n), t0)).count();
        assert_eq!(allowed, GLOBAL_MAX as usize, "one window admits GLOBAL_MAX offers");
        // The next window admits another GLOBAL_MAX, never more.
        let t1 = t0 + GLOBAL_WINDOW;
        let allowed = (1_000..2_000u16).filter(|n| limiter.allow(&peer(*n), t1)).count();
        assert_eq!(allowed, GLOBAL_MAX as usize);
    }

    #[test]
    fn a_refused_offer_does_not_start_the_peer_cooldown() {
        let mut limiter = EagerOfferLimiter::new();
        let t0 = Instant::now();
        for n in 0..GLOBAL_MAX as u16 {
            assert!(limiter.allow(&peer(n), t0));
        }
        assert!(!limiter.allow(&peer(999), t0), "cap spent");
        assert!(limiter.allow(&peer(999), t0 + GLOBAL_WINDOW), "not cooling down from a refusal");
    }

    #[test]
    fn memory_stays_bounded() {
        let mut limiter = EagerOfferLimiter::new();
        let mut now = Instant::now();
        for n in 0..(MAX_ENTRIES as u32 + 100) {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&n.to_be_bytes());
            // Spread over time so the global cap never refuses.
            now += PER_PEER_COOLDOWN;
            limiter.allow(&NodeId::from_bytes(bytes), now);
        }
        assert!(limiter.last.len() <= MAX_ENTRIES);
    }
}
