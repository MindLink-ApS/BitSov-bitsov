//! Media budgets belong to authenticated identities, across reader generations.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use konsensus_core::types::NodeId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// Allow the router's maximum 64 calls at 100 frames/s each, with at most
// 64 queued frames per identity in the shared 512-frame channel. Wire parsing
// caps each frame's bytes, so this also bounds admitted media bandwidth.
const MEDIA_FRAMES_PER_SECOND: f64 = 100.0 * 64.0;
const MEDIA_PEER_QUEUE: usize = 64;
const MAX_MEDIA_PEERS: usize = 4096;
const MEDIA_IDLE_TIMEOUT: Duration = Duration::from_secs(1);

struct PeerBudget {
    tokens: f64,
    updated: Instant,
    slots: Arc<Semaphore>,
}

impl PeerBudget {
    fn replenished(&self, now: Instant) -> f64 {
        (self.tokens
            + now.saturating_duration_since(self.updated).as_secs_f64() * MEDIA_FRAMES_PER_SECOND)
            .min(MEDIA_PEER_QUEUE as f64)
    }

    fn idle(&self, now: Instant) -> bool {
        // A queued frame pins this exact semaphore even after disconnect.
        // Forgetting a partially spent rate budget would also grant a new burst.
        self.slots.available_permits() == MEDIA_PEER_QUEUE
            && now.saturating_duration_since(self.updated) >= MEDIA_IDLE_TIMEOUT
            && self.replenished(now) == MEDIA_PEER_QUEUE as f64
    }
}

#[derive(Default)]
struct Budgets {
    peers: HashMap<NodeId, PeerBudget>,
    last_cleanup: Option<Instant>,
}

/// Shared by every acceptor, dialer and reconnect worker in one transport.
/// Readers never cache entries: lookup, eviction and acquisition are serialized
/// so an idle entry cannot be replaced while an old reader can still spend it.
#[derive(Default)]
pub(super) struct MediaIngress(Mutex<Budgets>);

impl MediaIngress {
    pub(super) fn try_acquire(&self, peer: NodeId, now: Instant) -> Option<OwnedSemaphorePermit> {
        let mut budgets = self.0.lock().unwrap_or_else(|e| e.into_inner());
        // A delayed reader must not recreate an evicted entry with a clock
        // predating eviction, then collect that elapsed time as another burst.
        let now = now.max(budgets.last_cleanup.unwrap_or(now));
        // Lazy idle eviction, at most one bounded scan per second even under
        // identity churn. Without traffic, retained state is still hard-capped.
        if budgets
            .last_cleanup
            .is_none_or(|last| now.saturating_duration_since(last) >= MEDIA_IDLE_TIMEOUT)
        {
            budgets.peers.retain(|_, budget| !budget.idle(now));
            budgets.last_cleanup = Some(now);
        }
        if budgets.peers.len() >= MAX_MEDIA_PEERS && !budgets.peers.contains_key(&peer) {
            return None;
        }
        let budget = budgets.peers.entry(peer).or_insert_with(|| PeerBudget {
            tokens: MEDIA_PEER_QUEUE as f64,
            updated: now,
            slots: Arc::new(Semaphore::new(MEDIA_PEER_QUEUE)),
        });
        // Concurrent readers may capture timestamps before acquiring this lock.
        let now = now.max(budget.updated);
        budget.tokens = budget.replenished(now);
        budget.updated = now;
        if budget.tokens < 1.0 {
            return None;
        }
        budget.tokens -= 1.0;
        Arc::clone(&budget.slots).try_acquire_owned().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_readers_share_rate_debt_even_after_dequeue() {
        let ingress = Arc::new(MediaIngress::default());
        let peer = NodeId::from_bytes([1; 32]);
        let now = Instant::now();
        let reader = Arc::clone(&ingress);
        for _ in 0..64 {
            // Dequeue immediately so only rate debt, not queue occupancy, remains.
            drop(reader.try_acquire(peer, now).unwrap());
        }
        drop(reader);
        let replacement = Arc::clone(&ingress);
        for _ in 0..1024 {
            assert!(replacement.try_acquire(peer, now).is_none());
        }
        // 6,400 frames/s replenishes exactly 32 frames in five milliseconds.
        let later = now + Duration::from_millis(5);
        for _ in 0..32 {
            drop(replacement.try_acquire(peer, later).unwrap());
        }
        assert!(replacement.try_acquire(peer, later).is_none());
        // An older reader's timestamp must not rewind the refill clock.
        assert!(ingress.try_acquire(peer, now).is_none());
        assert!(replacement.try_acquire(peer, later).is_none());
        // Other identities have independent allowances.
        assert!(ingress
            .try_acquire(NodeId::from_bytes([2; 32]), later)
            .is_some());
        // Idle eviction is safe once debt has recovered; no larger burst accrues.
        let later = now + Duration::from_secs(10);
        for _ in 0..64 {
            drop(ingress.try_acquire(peer, later).unwrap());
        }
        assert!(ingress.try_acquire(peer, later).is_none());
    }

    #[test]
    fn identity_churn_is_bounded_and_only_drained_idle_entries_are_evicted() {
        let ingress = MediaIngress::default();
        let now = Instant::now();
        let mut queued = Vec::new();
        for id in 0..MAX_MEDIA_PEERS as u32 {
            let mut bytes = [0; 32];
            bytes[..4].copy_from_slice(&id.to_be_bytes());
            queued.push(ingress.try_acquire(NodeId::from_bytes(bytes), now).unwrap());
        }
        let newcomer = NodeId::from_bytes([255; 32]);
        assert!(ingress.try_acquire(newcomer, now).is_none());
        let later = now + Duration::from_secs(10);
        assert!(
            ingress.try_acquire(newcomer, later).is_none(),
            "queued entries cannot expire"
        );
        assert_eq!(ingress.0.lock().unwrap().peers.len(), MAX_MEDIA_PEERS);
        // A full table must not deny an already tracked identity its own budget.
        let retained = NodeId::from_bytes([0; 32]);
        let mut retained_queue = vec![queued.remove(0)];
        for _ in 1..64 {
            retained_queue.push(ingress.try_acquire(retained, later).unwrap());
        }
        drop(queued);
        let later = later + MEDIA_IDLE_TIMEOUT;
        assert!(ingress.try_acquire(newcomer, later).is_some());
        assert_eq!(ingress.0.lock().unwrap().peers.len(), 2);
        assert!(
            ingress.try_acquire(retained, later).is_none(),
            "old permits still count"
        );
        // Dequeue exactly one old frame: exactly one new frame can replace it.
        retained_queue.pop();
        let slot = ingress.try_acquire(retained, later).unwrap();
        assert!(ingress.try_acquire(retained, later).is_none());
        drop(slot);
        drop(retained_queue);
        let later = later + MEDIA_IDLE_TIMEOUT;
        assert!(ingress.try_acquire(newcomer, later).is_some());
        assert_eq!(ingress.0.lock().unwrap().peers.len(), 1);
    }

    #[test]
    fn cleanup_does_not_forget_recent_rate_debt() {
        let ingress = MediaIngress::default();
        let now = Instant::now();
        drop(
            ingress
                .try_acquire(NodeId::from_bytes([1; 32]), now)
                .unwrap(),
        );
        let peer = NodeId::from_bytes([2; 32]);
        let before_cleanup = now + Duration::from_millis(999);
        for _ in 0..64 {
            drop(ingress.try_acquire(peer, before_cleanup).unwrap());
        }
        // The cleanup tick is due, but this identity has only refilled 6 tokens.
        let cleanup = now + MEDIA_IDLE_TIMEOUT;
        for _ in 0..6 {
            drop(ingress.try_acquire(peer, cleanup).unwrap());
        }
        assert!(ingress.try_acquire(peer, cleanup).is_none());
        assert_eq!(ingress.0.lock().unwrap().peers.len(), 1);
    }

    #[test]
    fn delayed_reader_cannot_recreate_an_evicted_budget_with_an_old_clock() {
        let ingress = MediaIngress::default();
        let now = Instant::now();
        let peer = NodeId::from_bytes([1; 32]);
        for _ in 0..64 {
            drop(ingress.try_acquire(peer, now).unwrap());
        }
        let cleanup = now + Duration::from_secs(10);
        drop(
            ingress
                .try_acquire(NodeId::from_bytes([2; 32]), cleanup)
                .unwrap(),
        );
        // This reader captured its timestamp before cleanup but was delayed
        // acquiring the lock. Its new bucket must start at the cleanup horizon.
        for _ in 0..64 {
            drop(ingress.try_acquire(peer, now).unwrap());
        }
        assert!(ingress.try_acquire(peer, cleanup).is_none());
        let refilled = cleanup + Duration::from_millis(5);
        for _ in 0..32 {
            drop(ingress.try_acquire(peer, refilled).unwrap());
        }
        assert!(ingress.try_acquire(peer, refilled).is_none());
    }
}
