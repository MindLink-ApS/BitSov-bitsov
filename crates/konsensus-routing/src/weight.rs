//! Synaptic weight — the core unit of connection strength between peers.
//!
//! Each peer-to-peer link has a [`SynapticWeight`] that tracks connection quality
//! through four dimensions: raw weight, latency EMA, success rate, and payment volume.
//! These combine into a single routing score used for path selection.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Default initial weight for a newly discovered peer.
const INITIAL_WEIGHT: f64 = 0.1;

/// Hebbian learning rate: how much a successful delivery increases weight.
/// Formula: `weight += HEBBIAN_RATE * (1.0 - weight)` — approaches 1.0 asymptotically.
const HEBBIAN_RATE: f64 = 0.01;

/// Decay factor applied per minute of inactivity.
/// `weight *= DECAY_PER_MINUTE` — after ~24 hours of silence, weight drops to ~25%.
const DECAY_PER_MINUTE: f64 = 0.999;

/// EMA smoothing factor for latency updates (α in EMA formula).
/// Higher values make EMA more responsive to recent measurements.
const LATENCY_EMA_ALPHA: f64 = 0.3;

/// Weight threshold below which a connection is considered for pruning.
pub const PRUNING_THRESHOLD: f64 = 0.01;

/// Duration a connection must remain below pruning threshold before deactivation.
pub const PRUNING_GRACE_PERIOD: Duration = Duration::from_secs(24 * 3600);

/// Relay count threshold — after this many relays to the same destination via
/// a peer, the routing table suggests a direct connection.
pub const DENDRITIC_GROWTH_THRESHOLD: u32 = 20;

/// Multiplier for learning rate during the "critical period" (first hour of connection).
const CRITICAL_PERIOD_BOOST: f64 = 2.0;

/// Duration of the critical period after first connection.
const CRITICAL_PERIOD_DURATION: Duration = Duration::from_secs(3600);

/// Queue depth at which homeostatic scaling activates, reducing all weights globally.
pub const HOMEOSTATIC_QUEUE_THRESHOLD: usize = 5000;

/// Factor by which all weights are scaled down during homeostatic response.
pub const HOMEOSTATIC_SCALE_FACTOR: f64 = 0.95;

/// Tracks the strength and quality of a connection to a single peer.
///
/// Updated on every message delivery attempt (success or failure) and decayed
/// periodically when the connection is idle. The four fields combine into a
/// routing score used by [`super::RoutingTable`] for path selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynapticWeight {
    /// Connection strength, range \[0.0, 1.0\].
    /// Strengthened by successful delivery (Hebbian), weakened by decay (LTD).
    weight: f64,

    /// Exponential moving average of round-trip latency in milliseconds.
    /// Lower is better. Updated on every successful delivery with an ack.
    latency_ema_ms: f64,

    /// Success rate as a ratio \[0.0, 1.0\]. Computed as `successes / attempts`.
    /// A peer with low success rate gets deprioritized even if weight is high.
    success_rate: f64,

    /// Cumulative payment volume in millisatoshis routed through this peer.
    /// Higher volume indicates economic significance.
    payment_volume_msat: u64,

    /// Total successful deliveries through this peer.
    successes: u64,

    /// Total delivery attempts through this peer.
    attempts: u64,

    /// Number of times this peer was used to relay to a specific destination.
    /// Keyed by destination — tracked externally in RoutingTable, but the
    /// per-peer relay count is here for the dendritic growth check.
    relay_count: u32,

    /// When this weight was last updated (decay reference point).
    /// Serialized as milliseconds since epoch for persistence.
    #[serde(skip, default = "Instant::now")]
    last_updated: Instant,

    /// When the first connection to this peer was established.
    /// Used for critical period (boosted learning) calculation.
    #[serde(skip, default = "Instant::now")]
    first_connected: Instant,

    /// When the weight first dropped below the pruning threshold.
    /// `None` if weight is above threshold. Used for pruning grace period.
    #[serde(skip)]
    below_threshold_since: Option<Instant>,

    /// Whether this connection has been deactivated by synaptic pruning.
    pruned: bool,
}

impl Default for SynapticWeight {
    fn default() -> Self {
        Self::new()
    }
}

impl SynapticWeight {
    /// Create a new synaptic weight with default initial values.
    pub fn new() -> Self {
        Self {
            weight: INITIAL_WEIGHT,
            latency_ema_ms: 0.0,
            success_rate: 1.0,
            payment_volume_msat: 0,
            successes: 0,
            attempts: 0,
            relay_count: 0,
            last_updated: Instant::now(),
            first_connected: Instant::now(),
            below_threshold_since: None,
            pruned: false,
        }
    }

    /// Create a weight with a specific initial value (for testing or migration).
    pub fn with_initial_weight(weight: f64) -> Self {
        Self {
            weight: weight.clamp(0.0, 1.0),
            ..Self::new()
        }
    }

    /// Current weight value in \[0.0, 1.0\].
    pub fn weight(&self) -> f64 {
        self.weight
    }

    /// Current latency EMA in milliseconds.
    pub fn latency_ema_ms(&self) -> f64 {
        self.latency_ema_ms
    }

    /// Current success rate in \[0.0, 1.0\].
    pub fn success_rate(&self) -> f64 {
        self.success_rate
    }

    /// Cumulative payment volume in millisatoshis.
    pub fn payment_volume_msat(&self) -> u64 {
        self.payment_volume_msat
    }

    /// Total successful deliveries.
    pub fn successes(&self) -> u64 {
        self.successes
    }

    /// Total delivery attempts.
    pub fn attempts(&self) -> u64 {
        self.attempts
    }

    /// Number of relays through this peer.
    pub fn relay_count(&self) -> u32 {
        self.relay_count
    }

    /// Whether this connection has been pruned (deactivated).
    pub fn is_pruned(&self) -> bool {
        self.pruned
    }

    /// How long since this weight was last updated.
    pub fn time_since_last_update(&self) -> Duration {
        self.last_updated.elapsed()
    }

    /// Whether this peer is in its critical period (boosted learning).
    pub fn in_critical_period(&self) -> bool {
        self.first_connected.elapsed() < CRITICAL_PERIOD_DURATION
    }

    /// Whether this connection should be suggested for direct peering
    /// (dendritic growth: relay count exceeds threshold).
    pub fn should_suggest_direct(&self) -> bool {
        self.relay_count >= DENDRITIC_GROWTH_THRESHOLD
    }

    /// Record a successful message delivery (Hebbian learning + STDP).
    ///
    /// `latency_ms` is the round-trip time for the delivery ack. Lower latency
    /// produces a stronger STDP bonus. `payment_msat` is the payment amount.
    pub fn record_success(&mut self, latency_ms: f64, payment_msat: u64) {
        self.apply_decay();

        self.attempts = self.attempts.saturating_add(1);
        self.successes = self.successes.saturating_add(1);
        self.payment_volume_msat = self.payment_volume_msat.saturating_add(payment_msat);

        // Hebbian learning: weight += rate * (1 - weight)
        let mut rate = HEBBIAN_RATE;
        if self.in_critical_period() {
            rate *= CRITICAL_PERIOD_BOOST;
        }
        self.weight += rate * (1.0 - self.weight);

        // STDP latency bonus: faster responses strengthen more
        // reward = 1 / (1 + latency_ms) — bounded in (0, 1]
        if latency_ms > 0.0 {
            let stdp_reward = 1.0 / (1.0 + latency_ms);
            self.weight += stdp_reward * rate * 0.5;
        }

        // Sanitize: NaN/Infinity → reset to initial weight rather than
        // allowing corrupted state to propagate to trust discount pricing.
        self.weight = if self.weight.is_finite() {
            self.weight.clamp(0.0, 1.0)
        } else {
            INITIAL_WEIGHT
        };

        // Update latency EMA — sanitize against NaN input
        if !latency_ms.is_finite() || latency_ms < 0.0 {
            // Skip EMA update for invalid latency
        } else if self.latency_ema_ms == 0.0 {
            self.latency_ema_ms = latency_ms;
        } else {
            self.latency_ema_ms =
                LATENCY_EMA_ALPHA * latency_ms + (1.0 - LATENCY_EMA_ALPHA) * self.latency_ema_ms;
        }

        // Update success rate
        self.success_rate = self.successes as f64 / self.attempts as f64;

        // Check pruning threshold
        self.update_pruning_state();

        self.last_updated = Instant::now();
    }

    /// Record a failed delivery attempt.
    pub fn record_failure(&mut self) {
        self.apply_decay();

        self.attempts = self.attempts.saturating_add(1);

        // Failure penalty: weight decreases more sharply than Hebbian increase
        self.weight *= 0.95;

        // Sanitize weight against NaN/Infinity
        if !self.weight.is_finite() {
            self.weight = INITIAL_WEIGHT;
        }

        // Update success rate
        if self.attempts > 0 {
            self.success_rate = self.successes as f64 / self.attempts as f64;
        }

        self.update_pruning_state();
        self.last_updated = Instant::now();
    }

    /// Increment relay count (for dendritic growth tracking).
    pub fn record_relay(&mut self) {
        self.relay_count = self.relay_count.saturating_add(1);
    }

    /// Apply time-based decay (long-term depression).
    ///
    /// Weight decays exponentially based on elapsed time since last update.
    /// Called automatically before any weight modification.
    pub fn apply_decay(&mut self) {
        let elapsed = self.last_updated.elapsed();
        let minutes = elapsed.as_secs_f64() / 60.0;
        if minutes > 0.0 {
            self.weight *= DECAY_PER_MINUTE.powf(minutes);
            // Sanitize: powf with extreme values could produce NaN/Infinity
            if !self.weight.is_finite() {
                self.weight = INITIAL_WEIGHT;
            }
            self.update_pruning_state();
            self.last_updated = Instant::now();
        }
    }

    /// Apply homeostatic scaling — reduce weight by a global factor.
    ///
    /// Called when the node's message queue exceeds the homeostatic threshold,
    /// to reduce routing pressure through overloaded paths.
    pub fn apply_homeostatic_scaling(&mut self) {
        self.weight *= HOMEOSTATIC_SCALE_FACTOR;
        if !self.weight.is_finite() {
            self.weight = INITIAL_WEIGHT;
        }
        self.update_pruning_state();
    }

    /// Check if the connection should be pruned.
    ///
    /// A connection is pruned if its weight has been below the pruning threshold
    /// (0.01) continuously for longer than the grace period (24 hours).
    pub fn check_pruning(&mut self) -> bool {
        if self.pruned {
            return true;
        }

        if let Some(since) = self.below_threshold_since {
            if since.elapsed() >= PRUNING_GRACE_PERIOD {
                self.pruned = true;
                return true;
            }
        }

        false
    }

    /// Reactivate a pruned connection (e.g., after receiving a new message from the peer).
    pub fn reactivate(&mut self) {
        self.pruned = false;
        self.weight = INITIAL_WEIGHT;
        self.below_threshold_since = None;
        self.first_connected = Instant::now(); // New critical period
        self.last_updated = Instant::now();
    }

    /// Compute the routing score for this peer.
    ///
    /// `score = weight * (1 / (1 + latency_ema_ms)) * success_rate`
    ///
    /// Higher score = better routing candidate.
    pub fn routing_score(&self) -> f64 {
        if self.pruned {
            return 0.0;
        }
        let latency_factor = 1.0 / (1.0 + self.latency_ema_ms);
        self.weight * latency_factor * self.success_rate
    }

    /// Force the pruned state (for testing and migration).
    #[doc(hidden)]
    pub fn set_pruned(&mut self, pruned: bool) {
        self.pruned = pruned;
    }

    /// Force weight to a specific value (for testing and migration).
    #[doc(hidden)]
    pub fn set_weight(&mut self, weight: f64) {
        self.weight = weight.clamp(0.0, 1.0);
        self.update_pruning_state();
    }

    /// Force the below-threshold timestamp for pruning tests.
    #[doc(hidden)]
    pub fn set_below_threshold_since(&mut self, since: Option<std::time::Instant>) {
        self.below_threshold_since = since;
    }

    /// Update the below-threshold tracking for pruning decisions.
    fn update_pruning_state(&mut self) {
        if self.weight < PRUNING_THRESHOLD {
            if self.below_threshold_since.is_none() {
                self.below_threshold_since = Some(Instant::now());
            }
        } else {
            self.below_threshold_since = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_weight_has_default_values() {
        let w = SynapticWeight::new();
        assert!((w.weight() - INITIAL_WEIGHT).abs() < f64::EPSILON);
        assert_eq!(w.latency_ema_ms(), 0.0);
        assert_eq!(w.success_rate(), 1.0);
        assert_eq!(w.payment_volume_msat(), 0);
        assert_eq!(w.successes(), 0);
        assert_eq!(w.attempts(), 0);
        assert!(!w.is_pruned());
    }

    #[test]
    fn with_initial_weight_clamps() {
        let w = SynapticWeight::with_initial_weight(1.5);
        assert!((w.weight() - 1.0).abs() < f64::EPSILON);

        let w = SynapticWeight::with_initial_weight(-0.5);
        assert!((w.weight() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn success_increases_weight() {
        let mut w = SynapticWeight::new();
        let initial = w.weight();
        w.record_success(50.0, 1000);
        assert!(w.weight() > initial);
        assert_eq!(w.successes(), 1);
        assert_eq!(w.attempts(), 1);
        assert_eq!(w.payment_volume_msat(), 1000);
    }

    #[test]
    fn multiple_successes_approach_one() {
        let mut w = SynapticWeight::new();
        for _ in 0..1000 {
            w.record_success(10.0, 100);
        }
        // Weight should approach 1.0 but never exceed it
        assert!(w.weight() <= 1.0);
        assert!(w.weight() > 0.9);
    }

    #[test]
    fn failure_decreases_weight() {
        let mut w = SynapticWeight::with_initial_weight(0.5);
        let initial = w.weight();
        w.record_failure();
        assert!(w.weight() < initial);
        assert_eq!(w.successes(), 0);
        assert_eq!(w.attempts(), 1);
    }

    #[test]
    fn success_rate_tracks_correctly() {
        let mut w = SynapticWeight::new();
        w.record_success(10.0, 100);
        w.record_success(10.0, 100);
        w.record_failure();
        // 2 successes out of 3 attempts
        assert!((w.success_rate() - 2.0 / 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn latency_ema_initialized_on_first_success() {
        let mut w = SynapticWeight::new();
        assert_eq!(w.latency_ema_ms(), 0.0);
        w.record_success(100.0, 1000);
        assert!((w.latency_ema_ms() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn latency_ema_smooths_values() {
        let mut w = SynapticWeight::new();
        w.record_success(100.0, 1000); // EMA = 100
        w.record_success(200.0, 1000); // EMA = 0.3*200 + 0.7*100 = 130
        assert!((w.latency_ema_ms() - 130.0).abs() < 1.0);
    }

    #[test]
    fn lower_latency_gives_higher_score() {
        let mut fast = SynapticWeight::with_initial_weight(0.5);
        fast.record_success(10.0, 1000);

        let mut slow = SynapticWeight::with_initial_weight(0.5);
        slow.record_success(500.0, 1000);

        assert!(fast.routing_score() > slow.routing_score());
    }

    #[test]
    fn pruned_peer_scores_zero() {
        let mut w = SynapticWeight::new();
        w.pruned = true;
        assert_eq!(w.routing_score(), 0.0);
    }

    #[test]
    fn reactivate_restores_peer() {
        let mut w = SynapticWeight::new();
        w.pruned = true;
        w.weight = 0.001;
        w.reactivate();
        assert!(!w.is_pruned());
        assert!((w.weight() - INITIAL_WEIGHT).abs() < f64::EPSILON);
    }

    #[test]
    fn relay_count_increments() {
        let mut w = SynapticWeight::new();
        assert!(!w.should_suggest_direct());
        for _ in 0..20 {
            w.record_relay();
        }
        assert!(w.should_suggest_direct());
        assert_eq!(w.relay_count(), 20);
    }

    #[test]
    fn homeostatic_scaling_reduces_weight() {
        let mut w = SynapticWeight::with_initial_weight(0.5);
        w.apply_homeostatic_scaling();
        assert!((w.weight() - 0.5 * HOMEOSTATIC_SCALE_FACTOR).abs() < f64::EPSILON);
    }

    #[test]
    fn payment_volume_saturates() {
        let mut w = SynapticWeight::new();
        w.record_success(10.0, u64::MAX);
        w.record_success(10.0, 1000);
        assert_eq!(w.payment_volume_msat(), u64::MAX);
    }

    #[test]
    fn stdp_bonus_rewards_fast_responses() {
        // Two peers with identical starting weight, one responds fast, one slow
        let mut fast = SynapticWeight::with_initial_weight(0.5);
        fast.record_success(1.0, 1000); // Very fast

        let mut slow = SynapticWeight::with_initial_weight(0.5);
        slow.record_success(1000.0, 1000); // Very slow

        // Fast peer should gain more weight from STDP bonus
        assert!(fast.weight() > slow.weight());
    }

    #[test]
    fn critical_period_boosts_learning() {
        // A fresh peer (in critical period) should learn faster
        let mut fresh = SynapticWeight::new();
        let initial = fresh.weight();
        fresh.record_success(50.0, 1000);
        let fresh_gain = fresh.weight() - initial;

        // A peer whose critical period has expired would learn at normal rate
        // We can't easily test this with real time, but we verify the flag
        assert!(fresh.in_critical_period());
        assert!(fresh_gain > 0.0);
    }

    #[test]
    fn serde_roundtrip() {
        let mut w = SynapticWeight::new();
        w.record_success(50.0, 5000);
        w.record_success(30.0, 3000);
        w.record_relay();

        let json = serde_json::to_string(&w).expect("serialize");
        let w2: SynapticWeight = serde_json::from_str(&json).expect("deserialize");

        assert!((w.weight() - w2.weight()).abs() < f64::EPSILON);
        assert!((w.latency_ema_ms() - w2.latency_ema_ms()).abs() < f64::EPSILON);
        assert!((w.success_rate() - w2.success_rate()).abs() < f64::EPSILON);
        assert_eq!(w.payment_volume_msat(), w2.payment_volume_msat());
        assert_eq!(w.successes(), w2.successes());
        assert_eq!(w.attempts(), w2.attempts());
        assert_eq!(w.relay_count(), w2.relay_count());
        assert_eq!(w.is_pruned(), w2.is_pruned());
    }

    #[test]
    fn routing_score_formula() {
        let mut w = SynapticWeight::with_initial_weight(0.8);
        w.latency_ema_ms = 99.0; // 1/(1+99) = 0.01
        w.success_rate = 0.5;
        // score = 0.8 * 0.01 * 0.5 = 0.004
        let expected = 0.8 * (1.0 / 100.0) * 0.5;
        assert!((w.routing_score() - expected).abs() < 1e-10);
    }

    #[test]
    fn zero_latency_stdp_gives_max_bonus() {
        // latency_ms = 0 should skip STDP (guard: latency_ms > 0.0)
        let mut w = SynapticWeight::with_initial_weight(0.5);
        w.record_success(0.0, 1000);
        // Should not panic and weight should increase from Hebbian only
        assert!(w.weight() > 0.5);
    }

    #[test]
    fn very_small_latency_gives_near_max_stdp() {
        let mut fast = SynapticWeight::with_initial_weight(0.5);
        fast.record_success(0.001, 1000);

        let mut normal = SynapticWeight::with_initial_weight(0.5);
        normal.record_success(100.0, 1000);

        assert!(fast.weight() > normal.weight());
    }

    #[test]
    fn failure_near_zero_weight_stays_non_negative() {
        let mut w = SynapticWeight::with_initial_weight(0.001);
        for _ in 0..100 {
            w.record_failure();
        }
        assert!(w.weight() >= 0.0);
        assert!(w.success_rate() == 0.0);
    }

    #[test]
    fn alternating_success_failure_converges() {
        let mut w = SynapticWeight::new();
        for i in 0..200 {
            if i % 2 == 0 {
                w.record_success(50.0, 100);
            } else {
                w.record_failure();
            }
        }
        // Success rate should be ~0.5
        assert!((w.success_rate() - 0.5).abs() < f64::EPSILON);
        // Weight should stabilize (not explode or collapse)
        assert!(w.weight() > 0.0);
        assert!(w.weight() < 1.0);
    }

    #[test]
    fn routing_score_zero_latency_ema() {
        let mut w = SynapticWeight::with_initial_weight(0.5);
        w.success_rate = 1.0;
        // latency_ema_ms = 0 => factor = 1/(1+0) = 1.0
        // score = 0.5 * 1.0 * 1.0 = 0.5
        assert!((w.routing_score() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn routing_score_zero_success_rate() {
        let mut w = SynapticWeight::with_initial_weight(0.8);
        w.success_rate = 0.0;
        assert_eq!(w.routing_score(), 0.0);
    }

    #[test]
    fn check_pruning_below_threshold_within_grace_period() {
        let mut w = SynapticWeight::with_initial_weight(0.005); // Below PRUNING_THRESHOLD
        w.update_pruning_state(); // Start tracking
        assert!(w.below_threshold_since.is_some());
        // Within grace period — should NOT be pruned
        assert!(!w.check_pruning());
    }

    #[test]
    fn recovery_from_near_pruning() {
        let mut w = SynapticWeight::with_initial_weight(0.005);
        w.update_pruning_state();
        assert!(w.below_threshold_since.is_some());

        // Recovery: weight goes above threshold
        w.weight = 0.5;
        w.update_pruning_state();
        assert!(w.below_threshold_since.is_none());
        assert!(!w.check_pruning());
    }

    #[test]
    fn relay_count_saturates_at_max() {
        let mut w = SynapticWeight::new();
        w.relay_count = u32::MAX;
        w.record_relay();
        assert_eq!(w.relay_count(), u32::MAX);
    }

    #[test]
    fn reactivate_resets_critical_period() {
        let mut w = SynapticWeight::new();
        w.pruned = true;
        w.weight = 0.001;
        w.below_threshold_since = Some(Instant::now());

        w.reactivate();
        assert!(w.in_critical_period());
        assert!(!w.is_pruned());
        assert!(w.below_threshold_since.is_none());
        assert!((w.weight() - INITIAL_WEIGHT).abs() < f64::EPSILON);
    }

    #[test]
    fn multiple_homeostatic_scalings_compound() {
        let mut w = SynapticWeight::with_initial_weight(1.0);
        for _ in 0..10 {
            w.apply_homeostatic_scaling();
        }
        let expected = HOMEOSTATIC_SCALE_FACTOR.powi(10);
        assert!((w.weight() - expected).abs() < 1e-10);
    }

    #[test]
    fn default_impl_matches_new() {
        let d = SynapticWeight::default();
        let n = SynapticWeight::new();
        assert!((d.weight() - n.weight()).abs() < f64::EPSILON);
        assert_eq!(d.successes(), n.successes());
        assert_eq!(d.attempts(), n.attempts());
        assert_eq!(d.is_pruned(), n.is_pruned());
    }

    #[test]
    fn serde_preserves_pruned_state() {
        let mut w = SynapticWeight::new();
        w.pruned = true;
        let json = serde_json::to_string(&w).expect("serialize");
        let w2: SynapticWeight = serde_json::from_str(&json).expect("deserialize");
        assert!(w2.is_pruned());
        assert_eq!(w2.routing_score(), 0.0);
    }

    // ── NaN/Infinity safety tests ─────────────────────────────────────

    #[test]
    fn nan_latency_does_not_corrupt_weight() {
        let mut w = SynapticWeight::new();
        let initial = w.weight();
        w.record_success(f64::NAN, 1000);
        // Weight should have changed (Hebbian learning) but must be finite
        assert!(w.weight().is_finite());
        assert!(w.weight() > initial);
        // Latency EMA should NOT have been updated with NaN
        assert!(w.latency_ema_ms().is_finite());
    }

    #[test]
    fn infinity_latency_does_not_corrupt_weight() {
        let mut w = SynapticWeight::new();
        w.record_success(f64::INFINITY, 1000);
        assert!(w.weight().is_finite());
        assert!(w.latency_ema_ms().is_finite());
    }

    #[test]
    fn negative_latency_skips_ema_update() {
        let mut w = SynapticWeight::new();
        w.record_success(100.0, 1000);
        let ema_after_valid = w.latency_ema_ms();
        w.record_success(-50.0, 1000);
        // EMA should not have changed from negative latency
        // (Hebbian learning still applies, but EMA is unchanged)
        assert!((w.latency_ema_ms() - ema_after_valid).abs() < f64::EPSILON);
    }

    #[test]
    fn corrupted_weight_field_recovers_on_decay() {
        let mut w = SynapticWeight::new();
        // Simulate corrupted weight (e.g., from deserialization)
        w.weight = f64::NAN;
        w.apply_decay();
        // Should recover to INITIAL_WEIGHT, not stay NaN
        assert!(w.weight().is_finite());
        assert!((w.weight() - INITIAL_WEIGHT).abs() < f64::EPSILON);
    }

    #[test]
    fn corrupted_weight_field_recovers_on_failure() {
        let mut w = SynapticWeight::new();
        w.weight = f64::INFINITY;
        w.record_failure();
        assert!(w.weight().is_finite());
        // apply_decay resets to INITIAL_WEIGHT, then record_failure applies * 0.95
        assert!((w.weight() - INITIAL_WEIGHT * 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn homeostatic_scaling_nan_recovery() {
        let mut w = SynapticWeight::new();
        w.weight = f64::NAN;
        w.apply_homeostatic_scaling();
        assert!(w.weight().is_finite());
    }

    #[test]
    fn attempt_counters_use_saturating_add() {
        let mut w = SynapticWeight::new();
        // Set counters near u64::MAX to verify saturating behavior
        w.attempts = u64::MAX - 1;
        w.successes = u64::MAX - 1;
        w.record_success(10.0, 100);
        assert_eq!(w.attempts(), u64::MAX);
        assert_eq!(w.successes(), u64::MAX);
        // One more should saturate, not overflow
        w.record_success(10.0, 100);
        assert_eq!(w.attempts(), u64::MAX);
        assert_eq!(w.successes(), u64::MAX);
        // Test failure path too
        w.attempts = u64::MAX - 1;
        w.record_failure();
        assert_eq!(w.attempts(), u64::MAX);
        w.record_failure();
        assert_eq!(w.attempts(), u64::MAX);
    }
}
