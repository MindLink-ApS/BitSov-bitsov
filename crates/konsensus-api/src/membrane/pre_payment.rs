//! Unpaid traffic can buy neither identity-indexed telemetry nor event storage.
//! Only fixed reason counters in a fixed array of coarse hours are retained.

use std::collections::BTreeMap;

use serde::Serialize;

const BUCKET_MS: u64 = 3_600_000;
const CAPACITY: usize = 24;
const REASONS: [PrePaymentReason; 8] = [
    PrePaymentReason::SessionBeforePayment,
    PrePaymentReason::DeliveryBeforePayment,
    PrePaymentReason::PriceBeforePayment,
    PrePaymentReason::PeerExchangeBeforePayment,
    PrePaymentReason::LightningInfoBeforePayment,
    PrePaymentReason::GossipBeforePayment,
    PrePaymentReason::InvoiceErrorBeforePayment,
    PrePaymentReason::AdmissionRequired,
];

/// Fixed vocabulary: no peer, address, request identifier or attacker text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrePaymentReason {
    /// Session establishment requires a privileged connection.
    SessionBeforePayment,
    /// Delivery acknowledgements cannot change trust before admission.
    DeliveryBeforePayment,
    /// Unpaid peers cannot read or update pricing via control frames.
    PriceBeforePayment,
    /// Peer discovery requires admission.
    PeerExchangeBeforePayment,
    /// Lightning onboarding requires admission.
    LightningInfoBeforePayment,
    /// Relaying gossip requires admission.
    GossipBeforePayment,
    /// An unpaid peer cannot cancel an unbound invoice request.
    InvoiceErrorBeforePayment,
    /// A non-admission invoice request requires admission first.
    AdmissionRequired,
}

#[derive(Clone, Copy, Default)]
struct Bucket {
    start_ms: u64,
    counts: [u64; REASONS.len()],
}

/// Read-only aggregate, independent of the event ring's `since` and `limit`.
#[derive(Debug, Serialize)]
pub struct PrePaymentRefusals {
    /// UTC hour width in milliseconds.
    pub bucket_ms: u64,
    /// Maximum retained hours, including the current hour.
    pub capacity: usize,
    /// Effective current UTC hour after rollback clamping, including quiet reads.
    pub effective_hour_start_ms: u64,
    /// Nonempty buckets, oldest first. Volatile; resets on restart.
    pub buckets: Vec<PrePaymentBucket>,
}

/// Counts for one coarse hour. No per-event data is retained.
#[derive(Debug, Serialize)]
pub struct PrePaymentBucket {
    /// UTC hour start (unix milliseconds).
    pub start_ms: u64,
    /// Only nonzero counts, keyed by fixed reasons.
    pub counts: BTreeMap<PrePaymentReason, u64>,
}

#[derive(Default)]
pub(super) struct PrePaymentCounters {
    buckets: [Bucket; CAPACITY],
    latest_start_ms: u64,
}

impl PrePaymentCounters {
    fn advance(&mut self, now_ms: u64) -> u64 {
        // A backward clock step must not resurrect expired buckets or evict
        // newer ones. Attribute new counts to the last observed coarse hour.
        self.latest_start_ms = self.latest_start_ms.max(now_ms / BUCKET_MS * BUCKET_MS);
        let oldest = self
            .latest_start_ms
            .saturating_sub((CAPACITY as u64 - 1) * BUCKET_MS);
        for bucket in &mut self.buckets {
            if bucket.start_ms < oldest {
                *bucket = Bucket::default();
            }
        }
        self.latest_start_ms
    }

    pub(super) fn record(&mut self, reason: PrePaymentReason, now_ms: u64) {
        let start_ms = self.advance(now_ms);
        let bucket = &mut self.buckets[(start_ms / BUCKET_MS % CAPACITY as u64) as usize];
        if bucket.start_ms != start_ms {
            *bucket = Bucket {
                start_ms,
                ..Bucket::default()
            };
        }
        let count = &mut bucket.counts[reason as usize];
        *count = count.saturating_add(1);
    }

    pub(super) fn snapshot(&mut self, now_ms: u64) -> PrePaymentRefusals {
        let effective_hour_start_ms = self.advance(now_ms);
        let mut buckets: Vec<_> = self
            .buckets
            .iter()
            .filter_map(|bucket| {
                let counts: BTreeMap<_, _> = REASONS
                    .iter()
                    .zip(bucket.counts)
                    .filter(|(_, count)| *count > 0)
                    .map(|(reason, count)| (*reason, count))
                    .collect();
                (!counts.is_empty()).then_some(PrePaymentBucket {
                    start_ms: bucket.start_ms,
                    counts,
                })
            })
            .collect();
        buckets.sort_unstable_by_key(|bucket| bucket.start_ms);
        PrePaymentRefusals {
            bucket_ms: BUCKET_MS,
            capacity: CAPACITY,
            effective_hour_start_ms,
            buckets,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_exposes_effective_hour_after_quiet_read_and_rollback() {
        let mut counters = PrePaymentCounters::default();
        counters.record(PrePaymentReason::SessionBeforePayment, 100 * BUCKET_MS);
        let quiet = serde_json::to_value(counters.snapshot(101 * BUCKET_MS)).unwrap();
        assert_eq!(quiet["effective_hour_start_ms"], 101 * BUCKET_MS);
        assert_eq!(quiet["buckets"].as_array().unwrap().len(), 1);
        assert_eq!(quiet["buckets"][0]["start_ms"], 100 * BUCKET_MS);

        let rollback = serde_json::to_value(counters.snapshot(99 * BUCKET_MS)).unwrap();
        assert_eq!(rollback, quiet);
        counters.record(PrePaymentReason::AdmissionRequired, 99 * BUCKET_MS);
        let recorded = serde_json::to_value(counters.snapshot(99 * BUCKET_MS)).unwrap();
        assert_eq!(recorded["effective_hour_start_ms"], 101 * BUCKET_MS);
        assert_eq!(recorded["buckets"][1]["start_ms"], 101 * BUCKET_MS);
        assert_eq!(recorded["buckets"][1]["counts"]["admission_required"], 1);

        let expired = serde_json::to_value(counters.snapshot(125 * BUCKET_MS)).unwrap();
        assert_eq!(expired["effective_hour_start_ms"], 125 * BUCKET_MS);
        assert_eq!(expired["buckets"], serde_json::json!([]));
    }

    #[test]
    fn counter_saturates_without_wrapping_or_panicking() {
        let mut counters = PrePaymentCounters::default();
        counters.buckets[0].counts[0] = u64::MAX;
        counters.record(PrePaymentReason::SessionBeforePayment, 0);
        assert_eq!(
            counters.snapshot(0).buckets[0].counts[&PrePaymentReason::SessionBeforePayment],
            u64::MAX
        );
    }
}
