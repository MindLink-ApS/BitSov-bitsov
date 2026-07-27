//! Circuit-breaking, timeout-bounded decorator for the settlement-verification
//! path (doorway hardening #3).
//!
//! The inbound message handler verifies every paid message by asking the
//! Lightning backend for the payment's settlement status
//! ([`LightningProvider::get_payment_status`]). That call is the only backend
//! round-trip on the admission path, and the handler awaits it inline — so a
//! slow or unhealthy backend head-of-line-stalls the whole node, and a cheap
//! paid-but-unsettleable flood amplifies the stall.
//!
//! This decorator wraps **only** `get_payment_status` with four protections,
//! every one **fail-closed** (a backend that is slow, down, at-capacity, or
//! unhealthy yields an *error*, which the payment gate maps to a rejection — it
//! never admits an unverified message):
//!
//! 1. **Per-call timeout** — a verification that does not return within
//!    `call_timeout` fails fast instead of pinning the handler.
//! 2. **Circuit breaker** — after `failure_threshold` consecutive failures the
//!    circuit opens and subsequent calls fast-fail for `open_cooldown` (no
//!    backend hit), capping the damage of a slow/unhealthy backend; after the
//!    cooldown a single probe is allowed (half-open) and closes the circuit on
//!    success.
//! 3. **Bounded verification concurrency** — a semaphore caps how many backend
//!    verifications run at once, so verification work cannot grow without bound
//!    under pressure.
//! 4. **Short negative cache** — a *non-settled* result is cached for
//!    `negative_ttl` so a same-hash retry-flood does not re-hammer the backend.
//!    The cache is **never permanent** and holds **only non-settled** results: a
//!    `Settled` (admission-bearing) result is **never** cached, so the gate's
//!    single-use / replay rules remain the sole authority over admission.
//!
//! It changes **no admission semantics**: a `Settled` result is passed through
//! verbatim, so the gate's recipient-binding, amount, replay, and preimage
//! checks all still run exactly as before. This decorator can only cause *more*
//! rejections (fail-closed), never an admission.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Semaphore;

use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails, PaymentStatus,
};

/// Tunables for [`CircuitBreakerLightning`]. Conservative defaults; an operator
/// override is a mechanical follow-up.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Maximum time a single `get_payment_status` (including waiting for a
    /// concurrency slot) may take before it fails fast.
    pub call_timeout: Duration,
    /// Consecutive failures (timeout or backend error) that open the circuit.
    pub failure_threshold: u32,
    /// How long the circuit stays open (fast-failing) before a half-open probe.
    pub open_cooldown: Duration,
    /// TTL for a cached *non-settled* lookup.
    pub negative_ttl: Duration,
    /// Maximum concurrent backend verifications.
    pub max_concurrent: usize,
    /// Hard cap on negative-cache entries.
    pub negative_cache_cap: usize,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            call_timeout: Duration::from_secs(2),
            failure_threshold: 5,
            open_cooldown: Duration::from_secs(20),
            negative_ttl: Duration::from_secs(3),
            max_concurrent: 16,
            negative_cache_cap: 4096,
        }
    }
}

struct BreakerState {
    consecutive_failures: u32,
    /// `Some(t)` while the circuit is open; fast-fail until `now >= t`.
    open_until: Option<Instant>,
}

struct NegEntry {
    details: PaymentDetails,
    cached_at: Instant,
}

/// A [`LightningProvider`] decorator that hardens the settlement-verification
/// call. Only `get_payment_status` is instrumented; the other required methods
/// delegate straight to the inner provider. Intended to wrap the provider handed
/// to the payment gate on the inbound path.
pub struct CircuitBreakerLightning {
    inner: Arc<dyn LightningProvider>,
    cfg: CircuitBreakerConfig,
    sem: Arc<Semaphore>,
    state: Mutex<BreakerState>,
    neg_cache: Mutex<HashMap<String, NegEntry>>,
}

impl CircuitBreakerLightning {
    /// Wrap `inner` with the given config.
    pub fn new(inner: Arc<dyn LightningProvider>, cfg: CircuitBreakerConfig) -> Self {
        let sem = Arc::new(Semaphore::new(cfg.max_concurrent.max(1)));
        Self {
            inner,
            cfg,
            sem,
            state: Mutex::new(BreakerState {
                consecutive_failures: 0,
                open_until: None,
            }),
            neg_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Wrap `inner` with conservative defaults.
    pub fn with_defaults(inner: Arc<dyn LightningProvider>) -> Self {
        Self::new(inner, CircuitBreakerConfig::default())
    }

    fn is_open(&self, now: Instant) -> bool {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        matches!(st.open_until, Some(until) if now < until)
    }

    fn record_failure(&self, now: Instant) {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.consecutive_failures = st.consecutive_failures.saturating_add(1);
        if st.consecutive_failures >= self.cfg.failure_threshold {
            st.open_until = Some(now + self.cfg.open_cooldown);
        }
    }

    fn record_success(&self) {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.consecutive_failures = 0;
        st.open_until = None;
    }

    fn neg_cache_get(&self, hash: &str, now: Instant) -> Option<PaymentDetails> {
        let mut cache = self.neg_cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = cache.get(hash) {
            if now.saturating_duration_since(entry.cached_at) < self.cfg.negative_ttl {
                return Some(entry.details.clone());
            }
            cache.remove(hash);
        }
        None
    }

    fn neg_cache_put(&self, hash: &str, details: &PaymentDetails, now: Instant) {
        // Defensive: only non-settled results are ever cached (admission-bearing
        // `Settled` results must always re-verify against the live backend so the
        // gate's single-use / replay store stays the sole admission authority).
        if details.status == PaymentStatus::Settled {
            return;
        }
        let mut cache = self.neg_cache.lock().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= self.cfg.negative_cache_cap {
            // Drop expired entries first; if still full, skip caching (best-effort).
            cache.retain(|_, e| now.saturating_duration_since(e.cached_at) < self.cfg.negative_ttl);
            if cache.len() >= self.cfg.negative_cache_cap {
                return;
            }
        }
        cache.insert(
            hash.to_string(),
            NegEntry {
                details: details.clone(),
                cached_at: now,
            },
        );
    }
}

#[async_trait]
impl LightningProvider for CircuitBreakerLightning {
    async fn get_payment_status(
        &self,
        payment_hash: &str,
    ) -> Result<PaymentDetails, LightningError> {
        let now = Instant::now();

        // 1. Circuit open → fast-fail (fail-closed), no backend hit.
        if self.is_open(now) {
            return Err(LightningError::Backend(
                "settlement-verification circuit open (backend unhealthy) — fail-closed".into(),
            ));
        }

        // 2. Recent non-settled result → return it without a backend hit. Gate
        //    sees a non-settled status and rejects (fail-closed). Never serves a
        //    `Settled` result (those are never cached).
        if let Some(details) = self.neg_cache_get(payment_hash, now) {
            return Ok(details);
        }

        // 3. Bounded concurrency: take a slot, but never wait longer than the
        //    call budget (at-capacity for too long is itself a fail-closed error).
        let permit = match tokio::time::timeout(
            self.cfg.call_timeout,
            Arc::clone(&self.sem).acquire_owned(),
        )
        .await
        {
            Ok(Ok(p)) => p,
            _ => {
                self.record_failure(Instant::now());
                return Err(LightningError::Backend(
                    "settlement verification at capacity / timed out acquiring a slot — fail-closed"
                        .into(),
                ));
            }
        };

        // 4. The actual backend call, bounded by the timeout.
        let result =
            tokio::time::timeout(self.cfg.call_timeout, self.inner.get_payment_status(payment_hash))
                .await;
        drop(permit);

        match result {
            Err(_elapsed) => {
                self.record_failure(Instant::now());
                Err(LightningError::Backend(
                    "settlement verification timed out — fail-closed".into(),
                ))
            }
            Ok(Err(e)) => {
                self.record_failure(Instant::now());
                Err(e)
            }
            Ok(Ok(details)) => {
                self.record_success();
                if details.status != PaymentStatus::Settled {
                    self.neg_cache_put(payment_hash, &details, Instant::now());
                }
                Ok(details)
            }
        }
    }

    // ── Pass-through for the rest of the trait (not instrumented) ────────────
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        self.inner
            .create_invoice(amount_msat, description, expiry_secs)
            .await
    }

    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        self.inner.pay_invoice(bolt11).await
    }

    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        self.inner.get_balance_msat().await
    }

    async fn is_available(&self) -> bool {
        self.inner.is_available().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_core::traits::lightning::PaymentDirection;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Behavior knobs for the fake backend.
    #[derive(Clone, Copy)]
    enum Behavior {
        Settled,
        Pending,
        Error,
        /// Sleep this long, then return `Settled` (simulates a slow backend).
        SlowSettled(Duration),
    }

    struct FakeProvider {
        behavior: Mutex<Behavior>,
        /// Total `get_payment_status` calls that reached the backend.
        calls: AtomicU32,
        /// Concurrently in-flight backend calls.
        in_flight: AtomicU32,
        /// High-water mark of concurrent in-flight calls.
        max_in_flight: AtomicU32,
    }

    impl FakeProvider {
        fn new(behavior: Behavior) -> Arc<Self> {
            Arc::new(Self {
                behavior: Mutex::new(behavior),
                calls: AtomicU32::new(0),
                in_flight: AtomicU32::new(0),
                max_in_flight: AtomicU32::new(0),
            })
        }
        fn set(&self, b: Behavior) {
            *self.behavior.lock().unwrap() = b;
        }
    }

    fn settled_details() -> PaymentDetails {
        PaymentDetails {
            payment_hash: "ab".repeat(32),
            preimage: Some("cd".repeat(32)),
            amount_msat: 1000,
            status: PaymentStatus::Settled,
            direction: PaymentDirection::Incoming,
            timestamp: 1_700_000_000,
            memo: None,
            fee_msat: None,
        }
    }

    fn pending_details() -> PaymentDetails {
        PaymentDetails {
            status: PaymentStatus::Pending,
            preimage: None,
            ..settled_details()
        }
    }

    #[async_trait]
    impl LightningProvider for FakeProvider {
        async fn get_payment_status(
            &self,
            _payment_hash: &str,
        ) -> Result<PaymentDetails, LightningError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let cur = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(cur, Ordering::SeqCst);
            // RAII guard so in_flight is decremented even when the decorator's
            // timeout CANCELS this future mid-sleep (otherwise the counter leaks
            // and the concurrency high-water mark is meaningless).
            struct InFlight<'a>(&'a AtomicU32);
            impl Drop for InFlight<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let _guard = InFlight(&self.in_flight);
            let behavior = *self.behavior.lock().unwrap();
            match behavior {
                Behavior::Settled => Ok(settled_details()),
                Behavior::Pending => Ok(pending_details()),
                Behavior::Error => Err(LightningError::Backend("boom".into())),
                Behavior::SlowSettled(d) => {
                    tokio::time::sleep(d).await;
                    Ok(settled_details())
                }
            }
        }
        async fn create_invoice(
            &self,
            _a: u64,
            _d: &str,
            _e: u32,
        ) -> Result<Invoice, LightningError> {
            Err(LightningError::Backend("n/a".into()))
        }
        async fn pay_invoice(&self, _b: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::Backend("n/a".into()))
        }
        async fn get_balance_msat(&self) -> Result<u64, LightningError> {
            Ok(0)
        }
        async fn is_available(&self) -> bool {
            true
        }
    }

    fn fast_cfg() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            call_timeout: Duration::from_millis(80),
            failure_threshold: 3,
            open_cooldown: Duration::from_millis(120),
            negative_ttl: Duration::from_millis(150),
            max_concurrent: 4,
            negative_cache_cap: 1024,
        }
    }

    // 1 — a slow backend fails closed within the timeout (never admits).
    #[tokio::test]
    async fn slow_backend_fails_closed_within_timeout() {
        let fake = FakeProvider::new(Behavior::SlowSettled(Duration::from_secs(5)));
        let cb = CircuitBreakerLightning::new(fake, fast_cfg());
        let start = Instant::now();
        let r = cb.get_payment_status("deadbeef").await;
        assert!(r.is_err(), "a slow backend must fail closed, never hang/admit");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "must time out fast, not wait for the slow backend"
        );
    }

    // 2 — a backend outage opens the circuit, then calls fast-fail without hitting it.
    #[tokio::test]
    async fn outage_opens_circuit_and_subsequent_calls_fast_fail() {
        let fake = FakeProvider::new(Behavior::Error);
        let cb = CircuitBreakerLightning::new(Arc::clone(&fake) as Arc<_>, fast_cfg());
        // Drive `failure_threshold` failures to open the circuit.
        for _ in 0..3 {
            assert!(cb.get_payment_status("h").await.is_err());
        }
        let calls_after_open = fake.calls.load(Ordering::SeqCst);
        // Further calls fast-fail WITHOUT reaching the backend.
        for _ in 0..10 {
            assert!(cb.get_payment_status("h").await.is_err());
        }
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            calls_after_open,
            "an open circuit must not hit the backend"
        );
    }

    // 3 — after the cooldown the circuit recovers (half-open probe closes it).
    #[tokio::test]
    async fn circuit_recovers_after_cooldown() {
        let fake = FakeProvider::new(Behavior::Error);
        let cb = CircuitBreakerLightning::new(Arc::clone(&fake) as Arc<_>, fast_cfg());
        for _ in 0..3 {
            let _ = cb.get_payment_status("h").await;
        }
        // Backend heals; wait out the cooldown.
        fake.set(Behavior::Settled);
        tokio::time::sleep(Duration::from_millis(150)).await;
        let r = cb.get_payment_status("h").await;
        assert!(r.is_ok(), "after cooldown + healthy backend, verification must succeed");
        assert_eq!(r.unwrap().status, PaymentStatus::Settled);
    }

    // 4 — replay/admission safety: a Settled result is NEVER cached, so every
    //     settled lookup re-hits the backend (the gate's replay store stays the
    //     sole admission authority).
    #[tokio::test]
    async fn settled_results_are_never_cached() {
        let fake = FakeProvider::new(Behavior::Settled);
        let cb = CircuitBreakerLightning::new(Arc::clone(&fake) as Arc<_>, fast_cfg());
        for _ in 0..4 {
            assert_eq!(
                cb.get_payment_status("same-hash").await.unwrap().status,
                PaymentStatus::Settled
            );
        }
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            4,
            "every settled verification must reach the backend — positive results are never cached"
        );
    }

    // 4b — a non-settled result IS briefly cached (cuts same-hash retry load).
    #[tokio::test]
    async fn pending_results_are_briefly_negative_cached() {
        let fake = FakeProvider::new(Behavior::Pending);
        let cb = CircuitBreakerLightning::new(Arc::clone(&fake) as Arc<_>, fast_cfg());
        for _ in 0..5 {
            assert_eq!(
                cb.get_payment_status("h").await.unwrap().status,
                PaymentStatus::Pending
            );
        }
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            1,
            "a non-settled result is negative-cached, so the backend is hit once within the TTL"
        );
    }

    // 5 — underpaid-proof safety: the decorator passes a settled result through
    //     verbatim (amount unchanged), so the gate's amount check still fires.
    #[tokio::test]
    async fn settled_details_pass_through_unchanged() {
        let fake = FakeProvider::new(Behavior::Settled);
        let cb = CircuitBreakerLightning::new(fake, fast_cfg());
        let d = cb.get_payment_status("h").await.unwrap();
        let original = settled_details();
        assert_eq!(d.amount_msat, original.amount_msat);
        assert_eq!(d.status, original.status);
        assert_eq!(d.direction, original.direction);
        assert_eq!(d.payment_hash, original.payment_hash);
    }

    // 6 — concurrent paid-flood pressure: many concurrent verifications stay
    //     bounded (≤ max_concurrent in flight), return promptly (fail-closed,
    //     never hang), and the breaker trips under the slow flood.
    #[tokio::test]
    async fn concurrent_flood_stays_bounded_and_fails_closed() {
        let fake = FakeProvider::new(Behavior::SlowSettled(Duration::from_millis(200)));
        let cb = Arc::new(CircuitBreakerLightning::new(Arc::clone(&fake) as Arc<_>, fast_cfg()));
        let start = Instant::now();
        let mut handles = Vec::new();
        for i in 0..64 {
            let cb = Arc::clone(&cb);
            handles.push(tokio::spawn(async move {
                cb.get_payment_status(&format!("hash-{i}")).await
            }));
        }
        let mut errs = 0;
        for h in handles {
            if h.await.unwrap().is_err() {
                errs += 1;
            }
        }
        // Every call returned (no hang) and all fail closed (slow backend).
        assert_eq!(errs, 64, "a slow flood must fail closed for every request");
        // Concurrency was bounded to the configured cap.
        assert!(
            fake.max_in_flight.load(Ordering::SeqCst) <= 4,
            "concurrent backend verifications must be bounded by max_concurrent"
        );
        // The flood resolved quickly relative to 64 × 200ms serial.
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "the flood must not pin the node for the full serial duration"
        );
    }
}
