//! Per-IP rate limiting middleware.
//!
//! Uses a sliding window counter to enforce requests-per-second limits.
//! Each client IP gets its own bucket. Expired entries are periodically
//! cleaned up to prevent memory growth.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::net::SocketAddr;
use std::sync::Arc;

/// Shared rate limiter state.
///
/// Uses a `Mutex<HashMap>` because the critical section is tiny
/// (one HashMap lookup + counter increment). No async lock needed.
#[derive(Debug)]
pub struct RateLimiter {
    /// Per-key request records: (window_start, request_count).
    buckets: Mutex<HashMap<String, Bucket>>,
    /// Maximum requests per window.
    max_requests: u32,
    /// Window duration.
    window: Duration,
}

#[derive(Debug)]
struct Bucket {
    /// Start of the current window.
    window_start: Instant,
    /// Number of requests in the current window.
    count: u32,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// `max_rps` is the maximum requests per second per IP.
    pub fn new(max_rps: u32) -> Self {
        Self::with_window(max_rps, Duration::from_secs(1))
    }

    /// Create a new rate limiter with a custom window duration.
    pub fn with_window(max_requests: u32, window: Duration) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            max_requests,
            window,
        }
    }

    /// Create the dedicated limiter for mnemonic (seed) read-back.
    ///
    /// Allows at most 5 reveal attempts per 60-second window. This is
    /// deliberately strict: revealing the recovery seed is a rare, manual
    /// action (backup display, recovery confirmation), so a human-paced
    /// allowance is plenty while still bounding brute-force of the re-auth
    /// gate to a few tries per minute (HARD-9).
    pub fn mnemonic_reveal_default() -> Self {
        Self::with_window(5, Duration::from_secs(60))
    }

    /// Check if a request for the given logical key is allowed.
    ///
    /// Returns `true` if the request is within the rate limit, `false` otherwise.
    /// Automatically resets the window when it expires.
    pub fn check_key(&self, key: &str) -> bool {
        let now = Instant::now();
        // Recover from mutex poisoning: rate limiter state is non-critical
        // (worst case: a few extra or missed requests), so we accept the
        // inner value rather than propagating the panic.
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| {
            tracing::warn!("rate limiter mutex poisoned, recovering");
            e.into_inner()
        });

        let bucket = buckets.entry(key.to_owned()).or_insert(Bucket {
            window_start: now,
            count: 0,
        });

        // If the window has expired, reset
        if now.duration_since(bucket.window_start) >= self.window {
            bucket.window_start = now;
            bucket.count = 1;
            return true;
        }

        // Increment and check
        bucket.count += 1;
        bucket.count <= self.max_requests
    }

    /// Check if a request from the given IP is allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_key(&ip.to_string())
    }

    /// Force the window for `key` to be treated as expired on the next check.
    ///
    /// The single-key analog of [`cleanup`](Self::cleanup): it ages the bucket's
    /// `window_start` back by the full window duration so the next
    /// [`check_key`](Self::check_key) starts a fresh window. A no-op if the key has
    /// no bucket yet.
    ///
    /// This is the honest reset primitive used to drive the window-reset path of a
    /// process-global per-route limiter deterministically (e.g. the SEC1 `auth_local`
    /// limiter, whose bucket cannot otherwise be aged without waiting a real minute).
    /// It only resets a counter — it never grants extra budget within a live window.
    pub fn expire_key(&self, key: &str) {
        // See check_key() for poisoning rationale.
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| {
            tracing::warn!("rate limiter mutex poisoned during expire_key, recovering");
            e.into_inner()
        });
        if let Some(bucket) = buckets.get_mut(key) {
            // Subtract the window so `now - window_start >= window` on the next check.
            bucket.window_start = bucket
                .window_start
                .checked_sub(self.window)
                .unwrap_or_else(Instant::now);
        }
    }

    /// Remove expired entries to prevent unbounded memory growth.
    ///
    /// Call this periodically (e.g., every 60 seconds).
    pub fn cleanup(&self) {
        let now = Instant::now();
        let expiry = self.window * 2; // Keep entries for 2x the window duration
        // See check() for poisoning rationale
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| {
            tracing::warn!("rate limiter mutex poisoned during cleanup, recovering");
            e.into_inner()
        });
        buckets.retain(|_, bucket| now.duration_since(bucket.window_start) < expiry);
    }
}

/// Axum middleware that enforces per-IP rate limiting.
///
/// Extracts the client IP from the connection info and checks against
/// the rate limiter. Returns 429 Too Many Requests if the limit is exceeded.
///
/// # Fail-closed on a missing client IP
///
/// The per-IP bucket *is* the rate-limit boundary. If `ConnectInfo` is
/// absent we cannot identify the caller, so we **reject the request**
/// rather than substituting a placeholder address. Two concrete attacks
/// the old `unwrap_or(127.0.0.1)` fallback enabled:
///
/// 1. **Bucket collapse.** Every IP-less request shared a single
///    `127.0.0.1` bucket, so one flooding client could exhaust the quota
///    for *all* such requests — or, behind a proxy that strips
///    `ConnectInfo`, every distinct client collapsed into one bucket.
/// 2. **Accidental loopback exemption.** Any rate-limit (or downstream)
///    tier that grants loopback callers special treatment would be handed
///    that exemption by an *unknown* caller masquerading as `127.0.0.1`.
///
/// A genuinely-loopback connection still presents a real loopback
/// `ConnectInfo` and keeps any intentional local-tier exemption. Only a
/// *missing* address fails closed.
///
/// A missing `ConnectInfo` is a server misconfiguration (the router must be
/// served with `into_make_service_with_connect_info::<SocketAddr>()`), so we
/// answer `500 Internal Server Error` rather than a client-facing `4xx`.
pub async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    req: Request,
    next: Next,
) -> Response {
    // Fail closed: a missing client IP must never be treated as loopback,
    // nor share a single placeholder bucket. Without an identifiable peer
    // we cannot enforce the per-IP limit, so we refuse the request.
    let ip = match connect_info {
        Some(ci) => ci.0.ip(),
        None => {
            tracing::error!(
                "rate limiter: missing ConnectInfo for request to {} — rejecting \
                 (router must be served with into_make_service_with_connect_info)",
                req.uri().path()
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "client address unavailable",
            )
                .into_response();
        }
    };

    if !limiter.check(ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "1")],
            "rate limit exceeded",
        )
            .into_response();
    }

    next.run(req).await
}

/// Spawn a background task that periodically cleans up expired rate limiter entries.
pub fn spawn_cleanup_task(limiter: Arc<RateLimiter>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            limiter.cleanup();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_requests_within_limit() {
        let limiter = RateLimiter::new(5);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..5 {
            assert!(limiter.check(ip));
        }
    }

    #[test]
    fn rejects_requests_over_limit() {
        let limiter = RateLimiter::new(3);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(limiter.check(ip)); // 1
        assert!(limiter.check(ip)); // 2
        assert!(limiter.check(ip)); // 3
        assert!(!limiter.check(ip)); // 4 — rejected
    }

    #[test]
    fn separate_limits_per_ip() {
        let limiter = RateLimiter::new(2);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        assert!(limiter.check(ip1));
        assert!(limiter.check(ip1));
        assert!(!limiter.check(ip1)); // ip1 exhausted

        assert!(limiter.check(ip2)); // ip2 still has quota
        assert!(limiter.check(ip2));
        assert!(!limiter.check(ip2));
    }

    #[test]
    fn cleanup_removes_expired_entries() {
        let limiter = RateLimiter::new(10);
        let ip: IpAddr = "172.16.0.1".parse().unwrap();

        limiter.check(ip);

        // Manually expire the entry
        {
            let mut buckets = limiter.buckets.lock().unwrap();
            if let Some(bucket) = buckets.get_mut(&ip.to_string()) {
                bucket.window_start = Instant::now() - Duration::from_secs(10);
            }
        }

        limiter.cleanup();

        let buckets = limiter.buckets.lock().unwrap();
        assert!(buckets.is_empty());
    }

    #[test]
    fn expire_key_resets_window_via_public_api() {
        let limiter = RateLimiter::with_window(2, Duration::from_secs(60));
        let key = "k";

        assert!(limiter.check_key(key)); // 1
        assert!(limiter.check_key(key)); // 2
        assert!(!limiter.check_key(key)); // 3 — exhausted

        // Public reset primitive ages the window out.
        limiter.expire_key(key);

        // Fresh window: allowed again.
        assert!(limiter.check_key(key));
    }

    #[test]
    fn expire_key_is_noop_for_unknown_key() {
        let limiter = RateLimiter::with_window(1, Duration::from_secs(60));
        // No bucket yet — must not panic.
        limiter.expire_key("never-seen");
        assert!(limiter.check_key("never-seen"));
    }

    #[test]
    fn window_resets_after_expiry() {
        let limiter = RateLimiter::new(2);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(!limiter.check(ip)); // exhausted

        // Manually expire the window
        {
            let mut buckets = limiter.buckets.lock().unwrap();
            if let Some(bucket) = buckets.get_mut(&ip.to_string()) {
                bucket.window_start = Instant::now() - Duration::from_secs(2);
            }
        }

        // Should be allowed again after window reset
        assert!(limiter.check(ip));
    }

    // --- Middleware-level tests (HARD-8: fail closed on a missing client IP) ---

    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::routing::get;
    use axum::Router;
    use std::net::Ipv4Addr;
    use tower::ServiceExt; // for `oneshot`

    /// Build a router whose only job is to surface the rate-limit middleware's
    /// decision. The inner handler returns `200 OK`, so any non-200 status is
    /// the middleware short-circuiting.
    fn middleware_router(limiter: Arc<RateLimiter>) -> Router {
        Router::new()
            .route("/", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(
                limiter,
                rate_limit_middleware,
            ))
    }

    /// A request that carries a real loopback `ConnectInfo` is treated as a
    /// genuine loopback connection and is served normally (the intentional
    /// local-tier path is preserved).
    #[tokio::test]
    async fn genuine_loopback_connect_info_is_allowed() {
        let limiter = Arc::new(RateLimiter::new(5));
        let app = middleware_router(limiter);

        let mut req = HttpRequest::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            54321,
        )));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// HARD-8 core: a request with **no** `ConnectInfo` must be rejected
    /// outright. It must NOT be silently bucketed as `127.0.0.1` (which would
    /// both collapse all such callers into one shared bucket and hand them any
    /// loopback-tier exemption). We assert the request is refused with a
    /// 5xx — never `200 OK`.
    #[tokio::test]
    async fn missing_connect_info_is_rejected_not_loopback() {
        let limiter = Arc::new(RateLimiter::new(5));
        let app = middleware_router(limiter.clone());

        // No ConnectInfo extension inserted -> Option<ConnectInfo> resolves None.
        let req = HttpRequest::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();

        // Fail closed: the request is refused, not served.
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "missing client IP must never reach the handler"
        );
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // And it must NOT have consumed the loopback bucket: a subsequent
        // genuine loopback caller still has its full quota. If the old
        // `unwrap_or(127.0.0.1)` fallback were present, the rejected request
        // would have incremented the loopback bucket.
        assert!(
            limiter.check(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "loopback bucket must be untouched by the IP-less request"
        );
    }

    /// Two rejected IP-less requests do not share — or even create — a bucket,
    /// so they can never exhaust a quota on each other's behalf. Each is
    /// independently refused, and the loopback bucket remains pristine.
    #[tokio::test]
    async fn missing_connect_info_does_not_create_shared_bucket() {
        let limiter = Arc::new(RateLimiter::new(1));

        for _ in 0..3 {
            let app = middleware_router(limiter.clone());
            let req = HttpRequest::builder()
                .uri("/")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }

        // No placeholder bucket was created at all.
        let buckets = limiter.buckets.lock().unwrap();
        assert!(
            buckets.is_empty(),
            "IP-less requests must not allocate any rate-limit bucket"
        );
    }
}
