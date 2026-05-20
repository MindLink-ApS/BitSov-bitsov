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
pub async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    req: Request,
    next: Next,
) -> Response {
    // Extract client IP — fall back to loopback if unavailable
    let ip = connect_info
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

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
}
