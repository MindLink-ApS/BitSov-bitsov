//! Single-use sign-in challenges for `GET /api/v1/auth/challenge`.
//!
//! The pool is process-local. Each source has its own cap and rate limit so
//! one caller cannot occupy every slot. A source at its cap replaces its own
//! oldest challenge. A different source is refused when the shared pool is full.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::error::ApiError;
use crate::rate_limit::RateLimiter;

/// Shared outstanding sign-in challenges.
pub const AUTH_CHALLENGE_MAX_LIVE: usize = 128;

/// Outstanding sign-in challenges one source may hold.
///
/// At this cap a new challenge from that source replaces its own oldest
/// challenge. Another source's challenge is left in place.
pub const AUTH_CHALLENGE_MAX_PER_SOURCE: usize = 8;

/// Challenge issuances accepted from one source per minute.
pub const AUTH_CHALLENGE_RATE_PER_MINUTE: u32 = 30;

const AUTH_CHALLENGE_RATE_WINDOW: Duration = Duration::from_secs(60);

struct LiveAuthChallenge {
    expires_at: Instant,
    source: String,
    /// Issuance order. Expiry timestamps can tie in a tight burst.
    seq: u64,
}

struct ChallengePool {
    live: HashMap<String, LiveAuthChallenge>,
    next_seq: u64,
}

/// Challenge store plus the per-source issuance limiter.
pub struct AuthChallenges {
    inner: Mutex<ChallengePool>,
    rate: RateLimiter,
}

impl AuthChallenges {
    /// Empty pool with its own rate-limit buckets.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(ChallengePool {
                live: HashMap::new(),
                next_seq: 0,
            }),
            rate: RateLimiter::with_window(
                AUTH_CHALLENGE_RATE_PER_MINUTE,
                AUTH_CHALLENGE_RATE_WINDOW,
            ),
        })
    }

    /// Insert `challenge` for `source`, evicting that source's oldest entry at its cap.
    ///
    /// One issuance is taken from `source`'s rate limit before a slot is reserved.
    /// A full shared pool still consumes that issuance and refuses the insert
    /// without evicting another source. A source already at its own cap replaces
    /// its oldest challenge, including when the shared pool is full. Callers that
    /// reject a request for any other reason must do so before `insert`.
    pub async fn insert(
        &self,
        source: &str,
        challenge: String,
        expires_at: Instant,
    ) -> Result<(), ApiError> {
        self.rate.cleanup();
        if !self.rate.check_key(source) {
            return Err(ApiError::TooManyRequests(
                "auth challenge rate limit exceeded".into(),
            ));
        }
        let mut pool = self.inner.lock().await;
        let now = Instant::now();
        pool.live.retain(|_, entry| entry.expires_at > now);
        let own_count = pool
            .live
            .values()
            .filter(|entry| entry.source == source)
            .count();
        if own_count >= AUTH_CHALLENGE_MAX_PER_SOURCE {
            let oldest = pool
                .live
                .iter()
                .filter(|(_, entry)| entry.source == source)
                .min_by_key(|(_, entry)| entry.seq)
                .map(|(id, _)| id.clone());
            if let Some(oldest) = oldest {
                pool.live.remove(&oldest);
            }
        } else if pool.live.len() >= AUTH_CHALLENGE_MAX_LIVE {
            return Err(ApiError::TooManyRequests(
                "too many outstanding auth challenges".into(),
            ));
        }
        let seq = pool.next_seq;
        pool.next_seq = pool.next_seq.saturating_add(1);
        pool.live.insert(
            challenge,
            LiveAuthChallenge {
                expires_at,
                source: source.to_owned(),
                seq,
            },
        );
        Ok(())
    }

    /// Consume a challenge once. Unknown, replayed, and expired values are refused.
    pub async fn consume(&self, challenge: &str) -> Result<(), ApiError> {
        let now = Instant::now();
        let mut pool = self.inner.lock().await;
        let entry = pool.live.remove(challenge).ok_or_else(|| {
            ApiError::Unauthorized("auth challenge is unknown or already used".into())
        })?;
        if entry.expires_at <= now {
            return Err(ApiError::Unauthorized("auth challenge expired".into()));
        }
        Ok(())
    }
}

/// Rate-limit and quota identity for a TCP peer.
///
/// The port is not part of the key: a new connection from the same address is
/// the same source. IPv4-mapped IPv6 addresses collapse to IPv4.
pub fn peer_source(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| IpAddr::V4(v4).to_string())
            .unwrap_or_else(|| ip.to_string()),
        IpAddr::V4(_) => ip.to_string(),
    }
}

/// Tunnel clients are keyed by the authenticated pairing, not the loopback bridge.
pub fn pairing_source(client_id: &str) -> String {
    format!("pairing:{client_id}")
}
