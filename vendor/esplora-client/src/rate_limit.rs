//! Shared Esplora HTTP admission. No remote response text enters diagnostics.
use crate::r#async::HttpTransport;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

/// Process-local rate-limit health shared by all consumers of an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainSyncFailure {
    /// Unix onset of this rate-limit episode.
    pub since: u64,
    /// True while the endpoint has an outstanding rate-limit failure.
    pub rate_limited: bool,
}

/// Endpoint admission and bounded HTTP 429 recovery.
#[derive(Debug)]
pub struct RateLimitedTransport {
    host: String,
    state: Mutex<State>,
}
#[derive(Debug, Default)]
struct State {
    until: Option<(Instant, Duration)>,
    since: Option<u64>,
    failures: u32,
    probing: bool,
}
impl RateLimitedTransport {
    /// Share the #200 cooldown across wallet sync, funding, fees and pricing.
    /// Scope by API endpoint, retaining paths/credentials so distinct services
    /// on the same host are not conflated. Dead entries are reclaimed.
    pub fn shared(url: &str) -> Arc<Self> {
        static REGISTRY: OnceLock<Mutex<HashMap<String, Weak<RateLimitedTransport>>>> =
            OnceLock::new();
        let key = url.trim_end_matches('/').to_owned();
        let mut registry = REGISTRY.get_or_init(Default::default).lock().unwrap();
        if let Some(existing) = registry.get(&key).and_then(Weak::upgrade) {
            return existing;
        }
        registry.retain(|_, transport| transport.strong_count() > 0);
        let transport = Self::new(url);
        registry.insert(key, Arc::downgrade(&transport));
        transport
    }

    /// Create isolated state (prefer `shared` for production consumers).
    pub fn new(url: &str) -> Arc<Self> {
        Arc::new(Self {
            host: reqwest::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".into()),
            state: Mutex::new(State::default()),
        })
    }
    /// Current endpoint rate-limit failure, until a recovery probe succeeds.
    pub fn failure(&self) -> Option<ChainSyncFailure> {
        self.state
            .lock()
            .unwrap()
            .since
            .map(|since| ChainSyncFailure {
                since,
                rate_limited: true,
            })
    }
    /// Remaining cooldown before a GET probe or bounded broadcast retry.
    pub fn retry_delay(&self) -> Duration {
        let state = self.state.lock().unwrap();
        state.until.map_or(Duration::ZERO, |(start, delay)| {
            delay.saturating_sub(start.elapsed())
        })
    }
    /// Admit an operation and record any HTTP 429 before returning it.
    pub async fn run<F, Fut>(
        &self,
        broadcast: bool,
        send: F,
    ) -> Result<reqwest::Response, crate::Error>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, crate::Error>>,
    {
        let probe = {
            let mut state = self.state.lock().unwrap();
            let cooling_down = state
                .until
                .is_some_and(|(start, delay)| start.elapsed() < delay);
            // Each broadcast waits one bounded cooldown in its own package task.
            // Its POST must reach the backend even if another request extends the
            // cooldown or owns the GET recovery probe in the meantime.
            if !broadcast && (state.probing || cooling_down) {
                return Err(rate_limited());
            }
            let probe = state.until.is_some() && !state.probing && !cooling_down;
            if probe {
                state.probing = true;
            }
            probe
        };
        let mut guard = ProbeGuard {
            transport: self,
            active: probe,
        };
        let response = send().await?;
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let now = SystemTime::now();
            let mut state = self.state.lock().unwrap();
            // Concurrent requests already in flight belong to the same episode.
            // They may extend Retry-After but must not multiply exponential steps.
            let new_episode = state
                .until
                .is_none_or(|(start, delay)| start.elapsed() >= delay);
            if new_episode {
                state.failures = state.failures.saturating_add(1);
            }
            let fallback = Duration::from_secs(
                10u64
                    .saturating_mul(1u64 << state.failures.saturating_sub(1).min(5))
                    .min(300),
            );
            let delay = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|h| h.to_str().ok())
                .and_then(|h| retry_after(h, now))
                .unwrap_or(fallback)
                .max(fallback)
                .min(Duration::from_secs(300));
            let remaining = state.until.map_or(Duration::ZERO, |(start, duration)| {
                duration.saturating_sub(start.elapsed())
            });
            state.until = Some((Instant::now(), delay.max(remaining)));
            state
                .since
                .get_or_insert(now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs());
            state.probing = false;
            guard.active = false;
            if new_episode {
                log::error!(target: "ldk_node::chain_sync",
                    "chain_rate_limited kind=rate_limited backend_host={} retry_in_secs={}", self.host, delay.as_secs());
            }
            return Err(rate_limited());
        }
        if probe {
            let mut state = self.state.lock().unwrap();
            // A concurrent old response may have extended the cooldown while
            // this probe was running. Never clear a newer 429.
            if state.probing {
                *state = State::default();
            }
            guard.active = false;
        }
        Ok(response)
    }
}
fn rate_limited() -> crate::Error {
    crate::Error::HttpResponse {
        status: 429,
        message: "backend rate limited".into(),
    }
}
fn retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
        .or_else(|| {
            httpdate::parse_http_date(value)
                .ok()
                .map(|date| date.duration_since(now).unwrap_or_default())
        })
}
struct ProbeGuard<'a> {
    transport: &'a RateLimitedTransport,
    active: bool,
}
impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            let mut state = self.transport.state.lock().unwrap();
            if state.probing {
                state.probing = false;
                state.until = Some((Instant::now(), Duration::from_secs(10)));
            }
        }
    }
}

impl HttpTransport for RateLimitedTransport {
    fn execute(
        &self,
        request: reqwest::RequestBuilder,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<reqwest::Response, crate::Error>> + Send + '_>,
    > {
        Box::pin(async move {
            let (client, request) = request.build_split();
            let request = request?;
            let broadcast = request.method() == reqwest::Method::POST;
            self.run(broadcast, || async { Ok(client.execute(request).await?) })
                .await
        })
    }
}

#[cfg(test)]
mod bitsov_rate_limit_tests {
    use super::*;
    fn response(status: u16, retry: Option<&str>) -> Result<reqwest::Response, crate::Error> {
        let mut builder = http::Response::builder().status(status);
        if let Some(retry) = retry {
            builder = builder.header("retry-after", retry);
        }
        Ok(builder.body(String::new()).unwrap().into())
    }
    #[tokio::test(start_paused = true)]
    async fn remote_retry_after_cannot_defer_admission_beyond_300_seconds() {
        for retry in [
            "86400".to_owned(),
            u64::MAX.to_string(),
            httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(86400)),
        ] {
            let transport = RateLimitedTransport::new("https://chain.invalid");
            assert!(transport
                .run(false, || async { response(429, Some(&retry)) })
                .await
                .is_err());
            assert!(transport.retry_delay() <= Duration::from_secs(300));
            tokio::time::advance(Duration::from_secs(300)).await;
            assert!(transport
                .run(false, || async { response(200, None) })
                .await
                .is_ok());
        }
    }
    #[tokio::test(start_paused = true)]
    async fn retry_after_blocks_other_operations_and_recovers() {
        let transport =
            RateLimitedTransport::new("https://user:secret@chain.invalid/private?token=secret");
        assert!(transport
            .run(false, || async { response(429, Some("120")) })
            .await
            .is_err());
        assert!(transport
            .run(false, || async {
                panic!("sync/fee/broadcast must share cooldown")
            })
            .await
            .is_err());
        tokio::time::advance(Duration::from_secs(119)).await;
        assert!(transport
            .run(false, || async { panic!("Retry-After must be respected") })
            .await
            .is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(transport
            .run(false, || async { response(200, None) })
            .await
            .is_ok());
        assert_eq!(transport.host, "chain.invalid");
    }
    #[tokio::test(start_paused = true)]
    async fn missing_retry_after_backs_off_and_caps() {
        let transport = RateLimitedTransport::new("https://chain.invalid");
        for delay in [10, 20, 40, 80, 160, 300, 300] {
            assert!(transport
                .run(false, || async { response(429, None) })
                .await
                .is_err());
            tokio::time::advance(Duration::from_secs(delay - 1)).await;
            assert!(transport
                .run(false, || async { panic!("retry early") })
                .await
                .is_err());
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        assert!(transport
            .run(false, || async { response(200, None) })
            .await
            .is_ok());
        assert!(transport
            .run(false, || async { response(429, Some("garbage")) })
            .await
            .is_err());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(transport
            .run(false, || async { response(200, None) })
            .await
            .is_ok());
    }
}

#[cfg(test)]
mod bitsov_recovery_tests {
    use super::*;
    #[test]
    fn retry_after_http_dates_and_overflow_are_safe() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(
            retry_after(&httpdate::fmt_http_date(now + Duration::from_secs(90)), now),
            Some(Duration::from_secs(90))
        );
        assert_eq!(
            retry_after(&httpdate::fmt_http_date(now - Duration::from_secs(90)), now),
            Some(Duration::ZERO)
        );
        assert_eq!(
            retry_after("18446744073709551615", now),
            Some(Duration::from_secs(u64::MAX))
        );
        assert_eq!(retry_after("18446744073709551616", now), None);
    }
    #[tokio::test(start_paused = true)]
    async fn one_recovery_probe_and_cancellation_releases_it() {
        let transport = RateLimitedTransport::new("https://chain.invalid");
        let response: reqwest::Response = http::Response::builder()
            .status(429)
            .body("")
            .unwrap()
            .into();
        assert!(transport
            .run(false, || async { Ok(response) })
            .await
            .is_err());
        tokio::time::advance(Duration::from_secs(10)).await;
        let probe_transport = transport.clone();
        let probe =
            tokio::spawn(async move { probe_transport.run(false, std::future::pending).await });
        tokio::task::yield_now().await;
        assert!(transport
            .run(false, || async { panic!("only one recovery probe") })
            .await
            .is_err());
        probe.abort();
        let _ = probe.await;
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(transport
            .run(false, || async { Ok(http::Response::new("").into()) })
            .await
            .is_ok());
        assert!(transport.failure().is_none());
    }
}
