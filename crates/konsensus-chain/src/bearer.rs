//! File-backed OAuth client credentials. Secrets and responses never enter diagnostics.
use esplora_client::r#async::HttpTransport;
use reqwest::{
    header::{HeaderValue, AUTHORIZATION},
    Client, RequestBuilder, Response,
};
use serde::Deserialize;
use std::{fmt, io::Read, path::Path, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::Instant};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Credentials {
    token_url: String,
    client_id: String,
    client_secret: String,
}

/// Intentionally carries neither OS/parser errors nor credential file contents/paths.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct CredentialsError(&'static str);

struct Token {
    header: HeaderValue,
    refresh_at: Instant,
    generation: u64,
}

/// Shared in-memory token cache; refresh is serialized across concurrent requests.
pub struct BearerAuth {
    credentials: Credentials,
    client: Client,
    token: Mutex<Option<Token>>,
    #[cfg(test)]
    wire: Option<Arc<dyn HttpTransport>>,
}
impl fmt::Debug for BearerAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerAuth([REDACTED])")
    }
}
fn unavailable() -> esplora_client::Error {
    esplora_client::Error::HttpResponse {
        status: 503,
        message: "authenticated chain source unavailable".into(),
    }
}

impl BearerAuth {
    /// Require a regular file owned by the current uid with exactly mode 0600.
    /// Inspect the opened descriptor, not a separate path stat; refuse symlinks.
    pub fn from_file(path: &Path) -> Result<Arc<Self>, CredentialsError> {
        #[cfg(unix)]
        let mut file = {
            use rustix::fs::{open, Mode, OFlags};
            use std::os::unix::fs::MetadataExt;
            let fd = open(
                path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| {
                CredentialsError(
                    "cannot open chain credentials file (requires owner-only 0600 regular file)",
                )
            })?;
            let file = std::fs::File::from(fd);
            let metadata = file
                .metadata()
                .map_err(|_| CredentialsError("cannot inspect chain credentials file"))?;
            if !metadata.is_file()
                || metadata.mode() & 0o7777 != 0o600
                || metadata.uid() != rustix::process::geteuid().as_raw()
            {
                return Err(CredentialsError(
                    "chain credentials file must be owned by this user and have mode 0600",
                ));
            }
            file
        };
        #[cfg(not(unix))]
        return Err(CredentialsError(
            "owner-only 0600 credentials files require Unix",
        ));
        #[cfg(unix)]
        {
            let mut contents = Zeroizing::new(String::new());
            (&mut file)
                .take(65537)
                .read_to_string(&mut contents)
                .map_err(|_| CredentialsError("cannot read chain credentials file"))?;
            if contents.len() > 65536 {
                return Err(CredentialsError("chain credentials file too large"));
            }
            let credentials: Credentials = toml::from_str(&contents)
                .map_err(|_| CredentialsError("invalid chain credentials TOML"))?;
            validate_url(&credentials.token_url)?;
            if credentials.client_id.is_empty() || credentials.client_secret.is_empty() {
                return Err(CredentialsError("chain credentials must be nonempty"));
            }
            let client = Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(4))
                .build()
                .map_err(|_| CredentialsError("cannot build chain authentication client"))?;
            Ok(Arc::new(Self {
                credentials,
                client,
                token: Mutex::new(None),
                #[cfg(test)]
                wire: None,
            }))
        }
    }

    async fn send(&self, request: RequestBuilder) -> Result<Response, esplora_client::Error> {
        let request = request.build().map_err(|_| unavailable())?;
        // Always use OUR no-redirect client, including requests built by LDK.
        #[cfg(test)]
        if let Some(wire) = &self.wire {
            return wire
                .execute(RequestBuilder::from_parts(self.client.clone(), request))
                .await;
        }
        self.client
            .execute(request)
            .await
            .map_err(|_| unavailable())
    }

    async fn header(
        &self,
        rejected_generation: Option<u64>,
    ) -> Result<(HeaderValue, u64), esplora_client::Error> {
        let mut cached = self.token.lock().await;
        if let Some(token) = cached.as_ref() {
            if Instant::now() < token.refresh_at && rejected_generation != Some(token.generation) {
                return Ok((token.header.clone(), token.generation));
            }
        }
        let generation = cached.as_ref().map_or(1, |t| t.generation + 1);
        // A failed refresh must never cause reuse of a rejected/expiring token.
        *cached = None;
        let started = Instant::now();
        let response = self
            .send(self.client.post(&self.credentials.token_url).form(&[
                ("client_id", self.credentials.client_id.as_str()),
                ("client_secret", self.credentials.client_secret.as_str()),
                ("grant_type", "client_credentials"),
                ("scope", "openid"),
            ]))
            .await
            .map_err(|_| unavailable())?;
        if !response.status().is_success() {
            return Err(unavailable());
        }
        #[derive(Deserialize)]
        struct Reply {
            access_token: String,
            expires_in: u64,
        }
        let body = Zeroizing::new(response.bytes().await.map_err(|_| unavailable())?.to_vec());
        let reply: Reply = serde_json::from_slice(&body).map_err(|_| unavailable())?;
        let secret = Zeroizing::new(reply.access_token);
        if secret.is_empty() || reply.expires_in == 0 {
            return Err(unavailable());
        }
        let value = Zeroizing::new(format!("Bearer {}", secret.as_str()));
        let mut header = HeaderValue::from_str(&value).map_err(|_| unavailable())?;
        header.set_sensitive(true);
        let lifetime = Duration::from_secs(reply.expires_in);
        // Refresh 30 seconds early for the provider's 300s tokens; handle short TTLs too.
        let margin = Duration::from_secs(30).min(lifetime / 10);
        let refresh_at = started
            .checked_add(lifetime - margin)
            .ok_or_else(unavailable)?;
        if refresh_at <= Instant::now() {
            return Err(unavailable());
        }
        *cached = Some(Token {
            header: header.clone(),
            refresh_at,
            generation,
        });
        Ok((header, generation))
    }

    /// Attach live credentials only to this explicit source. Redirects are never followed.
    pub fn transport(
        self: &Arc<Self>,
        endpoint: &str,
    ) -> Result<Arc<BearerTransport>, CredentialsError> {
        validate_url(endpoint)?;
        Ok(Arc::new(BearerTransport {
            auth: self.clone(),
            endpoint: reqwest::Url::parse(endpoint)
                .expect("validated URL")
                .as_str()
                .trim_end_matches('/')
                .into(),
        }))
    }
}

fn validate_url(value: &str) -> Result<(), CredentialsError> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| CredentialsError("invalid authenticated chain URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CredentialsError(
            "authenticated chain URLs require HTTPS without userinfo, query or fragment",
        ));
    }
    Ok(())
}

/// Redacted transport usable by both konsensus and every cloned LDK Esplora client.
pub struct BearerTransport {
    auth: Arc<BearerAuth>,
    endpoint: String,
}
impl fmt::Debug for BearerTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerTransport([REDACTED])")
    }
}
impl HttpTransport for BearerTransport {
    fn redact_errors(&self) -> bool {
        true
    }
    fn execute(
        &self,
        request: RequestBuilder,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Response, esplora_client::Error>> + Send + '_>,
    > {
        Box::pin(async move {
            let built = request.build().map_err(|_| unavailable())?;
            let url = built.url().as_str();
            if !url.starts_with(&format!("{}/", self.endpoint)) {
                return Err(unavailable());
            }
            let request = RequestBuilder::from_parts(self.auth.client.clone(), built);
            let (header, generation) = self.auth.header(None).await?;
            let retry = request.try_clone().ok_or_else(unavailable)?;
            let mut response = self
                .auth
                .send(request.header(AUTHORIZATION, header))
                .await?;
            if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                let (header, _) = self.auth.header(Some(generation)).await?;
                response = self.auth.send(retry.header(AUTHORIZATION, header)).await?;
            }
            if !response.status().is_success() {
                // Preserve 404 semantics without exposing an error body that could echo auth.
                let mut sanitized = http::Response::builder().status(response.status());
                if let Some(retry_after) = response.headers().get(reqwest::header::RETRY_AFTER) {
                    sanitized = sanitized.header(reqwest::header::RETRY_AFTER, retry_after);
                }
                return Ok(sanitized
                    .body(String::new())
                    .map_err(|_| unavailable())?
                    .into());
            }
            Ok(response)
        })
    }
}

#[cfg(all(test, unix))]
#[path = "tests/bearer.rs"]
pub(crate) mod tests;

/// LDK's live primary + explicit fallback transport. Each endpoint keeps its own
/// shared 429 admission state; only the primary receives OAuth credentials.
pub struct BearerFailover {
    primary: Arc<BearerTransport>,
    endpoints: Vec<(
        String,
        Arc<esplora_client::rate_limit::RateLimitedTransport>,
    )>,
    active: std::sync::atomic::AtomicUsize,
    failed: std::sync::atomic::AtomicBool,
}
impl fmt::Debug for BearerFailover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerFailover([REDACTED])")
    }
}
impl BearerFailover {
    /// Build from only the operator's existing LDK fallback list.
    pub fn new(
        auth: Arc<BearerAuth>,
        primary: &str,
        fallbacks: Vec<String>,
    ) -> Result<Arc<Self>, CredentialsError> {
        let primary = auth.transport(primary)?;
        let mut endpoints = Vec::new();
        for endpoint in std::iter::once(primary.endpoint.clone()).chain(fallbacks) {
            let url = reqwest::Url::parse(&endpoint)
                .map_err(|_| CredentialsError("invalid chain fallback URL"))?;
            if !matches!(url.scheme(), "https" | "http")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(CredentialsError("invalid chain fallback URL"));
            }
            let endpoint = url.as_str().trim_end_matches('/').to_owned();
            if !endpoints.iter().any(|(url, _)| url == &endpoint) {
                let limiter = esplora_client::rate_limit::RateLimitedTransport::shared(&endpoint);
                endpoints.push((endpoint, limiter));
            }
        }
        Ok(Arc::new(Self {
            primary,
            endpoints,
            active: 0.into(),
            failed: false.into(),
        }))
    }

    /// Host only, for truthful diagnostics after a live fallback.
    pub fn active_host(&self) -> Option<String> {
        reqwest::Url::parse(
            &self.endpoints[self.active.load(std::sync::atomic::Ordering::Relaxed)].0,
        )
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
    }
}
impl HttpTransport for BearerFailover {
    fn redact_errors(&self) -> bool {
        true
    }
    fn rate_limit_failure(&self) -> Option<esplora_client::rate_limit::ChainSyncFailure> {
        if !self.failed.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        self.endpoints
            .iter()
            .filter_map(|(_, limiter)| limiter.failure())
            .min_by_key(|f| f.since)
    }
    fn retry_delay(&self) -> Duration {
        if !self.failed.load(std::sync::atomic::Ordering::Relaxed) {
            return Duration::ZERO;
        }
        // After complete failure, wait for the earliest cooling endpoint.
        // Zero-delay endpoints just failed for another reason (e.g. OAuth).
        self.endpoints
            .iter()
            .map(|(_, limiter)| limiter.retry_delay())
            .filter(|delay| !delay.is_zero())
            .min()
            .unwrap_or_default()
    }
    fn execute(
        &self,
        request: RequestBuilder,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Response, esplora_client::Error>> + Send + '_>,
    > {
        Box::pin(async move {
            let request = request.build().map_err(|_| unavailable())?;
            let suffix = request
                .url()
                .as_str()
                .strip_prefix(&format!("{}/", self.primary.endpoint))
                .ok_or_else(unavailable)?;
            let broadcast = request.method() == reqwest::Method::POST;
            let mut rate_limited = false;
            for (index, (endpoint, limiter)) in self.endpoints.iter().enumerate() {
                if broadcast
                    && !limiter.retry_delay().is_zero()
                    && self
                        .endpoints
                        .iter()
                        .enumerate()
                        .any(|(other, (_, limiter))| {
                            other != index && limiter.retry_delay().is_zero()
                        })
                {
                    rate_limited = true;
                    continue;
                }
                let mut attempt = request.try_clone().ok_or_else(unavailable)?;
                *attempt.url_mut() = reqwest::Url::parse(&format!("{endpoint}/{suffix}"))
                    .map_err(|_| unavailable())?;
                attempt.headers_mut().remove(AUTHORIZATION);
                let attempt = RequestBuilder::from_parts(self.primary.auth.client.clone(), attempt);
                let response = limiter
                    .run(broadcast, || async {
                        if index == 0 {
                            self.primary.execute(attempt).await
                        } else {
                            self.primary.auth.send(attempt).await
                        }
                    })
                    .await;
                match response {
                    Ok(response)
                        if response.status().is_success()
                            || response.status() == reqwest::StatusCode::NOT_FOUND =>
                    {
                        self.failed
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        let previous = self
                            .active
                            .swap(index, std::sync::atomic::Ordering::Relaxed);
                        if previous != index {
                            tracing::warn!(
                                backend = "esplora",
                                trust_level = "third_party",
                                host = self.active_host(),
                                "LDK chain source changed"
                            );
                        }
                        if response.status() == reqwest::StatusCode::NOT_FOUND {
                            return Ok(http::Response::builder()
                                .status(404)
                                .body(String::new())
                                .map_err(|_| unavailable())?
                                .into());
                        }
                        return Ok(response);
                    }
                    Err(esplora_client::Error::HttpResponse { status: 429, .. }) => {
                        rate_limited = true
                    }
                    _ => {}
                }
            }
            self.failed
                .store(true, std::sync::atomic::Ordering::Relaxed);
            if rate_limited {
                Err(esplora_client::Error::HttpResponse {
                    status: 429,
                    message: "chain source rate limited".into(),
                })
            } else {
                Err(unavailable())
            }
        })
    }
}
