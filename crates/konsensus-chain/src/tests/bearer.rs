use super::*;
use std::os::unix::fs::PermissionsExt;

fn credentials(mode: u32, contents: &str) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), contents).unwrap();
    std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(mode)).unwrap();
    file
}
const CONFIG: &str = "token_url = 'https://login.invalid/token'\nclient_id = 'private-id'\nclient_secret = 'private-secret'\n";

#[test]
fn bearer_permissions_and_redaction() {
    for mode in [0o644, 0o640, 0o400, 0o660, 0o700] {
        let file = credentials(mode, CONFIG);
        let error = BearerAuth::from_file(file.path()).unwrap_err();
        assert!(error.to_string().contains("0600"));
        assert!(!format!("{error:?}").contains("private-secret"));
    }
    let file = credentials(0o600, CONFIG);
    let auth = BearerAuth::from_file(file.path()).unwrap();
    let debug = format!("{auth:?}");
    for private in ["private-secret", "private-id", "login.invalid"] {
        assert!(!debug.contains(private));
    }
    let file = credentials(0o600, "client_secret = 'private-secret'\nbad toml");
    let error = BearerAuth::from_file(file.path()).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("private-secret"));
}

#[test]
fn bearer_rejects_unsafe_token_urls() {
    for url in [
        "http://login.invalid/token",
        "https://user:private-secret@login.invalid/token",
        "https://login.invalid/token?secret=private-secret",
        "https://login.invalid/#private-secret",
    ] {
        let file = credentials(0o600, &CONFIG.replace("https://login.invalid/token", url));
        let error = BearerAuth::from_file(file.path()).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("private-secret"));
    }
}

#[derive(Debug)]
struct Wire {
    replies: std::sync::Mutex<std::collections::VecDeque<(u16, &'static str)>>,
    token_calls: std::sync::atomic::AtomicUsize,
    api_calls: std::sync::atomic::AtomicUsize,
}
impl HttpTransport for Wire {
    fn execute(
        &self,
        request: RequestBuilder,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Response, esplora_client::Error>> + Send + '_>,
    > {
        Box::pin(async move {
            use std::sync::atomic::Ordering::SeqCst;
            let request = request.build().unwrap();
            for secret in ["private-id", "private-secret", "private-token"] {
                assert!(!request.url().as_str().contains(secret));
            }
            if request.url().host_str() == Some("login.invalid") {
                self.token_calls.fetch_add(1, SeqCst);
                assert_eq!(request.method(), reqwest::Method::POST);
                assert!(!request.headers().contains_key(AUTHORIZATION));
                let body =
                    std::str::from_utf8(request.body().unwrap().as_bytes().unwrap()).unwrap();
                for field in [
                    "client_id=private-id",
                    "client_secret=private-secret",
                    "grant_type=client_credentials",
                    "scope=openid",
                ] {
                    assert!(body.contains(field));
                }
            } else {
                self.api_calls.fetch_add(1, SeqCst);
                if request
                    .url()
                    .host_str()
                    .is_some_and(|host| host.starts_with("fallback"))
                {
                    assert!(!request.headers().contains_key(AUTHORIZATION));
                } else {
                    let header = &request.headers()[AUTHORIZATION];
                    assert!(header.is_sensitive());
                    assert_eq!(header, "Bearer private-token");
                    assert!(!format!("{request:?}").contains("private-token"));
                }
            }
            let (status, body) = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra request");
            Ok(http::Response::builder()
                .status(status)
                .body(body)
                .unwrap()
                .into())
        })
    }
}
const TOKEN: &str = r#"{"access_token":"private-token","expires_in":300}"#;
pub(crate) fn auth_with_wire(wire: Arc<dyn HttpTransport>) -> Arc<BearerAuth> {
    let file = credentials(0o600, CONFIG);
    let mut auth = BearerAuth::from_file(file.path()).unwrap();
    Arc::get_mut(&mut auth).unwrap().wire = Some(wire);
    auth
}
fn fixture(replies: Vec<(u16, &'static str)>) -> (Arc<BearerAuth>, Arc<Wire>) {
    let wire = Arc::new(Wire {
        replies: std::sync::Mutex::new(replies.into()),
        token_calls: 0.into(),
        api_calls: 0.into(),
    });
    (auth_with_wire(wire.clone()), wire)
}
async fn get(transport: &BearerTransport) -> Response {
    transport
        .execute(Client::new().get("https://api.invalid/api/blocks/tip/height"))
        .await
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn bearer_refreshes_before_expiry_and_client_clones_use_live_headers() {
    let (auth, wire) = fixture(vec![
        (200, TOKEN),
        (200, "900000"),
        (200, "900001"),
        (200, TOKEN),
        (200, "900002"),
    ]);
    let transport = auth.transport("https://api.invalid/api").unwrap();
    let client: esplora_client::AsyncClient =
        esplora_client::AsyncClient::from_client("https://api.invalid/api".into(), Client::new())
            .with_transport(transport);
    assert_eq!(client.get_height().await.unwrap(), 900000);
    tokio::time::advance(Duration::from_secs(269)).await;
    assert_eq!(client.clone().get_height().await.unwrap(), 900001);
    assert_eq!(
        wire.token_calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(client.clone().get_height().await.unwrap(), 900002);
    assert_eq!(
        wire.token_calls.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
}

#[tokio::test]
async fn bearer_401_refreshes_once_and_redacts_error_response() {
    let (auth, wire) = fixture(vec![
        (200, TOKEN),
        (401, "private-token"),
        (200, TOKEN),
        (401, "private-secret private-token"),
    ]);
    let transport = auth.transport("https://api.invalid/api").unwrap();
    let client: esplora_client::AsyncClient =
        esplora_client::AsyncClient::from_client("https://api.invalid/api".into(), Client::new())
            .with_transport(transport);
    let error = client.get_height().await.unwrap_err();
    assert!(!format!("{error:?} {error}").contains("private-"));
    assert_eq!(
        wire.token_calls.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert_eq!(wire.api_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn bearer_401_recovers_and_concurrent_rejections_reuse_new_generation() {
    let (auth, wire) = fixture(vec![(200, TOKEN), (401, ""), (200, TOKEN), (200, "900000")]);
    let transport = auth.transport("https://api.invalid/api").unwrap();
    assert_eq!(get(&transport).await.text().await.unwrap(), "900000");
    // An in-flight request using generation 1 need not fetch generation 3.
    auth.header(Some(1)).await.unwrap();
    assert_eq!(
        wire.token_calls.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
}

#[tokio::test]
async fn bearer_token_errors_are_redacted_and_never_send_api_request() {
    for reply in [
        (401, "private-secret"),
        (200, "private-token"),
        (
            200,
            r#"{"access_token":"private-token\n","expires_in":300}"#,
        ),
        (200, r#"{"access_token":"private-token","expires_in":0}"#),
    ] {
        let (auth, wire) = fixture(vec![reply]);
        let transport = auth.transport("https://api.invalid/api").unwrap();
        let error = transport
            .execute(Client::new().get("https://api.invalid/api/blocks/tip/height"))
            .await
            .unwrap_err();
        assert!(!format!("{error:?} {error} {auth:?} {transport:?}").contains("private-"));
        assert_eq!(wire.api_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn bearer_never_sends_credentials_to_other_endpoints() {
    let (auth, wire) = fixture(vec![]);
    let transport = auth.transport("https://api.invalid/api").unwrap();
    for url in [
        "https://fallback.invalid/api/blocks/tip/height",
        "https://api.invalid/api-evil/blocks/tip/height",
    ] {
        assert!(transport.execute(Client::new().get(url)).await.is_err());
    }
    assert_eq!(
        wire.token_calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn bearer_refuses_symlinks_and_directories() {
    let file = credentials(0o600, CONFIG);
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("credentials");
    std::os::unix::fs::symlink(file.path(), &link).unwrap();
    assert!(BearerAuth::from_file(&link).is_err());
    assert!(BearerAuth::from_file(dir.path()).is_err());
}

/// Run explicitly outside the sandbox: cargo test -p konsensus-chain bearer_mock_server -- --ignored
#[tokio::test]
#[ignore = "requires loopback sockets"]
async fn bearer_mock_server_receives_form_and_authorization_header() {
    use axum::{
        extract::{Form, State},
        http::HeaderMap,
        routing::{get, post},
        Router,
    };
    use std::{
        collections::HashMap,
        sync::atomic::{AtomicUsize, Ordering::SeqCst},
    };
    async fn token(Form(form): Form<HashMap<String, String>>) -> &'static str {
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some("private-id")
        );
        assert_eq!(
            form.get("client_secret").map(String::as_str),
            Some("private-secret")
        );
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("client_credentials")
        );
        assert_eq!(form.get("scope").map(String::as_str), Some("openid"));
        TOKEN
    }
    async fn height(
        State(calls): State<Arc<AtomicUsize>>,
        headers: HeaderMap,
    ) -> (axum::http::StatusCode, &'static str) {
        assert_eq!(
            headers.get("authorization").unwrap(),
            "Bearer private-token"
        );
        if calls.fetch_add(1, SeqCst) == 0 {
            (axum::http::StatusCode::UNAUTHORIZED, "private-token")
        } else {
            (axum::http::StatusCode::OK, "900000")
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/token", post(token))
        .route("/api/blocks/tip/height", get(height))
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let file = credentials(0o600, CONFIG);
    let mut auth = BearerAuth::from_file(file.path()).unwrap();
    // Test-only loopback transport; production loader requires HTTPS.
    Arc::get_mut(&mut auth).unwrap().credentials.token_url = format!("{base}/token");
    let transport = Arc::new(BearerTransport {
        auth,
        endpoint: format!("{base}/api"),
    });
    let client: esplora_client::AsyncClient =
        esplora_client::AsyncClient::from_client(format!("{base}/api"), Client::new())
            .with_transport(transport);
    assert_eq!(client.get_height().await.unwrap(), 900000);
    assert_eq!(calls.load(SeqCst), 2);
    server.abort();
}

#[tokio::test]
async fn bearer_success_body_decode_errors_do_not_echo_token() {
    let (auth, _) = fixture(vec![(200, TOKEN), (200, r#"{"1":"private-token"}"#)]);
    let client: esplora_client::AsyncClient =
        esplora_client::AsyncClient::from_client("https://api.invalid/api".into(), Client::new())
            .with_transport(auth.transport("https://api.invalid/api").unwrap());
    let error = client.get_fee_estimates().await.unwrap_err();
    assert!(!format!("{error:?} {error}").contains("private-token"));
}

#[tokio::test]
async fn bearer_canonicalizes_endpoint_url() {
    let (auth, _) = fixture(vec![(200, TOKEN), (200, "900000")]);
    let transport = auth.transport("https://API.INVALID:443/api").unwrap();
    assert_eq!(get(&transport).await.status(), 200);
}

#[tokio::test(start_paused = true)]
async fn bearer_ldk_live_refresh_failure_falls_back_without_auth() {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    #[derive(Debug)]
    struct FailoverWire {
        tokens: AtomicUsize,
        primary: AtomicUsize,
        fallback: AtomicUsize,
    }
    impl HttpTransport for FailoverWire {
        fn execute(
            &self,
            request: RequestBuilder,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Response, esplora_client::Error>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                let request = request.build().unwrap();
                let (status, body) = match request.url().host_str().unwrap() {
                    "login.invalid" => {
                        if self.tokens.fetch_add(1, SeqCst) == 0 {
                            (200, TOKEN)
                        } else {
                            (503, "private-secret private-token")
                        }
                    }
                    "live.invalid" => {
                        self.primary.fetch_add(1, SeqCst);
                        assert_eq!(request.headers()[AUTHORIZATION], "Bearer private-token");
                        (200, "900000")
                    }
                    "fallback.invalid" => {
                        self.fallback.fetch_add(1, SeqCst);
                        assert!(!request.headers().contains_key(AUTHORIZATION));
                        assert_eq!(request.url().path(), "/api/blocks/tip/height");
                        (200, "900001")
                    }
                    _ => panic!("unexpected endpoint"),
                };
                Ok(http::Response::builder()
                    .status(status)
                    .body(body)
                    .unwrap()
                    .into())
            })
        }
    }
    let wire = Arc::new(FailoverWire {
        tokens: 0.into(),
        primary: 0.into(),
        fallback: 0.into(),
    });
    let auth = auth_with_wire(wire.clone());
    let failover = BearerFailover::new(
        auth,
        "https://live.invalid/api",
        vec!["https://fallback.invalid/api".into()],
    )
    .unwrap();
    let client: esplora_client::AsyncClient =
        esplora_client::AsyncClient::from_client("https://live.invalid/api".into(), Client::new())
            .with_transport(failover.clone());
    assert_eq!(client.get_height().await.unwrap(), 900000);
    tokio::time::advance(Duration::from_secs(270)).await;
    assert_eq!(client.clone().get_height().await.unwrap(), 900001);
    let started = Instant::now();
    for _ in 0..8 {
        assert_eq!(client.clone().get_height().await.unwrap(), 900001);
    }
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(wire.tokens.load(SeqCst), 2);
    assert_eq!(wire.primary.load(SeqCst), 1);
    assert_eq!(wire.fallback.load(SeqCst), 9);
    assert_eq!(failover.active_host().as_deref(), Some("fallback.invalid"));
}

#[tokio::test(start_paused = true)]
async fn bearer_broadcast_preserves_429_and_bounded_retry_delay() {
    let (auth, _) = fixture(vec![(200, TOKEN), (429, "private-token")]);
    let transport = BearerFailover::new(auth, "https://only429.invalid/api", vec![]).unwrap();
    let error = transport
        .execute(
            Client::new()
                .post("https://only429.invalid/api/tx")
                .body("transaction"),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        esplora_client::Error::HttpResponse { status: 429, .. }
    ));
    assert!(transport.rate_limit_failure().is_some());
    assert_eq!(transport.retry_delay(), Duration::from_secs(10));
}

#[tokio::test(start_paused = true)]
async fn bearer_primary_429_healthy_fallback_clears_health_and_broadcast_delay() {
    let (auth, wire) = fixture(vec![
        (200, TOKEN),
        (429, "private-token"),
        (200, "900000"),
        (200, "ok"),
    ]);
    let transport = BearerFailover::new(
        auth,
        "https://primary429.invalid/api",
        vec!["https://fallback.invalid/api".into()],
    )
    .unwrap();
    assert_eq!(
        transport
            .execute(Client::new().get("https://primary429.invalid/api/blocks/tip/height"))
            .await
            .unwrap()
            .status(),
        200
    );
    assert!(transport.rate_limit_failure().is_none());
    assert_eq!(transport.retry_delay(), Duration::ZERO);
    assert_eq!(transport.active_host().as_deref(), Some("fallback.invalid"));
    // A broadcast must not wait for the primary cooldown before trying fallback.
    // Current primary cooldown remains, so skip it for this broadcast as well.
    assert_eq!(
        transport
            .execute(
                Client::new()
                    .post("https://primary429.invalid/api/tx")
                    .body("transaction")
            )
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(wire.api_calls.load(std::sync::atomic::Ordering::SeqCst), 3);
}

#[tokio::test(start_paused = true)]
async fn bearer_token_failure_and_fallback_429_preserve_broadcast_retry() {
    let (auth, _) = fixture(vec![(503, "private-secret"), (429, "private-token")]);
    let transport = BearerFailover::new(
        auth,
        "https://oauth-down.invalid/api",
        vec!["https://fallback429.invalid/api".into()],
    )
    .unwrap();
    let error = transport
        .execute(
            Client::new()
                .post("https://oauth-down.invalid/api/tx")
                .body("transaction"),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        esplora_client::Error::HttpResponse { status: 429, .. }
    ));
    assert!(transport.rate_limit_failure().is_some());
    assert_eq!(transport.retry_delay(), Duration::from_secs(10));
}

#[tokio::test]
async fn bearer_fallback_logs_host_only_without_secrets() {
    #[derive(Clone)]
    struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let output = Capture(Arc::default());
    let sink = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || sink.clone())
        .finish();
    // This test binary has one capture subscriber. A global dispatcher keeps
    // callsite interest stable while other Tokio tests exercise the same site.
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let (auth, _) = fixture(vec![(503, "private-secret"), (200, "900000")]);
    let transport = BearerFailover::new(
        auth,
        "https://logs.invalid/api",
        vec!["https://fallback-logs.invalid/private-path".into()],
    )
    .unwrap();
    transport
        .execute(Client::new().get("https://logs.invalid/api/blocks/tip/height"))
        .await
        .unwrap();
    let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("fallback-logs.invalid"));
    assert!(logs.contains("third_party"));
    for private in [
        "private-secret",
        "private-token",
        "private-id",
        "private-path",
        "login.invalid",
    ] {
        assert!(!logs.contains(private));
    }
}

#[tokio::test]
async fn bearer_chain_provider_sends_header_and_reports_third_party_host() {
    use konsensus_core::traits::chain::{ChainProvider, TrustLevel};
    let (auth, wire) = fixture(vec![(200, TOKEN), (200, "900000")]);
    let provider = crate::EsploraProvider::new(crate::EsploraConfig::custom(
        "https://api.invalid/api".into(),
        TrustLevel::ServerTrust,
    ))
    .unwrap()
    .with_bearer(auth)
    .unwrap();
    assert_eq!(provider.get_block_height().await.unwrap(), 900000);
    assert_eq!(wire.api_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(provider.chain_view().host.as_deref(), Some("api.invalid"));
    assert_eq!(provider.chain_view().trust_level, "third_party");
}

#[tokio::test]
async fn bearer_provider_preserves_configured_request_budgets() {
    use konsensus_core::traits::chain::{ChainProvider, TrustLevel};
    #[derive(Debug)]
    struct Budgets(u64);
    impl HttpTransport for Budgets {
        fn execute(
            &self,
            request: RequestBuilder,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Response, esplora_client::Error>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                let request = request.build().unwrap();
                let (seconds, body) = match request.url().path() {
                    "/token" => (4, TOKEN),
                    "/api/blocks/tip/height" => (4, "900000"),
                    "/api/fee-estimates" => (self.0, r#"{"6":2.0}"#),
                    _ => panic!("unexpected request"),
                };
                assert_eq!(request.timeout(), Some(&Duration::from_secs(seconds)));
                Ok(http::Response::builder().body(body).unwrap().into())
            })
        }
    }
    for seconds in [30, 17] {
        let mut config = crate::EsploraConfig::custom(
            "https://budgets.invalid/api".into(),
            TrustLevel::ServerTrust,
        );
        config.timeout_secs = seconds;
        let provider = crate::EsploraProvider::new(config)
            .unwrap()
            .with_bearer(auth_with_wire(Arc::new(Budgets(seconds))))
            .unwrap();
        assert_eq!(provider.get_block_height().await.unwrap(), 900000);
        provider.estimate_fee(6).await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn bearer_failed_token_posts_are_coalesced_during_backoff() {
    use std::sync::atomic::Ordering::SeqCst;
    for reply in [(503, "private-secret"), (200, "private-token")] {
        let (auth, wire) = fixture(vec![reply; 9]);
        let started = Instant::now();
        assert!(auth.header(None).await.is_err());
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let auth = auth.clone();
            tasks.spawn(async move {
                assert!(auth.header(None).await.is_err());
            });
        }
        while let Some(task) = tasks.join_next().await {
            task.unwrap();
        }
        assert_eq!(wire.token_calls.load(SeqCst), 1);
        assert_eq!(started.elapsed(), Duration::ZERO, "cooldown must not sleep");
        // The retry window is short and bounded, even after repeated failures.
        for expected in 2..=5 {
            tokio::time::advance(Duration::from_secs(3)).await;
            assert!(auth.header(None).await.is_err());
            assert_eq!(wire.token_calls.load(SeqCst), expected);
        }
    }
}

#[tokio::test]
async fn bearer_failover_preserves_upstream_status_without_error_body() {
    for status in [400, 401, 403, 500, 502] {
        for fallback in [false, true] {
            let mut replies = vec![(200, TOKEN), (status, "private-token")];
            if status == 401 {
                replies.extend([(200, TOKEN), (401, "private-secret")]);
            }
            if fallback {
                replies.push((504, "private-token private-secret"));
            }
            let (auth, _) = fixture(replies);
            let transport = BearerFailover::new(
                auth,
                "https://status.invalid/api",
                if fallback {
                    vec!["https://fallback-status.invalid/api".into()]
                } else {
                    vec![]
                },
            )
            .unwrap();
            let error = transport
                .execute(
                    Client::new()
                        .post("https://status.invalid/api/tx")
                        .body("transaction"),
                )
                .await
                .unwrap_err();
            assert!(
                matches!(error, esplora_client::Error::HttpResponse { status: actual, .. } if actual == status)
            );
            assert!(!format!("{error:?} {error}").contains("private-"));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn bearer_backoff_expires_and_success_restores_cached_token() {
    use std::sync::atomic::Ordering::SeqCst;
    let (auth, wire) = fixture(vec![(503, "private-secret"), (200, TOKEN), (200, "900000")]);
    assert!(auth.header(None).await.is_err());
    let delay = auth.token.lock().await.retry_at.unwrap() - Instant::now();
    assert!((Duration::from_secs(1)..=Duration::from_secs(3)).contains(&delay));
    tokio::time::advance(delay - Duration::from_nanos(1)).await;
    assert!(auth.header(None).await.is_err());
    assert_eq!(wire.token_calls.load(SeqCst), 1);
    tokio::time::advance(Duration::from_nanos(1)).await;
    auth.header(None).await.unwrap();
    assert!(auth.token.lock().await.retry_at.is_none());
    let transport = auth.transport("https://api.invalid/api").unwrap();
    assert_eq!(get(&transport).await.status(), 200);
    assert_eq!(wire.token_calls.load(SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn bearer_failed_or_cancelled_token_post_backs_off_then_retries() {
    #[derive(Debug)]
    struct BrokenWire(std::sync::atomic::AtomicUsize);
    impl HttpTransport for BrokenWire {
        fn execute(
            &self,
            request: RequestBuilder,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Response, esplora_client::Error>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                let request = request.build().unwrap();
                if request.url().host_str() == Some("fallback-cancel.invalid") {
                    assert!(!request.headers().contains_key(AUTHORIZATION));
                    return Ok(http::Response::builder().body("900000").unwrap().into());
                }
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(4)).await;
                Err(unavailable())
            })
        }
    }
    for cancel in [false, true] {
        let wire = Arc::new(BrokenWire(0.into()));
        let auth = auth_with_wire(wire.clone());
        if cancel {
            assert!(
                tokio::time::timeout(Duration::from_secs(1), auth.header(None))
                    .await
                    .is_err()
            );
        } else {
            assert!(auth.header(None).await.is_err());
        }
        let failed = Instant::now();
        assert!(auth.header(None).await.is_err());
        let transport = BearerFailover::new(
            auth.clone(),
            "https://cancel.invalid/api",
            vec!["https://fallback-cancel.invalid/api".into()],
        )
        .unwrap();
        assert_eq!(
            transport
                .execute(Client::new().get("https://cancel.invalid/api/blocks/tip/height"))
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(failed.elapsed(), Duration::ZERO);
        assert_eq!(wire.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(if cancel { 7 } else { 3 })).await;
        assert!(auth.header(None).await.is_err());
        assert_eq!(wire.0.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn bearer_request_timeout_survives_401_retry_and_fallback() {
    #[derive(Debug)]
    struct Budgets(Arc<Wire>);
    impl HttpTransport for Budgets {
        fn execute(
            &self,
            request: RequestBuilder,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Response, esplora_client::Error>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                let (client, request) = request.build_split();
                let request = request.unwrap();
                let seconds = if request.url().host_str() == Some("login.invalid") {
                    4
                } else {
                    10
                };
                assert_eq!(request.timeout(), Some(&Duration::from_secs(seconds)));
                self.0
                    .execute(RequestBuilder::from_parts(client, request))
                    .await
            })
        }
    }
    let (_, wire) = fixture(vec![
        (200, TOKEN),
        (401, "private-token"),
        (200, TOKEN),
        (403, "private-secret"),
        (200, "900000"),
    ]);
    let auth = auth_with_wire(Arc::new(Budgets(wire.clone())));
    let transport = BearerFailover::new(
        auth,
        "https://budgets-retry.invalid/api",
        vec!["https://fallback-budgets.invalid/api".into()],
    )
    .unwrap();
    let client: esplora_client::AsyncClient =
        esplora_client::Builder::new("https://budgets-retry.invalid/api")
            .timeout(10)
            .build_async()
            .unwrap()
            .with_transport(transport.clone());
    assert_eq!(client.clone().get_height().await.unwrap(), 900000);
    assert_eq!(
        transport.active_host().as_deref(),
        Some("fallback-budgets.invalid")
    );
    assert_eq!(
        wire.token_calls.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert_eq!(wire.api_calls.load(std::sync::atomic::Ordering::SeqCst), 3);
}
