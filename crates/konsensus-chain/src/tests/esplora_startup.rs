use super::*;
use std::sync::Mutex as StdMutex;

#[derive(Debug)]
struct Endpoint {
    network: bitcoin::Network,
    height: u64,
    up: bool,
    delay: Duration,
    down_status: Option<u16>,
    data_requests: usize,
}

#[derive(Debug)]
struct StartupHttp {
    primary: StdMutex<Endpoint>,
    fallback: StdMutex<Endpoint>,
    header_started: tokio::sync::Notify,
    hold_fallback_header: std::sync::atomic::AtomicBool,
}

impl HttpTransport for StartupHttp {
    fn execute(
        &self,
        request: reqwest::RequestBuilder,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<reqwest::Response, esplora_client::Error>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let request = request.build().unwrap();
            let endpoint = match request.url().host_str().unwrap() {
                "startup-primary.invalid" => &self.primary,
                "startup-fallback.invalid" => &self.fallback,
                host => panic!("unexpected endpoint: {host}"),
            };
            let body = {
                let mut endpoint = endpoint.lock().unwrap();
                if !endpoint.up {
                    endpoint
                        .down_status
                        .map(|status| ("unavailable".into(), Duration::ZERO, status))
                } else {
                    let genesis = bitcoin::blockdata::constants::genesis_block(endpoint.network);
                    let hash = genesis.block_hash().to_string();
                    let path = request.url().path();
                    let body = if path == "/api/block-height/0" {
                        hash.clone()
                    } else if path == format!("/api/block/{hash}/header") {
                        bitcoin::consensus::encode::serialize_hex(&genesis.header)
                    } else {
                        endpoint.data_requests += 1;
                        match path {
                            "/api/blocks/tip/height" => endpoint.height.to_string(),
                            path if path == format!("/api/block-height/{}", endpoint.height) => {
                                hash.clone()
                            }
                            path if path == format!("/api/block/{hash}") => {
                                self.header_started.notify_one();
                                serde_json::json!({
                                    "id": hash,
                                    "height": endpoint.height,
                                    "timestamp": std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                                    "bits": 545259519,
                                    "nonce": 0,
                                    "difficulty": 1.0,
                                })
                                .to_string()
                            }
                            path => panic!("unexpected data request: {path}"),
                        }
                    };
                    Some((body, endpoint.delay, 200))
                }
            };
            let Some((body, delay, status)) = body else {
                return std::future::pending().await;
            };
            if request.url().host_str() == Some("startup-fallback.invalid")
                && request.url().path().starts_with("/api/block/")
                && !request.url().path().ends_with("/header")
                && self.hold_fallback_header.load(Ordering::SeqCst)
            {
                return std::future::pending().await;
            }
            // Model actual I/O without wall-clock sleeps or external services.
            tokio::time::sleep(delay).await;
            Ok(http::Response::builder()
                .status(status)
                .body(body)
                .unwrap()
                .into())
        })
    }
}

fn fixture(fallback: bool) -> (Arc<EsploraProvider>, Arc<StartupHttp>) {
    let wire = Arc::new(StartupHttp {
        header_started: tokio::sync::Notify::new(),
        hold_fallback_header: std::sync::atomic::AtomicBool::new(false),
        primary: StdMutex::new(Endpoint {
            network: bitcoin::Network::Signet,
            height: 202,
            up: false,
            delay: Duration::from_millis(10),
            down_status: None,
            data_requests: 0,
        }),
        fallback: StdMutex::new(Endpoint {
            network: bitcoin::Network::Signet,
            height: 101,
            up: false,
            delay: Duration::from_millis(10),
            down_status: None,
            data_requests: 0,
        }),
    });
    let mut provider = EsploraProvider::with_fallbacks(
        EsploraConfig::custom(
            "https://startup-primary.invalid/api".into(),
            TrustLevel::ServerTrust,
        ),
        if fallback {
            vec!["https://startup-fallback.invalid/api".into()]
        } else {
            Vec::new()
        },
    )
    .unwrap()
    .with_network(bitcoin::Network::Signet);
    provider.transport = Some(wire.clone());
    (Arc::new(provider), wire)
}

async fn startup_check(provider: &EsploraProvider) {
    // The node cancels its startup check after ten seconds and continues offline.
    assert!(
        tokio::time::timeout(Duration::from_secs(10), provider.verify_network())
            .await
            .is_err()
    );
}

async fn ready_height(provider: Arc<EsploraProvider>) -> u64 {
    // Use the node's actual tip wrapper and admission deadline.
    let tip = crate::FreshTip::wrap(provider, Some("signet"));
    tokio::time::timeout(Duration::from_secs(5), tip.get_block_height())
        .await
        .expect("fallback tip must fit the readiness deadline")
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn primary_recovers_after_startup_failure_without_restart() {
    let (provider, wire) = fixture(false);
    startup_check(&provider).await;
    assert!(provider.get_best_block_header().await.is_err());
    wire.primary.lock().unwrap().up = true;
    assert_eq!(ready_height(provider).await, 202);
}

#[tokio::test(start_paused = true)]
async fn slow_primary_recovers_within_readiness_deadline() {
    for (fallback, millis) in [(true, 500), (false, 900)] {
        let (provider, wire) = fixture(fallback);
        startup_check(&provider).await;
        wire.fallback.lock().unwrap().up = true;
        {
            let mut primary = wire.primary.lock().unwrap();
            primary.up = true;
            primary.delay = Duration::from_millis(millis);
        }
        assert_eq!(ready_height(provider.clone()).await, 202);
        assert_eq!(ready_height(provider).await, 202);
    }
}

#[tokio::test(start_paused = true)]
async fn progressing_primary_cannot_starve_a_healthy_fallback() {
    let (provider, wire) = fixture(true);
    startup_check(&provider).await;
    {
        let mut primary = wire.primary.lock().unwrap();
        primary.up = true;
        primary.delay = Duration::from_millis(1500);
    }
    wire.fallback.lock().unwrap().up = true;
    assert_eq!(ready_height(provider.clone()).await, 101);
    assert_eq!(ready_height(provider).await, 101);
}

#[tokio::test(start_paused = true)]
async fn fast_primary_failure_immediately_tries_a_slow_fallback() {
    let (provider, wire) = fixture(true);
    startup_check(&provider).await;
    wire.primary.lock().unwrap().down_status = Some(503);
    {
        let mut fallback = wire.fallback.lock().unwrap();
        fallback.up = true;
        fallback.delay = Duration::from_millis(600);
    }
    assert_eq!(ready_height(provider.clone()).await, 101);
    assert_eq!(ready_height(provider).await, 101);
}

#[tokio::test(start_paused = true)]
async fn silent_primary_leaves_a_slow_fallback_its_full_read_budget() {
    let (provider, wire) = fixture(true);
    startup_check(&provider).await;
    {
        let mut fallback = wire.fallback.lock().unwrap();
        fallback.up = true;
        fallback.delay = Duration::from_millis(600);
    }
    assert_eq!(ready_height(provider.clone()).await, 101);
    assert_eq!(ready_height(provider).await, 101);
}

#[tokio::test(start_paused = true)]
async fn canceled_fallback_read_requires_a_new_network_check() {
    let (provider, wire) = fixture(true);
    startup_check(&provider).await;
    {
        let mut primary = wire.primary.lock().unwrap();
        primary.up = true;
        primary.delay = Duration::from_millis(20);
    }
    wire.fallback.lock().unwrap().up = true;
    wire.hold_fallback_header.store(true, Ordering::SeqCst);
    assert_eq!(ready_height(provider.clone()).await, 202);
    {
        let mut primary = wire.primary.lock().unwrap();
        primary.up = false;
        primary.down_status = Some(503);
    }
    wire.fallback.lock().unwrap().network = bitcoin::Network::Regtest;
    wire.hold_fallback_header.store(false, Ordering::SeqCst);
    let fallback_reads = wire.fallback.lock().unwrap().data_requests;
    let error = provider.get_best_block_header().await.unwrap_err();
    assert!(error.to_string().contains("network mismatch"), "{error}");
    assert_eq!(wire.fallback.lock().unwrap().data_requests, fallback_reads);
}

#[tokio::test(start_paused = true)]
async fn fallback_serves_tip_after_startup_failure_then_primary_recovers() {
    let (provider, wire) = fixture(true);
    wire.fallback.lock().unwrap().up = true;
    startup_check(&provider).await;
    assert_eq!(ready_height(provider.clone()).await, 101);
    wire.primary.lock().unwrap().up = true;
    assert_eq!(provider.get_best_block_header().await.unwrap().height, 202);
    assert!(provider.refusal().is_ok());
}

#[tokio::test(start_paused = true)]
async fn fallback_recovers_while_primary_stays_down() {
    let (provider, wire) = fixture(true);
    startup_check(&provider).await;
    assert!(provider.get_best_block_header().await.is_err());
    wire.fallback.lock().unwrap().up = true;
    assert_eq!(ready_height(provider.clone()).await, 101);
    assert_eq!(ready_height(provider).await, 101);
}

#[tokio::test(start_paused = true)]
async fn recovering_primary_on_wrong_network_refuses_cached_fallback_tip() {
    let (provider, wire) = fixture(true);
    wire.fallback.lock().unwrap().up = true;
    startup_check(&provider).await;
    let tip = crate::FreshTip::wrap(provider.clone(), Some("signet"));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), tip.get_block_height())
            .await
            .unwrap()
            .unwrap(),
        101
    );
    {
        let mut primary = wire.primary.lock().unwrap();
        primary.network = bitcoin::Network::Regtest;
        primary.up = true;
    }
    let error = provider.get_best_block_header().await.unwrap_err();
    assert!(error.to_string().contains("network mismatch"), "{error}");
    let fallback_reads = wire.fallback.lock().unwrap().data_requests;
    assert!(tip.get_block_height().await.is_err());
    assert!(provider.get_best_block_header().await.is_err());
    assert_eq!(wire.primary.lock().unwrap().data_requests, 0);
    assert_eq!(wire.fallback.lock().unwrap().data_requests, fallback_reads);
}

#[tokio::test(start_paused = true)]
async fn wrong_network_fallback_never_serves_tip_after_startup_failure() {
    let (provider, wire) = fixture(true);
    startup_check(&provider).await;
    {
        let mut fallback = wire.fallback.lock().unwrap();
        fallback.network = bitcoin::Network::Regtest;
        fallback.up = true;
    }
    let error = provider.get_best_block_header().await.unwrap_err();
    assert!(error.to_string().contains("network mismatch"), "{error}");
    wire.primary.lock().unwrap().up = true;
    assert!(provider.get_best_block_header().await.is_err());
    assert_eq!(wire.primary.lock().unwrap().data_requests, 0);
    assert_eq!(wire.fallback.lock().unwrap().data_requests, 0);
}

#[tokio::test(start_paused = true)]
async fn concurrent_network_refusal_discards_an_in_flight_tip() {
    let (provider, wire) = fixture(true);
    {
        let mut fallback = wire.fallback.lock().unwrap();
        fallback.up = true;
        fallback.delay = Duration::from_millis(100);
    }
    startup_check(&provider).await;
    let reader = provider.clone();
    let read = tokio::spawn(async move { reader.get_best_block_header().await });
    tokio::time::timeout(Duration::from_secs(5), wire.header_started.notified())
        .await
        .expect("fallback header read must start");
    {
        let mut primary = wire.primary.lock().unwrap();
        primary.network = bitcoin::Network::Regtest;
        primary.up = true;
    }
    assert!(matches!(
        provider.verify_network().await,
        NetworkCheck::Mismatch(_)
    ));
    let error = read.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("network mismatch"), "{error}");
}
