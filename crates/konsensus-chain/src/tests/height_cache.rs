use super::*;
use std::collections::VecDeque;
use std::time::Duration;

/// Replace only the HTTP boundary; exercise the provider, limiter and parser.
#[derive(Debug)]
struct HeightHttp {
    calls: AtomicUsize,
    replies: std::sync::Mutex<VecDeque<(u16, &'static str)>>,
}

impl HttpTransport for HeightHttp {
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
            assert_eq!(request.method(), reqwest::Method::GET);
            assert_eq!(request.url().path(), "/api/blocks/tip/height");
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (status, body) = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("extra HTTP request");
            // Keep the refresh in flight while concurrent callers reach it.
            tokio::time::sleep(Duration::from_millis(1)).await;
            Ok(http::Response::builder()
                .status(status)
                .body(body)
                .unwrap()
                .into())
        })
    }
}

fn fixture(replies: Vec<(u16, &'static str)>) -> (Arc<EsploraProvider>, Arc<HeightHttp>) {
    let wire = Arc::new(HeightHttp {
        calls: AtomicUsize::new(0),
        replies: std::sync::Mutex::new(replies.into()),
    });
    let mut provider = EsploraProvider::new(EsploraConfig::custom(
        "https://height-cache.invalid".into(),
        TrustLevel::ServerTrust,
    ))
    .unwrap();
    provider.transport = Some(wire.clone());
    (Arc::new(provider), wire)
}

async fn concurrent_heights(provider: &Arc<EsploraProvider>, expected: u64) {
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let provider = provider.clone();
        tasks.spawn(async move { provider.get_block_height().await.unwrap() });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap(), expected);
    }
}

#[tokio::test(start_paused = true)]
async fn concurrent_calls_make_one_http_request_per_refresh() {
    let (provider, wire) = fixture(vec![(200, "850000"), (200, "850001")]);
    concurrent_heights(&provider, 850000).await;
    assert_eq!(wire.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.get_block_height().await.unwrap(), 850000);
    assert_eq!(wire.calls.load(Ordering::SeqCst), 1);

    tokio::time::advance(Duration::from_secs(30)).await;
    concurrent_heights(&provider, 850001).await;
    assert_eq!(wire.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn expires_at_ttl_even_with_frequent_reads() {
    // A reorg may lower the tip; cache the actual response, not a maximum.
    let (provider, wire) = fixture(vec![(200, "850001"), (200, "850000")]);
    assert_eq!(provider.get_block_height().await.unwrap(), 850001);
    tokio::time::advance(Duration::from_secs(20)).await;
    assert_eq!(provider.get_block_height().await.unwrap(), 850001);
    tokio::time::advance(Duration::from_millis(9999)).await;
    assert_eq!(provider.get_block_height().await.unwrap(), 850001);
    assert_eq!(wire.calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(provider.get_block_height().await.unwrap(), 850000);
    assert_eq!(wire.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn errors_and_invalid_heights_are_not_cached() {
    for reply in [(500, "unavailable"), (200, "not a height"), (200, "0")] {
        let (provider, wire) = fixture(vec![reply, (200, "850000")]);
        assert!(provider.get_block_height().await.is_err());
        assert_eq!(provider.get_block_height().await.unwrap(), 850000);
        assert_eq!(provider.get_block_height().await.unwrap(), 850000);
        assert_eq!(wire.calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test(start_paused = true)]
async fn failed_refresh_never_serves_stale_height_and_can_retry() {
    let (provider, wire) = fixture(vec![(200, "850000"), (500, "unavailable"), (200, "850001")]);
    assert_eq!(provider.get_block_height().await.unwrap(), 850000);
    tokio::time::advance(Duration::from_secs(30)).await;
    assert!(provider.get_block_height().await.is_err());
    assert_eq!(provider.get_block_height().await.unwrap(), 850001);
    assert_eq!(wire.calls.load(Ordering::SeqCst), 3);
}
