//! Recipient-only Esplora fault boundary. Success responses are real electrs
//! responses; the sole injected behavior is HTTP 429. No fabricated chain data.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub struct FaultProxy {
    pub url: String,
    limited: Arc<AtomicBool>,
    rejected: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

impl FaultProxy {
    pub async fn start(upstream: &str) -> Self {
        let parsed = reqwest::Url::parse(upstream).unwrap();
        assert_eq!(
            parsed.host_str(),
            Some("127.0.0.1"),
            "{SYNC}: isolated fault backend"
        );
        assert_ne!(
            parsed.port_or_known_default(),
            Some(3141),
            "{SYNC}: never target the live app proxy"
        );
        let upstream = upstream.to_owned();
        let limited = Arc::new(AtomicBool::new(false));
        let rejected = Arc::new(AtomicU64::new(0));
        let (gate, count) = (limited.clone(), rejected.clone());
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let router = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let (client, upstream, gate, count) = (
                client.clone(),
                upstream.clone(),
                gate.clone(),
                count.clone(),
            );
            async move {
                use axum::response::IntoResponse;
                if gate.load(Ordering::SeqCst) {
                    count.fetch_add(1, Ordering::SeqCst);
                    return (
                        axum::http::StatusCode::TOO_MANY_REQUESTS,
                        [("retry-after", "1")],
                        "Atlas run 4: injected regtest 429",
                    )
                        .into_response();
                }
                let (parts, body) = request.into_parts();
                let path = parts.uri.path_and_query().unwrap().as_str();
                let path = path.strip_prefix("/api").unwrap_or(path);
                let body = axum::body::to_bytes(body, 4 << 20).await.unwrap();
                match client
                    .request(parts.method, format!("{upstream}{path}"))
                    .body(body)
                    .send()
                    .await
                {
                    Ok(response) => {
                        let status = response.status();
                        (status, response.bytes().await.unwrap()).into_response()
                    }
                    Err(_) => axum::http::StatusCode::BAD_GATEWAY.into_response(),
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            url,
            limited,
            rejected,
            task,
        }
    }

    pub fn set_limited(&self, limited: bool) {
        self.limited.store(limited, Ordering::SeqCst);
    }
    pub fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::SeqCst)
    }
}

impl Drop for FaultProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Runs without Core/electrs: prove the fault boundary preserves method,
/// query, body and status, and that removing 429 reconnects to the upstream.
#[tokio::test]
async fn proxy_forwards_then_rate_limits_then_recovers() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!("http://{}", listener.local_addr().unwrap());
    let router = axum::Router::new().fallback(|request: axum::extract::Request| async move {
        let (parts, body) = request.into_parts();
        let body = axum::body::to_bytes(body, 1024).await.unwrap();
        (
            axum::http::StatusCode::CREATED,
            format!(
                "{} {} {}",
                parts.method,
                parts.uri,
                std::str::from_utf8(&body).unwrap()
            ),
        )
    });
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let proxy = FaultProxy::start(&upstream).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    for (path, limited) in [
        ("/api/tx?probe=1", false),
        ("/tx?probe=1", true),
        ("/tx?probe=1", false),
    ] {
        proxy.set_limited(limited);
        let response = client
            .post(format!("{}{path}", proxy.url))
            .body("regtest-body")
            .send()
            .await
            .unwrap();
        if limited {
            assert_eq!(
                response.status(),
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "{SYNC}"
            );
            assert_eq!(response.headers()["retry-after"], "1", "{SYNC}");
        } else {
            assert_eq!(response.status(), axum::http::StatusCode::CREATED, "{SYNC}");
            assert_eq!(
                response.text().await.unwrap(),
                "POST /tx?probe=1 regtest-body",
                "{SYNC}"
            );
        }
    }
    assert_eq!(
        proxy.rejected(),
        1,
        "{SYNC}: only the injected interval rejected requests"
    );
    server.abort();
    let _ = server.await;
}
