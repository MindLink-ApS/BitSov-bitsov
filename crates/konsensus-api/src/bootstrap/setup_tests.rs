use super::*;
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use tower::ServiceExt;

#[tokio::test]
async fn body_size_boundary_includes_state_polling() {
    for (method, path) in [
        ("GET", "/"),
        ("GET", "/setup/state"),
        ("POST", "/setup/start"),
    ] {
        let (_dir, _bootstrap, page) = fixture();
        let (cookie, csrf) = session(&page).await;
        for (size, expected) in [
            (2048, StatusCode::OK),
            (2049, StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let req = Request::builder()
                .method(method)
                .uri(path)
                .header("host", "bitsov.local:8080")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .extension(ConnectInfo("192.168.1.2:1".parse::<SocketAddr>().unwrap()))
                .body(Body::from(vec![b'x'; size]))
                .unwrap();
            assert_eq!(
                router(page.clone()).oneshot(req).await.unwrap().status(),
                expected,
                "{path}: {size}"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn source_table_is_bounded_without_resetting_active_buckets() {
    let limits = SetupRateLimits::default();
    let first = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
    for _ in 0..8 {
        assert!(limits.allow(first, false));
    }
    for n in 2..=1024u32 {
        assert!(limits.allow(IpAddr::V4(std::net::Ipv4Addr::from(0x0a000000 + n)), false));
    }
    let newcomer = "10.1.1.1".parse().unwrap();
    assert!(!limits.allow(newcomer, false));
    assert!(!limits.allow(first, false));
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(limits.allow(newcomer, false));
    assert!(limits.allow(first, false));
}

#[tokio::test]
async fn streamed_body_without_content_length_cannot_bypass_cap() {
    let (_dir, _bootstrap, page) = fixture();
    let chunks = (0..3).map(|_| Ok::<_, std::io::Error>(Bytes::from(vec![b'x'; 1024])));
    let req = Request::builder()
        .uri("/")
        .header("host", "bitsov.local:8080")
        .extension(ConnectInfo("192.168.1.2:1".parse::<SocketAddr>().unwrap()))
        .body(Body::from_stream(futures::stream::iter(chunks)))
        .unwrap();
    assert_eq!(
        router(page).oneshot(req).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test(start_paused = true)]
async fn status_page_and_polling_share_read_budget_and_forwarded_headers_cannot_reset_it() {
    let page = Arc::new(SetupPage::new(
        None,
        None,
        vec!["bitsov.local:8080".into()],
        "Box".into(),
        "LOCKED".into(),
    ));
    for n in 0..9 {
        let req = Request::builder()
            .uri("/")
            .header("host", "bitsov.local:8080")
            .header("x-forwarded-for", format!("192.168.2.{n}"))
            .header("forwarded", format!("for=192.168.2.{n}"))
            .extension(ConnectInfo("192.168.1.2:1".parse::<SocketAddr>().unwrap()))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router(page.clone()).oneshot(req).await.unwrap().status(),
            if n < 8 {
                StatusCode::OK
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
    assert_eq!(
        request(
            &page,
            "GET",
            "/setup/state",
            "192.168.1.2:1",
            "bitsov.local:8080",
            None,
            serde_json::json!({})
        )
        .await
        .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

// Removing admission from the guard must allow these bursts and fail the tests.
#[tokio::test(start_paused = true)]
async fn page_rate_limit_is_per_ip_refills_and_ignores_source_port() {
    let (_dir, _bootstrap, page) = fixture();
    for port in 1..=9 {
        let response = request(
            &page,
            "GET",
            "/",
            &format!("192.168.1.2:{port}"),
            "bitsov.local:8080",
            None,
            serde_json::json!({}),
        )
        .await;
        assert_eq!(
            response.status(),
            if port <= 8 {
                StatusCode::OK
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
    assert_eq!(
        request(
            &page,
            "GET",
            "/",
            "192.168.1.3:1",
            "bitsov.local:8080",
            None,
            serde_json::json!({})
        )
        .await
        .status(),
        StatusCode::OK
    );
    // IPv4-mapped addresses must not get a second bucket.
    assert_eq!(
        request(
            &page,
            "GET",
            "/",
            "[::ffff:192.168.1.2]:1",
            "bitsov.local:8080",
            None,
            serde_json::json!({})
        )
        .await
        .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        request(
            &page,
            "GET",
            "/",
            "192.168.1.2:1",
            "bitsov.local:8080",
            None,
            serde_json::json!({})
        )
        .await
        .status(),
        StatusCode::OK
    );
}

#[tokio::test(start_paused = true)]
async fn setup_posts_share_a_separate_bucket_across_routes() {
    let (_dir, _bootstrap, page) = fixture();
    let (cookie, csrf) = session(&page).await;
    for _ in 0..4 {
        assert_eq!(
            request(
                &page,
                "POST",
                "/setup/start",
                "192.168.1.2:1",
                "bitsov.local:8080",
                Some((&cookie, &csrf)),
                serde_json::json!({})
            )
            .await
            .status(),
            StatusCode::OK
        );
    }
    for path in ["/setup/start", "/setup/approve", "/setup/cancel"] {
        let response = request(
            &page,
            "POST",
            path,
            "192.168.1.2:2",
            "bitsov.local:8080",
            Some((&cookie, &csrf)),
            serde_json::json!({}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    assert_eq!(
        request(
            &page,
            "GET",
            "/setup/state",
            "192.168.1.2:1",
            "bitsov.local:8080",
            Some((&cookie, &csrf)),
            serde_json::json!({})
        )
        .await
        .status(),
        StatusCode::OK
    );
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(
        request(
            &page,
            "POST",
            "/setup/start",
            "192.168.1.2:1",
            "bitsov.local:8080",
            Some((&cookie, &csrf)),
            serde_json::json!({})
        )
        .await
        .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn body_cap_covers_handlers_without_body_extractors() {
    for (method, path) in [
        ("GET", "/"),
        ("POST", "/setup/start"),
        ("POST", "/setup/cancel"),
        ("POST", "/setup/approve"),
    ] {
        let (_dir, _bootstrap, page) = fixture();
        let (cookie, csrf) = session(&page).await;
        let response = request(
            &page,
            method,
            path,
            "192.168.1.2:1",
            "bitsov.local:8080",
            Some((&cookie, &csrf)),
            serde_json::json!("x".repeat(2049)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE, "{path}");
    }
}

#[tokio::test(start_paused = true)]
async fn body_read_has_an_absolute_deadline() {
    let (_dir, _bootstrap, page) = fixture();
    let (cookie, csrf) = session(&page).await;
    // A chunk arrives every second: an inactivity timeout would never fire.
    let body = Body::from_stream(futures::stream::unfold((), |_| async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        Some((
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"x")),
            (),
        ))
    }));
    let req = Request::builder()
        .method("POST")
        .uri("/setup/start")
        .header("host", "bitsov.local:8080")
        .header("cookie", cookie)
        .header("x-csrf-token", csrf)
        .extension(ConnectInfo("192.168.1.2:1".parse::<SocketAddr>().unwrap()))
        .body(body)
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(6), router(page).oneshot(req))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(response.headers()["connection"], "close");
}

struct Tickets;
impl SetupTickets for Tickets {
    fn mint(&self, _: Duration) -> Result<String, SetupTicketError> {
        Ok("bitsov://pair/test".into())
    }
    fn cancel(&self) -> Result<(), SetupTicketError> {
        Ok(())
    }
}
fn fixture() -> (tempfile::TempDir, Arc<BootstrapState>, Arc<SetupPage>) {
    let dir = tempfile::tempdir().unwrap();
    let pairing =
        Arc::new(crate::pairing::PairingService::open(dir.path(), String::new(), false).unwrap());
    let bootstrap = Arc::new(BootstrapState::new(
        super::super::DataDirLayout::new(dir.path()),
        pairing,
    ));
    let page = Arc::new(SetupPage::new(
        Some(bootstrap.clone()),
        Some(Arc::new(Tickets)),
        vec!["bitsov.local:8080".into()],
        "Box".into(),
        "setup".into(),
    ));
    (dir, bootstrap, page)
}
async fn request(
    page: &Arc<SetupPage>,
    method: &str,
    path: &str,
    source: &str,
    host: &str,
    session: Option<(&str, &str)>,
    body: serde_json::Value,
) -> axum::response::Response {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .header("content-type", "application/json");
    if let Some((cookie, csrf)) = session {
        req = req.header("cookie", cookie).header("x-csrf-token", csrf);
    }
    let mut req = req.body(Body::from(body.to_string())).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(source.parse::<SocketAddr>().unwrap()));
    router(page.clone()).oneshot(req).await.unwrap()
}
async fn session(page: &Arc<SetupPage>) -> (String, String) {
    let response = request(
        page,
        "GET",
        "/",
        "192.168.1.2:1234",
        "bitsov.local:8080",
        None,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("default-src 'none'"));
    assert!(response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .contains("SameSite=Strict"));
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let html = String::from_utf8(
        to_bytes(response.into_body(), 100000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let csrf = html
        .split("const csrf = '")
        .nth(1)
        .unwrap()
        .split('\'')
        .next()
        .unwrap()
        .to_owned();
    (cookie, csrf)
}
#[tokio::test]
async fn source_host_csrf_are_required_on_every_setup_action() {
    let (_dir, _bootstrap, page) = fixture();
    let (cookie, csrf) = session(&page).await;
    for source in [
        "8.8.8.8:1",
        "100.64.0.1:1",
        "127.0.0.1:1",
        "[::ffff:100.64.0.1]:1",
        "[fd7a:115c:a1e0::1]:1",
    ] {
        for (method, path) in [
            ("GET", "/"),
            ("POST", "/setup/start"),
            ("POST", "/setup/approve"),
            ("POST", "/setup/cancel"),
        ] {
            assert_eq!(
                request(
                    &page,
                    method,
                    path,
                    source,
                    "bitsov.local:8080",
                    Some((&cookie, &csrf)),
                    serde_json::json!({})
                )
                .await
                .status(),
                StatusCode::FORBIDDEN
            );
        }
    }
    for path in ["/setup/start", "/setup/approve", "/setup/cancel"] {
        for (host, session) in [
            ("evil.test:8080", Some((cookie.as_str(), csrf.as_str()))),
            ("bitsov.local:8080", None),
            ("bitsov.local:8080", Some((cookie.as_str(), "wrong"))),
        ] {
            assert_eq!(
                request(
                    &page,
                    "POST",
                    path,
                    "192.168.1.2:1",
                    host,
                    session,
                    serde_json::json!({})
                )
                .await
                .status(),
                StatusCode::FORBIDDEN
            );
        }
    }
    let response = request(
        &page,
        "POST",
        "/setup/start",
        "192.168.1.2:1",
        "bitsov.local:8080",
        Some((&cookie, &csrf)),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
}
#[tokio::test(start_paused = true)]
async fn window_and_three_cancels_close_setup_and_restart_reopens() {
    let (_dir, _bootstrap, page) = fixture();
    let (cookie, csrf) = session(&page).await;
    tokio::time::advance(Duration::from_secs(900)).await;
    assert_eq!(
        request(
            &page,
            "POST",
            "/setup/start",
            "192.168.1.2:1",
            "bitsov.local:8080",
            Some((&cookie, &csrf)),
            serde_json::json!({})
        )
        .await
        .status(),
        StatusCode::GONE
    );
    let (_dir2, _bootstrap2, page2) = fixture();
    let (cookie, csrf) = session(&page2).await;
    for _ in 0..3 {
        assert_eq!(
            request(
                &page2,
                "POST",
                "/setup/cancel",
                "192.168.1.2:1",
                "bitsov.local:8080",
                Some((&cookie, &csrf)),
                serde_json::json!({})
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!(
        request(
            &page2,
            "POST",
            "/setup/start",
            "192.168.1.2:1",
            "bitsov.local:8080",
            Some((&cookie, &csrf)),
            serde_json::json!({})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
async fn approval_only_sets_flag_for_exact_pending_digest_and_status_hides_secrets() {
    let (dir, bootstrap, page) = fixture();
    let digest = blake3::hash(b"sas");
    *bootstrap.pending.lock().unwrap() = Some(super::super::PendingIdentity {
        ceremony_id: "ceremony".into(),
        mnemonic: zeroize::Zeroizing::new("secret recovery phrase".into()),
        node_id: "pending-id".into(),
        fingerprint: "pending-fp".into(),
        client_id: "client".into(),
        created_at: tokio::time::Instant::now(),
        backup_check: [0, 1, 2],
        failed_backup_attempts: 0,
        password_commitment: None,
        sas: Some(super::super::PendingSas {
            device_key: [4; 65],
            device_name: "<script>phone</script>".into(),
            binding: crate::sas::NoiseBinding {
                handshake_hash: [1; 32],
                box_public_key: [2; 32],
                client_static: [3; 32],
            },
            digest,
            box_approved: false,
        }),
    });
    let (cookie, csrf) = session(&page).await;
    for (id, hash, expected) in [
        ("other", digest.to_hex().to_string(), StatusCode::CONFLICT),
        ("ceremony", "00".repeat(32), StatusCode::BAD_REQUEST),
        (
            "ceremony",
            digest.to_hex().to_string(),
            StatusCode::NO_CONTENT,
        ),
    ] {
        assert_eq!(
            request(
                &page,
                "POST",
                "/setup/approve",
                "192.168.1.2:1",
                "bitsov.local:8080",
                Some((&cookie, &csrf)),
                serde_json::json!({"ceremony_id":id,"sas_digest":hash})
            )
            .await
            .status(),
            expected
        );
    }
    assert!(
        bootstrap
            .pending
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .sas
            .as_ref()
            .unwrap()
            .box_approved
    );
    assert!(!bootstrap.is_committed());
    assert!(bootstrap.pairing.list_clients().is_empty());
    assert!(!dir.path().join("NODE_INITIALIZED").exists());
    bootstrap.committed.store(true, Ordering::SeqCst);
    let response = request(
        &page,
        "GET",
        "/",
        "192.168.1.2:1",
        "bitsov.local:8080",
        None,
        serde_json::json!({}),
    )
    .await;
    let html = String::from_utf8(
        to_bytes(response.into_body(), 100000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    for secret in [
        "Approve",
        "Start setup",
        "bitsov://",
        "secret recovery phrase",
        "const csrf",
    ] {
        assert!(!html.contains(secret));
    }
    assert!(html.contains("Use the BitSov app"));
    assert_eq!(
        request(
            &page,
            "POST",
            "/setup/approve",
            "192.168.1.2:1",
            "bitsov.local:8080",
            Some((&cookie, &csrf)),
            serde_json::json!({"ceremony_id":"ceremony","sas_digest":digest.to_hex().to_string()})
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
}
#[test]
fn private_address_policy() {
    for ip in [
        "10.0.0.1",
        "172.16.1.2",
        "192.168.1.2",
        "169.254.1.1",
        "fd00::1",
        "fe80::1",
        "::ffff:192.168.1.2",
    ] {
        assert!(lan_source(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "172.15.1.1",
        "172.32.1.1",
        "100.127.255.255",
        "::1",
        "0.0.0.0",
        "224.0.0.1",
        "2001:db8::1",
        "::ffff:8.8.8.8",
    ] {
        assert!(!lan_source(ip.parse().unwrap()), "{ip}");
    }
}
