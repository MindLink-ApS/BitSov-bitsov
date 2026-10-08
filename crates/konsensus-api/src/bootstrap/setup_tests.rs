use super::*;
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use tower::ServiceExt;

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
