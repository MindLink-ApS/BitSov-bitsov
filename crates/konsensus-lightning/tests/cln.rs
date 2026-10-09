//! Local TLS transport tests. Fixture keys are public test material, never credentials.
use konsensus_core::traits::lightning::{LightningError, LightningProvider};
use konsensus_lightning::{ClnConfig, ClnProvider};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
    TlsAcceptor,
};

const RUNE: &str = "TEST_ONLY_RUNE_DO_NOT_LOG";
const PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
fn info(version: &str, network: &str) -> String {
    serde_json::json!({"id": PUBKEY, "version": version, "network": network}).to_string()
}
struct Server {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
    response: Arc<Mutex<(u16, String)>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn new(status: u16, body: String) -> Self {
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(
                include_bytes!("fixtures/cln/server.der").to_vec(),
            )],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                include_bytes!("fixtures/cln/server-key.der").to_vec(),
            )),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let response = Arc::new(Mutex::new((status, body)));
        let (seen, reply) = (requests.clone(), response.clone());
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (acceptor, seen, reply) = (acceptor.clone(), seen.clone(), reply.clone());
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut request = Vec::new();
                    loop {
                        let mut buf = [0; 1024];
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        request.extend_from_slice(&buf[..n]);
                        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            let headers =
                                String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                            let len = headers
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length: "))
                                .unwrap_or("0")
                                .parse::<usize>()
                                .unwrap();
                            if request.len() >= end + 4 + len {
                                break;
                            }
                        }
                    }
                    seen.lock()
                        .unwrap()
                        .push(String::from_utf8(request).unwrap());
                    let (status, body) = reply.lock().unwrap().clone();
                    let redirect = if status == 302 {
                        format!("location: {body}\r\n")
                    } else {
                        String::new()
                    };
                    let wire = format!("HTTP/1.1 {status} Test\r\n{redirect}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                    let _ = stream.write_all(wire.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            port,
            requests,
            response,
            task,
        }
    }
    fn config(&self, dir: &tempfile::TempDir) -> ClnConfig {
        let rune_file = dir.path().join("rune");
        if rune_file.exists() {
            std::fs::remove_file(&rune_file).unwrap();
        }
        std::fs::write(&rune_file, format!("{RUNE}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&rune_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        ClnConfig {
            rest_url: format!("https://localhost:{}", self.port),
            resolve_ip: Some("127.0.0.1".parse().unwrap()),
            ca_cert_path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/cln/ca.pem"),
            rune_file,
            network: "regtest".into(),
            minimum_version: "v24.11".into(),
        }
    }
}

#[tokio::test]
async fn connects_with_header_only_and_reports_preview_status() {
    let server = Server::new(200, info("v24.11", "regtest")).await;
    let dir = tempfile::tempdir().unwrap();
    let config = server.config(&dir);
    let provider = ClnProvider::new(config.clone()).await.unwrap();
    for debug in [
        format!("{config:?}"),
        format!("{config:#?}"),
        format!("{provider:?}"),
        format!("{provider:#?}"),
    ] {
        assert!(!debug.contains(RUNE));
    }
    assert!(format!("{provider:?}").contains("<redacted>"));
    assert!(provider.is_available().await);
    assert_eq!(provider.get_node_pubkey().await.as_deref(), Some(PUBKEY));
    assert!(!provider.is_payment_capable().await);
    assert!(!provider.money_ready().await);
    assert!(!provider.readiness().await.money_ready);
    for request in server.requests.lock().unwrap().iter() {
        let (head, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("POST /v1/getinfo HTTP/1.1\r\n"));
        assert_eq!(
            head.lines()
                .filter(|l| l.contains(RUNE))
                .collect::<Vec<_>>(),
            vec![format!("rune: {RUNE}")]
        );
        assert_eq!(body, "{}");
    }
    let count = server.requests.lock().unwrap().len();
    assert!(provider.create_invoice(1, "test", 60).await.is_err());
    assert!(matches!(
        provider.pay_invoice("test").await,
        Err(LightningError::PaymentNotDispatched(_))
    ));
    assert!(provider.get_payment_status("hash").await.is_err());
    assert!(provider.get_balance_msat().await.is_err());
    assert!(provider
        .pay_invoice_with_fee_limit("test", 0)
        .await
        .is_err());
    assert!(provider.keysend(PUBKEY, 1, None).await.is_err());
    assert!(provider
        .keysend_with_fee_limit(PUBKEY, 1, None, 0)
        .await
        .is_err());
    assert!(matches!(
        provider.create_stateless_invoice(1, "test", 60).await,
        Err(LightningError::StatelessQuoteUnsupported)
    ));
    assert_eq!(server.requests.lock().unwrap().len(), count);
    *server.response.lock().unwrap() = (200, info("v24.11", "bitcoin"));
    assert!(!provider.is_available().await);
    assert!(provider.get_node_pubkey().await.is_none());
}

#[tokio::test]
async fn validates_versions_network_and_untrusted_responses() {
    let server = Server::new(200, info("v24.11", "regtest")).await;
    let dir = tempfile::tempdir().unwrap();
    for version in [
        "v24.11",
        "24.11",
        "v24.11.1",
        "v26.06.8",
        "v24.11-1-gabcdef",
    ] {
        *server.response.lock().unwrap() = (200, info(version, "regtest"));
        ClnProvider::new(server.config(&dir)).await.unwrap();
    }
    for version in [
        "v24.08",
        "v23.11.9",
        "v24.11rc1",
        "v24.11-rc1",
        "garbage",
        "v24.11evil",
        "999999999999999999999.1",
        "v24",
    ] {
        *server.response.lock().unwrap() = (200, info(version, "regtest"));
        assert!(
            ClnProvider::new(server.config(&dir)).await.is_err(),
            "{version}"
        );
    }
    for (status, body) in [
        (401, RUNE.into()),
        (500, RUNE.into()),
        (200, format!("{{\"id\":\"{RUNE}\"}}")),
        (200, info("v24.11", RUNE)),
        (200, info(RUNE, "regtest")),
        (200, info("v24.11", "regtest").replace(PUBKEY, RUNE)),
    ] {
        *server.response.lock().unwrap() = (status, body);
        let err = ClnProvider::new(server.config(&dir)).await.unwrap_err();
        assert!(!format!("{err:?} {err}").contains(RUNE));
    }
    *server.response.lock().unwrap() = (200, info("v24.11", "regtest"));
    let mut config = server.config(&dir);
    config.minimum_version = "v26.06".into();
    assert!(ClnProvider::new(config).await.is_err());
    let mut config = server.config(&dir);
    config.minimum_version = "v23.01".into();
    assert!(ClnProvider::new(config).await.is_err());
}

#[tokio::test]
async fn refuses_unsafe_urls_tls_and_redirects() {
    let server = Server::new(200, info("v24.11", "regtest")).await;
    let dir = tempfile::tempdir().unwrap();
    for url in [
        "http://localhost",
        "https://user:secret@localhost",
        "https://localhost/?rune=secret",
        "https://localhost/#secret",
        "https://localhost/secret",
        "not-a-url",
    ] {
        let mut config = server.config(&dir);
        config.rest_url = url.into();
        assert!(ClnProvider::new(config).await.is_err());
    }
    let mut config = server.config(&dir);
    config.ca_cert_path.set_file_name("wrong-ca.pem");
    assert!(ClnProvider::new(config).await.is_err());
    let mut config = server.config(&dir);
    config.rest_url = format!("https://127.0.0.1:{}", server.port);
    assert!(ClnProvider::new(config).await.is_err());
    assert!(server.requests.lock().unwrap().is_empty());
    let target = Server::new(200, info("v24.11", "regtest")).await;
    *server.response.lock().unwrap() =
        (302, format!("https://localhost:{}/v1/getinfo", target.port));
    assert!(ClnProvider::new(server.config(&dir)).await.is_err());
    assert!(target.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn refuses_bad_rune_files() {
    let server = Server::new(200, info("v24.11", "regtest")).await;
    let dir = tempfile::tempdir().unwrap();
    for contents in ["", "\n", "one\ntwo", "one\r\ntwo", " spaces "] {
        let config = server.config(&dir);
        std::fs::write(&config.rune_file, contents).unwrap();
        assert!(ClnProvider::new(config).await.is_err());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for mode in [0o644, 0o640, 0o660, 0o400, 0o700] {
            let config = server.config(&dir);
            std::fs::set_permissions(&config.rune_file, std::fs::Permissions::from_mode(mode))
                .unwrap();
            assert!(ClnProvider::new(config).await.is_err(), "{mode:o}");
        }
    }
    let config = server.config(&dir);
    std::fs::remove_file(&config.rune_file).unwrap();
    assert!(ClnProvider::new(config).await.is_err());
    assert!(server.requests.lock().unwrap().is_empty());
}
