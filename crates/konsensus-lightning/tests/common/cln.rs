#![allow(dead_code)]
//! Shared TLS clnrest fixture; all keys and runes are public test material.
use konsensus_lightning::ClnConfig;
use serde_json::Value;
use std::collections::HashMap;
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

pub const RUNE: &str = "TEST_ONLY_RUNE_DO_NOT_LOG";
pub const PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
pub fn info(version: &str, network: &str) -> String {
    serde_json::json!({"id": PUBKEY, "version": version, "network": network}).to_string()
}
pub struct Server {
    pub port: u16,
    pub requests: Arc<Mutex<Vec<String>>>,
    pub response: Arc<Mutex<(u16, String)>>,
    pub routes: Arc<Mutex<HashMap<String, (u16, String)>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    pub async fn new(status: u16, body: String) -> Self {
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(
                include_bytes!("../fixtures/cln/server.der").to_vec(),
            )],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                include_bytes!("../fixtures/cln/server-key.der").to_vec(),
            )),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let response = Arc::new(Mutex::new((status, body)));
        let routes = Arc::new(Mutex::new(HashMap::<String, (u16, String)>::new()));
        routes.lock().unwrap().insert(
            "/v1/help".into(),
            (
                200,
                serde_json::json!({"help":[{"command":"xpay invstring [maxfee]"},
                {"command":"xkeysend destination amount_msat [maxfee]"},
                {"command":"keysend destination amount_msat [maxfee]"}]})
                .to_string(),
            ),
        );
        let routing = routes.clone();
        let (seen, reply) = (requests.clone(), response.clone());
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (acceptor, seen, reply) = (acceptor.clone(), seen.clone(), reply.clone());
                let routing = routing.clone();
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
                    let request = String::from_utf8(request).unwrap();
                    let (headers, params) = request.split_once("\r\n\r\n").unwrap();
                    let path = headers.split_whitespace().nth(1).unwrap();
                    let params: Value = serde_json::from_str(params).unwrap();
                    let key = if let Some(start) = params.get("start") {
                        format!("{path}?start={start}")
                    } else {
                        path.to_string()
                    };
                    let (status, body) = routing
                        .lock()
                        .unwrap()
                        .get(&key)
                        .cloned()
                        .unwrap_or_else(|| reply.lock().unwrap().clone());
                    seen.lock().unwrap().push(request);
                    if status == 0 {
                        // Accepted POST whose outcome is never returned.
                        std::future::pending::<()>().await;
                    }
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
            routes,
            task,
        }
    }
    pub fn route(&self, method: &str, value: Value) {
        self.routes
            .lock()
            .unwrap()
            .insert(format!("/v1/{method}"), (200, value.to_string()));
    }
    pub fn calls(&self) -> Vec<(String, Value)> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| {
                let (head, body) = request.split_once("\r\n\r\n").unwrap();
                (
                    head.split_whitespace().nth(1).unwrap().to_string(),
                    serde_json::from_str(body).unwrap(),
                )
            })
            .collect()
    }
    pub fn config(&self, dir: &tempfile::TempDir) -> ClnConfig {
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
