//! Local TLS transport tests. Fixture keys are public test material, never credentials.
use konsensus_core::traits::lightning::{
    LightningError, LightningProvider, PaymentDirection, PaymentStatus,
};
use konsensus_lightning::{ClnConfig, ClnProvider};
use serde_json::{json, Value};
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

const RUNE: &str = "TEST_ONLY_RUNE_DO_NOT_LOG";
const PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
fn info(version: &str, network: &str) -> String {
    serde_json::json!({"id": PUBKEY, "version": version, "network": network}).to_string()
}
struct Server {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
    response: Arc<Mutex<(u16, String)>>,
    routes: Arc<Mutex<HashMap<String, (u16, String)>>>,
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
        let routes = Arc::new(Mutex::new(HashMap::<String, (u16, String)>::new()));
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
    fn route(&self, method: &str, value: Value) {
        self.routes
            .lock()
            .unwrap()
            .insert(format!("/v1/{method}"), (200, value.to_string()));
    }
    fn calls(&self) -> Vec<(String, Value)> {
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
    assert!(matches!(
        provider.pay_invoice("test").await,
        Err(LightningError::PaymentNotDispatched(_))
    ));
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

fn hash() -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest([42; 32]))
}
fn bolt11() -> String {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    lightning_invoice::InvoiceBuilder::new(lightning_invoice::Currency::Regtest)
        .amount_milli_satoshis(1234)
        .description("memo".into())
        .payment_hash(hash().parse().unwrap())
        .payment_secret(lightning_invoice::PaymentSecret([42; 32]))
        .duration_since_epoch(std::time::Duration::from_secs(1700000000))
        .expiry_time(std::time::Duration::from_secs(60))
        .min_final_cltv_expiry_delta(18)
        .build_signed(|message| {
            Secp256k1::new()
                .sign_ecdsa_recoverable(message, &SecretKey::from_slice(&[42; 32]).unwrap())
        })
        .unwrap()
        .to_string()
}
fn incoming(status: &str) -> Value {
    json!({"label":"keysend-1700000000.1", "payment_hash":hash(), "status":status,
        "amount_msat":1000, "amount_received_msat":2500, "payment_preimage":hex::encode([42;32]),
        "paid_at":1700000000, "expires_at":1700003600, "created_index":1, "description":"received"})
}
fn outgoing(status: &str) -> Value {
    json!({"payment_hash":hash(), "status":status, "amount_msat":2000,
        "amount_sent_msat":2025, "preimage":hex::encode([42;32]), "created_at":1700000001,
        "created_index":1})
}
async fn read_provider() -> (Server, tempfile::TempDir, ClnProvider) {
    let server = Server::new(200, info("v24.11", "regtest")).await;
    let dir = tempfile::tempdir().unwrap();
    let provider = ClnProvider::new(server.config(&dir)).await.unwrap();
    (server, dir, provider)
}

#[tokio::test]
async fn t3_invoice_statuses_use_received_amount_and_invoice_precedence() {
    let (server, _dir, provider) = read_provider().await;
    for (state, status, amount) in [
        ("paid", PaymentStatus::Settled, 2500),
        ("unpaid", PaymentStatus::Pending, 1000),
        ("expired", PaymentStatus::Expired, 1000),
    ] {
        server.route("listinvoices", json!({"invoices":[incoming(state)]}));
        server.route("listpays", json!({"pays":[outgoing("complete")]}));
        let detail = provider.get_payment_status(&hash()).await.unwrap();
        assert_eq!(detail.payment_hash, hash());
        assert_eq!(detail.status, status);
        assert_eq!(detail.direction, PaymentDirection::Incoming);
        assert_eq!(detail.amount_msat, amount);
        assert_eq!(
            detail.preimage,
            (state == "paid").then(|| hex::encode([42; 32]))
        );
        assert_eq!(detail.fee_msat, None);
    }
    assert!(server
        .calls()
        .iter()
        .skip(1)
        .all(|(path, body)| path == "/v1/listinvoices" && *body == json!({"payment_hash":hash()})));
}

#[tokio::test]
async fn amountless_invoices_use_received_amount_only_when_paid() {
    let (server, _dir, provider) = read_provider().await;
    for (state, status, amount) in [
        ("paid", PaymentStatus::Settled, 2500),
        ("unpaid", PaymentStatus::Pending, 0),
        ("expired", PaymentStatus::Expired, 0),
    ] {
        let mut row = incoming(state);
        row["amount_msat"] = json!("any");
        server.route("listinvoices", json!({"invoices":[row]}));
        let details = provider.get_payment_status(&hash()).await.unwrap();
        assert_eq!(details.status, status);
        assert_eq!(details.amount_msat, amount);
        assert_eq!(details.direction, PaymentDirection::Incoming);
        assert_eq!(
            details.preimage,
            (state == "paid").then(|| hex::encode([42; 32]))
        );
    }
}

#[tokio::test]
async fn t3_outgoing_statuses_and_unknown_hash() {
    let (server, _dir, provider) = read_provider().await;
    server.route("listinvoices", json!({"invoices":[]}));
    for (state, status) in [
        ("complete", PaymentStatus::Settled),
        ("pending", PaymentStatus::InFlight),
        ("failed", PaymentStatus::Failed),
    ] {
        server.route("listpays", json!({"pays":[outgoing(state)]}));
        let detail = provider.get_payment_status(&hash()).await.unwrap();
        assert_eq!(detail.status, status);
        assert_eq!(detail.direction, PaymentDirection::Outgoing);
        assert_eq!(detail.amount_msat, 2000);
        assert_eq!(detail.timestamp, 1700000001);
        assert_eq!(detail.fee_msat, (state == "complete").then_some(25));
        assert_eq!(
            detail.preimage,
            (state == "complete").then(|| hex::encode([42; 32]))
        );
    }
    server.route("listpays", json!({"pays":[]}));
    assert!(matches!(
        provider.get_payment_status(&hash()).await,
        Err(LightningError::PaymentNotFound(_))
    ));
    for pair in server.calls()[1..].chunks(2) {
        assert_eq!(
            pair[0],
            ("/v1/listinvoices".into(), json!({"payment_hash":hash()}))
        );
        assert_eq!(
            pair[1],
            ("/v1/listpays".into(), json!({"payment_hash":hash()}))
        );
    }
}

#[tokio::test]
async fn malformed_settlement_and_rpc_errors_fail_closed_without_secret_echo() {
    let (server, _dir, provider) = read_provider().await;
    let mut bad = Vec::new();
    for field in [
        "payment_hash",
        "payment_preimage",
        "amount_received_msat",
        "status",
    ] {
        let mut row = incoming("paid");
        row.as_object_mut().unwrap().remove(field);
        bad.push(row);
    }
    for (field, value) in [
        ("payment_hash", json!("11".repeat(32))),
        ("payment_preimage", json!(RUNE)),
        ("status", json!("unknown")),
        ("amount_received_msat", json!(-1)),
        ("amount_received_msat", json!("oops")),
        ("amount_received_msat", json!("any")),
        ("amount_msat", json!("ANY")),
        ("amount_msat", json!("oops")),
        ("amount_msat", json!({"any":null})),
    ] {
        let mut row = incoming("paid");
        row[field] = value;
        bad.push(row);
    }
    for row in bad {
        server.route("listinvoices", json!({"invoices":[row]}));
        let err = provider.get_payment_status(&hash()).await.unwrap_err();
        assert!(!format!("{err:?}").contains(RUNE));
    }
    for (status, body) in [
        (401, RUNE.to_string()),
        (500, RUNE.into()),
        (200, "{}".into()),
        (200, "x".repeat(4 * 1024 * 1024 + 1)),
    ] {
        server
            .routes
            .lock()
            .unwrap()
            .insert("/v1/listinvoices".into(), (status, body));
        assert!(provider.get_payment_status(&hash()).await.is_err());
    }
    assert!(!server
        .calls()
        .iter()
        .any(|(path, _)| path == "/v1/listpays"));
}

#[tokio::test]
async fn creates_invoice_with_unique_labels_and_backend_expiry() {
    let (server, _dir, provider) = read_provider().await;
    server.route(
        "invoice",
        json!({"bolt11":bolt11(), "payment_hash":hash().to_uppercase(), "expires_at":1700000060}),
    );
    for _ in 0..2 {
        let invoice = provider.create_invoice(1234, "memo", 60).await.unwrap();
        assert_eq!(invoice.bolt11, bolt11());
        assert_eq!(invoice.payment_hash, hash());
        assert_eq!(invoice.created_at, 1700000000);
        assert_eq!(invoice.expiry_secs, 60);
        assert_eq!(invoice.amount_msat, 1234);
        assert_eq!(invoice.description, "memo");
    }
    let calls = server.calls();
    assert_ne!(calls[1].1["label"], calls[2].1["label"]);
    for (path, body) in &calls[1..] {
        assert_eq!(path, "/v1/invoice");
        assert_eq!(body["amount_msat"], 1234);
        assert_eq!(body["description"], "memo");
        assert_eq!(body["expiry"], 60);
        let label = body["label"]
            .as_str()
            .unwrap()
            .strip_prefix("bitsov:")
            .unwrap();
        assert_eq!(hex::decode(label).unwrap().len(), 16);
    }
    server.route(
        "invoice",
        json!({"bolt11":bolt11(), "payment_hash":hash(),"expires_at":1}),
    );
    assert!(provider.create_invoice(1234, "memo", 60).await.is_err());
}

#[tokio::test]
async fn create_invoice_rejects_mismatched_bolt11_payment_hash() {
    let (server, _dir, provider) = read_provider().await;
    server.route(
        "invoice",
        json!({"bolt11":bolt11(), "payment_hash":"11".repeat(32), "expires_at":1700000060}),
    );
    assert!(provider.create_invoice(1234, "memo", 60).await.is_err());
}

#[tokio::test]
async fn create_invoice_rejects_invalid_bolt11_without_secret_echo() {
    let (server, _dir, provider) = read_provider().await;
    for invalid in ["", "lnbcrt-test", RUNE] {
        server.route(
            "invoice",
            json!({"bolt11":invalid, "payment_hash":hash(), "expires_at":1700000060}),
        );
        let err = provider.create_invoice(1234, "memo", 60).await.unwrap_err();
        assert!(!format!("{err:?}").contains(RUNE));
    }
}

fn channel(state: &str, connected: bool) -> Value {
    json!({"channel_id":"ab".repeat(32),"peer_id":PUBKEY,"state":state,"peer_connected":connected,
        "short_channel_id":"1x2x3", "total_msat":10000,"to_us_msat":6000,"spendable_msat":4500})
}
#[tokio::test]
async fn balances_and_channels_preserve_units_and_unknown_categories() {
    let (server, _dir, provider) = read_provider().await;
    server.route("listpeerchannels",json!({"channels":[channel("CHANNELD_NORMAL",true),channel("CHANNELD_NORMAL",false),channel("ONCHAIN",true),
        {"peer_id":PUBKEY,"state":"OPENINGD","peer_connected":true}]}));
    assert_eq!(provider.get_balance_msat().await.unwrap(), 9000);
    let channels = provider.list_channels().await.unwrap();
    assert_eq!(channels.len(), 3); // Unfunded negotiations have no channel ID/capacity yet.
    assert_eq!(channels[0].channel_id, "ab".repeat(32));
    assert_eq!(channels[0].peer_pubkey, PUBKEY);
    assert_eq!(channels[0].short_channel_id.as_deref(), Some("1x2x3"));
    assert_eq!(
        (
            channels[0].capacity_msat,
            channels[0].local_balance_msat,
            channels[0].remote_balance_msat
        ),
        (10000, 6000, 4000)
    );
    assert!(channels[0].active);
    assert!(!channels[1].active);
    assert!(!channels[2].active);
    server.route(
        "listfunds",
        json!({"outputs":[
        {"amount_msat":12000,"status":"confirmed","reserved":false},
        {"amount_msat":3000,"status":"confirmed","reserved":true},
        {"amount_msat":4000,"status":"unconfirmed","reserved":false},
        {"amount_msat":5000,"status":"immature","reserved":false},
        {"amount_msat":6000,"status":"spent","reserved":false}]}),
    );
    let balance = provider.get_balance_breakdown().await.unwrap();
    assert_eq!(balance.onchain_total_sats, Some(24));
    // listfunds does not expose CLN's emergency/anchor reserve.
    assert_eq!(balance.onchain_spendable_sats, None);
    assert_eq!(balance.lightning_spendable_sats, Some(9));
    assert_eq!(balance.anchor_reserve_sats, None);
    assert_eq!(balance.closing_sats, None);
    assert_eq!(balance.contested_sats, None);
    server.route("listfunds", json!({}));
    assert!(provider.get_balance_breakdown().await.is_err());
    server.route(
        "listpeerchannels",
        json!({"channels":[{"state":"CHANNELD_NORMAL"}]}),
    );
    assert!(provider.get_balance_msat().await.is_err());
}

#[tokio::test]
async fn history_pages_through_short_mpp_pages_merges_newest_and_refreshes_fees() {
    let (server, _dir, provider) = read_provider().await;
    assert!(provider.list_payments(0).await.unwrap().is_empty());
    assert_eq!(server.calls().len(), 1);
    let mut newer = incoming("paid");
    newer["created_index"] = json!(5);
    newer["paid_at"] = json!(1700000002);
    newer["payment_hash"] = json!("22".repeat(32));
    server.route(
        "listinvoices?start=0",
        json!({"invoices":[incoming("paid")]}),
    );
    server.route("listinvoices?start=2", json!({"invoices":[newer]}));
    server.route("listinvoices?start=6", json!({"invoices":[]}));
    let mut partial = outgoing("complete");
    partial["amount_sent_msat"] = json!(1000);
    server.route("listpays?start=0", json!({"pays":[partial]}));
    server.route("listpays?start=2", json!({"pays":[]}));
    server.route("listpays", json!({"pays":[outgoing("complete")]}));
    let payments = provider.list_payments(2).await.unwrap();
    assert_eq!(payments.len(), 2);
    assert_eq!(payments[0].payment_hash, "22".repeat(32));
    assert_eq!(payments[0].direction, PaymentDirection::Incoming);
    assert_eq!(payments[1].direction, PaymentDirection::Outgoing);
    assert_eq!(payments[1].fee_msat, Some(25));
    for (_, body) in server
        .calls()
        .into_iter()
        .skip(1)
        .filter(|(_, b)| b.get("start").is_some())
    {
        assert_eq!(body["index"], "created");
        assert!(body["limit"].as_u64().unwrap() > 0);
    }
}

struct Price;
#[async_trait::async_trait]
impl konsensus_core::traits::pricing::PricingEngine for Price {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get_price_msat(
        &self,
        _kind: u16,
    ) -> Result<u64, konsensus_core::traits::pricing::PricingError> {
        Ok(2000)
    }
    async fn get_category_price_msat(
        &self,
        _category: konsensus_core::kind::KindCategory,
    ) -> Result<u64, konsensus_core::traits::pricing::PricingError> {
        Ok(2000)
    }
}
#[tokio::test]
async fn t6_keysend_gate_accepts_real_settlement_rejects_forgery_and_underpayment() {
    use konsensus_core::{
        gate::{GateConfig, GateRejection, PaymentGate},
        identity::NodeIdentity,
        kind::KIND_CHAT,
        types::{NodeId, PaymentProof, Recipient, Signature},
        UkmEnvelopeBuilder,
    };
    let (server, _dir, provider) = read_provider().await;
    let identity=NodeIdentity::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "").unwrap();
    let recipient = NodeId::from_bytes([2; 32]);
    let gate = PaymentGate::with_config(GateConfig {
        verify_lightning_settlement: true,
        ..Default::default()
    });
    let envelope = |preimage: [u8; 32], amount| {
        let mut envelope = UkmEnvelopeBuilder::new(
            KIND_CHAT,
            *identity.node_id(),
            Recipient::Node(recipient),
            b"encrypted".to_vec(),
            PaymentProof::new(
                hex::decode(hash()).unwrap().try_into().unwrap(),
                preimage,
                amount,
            ),
        )
        .build();
        envelope.signature = Signature::from_ed25519(&identity.sign(&envelope.signable_bytes()));
        envelope
    };
    let mut row = incoming("paid");
    row["amount_msat"] = json!("any");
    server.route("listinvoices", json!({"invoices":[row.clone()]}));
    let valid = envelope([42; 32], 2000);
    assert!(gate
        .validate_paid_envelope(&valid, &Price, None, Some(&provider), 0.0, Some(&recipient))
        .await
        .is_ok());
    assert!(gate
        .validate_paid_envelope(
            &envelope([43; 32], 2000),
            &Price,
            None,
            Some(&provider),
            0.0,
            Some(&recipient)
        )
        .await
        .is_err());
    assert!(matches!(
        gate.validate_paid_envelope(
            &envelope([42; 32], 1000),
            &Price,
            None,
            Some(&provider),
            0.0,
            Some(&recipient)
        )
        .await,
        Err(GateRejection::InsufficientPayment { .. })
    ));
    row["payment_preimage"] = json!(hex::encode([43; 32]));
    server.route("listinvoices", json!({"invoices":[row.clone()]}));
    assert!(matches!(
        gate.validate_paid_envelope(&valid, &Price, None, Some(&provider), 0.0, Some(&recipient))
            .await,
        Err(GateRejection::PaymentSettlementMismatch(_))
    ));
    row["payment_preimage"] = json!(hex::encode([42; 32]));
    row["amount_received_msat"] = json!(1500);
    server.route("listinvoices", json!({"invoices":[row]}));
    assert!(matches!(
        gate.validate_paid_envelope(&valid, &Price, None, Some(&provider), 0.0, Some(&recipient))
            .await,
        Err(GateRejection::PaymentSettlementMismatch(_))
    ));
    server.route("listinvoices", json!({"invoices":[]}));
    server.route("listpays", json!({"pays":[outgoing("complete")]}));
    assert!(matches!(
        gate.validate_paid_envelope(&valid, &Price, None, Some(&provider), 0.0, Some(&recipient))
            .await,
        Err(GateRejection::PaymentSettlementMismatch(_))
    ));
}

#[tokio::test]
async fn gate_refuses_unpaid_and_expired_invoices() {
    use konsensus_core::{
        gate::{GateConfig, GateRejection, PaymentGate},
        identity::NodeIdentity,
        kind::KIND_CHAT,
        types::{NodeId, PaymentProof, Recipient, Signature},
        UkmEnvelopeBuilder,
    };
    let (server, _dir, provider) = read_provider().await;
    let identity = NodeIdentity::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "").unwrap();
    let recipient = NodeId::from_bytes([2; 32]);
    let gate = PaymentGate::with_config(GateConfig {
        verify_lightning_settlement: true,
        ..Default::default()
    });
    let mut envelope = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        *identity.node_id(),
        Recipient::Node(recipient),
        b"encrypted".to_vec(),
        PaymentProof::new(
            hex::decode(hash()).unwrap().try_into().unwrap(),
            [42; 32],
            2000,
        ),
    )
    .build();
    envelope.signature = Signature::from_ed25519(&identity.sign(&envelope.signable_bytes()));
    for state in ["unpaid", "expired"] {
        for amount in [json!(2500), json!("any")] {
            let mut row = incoming(state);
            row["amount_msat"] = amount;
            // Even a valid preimage and sufficient received amount must not
            // override the backend's unsettled status.
            server.route("listinvoices", json!({"invoices":[row]}));
            assert!(
                matches!(
                    gate.validate_paid_envelope(
                        &envelope,
                        &Price,
                        None,
                        Some(&provider),
                        0.0,
                        Some(&recipient)
                    )
                    .await,
                    Err(GateRejection::PaymentNotSettled(_))
                ),
                "{state}"
            );
        }
    }
}

#[tokio::test]
async fn malformed_balances_cannot_become_zero_or_wrapped() {
    let (server, _dir, provider) = read_provider().await;
    for value in [
        json!(null),
        json!(-1),
        json!(1.5),
        json!("1sat"),
        json!("18446744073709551616msat"),
    ] {
        let mut row = channel("CHANNELD_NORMAL", true);
        row["spendable_msat"] = value;
        server.route("listpeerchannels", json!({"channels":[row]}));
        assert!(provider.get_balance_msat().await.is_err());
    }
    let mut row = channel("CHANNELD_NORMAL", true);
    row["spendable_msat"] = json!(u64::MAX);
    server.route(
        "listpeerchannels",
        json!({"channels":[row,channel("CHANNELD_NORMAL",true)]}),
    );
    assert!(provider.get_balance_msat().await.is_err());
    let mut row = channel("CHANNELD_NORMAL", true);
    row["spendable_msat"] = json!("4500msat");
    server.route("listpeerchannels", json!({"channels":[row]}));
    assert_eq!(provider.get_balance_msat().await.unwrap(), 4500);
    server.route(
        "listfunds",
        json!({"outputs":[
        {"amount_msat":u64::MAX,"status":"confirmed","reserved":false},
        {"amount_msat":1,"status":"confirmed","reserved":false}]}),
    );
    assert!(provider.get_balance_breakdown().await.is_err());
    let mut row = channel("CHANNELD_NORMAL", true);
    row["to_us_msat"] = json!(10001);
    server.route("listpeerchannels", json!({"channels":[row]}));
    assert!(provider.list_channels().await.is_err());
    server.route("listpeerchannels", json!({"channels":[]}));
    server.route("listfunds", json!({"outputs":[]}));
    assert_eq!(provider.get_balance_msat().await.unwrap(), 0);
    assert_eq!(
        provider
            .get_balance_breakdown()
            .await
            .unwrap()
            .onchain_total_sats,
        Some(0)
    );
}

#[tokio::test]
async fn malformed_outgoing_records_and_stalled_history_are_errors() {
    let (server, _dir, provider) = read_provider().await;
    server.route("listinvoices", json!({"invoices":[]}));
    for (field, value) in [
        ("payment_hash", json!("22".repeat(32))),
        ("preimage", json!(null)),
        ("status", json!("unknown")),
        ("amount_sent_msat", json!(1999)),
    ] {
        let mut row = outgoing("complete");
        row[field] = value;
        server.route("listpays", json!({"pays":[row]}));
        assert!(provider.get_payment_status(&hash()).await.is_err());
    }
    server.route(
        "listinvoices?start=0",
        json!({"invoices":[incoming("paid")]}),
    );
    server.route(
        "listinvoices?start=2",
        json!({"invoices":[incoming("paid")]}),
    );
    assert!(provider.list_payments(1).await.is_err());
}

#[tokio::test]
async fn history_ranks_full_multipart_records_before_truncating() {
    let (server, _dir, provider) = read_provider().await;
    server.route(
        "listinvoices?start=0",
        json!({"invoices":[incoming("paid")]}),
    );
    server.route("listinvoices?start=2", json!({"invoices":[]}));
    let mut partial = outgoing("complete");
    partial["created_at"] = json!(1700000001);
    server.route("listpays?start=0", json!({"pays":[partial]}));
    server.route("listpays?start=2", json!({"pays":[]}));
    let mut full = outgoing("complete");
    full["created_at"] = json!(1699999999);
    server.route("listpays", json!({"pays":[full]}));
    let payments = provider.list_payments(1).await.unwrap();
    assert_eq!(payments.len(), 1);
    assert_eq!(payments[0].direction, PaymentDirection::Incoming);
}

#[tokio::test]
async fn outgoing_external_retries_prioritize_complete_then_pending_then_latest_failure() {
    let (server, _dir, provider) = read_provider().await;
    server.route("listinvoices", json!({"invoices":[]}));
    let mut failed = outgoing("failed");
    failed["created_at"] = json!(1700000002);
    server.route(
        "listpays",
        json!({"pays":[failed.clone(),outgoing("complete"),outgoing("pending")]}),
    );
    assert_eq!(
        provider.get_payment_status(&hash()).await.unwrap().status,
        PaymentStatus::Settled
    );
    server.route(
        "listpays",
        json!({"pays":[failed.clone(),outgoing("pending")]}),
    );
    assert_eq!(
        provider.get_payment_status(&hash()).await.unwrap().status,
        PaymentStatus::InFlight
    );
    server.route("listpays", json!({"pays":[outgoing("failed"),failed]}));
    assert_eq!(
        provider
            .get_payment_status(&hash())
            .await
            .unwrap()
            .timestamp,
        1700000002
    );
}

#[tokio::test]
async fn valid_invoice_history_page_can_exceed_getinfo_size_limit() {
    let (server, _dir, provider) = read_provider().await;
    let mock = konsensus_lightning::MockLightningProvider::new();
    let mut rows = Vec::new();
    for index in 1..=100 {
        let invoice = mock
            .create_invoice(1000, &"memo ".repeat(40), 3600)
            .await
            .unwrap();
        rows.push(
            json!({"label":format!("invoice-{index}"), "payment_hash":invoice.payment_hash,
            "bolt11":invoice.bolt11, "description":invoice.description, "amount_msat":1000,
            "status":"unpaid", "expires_at":invoice.created_at+3600, "created_index":index}),
        );
    }
    let body = json!({"invoices":rows});
    assert!(body.to_string().len() > 65_536);
    server.route("listinvoices?start=0", body);
    server.route("listinvoices?start=101", json!({"invoices":[]}));
    server.route("listpays?start=0", json!({"pays":[]}));
    assert_eq!(provider.list_payments(1).await.unwrap().len(), 1);
}

#[tokio::test]
async fn unknown_settled_outgoing_amount_is_not_reported_as_zero() {
    let (server, _dir, provider) = read_provider().await;
    server.route("listinvoices", json!({"invoices":[]}));
    let mut row = outgoing("complete");
    row.as_object_mut().unwrap().remove("amount_msat");
    server.route("listpays", json!({"pays":[row]}));
    assert!(provider.get_payment_status(&hash()).await.is_err());
}
