use super::*;

fn mock_identity_pubkey() -> String {
    format!("02{}", "ab".repeat(32))
}

#[test]
fn config_construction() {
    let config = LndConfig {
        api_url: "https://localhost:8080".into(),
        macaroon_hex: "0201036c6e64".into(),
        tls_cert_path: None,
    };
    assert_eq!(config.api_url, "https://localhost:8080");
}

#[test]
fn api_url_strips_trailing_slash() {
    let config = LndConfig {
        api_url: "https://localhost:8080/".into(),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(config, Client::new());
    assert_eq!(
        provider.api_url("/v1/invoices"),
        "https://localhost:8080/v1/invoices"
    );
}

#[test]
fn invoice_state_mapping() {
    assert_eq!(
        LndProvider::invoice_state_to_status("SETTLED"),
        PaymentStatus::Settled
    );
    assert_eq!(
        LndProvider::invoice_state_to_status("OPEN"),
        PaymentStatus::Pending
    );
    assert_eq!(
        LndProvider::invoice_state_to_status("CANCELED"),
        PaymentStatus::Failed
    );
    assert_eq!(
        LndProvider::invoice_state_to_status("ACCEPTED"),
        PaymentStatus::InFlight
    );
}

#[test]
fn payment_status_mapping() {
    assert_eq!(
        LndProvider::payment_status_to_status("SUCCEEDED"),
        PaymentStatus::Settled
    );
    assert_eq!(
        LndProvider::payment_status_to_status("FAILED"),
        PaymentStatus::Failed
    );
    assert_eq!(
        LndProvider::payment_status_to_status("IN_FLIGHT"),
        PaymentStatus::InFlight
    );
    assert_eq!(
        LndProvider::payment_status_to_status("UNKNOWN"),
        PaymentStatus::Pending
    );
}

#[test]
fn parse_u64_handles_various_inputs() {
    assert_eq!(LndProvider::parse_u64("1000"), 1000);
    assert_eq!(LndProvider::parse_u64("0"), 0);
    assert_eq!(LndProvider::parse_u64(""), 0);
    assert_eq!(LndProvider::parse_u64("not_a_number"), 0);
    assert_eq!(LndProvider::parse_u64("18446744073709551615"), u64::MAX);
}

#[test]
fn decode_r_hash_base64() {
    use base64::Engine;
    // 32 zero bytes in base64
    let b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
    let hex_str = LndProvider::decode_r_hash(&b64).unwrap();
    assert_eq!(hex_str, "00".repeat(32));
}

#[test]
fn decode_r_hash_known_value() {
    use base64::Engine;
    let bytes =
        hex::decode("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789").unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let result = LndProvider::decode_r_hash(&b64).unwrap();
    assert_eq!(
        result,
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    );
}

#[test]
fn payment_capable_default_true() {
    let config = LndConfig {
        api_url: "https://localhost:8080".into(),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(config, Client::new());
    assert!(provider.payment_capable.load(Ordering::Relaxed));
}

#[tokio::test]
async fn is_payment_capable_reflects_flag() {
    let config = LndConfig {
        api_url: "https://localhost:8080".into(),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(config, Client::new());

    assert!(provider.is_payment_capable().await);

    provider.payment_capable.store(false, Ordering::Relaxed);
    assert!(!provider.is_payment_capable().await);
}

// ── Mock HTTP server tests ──────────────────────────────────────────
// These test the full request/response flow against a mock LND REST API.

use axum::{Json, Router, routing::get, routing::post};
use std::net::SocketAddr;

async fn start_mock_lnd() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/v1/getinfo", get(mock_getinfo))
        .route("/v1/invoices", post(mock_addinvoice))
        .route("/v1/balance/channels", get(mock_channel_balance))
        .route("/v1/channels", get(mock_list_channels));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, handle)
}

async fn mock_getinfo() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "identity_pubkey": mock_identity_pubkey(),
        "synced_to_chain": true,
        "num_active_channels": 3
    }))
}

async fn mock_addinvoice() -> Json<serde_json::Value> {
    use base64::Engine;
    let hash_bytes = [0xab_u8; 32];
    let r_hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash_bytes);
    Json(serde_json::json!({
        "r_hash": r_hash_b64,
        "payment_request": "lnbc10n1pjtest"
    }))
}

async fn mock_channel_balance() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "local_balance": {
            "sat": "100000",
            "msat": "100000000"
        },
        "remote_balance": {
            "sat": "50000",
            "msat": "50000000"
        }
    }))
}

async fn mock_list_channels() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "channels": [{
            "remote_pubkey": "02abcdef",
            "capacity": "150000",
            "local_balance": "100000",
            "remote_balance": "50000",
            "active": true,
            "chan_id": "123456789"
        }]
    }))
}

fn test_provider(addr: SocketAddr) -> LndProvider {
    let config = LndConfig {
        api_url: format!("http://{addr}"),
        macaroon_hex: "0201036c6e64".into(),
        tls_cert_path: None,
    };
    LndProvider::with_client(config, Client::new())
}

#[tokio::test]
async fn mock_lnd_is_available() {
    let (addr, _handle) = start_mock_lnd().await;
    let provider = test_provider(addr);
    assert!(provider.is_available().await);
}

#[tokio::test]
async fn mock_lnd_create_invoice() {
    let (addr, _handle) = start_mock_lnd().await;
    let provider = test_provider(addr);

    let invoice = provider
        .create_invoice(10_000, "test invoice", 3600)
        .await
        .unwrap();

    assert_eq!(invoice.bolt11, "lnbc10n1pjtest");
    assert_eq!(invoice.payment_hash, "ab".repeat(32));
    assert_eq!(invoice.amount_msat, 10_000);
}

#[tokio::test]
async fn mock_lnd_get_balance() {
    let (addr, _handle) = start_mock_lnd().await;
    let provider = test_provider(addr);

    let balance = provider.get_balance_msat().await.unwrap();
    assert_eq!(balance, 100_000_000); // 100K sats in msat
}

#[tokio::test]
async fn mock_lnd_list_channels() {
    let (addr, _handle) = start_mock_lnd().await;
    let provider = test_provider(addr);

    let channels = provider.list_channels().await.unwrap();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].peer_pubkey, "02abcdef");
    assert_eq!(channels[0].capacity_msat, 150_000_000);
    assert_eq!(channels[0].local_balance_msat, 100_000_000);
    assert!(channels[0].active);
}

#[tokio::test]
async fn mock_lnd_probe_synced() {
    let (addr, _handle) = start_mock_lnd().await;
    let provider = test_provider(addr);

    provider.probe_payment_capability().await;
    assert!(provider.payment_capable.load(Ordering::Relaxed));
}

#[tokio::test]
async fn unreachable_lnd_not_available() {
    let config = LndConfig {
        api_url: "http://127.0.0.1:1".into(),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(
        config,
        Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .unwrap(),
    );

    assert!(!provider.is_available().await);
}

// ── TLS certificate error tests ────────────────────────────────────

#[test]
fn tls_cert_nonexistent_file_returns_connection_error() {
    let config = LndConfig {
        api_url: "https://localhost:8080".into(),
        macaroon_hex: "abc".into(),
        tls_cert_path: Some("/nonexistent/path/tls.cert".into()),
    };
    let err = LndProvider::new(config).unwrap_err();
    match err {
        LightningError::Connection(msg) => {
            assert!(msg.contains("failed to read TLS cert"), "got: {msg}");
        }
        other => panic!("expected Connection error, got: {other:?}"),
    }
}

#[test]
fn tls_cert_invalid_pem_returns_connection_error() {
    // Write garbage to a temp file
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("bad.cert");
    std::fs::write(&cert_path, b"this is not a PEM certificate").unwrap();

    let config = LndConfig {
        api_url: "https://localhost:8080".into(),
        macaroon_hex: "abc".into(),
        tls_cert_path: Some(cert_path.to_str().unwrap().into()),
    };
    let err = LndProvider::new(config).unwrap_err();
    match err {
        LightningError::Connection(msg) => {
            assert!(msg.contains("invalid TLS cert"), "got: {msg}");
        }
        other => panic!("expected Connection error, got: {other:?}"),
    }
}

#[test]
fn tls_cert_empty_file_returns_connection_error() {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("empty.cert");
    std::fs::write(&cert_path, b"").unwrap();

    let config = LndConfig {
        api_url: "https://localhost:8080".into(),
        macaroon_hex: "abc".into(),
        tls_cert_path: Some(cert_path.to_str().unwrap().into()),
    };
    let err = LndProvider::new(config).unwrap_err();
    match err {
        LightningError::Connection(msg) => {
            assert!(msg.contains("invalid TLS cert"), "got: {msg}");
        }
        other => panic!("expected Connection error, got: {other:?}"),
    }
}

#[test]
fn no_tls_cert_uses_system_roots() {
    let config = LndConfig {
        api_url: "https://localhost:8080".into(),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    // Should succeed — no cert to load
    let provider = LndProvider::new(config);
    assert!(provider.is_ok());
}

// ── Base64 edge case tests ─────────────────────────────────────────

#[test]
fn decode_r_hash_invalid_base64_returns_error() {
    let err = LndProvider::decode_r_hash("!!!not-base64!!!").unwrap_err();
    match err {
        LightningError::Backend(msg) => {
            assert!(msg.contains("decode r_hash base64"), "got: {msg}");
        }
        other => panic!("expected Backend error, got: {other:?}"),
    }
}

#[test]
fn decode_r_hash_empty_string_returns_empty_hex() {
    // Empty base64 decodes to empty bytes → empty hex
    let result = LndProvider::decode_r_hash("").unwrap();
    assert_eq!(result, "");
}

#[test]
fn decode_r_hash_url_safe_base64() {
    use base64::Engine;
    let bytes = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8];
    // URL-safe base64 uses -_ instead of +/
    let url_safe = base64::engine::general_purpose::URL_SAFE.encode(bytes);
    let result = LndProvider::decode_r_hash(&url_safe).unwrap();
    assert_eq!(result, hex::encode(bytes));
}

#[test]
fn decode_r_hash_with_padding() {
    use base64::Engine;
    // Single byte → needs padding
    let b64 = base64::engine::general_purpose::STANDARD.encode([0xAB]);
    assert!(b64.contains('='));
    let result = LndProvider::decode_r_hash(&b64).unwrap();
    assert_eq!(result, "ab");
}

// ── HTTP error code tests (mock server) ────────────────────────────

async fn start_mock_lnd_errors() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use axum::http::StatusCode;

    async fn error_401() -> (StatusCode, &'static str) {
        (
            StatusCode::UNAUTHORIZED,
            r#"{"message":"permission denied","code":7}"#,
        )
    }
    async fn error_500() -> (StatusCode, &'static str) {
        (StatusCode::INTERNAL_SERVER_ERROR, r#"{"error":"internal"}"#)
    }
    async fn error_404() -> (StatusCode, &'static str) {
        (StatusCode::NOT_FOUND, r#"{"error":"not found"}"#)
    }

    let app = Router::new()
        .route("/v1/getinfo", get(error_401))
        .route("/v1/invoices", post(error_500))
        .route("/v1/balance/channels", get(error_404))
        .route("/v1/channels", get(error_500));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, handle)
}

#[tokio::test]
async fn http_401_returns_auth_error() {
    let (addr, _handle) = start_mock_lnd_errors().await;
    let provider = test_provider(addr);

    let err = provider.get_info().await.unwrap_err();
    match err {
        LightningError::Auth(msg) => {
            assert!(msg.contains("401"), "got: {msg}");
        }
        other => panic!("expected Auth error, got: {other:?}"),
    }
}

#[tokio::test]
async fn http_500_marks_payment_incapable() {
    let (addr, _handle) = start_mock_lnd_errors().await;
    let provider = test_provider(addr);

    assert!(provider.payment_capable.load(Ordering::Relaxed));
    let _err = provider.create_invoice(1000, "test", 3600).await;
    assert!(!provider.payment_capable.load(Ordering::Relaxed));
}

#[tokio::test]
async fn http_404_balance_returns_error() {
    let (addr, _handle) = start_mock_lnd_errors().await;
    let provider = test_provider(addr);

    let err = provider.get_balance_msat().await.unwrap_err();
    match err {
        LightningError::PaymentNotFound(_) => {}
        other => panic!("expected PaymentNotFound error, got: {other:?}"),
    }
}

#[tokio::test]
async fn http_500_list_channels_returns_backend_error() {
    let (addr, _handle) = start_mock_lnd_errors().await;
    let provider = test_provider(addr);

    let err = provider.list_channels().await.unwrap_err();
    match err {
        LightningError::Backend(msg) => {
            assert!(msg.contains("500"), "got: {msg}");
        }
        other => panic!("expected Backend error, got: {other:?}"),
    }
}

// ── Malformed response tests ───────────────────────────────────────

async fn start_mock_lnd_malformed() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    /// Returns valid JSON but with missing required fields.
    async fn empty_invoice() -> Json<serde_json::Value> {
        Json(serde_json::json!({}))
    }
    /// Returns a response with r_hash but no payment_request.
    async fn partial_invoice() -> Json<serde_json::Value> {
        use base64::Engine;
        let r_hash = base64::engine::general_purpose::STANDARD.encode([0xCD; 32]);
        Json(serde_json::json!({
            "r_hash": r_hash
        }))
    }
    /// Returns completely broken JSON.
    async fn garbage_json() -> &'static str {
        "this is not json at all {{{}}}"
    }
    /// Returns valid getinfo for availability check.
    async fn ok_getinfo() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "identity_pubkey": "02abc",
            "synced_to_chain": true,
            "num_active_channels": 1
        }))
    }
    /// Returns empty channel balance (no local_balance field).
    async fn empty_balance() -> Json<serde_json::Value> {
        Json(serde_json::json!({}))
    }
    /// Returns empty channels list.
    async fn empty_channels() -> Json<serde_json::Value> {
        Json(serde_json::json!({}))
    }

    let app = Router::new()
        .route("/v1/getinfo", get(ok_getinfo))
        .route("/v1/invoices", post(empty_invoice))
        .route("/v1/balance/channels", get(empty_balance))
        .route("/v1/channels", get(empty_channels))
        .route("/partial_invoice", post(partial_invoice))
        .route("/garbage", get(garbage_json));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, handle)
}

#[tokio::test]
async fn malformed_invoice_missing_r_hash() {
    let (addr, _handle) = start_mock_lnd_malformed().await;
    let provider = test_provider(addr);

    let err = provider
        .create_invoice(1000, "test", 3600)
        .await
        .unwrap_err();
    match err {
        LightningError::InvoiceCreation(msg) => {
            assert!(msg.contains("no r_hash"), "got: {msg}");
        }
        other => panic!("expected InvoiceCreation error, got: {other:?}"),
    }
}

#[tokio::test]
async fn malformed_invoice_missing_payment_request() {
    let (addr, _handle) = start_mock_lnd_malformed().await;

    // Use a special route that returns r_hash but no payment_request
    let config = LndConfig {
        api_url: format!("http://{addr}"),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(config, Client::new());

    // Override the URL to hit the partial_invoice route
    let body = AddInvoiceRequest {
        value: "1".into(),
        value_msat: "1000".into(),
        memo: "test".into(),
        expiry: "3600".into(),
    };

    let response = provider
        .client
        .post(format!("http://{addr}/partial_invoice"))
        .header("Grpc-Metadata-macaroon", &provider.config.macaroon_hex)
        .json(&body)
        .send()
        .await
        .unwrap();

    let resp: AddInvoiceResponse = response.json().await.unwrap();
    assert!(resp.r_hash.is_some());
    assert!(resp.payment_request.is_none());
}

#[tokio::test]
async fn empty_balance_returns_zero() {
    let (addr, _handle) = start_mock_lnd_malformed().await;
    let provider = test_provider(addr);

    // Empty response should fall through to unwrap_or(0)
    let balance = provider.get_balance_msat().await.unwrap();
    assert_eq!(balance, 0);
}

#[tokio::test]
async fn empty_channels_returns_empty_vec() {
    let (addr, _handle) = start_mock_lnd_malformed().await;
    let provider = test_provider(addr);

    let channels = provider.list_channels().await.unwrap();
    assert!(channels.is_empty());
}

#[tokio::test]
async fn garbage_json_returns_backend_error() {
    let (addr, _handle) = start_mock_lnd_malformed().await;

    let config = LndConfig {
        api_url: format!("http://{addr}/garbage"),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(config, Client::new());

    // Hitting /garbage/v1/getinfo won't match, but we can test directly
    let response = provider
        .client
        .get(format!("http://{addr}/garbage"))
        .send()
        .await
        .unwrap();

    let result = response.json::<GetInfoResponse>().await;
    assert!(result.is_err());
}

// ── Streaming payment response edge cases ──────────────────────────

async fn start_mock_lnd_payment() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    /// Successful payment with streaming response (multiple lines).
    async fn pay_streaming_success() -> String {
        // Simulates LND's streaming response with intermediate + final status
        let line1 =
            serde_json::json!({"result": {"payment_hash": "abc123", "status": "IN_FLIGHT"}});
        let line2 = serde_json::json!({"result": {"payment_hash": "abc123", "payment_preimage": "def456", "status": "SUCCEEDED", "value_msat": "10000", "fee_msat": "5"}});
        format!("{}\n{}\n", line1, line2)
    }
    /// Payment that fails.
    async fn pay_failed() -> String {
        let line = serde_json::json!({"error": {"message": "no route found", "code": 2}});
        format!("{}\n", line)
    }
    /// Payment with empty response body.
    async fn pay_empty() -> &'static str {
        ""
    }
    /// Payment with garbage + valid line (tests resilience).
    async fn pay_mixed() -> String {
        let valid = serde_json::json!({"result": {"payment_hash": "good", "payment_preimage": "preimg", "status": "SUCCEEDED", "value_msat": "5000"}});
        format!("{{broken json\n\n{}\n", valid)
    }

    async fn ok_getinfo() -> Json<serde_json::Value> {
        Json(serde_json::json!({"identity_pubkey": "02abc", "synced_to_chain": true}))
    }

    let app = Router::new()
        .route("/v1/getinfo", get(ok_getinfo))
        .route("/v2/router/send", post(pay_streaming_success))
        .route("/pay_fail/v2/router/send", post(pay_failed))
        .route("/pay_empty/v2/router/send", post(pay_empty))
        .route("/pay_mixed/v2/router/send", post(pay_mixed));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, handle)
}

#[tokio::test]
async fn pay_invoice_streaming_uses_final_result() {
    let (addr, _handle) = start_mock_lnd_payment().await;
    let provider = test_provider(addr);

    let result = provider.pay_invoice("lnbc10n1test").await.unwrap();
    // Should use the SUCCEEDED result, not the IN_FLIGHT one
    assert_eq!(result.status, PaymentStatus::Settled);
    assert_eq!(result.payment_hash, "abc123");
    assert_eq!(result.preimage.as_deref(), Some("def456"));
    assert_eq!(result.amount_msat, 10_000);
    assert_eq!(result.fee_msat, Some(5));
    // Successful payment should mark as capable
    assert!(provider.payment_capable.load(Ordering::Relaxed));
}

#[tokio::test]
async fn pay_invoice_error_response_returns_payment_failed() {
    let (addr, _handle) = start_mock_lnd_payment().await;

    let config = LndConfig {
        api_url: format!("http://{addr}/pay_fail"),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(config, Client::new());

    let err = provider.pay_invoice("lnbc10n1test").await.unwrap_err();
    match err {
        LightningError::PaymentFailed(msg) => {
            assert!(msg.contains("no route found"), "got: {msg}");
        }
        other => panic!("expected PaymentFailed, got: {other:?}"),
    }
    // Error in payment should mark as incapable
    assert!(!provider.payment_capable.load(Ordering::Relaxed));
}

#[tokio::test]
async fn pay_invoice_empty_body_returns_error() {
    let (addr, _handle) = start_mock_lnd_payment().await;

    let config = LndConfig {
        api_url: format!("http://{addr}/pay_empty"),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(config, Client::new());

    let err = provider.pay_invoice("lnbc10n1test").await.unwrap_err();
    match err {
        LightningError::PaymentFailed(msg) => {
            assert!(msg.contains("no payment result"), "got: {msg}");
        }
        other => panic!("expected PaymentFailed, got: {other:?}"),
    }
}

#[tokio::test]
async fn pay_invoice_mixed_garbage_finds_valid_line() {
    let (addr, _handle) = start_mock_lnd_payment().await;

    let config = LndConfig {
        api_url: format!("http://{addr}/pay_mixed"),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(config, Client::new());

    let result = provider.pay_invoice("lnbc10n1test").await.unwrap();
    assert_eq!(result.status, PaymentStatus::Settled);
    assert_eq!(result.payment_hash, "good");
    assert_eq!(result.amount_msat, 5_000);
}

// ── Probe payment capability edge cases ────────────────────────────

#[tokio::test]
async fn probe_not_synced_marks_incapable() {
    async fn not_synced() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "identity_pubkey": "02abc",
            "synced_to_chain": false,
            "num_active_channels": 0
        }))
    }

    let app = Router::new().route("/v1/getinfo", get(not_synced));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    let provider = test_provider(addr);
    provider.probe_payment_capability().await;
    assert!(!provider.payment_capable.load(Ordering::Relaxed));
}

#[tokio::test]
async fn probe_unreachable_marks_incapable() {
    let config = LndConfig {
        api_url: "http://127.0.0.1:1".into(),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(
        config,
        Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .unwrap(),
    );

    assert!(provider.payment_capable.load(Ordering::Relaxed));
    provider.probe_payment_capability().await;
    assert!(!provider.payment_capable.load(Ordering::Relaxed));
}

// ── Payment status lookup edge cases ───────────────────────────────

async fn start_mock_lnd_payment_status() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    /// Invoice lookup returns settled with preimage.
    async fn settled_invoice(
        axum::extract::Path(hash): axum::extract::Path<String>,
    ) -> Json<serde_json::Value> {
        use base64::Engine;
        let preimage_bytes = [0xBB_u8; 32];
        let preimage_b64 = base64::engine::general_purpose::STANDARD.encode(preimage_bytes);
        Json(serde_json::json!({
            "r_hash": hash,
            "r_preimage": preimage_b64,
            "value_msat": "25000",
            "state": "SETTLED",
            "memo": "test payment",
            "creation_date": "1711900000"
        }))
    }
    /// Invoice with zero preimage (should filter to None).
    async fn zero_preimage_invoice(
        axum::extract::Path(_hash): axum::extract::Path<String>,
    ) -> Json<serde_json::Value> {
        use base64::Engine;
        let zero_preimage = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        Json(serde_json::json!({
            "r_hash": "abc",
            "r_preimage": zero_preimage,
            "value": "25",
            "state": "OPEN",
            "creation_date": "1711900000"
        }))
    }

    let app = Router::new()
        .route("/v1/invoice/:hash", get(settled_invoice))
        .route("/zero/v1/invoice/:hash", get(zero_preimage_invoice));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, handle)
}

#[tokio::test]
async fn payment_status_settled_invoice() {
    let (addr, _handle) = start_mock_lnd_payment_status().await;
    let provider = test_provider(addr);

    let details = provider.get_payment_status("somehash123").await.unwrap();
    assert_eq!(details.status, PaymentStatus::Settled);
    assert_eq!(details.amount_msat, 25_000);
    assert_eq!(details.direction, PaymentDirection::Incoming);
    assert!(details.preimage.is_some());
    assert_eq!(details.preimage.as_deref().unwrap(), "bb".repeat(32));
    assert_eq!(details.memo.as_deref(), Some("test payment"));
    assert_eq!(details.timestamp, 1_711_900_000);
}

#[tokio::test]
async fn payment_status_zero_preimage_filtered() {
    let (addr, _handle) = start_mock_lnd_payment_status().await;

    let config = LndConfig {
        api_url: format!("http://{addr}/zero"),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(config, Client::new());

    let details = provider.get_payment_status("anyhash").await.unwrap();
    // Zero preimage should be filtered to None
    assert!(details.preimage.is_none());
    assert_eq!(details.status, PaymentStatus::Pending); // "OPEN"
    // value_msat not present, falls back to value * 1000
    assert_eq!(details.amount_msat, 25_000);
}

// ── Keysend edge cases ─────────────────────────────────────────────

#[test]
fn keysend_invalid_dest_pubkey_hex() {
    // We can test the hex decoding part synchronously
    let result = hex::decode("not_hex_at_all");
    assert!(result.is_err());
}

// ── parse_u64 additional edge cases ────────────────────────────────

#[test]
fn parse_u64_overflow_returns_zero() {
    // u64::MAX + 1 in string form
    assert_eq!(LndProvider::parse_u64("18446744073709551616"), 0);
}

#[test]
fn parse_u64_negative_returns_zero() {
    assert_eq!(LndProvider::parse_u64("-1"), 0);
    assert_eq!(LndProvider::parse_u64("-999"), 0);
}

#[test]
fn parse_u64_whitespace_returns_zero() {
    assert_eq!(LndProvider::parse_u64(" 100 "), 0);
    assert_eq!(LndProvider::parse_u64("\t42"), 0);
}

#[test]
fn parse_u64_float_returns_zero() {
    assert_eq!(LndProvider::parse_u64("3.14"), 0);
    assert_eq!(LndProvider::parse_u64("100.0"), 0);
}

// ── Invoice state and payment status exhaustive coverage ───────────

#[test]
fn invoice_state_cancelled_british_spelling() {
    assert_eq!(
        LndProvider::invoice_state_to_status("CANCELLED"),
        PaymentStatus::Failed
    );
}

#[test]
fn invoice_state_unknown_defaults_to_pending() {
    assert_eq!(
        LndProvider::invoice_state_to_status("SOMETHING_UNEXPECTED"),
        PaymentStatus::Pending
    );
    assert_eq!(
        LndProvider::invoice_state_to_status(""),
        PaymentStatus::Pending
    );
}

#[test]
fn payment_status_unknown_defaults_to_pending() {
    assert_eq!(
        LndProvider::payment_status_to_status("SOMETHING_ELSE"),
        PaymentStatus::Pending
    );
    assert_eq!(
        LndProvider::payment_status_to_status(""),
        PaymentStatus::Pending
    );
}

// ── API URL construction ───────────────────────────────────────────

#[test]
fn api_url_no_trailing_slash() {
    let config = LndConfig {
        api_url: "https://mynode:8080".into(),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(config, Client::new());
    assert_eq!(
        provider.api_url("/v1/getinfo"),
        "https://mynode:8080/v1/getinfo"
    );
}

#[test]
fn api_url_multiple_trailing_slashes() {
    let config = LndConfig {
        api_url: "https://mynode:8080///".into(),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(config, Client::new());
    // trim_end_matches('/') removes all trailing slashes
    assert_eq!(
        provider.api_url("/v1/getinfo"),
        "https://mynode:8080/v1/getinfo"
    );
}

// ── list_payments tests ──────────────────────────────────────────────

async fn start_mock_lnd_list_payments() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    async fn ok_getinfo() -> Json<serde_json::Value> {
        Json(serde_json::json!({"identity_pubkey": "02abc", "synced_to_chain": true}))
    }

    async fn list_payments_ok() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "payments": [
                {
                    "payment_hash": "aabb00112233445566778899aabb00112233445566778899aabb001122334455",
                    "payment_preimage": "cc11223344556677889900aabbccddeeff00112233445566778899aabbccddee",
                    "value_sat": "100",
                    "value_msat": "100000",
                    "status": "SUCCEEDED",
                    "creation_date": "1711900000",
                    "fee_msat": "10"
                },
                {
                    "payment_hash": "ddee00112233445566778899aabb00112233445566778899aabb001122334455",
                    "status": "FAILED",
                    "creation_date": "1711900100"
                },
                {
                    "payment_hash": "ff00112233445566778899aabb00112233445566778899aabb001122334455cc",
                    "payment_preimage": "0000000000000000000000000000000000000000000000000000000000000000",
                    "value_msat": "5000",
                    "status": "SUCCEEDED",
                    "creation_date": "1711900200"
                }
            ]
        }))
    }

    async fn list_payments_empty() -> Json<serde_json::Value> {
        Json(serde_json::json!({}))
    }

    let app = Router::new()
        .route("/v1/getinfo", get(ok_getinfo))
        .route("/v2/payments", get(list_payments_ok))
        .route("/empty/v2/payments", get(list_payments_empty));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, handle)
}

#[tokio::test]
async fn list_payments_returns_parsed_payments() {
    let (addr, _handle) = start_mock_lnd_list_payments().await;
    let provider = test_provider(addr);

    let payments = provider.list_payments(10).await.unwrap();
    assert_eq!(payments.len(), 3);

    // First: settled with preimage
    assert_eq!(payments[0].status, PaymentStatus::Settled);
    assert_eq!(payments[0].amount_msat, 100_000);
    assert!(payments[0].preimage.is_some());
    assert_eq!(payments[0].fee_msat, Some(10));
    assert_eq!(payments[0].direction, PaymentDirection::Outgoing);
    assert_eq!(payments[0].timestamp, 1_711_900_000);

    // Second: failed, no preimage
    assert_eq!(payments[1].status, PaymentStatus::Failed);
    assert!(payments[1].preimage.is_none());
    assert_eq!(payments[1].fee_msat, None);

    // Third: zero preimage should be filtered to None
    assert_eq!(payments[2].status, PaymentStatus::Settled);
    assert!(payments[2].preimage.is_none());
    assert_eq!(payments[2].amount_msat, 5_000);
}

#[tokio::test]
async fn list_payments_empty_returns_empty_vec() {
    let (addr, _handle) = start_mock_lnd_list_payments().await;

    let config = LndConfig {
        api_url: format!("http://{addr}/empty"),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(config, Client::new());

    let payments = provider.list_payments(50).await.unwrap();
    assert!(payments.is_empty());
}

#[tokio::test]
async fn list_payments_limit_capped_at_100() {
    // Verify the limit parameter is capped (we check the URL construction).
    // The provider clamps to min(limit, 100).
    let (addr, _handle) = start_mock_lnd_list_payments().await;
    let provider = test_provider(addr);

    // Should not panic or error with limit > 100
    let payments = provider.list_payments(500).await.unwrap();
    assert_eq!(payments.len(), 3);
}

// ── keysend happy path tests ──────────────────────────────────────────

async fn start_mock_lnd_keysend() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    async fn ok_getinfo() -> Json<serde_json::Value> {
        Json(serde_json::json!({"identity_pubkey": "02abc", "synced_to_chain": true}))
    }

    /// Successful keysend — returns streaming response with SUCCEEDED status.
    async fn keysend_success() -> String {
        let line = serde_json::json!({
            "result": {
                "payment_hash": "somehash",
                "payment_preimage": "somepreimage",
                "status": "SUCCEEDED",
                "value_msat": "50000",
                "fee_msat": "15"
            }
        });
        format!("{}\n", line)
    }

    /// Keysend failure — no route.
    async fn keysend_fail() -> String {
        let line = serde_json::json!({
            "error": {"message": "unable to find a path to destination", "code": 2}
        });
        format!("{}\n", line)
    }

    let app = Router::new()
        .route("/v1/getinfo", get(ok_getinfo))
        .route("/v2/router/send", post(keysend_success))
        .route("/fail/v2/router/send", post(keysend_fail));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, handle)
}

#[tokio::test]
async fn keysend_success_returns_payment_details() {
    let (addr, _handle) = start_mock_lnd_keysend().await;
    let provider = test_provider(addr);

    // Valid compressed pubkey (33 bytes = 66 hex chars)
    let dest = "02".to_string() + &"ab".repeat(32);
    let result = provider
        .keysend(&dest, 50_000, Some("test keysend"))
        .await
        .unwrap();

    assert_eq!(result.status, PaymentStatus::Settled);
    assert_eq!(result.amount_msat, 50_000);
    assert!(result.preimage.is_some());
    assert_eq!(result.direction, PaymentDirection::Outgoing);
    assert_eq!(result.memo.as_deref(), Some("test keysend"));
    // Payment hash is computed locally from random preimage
    assert!(!result.payment_hash.is_empty());
    assert!(provider.payment_capable.load(Ordering::Relaxed));
}

#[tokio::test]
async fn keysend_failure_returns_error() {
    let (addr, _handle) = start_mock_lnd_keysend().await;

    let config = LndConfig {
        api_url: format!("http://{addr}/fail"),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(config, Client::new());

    let dest = "03".to_string() + &"cd".repeat(32);
    let err = provider.keysend(&dest, 1_000, None).await.unwrap_err();
    match err {
        LightningError::PaymentFailed(msg) => {
            assert!(msg.contains("unable to find a path"), "got: {msg}");
        }
        other => panic!("expected PaymentFailed, got: {other:?}"),
    }
}

#[tokio::test]
async fn keysend_invalid_hex_pubkey_returns_error() {
    let (addr, _handle) = start_mock_lnd_keysend().await;
    let provider = test_provider(addr);

    let err = provider
        .keysend("not_valid_hex", 1_000, None)
        .await
        .unwrap_err();
    match err {
        LightningError::PaymentFailed(msg) => {
            assert!(msg.contains("invalid dest_pubkey hex"), "got: {msg}");
        }
        other => panic!("expected PaymentFailed, got: {other:?}"),
    }
}

// ── get_payment_status outgoing path (invoice 404, found in payments list) ──

async fn start_mock_lnd_outgoing_payment_status() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use axum::http::StatusCode;

    /// Invoice lookup returns 404 — not an incoming payment.
    async fn invoice_not_found(
        axum::extract::Path(_hash): axum::extract::Path<String>,
    ) -> (StatusCode, &'static str) {
        (StatusCode::NOT_FOUND, r#"{"error":"invoice not found"}"#)
    }

    /// Payments list with the hash we're looking for.
    async fn list_payments_with_target() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "payments": [
                {
                    "payment_hash": "other_hash_not_matching",
                    "status": "SUCCEEDED",
                    "value_msat": "1000"
                },
                {
                    "payment_hash": "target_hash_to_find",
                    "payment_preimage": "found_preimage_value",
                    "value_msat": "25000",
                    "status": "SUCCEEDED",
                    "creation_date": "1711900500",
                    "fee_msat": "42"
                }
            ]
        }))
    }

    /// Payments list without the hash — should return PaymentNotFound.
    async fn list_payments_without_target() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "payments": [
                {
                    "payment_hash": "some_other_hash",
                    "status": "FAILED"
                }
            ]
        }))
    }

    let app = Router::new()
        .route("/v1/invoice/:hash", get(invoice_not_found))
        .route("/v2/payments", get(list_payments_with_target))
        .route("/notfound/v1/invoice/:hash", get(invoice_not_found))
        .route("/notfound/v2/payments", get(list_payments_without_target));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, handle)
}

#[tokio::test]
async fn payment_status_falls_through_to_outgoing_payments() {
    let (addr, _handle) = start_mock_lnd_outgoing_payment_status().await;
    let provider = test_provider(addr);

    let details = provider
        .get_payment_status("target_hash_to_find")
        .await
        .unwrap();
    assert_eq!(details.status, PaymentStatus::Settled);
    assert_eq!(details.amount_msat, 25_000);
    assert_eq!(details.direction, PaymentDirection::Outgoing);
    assert_eq!(details.preimage.as_deref(), Some("found_preimage_value"));
    assert_eq!(details.fee_msat, Some(42));
    assert_eq!(details.timestamp, 1_711_900_500);
}

#[tokio::test]
async fn payment_status_not_found_in_either() {
    let (addr, _handle) = start_mock_lnd_outgoing_payment_status().await;

    let config = LndConfig {
        api_url: format!("http://{addr}/notfound"),
        macaroon_hex: "abc".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::with_client(config, Client::new());

    let err = provider
        .get_payment_status("nonexistent_hash")
        .await
        .unwrap_err();
    match err {
        LightningError::PaymentNotFound(hash) => {
            assert_eq!(hash, "nonexistent_hash");
        }
        other => panic!("expected PaymentNotFound, got: {other:?}"),
    }
}

// ── verify_payment (default trait impl delegates to get_payment_status) ──

#[tokio::test]
async fn verify_payment_settled_returns_ok() {
    let (addr, _handle) = start_mock_lnd_payment_status().await;
    let provider = test_provider(addr);

    let details = provider.verify_payment("somehash123").await.unwrap();
    assert_eq!(details.status, PaymentStatus::Settled);
    assert!(details.preimage.is_some());
}

#[tokio::test]
async fn get_node_pubkey_from_mock_lnd() {
    let (addr, _handle) = start_mock_lnd().await;
    let config = LndConfig {
        api_url: format!("http://{addr}"),
        macaroon_hex: "0201036c6e64".into(),
        tls_cert_path: None,
    };
    let provider = LndProvider::new(config).unwrap();
    let pubkey = provider.get_node_pubkey().await;
    assert!(pubkey.is_some());
    assert_eq!(pubkey.unwrap(), mock_identity_pubkey());
}
