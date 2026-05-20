//! Tests for LNbits provider using a mock HTTP server.

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::{json, Value};
    use tokio::sync::Mutex;

    use konsensus_core::traits::lightning::{LightningProvider, PaymentDirection, PaymentStatus};

    use crate::lnbits::{LnbitsConfig, LnbitsProvider};

    /// Shared mock state for tracking calls and controlling responses.
    #[derive(Default)]
    struct MockState {
        invoices: Vec<Value>,
        payments: std::collections::HashMap<String, Value>,
        balance_msat: i64,
        last_admin_key: Option<String>,
    }

    type SharedState = Arc<Mutex<MockState>>;

    /// Build a mock LNbits server.
    fn mock_router(state: SharedState) -> Router {
        Router::new()
            .route("/api/v1/payments", get(handle_list_payments).post(handle_payment))
            .route("/api/v1/payments/:hash", get(handle_payment_check))
            .route("/api/v1/wallet", get(handle_wallet))
            .with_state(state)
    }

    /// Build a mock server that always returns 401.
    fn mock_auth_reject_router() -> Router {
        Router::new()
            .route("/api/v1/payments", get(handle_auth_reject).post(handle_auth_reject))
            .route("/api/v1/payments/:hash", get(handle_auth_reject))
            .route("/api/v1/wallet", get(handle_auth_reject))
    }

    async fn handle_auth_reject() -> impl IntoResponse {
        (StatusCode::UNAUTHORIZED, Json(json!({ "detail": "Invalid API key" })))
    }

    async fn handle_payment(
        State(state): State<SharedState>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        let mut s = state.lock().await;
        s.last_admin_key = headers
            .get("X-Api-Key")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let is_outgoing = body.get("out").and_then(|v| v.as_bool()).unwrap_or(false);

        if is_outgoing {
            // Pay invoice
            let hash = "outgoing_hash_abc123";
            s.payments.insert(
                hash.to_string(),
                json!({
                    "paid": true,
                    "settled": true,
                    "details": {
                        "payment_hash": hash,
                        "preimage": "00".repeat(32),
                        "amount": -1000,
                        "pending": false,
                        "time": 1700000000
                    }
                }),
            );
            (StatusCode::OK, Json(json!({ "payment_hash": hash })))
        } else {
            // Create invoice
            let amount = body.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
            let memo = body
                .get("memo")
                .and_then(|v| v.as_str())
                .unwrap_or("test");
            let hash = format!("inv_hash_{amount}");
            let bolt11 = format!("lnbc{amount}n1test_bolt11_string");

            s.invoices.push(json!({
                "payment_hash": &hash,
                "bolt11": &bolt11,
                "amount": amount,
                "memo": memo,
            }));

            // Register as pending payment
            s.payments.insert(
                hash.clone(),
                json!({
                    "paid": false,
                    "expired": false,
                    "details": {
                        "payment_hash": &hash,
                        "amount": (amount as i64) * 1000,
                        "pending": true,
                        "time": 1700000000
                    }
                }),
            );

            (
                StatusCode::CREATED,
                Json(json!({
                    "payment_hash": hash,
                    "bolt11": bolt11,
                })),
            )
        }
    }

    async fn handle_payment_check(
        State(state): State<SharedState>,
        Path(hash): Path<String>,
    ) -> impl IntoResponse {
        let s = state.lock().await;
        match s.payments.get(&hash) {
            Some(payment) => (StatusCode::OK, Json(payment.clone())),
            None => (StatusCode::NOT_FOUND, Json(json!({ "detail": "not found" }))),
        }
    }

    async fn handle_list_payments(State(state): State<SharedState>) -> impl IntoResponse {
        let s = state.lock().await;
        let entries: Vec<Value> = s
            .payments
            .iter()
            .map(|(hash, val)| {
                let details = val.get("details");
                json!({
                    "payment_hash": hash,
                    "amount": details.and_then(|d| d.get("amount")).and_then(|a| a.as_i64()).unwrap_or(0),
                    "fee": 0,
                    "memo": "test payment",
                    "status": if val.get("paid").and_then(|p| p.as_bool()).unwrap_or(false) { "success" } else { "pending" },
                    "preimage": details.and_then(|d| d.get("preimage")).and_then(|p| p.as_str()).unwrap_or(""),
                    "time": 1700000000.0_f64,
                })
            })
            .collect();
        Json(json!(entries))
    }

    async fn handle_wallet(State(state): State<SharedState>) -> impl IntoResponse {
        let s = state.lock().await;
        Json(json!({
            "balance_msat": s.balance_msat,
            "name": "test-wallet",
        }))
    }

    /// Start the mock server and return its address.
    async fn start_mock_server(state: SharedState) -> SocketAddr {
        let router = mock_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        addr
    }

    /// Start the auth-rejecting mock server and return its address.
    async fn start_mock_auth_reject_server() -> SocketAddr {
        let router = mock_auth_reject_router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        addr
    }

    fn make_provider(addr: SocketAddr) -> LnbitsProvider {
        let config = LnbitsConfig {
            api_url: format!("http://{addr}"),
            admin_key: "test-admin-key-123".to_string(),
        };
        LnbitsProvider::new(config).unwrap()
    }

    #[tokio::test]
    async fn create_invoice_success() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let addr = start_mock_server(state.clone()).await;
        let provider = make_provider(addr);

        let invoice = provider
            .create_invoice(10_000, "test payment", 3600)
            .await
            .unwrap();

        assert_eq!(invoice.amount_msat, 10_000);
        assert_eq!(invoice.description, "test payment");
        assert_eq!(invoice.expiry_secs, 3600);
        assert!(!invoice.payment_hash.is_empty());
        assert!(invoice.bolt11.starts_with("lnbc"));

        // Verify the admin key was sent
        let s = state.lock().await;
        assert_eq!(s.last_admin_key.as_deref(), Some("test-admin-key-123"));
        assert_eq!(s.invoices.len(), 1);
    }

    #[tokio::test]
    async fn create_invoice_rejects_zero_amount() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let result = provider.create_invoice(500, "too small", 3600).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn pay_invoice_success() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let details = provider
            .pay_invoice("lnbc10n1test_bolt11")
            .await
            .unwrap();

        assert_eq!(details.payment_hash, "outgoing_hash_abc123");
        assert_eq!(details.status, PaymentStatus::InFlight);
    }

    #[tokio::test]
    async fn get_payment_status_pending() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        // Create an invoice first (registers as pending)
        let invoice = provider.create_invoice(5_000, "test", 3600).await.unwrap();

        let details = provider
            .get_payment_status(&invoice.payment_hash)
            .await
            .unwrap();

        assert_eq!(details.status, PaymentStatus::Pending);
        assert!(details.preimage.is_none());
    }

    #[tokio::test]
    async fn get_payment_status_settled() {
        let state = Arc::new(Mutex::new(MockState {
            balance_msat: 0,
            ..Default::default()
        }));

        // Pre-populate a settled payment
        {
            let mut s = state.lock().await;
            s.payments.insert(
                "settled_hash".to_string(),
                json!({
                    "paid": true,
                    "settled": true,
                    "details": {
                        "payment_hash": "settled_hash",
                        "preimage": "aa".repeat(32),
                        "amount": 5000,
                        "pending": false,
                        "time": 1700000000
                    }
                }),
            );
        }

        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let details = provider
            .get_payment_status("settled_hash")
            .await
            .unwrap();

        assert_eq!(details.status, PaymentStatus::Settled);
        assert!(details.preimage.is_some());
    }

    #[tokio::test]
    async fn get_payment_status_not_found() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let result = provider.get_payment_status("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn verify_payment_settled() {
        let state = Arc::new(Mutex::new(MockState::default()));
        {
            let mut s = state.lock().await;
            s.payments.insert(
                "verified_hash".to_string(),
                json!({
                    "paid": true,
                    "details": {
                        "payment_hash": "verified_hash",
                        "preimage": "bb".repeat(32),
                        "amount": 10000,
                        "time": 1700000000
                    }
                }),
            );
        }

        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        // verify_payment is a default method on the trait
        let details = provider.verify_payment("verified_hash").await.unwrap();
        assert_eq!(details.status, PaymentStatus::Settled);
        assert!(details.preimage.is_some());
    }

    #[tokio::test]
    async fn verify_payment_rejects_unsettled() {
        let state = Arc::new(Mutex::new(MockState::default()));
        {
            let mut s = state.lock().await;
            s.payments.insert(
                "pending_hash".to_string(),
                json!({
                    "paid": false,
                    "details": {
                        "payment_hash": "pending_hash",
                        "amount": 5000,
                        "pending": true,
                        "time": 1700000000
                    }
                }),
            );
        }

        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let result = provider.verify_payment("pending_hash").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_balance() {
        let state = Arc::new(Mutex::new(MockState {
            balance_msat: 500_000,
            ..Default::default()
        }));

        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let balance = provider.get_balance_msat().await.unwrap();
        assert_eq!(balance, 500_000);
    }

    #[tokio::test]
    async fn is_available_returns_true() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        assert!(provider.is_available().await);
    }

    #[tokio::test]
    async fn is_available_returns_false_when_unreachable() {
        let config = LnbitsConfig {
            api_url: "http://127.0.0.1:1".to_string(), // nothing listening
            admin_key: "key".to_string(),
        };
        let provider = LnbitsProvider::new(config).unwrap();

        assert!(!provider.is_available().await);
    }

    #[tokio::test]
    async fn list_payments_empty() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let payments = provider.list_payments(10).await.unwrap();
        assert!(payments.is_empty());
    }

    #[tokio::test]
    async fn list_payments_returns_entries() {
        let state = Arc::new(Mutex::new(MockState::default()));
        {
            let mut s = state.lock().await;
            s.payments.insert(
                "pay_hash_1".to_string(),
                json!({
                    "paid": true,
                    "details": {
                        "payment_hash": "pay_hash_1",
                        "preimage": "cc".repeat(32),
                        "amount": -5000,
                        "time": 1700000000
                    }
                }),
            );
            s.payments.insert(
                "pay_hash_2".to_string(),
                json!({
                    "paid": false,
                    "details": {
                        "payment_hash": "pay_hash_2",
                        "amount": 10000,
                        "pending": true,
                        "time": 1700000001
                    }
                }),
            );
        }

        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let payments = provider.list_payments(10).await.unwrap();
        assert_eq!(payments.len(), 2);
    }

    #[tokio::test]
    async fn create_invoice_auth_error() {
        let addr = start_mock_auth_reject_server().await;
        let provider = make_provider(addr);

        let result = provider.create_invoice(5_000, "test", 3600).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Auth errors should be LightningError::Auth, not Backend
        assert!(
            matches!(err, konsensus_core::traits::lightning::LightningError::Auth(_)),
            "expected Auth error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn get_balance_auth_error() {
        let addr = start_mock_auth_reject_server().await;
        let provider = make_provider(addr);

        let result = provider.get_balance_msat().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, konsensus_core::traits::lightning::LightningError::Auth(_)),
            "expected Auth error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn pay_invoice_auth_error() {
        let addr = start_mock_auth_reject_server().await;
        let provider = make_provider(addr);

        let result = provider.pay_invoice("lnbc10n1test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_balance_negative_returns_zero() {
        let state = Arc::new(Mutex::new(MockState {
            balance_msat: -100_000,
            ..Default::default()
        }));

        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let balance = provider.get_balance_msat().await.unwrap();
        // Negative balance should be clamped to 0
        assert_eq!(balance, 0);
    }

    #[tokio::test]
    async fn connection_error_returns_connection_variant() {
        let config = LnbitsConfig {
            api_url: "http://127.0.0.1:1".to_string(),
            admin_key: "key".to_string(),
        };
        let provider = LnbitsProvider::new(config).unwrap();

        let result = provider.create_invoice(5_000, "test", 3600).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, konsensus_core::traits::lightning::LightningError::Connection(_)),
            "expected Connection error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn get_payment_status_expired() {
        let state = Arc::new(Mutex::new(MockState::default()));
        {
            let mut s = state.lock().await;
            s.payments.insert(
                "expired_hash".to_string(),
                json!({
                    "paid": false,
                    "expired": true,
                    "details": {
                        "payment_hash": "expired_hash",
                        "amount": 5000,
                        "time": 1700000000
                    }
                }),
            );
        }

        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let details = provider
            .get_payment_status("expired_hash")
            .await
            .unwrap();

        assert_eq!(details.status, PaymentStatus::Expired);
    }

    #[tokio::test]
    async fn list_payments_caps_at_100() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        // Even if we request 500, the provider should cap at 100
        let payments = provider.list_payments(500).await.unwrap();
        assert!(payments.is_empty()); // No data, but the request succeeded
    }

    // ── Malformed response tests ──────────────────────────────────────

    /// Build a mock server that returns malformed JSON for all endpoints.
    fn mock_malformed_json_router() -> Router {
        async fn malformed_handler() -> impl IntoResponse {
            (StatusCode::OK, "this is not valid json {{{")
        }
        async fn malformed_created() -> impl IntoResponse {
            (StatusCode::CREATED, "not json either")
        }
        Router::new()
            .route(
                "/api/v1/payments",
                get(malformed_handler).post(malformed_created),
            )
            .route("/api/v1/payments/:hash", get(malformed_handler))
            .route("/api/v1/wallet", get(malformed_handler))
    }

    async fn start_mock_malformed_server() -> SocketAddr {
        let router = mock_malformed_json_router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn create_invoice_malformed_json_returns_backend_error() {
        let addr = start_mock_malformed_server().await;
        let provider = make_provider(addr);

        let result = provider.create_invoice(5_000, "test", 3600).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, konsensus_core::traits::lightning::LightningError::Backend(_)),
            "expected Backend error for malformed JSON, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn get_balance_malformed_json_returns_backend_error() {
        let addr = start_mock_malformed_server().await;
        let provider = make_provider(addr);

        let result = provider.get_balance_msat().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, konsensus_core::traits::lightning::LightningError::Backend(_)),
            "expected Backend error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn get_payment_status_malformed_json_returns_backend_error() {
        let addr = start_mock_malformed_server().await;
        let provider = make_provider(addr);

        let result = provider.get_payment_status("somehash").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, konsensus_core::traits::lightning::LightningError::Backend(_)),
            "expected Backend error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn list_payments_malformed_json_returns_backend_error() {
        let addr = start_mock_malformed_server().await;
        let provider = make_provider(addr);

        let result = provider.list_payments(10).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, konsensus_core::traits::lightning::LightningError::Backend(_)),
            "expected Backend error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn pay_invoice_malformed_json_returns_backend_error() {
        let addr = start_mock_malformed_server().await;
        let provider = make_provider(addr);

        let result = provider.pay_invoice("lnbc10n1test").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, konsensus_core::traits::lightning::LightningError::Backend(_)),
            "expected Backend error, got: {err:?}"
        );
    }

    // ── 5xx server error tests ────────────────────────────────────────

    fn mock_5xx_router() -> Router {
        async fn internal_error() -> impl IntoResponse {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "detail": "database connection lost" })),
            )
        }
        Router::new()
            .route("/api/v1/payments", get(internal_error).post(internal_error))
            .route("/api/v1/payments/:hash", get(internal_error))
            .route("/api/v1/wallet", get(internal_error))
    }

    async fn start_mock_5xx_server() -> SocketAddr {
        let router = mock_5xx_router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn create_invoice_5xx_returns_backend_error() {
        let addr = start_mock_5xx_server().await;
        let provider = make_provider(addr);

        let result = provider.create_invoice(5_000, "test", 3600).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        // 5xx is not 401/403, so should be Backend not Auth
        assert!(
            matches!(err, konsensus_core::traits::lightning::LightningError::Backend(_)),
            "expected Backend error for 500, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn get_balance_5xx_returns_backend_error() {
        let addr = start_mock_5xx_server().await;
        let provider = make_provider(addr);

        let result = provider.get_balance_msat().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, konsensus_core::traits::lightning::LightningError::Backend(_)),
            "expected Backend error for 500, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn pay_invoice_5xx_returns_backend_error() {
        let addr = start_mock_5xx_server().await;
        let provider = make_provider(addr);

        let result = provider.pay_invoice("lnbc10n1test").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, konsensus_core::traits::lightning::LightningError::Backend(_)),
            "expected Backend error for 500, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn is_available_returns_false_on_5xx() {
        let addr = start_mock_5xx_server().await;
        let provider = make_provider(addr);
        // 500 status is not success, so is_available should return false
        assert!(!provider.is_available().await);
    }

    // ── Response with missing fields ──────────────────────────────────

    fn mock_missing_fields_router() -> Router {
        async fn invoice_no_hash() -> impl IntoResponse {
            // Response missing payment_hash
            (StatusCode::CREATED, Json(json!({ "bolt11": "lnbc1test" })))
        }
        async fn payment_no_details() -> impl IntoResponse {
            // Payment status with no details at all
            (
                StatusCode::OK,
                Json(json!({ "paid": true, "settled": true })),
            )
        }
        async fn wallet_empty_object() -> impl IntoResponse {
            // Wallet response with no balance fields
            (StatusCode::OK, Json(json!({})))
        }
        Router::new()
            .route("/api/v1/payments", axum::routing::post(invoice_no_hash))
            .route("/api/v1/payments/:hash", get(payment_no_details))
            .route("/api/v1/wallet", get(wallet_empty_object))
    }

    async fn start_mock_missing_fields_server() -> SocketAddr {
        let router = mock_missing_fields_router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn create_invoice_missing_payment_hash() {
        let addr = start_mock_missing_fields_server().await;
        let provider = make_provider(addr);

        let result = provider.create_invoice(5_000, "test", 3600).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("payment_hash"),
            "error should mention missing payment_hash: {err_msg}"
        );
    }

    #[tokio::test]
    async fn get_payment_status_no_details_returns_defaults() {
        let addr = start_mock_missing_fields_server().await;
        let provider = make_provider(addr);

        // Should succeed but with default values for missing fields
        let details = provider.get_payment_status("anyhash").await.unwrap();
        assert_eq!(details.status, PaymentStatus::Settled);
        assert!(details.preimage.is_none()); // No details block
        assert_eq!(details.amount_msat, 0); // Default
        assert_eq!(details.timestamp, 0); // Default
    }

    #[tokio::test]
    async fn get_balance_missing_fields_returns_zero() {
        let addr = start_mock_missing_fields_server().await;
        let provider = make_provider(addr);

        let balance = provider.get_balance_msat().await.unwrap();
        assert_eq!(balance, 0); // No balance fields -> 0
    }

    // ── Direction and fee edge cases ──────────────────────────────────

    #[tokio::test]
    async fn get_payment_status_outgoing_direction_from_negative_amount() {
        let state = Arc::new(Mutex::new(MockState::default()));
        {
            let mut s = state.lock().await;
            s.payments.insert(
                "outgoing_test".to_string(),
                json!({
                    "paid": true,
                    "details": {
                        "payment_hash": "outgoing_test",
                        "preimage": "dd".repeat(32),
                        "amount": -50000,
                        "time": 1700000000
                    },
                    "fee": 100
                }),
            );
        }

        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let details = provider.get_payment_status("outgoing_test").await.unwrap();
        assert_eq!(details.direction, PaymentDirection::Outgoing);
        assert_eq!(details.amount_msat, 50000); // unsigned_abs of -50000
        assert_eq!(details.fee_msat, Some(100));
    }

    #[tokio::test]
    async fn get_payment_status_incoming_direction_from_positive_amount() {
        let state = Arc::new(Mutex::new(MockState::default()));
        {
            let mut s = state.lock().await;
            s.payments.insert(
                "incoming_test".to_string(),
                json!({
                    "paid": true,
                    "details": {
                        "payment_hash": "incoming_test",
                        "amount": 75000,
                        "time": 1700000000
                    }
                }),
            );
        }

        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let details = provider
            .get_payment_status("incoming_test")
            .await
            .unwrap();
        assert_eq!(details.direction, PaymentDirection::Incoming);
        assert_eq!(details.amount_msat, 75000);
    }

    #[tokio::test]
    async fn get_payment_status_zero_amount_is_incoming() {
        let state = Arc::new(Mutex::new(MockState::default()));
        {
            let mut s = state.lock().await;
            s.payments.insert(
                "zero_test".to_string(),
                json!({
                    "paid": false,
                    "details": {
                        "payment_hash": "zero_test",
                        "amount": 0,
                        "time": 0
                    }
                }),
            );
        }

        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let details = provider.get_payment_status("zero_test").await.unwrap();
        // amount 0 is not < 0, so direction defaults to Incoming
        assert_eq!(details.direction, PaymentDirection::Incoming);
        assert_eq!(details.amount_msat, 0);
    }

    #[tokio::test]
    async fn get_balance_with_balance_field_instead_of_msat() {
        // Test fallback: balance_msat missing, but balance (in sats) is present
        fn mock_balance_sats_router() -> Router {
            async fn wallet_sats() -> impl IntoResponse {
                (
                    StatusCode::OK,
                    Json(json!({ "balance": 500 })), // 500 sats, no balance_msat
                )
            }
            Router::new().route("/api/v1/wallet", get(wallet_sats))
        }

        let router = mock_balance_sats_router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let provider = make_provider(addr);
        let balance = provider.get_balance_msat().await.unwrap();
        assert_eq!(balance, 500_000); // 500 sats * 1000 = 500_000 msat
    }

    // ── Invoice amount edge cases ─────────────────────────────────────

    #[tokio::test]
    async fn create_invoice_exactly_1000_msat_succeeds() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        // 1000 msat = 1 sat, minimum amount
        let invoice = provider.create_invoice(1_000, "min", 3600).await.unwrap();
        assert_eq!(invoice.amount_msat, 1_000);
    }

    #[tokio::test]
    async fn create_invoice_999_msat_rejected() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        // 999 msat / 1000 = 0 sats, rejected
        let result = provider.create_invoice(999, "too small", 3600).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn create_invoice_zero_msat_rejected() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let result = provider.create_invoice(0, "zero", 3600).await;
        assert!(result.is_err());
    }

    // ── list_payments direction and status parsing ────────────────────

    #[tokio::test]
    async fn list_payments_parses_direction_and_status() {
        let state = Arc::new(Mutex::new(MockState::default()));
        {
            let mut s = state.lock().await;
            // Outgoing settled payment
            s.payments.insert(
                "out_settled".to_string(),
                json!({
                    "paid": true,
                    "details": {
                        "payment_hash": "out_settled",
                        "preimage": "ee".repeat(32),
                        "amount": -25000,
                        "time": 1700000000
                    }
                }),
            );
        }

        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        let payments = provider.list_payments(10).await.unwrap();
        assert_eq!(payments.len(), 1);

        let p = &payments[0];
        // The list endpoint reports amount directly (negative = outgoing)
        assert_eq!(p.direction, PaymentDirection::Outgoing);
    }

    // ── API URL construction (tested indirectly via mock) ──────────────

    #[tokio::test]
    async fn trailing_slash_in_url_works() {
        // Verify that a trailing slash in the config URL doesn't break API calls
        let state = Arc::new(Mutex::new(MockState {
            balance_msat: 42_000,
            ..Default::default()
        }));
        let addr = start_mock_server(state).await;

        let config = LnbitsConfig {
            api_url: format!("http://{addr}/"), // trailing slash
            admin_key: "test-admin-key-123".to_string(),
        };
        let provider = LnbitsProvider::new(config).unwrap();

        let balance = provider.get_balance_msat().await.unwrap();
        assert_eq!(balance, 42_000);
    }

    // ── list_payments with various status strings ─────────────────────

    // ── payment_capable flag tests ──────────────────────────────────

    #[tokio::test]
    async fn pay_invoice_5xx_marks_payment_incapable() {
        let addr = start_mock_5xx_server().await;
        let provider = make_provider(addr);

        // Provider starts as payment-capable
        assert!(provider.is_payment_capable().await);

        // A payment attempt that fails with 5xx marks incapable
        let result = provider.pay_invoice("lnbc10n1test").await;
        assert!(result.is_err());

        // After 5xx failure, is_payment_capable returns false
        assert!(!provider.is_payment_capable().await);
        // But is_available still returns true if the server is reachable
        // (5xx server won't return 200 for wallet check, so both are false here)
        assert!(!provider.is_available().await);
    }

    #[tokio::test]
    async fn successful_payment_clears_incapable_flag() {
        // Start with a working mock server
        let state = Arc::new(Mutex::new(MockState::default()));
        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        // Manually set the flag to false to simulate a prior 5xx
        provider
            .payment_capable
            .store(false, std::sync::atomic::Ordering::Relaxed);

        // is_available should be true (server is reachable)
        assert!(provider.is_available().await);
        // but is_payment_capable should be false (flag is set)
        assert!(!provider.is_payment_capable().await);

        // A successful payment should clear the flag
        let result = provider.pay_invoice("lnbc10n1test").await;
        assert!(result.is_ok());

        // Now both should be true
        assert!(provider.is_available().await);
        assert!(provider.is_payment_capable().await);
    }

    #[tokio::test]
    async fn fresh_provider_is_payment_capable() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        // A fresh provider should be both available and payment-capable
        assert!(provider.is_available().await);
        assert!(provider.is_payment_capable().await);
    }

    #[tokio::test]
    async fn list_payments_status_mapping() {
        // Test that all status strings map correctly
        fn mock_status_router() -> Router {
            async fn list_handler() -> impl IntoResponse {
                Json(json!([
                    { "payment_hash": "h1", "amount": 1000, "status": "success", "time": 1.0 },
                    { "payment_hash": "h2", "amount": -2000, "status": "failed", "time": 2.0 },
                    { "payment_hash": "h3", "amount": 3000, "status": "expired", "time": 3.0 },
                    { "payment_hash": "h4", "amount": 4000, "status": "unknown_status", "time": 4.0 },
                    { "payment_hash": "h5", "amount": 5000, "time": 5.0 }
                ]))
            }
            Router::new().route("/api/v1/payments", get(list_handler))
        }

        let router = mock_status_router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let provider = make_provider(addr);
        let payments = provider.list_payments(10).await.unwrap();

        assert_eq!(payments.len(), 5);
        assert_eq!(payments[0].status, PaymentStatus::Settled);
        assert_eq!(payments[1].status, PaymentStatus::Failed);
        assert_eq!(payments[1].direction, PaymentDirection::Outgoing);
        assert_eq!(payments[2].status, PaymentStatus::Expired);
        assert_eq!(payments[3].status, PaymentStatus::Pending); // unknown maps to pending
        assert_eq!(payments[4].status, PaymentStatus::Pending); // missing maps to pending
    }

    // ── probe_payment_capability tests ─────────────────────────────────

    /// Mock LNbits with VoidWallet funding source — invoices work, payments fail.
    fn mock_voidwallet_router() -> Router {
        async fn wallet_ok() -> impl IntoResponse {
            (StatusCode::OK, Json(json!({ "name": "test", "balance": 100000 })))
        }
        async fn payments_handler(Json(body): Json<Value>) -> impl IntoResponse {
            let is_outgoing = body.get("out").and_then(|v| v.as_bool()).unwrap_or(false);
            if is_outgoing {
                // VoidWallet rejects outbound payments with 520
                (
                    StatusCode::from_u16(520).unwrap(),
                    Json(json!({
                        "detail": "Payment failed: VoidWallet cannot pay invoices.",
                        "status": "failed"
                    })),
                )
            } else {
                // Invoice creation still works with VoidWallet
                let amount = body.get("amount").and_then(|v| v.as_u64()).unwrap_or(1);
                (
                    StatusCode::CREATED,
                    Json(json!({
                        "payment_hash": format!("probe_hash_{amount}"),
                        "bolt11": format!("lnbc{amount}n1probe_bolt11")
                    })),
                )
            }
        }
        Router::new()
            .route("/api/v1/wallet", get(wallet_ok))
            .route("/api/v1/payments", axum::routing::post(payments_handler))
    }

    #[tokio::test]
    async fn probe_detects_voidwallet() {
        let router = mock_voidwallet_router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let provider = make_provider(addr);
        // Before probe, payment_capable defaults to true
        assert!(provider.is_payment_capable().await);

        provider.probe_payment_capability().await;

        // After probe, VoidWallet is detected
        assert!(!provider.is_payment_capable().await);
    }

    #[tokio::test]
    async fn probe_succeeds_with_real_funding_source() {
        // Normal mock server supports both invoices and payments
        let state = Arc::new(Mutex::new(MockState {
            balance_msat: 1_000_000,
            ..Default::default()
        }));
        let addr = start_mock_server(state).await;
        let provider = make_provider(addr);

        provider.probe_payment_capability().await;

        // Funding source is real — payment_capable stays true
        assert!(provider.is_payment_capable().await);
    }

    #[tokio::test]
    async fn probe_detects_unreachable_api() {
        // Connect to a port that nothing is listening on
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // Close the port

        let provider = make_provider(addr);

        provider.probe_payment_capability().await;

        // API unreachable — payment_capable set to false
        assert!(!provider.is_payment_capable().await);
    }
}
