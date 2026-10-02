mod common;
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use common::test_router as build_router;
use common::*;
use konsensus_api::auth;
use konsensus_core::identity::NodeIdentity;
use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails,
};
use konsensus_core::traits::pricing::{PricingEngine, PricingError};
use konsensus_core::types::NodeId;
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn files_list_empty() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/files")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["files"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn nonexistent_file_returns_404() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/files/nonexistent-file-id")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── File upload test ──────────────────────────────────────────────

#[tokio::test]
async fn file_upload_success() {
    let state = test_state();
    let auth = auth_header(&state);

    let data = b"hello world";
    let data_b64 = base64::engine::general_purpose::STANDARD.encode(data);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "filename": "hello.txt",
                "mime_type": "text/plain",
                "data_b64": data_b64,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(!result["file_id"].as_str().unwrap().is_empty());
    assert_eq!(result["size_bytes"], data.len() as u64);
    assert!(!result["blake3_hash"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn file_upload_rejects_empty_filename() {
    let state = test_state();
    let auth = auth_header(&state);

    let data_b64 = base64::engine::general_purpose::STANDARD.encode(b"data");

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "filename": "",
                "data_b64": data_b64,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn file_upload_rejects_path_traversal() {
    let state = test_state();
    let auth = auth_header(&state);

    let data_b64 = base64::engine::general_purpose::STANDARD.encode(b"data");

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "filename": "../../../etc/passwd",
                "data_b64": data_b64,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn file_upload_rejects_invalid_base64() {
    let state = test_state();
    let auth = auth_header(&state);

    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "filename": "test.txt",
                "data_b64": "not-valid-base64!!!",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn file_upload_requires_auth() {
    let state = test_state();
    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "filename": "test.txt",
                "data_b64": "aGVsbG8=",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ═══════════════════════════════════════════════════════════════════
// File send endpoint tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn send_file_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files/test-file-id/send")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"recipient":"aa"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn send_file_not_found() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));
    let recipient = "ff".repeat(32);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files/nonexistent-file-id/send")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(format!(r#"{{"recipient":"{recipient}"}}"#)))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn send_file_invalid_recipient() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    // First store a file so the 404 doesn't fire first
    let file_record = konsensus_storage::FileRecord {
        id: "test-file-1".into(),
        filename: "hello.txt".into(),
        mime_type: "text/plain".into(),
        size_bytes: 5,
        blake3_hash: "aa".repeat(32),
        sender: "00".repeat(32),
        message_id: None,
        data: b"hello".to_vec(),
        created_at: "2026-03-30T00:00:00Z".into(),
    };
    state.storage.store_file(&file_record).await.unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files/test-file-1/send")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"recipient":"not-valid-hex"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn upload_file_rejects_unknown_fields() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "filename": "test.txt",
                "data_b64": base64::engine::general_purpose::STANDARD.encode(b"hello"),
                "bonus_field": 42
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown fields in upload request should be rejected"
    );
}

// ─── Files: delete ────────────────────────────────────────────────

#[tokio::test]
async fn delete_file_success() {
    let state = test_state();
    let auth = auth_header(&state);

    let data_b64 = base64::engine::general_purpose::STANDARD.encode(b"file-data");

    // Upload a file first
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/files")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "filename": "to_delete.txt",
                "mime_type": "text/plain",
                "data_b64": data_b64,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let file_id = json["file_id"].as_str().unwrap().to_string();

    // Delete the file
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/files/{file_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["deleted"], true);

    // Verify the file is gone
    let app = build_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(format!("/api/v1/files/{file_id}"))
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_file_nonexistent_returns_false() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/files/nonexistent-id-1234")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["deleted"], false);
}

#[tokio::test]
async fn delete_file_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/files/some-id")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn spend_upload_is_bounded_and_does_not_grant_file_management() {
    let state = test_state();
    let token = auth::create_token(&state.identity.node_id().to_hex(), &state.jwt_secret, vec![auth::Scope::Spend]).unwrap();
    let app = build_router(state);
    let request = |method: &str, path: &str, body: serde_json::Value| Request::builder()
        .method(method).uri(path).header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json").body(Body::from(body.to_string())).unwrap();
    let response = app.clone().oneshot(request("POST", "/api/v1/files", serde_json::json!({"filename":"paired.txt", "mime_type":"text/plain", "data_b64":"aGVsbG8="}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
    let uploaded: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let response = app.clone().oneshot(request("DELETE", &format!("/api/v1/files/{}", uploaded["file_id"].as_str().unwrap()), serde_json::json!({}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = app.oneshot(request("POST", "/api/v1/files", serde_json::json!({"filename":"large.txt", "mime_type":"text/plain", "data_b64":"A".repeat(6*1024*1024)}))).await.unwrap();
    assert!(response.status().is_client_error());
}

#[tokio::test(start_paused = true)]
async fn staging_quotas_expiry_ownership_and_inflight_accounting() {
    use konsensus_api::file_staging::FileStaging;
    use std::time::Duration;
    let state = test_state();
    let caller = |id: &str| auth::AuthUser {
        node_id: id.into(),
        scopes: vec![auth::Scope::Spend],
        pairing: None,
    };
    let a = caller("a");
    let b = caller("b");
    let c = caller("c");
    let file = |id: &str, n: usize| konsensus_storage::FileRecord {
        id: id.into(),
        filename: "f".into(),
        mime_type: "x".into(),
        size_bytes: n as u64,
        blake3_hash: String::new(),
        sender: "a".into(),
        message_id: None,
        data: vec![1; n],
        created_at: String::new(),
    };
    {
        let mut s = state.file_staging.lock().unwrap();
        assert!(s
            .insert(&state, &a, file("too-big", 4 * 1024 * 1024 + 1))
            .is_err());
        for (owner, id) in [(&a, "a1"), (&a, "a2"), (&b, "b1"), (&b, "b2")] {
            s.insert(&state, owner, file(id, 4 * 1024 * 1024)).unwrap();
        }
        assert!(s.insert(&state, &a, file("own-full", 1)).is_err());
        assert!(s.insert(&state, &c, file("global-full", 1)).is_err());
        assert!(s.get(&state, &b, "a1").is_none());
    }
    assert!(FileStaging::claim(&state, &b, "a1").is_err());
    let send = FileStaging::claim(&state, &a, "a1").unwrap().unwrap();
    assert!(FileStaging::claim(&state, &a, "a1").is_err());
    assert!(
        !state.file_staging.lock().unwrap().remove("a1"),
        "admin cannot release in-flight quota"
    );
    tokio::time::advance(Duration::from_secs(301)).await;
    {
        let mut s = state.file_staging.lock().unwrap();
        s.sweep(&state);
        assert!(s.get(&state, &a, "a2").is_none());
        // The expired in-flight 4 MiB still counts against this owner's quota.
        s.insert(&state, &a, file("a3", 4 * 1024 * 1024)).unwrap();
        assert!(s.insert(&state, &a, file("inflight-counts", 1)).is_err());
    }
    drop(send);
    let mut s = state.file_staging.lock().unwrap();
    s.insert(&state, &a, file("a4", 4 * 1024 * 1024)).unwrap();
    assert!(s.get(&state, &a, "a1").is_none());
}

#[tokio::test]
async fn staged_send_consumes_success_and_failure_but_cap_refusal_preserves_upload() {
    use konsensus_lightning::shared_mock::SharedMockProvider;
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("payments.sqlite");
    let payer = Arc::new(SharedMockProvider::new(&ledger, "a", 10000).unwrap());
    let payee = Arc::new(SharedMockProvider::new(&ledger, "b", 0).unwrap());
    let mut state = test_state_with_lightning(payer.clone());
    let (_, identity) = NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let transport = ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
        .with_invoice_responder(move |_, amount| {
            let invoice =
                futures::executor::block_on(payee.create_invoice(amount, "file", 60)).unwrap();
            Some(konsensus_api::state::InvoiceResponseData {
                recipient: peer,
                bolt11: invoice.bolt11,
                payment_hash: invoice.payment_hash,
            })
        });
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(transport);
    let token = auth_header(&state);
    let app = build_router(state.clone());
    let req = |method: &str, path: &str, body: serde_json::Value| {
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", &token)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let upload = serde_json::json!({"filename":"f.txt","data_b64":"aGVsbG8="});
    let response = app
        .clone()
        .oneshot(req("POST", "/api/v1/files", upload.clone()))
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let id = value["file_id"].as_str().unwrap();
    let path = format!("/api/v1/files/{id}");
    let send = format!("{path}/send");
    let body = serde_json::json!({"recipient":peer.to_hex(),"max_total_msat":0});
    assert_eq!(
        app.clone()
            .oneshot(req("POST", &send, body))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        app.clone()
            .oneshot(req("GET", &path, serde_json::Value::Null))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let body = serde_json::json!({"recipient":peer.to_hex(),"max_routing_fee_msat":0,"max_total_msat":1000});
    // Missing session fails before payment but consumes the attempted send.
    assert_eq!(
        app.clone()
            .oneshot(req("POST", &send, body.clone()))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(payer.get_balance_msat().await.unwrap(), 10000);
    assert_eq!(
        app.clone()
            .oneshot(req("GET", &path, serde_json::Value::Null))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
    state
        .session_manager
        .initiate_session(&peer, &target.prekey_bundle().await)
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(req("POST", "/api/v1/files", upload))
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let id = value["file_id"].as_str().unwrap();
    let path = format!("/api/v1/files/{id}");
    assert_eq!(
        app.clone()
            .oneshot(req("POST", &format!("{path}/send"), body))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(payer.get_balance_msat().await.unwrap(), 9000);
    assert_eq!(
        app.oneshot(req("GET", &path, serde_json::Value::Null))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test(start_paused = true)]
async fn stalled_staged_send_times_out_unknown_and_releases_blob() {
    use konsensus_lightning::shared_mock::SharedMockProvider;
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Stalled {
        dispatched: AtomicBool,
    }
    #[async_trait]
    impl LightningProvider for Stalled {
    async fn pay_invoice_with_fee_limit(&self, invoice: &str, _cap: u64) -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError> {
        self.pay_invoice(invoice).await
    }

    async fn keysend_with_fee_limit(&self, dest: &str, amount: u64, memo: Option<&str>, _cap: u64) -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError> {
        self.keysend(dest, amount, memo).await
    }

        async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
            unreachable!()
        }
        async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            self.dispatched.store(true, Ordering::SeqCst);
            std::future::pending().await
        }
        async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            std::future::pending().await
        }
        async fn get_balance_msat(&self) -> Result<u64, LightningError> {
            Ok(10000)
        }
        async fn is_available(&self) -> bool {
            true
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let payee = SharedMockProvider::new(&dir.path().join("mock.db"), "b", 0).unwrap();
    let payer = Arc::new(Stalled {
        dispatched: AtomicBool::new(false),
    });
    let mut state = test_state_with_lightning(payer.clone());
    let (_, identity) = NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(
        ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
            .with_invoice_responder(move |_, amount| {
                let invoice =
                    futures::executor::block_on(payee.create_invoice(amount, "file", 60)).unwrap();
                Some(konsensus_api::state::InvoiceResponseData {
                    recipient: peer,
                    bolt11: invoice.bolt11,
                    payment_hash: invoice.payment_hash,
                })
            }),
    );
    let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
    state
        .session_manager
        .initiate_session(&peer, &target.prekey_bundle().await)
        .await
        .unwrap();
    let token = auth_header(&state);
    let app = build_router(state.clone());
    let req = |method: &str, path: &str, body: serde_json::Value| {
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", &token)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/files",
            serde_json::json!({"filename":"f","data_b64":"aGVsbG8="}),
        ))
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let path = format!("/api/v1/files/{}", value["file_id"].as_str().unwrap());
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("{path}/send"),
            serde_json::json!({"recipient":peer.to_hex(),"max_routing_fee_msat":0,"max_total_msat":1000}),
        ))
        .await
        .unwrap();
    assert!(payer.dispatched.load(Ordering::SeqCst));
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert!(String::from_utf8(body.to_vec())
        .unwrap()
        .contains("do not retry"));
    assert_eq!(
        app.oneshot(req("GET", &path, serde_json::Value::Null))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn pending_pricing_cannot_retain_deleted_staging_outside_quota() {
    struct PendingPricing {
        entered: tokio::sync::Notify,
    }
    #[async_trait]
    impl PricingEngine for PendingPricing {
        async fn get_price_msat(&self, _: u16) -> Result<u64, PricingError> {
            self.entered.notify_one();
            std::future::pending().await
        }
        async fn get_category_price_msat(
            &self,
            _: konsensus_core::kind::KindCategory,
        ) -> Result<u64, PricingError> {
            unreachable!()
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }
    let mut state = test_state();
    let pricing = Arc::new(PendingPricing {
        entered: tokio::sync::Notify::new(),
    });
    Arc::get_mut(&mut state).unwrap().pricing = pricing.clone();
    let caller = auth::AuthUser {
        node_id: state.identity.node_id().to_hex(),
        scopes: vec![auth::Scope::Admin],
        pairing: None,
    };
    let file = konsensus_storage::FileRecord {
        id: "stage-pending".into(),
        filename: "f".into(),
        mime_type: "x".into(),
        size_bytes: 4 * 1024 * 1024,
        blake3_hash: String::new(),
        sender: caller.node_id.clone(),
        message_id: None,
        data: vec![1; 4 * 1024 * 1024],
        created_at: String::new(),
    };
    let bytes = {
        let mut staging = state.file_staging.lock().unwrap();
        staging.insert(&state, &caller, file).unwrap();
        Arc::downgrade(&staging.get(&state, &caller, "stage-pending").unwrap())
    };
    let app = build_router(state.clone());
    let token = auth_header(&state);
    let request=Request::builder().method("POST").uri("/api/v1/files/stage-pending/send")
        .header("authorization",token).header("content-type","application/json")
        .body(Body::from(serde_json::json!({"recipient":NodeId::from_bytes([2;32]).to_hex(),"max_routing_fee_msat":0,"max_total_msat":1000}).to_string())).unwrap();
    let sending = tokio::spawn(async move { app.oneshot(request).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        pricing.entered.notified(),
    )
    .await
    .unwrap();
    assert!(state.file_staging.lock().unwrap().remove("stage-pending"));
    assert!(
        bytes.upgrade().is_none(),
        "pricing await retained bytes after quota was released"
    );
    sending.abort();
    let _ = sending.await;
}
