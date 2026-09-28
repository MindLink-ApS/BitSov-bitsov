use konsensus_core::traits::lightning::{LightningProvider, PaymentStatus};
use konsensus_lightning::{LndConfig, LndProvider};

#[tokio::test]
async fn invoice_and_keysend_pass_exact_msat_limit_including_zero() {
    let mut server = mockito::Server::new_async().await;
    let provider = LndProvider::new(LndConfig {
        api_url: server.url(), macaroon_hex: "00".into(), tls_cert_path: None,
    }).unwrap();
    let _track = server.mock("GET", mockito::Matcher::Regex("^/v2/router/track/".into()))
        .with_status(404).with_body(r#"{"code":5,"message":"not found"}"#).create_async().await;
    for cap in [0, 1234] {
        for keysend in [false, true] {
            let request = server.mock("POST", "/v2/router/send")
                .match_body(mockito::Matcher::PartialJson(serde_json::json!({"fee_limit_msat":cap.to_string()})))
                .with_status(200)
                .with_body(r#"{"result":{"status":"SUCCEEDED","payment_hash":"aa","payment_preimage":"bb","value_msat":"1000","fee_msat":"0"}}"#)
                .expect(1).create_async().await;
            let result = if keysend {
                provider.keysend_with_fee_limit(&format!("02{}", "11".repeat(32)), 1000, None, cap).await
            } else {
                provider.pay_invoice_with_fee_limit(&konsensus_lightning::MockLightningProvider::new().create_invoice(1000, "LND test", 3600).await.unwrap().bolt11, cap).await
            };
            assert_eq!(result.unwrap().status, PaymentStatus::Settled);
            request.assert_async().await;
        }
    }
}

#[tokio::test]
async fn existing_or_unverifiable_invoice_never_posts_and_terminal_failure_stays_typed() {
    use konsensus_core::traits::lightning::LightningError;
    for (code, body) in [(200, r#"{"result":{"status":"FAILED"}}"#), (403, r#"{"code":7}"#), (404, "not json")] {
        let mut server = mockito::Server::new_async().await;
        let provider = LndProvider::new(LndConfig { api_url:server.url(), macaroon_hex:"00".into(), tls_cert_path:None }).unwrap();
        let _track = server.mock("GET", mockito::Matcher::Any).with_status(code).with_body(body).create_async().await;
        let post = server.mock("POST", "/v2/router/send").expect(0).create_async().await;
        let invoice = konsensus_lightning::MockLightningProvider::new().create_invoice(1000, "freshness", 3600).await.unwrap();
        assert!(matches!(provider.pay_invoice_with_fee_limit(&invoice.bolt11, 5000).await, Err(LightningError::PaymentNotDispatched(_))));
        post.assert_async().await;
    }
    let mut server = mockito::Server::new_async().await;
    let provider = LndProvider::new(LndConfig { api_url:server.url(), macaroon_hex:"00".into(), tls_cert_path:None }).unwrap();
    let _track = server.mock("GET", mockito::Matcher::Any).with_status(404).with_body(r#"{"code":5}"#).expect(1).create_async().await;
    let post = server.mock("POST", "/v2/router/send").with_status(200).with_body(r#"{"result":{"status":"FAILED","payment_hash":"aa","value_msat":"1000"}}"#).expect(1).create_async().await;
    let invoice = konsensus_lightning::MockLightningProvider::new().create_invoice(1000, "route failure", 3600).await.unwrap();
    assert_eq!(provider.pay_invoice_with_fee_limit(&invoice.bolt11, 5000).await.unwrap().status, PaymentStatus::Failed);
    assert!(matches!(provider.pay_invoice_with_fee_limit(&invoice.bolt11, 10000).await, Err(LightningError::PaymentNotDispatched(_))));
    post.assert_async().await;
}
