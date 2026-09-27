//! Fake HTTP only: exercise the actual LND adapter without an LND process.
use konsensus_core::traits::lightning::{LightningError, LightningProvider};
use konsensus_lightning::{LndConfig, LndProvider};

fn provider(url: String) -> LndProvider {
    LndProvider::with_client(
        LndConfig {
            api_url: url,
            macaroon_hex: "test-only".into(),
            tls_cert_path: None,
        },
        reqwest::Client::builder().no_proxy().build().unwrap(),
    )
}

#[tokio::test]
async fn local_key_rejection_is_proven_before_dispatch() {
    let mut server = mockito::Server::new_async().await;
    let payment = server
        .mock("POST", "/v2/router/send")
        .expect(0)
        .create_async()
        .await;
    let err = provider(server.url())
        .keysend("not-hex", 1000, None)
        .await
        .unwrap_err();
    assert!(matches!(err, LightningError::PaymentNotDispatched(_)));
    payment.assert_async().await;
}

#[tokio::test]
async fn missing_or_malformed_remote_results_never_prove_no_dispatch() {
    for body in ["", "not-json", "{\"error\":{\"message\":\"unknown\"}}"] {
        let mut server = mockito::Server::new_async().await;
        let payment = server
            .mock("POST", "/v2/router/send")
            .match_body(mockito::Matcher::PartialJson(
                serde_json::json!({"amt_msat":"1000"}),
            ))
            .with_status(200)
            .with_body(body)
            .expect(1)
            .create_async()
            .await;
        let err = provider(server.url())
            .keysend(&format!("02{}", "11".repeat(32)), 1000, None)
            .await
            .unwrap_err();
        assert!(
            !matches!(err, LightningError::PaymentNotDispatched(_)),
            "{err}"
        );
        payment.assert_async().await;
    }
}
