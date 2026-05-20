//! L0f — `send_onchain` post-broadcast verification.
//!
//! Tests live at the `esplora_tx_visible` helper layer because exercising
//! the full LDK on-chain path requires bitcoind+electrsd (gated on the
//! `ldk-integration-test` feature). The helper itself is what surfaces
//! the BroadcastUnconfirmed condition; LDK simply forwards its return.
//!
//! What this asserts:
//! 1. A 200 from Esplora's `/tx/<txid>` → `Ok(true)`.
//! 2. A 404 → `Ok(false)`.
//! 3. Any other status (5xx, 502 from CDN, etc.) → `Err`.
//! 4. Empty `esplora_url` (test-path via `LdkProvider::from_node`) → `Ok(false)`.
//!
//! `LightningError::BroadcastUnconfirmed { txid }` is exercised at the
//! API-handler layer (`konsensus-api` send_onchain handler test).

use konsensus_lightning::esplora_tx_visible;

#[tokio::test]
async fn empty_url_returns_false_no_panic() {
    let result = esplora_tx_visible("", "deadbeef").await;
    assert_eq!(result, Ok(false));
}

#[tokio::test]
async fn http_200_means_visible() {
    let mut server = mockito::Server::new_async().await;
    let url = server.url();
    let mock = server
        .mock("GET", "/tx/abc123")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let result = esplora_tx_visible(&url, "abc123").await;
    assert_eq!(result, Ok(true));
    mock.assert_async().await;
}

#[tokio::test]
async fn http_404_means_unconfirmed() {
    let mut server = mockito::Server::new_async().await;
    let url = server.url();
    let mock = server
        .mock("GET", "/tx/nope")
        .with_status(404)
        .create_async()
        .await;

    let result = esplora_tx_visible(&url, "nope").await;
    assert_eq!(result, Ok(false));
    mock.assert_async().await;
}

#[tokio::test]
async fn http_5xx_is_err() {
    let mut server = mockito::Server::new_async().await;
    let url = server.url();
    let mock = server
        .mock("GET", "/tx/xyz")
        .with_status(503)
        .create_async()
        .await;

    let result = esplora_tx_visible(&url, "xyz").await;
    assert!(result.is_err(), "5xx should produce Err so caller treats as BroadcastUnconfirmed");
    mock.assert_async().await;
}

#[tokio::test]
async fn trailing_slash_in_url_is_normalized() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/", server.url());
    let mock = server
        .mock("GET", "/tx/withSlash")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let result = esplora_tx_visible(&url, "withSlash").await;
    assert_eq!(result, Ok(true));
    mock.assert_async().await;
}
