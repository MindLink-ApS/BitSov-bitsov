//! L4b — Esplora primary/fallback runtime switch.
//!
//! Tests at the `probe_esplora_fee_estimates` + `select_esplora_endpoint`
//! helper layer. The end-to-end path through `LdkProvider::new` requires
//! a running LDK node (gated on the `ldk-integration-test` feature) and
//! would only exercise the same selection logic via the helpers — so the
//! tests live here, where they can hammer the decision matrix against
//! `mockito` HTTP fixtures in a few hundred milliseconds.
//!
//! What this asserts:
//! 1. Probe returns `Ok(())` on HTTP 200, `Err` on 5xx / 404 / network failure.
//! 2. With no fallback configured, selection returns the primary regardless
//!    of probe outcome (best-effort — LDK will surface its own startup
//!    error if the endpoint is dead).
//! 3. With a fallback configured and the primary healthy, the primary
//!    wins (no needless switch).
//! 4. With a fallback configured and the primary unreachable, the
//!    fallback URL is selected.
//! 5. With both unreachable, the fallback URL is still returned
//!    (operator's explicit fallback gets exercised before LDK takes over
//!    and crash-loops with a real error).

use konsensus_lightning::{probe_esplora_fee_estimates, select_esplora_endpoint};

#[tokio::test]
async fn esplora_fallback_probe_ok_on_http_200() {
    let mut server = mockito::Server::new_async().await;
    let url = server.url();
    let mock = server
        .mock("GET", "/fee-estimates")
        .with_status(200)
        .with_body("{\"1\": 25.0}")
        .create_async()
        .await;

    assert!(probe_esplora_fee_estimates(&url).await.is_ok());
    mock.assert_async().await;
}

#[tokio::test]
async fn esplora_fallback_probe_err_on_http_5xx() {
    let mut server = mockito::Server::new_async().await;
    let url = server.url();
    let mock = server
        .mock("GET", "/fee-estimates")
        .with_status(502)
        .create_async()
        .await;

    let result = probe_esplora_fee_estimates(&url).await;
    assert!(result.is_err(), "5xx should produce Err so caller can fall over");
    mock.assert_async().await;
}

#[tokio::test]
async fn esplora_fallback_probe_err_on_http_404() {
    let mut server = mockito::Server::new_async().await;
    let url = server.url();
    let mock = server
        .mock("GET", "/fee-estimates")
        .with_status(404)
        .create_async()
        .await;

    let result = probe_esplora_fee_estimates(&url).await;
    assert!(
        result.is_err(),
        "404 means the endpoint isn't a working esplora — fall over"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn esplora_fallback_probe_err_on_unreachable_host() {
    // Reserved-for-documentation TLD that never resolves — produces a
    // transport-layer error, which is what we want to exercise.
    let result =
        probe_esplora_fee_estimates("http://nonexistent-host.invalid").await;
    assert!(result.is_err(), "transport error must surface as Err");
}

#[tokio::test]
async fn esplora_fallback_probe_normalizes_trailing_slash() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/", server.url());
    let mock = server
        .mock("GET", "/fee-estimates")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    assert!(probe_esplora_fee_estimates(&url).await.is_ok());
    mock.assert_async().await;
}

#[tokio::test]
async fn esplora_fallback_select_returns_primary_when_no_fallback_configured() {
    // Primary is unreachable but no fallback exists — we must still
    // return the primary so the rest of the original behavior is preserved.
    let chosen = select_esplora_endpoint("http://nonexistent-host.invalid", None).await;
    assert_eq!(chosen, "http://nonexistent-host.invalid");
}

#[tokio::test]
async fn esplora_fallback_select_returns_primary_when_primary_healthy() {
    let mut server = mockito::Server::new_async().await;
    let url = server.url();
    let mock = server
        .mock("GET", "/fee-estimates")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let chosen = select_esplora_endpoint(&url, Some("http://nonexistent-host.invalid")).await;
    assert_eq!(chosen, url);
    mock.assert_async().await;
}

#[tokio::test]
async fn esplora_fallback_select_switches_to_fallback_when_primary_fails() {
    let mut fallback = mockito::Server::new_async().await;
    let fallback_url = fallback.url();
    let fallback_mock = fallback
        .mock("GET", "/fee-estimates")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let chosen = select_esplora_endpoint(
        "http://nonexistent-host.invalid",
        Some(&fallback_url),
    )
    .await;
    assert_eq!(chosen, fallback_url, "must switch to fallback");
    fallback_mock.assert_async().await;
}

#[tokio::test]
async fn esplora_fallback_select_returns_fallback_even_when_both_fail() {
    // Both unreachable: still return the fallback. The operator
    // configured it explicitly, and letting LDK try the fallback at least
    // exercises their preferred endpoint. LDK will surface a startup
    // error if that endpoint is genuinely down.
    let chosen = select_esplora_endpoint(
        "http://nonexistent-host.invalid",
        Some("http://nonexistent-fallback.invalid"),
    )
    .await;
    assert_eq!(chosen, "http://nonexistent-fallback.invalid");
}

#[tokio::test]
async fn esplora_fallback_select_switches_when_primary_returns_5xx() {
    // Different failure mode (5xx instead of transport) — must also
    // trigger fallover.
    let mut primary = mockito::Server::new_async().await;
    let primary_url = primary.url();
    let primary_mock = primary
        .mock("GET", "/fee-estimates")
        .with_status(503)
        .create_async()
        .await;

    let mut fallback = mockito::Server::new_async().await;
    let fallback_url = fallback.url();
    let fallback_mock = fallback
        .mock("GET", "/fee-estimates")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let chosen = select_esplora_endpoint(&primary_url, Some(&fallback_url)).await;
    assert_eq!(chosen, fallback_url);
    primary_mock.assert_async().await;
    fallback_mock.assert_async().await;
}
