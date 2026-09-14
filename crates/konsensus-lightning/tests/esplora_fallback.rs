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
    assert!(
        result.is_err(),
        "5xx should produce Err so caller can fall over"
    );
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
    let result = probe_esplora_fee_estimates("http://nonexistent-host.invalid").await;
    assert!(result.is_err(), "transport error must surface as Err");
}

#[tokio::test]
async fn esplora_fallback_probe_normalizes_trailing_slash() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/", server.url());
    let mock = server
        .mock("GET", "/fee-estimates")
        .with_status(200)
        // #66: fixture updated from `{}` to a real fee map. An empty map used to
        // pass because the probe never read the body; it is now correctly a
        // failure, so this test must serve a healthy endpoint to test the
        // trailing-slash normalisation it is actually about.
        .with_body("{\"1\":25.0,\"6\":10.0}")
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
        // #66: "healthy" now means usable fee data, not merely HTTP 200.
        .with_body("{\"1\":25.0,\"6\":10.0}")
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

    let chosen =
        select_esplora_endpoint("http://nonexistent-host.invalid", Some(&fallback_url)).await;
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

// ---------------------------------------------------------------------------
// genome #66 — a 2xx is not evidence. The probe must validate the fee payload,
// or the fallback is unreachable: LDK is handed a "healthy" endpoint whose body
// it cannot use and refuses to start with `Failed to update fee rate estimates`.
// ---------------------------------------------------------------------------

/// The exact production shape: a rate-limited primary answering 429.
#[tokio::test]
async fn issue66_probe_err_on_rate_limited_primary() {
    let mut server = mockito::Server::new_async().await;
    let url = server.url();
    let mock = server
        .mock("GET", "/fee-estimates")
        .with_status(429)
        .with_body("{\"error\":\"rate limited\"}")
        .create_async()
        .await;

    let err = probe_esplora_fee_estimates(&url).await.unwrap_err();
    assert!(err.contains("429"), "error should name the status: {err}");
    mock.assert_async().await;
}

/// 200 with a body LDK cannot consume — the #66 case that used to pass.
#[tokio::test]
async fn issue66_probe_err_on_malformed_success_body() {
    for (label, body) in [
        (
            "html error page",
            "<!doctype html><h1>Service Unavailable</h1>",
        ),
        (
            "deprecation notice",
            "{\"message\":\"endpoint deprecated, use /v1/fees/precise\"}",
        ),
        ("wrong value type", "{\"1\":\"fast\",\"6\":\"slow\"}"),
    ] {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();
        let mock = server
            .mock("GET", "/fee-estimates")
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        let result = probe_esplora_fee_estimates(&url).await;
        assert!(
            result.is_err(),
            "{label}: HTTP 200 with an unusable body must fail the probe, else the \
             fallback is never consulted and LDK dies on its own fee fetch (#66)"
        );
        mock.assert_async().await;
    }
}

/// Parsable, well-typed, but carries no usable rate.
#[tokio::test]
async fn issue66_probe_err_on_empty_or_nonpositive_estimates() {
    for (label, body) in [
        ("empty map", "{}"),
        ("zero rates", "{\"1\":0.0,\"6\":0.0}"),
        ("non-numeric targets", "{\"fastestFee\":12.0}"),
    ] {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();
        let mock = server
            .mock("GET", "/fee-estimates")
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        let result = probe_esplora_fee_estimates(&url).await;
        assert!(
            result.is_err(),
            "{label}: no usable fee rate must fail the probe"
        );
        mock.assert_async().await;
    }
}

/// A real Esplora map still passes — the fix must not reject healthy endpoints.
#[tokio::test]
async fn issue66_probe_ok_on_real_esplora_shape() {
    let mut server = mockito::Server::new_async().await;
    let url = server.url();
    let mock = server
        .mock("GET", "/fee-estimates")
        .with_status(200)
        .with_body("{\"1\":41.2,\"2\":30.0,\"6\":12.5,\"144\":2.0,\"1008\":1.0}")
        .create_async()
        .await;

    assert!(probe_esplora_fee_estimates(&url).await.is_ok());
    mock.assert_async().await;
}

/// The end-to-end #66 claim: primary answers 200-but-unusable, and selection
/// now reaches the healthy fallback instead of pinning the node to the primary.
#[tokio::test]
async fn issue66_unusable_primary_falls_over_to_healthy_fallback() {
    let mut primary = mockito::Server::new_async().await;
    let primary_url = primary.url();
    let primary_mock = primary
        .mock("GET", "/fee-estimates")
        .with_status(200)
        .with_body("{\"message\":\"endpoint deprecated\"}")
        .create_async()
        .await;

    let mut fallback = mockito::Server::new_async().await;
    let fallback_url = fallback.url();
    let fallback_mock = fallback
        .mock("GET", "/fee-estimates")
        .with_status(200)
        .with_body("{\"1\":25.0,\"6\":10.0}")
        .create_async()
        .await;

    let chosen = select_esplora_endpoint(&primary_url, Some(&fallback_url)).await;
    assert_eq!(
        chosen, fallback_url,
        "a primary that answers 2xx with unusable fee data must not win (#66)"
    );
    primary_mock.assert_async().await;
    fallback_mock.assert_async().await;
}

// ---------------------------------------------------------------------------
// #66 round 2 (Codex R1): the probe must mirror LDK's CONCRETE type.
// esplora-client 0.12.3 parses the whole body as HashMap<u16, f64>, so one key
// LDK cannot represent fails its entire fetch. A probe that accepts "at least
// one usable entry" would pass these and still kill startup — same defect, one
// layer in.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn issue66_probe_err_on_mixed_valid_and_invalid_keys() {
    for (label, body) in [
        (
            "non-numeric key beside a valid one",
            "{\"1\":10.0,\"invalid\":1.0}",
        ),
        (
            "u16-overflow key beside a valid one",
            "{\"1\":10.0,\"65536\":1.0}",
        ),
        ("negative key beside a valid one", "{\"1\":10.0,\"-1\":1.0}"),
    ] {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();
        let mock = server
            .mock("GET", "/fee-estimates")
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        let result = probe_esplora_fee_estimates(&url).await;
        assert!(
            result.is_err(),
            "{label}: LDK deserializes the WHOLE map into HashMap<u16, f64>, so this \
             body fails its fetch — the probe must reject it too, or the fallback is \
             suppressed and startup dies anyway (#66)"
        );
        mock.assert_async().await;
    }
}

/// The boundary itself: 65535 is representable, 65536 is not.
#[tokio::test]
async fn issue66_probe_u16_key_boundary() {
    for (body, want_ok) in [("{\"65535\":1.5}", true), ("{\"65536\":1.5}", false)] {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();
        let mock = server
            .mock("GET", "/fee-estimates")
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        assert_eq!(
            probe_esplora_fee_estimates(&url).await.is_ok(),
            want_ok,
            "u16 boundary: {body} should be ok={want_ok}"
        );
        mock.assert_async().await;
    }
}

/// Selection must reach the fallback when the primary carries a key LDK rejects.
#[tokio::test]
async fn issue66_mixed_key_primary_falls_over_to_healthy_fallback() {
    let mut primary = mockito::Server::new_async().await;
    let primary_url = primary.url();
    let primary_mock = primary
        .mock("GET", "/fee-estimates")
        .with_status(200)
        .with_body("{\"1\":10.0,\"invalid\":1.0}")
        .create_async()
        .await;

    let mut fallback = mockito::Server::new_async().await;
    let fallback_url = fallback.url();
    let fallback_mock = fallback
        .mock("GET", "/fee-estimates")
        .with_status(200)
        .with_body("{\"1\":25.0,\"6\":10.0}")
        .create_async()
        .await;

    let chosen = select_esplora_endpoint(&primary_url, Some(&fallback_url)).await;
    assert_eq!(
        chosen, fallback_url,
        "a primary whose map LDK cannot deserialize must not win (#66)"
    );
    primary_mock.assert_async().await;
    fallback_mock.assert_async().await;
}
