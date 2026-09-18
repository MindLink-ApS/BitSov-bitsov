//! genome #72 — negative tests: what a loopback token is REFUSED.
//!
//! The claim these tests support is narrow and deliberate: *a token minted by
//! `POST /auth/local` cannot pay, open channels, restore an identity, reveal a mnemonic, or
//! export the relationship graph.* They do not show that local malware "can only read the
//! balance" — any process may still call `/auth/local` and obtain `read` + `receive`, which
//! includes reading message history and generating addresses. The blast radius is smaller;
//! it is not gone, and nothing here should be quoted as saying otherwise.
//!
//! Routes are declared once in the tables below and reused by both the scope assertions and
//! `every_asserted_route_actually_exists`, so a mistyped path or method fails loudly instead
//! of passing vacuously as a 404.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{test_router as build_router, test_state};
use konsensus_api::auth::{self, Scope};
use tower::ServiceExt;

type Route = (&'static str, &'static str, &'static str); // method, uri, body

/// Moving value. Must be refused a loopback token.
const SPEND_ROUTES: &[Route] = &[
    ("POST", "/api/v1/payments/pay", r#"{"invoice":"lnbc1"}"#),
    ("POST", "/api/v1/payments/keysend", r#"{"node_id":"ab","amount_msat":1000}"#),
    ("POST", "/api/v1/payments/send-onchain", r#"{"address":"bc1q","amount_sat":1000}"#),
    ("POST", "/api/v1/payments/open-channel", r#"{"node_id":"ab","amount_sat":20000}"#),
    ("POST", "/api/v1/payments/close-channel", r#"{"channel_id":"ab"}"#),
];

/// Paid messaging is spending: under "payment IS the connection" a send settles a payment,
/// so it must not be reachable with a token that cannot spend.
const PAID_MESSAGE_ROUTES: &[Route] = &[
    ("POST", "/api/v1/messages", r#"{"recipient":"ab","content":"hi"}"#),
    ("POST", "/api/v1/messages/compose", r#"{"recipient":"ab","subject":"s","body":"b"}"#),
];

/// Key material and identity replacement — the operations that must never follow from
/// merely being a process on the machine.
const IDENTITY_ROUTES: &[Route] = &[
    ("POST", "/api/v1/identity/mnemonic", "{}"),
    ("POST", "/api/v1/identity/restore", r#"{"mnemonic":"x"}"#),
    ("POST", "/api/v1/identity/verify-mnemonic", r#"{"mnemonic":"x"}"#),
];

/// Bulk relationship export and node reconfiguration.
const ADMIN_ROUTES: &[Route] = &[
    ("GET", "/api/v1/export/bundle", ""),
    ("GET", "/api/v1/peers/export", ""),
    ("POST", "/api/v1/peers/import", r#"{"peers":[]}"#),
    ("POST", "/api/v1/gossip/publish", "{}"),
];

/// The funding flow the app actually ships. Must keep working on `read` + `receive`.
const FUNDING_FLOW_ROUTES: &[Route] = &[
    ("GET", "/api/v1/identity", ""),
    ("GET", "/api/v1/status", ""),
    ("GET", "/api/v1/payments/balance", ""),
    ("GET", "/api/v1/payments/funding-address", ""),
];

/// Exactly what `POST /auth/local` mints.
fn loopback_token(secret: &str, node_id: &str) -> String {
    auth::create_token(node_id, secret, Scope::loopback_only()).unwrap()
}

/// Exactly what the key-proof issuer `POST /auth/token` mints.
fn full_token(secret: &str, node_id: &str) -> String {
    auth::create_token(node_id, secret, Scope::all()).unwrap()
}

fn creds() -> (String, String) {
    let state = test_state();
    (state.jwt_secret.clone(), state.identity.node_id().to_hex())
}

async fn call(method: &str, uri: &str, token: &str, body: &str) -> StatusCode {
    let state = test_state();
    let app = build_router(state);
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

async fn assert_all_forbidden(routes: &[Route], token: &str, why: &str) {
    for (method, uri, body) in routes {
        let status = call(method, uri, token, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri} must be 403 for a loopback token ({why}), got {status}"
        );
    }
}

#[tokio::test]
async fn loopback_token_cannot_spend() {
    let (secret, node_id) = creds();
    assert_all_forbidden(SPEND_ROUTES, &loopback_token(&secret, &node_id), "moves value").await;
}

#[tokio::test]
async fn loopback_token_cannot_send_paid_messages() {
    let (secret, node_id) = creds();
    assert_all_forbidden(
        PAID_MESSAGE_ROUTES,
        &loopback_token(&secret, &node_id),
        "a send settles a payment",
    )
    .await;
}

#[tokio::test]
async fn loopback_token_cannot_touch_identity() {
    let (secret, node_id) = creds();
    assert_all_forbidden(
        IDENTITY_ROUTES,
        &loopback_token(&secret, &node_id),
        "key material and identity replacement",
    )
    .await;
}

#[tokio::test]
async fn loopback_token_cannot_administer() {
    let (secret, node_id) = creds();
    assert_all_forbidden(
        ADMIN_ROUTES,
        &loopback_token(&secret, &node_id),
        "bulk export and reconfiguration",
    )
    .await;
}

/// A security change that silently broke the shipped product would just be reverted later,
/// so the funding flow is asserted as explicitly as the refusals.
#[tokio::test]
async fn loopback_token_can_still_run_the_funding_flow() {
    let (secret, node_id) = creds();
    let token = loopback_token(&secret, &node_id);

    for (method, uri, body) in FUNDING_FLOW_ROUTES {
        let status = call(method, uri, &token, body).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{uri} is part of the shipped funding flow and must remain reachable, got {status}"
        );
    }
}

/// Both issuers once shared a single `create_token`. This guards against the loopback
/// constraint silently narrowing the key-proof path too.
#[tokio::test]
async fn key_proof_token_retains_full_authority() {
    let (secret, node_id) = creds();
    let token = full_token(&secret, &node_id);

    for (method, uri, body) in SPEND_ROUTES
        .iter()
        .chain(IDENTITY_ROUTES)
        .chain(ADMIN_ROUTES)
        .chain(PAID_MESSAGE_ROUTES)
    {
        let status = call(method, uri, &token, body).await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri}: a token proving possession of the node key must retain authority"
        );
    }
}

/// Migration: a token minted before scopes existed is REJECTED — not silently granted full
/// authority, and not silently downgraded to `read` to keep a screen green.
#[tokio::test]
async fn pre_scope_tokens_are_rejected_not_upgraded() {
    let (secret, node_id) = creds();

    // A token in the old shape: {sub, iat, exp} with no `scp` claim, correctly signed.
    let header = base64_url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let now = chrono::Utc::now().timestamp();
    let payload =
        base64_url(format!(r#"{{"sub":"{node_id}","iat":{now},"exp":{}}}"#, now + 3600).as_bytes());
    let sig = hmac_sha256_b64(&format!("{header}.{payload}"), &secret);
    let legacy = format!("{header}.{payload}.{sig}");

    // Not 403 — that would mean the claims parsed and only the scope was missing. The token
    // must fail validation outright, on read routes as much as on spend routes.
    for (method, uri, body) in FUNDING_FLOW_ROUTES.iter().chain(SPEND_ROUTES) {
        let status = call(method, uri, &legacy, body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {uri}: a pre-scope token must be rejected outright, got {status}"
        );
    }
}

/// Guard against a vacuous suite: every route asserted above must actually exist with the
/// method used. A typo would otherwise return 404 and quietly satisfy the `assert_ne!`s.
#[tokio::test]
async fn every_asserted_route_actually_exists() {
    let (secret, node_id) = creds();
    let token = full_token(&secret, &node_id);

    for (method, uri, body) in SPEND_ROUTES
        .iter()
        .chain(PAID_MESSAGE_ROUTES)
        .chain(IDENTITY_ROUTES)
        .chain(ADMIN_ROUTES)
        .chain(FUNDING_FLOW_ROUTES)
    {
        let status = call(method, uri, &token, body).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "{method} {uri} is asserted by these tests but is not a route — assertion is vacuous"
        );
        assert_ne!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {uri} is asserted with a method the router rejects — assertion is vacuous"
        );
    }
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hmac_sha256_b64(signing_input: &str, secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signing_input.as_bytes());
    base64_url(&mac.finalize().into_bytes())
}
