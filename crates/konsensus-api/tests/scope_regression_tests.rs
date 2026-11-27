//! Regressions for the three authorization defects a review found on 9df55f2 (genome #72).
//!
//! Each of these passed CI and passed the scope coverage tests while broken, so each one
//! is pinned here by behaviour rather than by source inspection:
//!
//! 1. `/onboarding/start` demanded `admin`, which the app's loopback token cannot hold —
//!    the shipped funding flow returned 403, beyond the restore regression already filed.
//! 2. `GET /ws` authenticated itself and never checked scopes, so a token the REST routes
//!    refused was still upgraded and subscribed to plaintext message broadcasts.
//! 3. Three calendar handlers required only `admin` while calling `create_payment_proof`,
//!    so an admin-without-spend token passed authorization for an operation that pays.
//!    Each is now refused on a node that would really pay: the same request with every
//!    scope reaches a payment, so the zero-payment count after the refusal is evidence.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{
    setup_e2ee_session, test_router as build_router, test_state, test_state_with_lightning,
    ConnectedStubTransport, CountingLightning,
};
use konsensus_api::auth::{self, Scope};
use konsensus_api::state::AppState;
use std::sync::Arc;
use tower::ServiceExt;

fn token(scopes: Vec<Scope>) -> String {
    let state = test_state();
    auth::create_token(&state.identity.node_id().to_hex(), &state.jwt_secret, scopes).unwrap()
}

/// Exactly what `POST /auth/local` mints.
fn loopback() -> String {
    token(Scope::loopback_only())
}

fn request(method: &str, uri: &str, tok: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {tok}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

// ─── 1. The app's funding flow must actually work ──────────────────────────────

/// The app sends exactly this body from `fund_start`. Previously 403.
///
/// Asserted end to end on one state: the POST succeeds, hands back a funding address and
/// the required amount, and the state the app then polls reflects it. A status-code-only
/// test would not have distinguished "authorized" from "authorized and useless".
#[tokio::test]
async fn loopback_token_can_start_full_tier_funding() {
    let state = test_state();
    let tok = loopback();

    let resp = build_router(Arc::clone(&state))
        .oneshot(request(
            "POST",
            "/api/v1/onboarding/start",
            &tok,
            r#"{"tier":"full","funding_amount_sats":50000}"#,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the shipped app's funding start must not require admin"
    );

    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["current_step"], "funding");
    assert_eq!(json["funding_amount_sats_required"], 50000);
    assert!(
        json["funding_address"].as_str().is_some_and(|a| !a.is_empty()),
        "funding start must return a funding address, got {json}"
    );

    // The screen then polls this. It must reflect the state just created.
    let resp = build_router(state)
        .oneshot(request("GET", "/api/v1/onboarding/state", &tok, ""))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["current_step"], "funding");
    assert_eq!(json["funding_amount_sats_required"], 50000);
}

/// The administrative half of the same route stays behind `admin`. Preserving funding must
/// not have widened the route wholesale.
#[tokio::test]
async fn loopback_token_cannot_start_light_tier_onboarding() {
    let resp = build_router(test_state())
        .oneshot(request(
            "POST",
            "/api/v1/onboarding/start",
            &loopback(),
            r#"{"tier":"light"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "invite-based onboarding establishes a relationship and must still require admin"
    );
}

/// Positive control: the light path is reachable with real authority, so the test above is
/// about the scope and not about a broken route.
#[tokio::test]
async fn full_token_can_start_light_tier_onboarding() {
    let resp = build_router(test_state())
        .oneshot(request(
            "POST",
            "/api/v1/onboarding/start",
            &token(Scope::all()),
            r#"{"tier":"light"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── 2. WebSocket admission must check scopes ─────────────────────────────────

/// A real WebSocket handshake against a real listener.
///
/// `oneshot` cannot be used here: axum's `WebSocketUpgrade` extractor needs hyper's
/// `OnUpgrade` extension, which only exists on a genuinely served connection, so a
/// `oneshot` request is rejected with 426 before the handler body ever runs. That 426
/// would mask both the defect and its fix, so these tests serve the router on a loopback
/// port and speak the handshake over TCP, reading back the real status line.
async fn ws_handshake_status(query: &str, protocol_header: Option<&str>) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = konsensus_api::build_router_for_addr(test_state(), addr);
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .unwrap();
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let protocol_line = protocol_header
        .map(|p| format!("Sec-WebSocket-Protocol: {p}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "GET /api/v1/ws{query} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         {protocol_line}\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).await.unwrap();
    let status_line = String::from_utf8_lossy(&buf[..n]);
    server.abort();

    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status code in response: {status_line:?}"))
}

/// A token without `read` is refused on REST. It must also be refused the upgrade, because
/// the socket immediately subscribes to plaintext message and delivery broadcasts.
#[tokio::test]
async fn ws_upgrade_requires_read_scope_via_query() {
    let tok = token(vec![Scope::Receive]);
    let status = ws_handshake_status(&format!("?token={tok}"), None).await;
    assert_eq!(
        status, 403,
        "a token lacking read must not be upgraded, got {status}"
    );
}

/// Same check for the subprotocol form, which is what browsers use. Both paths funnel
/// through one validation site, and this proves neither is exempt.
#[tokio::test]
async fn ws_upgrade_requires_read_scope_via_subprotocol() {
    let tok = token(vec![Scope::Receive]);
    let status =
        ws_handshake_status("", Some(&format!("bitsov.v1, bitsov.jwt.{tok}"))).await;
    assert_eq!(status, 403);
}

/// An empty scope set is the shape a pre-scope token would have had if it parsed. It must
/// not be treated as "no restrictions".
#[tokio::test]
async fn ws_upgrade_rejects_empty_scope_set() {
    let tok = token(vec![]);
    let status = ws_handshake_status(&format!("?token={tok}"), None).await;
    assert_eq!(status, 403);
}

/// Read alone is insufficient for the local paired observability stream.
/// Paired positive controls and revocation are tested in pairing_tests.
#[tokio::test]
async fn ws_upgrade_refuses_an_unpaired_read_scoped_token() {
    let status = ws_handshake_status(&format!("?token={}", loopback()), None).await;
    assert_eq!(
        status, 403,
        "an unpaired token must not open the observability stream, got {status}"
    );
}

// ─── 3. Paid calendar operations must require spend ───────────────────────────

const ADMIN_NOT_SPEND: &[Scope] = &[Scope::Read, Scope::Receive, Scope::Admin];

/// A node that would pay on every calendar path: a counting wallet, the default nonzero
/// calendar prices, a peer that is connected, has an established E2EE session and a
/// verified Lightning key (so a payment goes out as a keysend), and an event this node
/// organizes with that peer attending (for the update path).
///
/// The refusals below are only evidence if the same request would otherwise have paid,
/// so each test first sends it with an admin-without-spend token (refused, nothing
/// dispatched) and then, on the same node, with a spend-authorized token (dispatched).
async fn paying_node() -> (Arc<AppState>, Arc<CountingLightning>, String) {
    let ln = Arc::new(CountingLightning::default());
    let mut state = test_state_with_lightning(Arc::clone(&ln) as Arc<_>);
    let peer_id = setup_e2ee_session(&state.session_manager).await;
    let invoice_requests = state.invoice_requests.clone();
    Arc::get_mut(&mut state).unwrap().transport =
        Arc::new(ConnectedStubTransport::new(vec![peer_id], invoice_requests));
    state.peer_ln_pubkeys.lock().await.insert(
        peer_id,
        konsensus_api::state::PeerLightningKey::Verified(format!("02{}", "aa".repeat(32))),
    );
    let peer = peer_id.to_hex();
    state
        .storage
        .store_calendar_event(&konsensus_storage::CalendarEventRecord {
            id: "evt-1".into(),
            message_id: None,
            organizer: state.identity.node_id().to_hex(),
            title: "standup".into(),
            description: None,
            start_ms: 1_800_000_000_000,
            end_ms: 1_800_003_600_000,
            tz: "UTC".into(),
            location: None,
            attendees_json: serde_json::json!([peer]).to_string(),
            recurrence_json: None,
            color: None,
            created_at: String::new(),
            parent_id: None,
        })
        .await
        .unwrap();
    (state, ln, peer)
}

/// Every Lightning call that would move value or ask for an invoice.
fn dispatched(ln: &CountingLightning) -> usize {
    ln.money() + ln.invoices()
}

/// Refused with admin-without-spend and nothing dispatched; then, on the same node, the
/// same request with every scope reaches a payment.
async fn refused_on_a_path_that_pays(method: &str, uri: &str, body: &str) {
    let (state, ln, _) = paying_node().await;
    let refused = build_router(Arc::clone(&state))
        .oneshot(request(method, uri, &token(ADMIN_NOT_SPEND.to_vec()), body))
        .await
        .unwrap();
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "{method} {uri} can dispatch a payment and must require spend, got {}",
        refused.status()
    );
    assert_eq!(dispatched(&ln), 0, "{method} {uri} dispatched a payment despite refusing");

    let allowed = build_router(state)
        .oneshot(request(method, uri, &token(Scope::all()), body))
        .await
        .unwrap();
    let status = allowed.status();
    let bytes = axum::body::to_bytes(allowed.into_body(), 100_000).await.unwrap();
    assert!(
        dispatched(&ln) > 0,
        "{method} {uri} did not reach a payment with every scope ({status}: {}), so the refusal above proves nothing",
        String::from_utf8_lossy(&bytes)
    );
}

#[tokio::test]
async fn admin_without_spend_cannot_create_a_paid_calendar_event() {
    let (_, _, peer) = paying_node().await;
    let body = serde_json::json!({
        "title": "standup", "start": 1_800_000_000_000u64, "end": 1_800_003_600_000u64,
        "attendees": [peer], "description": "sync",
    });
    refused_on_a_path_that_pays("POST", "/api/v1/calendar/events", &body.to_string()).await;
}

#[tokio::test]
async fn admin_without_spend_cannot_update_a_paid_calendar_event() {
    refused_on_a_path_that_pays(
        "PUT",
        "/api/v1/calendar/events/evt-1",
        r#"{"title":"standup moved","start":1800007200000,"end":1800010800000}"#,
    )
    .await;
}

#[tokio::test]
async fn admin_without_spend_cannot_rsvp() {
    let (_, _, peer) = paying_node().await;
    let body = serde_json::json!({ "response": "accepted", "organizer": peer });
    refused_on_a_path_that_pays("POST", "/api/v1/calendar/events/evt-1/rsvp", &body.to_string()).await;
}
