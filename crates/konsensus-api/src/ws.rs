//! WebSocket real-time message delivery.
//!
//! Connected clients receive new messages as they arrive. The WebSocket
//! endpoint requires JWT authentication before upgrade. Browser clients should
//! send the JWT as a `bitsov.jwt.<token>` WebSocket subprotocol so reverse
//! proxies do not log bearer tokens in URLs. The legacy query parameter remains
//! accepted for local tooling only.

use std::future::{poll_fn, Future};
use std::sync::Arc;
use std::task::Poll;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, warn};

use crate::auth;
use crate::state::AppState;

/// WebSocket connection query parameters.
#[derive(Deserialize)]
pub struct WsParams {
    /// JWT token for authentication.
    #[serde(default)]
    pub token: Option<String>,
}

pub(crate) const WS_PROTOCOL: &str = "bitsov.v1";
const WS_JWT_PROTOCOL_PREFIX: &str = "bitsov.jwt.";

/// `GET /api/v1/ws` — WebSocket connection.
async fn ws_handler(
    _local: crate::local_read::LocalConnection,
    State(state): State<Arc<AppState>>,
    Query(params): Query<WsParams>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(token) = extract_ws_token(params.token.as_deref(), &headers) else {
        warn!("WebSocket auth failed: missing token");
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    };

    // Validate JWT before upgrading — reject with 401 if invalid
    match auth::validate_token(&token, &state.jwt_secret) {
        Ok(claims) => {
            match auth::check_pairing_binding(&state, &claims) {
                Ok(Some(_)) => {}
                Ok(None) => return (StatusCode::FORBIDDEN, "local paired read required").into_response(),
                Err(_) => return (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
            }
            // This endpoint authenticates itself rather than going through the
            // `ScopedAuth` extractor, so it was silently exempt from the #72
            // authorization migration: a token the REST routes refused was still
            // upgraded here and then subscribed to plaintext message and delivery
            // broadcasts. Authorize explicitly, before the upgrade, for both the
            // subprotocol and the legacy query-parameter form.
            if !claims.scp.contains(&auth::Scope::Read) {
                warn!(
                    node_id = %claims.sub,
                    "WebSocket rejected: token lacks the read scope"
                );
                return (StatusCode::FORBIDDEN, "token lacks required scope: read").into_response();
            }
            debug!(node_id = %claims.sub, "WebSocket authenticated");
            ws.protocols([WS_PROTOCOL])
                .on_upgrade(move |socket| handle_ws(socket, state, claims))
                .into_response()
        }
        Err(e) => {
            warn!(error = %e, "WebSocket auth failed");
            (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
        }
    }
}

pub(crate) fn extract_ws_token(query_token: Option<&str>, headers: &HeaderMap) -> Option<String> {
    // Prefer the subprotocol. A `?token=` value must not replace a token the
    // client already sent in a header that proxies are less likely to log.
    let from_protocol = headers
        .get(axum::http::header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .and_then(|protocols| {
            protocols
                .split(',')
                .map(str::trim)
                .find_map(|protocol| protocol.strip_prefix(WS_JWT_PROTOCOL_PREFIX))
        })
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned);
    if from_protocol.is_some() {
        return from_protocol;
    }

    query_token
        .filter(|token| !token.trim().is_empty())
        .map(ToOwned::to_owned)
}

/// Keepalive ping interval for WebSocket connections.
///
/// Prevents intermediate proxies (nginx, load balancers) from closing idle
/// connections. 45 seconds is safely under most proxy timeouts (60-120s).
const WS_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(45);

enum WsEvent {
    Message(Result<Arc<crate::state::WsMessage>, RecvError>),
    Delivery(Result<Arc<crate::state::WsDeliveryStatus>, RecvError>),
    Membrane(Result<Arc<crate::membrane::MembraneEvent>, RecvError>),
    Socket(Option<Result<Message, axum::Error>>),
    Keepalive,
}

/// Handle an authenticated WebSocket connection.
///
/// Subscribes to the broadcast channel and forwards messages (with decrypted
/// plaintext when available) to the client as JSON. Sends periodic keepalive
/// pings to prevent idle connection timeouts.
///
/// Closes the socket when its token expires. Waiting for the next event to
/// notice would take that event off the feed and drop it, and the client's
/// next connection subscribes too late to see it.
async fn handle_ws(mut socket: WebSocket, state: Arc<AppState>, claims: auth::Claims) {
    let mut rx = state.ws_broadcast.subscribe();
    let mut delivery_rx = state.ws_delivery_broadcast.subscribe();
    let mut membrane_rx = state.audit_log.membrane().subscribe();
    let mut keepalive = tokio::time::interval(WS_KEEPALIVE_INTERVAL);
    // The first tick fires immediately — skip it since we just connected.
    keepalive.tick().await;
    let token_expired = wait_until_expired(claims.exp, chrono::Utc::now);
    tokio::pin!(token_expired);

    loop {
        let event = tokio::select! {
            // Polled first: once the token has expired, the stream closes
            // without taking another event off the feed.
            biased;

            () = &mut token_expired => {
                debug!("WebSocket token expired; closing the stream");
                break;
            }

            // Only expiry has strict priority. Share service among all other
            // ready sources, even while the message receiver is backlogged.
            event = async {
                tokio::select! {
                    result = rx.recv() => WsEvent::Message(result),
                    result = delivery_rx.recv() => WsEvent::Delivery(result),
                    result = membrane_rx.recv() => WsEvent::Membrane(result),
                    msg = socket.recv() => WsEvent::Socket(msg),
                    _ = keepalive.tick() => WsEvent::Keepalive,
                }
            } => event,
        };

        match event {
            // Forward new messages from broadcast channel to WebSocket
            WsEvent::Message(result) => {
                match result {
                    Ok(ws_msg) => {
                        if !stream_authorized(&state, &claims) { break; }
                        // Serialize WsMessage to JSON for the client
                        match serde_json::to_string(ws_msg.as_ref()) {
                            Ok(json) => {
                                if socket.send(Message::Text(json)).await.is_err() {
                                    debug!("WebSocket client disconnected");
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to serialize message for WS");
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(missed = n, "WebSocket client lagged, dropped messages");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        debug!("broadcast channel closed");
                        break;
                    }
                }
            }

            // Forward delivery status updates to WebSocket
            WsEvent::Delivery(result) => {
                match result {
                    Ok(status) => {
                        if !stream_authorized(&state, &claims) { break; }
                        match serde_json::to_string(status.as_ref()) {
                            Ok(json) => {
                                if socket.send(Message::Text(json)).await.is_err() {
                                    debug!("WebSocket client disconnected");
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to serialize delivery status for WS");
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(missed = n, "WebSocket client lagged, dropped delivery status events");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        // Delivery channel closed — continue with message channel only
                    }
                }
            }

            // Forward membrane events (N2): admission decisions at the gate.
            WsEvent::Membrane(result) => {
                match result {
                    Ok(event) => {
                        if !stream_authorized(&state, &claims) { break; }
                        match serde_json::to_string(event.as_ref()) {
                            Ok(json) => {
                                if socket.send(Message::Text(json)).await.is_err() {
                                    debug!("WebSocket client disconnected");
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to serialize membrane event for WS");
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        // The ring (`GET /api/v1/membrane`) still holds them.
                        warn!(missed = n, "WebSocket client lagged, dropped membrane events");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {}
                }
            }

            // Handle incoming messages from the client
            WsEvent::Socket(msg) => {
                match msg {
                    Some(Ok(Message::Ping(data))) => match socket.send(Message::Pong(data)).await {
                        Ok(()) => {}
                        Err(_) => break,
                    },
                    Some(Ok(Message::Close(_))) | None => {
                        debug!("WebSocket client closed connection");
                        break;
                    }
                    Some(Err(e)) => {
                        debug!(error = %e, "WebSocket error");
                        break;
                    }
                    Some(Ok(Message::Text(text))) => {
                        // Handle application-level ping from frontend
                        if let Ok(val) = konsensus_core::wire_json::from_str::<serde_json::Value>(&text) {
                            if val.get("type").and_then(|t| t.as_str()) == Some("ping") {
                                let pong = r#"{"type":"pong"}"#.to_string();
                                if socket.send(Message::Text(pong)).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    _ => {
                        // Ignore other binary messages from client
                    }
                }
            }

            // Send keepalive pings to prevent idle connection timeouts
            WsEvent::Keepalive => {
                if !stream_authorized(&state, &claims) { break; }
                if socket.send(Message::Ping(vec![0x6b, 0x61])).await.is_err() {
                    debug!("WebSocket client disconnected during keepalive");
                    break;
                }
            }
        }
    }
}

// Re-check before each plaintext/delivery send, not just at upgrade: already
// connected clients lose access when their pairing is revoked or rebound.
fn stream_authorized(state: &Arc<AppState>, claims: &auth::Claims) -> bool {
    claims.exp > chrono::Utc::now().timestamp()
        && claims.scp.contains(&auth::Scope::Read)
        && matches!(auth::check_pairing_binding(state, claims), Ok(Some(_)))
}

// Time left until `stream_authorized` starts refusing on expiry: from the
// first instant of second `exp`. Milliseconds, so the stream is not left open
// for up to a second after its token stops being valid.
fn until_expiry(exp: i64, now: chrono::DateTime<chrono::Utc>) -> std::time::Duration {
    let left_ms = exp.saturating_mul(1000).saturating_sub(now.timestamp_millis());
    std::time::Duration::from_millis(u64::try_from(left_ms).unwrap_or(0))
}

async fn wait_until_expired(exp: i64, now: impl Fn() -> chrono::DateTime<chrono::Utc>) {
    loop {
        let remaining = until_expiry(exp, now());
        if remaining.is_zero() {
            return;
        }
        // Re-read wall time at least once a second while idle, retaining the
        // exact expiry deadline when it is closer. Monotonic time can diverge
        // from JWT wall time after a clock adjustment or system suspend.
        let recheck = tokio::time::sleep(remaining.min(std::time::Duration::from_secs(1)));
        tokio::pin!(recheck);
        poll_fn(|cx| {
            // The biased outer select polls this before the feed on every
            // wake, even if the periodic recheck timer is still pending.
            if until_expiry(exp, now()).is_zero() {
                Poll::Ready(())
            } else {
                recheck.as_mut().poll(cx)
            }
        })
        .await;
    }
}

/// Registers the WebSocket upgrade route for real-time event streaming.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/ws", get(ws_handler))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn expiry_preempts_ready_event_after_wall_clock_step() {
        let now = std::cell::Cell::new(chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap());
        let exp = now.get().timestamp() + 3600;
        let expired = wait_until_expired(exp, || now.get());
        tokio::pin!(expired);
        assert!(futures::poll!(&mut expired).is_pending());

        // Wall time jumps an hour, while the monotonic timer has not advanced.
        now.set(chrono::DateTime::from_timestamp(exp, 0).unwrap());
        let (tx, mut rx) = tokio::sync::broadcast::channel(1);
        tx.send("first event after expiry").unwrap();
        tokio::select! {
            biased;
            () = &mut expired => {}
            _ = rx.recv() => panic!("expired stream consumed the next broadcast event"),
        }
        assert_eq!(rx.try_recv(), Ok("first event after expiry"));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_expiry_rechecks_wall_clock_after_step() {
        use std::sync::atomic::{AtomicI64, Ordering};

        let now = Arc::new(AtomicI64::new(1_700_000_000));
        let exp = 1_700_003_600;
        let clock = Arc::clone(&now);
        let expired = tokio::spawn(wait_until_expired(exp, move || {
            chrono::DateTime::from_timestamp(clock.load(Ordering::SeqCst), 0).unwrap()
        }));
        tokio::task::yield_now().await;
        assert!(!expired.is_finished());

        now.store(exp, Ordering::SeqCst);
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(expired.is_finished(), "idle stream stayed open after expiry");
        expired.await.unwrap();
    }

    #[test]
    fn extract_ws_token_prefers_subprotocol_over_query() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::SEC_WEBSOCKET_PROTOCOL,
            "bitsov.v1, bitsov.jwt.header-token".parse().unwrap(),
        );

        assert_eq!(
            extract_ws_token(Some("query-token"), &headers).as_deref(),
            Some("header-token")
        );
    }

    #[test]
    fn extract_ws_token_accepts_query_when_subprotocol_is_absent() {
        let headers = HeaderMap::new();
        assert_eq!(
            extract_ws_token(Some("query-token"), &headers).as_deref(),
            Some("query-token")
        );
    }

    #[test]
    fn extract_ws_token_accepts_subprotocol_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::SEC_WEBSOCKET_PROTOCOL,
            "bitsov.v1, bitsov.jwt.header-token".parse().unwrap(),
        );

        assert_eq!(
            extract_ws_token(None, &headers).as_deref(),
            Some("header-token")
        );
    }

    #[test]
    fn extract_ws_token_rejects_missing_token() {
        let headers = HeaderMap::new();
        assert!(extract_ws_token(None, &headers).is_none());
    }
}
