//! WebSocket real-time message delivery.
//!
//! Connected clients receive new messages as they arrive. The WebSocket
//! endpoint requires JWT authentication via a query parameter.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::auth;
use crate::state::AppState;

/// WebSocket connection query parameters.
#[derive(Deserialize)]
pub struct WsParams {
    /// JWT token for authentication.
    pub token: String,
}

/// `GET /api/v1/ws?token=<jwt>` — WebSocket connection.
async fn ws_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<WsParams>,
    ws: WebSocketUpgrade,
) -> Response {
    // Validate JWT before upgrading — reject with 401 if invalid
    match auth::validate_token(&params.token, &state.jwt_secret) {
        Ok(claims) => {
            debug!(node_id = %claims.sub, "WebSocket authenticated");
            ws.on_upgrade(move |socket| handle_ws(socket, state))
                .into_response()
        }
        Err(e) => {
            warn!(error = %e, "WebSocket auth failed");
            (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
        }
    }
}

/// Keepalive ping interval for WebSocket connections.
///
/// Prevents intermediate proxies (nginx, load balancers) from closing idle
/// connections. 45 seconds is safely under most proxy timeouts (60-120s).
const WS_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(45);

/// Handle an authenticated WebSocket connection.
///
/// Subscribes to the broadcast channel and forwards messages (with decrypted
/// plaintext when available) to the client as JSON. Sends periodic keepalive
/// pings to prevent idle connection timeouts.
async fn handle_ws(mut socket: WebSocket, state: Arc<AppState>) {
    let mut rx = state.ws_broadcast.subscribe();
    let mut delivery_rx = state.ws_delivery_broadcast.subscribe();
    let mut keepalive = tokio::time::interval(WS_KEEPALIVE_INTERVAL);
    // The first tick fires immediately — skip it since we just connected.
    keepalive.tick().await;

    loop {
        tokio::select! {
            // Forward new messages from broadcast channel to WebSocket
            result = rx.recv() => {
                match result {
                    Ok(ws_msg) => {
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
            result = delivery_rx.recv() => {
                match result {
                    Ok(status) => {
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

            // Handle incoming messages from the client
            msg = socket.recv() => {
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
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
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
            _ = keepalive.tick() => {
                if socket.send(Message::Ping(vec![0x6b, 0x61])).await.is_err() {
                    debug!("WebSocket client disconnected during keepalive");
                    break;
                }
            }
        }
    }
}

/// Registers the WebSocket upgrade route for real-time event streaming.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/ws", get(ws_handler))
}
