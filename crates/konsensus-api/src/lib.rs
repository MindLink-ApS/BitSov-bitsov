//! konsensus-api — Axum REST + WebSocket API for the BitSov v2 node.
//!
//! This crate provides the HTTP/WebSocket interface that frontends and
//! external clients use to interact with a running node. All endpoints
//! are authenticated via JWT and rate-limited.

#![forbid(unsafe_code)]
//!
//! # Architecture
//!
//! The API server is stateless — all state lives in the shared [`AppState`],
//! which holds references to the node's components (storage, transport,
//! lightning, etc.). Handlers are thin wrappers that delegate to the
//! underlying crate implementations.
//!
//! # Auth gating (L7b)
//!
//! Every handler that touches user state, identity material, payments,
//! peers, or chain data takes the [`auth::AuthUser`] extractor and so
//! returns `401 Unauthorized` for callers without a valid JWT. The
//! `auth_gate` integration tests in `tests/auth_tests.rs` and
//! `tests/payment_tests.rs` lock this in.
//!
//! The router intentionally exposes a small set of routes without the
//! `AuthUser` extractor. Each is documented at the registration site
//! and re-summarised here so the carve-outs are auditable in one place:
//!
//! - `GET  /metrics` — Prometheus exposition format. Scrapers do not
//!   carry JWTs; restrict via network ACL / VPC.
//! - `GET  /api/v1/health` — UNAUTHENTICATED, redacted liveness probe (status
//!   plus non-sensitive counters/flags only), so deploy tooling and the
//!   `NodeOffline` UI can detect a reachable but un-tokened node. Identity,
//!   peer IDs, wallet balance, and LN pubkey are owner-only at `/api/v1/status`.
//! - `GET  /api/v1/status` — owner-only full node status (behind `AuthUser`).
//! - `GET  /api/v1/preflight` and `GET /livez` — cheap operator liveness
//!   probes mounted only when `AppState::operator_probes_enabled` is true.
//!   They do not query Lightning, chain, storage, peers, or user state.
//! - `GET  /api/v1/auth/challenge` — emits a short-lived single-use
//!   Ed25519 challenge. Cannot require a JWT to issue one.
//! - `POST /api/v1/auth/token` — JWT bootstrap via Ed25519 signature over
//!   that challenge. Cannot require a JWT to issue one.
//! - `POST /api/v1/auth/local` — JWT bootstrap restricted to loopback
//!   callers via `ConnectInfo`. The loopback check is the auth gate.
//! - `GET  /api/v1/ws` — WebSocket upgrade. Validates the JWT inline
//!   from the `?token=<jwt>` query parameter inside `ws_handler`
//!   (browsers cannot set `Authorization` on the WS handshake).
//!   Functionally gated; see `ws.rs`.

pub mod audit;
pub mod auth;
pub mod error;
pub mod handlers;
pub mod metrics;
pub mod rate_limit;
pub mod state;
pub mod ws;

pub use audit::AuditLog;
pub use rate_limit::RateLimiter;
pub use state::{AppState, InvoiceResponseData, WsMessage};

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderValue, header};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::get;
use tokio::sync::watch;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

/// Serve Prometheus metrics in text exposition format.
///
/// This endpoint is intentionally unauthenticated — Prometheus scrapers
/// do not carry JWT tokens.  Access should be restricted at the network
/// level (firewall / VPC) to prevent metric data from leaking publicly.
async fn metrics_handler() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        metrics::render(),
    )
}

/// Build the Axum router with all routes and middleware.
pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = if state.cors_enabled {
        CorsLayer::new()
            .allow_origin(cors_allowed_origins())
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
    } else {
        CorsLayer::new()
    };

    let rate_limiter = Arc::clone(&state.rate_limiter);

    Router::new()
        .merge(handlers::health::routes(state.operator_probes_enabled))
        .merge(handlers::messages::routes())
        .merge(handlers::rooms::routes())
        .merge(handlers::peers::routes())
        .merge(handlers::payments::routes())
        .merge(handlers::identity::routes(
            state.sensitive_identity_routes_enabled,
        ))
        .merge(handlers::auth_routes::routes(
            state.sensitive_identity_routes_enabled,
        ))
        .merge(handlers::sessions::routes())
        .merge(handlers::files::routes())
        .merge(handlers::pricing::routes())
        .merge(handlers::routing::routes())
        .merge(handlers::chain::routes())
        .merge(handlers::calendar::routes())
        .merge(handlers::content::routes())
        .merge(handlers::export::routes())
        .merge(handlers::hosting::routes())
        .merge(handlers::invite::routes())
        .merge(handlers::invites::routes())
        .merge(handlers::onboarding::routes())
        .merge(handlers::gossip::routes())
        .merge(ws::routes())
        // Prometheus scrape endpoint — unauthenticated, restrict via network ACL.
        .route("/metrics", get(metrics_handler))
        .layer(middleware::from_fn_with_state(
            rate_limiter,
            rate_limit::rate_limit_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

fn cors_allowed_origins() -> Vec<HeaderValue> {
    parse_cors_allowed_origins(
        &std::env::var("KONSENSUS_CORS_ALLOWED_ORIGINS").unwrap_or_else(|_| {
            [
                "http://localhost:1420",
                "http://127.0.0.1:1420",
                "http://localhost:4173",
                "http://127.0.0.1:4173",
            ]
            .join(",")
        }),
    )
}

fn parse_cors_allowed_origins(raw: &str) -> Vec<HeaderValue> {
    raw.split(',')
        .filter_map(|origin| {
            let origin = origin.trim();
            if origin.is_empty() {
                return None;
            }
            HeaderValue::from_str(origin).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_cors_origins_are_not_wildcard() {
        let origins = parse_cors_allowed_origins("http://localhost:1420, https://node.example");
        assert!(
            origins
                .iter()
                .any(|origin| origin == HeaderValue::from_static("http://localhost:1420"))
        );
        assert!(
            !origins
                .iter()
                .any(|origin| origin == HeaderValue::from_static("*"))
        );
    }
}

/// Start the API server.
///
/// Listens on the given address and serves until the shutdown signal fires.
pub async fn serve(
    addr: SocketAddr,
    state: Arc<AppState>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialise Prometheus metrics recorder (idempotent — safe if called twice).
    if let Err(e) = metrics::init() {
        tracing::warn!(error = %e, "Prometheus metrics recorder init failed — /metrics endpoint will return empty");
    }

    // Start the memory RSS sampler background task (Linux only).
    metrics::spawn_memory_monitor();

    // Start periodic cleanup of expired rate limiter entries
    rate_limit::spawn_cleanup_task(Arc::clone(&state.rate_limiter));

    let app = build_router(state).into_make_service_with_connect_info::<SocketAddr>();

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "API server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.changed().await;
            info!("API server shutting down");
        })
        .await?;

    Ok(())
}
