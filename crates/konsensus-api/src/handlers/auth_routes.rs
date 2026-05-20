//! Authentication endpoints — token issuance.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::audit::events;
use crate::auth;
use crate::error::ApiError;
use crate::state::AppState;

/// Token request — the client proves they know the node's signing key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    /// Hex-encoded Ed25519 signature of the challenge string "konsensus-auth".
    pub signature: String,
}

/// Token response.
#[derive(Serialize)]
pub struct TokenResponse {
    /// JWT bearer token.
    pub token: String,
    /// Expiration (Unix timestamp).
    pub expires_at: i64,
}

/// `POST /api/v1/auth/token` — issue a JWT token.
///
/// The client signs the string "konsensus-auth" with their Ed25519 key.
/// If the signature matches the node's public key, a JWT is issued.
async fn issue_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let challenge = b"konsensus-auth";

    // Decode the signature
    let sig_bytes = hex::decode(&req.signature)
        .map_err(|e| ApiError::BadRequest(format!("invalid signature hex: {e}")))?;

    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| ApiError::BadRequest(format!("invalid signature: {e}")))?;

    // Verify against the node's public key
    let node_id_hex = state.identity.node_id().to_hex();
    if state.identity.verify(challenge, &sig).is_err() {
        metrics::counter!(crate::metrics::AUTH_FAILURES).increment(1);
        state.audit_log.record(
            events::AUTH_ATTEMPT,
            &node_id_hex,
            Some(serde_json::json!({"success": false})),
        );
        return Err(ApiError::Unauthorized("signature verification failed".into()));
    }

    // Issue token
    let token = auth::create_token(&node_id_hex, &state.jwt_secret)
        .map_err(|e| ApiError::Internal(format!("token creation failed: {e}")))?;

    let claims = auth::validate_token(&token, &state.jwt_secret)
        .map_err(|e| ApiError::Internal(format!("token validation failed: {e}")))?;

    state.audit_log.record(
        events::AUTH_TOKEN_ISSUED,
        &node_id_hex,
        None,
    );

    Ok(Json(TokenResponse {
        token,
        expires_at: claims.exp,
    }))
}

/// `POST /api/v1/auth/local` — issue a JWT for localhost connections.
///
/// If the request originates from 127.0.0.1 or ::1, a JWT is issued
/// without requiring signature proof. Physical/local access to the
/// machine running the node is sufficient trust for the desktop UX.
///
/// This follows standard practice for desktop apps (Spotify, Discord,
/// VS Code) where the local API is the trust boundary.
async fn issue_local_token(
    State(state): State<Arc<AppState>>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
) -> Result<Json<TokenResponse>, ApiError> {
    // Only allow from localhost
    let is_local = connect_info
        .map(|ci| ci.0.ip().is_loopback())
        .unwrap_or(false);

    if !is_local {
        return Err(ApiError::Unauthorized(
            "local auth is only available from localhost".into(),
        ));
    }

    let node_id_hex = state.identity.node_id().to_hex();

    let token = auth::create_token(&node_id_hex, &state.jwt_secret)
        .map_err(|e| ApiError::Internal(format!("token creation failed: {e}")))?;

    let claims = auth::validate_token(&token, &state.jwt_secret)
        .map_err(|e| ApiError::Internal(format!("token validation failed: {e}")))?;

    state.audit_log.record(
        events::AUTH_TOKEN_ISSUED,
        &node_id_hex,
        Some(serde_json::json!({"method": "local"})),
    );

    Ok(Json(TokenResponse {
        token,
        expires_at: claims.exp,
    }))
}

/// Registers authentication routes for issuing API and local access tokens.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/auth/token", post(issue_token))
        .route("/api/v1/auth/local", post(issue_local_token))
}
