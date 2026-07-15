//! Authentication endpoints — token issuance.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::audit::events;
use crate::auth;
use crate::error::ApiError;
use crate::state::AppState;

const AUTH_CHALLENGE_TTL: Duration = Duration::from_secs(120);
const AUTH_CHALLENGE_MAX_LIVE: usize = 128;

/// Authentication challenge response.
#[derive(Serialize)]
pub struct ChallengeResponse {
    /// Opaque string the client must sign exactly as returned.
    pub challenge: String,
    /// Expiration (Unix timestamp).
    pub expires_at: i64,
}

/// Token request — the client proves they know the node's signing key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    /// Opaque challenge string from `GET /api/v1/auth/challenge`.
    pub challenge: String,
    /// Hex-encoded Ed25519 signature of `challenge`.
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

/// `GET /api/v1/auth/challenge` — issue a short-lived single-use challenge.
async fn issue_challenge(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(AUTH_CHALLENGE_TTL.as_secs() as i64);
    // The node_id is deliberately NOT embedded here. `/health` redacts it
    // (owner-only — see `PublicHealthResponse`), so an unauthenticated caller must
    // not be able to recover it via the challenge. It is not load-bearing for
    // auth: `issue_token` verifies the signature over the whole challenge against
    // THIS node's own key plus single-use membership in `auth_challenges` (a node
    // only ever issues challenges for itself), and the 32-byte nonce already makes
    // every challenge globally unique.
    let challenge = format!(
        "bitsov-auth-v1:{}:{}",
        hex::encode(nonce),
        expires_at.timestamp()
    );

    let mut challenges = state.auth_challenges.lock().await;
    let now_instant = Instant::now();
    challenges.retain(|_, expires| *expires > now_instant);
    if challenges.len() >= AUTH_CHALLENGE_MAX_LIVE {
        return Err(ApiError::TooManyRequests(
            "too many outstanding auth challenges".into(),
        ));
    }
    challenges.insert(challenge.clone(), now_instant + AUTH_CHALLENGE_TTL);

    Ok(Json(ChallengeResponse {
        challenge,
        expires_at: expires_at.timestamp(),
    }))
}

/// `POST /api/v1/auth/token` — issue a JWT token.
///
/// The client signs a short-lived single-use challenge with their Ed25519 key.
/// If the signature matches the node's public key, a JWT is issued.
async fn issue_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let challenge = req.challenge.trim();
    if challenge.is_empty() {
        return Err(ApiError::BadRequest("challenge is required".into()));
    }

    let now = Instant::now();
    let mut challenges = state.auth_challenges.lock().await;
    let expires_at = challenges.remove(challenge).ok_or_else(|| {
        ApiError::Unauthorized("auth challenge is unknown or already used".into())
    })?;
    if expires_at <= now {
        return Err(ApiError::Unauthorized("auth challenge expired".into()));
    }
    drop(challenges);

    // Decode the signature
    let sig_bytes = hex::decode(&req.signature)
        .map_err(|e| ApiError::BadRequest(format!("invalid signature hex: {e}")))?;

    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| ApiError::BadRequest(format!("invalid signature: {e}")))?;

    // Verify against the node's public key
    let node_id_hex = state.identity.node_id().to_hex();
    if state.identity.verify(challenge.as_bytes(), &sig).is_err() {
        metrics::counter!(crate::metrics::AUTH_FAILURES).increment(1);
        state.audit_log.record(
            events::AUTH_ATTEMPT,
            &node_id_hex,
            Some(serde_json::json!({"success": false})),
        );
        return Err(ApiError::Unauthorized(
            "signature verification failed".into(),
        ));
    }

    // Issue token
    let token = auth::create_token(&node_id_hex, &state.jwt_secret)
        .map_err(|e| ApiError::Internal(format!("token creation failed: {e}")))?;

    let claims = auth::validate_token(&token, &state.jwt_secret)
        .map_err(|e| ApiError::Internal(format!("token validation failed: {e}")))?;

    state
        .audit_log
        .record(events::AUTH_TOKEN_ISSUED, &node_id_hex, None);

    Ok(Json(TokenResponse {
        token,
        expires_at: claims.exp,
    }))
}

/// Max `/auth/local` token issuances per minute. Local access is the trust
/// boundary, but an unthrottled mint lets any loopback process spin JWTs in a tight
/// loop (token-grinding / audit-log flooding). 5/min is ample for the desktop UX
/// (~one token per app launch) while bounding abuse (SEC1).
const AUTH_LOCAL_LIMIT_PER_MINUTE: u32 = 5;

/// Dedicated low-rate throttle for `POST /api/v1/auth/local`, keyed on the single
/// literal `"auth_local"` — the route is loopback-only, so one shared bucket is the
/// right granularity. Separate from the global per-IP limiter held in `AppState`.
fn auth_local_rate_limiter() -> &'static crate::rate_limit::RateLimiter {
    static LIMITER: std::sync::OnceLock<crate::rate_limit::RateLimiter> =
        std::sync::OnceLock::new();
    LIMITER.get_or_init(|| {
        crate::rate_limit::RateLimiter::with_window(
            AUTH_LOCAL_LIMIT_PER_MINUTE,
            Duration::from_secs(60),
        )
    })
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

    // SEC1: throttle local token minting so a loopback process can't grind JWTs
    // (or flood the audit log) in a tight loop. The loopback guard above is the
    // admission control; this bounds the rate. Checked after the loopback guard so
    // a non-local request cannot consume the route's shared budget.
    if !auth_local_rate_limiter().check_key("auth_local") {
        return Err(ApiError::TooManyRequests(
            "local auth rate limit exceeded; retry in a minute".into(),
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
pub fn routes(local_auth_enabled: bool) -> Router<Arc<AppState>> {
    let router = Router::new()
        .route("/api/v1/auth/challenge", get(issue_challenge))
        .route("/api/v1/auth/token", post(issue_token));

    if local_auth_enabled {
        router.route("/api/v1/auth/local", post(issue_local_token))
    } else {
        router
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC1 seam: drive the *actual* production `auth_local` limiter (not a fresh
    /// throwaway) through its cap boundary and the window-reset path.
    ///
    /// The HTTP-level test (`tests/auth_tests::auth_local_rate_limited_after_burst`)
    /// proves a 429 surfaces on the real route. This unit test proves the two things
    /// that test cannot: (1) the cap boundary is *exact* — the Nth call where
    /// `N == AUTH_LOCAL_LIMIT_PER_MINUTE` still succeeds and `N+1`/`N+2` are denied —
    /// and (2) the window *resets*: after the window elapses, minting succeeds again.
    ///
    /// The route's limiter is a process-global `OnceLock` keyed on the single literal
    /// `"auth_local"`, so its bucket can't be made fresh per-test. We instead reset it
    /// explicitly with `expire_key` at the start (defend against any earlier unit test
    /// in this binary having touched the bucket) and to simulate the window elapsing —
    /// `Instant`-based windows otherwise need a real wall-clock minute.
    #[test]
    fn auth_local_limiter_cap_is_exact_and_window_resets() {
        let limiter = auth_local_rate_limiter();
        const KEY: &str = "auth_local";

        // Start from a known-clean window for the shared global bucket.
        limiter.expire_key(KEY);

        // Exactly AUTH_LOCAL_LIMIT_PER_MINUTE calls succeed — boundary is inclusive.
        for i in 1..=AUTH_LOCAL_LIMIT_PER_MINUTE {
            assert!(
                limiter.check_key(KEY),
                "mint {i}/{AUTH_LOCAL_LIMIT_PER_MINUTE} within the window must be allowed"
            );
        }

        // The next two are denied — the cap trips exactly at the limit, not one over.
        assert!(
            !limiter.check_key(KEY),
            "mint {} (cap+1) within the same window must be rate-limited",
            AUTH_LOCAL_LIMIT_PER_MINUTE + 1
        );
        assert!(
            !limiter.check_key(KEY),
            "mint {} (cap+2) stays rate-limited within the same window",
            AUTH_LOCAL_LIMIT_PER_MINUTE + 2
        );

        // Simulate the 60s window elapsing on the production limiter.
        limiter.expire_key(KEY);

        // After the window resets, minting succeeds again (and a full fresh budget
        // is available, confirming the reset is a true new window, not a one-off).
        for i in 1..=AUTH_LOCAL_LIMIT_PER_MINUTE {
            assert!(
                limiter.check_key(KEY),
                "after window reset, mint {i}/{AUTH_LOCAL_LIMIT_PER_MINUTE} must succeed again"
            );
        }
        assert!(
            !limiter.check_key(KEY),
            "the fresh window honours the same cap (still {AUTH_LOCAL_LIMIT_PER_MINUTE}/min)"
        );

        // Leave the shared bucket clean for any other test in this binary.
        limiter.expire_key(KEY);
    }
}
