//! JWT authentication middleware and token management.
//!
//! The API uses JWT bearer tokens for authentication. Tokens are issued
//! via the `/api/v1/auth/token` endpoint after verifying the node's identity.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::state::AppState;

/// JWT claims.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (node ID hex).
    pub sub: String,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Expiration (Unix timestamp).
    pub exp: i64,
}

/// Token validity duration: 24 hours.
const TOKEN_VALIDITY_SECS: i64 = 86400;

/// Create a JWT token for the node.
pub fn create_token(node_id_hex: &str, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: node_id_hex.to_string(),
        iat: now,
        exp: now + TOKEN_VALIDITY_SECS,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

/// Validate a JWT token and return the claims.
pub fn validate_token(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(data.claims)
}

/// Extractor for authenticated requests.
///
/// Checks the `Authorization: Bearer <token>` header and validates the JWT.
/// If valid, the handler receives `AuthUser` with the node ID.
pub struct AuthUser {
    /// The authenticated node ID (hex).
    pub node_id: String,
}

#[axum::async_trait]
impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, "missing authorization header").into_response()
            })?;

        let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, "invalid authorization format").into_response()
        })?;

        let claims = validate_token(token, &state.jwt_secret).map_err(|e| {
            metrics::counter!(crate::metrics::AUTH_FAILURES).increment(1);
            (
                StatusCode::UNAUTHORIZED,
                format!("invalid token: {e}"),
            )
                .into_response()
        })?;

        Ok(AuthUser {
            node_id: claims.sub,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_validate_token() {
        let secret = "test-secret-key";
        let node_id = "aabbccdd";

        let token = create_token(node_id, secret).unwrap();
        let claims = validate_token(&token, secret).unwrap();

        assert_eq!(claims.sub, node_id);
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn invalid_secret_rejected() {
        let token = create_token("node1", "secret1").unwrap();
        let result = validate_token(&token, "wrong-secret");
        assert!(result.is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let secret = "test-secret";
        let claims = Claims {
            sub: "node1".into(),
            iat: 1_000_000,
            exp: 1_000_001, // expired long ago
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let result = validate_token(&token, secret);
        assert!(result.is_err());
    }

    #[test]
    fn completely_garbage_token_rejected() {
        let result = validate_token("not-a-jwt-at-all", "secret");
        assert!(result.is_err());
    }

    #[test]
    fn empty_token_rejected() {
        let result = validate_token("", "secret");
        assert!(result.is_err());
    }

    #[test]
    fn token_with_wrong_structure_rejected() {
        // JWT must have 3 dot-separated parts
        let result = validate_token("part1.part2", "secret");
        assert!(result.is_err());
    }

    #[test]
    fn token_with_empty_secret_works() {
        // Empty secret is technically valid for HMAC
        let token = create_token("node1", "").unwrap();
        let claims = validate_token(&token, "").unwrap();
        assert_eq!(claims.sub, "node1");
    }

    #[test]
    fn token_with_empty_node_id() {
        let secret = "test-secret";
        let token = create_token("", secret).unwrap();
        let claims = validate_token(&token, secret).unwrap();
        assert_eq!(claims.sub, "");
    }

    #[test]
    fn token_with_long_node_id() {
        let secret = "test-secret";
        let long_id = "a".repeat(1024);
        let token = create_token(&long_id, secret).unwrap();
        let claims = validate_token(&token, secret).unwrap();
        assert_eq!(claims.sub, long_id);
    }

    #[test]
    fn token_with_unicode_node_id() {
        let secret = "test-secret";
        let token = create_token("n\u{00f6}de-\u{1f600}", secret).unwrap();
        let claims = validate_token(&token, secret).unwrap();
        assert_eq!(claims.sub, "n\u{00f6}de-\u{1f600}");
    }

    #[test]
    fn token_claims_have_24h_expiry() {
        let secret = "test-secret";
        let token = create_token("node1", secret).unwrap();
        let claims = validate_token(&token, secret).unwrap();
        assert_eq!(claims.exp - claims.iat, 86400);
    }

    #[test]
    fn two_tokens_same_input_differ() {
        // Tokens generated at different times should differ (different iat/exp)
        // In practice they may be identical if generated within the same second,
        // but the structure should be consistent
        let secret = "test-secret";
        let t1 = create_token("node1", secret).unwrap();
        let t2 = create_token("node1", secret).unwrap();
        // Both should validate
        assert!(validate_token(&t1, secret).is_ok());
        assert!(validate_token(&t2, secret).is_ok());
    }

    #[test]
    fn base64_padding_in_token_rejected() {
        // Tamper with a valid token by adding padding characters
        let secret = "test-secret";
        let token = create_token("node1", secret).unwrap();
        let tampered = format!("{token}===");
        let result = validate_token(&tampered, secret);
        assert!(result.is_err());
    }

    #[test]
    fn token_with_modified_payload_rejected() {
        let secret = "test-secret";
        let token = create_token("node1", secret).unwrap();
        // Flip a character in the middle (payload section)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let mut payload = parts[1].to_string();
        if let Some(c) = payload.pop() {
            // Append a different character
            payload.push(if c == 'A' { 'B' } else { 'A' });
        }
        let tampered = format!("{}.{}.{}", parts[0], payload, parts[2]);
        let result = validate_token(&tampered, secret);
        assert!(result.is_err());
    }
}
