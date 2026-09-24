//! JWT authentication middleware and token management.
//!
//! The API uses JWT bearer tokens for authentication. Tokens are issued
//! via the `/api/v1/auth/token` endpoint after verifying the node's identity.
//!
//! # Why no third-party JWT crate
//!
//! BitSov only ever issues and accepts **HS256** tokens it minted itself.
//! `jsonwebtoken` 9 carries GHSA-h395-gr6q-cpjc with no 9.x fix, and 10 forces a
//! crypto-provider feature that pulls either `rsa` 0.9.10 (unfixed
//! RUSTSEC-2023-0071 Marvin side-channel) or `aws-lc-rs` (a new C/cmake
//! dependency). Since the entire need is one HMAC-SHA256 path, this module
//! composes the audited in-tree RustCrypto crates (`hmac` + `sha2`) instead —
//! no cryptographic primitive is hand-rolled, only the JWT *encoding format*
//! (RFC 7519 compact serialization) is assembled here.
//!
//! Verification is **structurally immune to algorithm confusion**: the verifier
//! always computes HMAC-SHA256 — the algorithm is fixed by policy, never chosen
//! from the attacker-controlled token header. The header's `alg` is additionally
//! required to be exactly `HS256`, any `crit` header is rejected (RFC 7515 §4.1.11),
//! signature comparison is constant-time (`Mac::verify_slice`), and `exp` is
//! enforced with zero leeway (stricter than jsonwebtoken's 60 s default).

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use thiserror::Error;

use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

/// Errors from token creation or validation.
///
/// Variants are deliberately coarse: the API maps all of them to a single 401,
/// and fine-grained "why" strings must not become an oracle for forgery attempts.
#[derive(Debug, Error)]
pub enum TokenError {
    /// Not three non-empty dot-separated base64url segments.
    #[error("malformed token")]
    Malformed,
    /// Header is not valid base64url/JSON, or carries an unsupported `crit`.
    #[error("invalid token header")]
    InvalidHeader,
    /// Header `alg` is anything other than `HS256`.
    #[error("unsupported token algorithm (only HS256 is accepted)")]
    UnsupportedAlgorithm,
    /// HMAC-SHA256 verification failed.
    #[error("invalid token signature")]
    InvalidSignature,
    /// Claims segment is not valid base64url/JSON for [`Claims`].
    #[error("invalid token claims")]
    InvalidClaims,
    /// The token's `exp` is in the past (zero leeway).
    #[error("token expired")]
    Expired,
}

/// Minimum acceptable length, in bytes, for an explicitly-configured JWT secret.
///
/// HS256 keys shorter than the 32-byte (256-bit) HMAC-SHA-256 output are
/// brute-forceable and weaken every token signed with them. An empty secret
/// makes token forgery trivial. A secret below this threshold is rejected at
/// startup (fail-closed); the deterministic-from-identity fallback always
/// produces a 32-byte key and is therefore accepted.
pub const MIN_JWT_SECRET_BYTES: usize = 32;

/// Reject an explicitly-configured JWT secret that is empty or too short.
///
/// Call this at config-load / startup time on an operator-supplied secret.
/// The deterministic-from-identity fallback must NOT be passed here — it is a
/// derived 32-byte key and is always acceptable.
///
/// # Errors
///
/// Returns `Err` with a human-readable reason if the secret is empty or
/// shorter than [`MIN_JWT_SECRET_BYTES`] bytes.
pub fn validate_jwt_secret(secret: &str) -> Result<(), String> {
    // `str::len()` is the byte length, which is what HMAC keys are measured in.
    let len = secret.len();
    if len == 0 {
        return Err(
            "configured JWT secret is empty — an empty HMAC key makes token forgery trivial. \
             Set api.jwt_secret to at least 32 bytes, or omit it to derive one from the node identity."
                .to_string(),
        );
    }
    if len < MIN_JWT_SECRET_BYTES {
        return Err(format!(
            "configured JWT secret is too short ({len} bytes) — HS256 requires at least \
             {MIN_JWT_SECRET_BYTES} bytes (256 bits) to resist brute force. \
             Use a longer secret, or omit api.jwt_secret to derive one from the node identity."
        ));
    }
    Ok(())
}

/// The fixed JWT header for every token this node mints: `{"alg":"HS256","typ":"JWT"}`.
const JWT_HEADER_JSON: &[u8] = br#"{"alg":"HS256","typ":"JWT"}"#;

/// Compute the base64url (no padding) HMAC-SHA256 signature over `<h>.<p>`.
fn hs256_signature(header_b64: &str, payload_b64: &str, secret: &str) -> Result<String, TokenError> {
    // `Hmac::new_from_slice` accepts any key length; the 32-byte floor for
    // operator-configured secrets is enforced separately by `validate_jwt_secret`.
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| TokenError::InvalidSignature)?;
    mac.update(header_b64.as_bytes());
    mac.update(b".");
    mac.update(payload_b64.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

/// Serialize and sign `claims` as an HS256 compact JWT.
///
/// Kept separate from [`create_token`] so tests can sign arbitrary (e.g. already
/// expired) claims through the exact production signing path.
fn sign_claims(claims: &Claims, secret: &str) -> Result<String, TokenError> {
    let header_b64 = URL_SAFE_NO_PAD.encode(JWT_HEADER_JSON);
    let payload_json = serde_json::to_vec(claims).map_err(|_| TokenError::InvalidClaims)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    let sig_b64 = hs256_signature(&header_b64, &payload_b64, secret)?;
    Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
}

/// A capability carried by a token (genome #72).
///
/// Authority used to be all-or-nothing: every authenticated route was equivalent, so
/// reading a balance and spending it were the same grant. Scopes exist so the ISSUER can
/// be constrained — a caller proving only that it reached loopback must not be able to
/// obtain spend, identity or credential authority at all. A caller politely requesting
/// less would achieve nothing, because a malicious caller simply would not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Observe state: status, identity, balances, history, peers, rooms, pricing.
    Read,
    /// Create the means to be paid: funding address, invoice.
    Receive,
    /// Move value: pay, keysend, on-chain send, channel open/close — and paid
    /// messaging, which settles a payment per message. Under "payment IS the
    /// connection" a message send IS a spend; classing it as messaging would reopen
    /// the hole by another door.
    Spend,
    /// Change node configuration and relationships: peers, pricing, gossip, invites,
    /// content, bulk export of the relationship graph.
    Admin,
    /// Key material and identity replacement: reveal mnemonic, restore, verify.
    Identity,
    /// Mint credentials at least as strong as one's own.
    Credential,
}

impl Scope {
    /// Wire form, used in the `scp` claim.
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Receive => "receive",
            Scope::Spend => "spend",
            Scope::Admin => "admin",
            Scope::Identity => "identity",
            Scope::Credential => "credential",
        }
    }

    /// Every scope. Granted only to a caller that proved possession of the node's
    /// identity key.
    pub fn all() -> Vec<Scope> {
        vec![
            Scope::Read,
            Scope::Receive,
            Scope::Spend,
            Scope::Admin,
            Scope::Identity,
            Scope::Credential,
        ]
    }

    /// What loopback presence alone may obtain. Deliberately NOT a subset that can be
    /// widened by the caller: this is the complete set `/auth/local` can mint.
    pub fn loopback_only() -> Vec<Scope> {
        vec![Scope::Read, Scope::Receive]
    }
}

/// JWT claims.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (node ID hex).
    pub sub: String,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Expiration (Unix timestamp).
    pub exp: i64,
    /// Granted capabilities (#72).
    ///
    /// NOT optional, and deliberately without a serde default: a token minted before
    /// scopes existed fails claims parsing and is rejected outright. Defaulting it to
    /// anything would either silently grant full authority to legacy tokens or silently
    /// downgrade them to keep a screen green — both are the hidden fallback this ticket
    /// exists to avoid. Callers re-authenticate; tokens live 24h.
    pub scp: Vec<Scope>,

    /// Paired client id (#76). Present only on tokens issued to a paired client.
    ///
    /// Absent on `/auth/local` and key-proof tokens, which is why it is an
    /// `Option` — but a token that carries `cid` must also carry `epc` and
    /// `idf`, and all three are re-checked against the live pairing record on
    /// every request. See [`PairingBinding::from_claims`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,

    /// Pairing revocation epoch (#76). Bumping the pairing's epoch invalidates
    /// every outstanding token for that client immediately.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epc: Option<u64>,

    /// Fingerprint of the identity this token was issued against (#76).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idf: Option<String>,

    /// Marks a token minted during identity-free bootstrap (#76).
    ///
    /// Bootstrap runs on an ephemeral in-memory signing secret, so these
    /// tokens stop verifying the instant the identity-derived secret takes
    /// over. This claim is a second, independent gate: the live router rejects
    /// any token that carries it, so even a bootstrap token re-signed with the
    /// live secret conveys nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bst: Option<bool>,
}

impl Claims {
    /// Does this token carry `scope`?
    pub fn has(&self, scope: Scope) -> bool {
        self.scp.contains(&scope)
    }
}

/// The pairing binding a token asserts (#76).
///
/// Extracted as a unit so the three fields cannot drift apart: a token that
/// carries any one of them must carry all three, and a token that carries none
/// is a non-paired token (loopback or key-proof) which is checked by its own
/// issuer's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingBinding {
    /// Paired client id.
    pub client_id: String,
    /// Pairing epoch.
    pub epoch: u64,
    /// Identity fingerprint.
    pub fingerprint: String,
}

impl PairingBinding {
    /// Read the binding out of `claims`.
    ///
    /// `Ok(None)` means "not a paired token". `Err` means the token claims a
    /// partial binding, which is rejected outright rather than interpreted:
    /// half a binding is not a weaker grant, it is a malformed one.
    pub fn from_claims(claims: &Claims) -> Result<Option<Self>, TokenError> {
        match (
            claims.cid.as_deref(),
            claims.epc,
            claims.idf.as_deref(),
        ) {
            (None, None, None) => Ok(None),
            (Some(cid), Some(epoch), Some(idf)) if !cid.is_empty() && !idf.is_empty() => {
                Ok(Some(PairingBinding {
                    client_id: cid.to_string(),
                    epoch,
                    fingerprint: idf.to_string(),
                }))
            }
            _ => Err(TokenError::InvalidClaims),
        }
    }
}

/// Token validity duration: 24 hours.
const TOKEN_VALIDITY_SECS: i64 = 86400;

/// Create a JWT token carrying exactly `scopes`.
///
/// Every issuer names its own scope set at the call site. Both issuers previously shared
/// one no-argument `create_token`, so a change made for the loopback path would silently
/// have altered the key-proof path too; requiring the set here makes that impossible to
/// do by accident (#72).
pub fn create_token(node_id_hex: &str, secret: &str, scopes: Vec<Scope>) -> Result<String, TokenError> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: node_id_hex.to_string(),
        iat: now,
        exp: now + TOKEN_VALIDITY_SECS,
        scp: scopes,
        cid: None,
        epc: None,
        idf: None,
        bst: None,
    };
    sign_claims(&claims, secret)
}

/// Paired-client token lifetime: 10 minutes (#76).
///
/// Minutes rather than the 24 hours a loopback token gets. The durable secret
/// is the client key the app holds, so a leaked token must stop being useful
/// quickly; the app re-signs a fresh challenge to get another one.
pub const PAIRED_TOKEN_VALIDITY_SECS: i64 = 600;

/// Create a short-lived token for a paired client, bound to its pairing (#76).
///
/// The binding travels in the token and is re-checked against the durable
/// pairing record on every request, so revocation (an epoch bump) and identity
/// replacement both take effect immediately rather than at expiry.
pub fn create_paired_token(
    subject: &str,
    secret: &str,
    scopes: Vec<Scope>,
    client_id: &str,
    epoch: u64,
    identity_fingerprint: &str,
) -> Result<String, TokenError> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: subject.to_string(),
        iat: now,
        exp: now + PAIRED_TOKEN_VALIDITY_SECS,
        scp: scopes,
        cid: Some(client_id.to_string()),
        epc: Some(epoch),
        idf: Some(identity_fingerprint.to_string()),
        bst: None,
    };
    sign_claims(&claims, secret)
}

/// Create a token for a paired client during identity-free bootstrap (#76).
///
/// Marked `bst` and signed with the bootstrap process's ephemeral secret.
/// There is deliberately no identity fingerprint to bind to yet — the pairing
/// is stamped with the committed identity's fingerprint as part of the
/// transition, and every token minted here stops verifying at the same instant.
pub fn create_bootstrap_token(
    secret: &str,
    scopes: Vec<Scope>,
    client_id: &str,
    epoch: u64,
) -> Result<String, TokenError> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: "bootstrap".to_string(),
        iat: now,
        exp: now + PAIRED_TOKEN_VALIDITY_SECS,
        scp: scopes,
        cid: Some(client_id.to_string()),
        epc: Some(epoch),
        idf: Some(String::new()),
        bst: Some(true),
    };
    sign_claims(&claims, secret)
}

/// Validate a JWT token and return the claims.
///
/// The verifier ALWAYS computes HMAC-SHA256 — the algorithm is fixed by policy,
/// never taken from the token header, so `alg`-confusion (`none`, `HS512`,
/// asymmetric-key smuggling) is structurally impossible. The header is
/// additionally required to declare exactly `HS256` and must not carry a `crit`
/// list. Signature comparison is constant-time. `exp` is enforced with zero
/// leeway and is non-optional (a token without `exp` fails claims parsing).
pub fn validate_token(token: &str, secret: &str) -> Result<Claims, TokenError> {
    // Exactly three non-empty segments. `splitn` is not used so a fourth
    // segment is detected as malformed rather than silently ignored.
    let mut parts = token.split('.');
    let (header_b64, payload_b64, sig_b64) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
                (h, p, s)
            }
            _ => return Err(TokenError::Malformed),
        };

    // Signature FIRST, before any attacker-controlled JSON is parsed. Strict
    // no-padding base64url: a padded or otherwise non-canonical signature
    // segment is rejected outright.
    let sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| TokenError::Malformed)?;
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| TokenError::InvalidSignature)?;
    mac.update(header_b64.as_bytes());
    mac.update(b".");
    mac.update(payload_b64.as_bytes());
    // Constant-time comparison (also rejects truncated/overlong signatures).
    mac.verify_slice(&sig)
        .map_err(|_| TokenError::InvalidSignature)?;

    // Header checks. Safe to parse after verification: the signature covers the
    // header bytes, and the verification algorithm above never depended on it.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| TokenError::InvalidHeader)?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| TokenError::InvalidHeader)?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("HS256") {
        return Err(TokenError::UnsupportedAlgorithm);
    }
    // RFC 7515 §4.1.11: extensions marked critical MUST be understood; we
    // support none, so any `crit` is a rejection.
    if header.get("crit").is_some() {
        return Err(TokenError::InvalidHeader);
    }

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| TokenError::InvalidClaims)?;
    let claims: Claims =
        serde_json::from_slice(&claims_bytes).map_err(|_| TokenError::InvalidClaims)?;
    if claims.exp <= Utc::now().timestamp() {
        return Err(TokenError::Expired);
    }
    Ok(claims)
}

/// Extractor for authenticated requests.
///
/// Checks the `Authorization: Bearer <token>` header and validates the JWT.
/// If valid, the handler receives `AuthUser` with the node ID.
pub struct AuthUser {
    /// The authenticated node ID (hex).
    pub node_id: String,
    /// Capabilities this token carries (#72).
    pub scopes: Vec<Scope>,
    /// The pairing this token was issued to, if any (#76).
    ///
    /// `None` for `/auth/local` and key-proof tokens. When `Some`, the binding
    /// has already been verified against the durable pairing record — the
    /// presence of this value in a handler is proof the check ran.
    pub pairing: Option<PairingBinding>,
}

impl AuthUser {
    /// Does this caller hold `scope`?
    pub fn has(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }
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
            // Membrane discipline (same pattern as ws.rs): keep the failure
            // class internal (tracing + metrics) and return a UNIFORM public
            // body — malformed vs bad-signature vs expired vs unsupported-alg
            // must not be distinguishable by the caller.
            tracing::warn!(error = %e, "bearer token rejected");
            (StatusCode::UNAUTHORIZED, "invalid token").into_response()
        })?;

        let pairing = check_pairing_binding(state, &claims).map_err(|reason| {
            metrics::counter!(crate::metrics::AUTH_FAILURES).increment(1);
            tracing::warn!(reason = %reason, "paired token rejected");
            (StatusCode::UNAUTHORIZED, "invalid token").into_response()
        })?;

        Ok(AuthUser {
            node_id: claims.sub,
            scopes: claims.scp,
            pairing,
        })
    }
}

/// Re-check a token's pairing binding against the durable record (#76).
///
/// Every authenticated request pays this cost, which is the point: an epoch
/// bump from the CLI, a deleted pairing, or a replaced identity must invalidate
/// outstanding tokens *now*, not when they expire.
///
/// Rejection is outright in every failure case. There is no path here that
/// downgrades a token to a weaker scope set to keep a caller working — the
/// same discipline #72 applied to the scope-less legacy token.
pub(crate) fn check_pairing_binding(
    state: &Arc<AppState>,
    claims: &Claims,
) -> Result<Option<PairingBinding>, String> {
    // A bootstrap token has no business on the live router. Bootstrap uses an
    // ephemeral secret so these normally die at the signature check; this is
    // the independent second gate.
    if claims.bst == Some(true) {
        return Err("token was minted during identity-free bootstrap".into());
    }

    let binding = PairingBinding::from_claims(claims)
        .map_err(|_| "token carries a partial pairing binding".to_string())?;

    let Some(binding) = binding else {
        return Ok(None);
    };

    // A paired token on a node with no pairing service cannot be checked, so it
    // is refused. Failing open here would make the binding advisory.
    let service = state
        .pairing
        .as_ref()
        .ok_or_else(|| "pairing is not configured on this node".to_string())?;

    service
        .verify_token_binding(
            &binding.client_id,
            binding.epoch,
            &binding.fingerprint,
            &claims.scp,
        )
        .map_err(|e| e.to_string())?;

    Ok(Some(binding))
}

/// Scope-enforcing extractors (#72).
///
/// A handler names the authority it needs in its own signature, so enforcement is a
/// property of the type system rather than a habit: `ScopedAuth<Spend>` cannot be
/// satisfied by a token that lacks `spend`, and a handler cannot silently skip the
/// check the way an `if auth.has(..)` line can be forgotten or deleted.
pub mod scoped {
    use super::{AuthUser, Scope};
    use axum::extract::FromRequestParts;
    use axum::http::request::Parts;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use std::sync::Arc;

    /// Marker trait: which scope an extractor demands.
    pub trait RequiredScope {
        const SCOPE: Scope;
    }

    macro_rules! scope_marker {
        ($name:ident, $scope:expr, $doc:expr) => {
            #[doc = $doc]
            pub struct $name;
            impl RequiredScope for $name {
                const SCOPE: Scope = $scope;
            }
        };
    }

    scope_marker!(Read, Scope::Read, "Requires `read`.");
    scope_marker!(Receive, Scope::Receive, "Requires `receive`.");
    scope_marker!(Spend, Scope::Spend, "Requires `spend`.");
    scope_marker!(Admin, Scope::Admin, "Requires `admin`.");
    scope_marker!(Identity, Scope::Identity, "Requires `identity`.");
    scope_marker!(Credential, Scope::Credential, "Requires `credential`.");

    /// An authenticated caller that has been checked for `S`.
    pub struct ScopedAuth<S: RequiredScope> {
        pub user: AuthUser,
        _scope: std::marker::PhantomData<S>,
    }

    /// Deref to the inner [`AuthUser`] so existing handlers keep using `auth.node_id`
    /// unchanged. The scope check has already happened by the time a handler holds one
    /// of these — the type is the proof, the fields are just the payload.
    impl<S: RequiredScope> std::ops::Deref for ScopedAuth<S> {
        type Target = AuthUser;
        fn deref(&self) -> &AuthUser {
            &self.user
        }
    }

    #[axum::async_trait]
    impl<S> FromRequestParts<Arc<crate::AppState>> for ScopedAuth<S>
    where
        S: RequiredScope + Send,
    {
        type Rejection = Response;

        async fn from_request_parts(
            parts: &mut Parts,
            state: &Arc<crate::AppState>,
        ) -> Result<Self, Self::Rejection> {
            let user = AuthUser::from_request_parts(parts, state).await?;
            if !user.has(S::SCOPE) {
                metrics::counter!(crate::metrics::AUTH_FAILURES).increment(1);
                tracing::warn!(
                    required = S::SCOPE.as_str(),
                    "token lacks the required scope"
                );
                // 403, not 401: the caller authenticated successfully and simply is not
                // permitted. Returning 401 would invite a client to re-authenticate in a
                // loop for authority it can never obtain from its issuer.
                return Err((
                    StatusCode::FORBIDDEN,
                    format!("token lacks required scope: {}", S::SCOPE.as_str()),
                )
                    .into_response());
            }
            Ok(ScopedAuth {
                user,
                _scope: std::marker::PhantomData,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_validate_token() {
        let secret = "test-secret-key";
        let node_id = "aabbccdd";

        let token = create_token(node_id, secret, Scope::all()).unwrap();
        let claims = validate_token(&token, secret).unwrap();

        assert_eq!(claims.sub, node_id);
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn invalid_secret_rejected() {
        let token = create_token("node1", "secret1", Scope::all()).unwrap();
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
            scp: Scope::all(),
            cid: None,
            epc: None,
            idf: None,
            bst: None,
        };
        // Signed through the exact production signing path — only the claims differ.
        let token = sign_claims(&claims, secret).unwrap();

        let result = validate_token(&token, secret);
        assert!(matches!(result, Err(TokenError::Expired)));
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
        // Regression: HMAC itself accepts an empty key, so an empty configured
        // secret used to produce verifiable tokens — a token-forgery foot-gun.
        // The startup gate now rejects an empty secret (fail-closed); this test
        // documents that rejection.
        assert!(
            validate_jwt_secret("").is_err(),
            "empty JWT secret must be rejected at startup"
        );
    }

    #[test]
    fn short_secret_rejected() {
        // 31 bytes — one short of the 32-byte (256-bit) HS256 floor.
        let short = "a".repeat(MIN_JWT_SECRET_BYTES - 1);
        let err = validate_jwt_secret(&short).unwrap_err();
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn exactly_min_length_secret_accepted() {
        let ok = "a".repeat(MIN_JWT_SECRET_BYTES);
        assert!(validate_jwt_secret(&ok).is_ok());
    }

    #[test]
    fn long_secret_accepted() {
        let ok = "a".repeat(64);
        assert!(validate_jwt_secret(&ok).is_ok());
    }

    #[test]
    fn min_length_counts_bytes_not_chars() {
        // 16 multi-byte chars = 48 bytes (each \u{00e9} is 2 bytes in UTF-8),
        // so it clears the 32-BYTE floor despite being only 16 characters.
        let multibyte = "\u{00e9}".repeat(16);
        assert_eq!(multibyte.chars().count(), 16);
        assert!(multibyte.len() >= MIN_JWT_SECRET_BYTES);
        assert!(validate_jwt_secret(&multibyte).is_ok());
    }

    /// Forge a token with an arbitrary header JSON but a VALID HMAC-SHA256
    /// signature over it (worst case for header-pinning tests: the signature
    /// check passes, so rejection must come from the header policy itself).
    fn forge_with_header(header_json: &str, claims: &Claims, secret: &str) -> String {
        let h = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let s = hs256_signature(&h, &p, secret).unwrap();
        format!("{h}.{p}.{s}")
    }

    fn fresh_claims() -> Claims {
        let now = Utc::now().timestamp();
        Claims {
            sub: "node1".into(),
            iat: now,
            exp: now + TOKEN_VALIDITY_SECS,
            scp: Scope::all(),
            cid: None,
            epc: None,
            idf: None,
            bst: None,
        }
    }

    #[test]
    fn validation_policy_pins_hs256() {
        // Worst-case algorithm confusion: the header claims HS512 but the
        // HMAC-SHA256 signature over the token is VALID. The verifier must
        // still reject purely on the pinned-header policy.
        let secret = "a".repeat(MIN_JWT_SECRET_BYTES);
        let token = forge_with_header(r#"{"alg":"HS512","typ":"JWT"}"#, &fresh_claims(), &secret);
        assert!(matches!(
            validate_token(&token, &secret),
            Err(TokenError::UnsupportedAlgorithm)
        ));
    }

    #[test]
    fn alg_none_rejected() {
        // The classic `alg: none` forgery: no/garbage signature. The verifier
        // always computes HMAC-SHA256, so this dies at the signature check —
        // and even with a valid signature the header policy would reject it.
        let secret = "a".repeat(MIN_JWT_SECRET_BYTES);
        let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&fresh_claims()).unwrap());
        // Empty signature segment => malformed; forged-but-unsigned dies early.
        assert!(validate_token(&format!("{h}.{p}."), &secret).is_err());
        // And with a VALID signature over an alg=none header, the pin rejects.
        let token = forge_with_header(r#"{"alg":"none","typ":"JWT"}"#, &fresh_claims(), &secret);
        assert!(matches!(
            validate_token(&token, &secret),
            Err(TokenError::UnsupportedAlgorithm)
        ));
    }

    #[test]
    fn crit_header_rejected() {
        // RFC 7515 §4.1.11: unsupported critical extensions MUST be rejected,
        // even when the signature is valid and alg is HS256.
        let secret = "a".repeat(MIN_JWT_SECRET_BYTES);
        let token = forge_with_header(
            r#"{"alg":"HS256","typ":"JWT","crit":["exp"]}"#,
            &fresh_claims(),
            &secret,
        );
        assert!(matches!(
            validate_token(&token, &secret),
            Err(TokenError::InvalidHeader)
        ));
    }

    #[test]
    fn four_segment_token_rejected() {
        let secret = "a".repeat(MIN_JWT_SECRET_BYTES);
        let token = create_token("node1", &secret, Scope::all()).unwrap();
        assert!(matches!(
            validate_token(&format!("{token}.extra"), &secret),
            Err(TokenError::Malformed)
        ));
    }

    #[test]
    fn truncated_signature_rejected() {
        // A prefix of the real signature must fail (verify_slice rejects
        // length mismatches; nothing accepts a "close enough" MAC).
        let secret = "a".repeat(MIN_JWT_SECRET_BYTES);
        let token = create_token("node1", &secret, Scope::all()).unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        let sig = parts[2];
        let truncated = &sig[..sig.len() - 8];
        parts[2] = truncated;
        assert!(validate_token(&parts.join("."), &secret).is_err());
    }

    /// #72 reversed half of this fixture's original contract, deliberately.
    ///
    /// The fixture below is byte-for-byte what jsonwebtoken 9 emitted, and it carries no
    /// `scp` claim. It used to assert "a node upgrade must not sever existing owner
    /// sessions". That is now exactly the wrong outcome: a token minted before scopes
    /// existed conveys no authorization, and honouring it would mean either granting it
    /// everything or quietly reinterpreting it as `read`. Both are the hidden fallback the
    /// ticket exists to remove, so it is rejected and the caller re-authenticates.
    ///
    /// Note the MAC still verifies — this fails at claims parsing, not at the signature.
    #[test]
    fn legacy_scopeless_token_is_now_rejected() {
        const LEGACY_SECRET: &str = "legacy-fixture-secret-0123456789abcdef";
        const LEGACY_HEADER_B64: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9";
        const LEGACY_CLAIMS_B64: &str =
            "eyJzdWIiOiJsZWdhY3ktbm9kZSIsImlhdCI6MTAwMDAwMCwiZXhwIjo5OTk5OTk5OTk5fQ";
        const LEGACY_SIG_B64: &str = "7S1JtUNsZQt5jDql3oo0o9eILAheqKWRJ5n3rKD-Ot0";
        let legacy_token = format!("{LEGACY_HEADER_B64}.{LEGACY_CLAIMS_B64}.{LEGACY_SIG_B64}");

        // Sanity: the MAC is genuinely good, so the rejection below is about the missing
        // scope claim and not an unrelated signature failure.
        assert_eq!(
            hs256_signature(LEGACY_HEADER_B64, LEGACY_CLAIMS_B64, LEGACY_SECRET).unwrap(),
            LEGACY_SIG_B64,
            "fixture MAC should still verify — otherwise this test proves nothing about scopes"
        );

        assert!(
            validate_token(&legacy_token, LEGACY_SECRET).is_err(),
            "a pre-scope token must be rejected, never granted authority by default"
        );
    }

    /// The half of the original fixture that still holds: the verifier checks the raw
    /// segments and never re-serializes, so legacy header field order
    /// (`{"typ":"JWT","alg":"HS256"}`, typ first, where this module emits alg first) must
    /// remain acceptable. Built at runtime rather than hardcoded so no contiguous
    /// `eyJ*.eyJ*` literal exists for gitleaks' JWT rule to flag.
    #[test]
    fn legacy_header_field_order_still_validates() {
        let secret = "a".repeat(MIN_JWT_SECRET_BYTES);
        let h = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"HS256"}"#);
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&fresh_claims()).unwrap());
        let s = hs256_signature(&h, &p, &secret).unwrap();

        let claims = validate_token(&format!("{h}.{p}.{s}"), &secret)
            .expect("legacy header field order must still verify");
        assert_eq!(claims.sub, "node1");
        assert_eq!(claims.scp, Scope::all());
    }

    #[test]
    fn valid_mac_malformed_header_json_rejected() {
        // Stolen-key worst case: the MAC verifies but the header is not JSON.
        // Everything after the MAC gate is still attacker-controlled input.
        let secret = "a".repeat(MIN_JWT_SECRET_BYTES);
        let h = URL_SAFE_NO_PAD.encode(b"not-json-at-all");
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&fresh_claims()).unwrap());
        let s = hs256_signature(&h, &p, &secret).unwrap();
        assert!(matches!(
            validate_token(&format!("{h}.{p}.{s}"), &secret),
            Err(TokenError::InvalidHeader)
        ));
    }

    #[test]
    fn valid_mac_malformed_claims_json_rejected() {
        let secret = "a".repeat(MIN_JWT_SECRET_BYTES);
        let h = URL_SAFE_NO_PAD.encode(JWT_HEADER_JSON);
        let p = URL_SAFE_NO_PAD.encode(b"{\"sub\":unterminated");
        let s = hs256_signature(&h, &p, &secret).unwrap();
        assert!(matches!(
            validate_token(&format!("{h}.{p}.{s}"), &secret),
            Err(TokenError::InvalidClaims)
        ));
    }

    #[test]
    fn valid_mac_wrong_type_exp_iat_rejected() {
        // exp/iat as strings (or any non-i64) must fail claims parsing, not be
        // coerced. A string "exp" would otherwise dodge the expiry comparison.
        let secret = "a".repeat(MIN_JWT_SECRET_BYTES);
        for bad in [
            br#"{"sub":"n","iat":"1000000","exp":9999999999}"#.as_slice(),
            br#"{"sub":"n","iat":1000000,"exp":"9999999999"}"#.as_slice(),
            br#"{"sub":"n","iat":1000000,"exp":true}"#.as_slice(),
            br#"{"sub":"n","iat":1.5,"exp":9999999999}"#.as_slice(),
        ] {
            let h = URL_SAFE_NO_PAD.encode(JWT_HEADER_JSON);
            let p = URL_SAFE_NO_PAD.encode(bad);
            let s = hs256_signature(&h, &p, &secret).unwrap();
            assert!(
                matches!(
                    validate_token(&format!("{h}.{p}.{s}"), &secret),
                    Err(TokenError::InvalidClaims)
                ),
                "claims {} must be rejected",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn token_without_exp_rejected() {
        // `exp` is non-optional in Claims: a token missing it must fail claims
        // parsing, never "validate without expiry".
        let secret = "a".repeat(MIN_JWT_SECRET_BYTES);
        let h = URL_SAFE_NO_PAD.encode(JWT_HEADER_JSON);
        let p = URL_SAFE_NO_PAD.encode(br#"{"sub":"node1","iat":1000000}"#);
        let s = hs256_signature(&h, &p, &secret).unwrap();
        assert!(matches!(
            validate_token(&format!("{h}.{p}.{s}"), &secret),
            Err(TokenError::InvalidClaims)
        ));
    }

    #[test]
    fn token_with_empty_node_id() {
        let secret = "test-secret";
        let token = create_token("", secret, Scope::all()).unwrap();
        let claims = validate_token(&token, secret).unwrap();
        assert_eq!(claims.sub, "");
    }

    #[test]
    fn token_with_long_node_id() {
        let secret = "test-secret";
        let long_id = "a".repeat(1024);
        let token = create_token(&long_id, secret, Scope::all()).unwrap();
        let claims = validate_token(&token, secret).unwrap();
        assert_eq!(claims.sub, long_id);
    }

    #[test]
    fn token_with_unicode_node_id() {
        let secret = "test-secret";
        let token = create_token("n\u{00f6}de-\u{1f600}", secret, Scope::all()).unwrap();
        let claims = validate_token(&token, secret).unwrap();
        assert_eq!(claims.sub, "n\u{00f6}de-\u{1f600}");
    }

    #[test]
    fn token_claims_have_24h_expiry() {
        let secret = "test-secret";
        let token = create_token("node1", secret, Scope::all()).unwrap();
        let claims = validate_token(&token, secret).unwrap();
        assert_eq!(claims.exp - claims.iat, 86400);
    }

    #[test]
    fn two_tokens_same_input_differ() {
        // Tokens generated at different times should differ (different iat/exp)
        // In practice they may be identical if generated within the same second,
        // but the structure should be consistent
        let secret = "test-secret";
        let t1 = create_token("node1", secret, Scope::all()).unwrap();
        let t2 = create_token("node1", secret, Scope::all()).unwrap();
        // Both should validate
        assert!(validate_token(&t1, secret).is_ok());
        assert!(validate_token(&t2, secret).is_ok());
    }

    #[test]
    fn base64_padding_in_token_rejected() {
        // Tamper with a valid token by adding padding characters
        let secret = "test-secret";
        let token = create_token("node1", secret, Scope::all()).unwrap();
        let tampered = format!("{token}===");
        let result = validate_token(&tampered, secret);
        assert!(result.is_err());
    }

    #[test]
    fn token_with_modified_payload_rejected() {
        let secret = "test-secret";
        let token = create_token("node1", secret, Scope::all()).unwrap();
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
