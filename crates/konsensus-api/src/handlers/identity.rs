//! Identity endpoints — node identity information and recovery.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::audit::events;
use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

/// Node identity response.
#[derive(Serialize)]
pub struct IdentityResponse {
    /// Ed25519 public key (hex).
    pub node_id: String,
    /// X25519 public key (hex) for key exchange.
    pub x25519_public: String,
    /// secp256k1 public key (hex) for Bitcoin operations.
    pub secp256k1_public: String,
}

/// Request body for mnemonic verification.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyMnemonicRequest {
    /// BIP-39 mnemonic phrase (12 or 24 words, space-separated).
    pub mnemonic: String,
}

/// Response from mnemonic verification.
#[derive(Serialize)]
pub struct VerifyMnemonicResponse {
    /// The node ID (Ed25519 public key, hex) that this mnemonic would produce.
    pub node_id: String,
}

/// Request body for identity restore.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    /// BIP-39 mnemonic phrase (12 or 24 words, space-separated).
    pub mnemonic: String,
}

/// Response from identity restore.
#[derive(Serialize)]
pub struct RestoreResponse {
    /// The node ID derived from the restored mnemonic.
    pub node_id: String,
    /// Whether the node must be restarted for the new identity to take effect.
    pub restart_required: bool,
}

/// `GET /api/v1/identity` — get the node's public identity.
async fn get_identity(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Json<IdentityResponse> {
    Json(IdentityResponse {
        node_id: state.identity.node_id().to_hex(),
        x25519_public: hex::encode(state.identity.x25519_public().as_bytes()),
        secp256k1_public: state.identity.secp_public_key().to_string(),
    })
}

/// `POST /api/v1/identity/verify-mnemonic` — validate a mnemonic and return the derived node ID.
///
/// Used by the recovery wizard to let the user confirm which identity a mnemonic
/// would produce before committing to a restore. This is a stateless operation —
/// it does not modify any node state.
///
/// Gated behind `AuthUser` (L7b): the companion `restore_identity` endpoint
/// already requires auth, so the wizard always runs from an authenticated
/// context. Gating closes an oracle that an unauthenticated caller could
/// otherwise use to enumerate node IDs from candidate mnemonics.
async fn verify_mnemonic(
    _auth: AuthUser,
    Json(req): Json<VerifyMnemonicRequest>,
) -> Result<Json<VerifyMnemonicResponse>, ApiError> {
    validate_mnemonic_word_count(&req.mnemonic)?;
    let identity = konsensus_core::NodeIdentity::from_mnemonic(&req.mnemonic, "")
        .map_err(|e| ApiError::BadRequest(format!("invalid mnemonic: {e}")))?;

    Ok(Json(VerifyMnemonicResponse {
        node_id: identity.node_id().to_hex(),
    }))
}

/// `POST /api/v1/identity/restore` — write a recovery mnemonic to the data directory.
///
/// Saves the mnemonic to the node's data directory as `mnemonic.txt`. The node
/// must be restarted for the new identity to take effect. If the data directory
/// is not configured, returns an error.
async fn restore_identity(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<RestoreRequest>,
) -> Result<Json<RestoreResponse>, ApiError> {
    // Validate the mnemonic first
    validate_mnemonic_word_count(&req.mnemonic)?;
    let identity = konsensus_core::NodeIdentity::from_mnemonic(&req.mnemonic, "")
        .map_err(|e| ApiError::BadRequest(format!("invalid mnemonic: {e}")))?;

    let data_dir = state
        .data_dir
        .as_ref()
        .ok_or_else(|| ApiError::Internal("node data directory not configured".into()))?;

    let mnemonic_path = data_dir.join("mnemonic.txt");

    // Write the mnemonic as plaintext. Users can encrypt it later via
    // `konsensus init --encrypt` or the CLI password prompt.
    std::fs::write(&mnemonic_path, &req.mnemonic)
        .map_err(|e| ApiError::Internal(format!("failed to write mnemonic: {e}")))?;

    Ok(Json(RestoreResponse {
        node_id: identity.node_id().to_hex(),
        restart_required: true,
    }))
}

/// Request body for the mnemonic read-back (seed reveal).
///
/// Revealing the recovery seed requires explicit re-authentication on top of
/// the JWT carried by [`AuthUser`]: the caller must present a fresh,
/// single-use challenge (from `GET /api/v1/auth/challenge`) together with its
/// Ed25519 signature, proving live possession of the node signing key at the
/// moment of the reveal. A stolen long-lived JWT alone is therefore not
/// sufficient to exfiltrate the seed (HARD-9).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevealMnemonicRequest {
    /// Opaque single-use challenge string from `GET /api/v1/auth/challenge`.
    pub challenge: String,
    /// Hex-encoded Ed25519 signature of `challenge` by the node key.
    pub signature: String,
}

/// Response from mnemonic retrieval.
///
/// The seed is held in [`Zeroizing<String>`] so the in-process plaintext is
/// scrubbed from memory the moment this response value is dropped (HARD-9).
/// Serialization writes the seed into the HTTP body exactly once — that is the
/// feature — but no lingering raw `String` or clone is left behind on this
/// seam. The custom serializer borrows the inner `&str` without copying it out
/// of the zeroizing wrapper.
#[derive(Serialize)]
pub struct MnemonicResponse {
    /// The BIP-39 mnemonic phrase (space-separated words).
    #[serde(serialize_with = "serialize_zeroizing")]
    pub mnemonic: Zeroizing<String>,
}

/// Serialize a [`Zeroizing<String>`] by borrowing its `&str`, so the seed is
/// never copied into an intermediate owned `String` before hitting the wire.
fn serialize_zeroizing<S>(value: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.as_str())
}

/// Read a plaintext mnemonic file into a [`Zeroizing<String>`], trimming
/// trailing whitespace into a fresh zeroizing allocation.
///
/// This mirrors the zeroizing read contract of
/// `konsensus_node::mnemonic_crypto::read_mnemonic` on the REST reveal seam
/// (HARD-9). `konsensus-api` cannot depend on `konsensus-node` (the dependency
/// runs the other way), so the contract is reproduced here rather than imported.
///
/// The untrimmed `read_to_string` buffer is wrapped in `Zeroizing` immediately,
/// so the raw file contents (the seed included) are scrubbed on drop — not just
/// the trimmed copy. There is no residual non-zeroizing plaintext on this seam.
/// Only `.enc`-absent plaintext files reach this path; encrypted mnemonics are
/// rejected before it is called.
fn read_plaintext_mnemonic_zeroizing(
    path: &std::path::Path,
) -> Result<Zeroizing<String>, std::io::Error> {
    // Wrap the full read buffer in `Zeroizing` before any further use so the
    // untrimmed plaintext (which contains the whole mnemonic) is wiped on drop,
    // not only the trimmed result (#238 residual-leak fix).
    let raw = Zeroizing::new(std::fs::read_to_string(path)?);
    Ok(Zeroizing::new(raw.trim().to_string()))
}

/// Consume a single-use auth challenge, returning an error if it is unknown,
/// already used, or expired. Mirrors the consumption semantics of
/// `POST /api/v1/auth/token` so the reveal re-auth is exactly as strong.
async fn consume_challenge(state: &AppState, challenge: &str) -> Result<(), ApiError> {
    let now = Instant::now();
    let mut challenges = state.auth_challenges.lock().await;
    let expires_at = challenges.remove(challenge).ok_or_else(|| {
        ApiError::Unauthorized("auth challenge is unknown or already used".into())
    })?;
    if expires_at <= now {
        return Err(ApiError::Unauthorized("auth challenge expired".into()));
    }
    Ok(())
}

/// `POST /api/v1/identity/mnemonic` — reveal the node's mnemonic for backup.
///
/// Returns the plaintext recovery seed from the node's data directory. This is
/// the single most sensitive read in the API, so it is hardened well beyond a
/// plain JWT check (HARD-9):
///
/// 1. **Re-auth.** The caller must prove live possession of the node signing
///    key by signing a fresh single-use challenge (defence against a leaked
///    24h JWT silently exfiltrating the seed).
/// 2. **Rate limit.** A dedicated strict limiter bounds reveal attempts to a
///    handful per minute, throttling brute-force of the re-auth gate.
/// 3. **Audit.** Every attempt — success or failure — is recorded to the
///    append-only audit log. The seed itself is never logged.
///
/// If the mnemonic is encrypted (`.enc` file), returns an error directing the
/// user to the CLI. Intended for the onboarding wizard / settings to display
/// the recovery phrase for backup.
async fn reveal_mnemonic(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<RevealMnemonicRequest>,
) -> Result<Json<MnemonicResponse>, ApiError> {
    let actor = auth.node_id.clone();

    // 2. Rate limit (checked first so flooding cannot exhaust the audit log or
    //    the challenge store). Keyed per authenticated actor.
    if !state.mnemonic_reveal_limiter.check_key(&actor) {
        state.audit_log.record(
            events::MNEMONIC_REVEALED,
            &actor,
            Some(serde_json::json!({"success": false, "reason": "rate_limited"})),
        );
        return Err(ApiError::TooManyRequests(
            "too many mnemonic reveal attempts — try again shortly".into(),
        ));
    }

    // 1. Re-auth: consume the single-use challenge and verify the signature
    //    against the node's own public key.
    let challenge = req.challenge.trim();
    if challenge.is_empty() {
        state.audit_log.record(
            events::MNEMONIC_REVEALED,
            &actor,
            Some(serde_json::json!({"success": false, "reason": "missing_challenge"})),
        );
        return Err(ApiError::BadRequest("challenge is required".into()));
    }

    if let Err(e) = consume_challenge(&state, challenge).await {
        state.audit_log.record(
            events::MNEMONIC_REVEALED,
            &actor,
            Some(serde_json::json!({"success": false, "reason": "challenge_invalid"})),
        );
        return Err(e);
    }

    let sig_bytes = hex::decode(&req.signature).map_err(|e| {
        state.audit_log.record(
            events::MNEMONIC_REVEALED,
            &actor,
            Some(serde_json::json!({"success": false, "reason": "bad_signature_hex"})),
        );
        ApiError::BadRequest(format!("invalid signature hex: {e}"))
    })?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|e| {
        state.audit_log.record(
            events::MNEMONIC_REVEALED,
            &actor,
            Some(serde_json::json!({"success": false, "reason": "bad_signature"})),
        );
        ApiError::BadRequest(format!("invalid signature: {e}"))
    })?;

    if state.identity.verify(challenge.as_bytes(), &sig).is_err() {
        metrics::counter!(crate::metrics::AUTH_FAILURES).increment(1);
        state.audit_log.record(
            events::MNEMONIC_REVEALED,
            &actor,
            Some(serde_json::json!({"success": false, "reason": "signature_verify_failed"})),
        );
        return Err(ApiError::Unauthorized(
            "re-auth signature verification failed".into(),
        ));
    }

    // Re-auth passed. Now read the seed. Every failure path below STILL audits a
    // `success: false` reveal attempt with a reason: these are exactly the
    // sensitive post-re-auth cases (a caller has proven possession of the node
    // key), so the "every reveal attempt is audited" contract must hold here too.
    // The seed itself is never included in any audit detail.
    let data_dir = match state.data_dir.as_ref() {
        Some(dir) => dir,
        None => {
            state.audit_log.record(
                events::MNEMONIC_REVEALED,
                &actor,
                Some(serde_json::json!({"success": false, "reason": "no_data_dir"})),
            );
            return Err(ApiError::Internal(
                "node data directory not configured".into(),
            ));
        }
    };

    let plain_path = data_dir.join("mnemonic.txt");
    let enc_path = data_dir.join("mnemonic.enc");

    if enc_path.exists() {
        state.audit_log.record(
            events::MNEMONIC_REVEALED,
            &actor,
            Some(serde_json::json!({"success": false, "reason": "mnemonic_encrypted"})),
        );
        return Err(ApiError::BadRequest(
            "mnemonic is encrypted — use the CLI to view it: konsensus node-id".into(),
        ));
    }

    if !plain_path.exists() {
        state.audit_log.record(
            events::MNEMONIC_REVEALED,
            &actor,
            Some(serde_json::json!({"success": false, "reason": "mnemonic_file_missing"})),
        );
        return Err(ApiError::NotFound(
            "mnemonic file not found in data directory".into(),
        ));
    }

    // Read the seed into a zeroizing string and keep it zeroizing end-to-end:
    // it is trimmed in place, audited (without ever logging the seed), then
    // moved into the response whose `Serialize` impl borrows it for the wire.
    // The plaintext `String` is scrubbed from memory on drop (HARD-9). No raw
    // non-zeroizing `String` or clone of the seed survives this seam.
    let mnemonic = read_plaintext_mnemonic_zeroizing(&plain_path).map_err(|e| {
        state.audit_log.record(
            events::MNEMONIC_REVEALED,
            &actor,
            Some(serde_json::json!({"success": false, "reason": "read_error"})),
        );
        ApiError::Internal(format!("failed to read mnemonic: {e}"))
    })?;

    // 3. Audit the successful reveal. The seed is NEVER included in the detail.
    state.audit_log.record(
        events::MNEMONIC_REVEALED,
        &actor,
        Some(serde_json::json!({"success": true})),
    );

    Ok(Json(MnemonicResponse { mnemonic }))
}

/// Validates that a mnemonic has a valid BIP-39 word count (12 or 24 words).
///
/// This is a cheap pre-check before the expensive key derivation, preventing
/// resource exhaustion from arbitrarily long inputs.
fn validate_mnemonic_word_count(mnemonic: &str) -> Result<(), ApiError> {
    let word_count = mnemonic.split_whitespace().count();
    if word_count != 12 && word_count != 24 {
        return Err(ApiError::BadRequest(format!(
            "mnemonic must be 12 or 24 words, got {word_count}"
        )));
    }
    Ok(())
}

/// Registers identity routes.
///
/// Mnemonic restore/reveal routes are mounted only for self-hosted contexts.
/// In operator/relay contexts they must be architecturally absent so an
/// operator-side auth bypass cannot become mnemonic custody.
pub fn routes(sensitive_identity_routes_enabled: bool) -> Router<Arc<AppState>> {
    let router = Router::new().route("/api/v1/identity", get(get_identity));

    if sensitive_identity_routes_enabled {
        router
            // Reveal is a POST (not GET): it requires a re-auth body (fresh
            // challenge + signature) and is the most sensitive read in the
            // API. See `reveal_mnemonic` (HARD-9).
            .route("/api/v1/identity/mnemonic", post(reveal_mnemonic))
            .route("/api/v1/identity/verify-mnemonic", post(verify_mnemonic))
            .route("/api/v1/identity/restore", post(restore_identity))
    } else {
        router
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plaintext-reveal helper returns a [`Zeroizing<String>`] — enforced
    /// at the type level — and trims surrounding whitespace/newlines into that
    /// zeroizing allocation. This is the seam HARD-9 hardens: the in-process
    /// seed is scrubbed on drop rather than left in a raw `String`.
    #[test]
    fn read_plaintext_mnemonic_is_zeroizing_and_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mnemonic.txt");
        std::fs::write(&path, "  abandon abandon about \n").unwrap();

        let seed: Zeroizing<String> = read_plaintext_mnemonic_zeroizing(&path).unwrap();
        assert_eq!(seed.as_str(), "abandon abandon about");
    }

    /// `MnemonicResponse.mnemonic` must stay a `Zeroizing<String>` so the seed
    /// is scrubbed on drop, while still serializing to a plain JSON string for
    /// the wire (the reveal feature). Asserting both pins the contract against
    /// a regression back to a raw `String` field.
    #[test]
    fn mnemonic_response_holds_zeroizing_and_serializes_as_string() {
        let resp = MnemonicResponse {
            mnemonic: Zeroizing::new("abandon abandon about".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["mnemonic"], "abandon abandon about");
        // The serialized form is a bare string, not an object/array — i.e. the
        // zeroizing wrapper is transparent on the wire.
        assert!(json["mnemonic"].is_string());
    }

    /// Structural guard: the reveal handler source must route the seed read
    /// through the zeroizing helper and must NOT contain a raw
    /// `read_to_string(&plain_path)` on the reveal seam. This is a code-shape
    /// assertion that survives even if the runtime behaviour looks identical —
    /// the exact regression Codex flagged on PR #238.
    #[test]
    fn reveal_seam_uses_zeroizing_read_not_raw_string() {
        let src = include_str!("identity.rs");
        assert!(
            src.contains("read_plaintext_mnemonic_zeroizing(&plain_path)"),
            "reveal handler must read the seed via the zeroizing helper"
        );
        // Build the forbidden needle from parts so this assertion's own source
        // line does not contain it verbatim (which `include_str!` would match).
        let raw_read_needle = format!("std::fs::{}(&plain_path)", "read_to_string");
        assert!(
            !src.contains(&raw_read_needle),
            "reveal seam must not read the seed into a raw non-zeroizing String"
        );
        // Positive guard (#238): the plaintext helper must wrap the untrimmed
        // read buffer in `Zeroizing` immediately, so the full file contents are
        // scrubbed on drop rather than left as a residual non-zeroizing String.
        // Built from parts so this line does not self-match under include_str!.
        let zeroizing_read_needle = format!("Zeroizing::new(std::fs::{}(", "read_to_string");
        assert!(
            src.contains(&zeroizing_read_needle),
            "plaintext seed read must wrap the untrimmed buffer in Zeroizing immediately"
        );
    }
}
