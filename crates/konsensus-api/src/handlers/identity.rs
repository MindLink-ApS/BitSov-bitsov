//! Identity endpoints — node identity information and recovery.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

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

/// Response from mnemonic retrieval.
#[derive(Serialize)]
pub struct MnemonicResponse {
    /// The BIP-39 mnemonic phrase (space-separated words).
    pub mnemonic: String,
}

/// `GET /api/v1/identity/mnemonic` — retrieve the node's mnemonic for backup display.
///
/// Returns the plaintext mnemonic from the node's data directory. If the mnemonic
/// is encrypted (`.enc` file), returns an error directing the user to the CLI.
/// This endpoint is JWT-protected and intended for the onboarding wizard to display
/// the recovery phrase for backup.
async fn get_mnemonic(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<MnemonicResponse>, ApiError> {
    let data_dir = state
        .data_dir
        .as_ref()
        .ok_or_else(|| ApiError::Internal("node data directory not configured".into()))?;

    let plain_path = data_dir.join("mnemonic.txt");
    let enc_path = data_dir.join("mnemonic.enc");

    if enc_path.exists() {
        return Err(ApiError::BadRequest(
            "mnemonic is encrypted — use the CLI to view it: konsensus node-id".into(),
        ));
    }

    if !plain_path.exists() {
        return Err(ApiError::NotFound(
            "mnemonic file not found in data directory".into(),
        ));
    }

    let mnemonic = std::fs::read_to_string(&plain_path)
        .map_err(|e| ApiError::Internal(format!("failed to read mnemonic: {e}")))?;

    Ok(Json(MnemonicResponse {
        mnemonic: mnemonic.trim().to_string(),
    }))
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
            .route("/api/v1/identity/mnemonic", get(get_mnemonic))
            .route("/api/v1/identity/verify-mnemonic", post(verify_mnemonic))
            .route("/api/v1/identity/restore", post(restore_identity))
    } else {
        router
    }
}
