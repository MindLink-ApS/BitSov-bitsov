//! `GET /api/v1/export/bundle` — the one-click sovereignty exit bundle (X1).
//!
//! Assembles the node owner's complete *encrypted* recovery set into a single
//! authenticated response so they can migrate to self-hosting (or another
//! operator) with identity, funds, and relationships intact:
//!
//! - **SCB** (`scb-latest.aes`) — LDK channel-monitor state, encrypted with a
//!   seed-derived key by the rotation producer
//!   ([`konsensus_lightning::scb_rotate`]). Recovers **funds**. Served as-is.
//! - **Whitelist sidecar** — `peers` + `accepted_invites`, freshly sealed at
//!   request time with the identity AES key
//!   ([`konsensus_storage::WhitelistBackup`]). Recovers **relationships**.
//! - A restore **manifest** with the exact CLI steps.
//!
//! Charter discipline (P4):
//! - The bundle is **ciphertext only**. Both artifacts decrypt solely with the
//!   user's mnemonic-derived keys; the response carries no plaintext.
//! - The **mnemonic is never included** in this export — the user must already
//!   hold their seed separately. (On an operator-hosted *full* node the seed and
//!   AES key necessarily live on the host at runtime; this export does not — and
//!   cannot — change that. The strong "the operator can't read you" property
//!   belongs only to the unbuilt ciphertext-only relay tier, never a hosted full
//!   node. The narrow, honest guarantee here is that the export *response* is
//!   ciphertext-only.)
//! - Honest scope: recovers the peer whitelist + accepted invites + LDK channel
//!   state, **not** message history (`konsensus.db` messages/rooms/calendar/
//!   content, and pending/outgoing invites, are in neither artifact).
//! - Gated behind [`AuthUser`] (loopback JWT) — only the node owner. Available on
//!   every tier because the response is inert ciphertext without the seed, so it
//!   adds no operator-readable surface; this lets a user always pull their
//!   encrypted recovery set out. It does NOT by itself make hosted operation
//!   sovereign (a hosted operator still holds the runtime keys + metadata).

use std::path::Path;
use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use serde::Serialize;

use konsensus_storage::{Storage, WhitelistBackup};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

/// Filename of the rotated, encrypted SCB snapshot produced by
/// `konsensus_lightning::scb_rotate` (mirrors its private `LATEST_NAME`). Kept
/// as a local constant to avoid a cross-crate coupling for a single string.
const SCB_LATEST_NAME: &str = "scb-latest.aes";

/// SCB snapshot age beyond which the bundle carries a freshness warning. The
/// rotation producer refreshes `scb-latest.aes` on its own timer; a snapshot
/// older than this hints the node has not run recently and the channel state
/// in the bundle may lag the chain.
const SCB_STALE_WARN_SECS: u64 = 6 * 60 * 60;

/// Defensive upper bound on the SCB snapshot we will read + base64 into a
/// response. LDK channel-monitor state is normally kilobytes; a file beyond this
/// is corrupt/anomalous, so we omit it (with a warning) rather than amplify it
/// into a large allocation in the JSON body.
const SCB_MAX_BYTES: usize = 16 * 1024 * 1024;

/// The base64 + JSON exit bundle. Every byte the user receives is ciphertext
/// (or non-sensitive metadata); nothing here decrypts without the mnemonic.
#[derive(Debug, Serialize)]
pub struct ExitBundle {
    /// Stable format tag for the restore tooling.
    pub format: String,
    /// This node's identity (hex), for the user to confirm which node they
    /// exported.
    pub node_id: String,
    /// Unix time the bundle was assembled.
    pub created_unix: u64,
    /// Freshly sealed whitelist (peers + accepted_invites), base64. Recovers
    /// relationships. Decrypts only with the identity AES key.
    pub whitelist_backup_b64: String,
    /// Latest rotated, encrypted SCB (LDK channel state), base64 — `None` if no
    /// snapshot exists yet (e.g. a non-LDK backend). Recovers funds.
    pub scb_latest_b64: Option<String>,
    /// Age in seconds of the attached SCB snapshot (`None` when absent).
    pub scb_age_seconds: Option<u64>,
    /// Human-readable manifest: what's inside, what's not, how to restore.
    pub manifest: ExitManifest,
    /// Non-fatal advisories (stale/absent SCB, unconfigured backup dir).
    pub warnings: Vec<String>,
}

/// Plain-language description of the bundle's contents and restore procedure.
#[derive(Debug, Serialize)]
pub struct ExitManifest {
    /// What the bundle recovers.
    pub contains: Vec<String>,
    /// What it deliberately does NOT carry (so the user is never surprised).
    pub does_not_contain: Vec<String>,
    /// The exact CLI restore sequence on a fresh machine.
    pub restore_steps: Vec<String>,
}

/// `GET /api/v1/export/bundle` — authenticated owner-only export.
async fn export_bundle(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ExitBundle>, ApiError> {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let bundle = build_exit_bundle(
        state.storage.as_ref(),
        state.identity.aes_key(),
        state.identity.node_id().to_hex(),
        state.backup_dir.as_deref(),
        now_unix,
    )
    .await?;

    Ok(Json(bundle))
}

/// Pure assembly of the exit bundle — factored out of the Axum handler so it is
/// unit-testable with an in-memory store and a temp backup dir.
async fn build_exit_bundle(
    storage: &dyn Storage,
    aes_key: &[u8; 32],
    node_id_hex: String,
    backup_dir: Option<&Path>,
    now_unix: u64,
) -> Result<ExitBundle, ApiError> {
    let mut warnings = Vec::new();

    // 1. Seal a FRESH whitelist (peers + accepted_invites) at request time —
    //    current state, not the possibly-stale on-disk sidecar.
    //    Note: a collect failure here is intentionally FATAL (unlike the SCB
    //    path below, which degrades to a warning). The whitelist is the
    //    load-bearing relationship artifact; shipping a bundle that silently
    //    dropped it would give a false sense of a complete exit.
    let whitelist = WhitelistBackup::collect(storage, now_unix)
        .await
        .map_err(|e| ApiError::Storage(format!("failed to collect whitelist backup: {e}")))?;
    let sealed = whitelist
        .seal(aes_key)
        .map_err(|e| ApiError::Internal(format!("failed to seal whitelist backup: {e}")))?;
    let whitelist_backup_b64 = base64::engine::general_purpose::STANDARD.encode(&sealed);

    // 2. Attach the latest rotated, ENCRYPTED SCB snapshot (LDK channel state),
    //    served as-is. The rotation producer keeps it current; we only surface
    //    a freshness warning, never re-derive channel state here.
    let (scb_latest_b64, scb_age_seconds) = match backup_dir {
        Some(dir) => read_scb_snapshot(dir, &mut warnings),
        None => {
            warnings.push(
                "backup directory not configured — channel-state (SCB) recovery is unavailable; \
                 your mnemonic + whitelist backup still recover identity and relationships"
                    .into(),
            );
            (None, None)
        }
    };

    Ok(ExitBundle {
        format: "bitsov-exit-bundle/v1".into(),
        node_id: node_id_hex,
        created_unix: now_unix,
        whitelist_backup_b64,
        scb_latest_b64,
        scb_age_seconds,
        manifest: ExitManifest {
            contains: vec![
                "LDK channel-monitor state (encrypted) — recovers your funds".into(),
                "peer whitelist + accepted invites (encrypted) — who you federate with".into(),
            ],
            does_not_contain: vec![
                "your mnemonic / seed — keep it safe and SEPARATE; it is NOT in this bundle".into(),
                "message history, rooms, calendar, or stored content".into(),
                "pending/outgoing invites you have not had accepted yet".into(),
            ],
            restore_steps: vec![
                "On the new machine, install BitSov and run `konsensus init` with YOUR existing \
                 mnemonic (the same seed — that is what re-binds this identity)."
                    .into(),
                "Base64-decode `scb_latest_b64` into `scb-latest.aes` and `whitelist_backup_b64` \
                 into `whitelist-latest.aes`."
                    .into(),
                "Preview recoverable channels: `konsensus scb restore --from scb-latest.aes` \
                 (run from your node directory or pass `--config <konsensus.toml>`). Then, to \
                 actually reclaim funds on-chain via force-close, re-run with `--confirm`."
                    .into(),
                "Re-admit your peers: `konsensus whitelist restore --from whitelist-latest.aes`."
                    .into(),
                "Both files decrypt only with keys derived from your mnemonic — without it the \
                 bundle is inert ciphertext."
                    .into(),
            ],
        },
        warnings,
    })
}

/// Read the latest encrypted SCB snapshot from `dir`, pushing a warning if it is
/// missing or stale. Returns `(base64_ciphertext, age_seconds)`.
fn read_scb_snapshot(dir: &Path, warnings: &mut Vec<String>) -> (Option<String>, Option<u64>) {
    let scb_path = dir.join(SCB_LATEST_NAME);
    match std::fs::read(&scb_path) {
        Ok(bytes) => {
            let age_seconds = std::fs::metadata(&scb_path)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .map(|d| d.as_secs());
            // Defensive: never amplify a corrupt/oversized backup file into the
            // JSON body. Normal SCB state is kilobytes.
            if bytes.len() > SCB_MAX_BYTES {
                warnings.push(format!(
                    "SCB snapshot is unexpectedly large ({} bytes, over the {} byte cap) — \
                     omitted from the bundle; recover it directly from the node's backup \
                     directory instead",
                    bytes.len(),
                    SCB_MAX_BYTES
                ));
                return (None, None);
            }
            if let Some(secs) = age_seconds {
                if secs > SCB_STALE_WARN_SECS {
                    warnings.push(format!(
                        "SCB snapshot is {secs}s old — let the node run/reconnect so its channel \
                         state is current before relying on this backup"
                    ));
                }
            }
            (
                Some(base64::engine::general_purpose::STANDARD.encode(&bytes)),
                age_seconds,
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warnings.push(
                "no SCB snapshot present yet (non-LDK backend, or the node has not rotated one) — \
                 channel-state recovery is unavailable; your mnemonic + whitelist backup still \
                 recover identity and relationships"
                    .into(),
            );
            (None, None)
        }
        // A present-but-unreadable SCB is a real error: surface it rather than
        // silently shipping a fund-recovery bundle with no channel state.
        Err(e) => {
            warnings.push(format!(
                "could not read SCB snapshot ({e}) — channel-state recovery is unavailable in this \
                 bundle"
            ));
            (None, None)
        }
    }
}

/// X1 mounts a single authenticated read endpoint. No tier gate — the export
/// *response* is ciphertext-only, so it is safe to expose on any tier including
/// a hosted node. This does NOT by itself make hosted operation sovereign (a
/// hosted operator still holds the runtime keys + metadata); it only guarantees
/// the owner can always pull their encrypted recovery set out.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/export/bundle", get(export_bundle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_storage::SqliteStorage;

    const TEST_KEY: [u8; 32] = [0x42; 32];

    /// The bundle is ciphertext-only and the whitelist artifact actually opens
    /// with the sealing key — i.e. it is a real, restorable backup, not a stub.
    #[tokio::test]
    async fn exit_bundle_is_ciphertext_only_and_openable() {
        let storage = SqliteStorage::in_memory().await.unwrap();

        let bundle = build_exit_bundle(&storage, &TEST_KEY, "abcd".into(), None, 1_700_000_000)
            .await
            .expect("bundle assembles");

        assert_eq!(bundle.format, "bitsov-exit-bundle/v1");
        assert_eq!(bundle.node_id, "abcd");

        // Whitelist artifact decodes and RE-OPENS with the same key (proves it
        // is genuine, restorable ciphertext — the restorable-exit property).
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&bundle.whitelist_backup_b64)
            .expect("valid base64");
        WhitelistBackup::open(&raw, &TEST_KEY).expect("whitelist backup opens with the seal key");

        // No backup dir configured → no SCB, with an explicit advisory.
        assert!(bundle.scb_latest_b64.is_none());
        assert!(bundle.scb_age_seconds.is_none());
        assert!(bundle
            .warnings
            .iter()
            .any(|w| w.contains("backup directory not configured")));

        // The manifest never promises the mnemonic or message history.
        assert!(bundle
            .manifest
            .does_not_contain
            .iter()
            .any(|s| s.contains("mnemonic")));
        assert!(bundle
            .manifest
            .does_not_contain
            .iter()
            .any(|s| s.to_lowercase().contains("message history")));
    }

    /// When a rotated SCB snapshot exists on disk, it is attached verbatim
    /// (base64) and its age is reported.
    #[tokio::test]
    async fn exit_bundle_attaches_scb_when_present() {
        let storage = SqliteStorage::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let scb_bytes = b"BSCBKV01\x00\x00\x00\x00encrypted-channel-state";
        std::fs::write(dir.path().join(SCB_LATEST_NAME), scb_bytes).unwrap();

        let bundle = build_exit_bundle(
            &storage,
            &TEST_KEY,
            "node".into(),
            Some(dir.path()),
            1_700_000_000,
        )
        .await
        .expect("bundle assembles");

        let scb_b64 = bundle.scb_latest_b64.expect("scb attached");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&scb_b64)
            .expect("valid base64");
        assert_eq!(decoded, scb_bytes, "SCB attached verbatim as ciphertext");
        assert!(bundle.scb_age_seconds.is_some(), "fresh snapshot has an age");
    }
}
