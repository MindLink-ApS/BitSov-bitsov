//! Durable payment-attempt reconciliation, not a recipient admission grant.
//! Written before dispatch. Only recipient settlement can authorize admission.
use crate::{error::ApiError, state::AppState};
use konsensus_core::{NodeId, UkmEnvelope};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

#[derive(Serialize, Deserialize)]
pub(super) struct Attempt {
    pub payment_hash: String,
    pub amount_msat: u64,
    pub quote: Option<(u16, u64)>,
    pub envelope: Option<UkmEnvelope>,
    #[serde(default)]
    pub settled_at_unix: Option<u64>,
}
fn error(e: impl std::fmt::Display) -> ApiError {
    ApiError::Storage(format!("admission journal: {e}"))
}
fn directory(state: &AppState) -> Option<std::path::PathBuf> {
    state
        .data_dir
        .as_ref()
        .map(|p| p.join("admission-attempts"))
}
pub(super) fn load(state: &AppState, peer: &NodeId) -> Result<Option<Attempt>, ApiError> {
    let Some(dir) = directory(state) else {
        return Ok(None);
    };
    match fs::read(dir.join(peer.to_hex())) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(error),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(error(e)),
    }
}
fn sync_dir(dir: &Path) -> Result<(), ApiError> {
    fs::File::open(dir)
        .and_then(|f| f.sync_all())
        .map_err(error)
}
pub(super) fn save(state: &AppState, peer: &NodeId, attempt: &Attempt) -> Result<(), ApiError> {
    let Some(dir) = directory(state) else {
        return Ok(());
    }; // ephemeral test states
    fs::create_dir_all(&dir).map_err(error)?;
    if let Some(parent) = dir.parent() {
        sync_dir(parent)?;
    }
    let tmp = dir.join(format!(".{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp).map_err(error)?;
        file.write_all(&serde_json::to_vec(attempt).map_err(error)?)
            .map_err(error)?;
        file.sync_all().map_err(error)?;
        fs::rename(&tmp, dir.join(peer.to_hex())).map_err(error)?;
        sync_dir(&dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}
pub(super) fn clear(state: &AppState, peer: &NodeId) -> Result<(), ApiError> {
    let Some(dir) = directory(state) else {
        return Ok(());
    };
    match fs::remove_file(dir.join(peer.to_hex())) {
        Ok(()) => sync_dir(&dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(error(e)),
    }
}
