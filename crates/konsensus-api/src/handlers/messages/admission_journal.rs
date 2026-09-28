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

/// Original context for the N2 settlement notification, never admission authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ReadmissionSettlement {
    pub budget_msat: Option<u64>,
    #[serde(default)]
    pub reported: bool,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Attempt {
    /// False proves the operation-journal handshake has not reached dispatch.
    /// Legacy journals remain conservatively dispatched.
    #[serde(default = "legacy_proof_delivered")]
    pub dispatch_started: bool,
    #[serde(default)]
    pub previous_attempt: Option<Box<Attempt>>,
    #[serde(default)]
    pub operation: Option<crate::spend_budget::OperationReservationLink>,
    #[serde(default)]
    pub max_routing_fee_msat: Option<u64>,
    pub payment_hash: String,
    pub amount_msat: u64,
    pub quote: Option<(u16, u64)>,
    pub envelope: Option<UkmEnvelope>,
    #[serde(default)]
    pub settled_at_unix: Option<u64>,
    #[serde(default)]
    pub original_reservation: Option<crate::spend_budget::Reservation>,
    #[serde(default)]
    pub message_may_have_dispatched: bool,
    #[serde(default)]
    pub readmission: Option<ReadmissionSettlement>,
    /// Whether the proof in `envelope` may have gone out. A journal written
    /// before this field existed counts as delivered: its proof may have been
    /// consumed, so it is never re-sent on a replacement connection.
    #[serde(default = "legacy_proof_delivered")]
    pub proof_delivered: bool,
}
fn legacy_proof_delivered() -> bool {
    true
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

/// Resolve a positively failed attempt before removing its recovery identity.
pub(super) fn clear_failed(state: &AppState, peer: &NodeId) -> Result<(), ApiError> {
    if let Some(attempt) = load(state, peer)? {
        if !attempt.message_may_have_dispatched {
            if let (Some(service), Some(original)) = (&state.pairing, &attempt.original_reservation) {
                service.resolve_spend(original, &peer.to_hex(), 0);
            }
        }
    }
    clear(state, peer)
}


/// Remove only the exact known-undispatched guard, restoring any earlier record.
/// Persisted intent makes cancellation/process death during the async operation
/// write recoverable too; a legacy or possibly-dispatched attempt is untouched.
pub(super) fn undo_undispatched(state: &AppState, peer: &NodeId, hash: &str) -> Result<bool, ApiError> {
    let Some(attempt) = load(state, peer)? else { return Ok(false); };
    if attempt.payment_hash != hash || attempt.dispatch_started { return Ok(false); }
    if let (Some(service), Some(original)) = (&state.pairing, &attempt.original_reservation) {
        service.try_resolve_spend(original, &peer.to_hex(), 0).map_err(error)?;
    }
    match attempt.previous_attempt {
        Some(previous) => save(state, peer, &previous)?,
        None => clear(state, peer)?,
    }
    Ok(true)
}

/// Checkpoint positive non-dispatch before any cancellable operation-store await.
pub(super) fn mark_undispatched(state: &AppState, peer: &NodeId, hash: &str) -> Result<(), ApiError> {
    if let Some(mut attempt) = load(state, peer)? {
        if attempt.payment_hash == hash {
            attempt.dispatch_started = false;
            save(state, peer, &attempt)?;
        }
    }
    Ok(())
}
