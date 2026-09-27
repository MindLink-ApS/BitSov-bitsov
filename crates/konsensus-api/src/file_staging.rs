//! Bounded volatile upload staging. Never writes blobs or metadata to disk:
//! restart starts empty, and abandoned uploads expire after five minutes.
use crate::{
    auth::{AuthUser, PairingBinding, Scope},
    error::ApiError,
    state::AppState,
};
use konsensus_storage::FileRecord;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;

pub const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_OWNER_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_FILES: usize = 64;
const TTL: Duration = Duration::from_secs(300);

#[derive(Clone, PartialEq, Eq)]
enum Owner {
    Paired {
        binding: PairingBinding,
        grant_op_id: String,
    },
    Local(String),
}
impl Owner {
    fn from_auth(state: &AppState, auth: &AuthUser) -> Option<Self> {
        match &auth.pairing {
            Some(binding) => Some(Self::Paired {
                binding: binding.clone(),
                grant_op_id: state.pairing.as_ref()?.live_spend_grant_id(binding)?,
            }),
            None => Some(Self::Local(auth.node_id.clone())),
        }
    }
    fn live(&self, state: &AppState) -> bool {
        match self {
            Self::Local(_) => true,
            Self::Paired {
                binding,
                grant_op_id,
            } => state
                .pairing
                .as_ref()
                .is_some_and(|s| s.live_spend_grant_id(binding).as_ref() == Some(grant_op_id)),
        }
    }
}
struct Entry {
    owner: Owner,
    file: Arc<FileRecord>,
    expires: Instant,
    sending: bool,
}
#[derive(Default)]
pub struct FileStaging {
    entries: HashMap<String, Entry>,
}
impl FileStaging {
    /// Includes in-flight sends in the quota until their guard is dropped.
    pub fn sweep(&mut self, state: &AppState) {
        let now = Instant::now();
        self.entries
            .retain(|_, e| e.sending || (e.expires > now && e.owner.live(state)));
    }
    pub fn insert(
        &mut self,
        state: &AppState,
        auth: &AuthUser,
        file: FileRecord,
    ) -> Result<(), ApiError> {
        self.sweep(state);
        let owner = Owner::from_auth(state, auth)
            .ok_or_else(|| ApiError::Forbidden("spend grant is no longer valid".into()))?;
        if !owner.live(state) {
            return Err(ApiError::Forbidden("spend grant is no longer valid".into()));
        }
        let size = file.data.len();
        if size > MAX_FILE_BYTES {
            return Err(ApiError::BadRequest(
                "file exceeds staging size limit".into(),
            ));
        }
        let total: usize = self.entries.values().map(|e| e.file.data.len()).sum();
        let own: usize = self
            .entries
            .values()
            .filter(|e| e.owner == owner)
            .map(|e| e.file.data.len())
            .sum();
        if self.entries.len() >= MAX_FILES
            || total + size > MAX_TOTAL_BYTES
            || own + size > MAX_OWNER_BYTES
        {
            return Err(ApiError::TooManyRequests(
                "file staging quota exhausted".into(),
            ));
        }
        self.entries.insert(
            file.id.clone(),
            Entry {
                owner,
                file: Arc::new(file),
                expires: Instant::now() + TTL,
                sending: false,
            },
        );
        Ok(())
    }
    pub fn get(&mut self, state: &AppState, auth: &AuthUser, id: &str) -> Option<Arc<FileRecord>> {
        self.sweep(state);
        let owner = Owner::from_auth(state, auth);
        self.entries
            .get(id)
            .filter(|e| !e.sending && (auth.has(Scope::Admin) || Some(&e.owner) == owner.as_ref()))
            .map(|e| Arc::clone(&e.file))
    }
    pub fn list(
        &mut self,
        state: &AppState,
        auth: &AuthUser,
    ) -> Vec<konsensus_storage::FileMetadata> {
        self.sweep(state);
        let owner = Owner::from_auth(state, auth);
        self.entries
            .values()
            .filter(|e| !e.sending && (auth.has(Scope::Admin) || Some(&e.owner) == owner.as_ref()))
            .map(|e| konsensus_storage::FileMetadata::from(e.file.as_ref()))
            .collect()
    }
    pub fn deadline(&self, id: &str) -> Instant {
        let max = Instant::now() + Duration::from_secs(60);
        self.entries
            .get(id)
            .map(|e| e.expires.min(max))
            .unwrap_or(max)
    }
    pub fn remove(&mut self, id: &str) -> bool {
        // Even an admin deletion must not release quota while a send still
        // owns the bytes. The guard removes it when that send ends.
        if self.entries.get(id).is_some_and(|e| e.sending) {
            return false;
        }
        self.entries.remove(id).is_some()
    }
    pub fn claim(
        state: &AppState,
        auth: &AuthUser,
        id: &str,
    ) -> Result<Option<SendGuard>, ApiError> {
        let mut staging = state.file_staging.lock().unwrap_or_else(|e| e.into_inner());
        staging.sweep(state);
        let Some(entry) = staging.entries.get_mut(id) else {
            return Ok(None);
        };
        if !entry.owner.live(state)
            || (!auth.has(Scope::Admin)
                && Some(entry.owner.clone()) != Owner::from_auth(state, auth))
        {
            return Err(ApiError::Forbidden("file belongs to another grant".into()));
        }
        if entry.sending {
            return Err(ApiError::Conflict("file send already in progress".into()));
        }
        entry.sending = true;
        Ok(Some(SendGuard {
            staging: Arc::clone(&state.file_staging),
            id: id.into(),
        }))
    }
}
/// Consumes staging on completion, error, or cancellation of a send. The quota
/// remains reserved throughout awaits, preventing concurrent sends from evading it.
pub struct SendGuard {
    staging: Arc<Mutex<FileStaging>>,
    id: String,
}
impl Drop for SendGuard {
    fn drop(&mut self) {
        self.staging
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn file(id: &str, size: usize) -> FileRecord {
        FileRecord {
            id: id.into(),
            filename: "f".into(),
            mime_type: "x".into(),
            size_bytes: size as u64,
            blake3_hash: String::new(),
            sender: String::new(),
            message_id: None,
            data: vec![0; size],
            created_at: String::new(),
        }
    }
    // Route-level tests exercise AppState-backed authorization and cleanup.
    #[test]
    fn fresh_start_has_no_staged_records() {
        assert!(FileStaging::default().entries.is_empty());
    }
    #[test]
    fn send_guard_consumes_blob_on_cancellation() {
        let staging = Arc::new(Mutex::new(FileStaging::default()));
        staging.lock().unwrap().entries.insert(
            "x".into(),
            Entry {
                owner: Owner::Local("a".into()),
                file: Arc::new(file("x", 1)),
                expires: Instant::now() + TTL,
                sending: true,
            },
        );
        drop(SendGuard {
            staging: staging.clone(),
            id: "x".into(),
        });
        assert!(staging.lock().unwrap().entries.is_empty());
    }
}
