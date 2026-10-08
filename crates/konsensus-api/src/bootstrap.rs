//! Identity-free bootstrap: first-run pairing, create/restore, and the atomic
//! transition to an initialized node (#76, P1-1).
//!
//! # Why this exists at all
//!
//! `konsensus init` generates an identity unconditionally, and the JWT secret
//! is derived from that identity — so a node with no identity has no signing
//! key either. An app installed on a clean machine therefore had no way to
//! restore from a recovery phrase: there was nothing to authenticate against.
//!
//! Bootstrap is a mode of **`serve`**, not of `init`. `init` keeps its current
//! behaviour for operators who create a node from the CLI.
//!
//! # Entry is positive evidence of emptiness, never inference
//!
//! [`classify`] requires a **conjunction**: the `NODE_INITIALIZED` marker is
//! absent, *and* no identity material exists, *and* no wallet or channel state
//! exists. If the marker is absent but any other clause fails, the node
//! **refuses to start** and names the repair command. It does not enter
//! bootstrap.
//!
//! That rule is the load-bearing one. Absence of a mnemonic on a node holding
//! channel state is a **deleted key**, not a fresh install, and must never be
//! answered by reopening first-run authority — which is precisely the state an
//! attacker would try to induce.
//!
//! **"Fresh" is never "an existing identity with a zero balance".** Balance is
//! not an authorization input: it is not a field of [`DataDirProbe`] and
//! [`classify`] cannot consult it. An initialized node with no funds is
//! initialized.
//!
//! # The transition
//!
//! One commit, marker last, single-flight — see [`commit_first_run`].

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use serde::{Deserialize, Serialize};

use crate::auth::{self, Scope};
use crate::pairing::{self, PairingError, PairingService};
use crate::rate_limit::RemoteTunnelClients;

/// The marker file whose presence is the **sole** authority signal for "this
/// data directory has been initialized".
///
/// Written last in the transition and never consulted alongside a heuristic.
pub const MARKER_FILE: &str = "NODE_INITIALIZED";

/// Prefix of a staging directory used by an in-flight transition.
pub const STAGING_PREFIX: &str = ".init-";

/// Subdirectory the transition renames into place, holding identity material.
pub const IDENTITY_DIR: &str = "identity";

/// Where the data directory's files live, so the probe and the transition agree.
#[derive(Debug, Clone)]
pub struct DataDirLayout {
    /// The node data directory.
    pub data_dir: PathBuf,
    mnemonic_path: Option<PathBuf>,
    storage_path: Option<PathBuf>,
    backup_dir: Option<PathBuf>,
    external_store: bool,
}

impl DataDirLayout {
    /// Layout for `data_dir`.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            mnemonic_path: None,
            storage_path: None,
            backup_dir: None,
            external_store: false,
        }
    }

    /// Use the same configured paths as the running node. A remote store cannot
    /// be proven empty by a filesystem probe, so it never permits bootstrap.
    pub fn with_configured_paths(
        mut self,
        mnemonic: PathBuf,
        sqlite: Option<PathBuf>,
        backup_dir: PathBuf,
    ) -> Self {
        self.mnemonic_path = Some(mnemonic);
        self.external_store = sqlite.is_none();
        self.storage_path = sqlite;
        self.backup_dir = Some(backup_dir);
        self
    }

    /// The initialization marker.
    pub fn marker(&self) -> PathBuf {
        self.data_dir.join(MARKER_FILE)
    }

    /// The identity directory the transition renames into place.
    pub fn identity_dir(&self) -> PathBuf {
        self.data_dir.join(IDENTITY_DIR)
    }

    /// Every place a mnemonic may live. `init` writes the top-level file; the
    /// bootstrap transition writes the one under `identity/`.
    pub fn mnemonic_candidates(&self) -> Vec<PathBuf> {
        let mut paths = vec![
            self.data_dir.join("mnemonic.txt"),
            self.data_dir.join("mnemonic.enc"),
            self.identity_dir().join("mnemonic.txt"),
            self.identity_dir().join("mnemonic.enc"),
            self.identity_dir().join("identity.json"),
        ];
        paths.extend(self.mnemonic_path.iter().cloned());
        paths
    }

    /// Wallet, channel and store state. Any of these on a marker-less node
    /// means "deleted key", not "fresh install".
    pub fn state_candidates(&self) -> Vec<PathBuf> {
        let mut paths = vec![
            self.data_dir.join("konsensus.db"),
            self.data_dir.join("ldk"),
            self.identity_dir().join("ldk"),
            self.data_dir.join("backups"),
        ];
        if let Some(mnemonic) = &self.mnemonic_path {
            paths.push(mnemonic.parent().unwrap_or(Path::new(".")).join("ldk"));
        }
        paths.extend(self.storage_path.iter().cloned());
        paths.extend(self.backup_dir.iter().cloned());
        paths
    }

    /// The storage database, whose readability is checked on an initialized node.
    pub fn store(&self) -> PathBuf {
        self.storage_path
            .clone()
            .unwrap_or_else(|| self.data_dir.join("konsensus.db"))
    }

    /// The config file `konsensus init` writes and the transition does not.
    pub fn config(&self) -> PathBuf {
        self.data_dir.join("konsensus.toml")
    }
}

/// Facts about a data directory. Deliberately only facts about **files**.
///
/// There is no balance field, and no way to add one without editing this type:
/// balance is not an authorization input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDirProbe {
    /// Is the `NODE_INITIALIZED` marker present?
    pub marker_present: bool,
    /// Does any identity material exist (mnemonic file, identity record)?
    pub identity_material_present: bool,
    /// Does any wallet, channel or store state exist?
    pub wallet_or_channel_state_present: bool,
    /// Is the storage database readable (absent counts as readable)?
    pub store_readable: bool,
    /// Staging directories left by an interrupted transition. **Reported and
    /// ignored** — startup never consumes one.
    pub stray_staging: Vec<PathBuf>,
}

impl DataDirProbe {
    /// Probe `layout` on disk.
    pub fn inspect(layout: &DataDirLayout) -> io::Result<Self> {
        let marker_present = layout.marker().try_exists()?;
        let mut identity_material_present = false;
        for path in layout.mnemonic_candidates() {
            identity_material_present |= path.try_exists()?;
        }
        let mut wallet_or_channel_state_present = layout.external_store;
        for path in layout.state_candidates() {
            wallet_or_channel_state_present |= path.try_exists()?;
        }

        let store = layout.store();
        let store_readable = if store.try_exists()? {
            is_readable_sqlite(&store)
        } else {
            true
        };

        let mut stray_staging = Vec::new();
        if layout.data_dir.exists() {
            for entry in std::fs::read_dir(&layout.data_dir)? {
                let entry = entry?;
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(STAGING_PREFIX)
                {
                    stray_staging.push(entry.path());
                }
            }
            stray_staging.sort();
        }

        Ok(Self {
            marker_present,
            identity_material_present,
            wallet_or_channel_state_present,
            store_readable,
            stray_staging,
        })
    }
}

/// A file that exists but is not a usable SQLite database is corrupt, which is
/// an operator repair — never an automatic reopen of first-run authority.
fn is_readable_sqlite(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut header = [0u8; 16];
    match f.read_exact(&mut header) {
        // A truncated existing store is not a fresh database.
        Err(_) => false,
        Ok(()) => &header == b"SQLite format 3\0",
    }
}

/// Why a node refuses to start, and what the operator should actually run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Refusal {
    /// Stable machine-readable reason.
    pub reason: &'static str,
    /// Human-readable explanation of the state found.
    pub detail: String,
    /// The concrete repair action. Not advice to "check the logs".
    pub repair: String,
}

/// What a `serve` invocation should do with this data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupMode {
    /// No identity, no state, no marker: first-run bootstrap may open.
    Bootstrap,
    /// Fully initialized: start the node normally.
    Initialized,
    /// Partial or damaged state: fail closed and demand repair.
    Refuse(Refusal),
}

/// Decide the startup mode from file facts alone.
///
/// The governing principle, applied in every branch: **fail closed and demand
/// repair, rather than reopen first-run authority.**
pub fn classify(probe: &DataDirProbe) -> StartupMode {
    if !probe.marker_present {
        // Marker absent. Bootstrap requires the FULL conjunction.

        if probe.identity_material_present && probe.wallet_or_channel_state_present {
            return StartupMode::Refuse(Refusal {
                reason: "identity_and_state_without_marker",
                detail: "identity material and wallet/channel state exist but the \
                         NODE_INITIALIZED marker is absent — common when upgrading a production \
                         node from before #76/#77 (the marker did not exist yet), or after a crash \
                         between renaming identity into place and writing the marker"
                    .into(),
                repair: repair_mark_initialized(),
            });
        }
        if probe.identity_material_present {
            return StartupMode::Refuse(Refusal {
                reason: "identity_without_marker",
                detail: "identity material exists but the initialization marker is absent — \
                         an interrupted first-run transition, not a fresh install"
                    .into(),
                repair: repair_mark_initialized(),
            });
        }
        if probe.wallet_or_channel_state_present {
            return StartupMode::Refuse(Refusal {
                reason: "state_without_identity",
                detail: "wallet or channel state exists but no identity material does — this \
                         is a DELETED KEY on a node that may hold funds, not a fresh install. \
                         Reopening first-run authority here would hand a paired client control \
                         of live channel state"
                    .into(),
                repair: repair_restore_mnemonic(),
            });
        }
        return StartupMode::Bootstrap;
    }

    // Marker present: this directory is initialized, whatever its balance.
    if !probe.identity_material_present {
        return StartupMode::Refuse(Refusal {
            reason: "initialized_missing_identity",
            detail: "the node is initialized but its mnemonic file is missing — a funded node \
                     with a deleted key. Answering this as a fresh node would hand first-run \
                     authority over live channel state"
                .into(),
            repair: repair_restore_mnemonic(),
        });
    }
    if !probe.store_readable {
        return StartupMode::Refuse(Refusal {
            reason: "initialized_store_corrupt",
            detail: "the node is initialized and its identity is present, but konsensus.db is \
                     not a readable database"
                .into(),
            repair: "restore konsensus.db from backup, then run \
                     `konsensus whitelist restore --from <whitelist-latest.aes>` if the \
                     whitelist was lost. Repair is an operator action — the node will not \
                     recreate the store, because that would silently discard relationships."
                .into(),
        });
    }
    StartupMode::Initialized
}

fn repair_mark_initialized() -> String {
    "run `konsensus repair mark-initialized --config <path-to-konsensus.toml> --confirm` \
     (writes NODE_INITIALIZED and nothing else). Required for legacy nodes upgraded without \
     the marker and for interrupted first-run transitions. The node will not write the marker \
     for you, because doing so silently would make a crashed transition indistinguishable from \
     a completed one. Alternatively, move the data directory aside to start over."
        .to_string()
}

fn repair_restore_mnemonic() -> String {
    "restore the recovery phrase for THIS node with \
     `konsensus restore --dir <data-dir> --mnemonic \"<24 words>\"` (the same identity as \
     the existing state), or move the data directory aside if the funds are genuinely \
     abandoned. The node will not open first-run pairing on a directory that already holds \
     state."
        .to_string()
}

/// Where a crash is simulated in [`commit_first_run_with_fault`].
///
/// A testability seam, not a feature: production calls [`commit_first_run`],
/// which passes [`CommitFault::None`]. The crash-safety rules in `classify`
/// cannot be verified any other way without killing a real process mid-syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitFault {
    /// Commit normally.
    None,
    /// Stop after staging, before the rename.
    AbortBeforeRename,
    /// Stop after the rename, before the marker is written.
    AbortAfterRename,
}

/// What a completed transition produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitOutcome {
    /// Node id (hex) of the committed identity.
    pub node_id: String,
    /// Fingerprint of the committed identity.
    pub identity_fingerprint: String,
    /// Path the mnemonic was written to.
    pub mnemonic_path: PathBuf,
    /// Box transport key and its identity proof, written to `identity.json`.
    pub box_transport: Option<(String, String)>,
    /// Live transport public key (hex), written to `identity.json`.
    pub transport_pubkey: Option<String>,
    /// Identity signature over the live transport key, written to `identity.json`.
    pub transport_signature: Option<String>,
}

/// Hook after rebind and before `NODE_INITIALIZED` (clippy::type_complexity).
type BeforeMarkerHook<'a> = dyn Fn(&CommitOutcome) -> Result<(), CommitError> + 'a;

/// Owned, thread-safe [`BeforeMarkerHook`] for [`BootstrapState`].
type BeforeMarkerHookOwned = Arc<dyn Fn(&CommitOutcome) -> Result<(), CommitError> + Send + Sync>;

/// Encryption supplied by the node crate; the API never receives the password.
pub type EncryptSeedHook = dyn Fn(&str, &Path) -> Result<PathBuf, CommitError> + Send + Sync;
/// Transient owner signing supplied by the node crate.
pub type SignOwnerHook = dyn Fn(&str, &str, &str) -> Result<String, CommitError> + Send + Sync;

/// Local first-run capabilities. Captured passwords must be zeroizing.
pub struct LocalOwnerHooks {
    /// Write and fsync staging/mnemonic.enc with owner-only permissions.
    pub encrypt_seed: Box<EncryptSeedHook>,
    /// Sign the canonical owner approval; discard the derived signing key.
    pub sign_owner_approval: Box<SignOwnerHook>,
    /// Require enrollment of the first owner device.
    pub enroll_device: bool,
}

/// Builds one ceremony's hooks from the password received in `finalize`.
/// The hooks own the only copy, which zeroizes when finalize returns.
pub type RemoteOwnerHooksFactory =
    dyn Fn(Zeroizing<String>) -> Result<LocalOwnerHooks, CommitError> + Send + Sync;

/// Remote first run (P2): no startup password exists. `create-pending`
/// accepts a `password_commitment` and `finalize` the password itself, both
/// **only** from a peer registered by the box-static Noise tunnel. The same
/// requests on the loopback listener are refused. Device enrollment is
/// mandatory: a box restarted into locked mode is unlocked by that device.
pub struct RemoteOwner {
    /// Hook factory supplied by the node crate.
    pub hooks: Box<RemoteOwnerHooksFactory>,
    /// Server-owned tunnel registrations, never HTTP headers.
    pub tunnel: Arc<RemoteTunnelClients>,
}

// No Debug/Clone: the only retained phrase buffer zeroizes on drop, including
// cancellation, expiry, failed backup, shutdown and commit errors.
#[derive(zeroize::ZeroizeOnDrop)]
struct PendingIdentity {
    ceremony_id: String,
    mnemonic: Zeroizing<String>,
    node_id: String,
    fingerprint: String,
    client_id: String,
    #[zeroize(skip)]
    created_at: tokio::time::Instant,
    backup_check: [usize; 3],
    failed_backup_attempts: u8,
    /// `blake3(password)` from a remote create-pending; `None` locally.
    password_commitment: Option<[u8; 32]>,
    #[zeroize(skip)]
    sas: Option<PendingSas>,
}

struct PendingSas {
    box_approved: bool,
    device_key: [u8; 65],
    device_name: String,
    binding: crate::sas::NoiseBinding,
    digest: blake3::Hash,
}

impl PendingIdentity {
    fn expired(&self) -> bool {
        self.created_at.elapsed()
            >= std::time::Duration::from_secs(if self.sas.is_some() { 15 * 60 } else { 30 * 60 })
    }
}

/// One-time phrase response; never logged or retained as a response cache.
#[derive(Serialize)]
pub struct CreatePendingResponse {
    /// Random ceremony handle.
    pub ceremony_id: String,
    /// Pending node identity.
    pub node_id: String,
    /// Shown exactly once.
    pub mnemonic: Zeroizing<String>,
    /// Unix expiry, for the UI. Enforcement uses a monotonic clock.
    pub expires_at: i64,
    /// Three distinct zero-based word positions.
    pub backup_check: [usize; 3],
    /// Opt-in SAS protocol version (absent for legacy clients).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sas_version: Option<u8>,
    /// Fresh 16-byte nonce, lowercase hex. No SAS/claim commitment is returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub box_nonce: Option<String>,
}

/// Device proof of possession; it is not owner approval.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceEnrollment {
    /// Uncompressed SEC1 P-256 point, hex.
    pub public_key: String,
    /// Visible device label.
    pub name: String,
    /// DER signature over registration_message, hex.
    pub proof: String,
}

/// Remote create-pending: commits to the password finalize must carry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteCreatePendingBody {
    /// Lowercase hex `blake3(password)`.
    pub password_commitment: String,
    /// Explicit SAS protocol opt-in.
    pub sas_version: Option<u8>,
    /// Key and label committed before the box generates its nonce.
    pub device: Option<CommittedDevice>,
}

/// Device commitment carried by SAS create-pending, before proof at finalize.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedDevice {
    /// Uncompressed P-256 SEC1 key, hex.
    pub public_key: String,
    /// Device label, bound for this ceremony.
    pub name: String,
}

/// No password is accepted on the loopback path; see [`RemoteOwner`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeBody {
    /// Handle from create-pending.
    pub ceremony_id: String,
    /// Words at the requested positions, in order.
    pub backup_words: [Zeroizing<String>; 3],
    /// Required only in enrollment mode.
    pub device: Option<DeviceEnrollment>,
    /// Must be 1 for an SAS ceremony; omission cannot downgrade it.
    pub sas_version: Option<u8>,
    /// Full 32-byte SAS digest as lowercase hex.
    pub sas_digest: Option<String>,
}

/// Terminal local first-run result. Contains no phrase.
#[derive(Serialize)]
pub struct FinalizeResponse {
    /// Committed node id.
    pub node_id: String,
    /// Paired client that completed the ceremony.
    pub client_id: String,
    /// Pairing epoch preserved by the commit.
    pub epoch: u64,
    /// The supervisor must restart explicitly.
    pub restart_required: bool,
    /// Enrolled device key id, if requested.
    pub device_key_id: Option<String>,
    /// Display fingerprint of the device key.
    pub device_fingerprint: Option<String>,
    /// Committed encrypted seed path.
    pub mnemonic_path: String,
    /// Box transport public key (hex) and the committed identity's proof
    /// over it, so a client can pin the box under `node_id` before restart.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub box_transport_pubkey: Option<String>,
    /// Base64url-no-pad Ed25519 signature over `box_transport_proof_message`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub box_transport_signature: Option<String>,
    /// Seed-derived X25519 public key (hex) for the unlocked listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_pubkey: Option<String>,
    /// Base64url-no-pad Ed25519 signature over `transport_proof_message`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_signature: Option<String>,
}

/// Errors from the transition.
#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    /// Another transition is in flight, or one already completed.
    #[error("a first-run transition is already in progress or has completed")]
    Conflict,
    /// The supplied recovery phrase is not a valid mnemonic.
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    /// A simulated crash point was reached (tests only).
    #[error("transition aborted at the {0:?} fault point")]
    Aborted(CommitFault),
    /// Filesystem failure.
    #[error("transition failed: {0}")]
    Io(String),
    /// Pairing records could not be rebound to the new identity.
    #[error("rebinding pairings to the committed identity failed: {0}")]
    Pairing(String),
}

impl From<io::Error> for CommitError {
    fn from(e: io::Error) -> Self {
        CommitError::Io(e.to_string())
    }
}

/// Commit a first-run identity: one atomic commit, marker last.
///
/// 1. Materialize identity material into `<data_dir>/.init-<uuid>/`, fsyncing
///    each file.
/// 2. `rename()` that directory into place — the atomic step.
/// 3. Rebind pairing records to the new identity fingerprint.
/// 4. Write `NODE_INITIALIZED` with fsync, then fsync the parent directory.
///
/// The marker is written **last** and is the sole authority signal. A crash
/// before the rename leaves only a staging directory, which startup ignores and
/// reports; bootstrap is still legitimately open because no identity or state
/// exists. A crash after the rename but before the marker is a **refusal** on
/// the next start, naming the repair command — it never auto-reopens bootstrap.
pub fn commit_first_run(
    layout: &DataDirLayout,
    mnemonic: &str,
    pairing: Option<&PairingService>,
) -> Result<CommitOutcome, CommitError> {
    commit_first_run_with_fault(layout, mnemonic, pairing, CommitFault::None)
}

/// [`commit_first_run`] with an injectable crash point. See [`CommitFault`].
pub fn commit_first_run_with_fault(
    layout: &DataDirLayout,
    mnemonic: &str,
    pairing: Option<&PairingService>,
    fault: CommitFault,
) -> Result<CommitOutcome, CommitError> {
    commit_first_run_with_before_marker(layout, mnemonic, pairing, fault, None)
}

/// Like [`commit_first_run_with_fault`], but runs `before_marker` after rebind
/// and **before** publishing `NODE_INITIALIZED`. Used to durably align the
/// operator's config with the committed mnemonic path so a completed marker
/// never points at a missing identity file.
pub fn commit_first_run_with_before_marker(
    layout: &DataDirLayout,
    mnemonic: &str,
    pairing: Option<&PairingService>,
    fault: CommitFault,
    before_marker: Option<&BeforeMarkerHook<'_>>,
) -> Result<CommitOutcome, CommitError> {
    commit_first_run_local(layout, mnemonic, pairing, fault, before_marker, None, None)
}

fn commit_first_run_local(
    layout: &DataDirLayout,
    mnemonic: &str,
    pairing: Option<&PairingService>,
    fault: CommitFault,
    before_marker: Option<&BeforeMarkerHook<'_>>,
    local: Option<&LocalOwnerHooks>,
    device: Option<pairing::device::DeviceKey>,
) -> Result<CommitOutcome, CommitError> {
    // A failed post-rename attempt never reopens bootstrap in this process.
    if classify(&DataDirProbe::inspect(layout)?) != StartupMode::Bootstrap {
        return Err(CommitError::Conflict);
    }
    let identity = konsensus_core::NodeIdentity::from_mnemonic(mnemonic, "")
        .map_err(|e| CommitError::InvalidMnemonic(e.to_string()))?;
    let node_id = identity.node_id().to_hex();
    let fingerprint = pairing::identity_fingerprint(&node_id);

    std::fs::create_dir_all(&layout.data_dir)?;

    // 1. Staging.
    let staging = layout
        .data_dir
        .join(format!("{STAGING_PREFIX}{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&staging)?;
    pairing::restrict_dir(&staging)?;
    let mnemonic_name = if let Some(hooks) = local {
        let path = (hooks.encrypt_seed)(mnemonic, &staging)?;
        if path != staging.join("mnemonic.enc") || staging.join("mnemonic.txt").exists() {
            return Err(CommitError::Io("invalid encrypted seed output".into()));
        }
        "mnemonic.enc"
    } else {
        pairing::write_protected(&staging.join("mnemonic.txt"), mnemonic.as_bytes())?;
        "mnemonic.txt"
    };
    // The same signed public document a live start writes, so a box restarted
    // straight into locked mode can verify its box key against this identity.
    let mut metadata = pairing
        .map(|service| {
            crate::remote_access::public_identity_proofs(&identity, &service.box_transport_pubkey())
        })
        .unwrap_or_default();
    let box_transport = metadata
        .get("box_transport_pubkey")
        .and_then(|v| v.as_str())
        .zip(
            metadata
                .get("box_transport_signature")
                .and_then(|v| v.as_str()),
        )
        .map(|(key, signature)| (key.to_owned(), signature.to_owned()));
    let transport_pubkey = metadata
        .get("transport_pubkey")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let transport_signature = metadata
        .get("transport_signature")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    metadata.insert("identity_fingerprint".into(), fingerprint.clone().into());
    metadata.insert("committed_at".into(), chrono::Utc::now().timestamp().into());
    pairing::write_protected(
        &staging.join("identity.json"),
        serde_json::Value::Object(metadata).to_string().as_bytes(),
    )?;
    pairing::fsync_dir(&staging)?;

    if fault == CommitFault::AbortBeforeRename {
        return Err(CommitError::Aborted(fault));
    }

    // 2. The atomic step. `rename` onto an existing directory would fail, which
    //    is the behaviour we want: a second transition cannot overwrite the
    //    first one's identity.
    let target = layout.identity_dir();
    if target.exists() {
        return Err(CommitError::Conflict);
    }
    std::fs::rename(&staging, &target)?;
    pairing::fsync_dir(&layout.data_dir)?;

    if fault == CommitFault::AbortAfterRename {
        return Err(CommitError::Aborted(fault));
    }

    // 3. Pairings survive, rebound. A pairing made during bootstrap is stamped
    //    with the committed identity's fingerprint and loses its first-run
    //    `identity` scope as part of this same commit.
    if let Some(service) = pairing {
        service
            .rebind_to_identity(&fingerprint)
            .map_err(|e| CommitError::Pairing(e.to_string()))?;
    }

    if let Some(record) = device {
        pairing
            .ok_or_else(|| CommitError::Pairing("pairing unavailable".into()))?
            .install_first_run_device_key(record)
            .map_err(|e| CommitError::Pairing(e.to_string()))?;
    }

    let outcome = CommitOutcome {
        node_id,
        identity_fingerprint: fingerprint.clone(),
        mnemonic_path: target.join(mnemonic_name),
        box_transport,
        transport_pubkey,
        transport_signature,
    };

    // Align any operator config with the committed mnemonic *before* the
    // marker. A completed marker with an unusable config is not recoverable by
    // `prepare_start` without a separate repair of the config itself.
    if let Some(hook) = before_marker {
        hook(&outcome)?;
    }

    // 4. Marker last.
    pairing::write_protected(
        &layout.marker(),
        serde_json::json!({
            "identity_fingerprint": fingerprint,
            "initialized_at": chrono::Utc::now().timestamp(),
        })
        .to_string()
        .as_bytes(),
    )?;
    pairing::fsync_dir(&layout.data_dir)?;

    Ok(outcome)
}

/// State for the bootstrap HTTP surface.
///
/// Note what is **not** here: no storage, no lightning, no chain, no transport,
/// no identity. A node in bootstrap genuinely cannot pay, message or peer, and
/// the router reflects that rather than mounting routes that return 403.
pub struct BootstrapState {
    /// Data directory layout.
    pub layout: DataDirLayout,
    /// Pairing service, bound to the empty fingerprint until the commit.
    pub pairing: Arc<PairingService>,
    /// **Ephemeral** signing secret, generated at start and held only in
    /// memory. This value does not rotate in this process. Commit rebinds the
    /// pairing fingerprint and strips identity authority, invalidating the
    /// bootstrap binding. A separately started live node uses its own
    /// identity-derived secret and also rejects the `bst` claim explicitly.
    pub jwt_secret: String,
    /// Single-flight guard: one transition attempt per process.
    transition: Mutex<()>,
    /// Set once a transition has committed. A second attempt gets 409.
    committed: AtomicBool,
    /// Outcome of the committed transition, for the supervising process.
    outcome: Mutex<Option<CommitOutcome>>,
    /// Startup instant, for `/livez`.
    pub started_at: Instant,
    /// Optional durable work that must complete before the marker is published
    /// (e.g. aligning the operator's config file with the committed mnemonic).
    before_marker: Option<BeforeMarkerHookOwned>,
    local: Option<LocalOwnerHooks>,
    remote: Option<RemoteOwner>,
    pending: Mutex<Option<PendingIdentity>>,
    sas_failures: std::sync::atomic::AtomicU8,
    sas_started_at: tokio::time::Instant,
}

impl BootstrapState {
    /// Build bootstrap state for `layout`, generating the ephemeral secret.
    pub fn new(layout: DataDirLayout, pairing: Arc<PairingService>) -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self {
            layout,
            pairing,
            jwt_secret: hex::encode(secret),
            transition: Mutex::new(()),
            committed: AtomicBool::new(false),
            outcome: Mutex::new(None),
            started_at: Instant::now(),
            before_marker: None,
            local: None,
            remote: None,
            pending: Mutex::new(None),
            sas_failures: std::sync::atomic::AtomicU8::new(0),
            sas_started_at: tokio::time::Instant::now(),
        }
    }

    /// Remaining home setup window; also used by the shared CLI/page ticket authority.
    pub fn setup_remaining(&self) -> Option<std::time::Duration> {
        if self.is_committed() || self.sas_failures.load(Ordering::SeqCst) >= 3 {
            return None;
        }
        std::time::Duration::from_secs(900)
            .checked_sub(self.sas_started_at.elapsed())
            .filter(|d| !d.is_zero())
    }

    /// Run `hook` after identity rebind and before writing `NODE_INITIALIZED`.
    pub fn with_before_marker<F>(mut self, hook: F) -> Self
    where
        F: Fn(&CommitOutcome) -> Result<(), CommitError> + Send + Sync + 'static,
    {
        self.before_marker = Some(Arc::new(hook));
        self
    }

    /// Enable encrypted two-phase bootstrap with node-supplied hooks.
    pub fn with_local_owner(mut self, hooks: LocalOwnerHooks) -> Self {
        self.local = Some(hooks);
        self.remote = None;
        self
    }

    /// Enable the tunnel-only remote first run. Replaces any startup hooks:
    /// a remote ceremony never uses a password the process started with.
    pub fn with_remote_owner(mut self, remote: RemoteOwner) -> Self {
        self.remote = Some(remote);
        self.local = None;
        self
    }

    /// Is `peer` the server-registered tunnel of `client_id`? Loopback and
    /// unregistered connections to the internal listener never are.
    fn tunnel_peer_is(
        &self,
        peer: Option<ConnectInfo<SocketAddr>>,
        client_id: &str,
    ) -> Result<(), BootstrapError> {
        let tunnel = self
            .remote
            .as_ref()
            .zip(peer)
            .and_then(|(remote, peer)| remote.tunnel.client_id(peer.0));
        if tunnel.as_deref() != Some(client_id) {
            return Err(ceremony_error(StatusCode::BAD_REQUEST, "tunnel_required"));
        }
        Ok(())
    }

    fn ensure_open(&self) -> Result<(), CommitError> {
        if self.is_committed()
            || classify(&DataDirProbe::inspect(&self.layout)?) != StartupMode::Bootstrap
        {
            return Err(CommitError::Conflict);
        }
        Ok(())
    }

    fn commit_locked(
        &self,
        mnemonic: &str,
        fault: CommitFault,
        device: Option<pairing::device::DeviceKey>,
        hooks: Option<&LocalOwnerHooks>,
    ) -> Result<CommitOutcome, CommitError> {
        let outcome = commit_first_run_local(
            &self.layout,
            mnemonic,
            Some(&self.pairing),
            fault,
            self.before_marker
                .as_ref()
                .map(|h| h.as_ref() as &BeforeMarkerHook<'_>),
            hooks,
            device,
        )?;
        *self.outcome.lock().unwrap() = Some(outcome.clone());
        self.committed.store(true, Ordering::SeqCst);
        Ok(outcome)
    }

    /// Finish a pending ceremony under the same single-flight lock as legacy
    /// commits. Faults are explicit test inputs, never HTTP parameters.
    pub fn finalize(
        &self,
        client_id: &str,
        body: FinalizeBody,
        fault: CommitFault,
    ) -> Result<FinalizeResponse, (StatusCode, String)> {
        self.finalize_with(client_id, body, None, None, fault)
    }

    /// Remote first-run finalize. The caller has already verified that the
    /// request arrived through `client_id`'s tunnel; the password must match
    /// the create-pending commitment and is dropped when this returns.
    pub fn finalize_remote(
        &self,
        client_id: &str,
        body: FinalizeBody,
        password: Zeroizing<String>,
        noise: Option<crate::sas::NoiseBinding>,
        fault: CommitFault,
    ) -> Result<FinalizeResponse, (StatusCode, String)> {
        self.finalize_with(client_id, body, Some(password), noise, fault)
    }

    fn finalize_with(
        &self,
        client_id: &str,
        body: FinalizeBody,
        password: Option<Zeroizing<String>>,
        noise: Option<crate::sas::NoiseBinding>,
        fault: CommitFault,
    ) -> Result<FinalizeResponse, (StatusCode, String)> {
        let _guard = self
            .transition
            .try_lock()
            .map_err(|_| ceremony_error(StatusCode::CONFLICT, "ceremony_in_progress"))?;
        self.ensure_open().map_err(commit_error_response)?;
        let remote = match (&self.remote, &password, &self.local) {
            (Some(_), Some(_), _) => true,
            (None, None, Some(_)) => false,
            _ => return Err(ceremony_error(StatusCode::CONFLICT, "password_unavailable")),
        };
        let mut slot = self.pending.lock().unwrap();
        let pending = slot
            .as_mut()
            .ok_or_else(|| ceremony_error(StatusCode::GONE, "ceremony_lost"))?;
        if pending.client_id != client_id {
            return Err(ceremony_error(
                StatusCode::FORBIDDEN,
                "ceremony_client_mismatch",
            ));
        }
        if pending.expired() {
            *slot = None;
            return Err(ceremony_error(StatusCode::GONE, "ceremony_expired"));
        }
        if pending.ceremony_id != body.ceremony_id {
            return Err(ceremony_error(StatusCode::GONE, "ceremony_lost"));
        }
        if self.sas_failures.load(Ordering::SeqCst) >= 3 {
            return Err(ceremony_error(StatusCode::FORBIDDEN, "setup_closed"));
        }
        if remote && pending.sas.is_none() && crate::sas::required(&self.layout.data_dir) {
            return Err(ceremony_error(StatusCode::FORBIDDEN, "sas_required"));
        }
        if let Some(sas) = &pending.sas {
            if noise != Some(sas.binding) {
                return Err(ceremony_error(
                    StatusCode::FORBIDDEN,
                    "ceremony_noise_mismatch",
                ));
            }
            if self.sas_started_at.elapsed() >= std::time::Duration::from_secs(900) {
                *slot = None;
                return Err(ceremony_error(StatusCode::GONE, "setup_expired"));
            }
            let digest = body
                .sas_digest
                .as_deref()
                .and_then(|s| blake3::Hash::from_hex(s).ok());
            let digest_matches = digest
                .is_some_and(|digest| bool::from(digest.as_bytes().ct_eq(sas.digest.as_bytes())));
            let device_matches = body.device.as_ref().is_some_and(|d| {
                crate::sas::device_key(&d.public_key).ok() == Some(sas.device_key)
                    && d.name == sas.device_name
            });
            if body.sas_version != Some(1) || !digest_matches || !device_matches {
                self.sas_failures.fetch_add(1, Ordering::SeqCst);
                *slot = None;
                return Err(ceremony_error(StatusCode::BAD_REQUEST, "sas_mismatch"));
            }
            if !sas.box_approved {
                return Err(ceremony_error(StatusCode::CONFLICT, "box_approval_pending"));
            }
        } else if body.sas_version.is_some() || body.sas_digest.is_some() {
            return Err(ceremony_error(StatusCode::BAD_REQUEST, "unexpected_sas"));
        }
        let remote_hooks = match (password, &self.remote) {
            (Some(password), Some(owner)) => {
                let commitment = pending.password_commitment.ok_or_else(|| {
                    ceremony_error(StatusCode::BAD_REQUEST, "password_commitment_missing")
                })?;
                if password.is_empty() {
                    return Err(ceremony_error(StatusCode::BAD_REQUEST, "password_required"));
                }
                // blake3::Hash equality is constant-time.
                if blake3::hash(password.as_bytes()) != blake3::Hash::from(commitment) {
                    pending.failed_backup_attempts += 1;
                    if pending.failed_backup_attempts >= 3 {
                        if pending.sas.is_some() {
                            self.sas_failures.fetch_add(1, Ordering::SeqCst);
                        }
                        *slot = None;
                        return Err(ceremony_error(StatusCode::GONE, "ceremony_lost"));
                    }
                    return Err(ceremony_error(
                        StatusCode::BAD_REQUEST,
                        "password_commitment_mismatch",
                    ));
                }
                Some((owner.hooks)(password).map_err(commit_error_response)?)
            }
            _ => None,
        };
        let hooks = match remote_hooks.as_ref().or(self.local.as_ref()) {
            Some(hooks) => hooks,
            None => return Err(ceremony_error(StatusCode::CONFLICT, "password_unavailable")),
        };
        if (hooks.enroll_device || remote) != body.device.is_some() {
            return Err(ceremony_error(
                StatusCode::BAD_REQUEST,
                "device_requirement_mismatch",
            ));
        }
        let words: Vec<_> = pending.mnemonic.split_whitespace().collect();
        if !pending
            .backup_check
            .iter()
            .zip(&body.backup_words)
            .all(|(i, word)| words[*i] == word.as_str())
        {
            pending.failed_backup_attempts += 1;
            if pending.failed_backup_attempts >= 3 {
                if pending.sas.is_some() {
                    self.sas_failures.fetch_add(1, Ordering::SeqCst);
                }
                *slot = None;
                return Err(ceremony_error(StatusCode::GONE, "ceremony_lost"));
            }
            return Err(ceremony_error(
                StatusCode::BAD_REQUEST,
                "backup_check_failed",
            ));
        }
        let device = if let Some(device) = body.device {
            let mut record = self
                .pairing
                .prepare_first_run_device_key(
                    client_id,
                    &pending.fingerprint,
                    &device.public_key,
                    &device.name,
                    &device.proof,
                    pending.sas.as_ref().map(|s| &s.digest),
                )
                .map_err(|e| {
                    if matches!(e, PairingError::BadProof) {
                        ceremony_error(StatusCode::FORBIDDEN, "bad_device_proof")
                    } else {
                        pairing_error_response(e)
                    }
                })?;
            if remote {
                record.enrolled_by = "remote_first_run".into();
            }
            let message = pairing::device::owner_approval_message(
                &pending.fingerprint,
                &record.client_pubkey,
                record.epoch,
                &record.public_key,
            );
            record.owner_approval =
                (hooks.sign_owner_approval)(&pending.mnemonic, &pending.node_id, &message)
                    .map_err(commit_error_response)?;
            Some(record)
        } else {
            None
        };
        let device_key_id = device.as_ref().map(|d| d.key_id.clone());
        // Use the device's binding when enrolled; installation rechecks its epoch
        // under the pairing lock. Local ceremonies may omit device enrollment.
        let epoch = match &device {
            Some(record) => record.epoch,
            None => {
                self.pairing
                    .list_clients()
                    .into_iter()
                    .find(|client| client.client_id == client_id)
                    .ok_or_else(|| pairing_error_response(PairingError::OwnerChannelUnavailable))?
                    .epoch
            }
        };
        // From here even a failed commit consumes the phrase. A post-rename
        // failure additionally requires explicit repair, never a retry.
        let pending = slot.take().unwrap();
        drop(slot);
        let outcome = self
            .commit_locked(&pending.mnemonic, fault, device, Some(hooks))
            .map_err(commit_error_response)?;
        let (box_transport_pubkey, box_transport_signature) = outcome.box_transport.unzip();
        Ok(FinalizeResponse {
            node_id: outcome.node_id,
            client_id: client_id.to_owned(),
            epoch,
            transport_pubkey: outcome.transport_pubkey,
            transport_signature: outcome.transport_signature,
            restart_required: true,
            device_fingerprint: device_key_id
                .as_deref()
                .map(pairing::device::key_fingerprint),
            device_key_id,
            mnemonic_path: outcome.mnemonic_path.display().to_string(),
            box_transport_pubkey,
            box_transport_signature,
        })
    }

    /// Has the transition committed?
    pub fn is_committed(&self) -> bool {
        self.committed.load(Ordering::SeqCst)
    }

    /// The committed identity, if the transition ran.
    pub fn outcome(&self) -> Option<CommitOutcome> {
        self.outcome.lock().ok().and_then(|o| o.clone())
    }

    /// Run a first-run transition under the single-flight guard.
    ///
    /// A concurrent second attempt gets [`CommitError::Conflict`] and writes
    /// nothing — there is no partial state from the loser.
    pub fn transition(
        &self,
        mnemonic: &str,
        fault: CommitFault,
    ) -> Result<CommitOutcome, CommitError> {
        let _guard = self
            .transition
            .try_lock()
            .map_err(|_| CommitError::Conflict)?;
        // Without a startup password a legacy commit would write a plaintext
        // seed that `--remote-unlock` then refuses to start.
        if self.remote.is_some() {
            return Err(CommitError::Conflict);
        }
        self.ensure_open()?;
        let mut pending = self.pending.lock().unwrap();
        if pending.as_ref().is_some_and(PendingIdentity::expired) {
            *pending = None;
        }
        if pending.is_some() {
            return Err(CommitError::Conflict);
        }
        self.commit_locked(mnemonic, fault, None, self.local.as_ref())
    }
}

/// An authenticated bootstrap caller: a first-run pairing holding `identity`.
///
/// First-run create/restore is **protected**, not open. The bootstrap router is
/// a smaller surface, not an unauthenticated one.
pub struct BootstrapAuth {
    /// The paired client that authenticated.
    pub client_id: String,
}

#[axum::async_trait]
impl FromRequestParts<Arc<BootstrapState>> for BootstrapAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<BootstrapState>,
    ) -> Result<Self, Self::Rejection> {
        let unauthorized = || (StatusCode::UNAUTHORIZED, "invalid token").into_response();

        let token = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(unauthorized)?;

        let claims = auth::validate_token(token, &state.jwt_secret).map_err(|_| unauthorized())?;
        // Only a token minted by THIS bootstrap process is acceptable here.
        if claims.bst != Some(true) {
            return Err(unauthorized());
        }
        if !claims.has(Scope::Identity) {
            return Err((
                StatusCode::FORBIDDEN,
                "token lacks required scope: identity",
            )
                .into_response());
        }
        let client_id = claims.cid.clone().ok_or_else(unauthorized)?;
        let epoch = claims.epc.ok_or_else(unauthorized)?;
        if (state.is_committed() || state.transition.try_lock().is_err())
            && (parts.uri.path() == "/api/v1/identity/finalize"
                || parts.uri.path().starts_with("/api/v1/identity/pending/"))
        {
            return Err((StatusCode::CONFLICT, "already initialized").into_response());
        }
        state
            .pairing
            .verify_token_binding(&client_id, epoch, "", &claims.scp)
            .map_err(|_| unauthorized())?;

        Ok(BootstrapAuth { client_id })
    }
}

/// Unauthenticated `GET /api/v1/bootstrap/state` response.
/// Refusal diagnostics and repair guidance belong in the CLI/stderr output.
#[derive(Debug, Serialize)]
pub struct BootstrapStateResponse {
    /// `"bootstrap"`, `"initialized"`, or `"refused"` (operator repair required).
    pub state: &'static str,
    /// Whether a first-run restore is available.
    pub can_restore: bool,
    /// Whether a first-run create is available.
    pub can_create: bool,
    /// Explicit local ceremony availability, with no secret material.
    pub local_owner: LocalOwnerState,
}

/// Public local ceremony status.
#[derive(Debug, Serialize)]
pub struct LocalOwnerState {
    /// An encryption password was supplied at startup.
    pub available: bool,
    /// First owner enrollment is required.
    pub enroll_device: bool,
    /// A phrase is held in memory awaiting backup proof.
    pub pending: bool,
    /// Remote first run: the password arrives in finalize, tunnel only.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub tunnel_password: bool,
}

async fn bootstrap_state(
    State(state): State<Arc<BootstrapState>>,
) -> Result<Json<BootstrapStateResponse>, BootstrapError> {
    // Match ensure_open: an unsuccessful post-rename commit is not committed,
    // but its on-disk identity still closes bootstrap and requires repair.
    let mode = if state.is_committed() {
        StartupMode::Initialized
    } else {
        classify(
            &DataDirProbe::inspect(&state.layout).map_err(|e| commit_error_response(e.into()))?,
        )
    };
    let open = mode == StartupMode::Bootstrap;
    let status = match mode {
        StartupMode::Bootstrap => "bootstrap",
        StartupMode::Initialized => "initialized",
        StartupMode::Refuse(_) => "refused",
    };
    let mut pending = state.pending.lock().unwrap();
    if pending.as_ref().is_some_and(PendingIdentity::expired) {
        *pending = None;
    }
    let remote = state.remote.is_some();
    Ok(Json(BootstrapStateResponse {
        state: status,
        // Remote first run has no restore route: only the ceremony creates.
        can_restore: open && !remote,
        can_create: open,
        local_owner: LocalOwnerState {
            available: state.local.is_some() || remote,
            enroll_device: remote || state.local.as_ref().is_some_and(|l| l.enroll_device),
            pending: pending.is_some(),
            tunnel_password: remote,
        },
    }))
}

async fn livez() -> &'static str {
    "ok"
}

/// Pair request body, shared with the live router's shape.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairRequestBody {
    /// Human-readable client name, shown to the owner.
    pub client_name: String,
    /// Ed25519 client public key (hex).
    pub client_pubkey: String,
}

/// Pair request response. Carries **no** secret and no short code.
#[derive(Debug, Serialize)]
pub struct PairRequestResponse {
    /// Ceremony id.
    pub pair_id: String,
    /// Unix seconds after which the request can no longer be confirmed.
    pub expires_at: i64,
    /// Where the client must read the challenge from.
    pub challenge_path: String,
}

/// Pair confirm body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairConfirmBody {
    /// Ceremony id from `/pair/request`.
    pub pair_id: String,
    /// Hex Ed25519 signature over `pair_id || client_pubkey || challenge`.
    pub signature: String,
}

/// Pair confirm response.
#[derive(Debug, Serialize)]
pub struct PairConfirmResponse {
    /// The paired client id.
    pub client_id: String,
    /// Scopes the pairing carries.
    pub scopes: Vec<Scope>,
}

/// Token issuance body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairTokenBody {
    /// Paired client id.
    pub client_id: String,
    /// Challenge from `/pair/challenge`.
    pub challenge: String,
    /// Hex Ed25519 signature over the challenge.
    pub signature: String,
}

/// Token issuance response.
#[derive(Debug, Serialize)]
pub struct PairTokenResponse {
    /// The JWT.
    pub token: String,
    /// Unix seconds of expiry.
    pub expires_at: i64,
    /// Scopes carried.
    pub scopes: Vec<Scope>,
}

type BootstrapError = (StatusCode, String);

fn pairing_error_response(e: PairingError) -> BootstrapError {
    let status = match e {
        PairingError::Closed => StatusCode::CONFLICT,
        PairingError::TooManyPending => StatusCode::TOO_MANY_REQUESTS,
        PairingError::UnknownPending | PairingError::BadProof => StatusCode::UNAUTHORIZED,
        PairingError::Malformed(_) => StatusCode::BAD_REQUEST,
        PairingError::UnknownClient | PairingError::UnknownOperation => StatusCode::NOT_FOUND,
        PairingError::OwnerChannelUnavailable => StatusCode::FORBIDDEN,
        PairingError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::FORBIDDEN,
    };
    (status, e.to_string())
}

async fn pair_request(
    State(state): State<Arc<BootstrapState>>,
    Json(body): Json<PairRequestBody>,
) -> Result<Json<PairRequestResponse>, BootstrapError> {
    let outcome = state
        .pairing
        .request_pairing(&body.client_name, &body.client_pubkey)
        .map_err(pairing_error_response)?;
    Ok(Json(PairRequestResponse {
        challenge_path: state
            .pairing
            .dir()
            .join(format!("challenge-{}", outcome.pair_id))
            .display()
            .to_string(),
        pair_id: outcome.pair_id,
        expires_at: outcome.expires_at,
    }))
}

async fn pair_confirm(
    State(state): State<Arc<BootstrapState>>,
    Json(body): Json<PairConfirmBody>,
) -> Result<Json<PairConfirmResponse>, BootstrapError> {
    // First-run pairings carry `identity` — and only while no identity exists.
    // `rebind_to_identity` strips it as part of the transition commit.
    let record = state
        .pairing
        .confirm_pairing(
            &body.pair_id,
            &body.signature,
            pairing::bootstrap_pairing_scopes(),
        )
        .map_err(pairing_error_response)?;
    Ok(Json(PairConfirmResponse {
        client_id: record.client_id,
        scopes: record.scopes,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeQuery {
    client_id: String,
}

async fn pair_challenge(
    State(state): State<Arc<BootstrapState>>,
    axum::extract::Query(q): axum::extract::Query<ChallengeQuery>,
) -> Result<Json<serde_json::Value>, BootstrapError> {
    let challenge = state
        .pairing
        .issue_token_challenge(&q.client_id)
        .map_err(pairing_error_response)?;
    Ok(Json(serde_json::json!({ "challenge": challenge })))
}

async fn pair_token(
    State(state): State<Arc<BootstrapState>>,
    Json(body): Json<PairTokenBody>,
) -> Result<Json<PairTokenResponse>, BootstrapError> {
    // Bootstrap tokens are minted against the ephemeral secret and marked
    // `bst`, so they cannot be replayed against the live node after commit.
    let issued = state
        .pairing
        .issue_bootstrap_token(
            &state.jwt_secret,
            &body.client_id,
            &body.challenge,
            &body.signature,
        )
        .map_err(pairing_error_response)?;
    Ok(Json(PairTokenResponse {
        token: issued.token,
        expires_at: issued.expires_at,
        scopes: issued.scopes,
    }))
}

/// First-run restore/create body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstRunRestoreBody {
    /// BIP-39 recovery phrase (12 or 24 words).
    pub mnemonic: Zeroizing<String>,
}

/// Terminal response from a first-run create or restore.
#[derive(Serialize)]
pub struct FirstRunResponse {
    /// Node id of the committed identity.
    pub node_id: String,
    /// Always true: the operator starts the live node, the API never does.
    pub restart_required: bool,
    /// For a create, the phrase the user must write down. Absent on restore.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<Zeroizing<String>>,
}

fn commit_error_response(e: CommitError) -> BootstrapError {
    let status = match e {
        CommitError::Conflict => StatusCode::CONFLICT,
        CommitError::InvalidMnemonic(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, e.to_string())
}

async fn first_run_restore(
    _auth: BootstrapAuth,
    State(state): State<Arc<BootstrapState>>,
    Json(body): Json<FirstRunRestoreBody>,
) -> Result<Json<FirstRunResponse>, BootstrapError> {
    let words = body.mnemonic.split_whitespace().count();
    if words != 12 && words != 24 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("mnemonic must be 12 or 24 words, got {words}"),
        ));
    }
    let outcome = state
        .transition(&body.mnemonic, CommitFault::None)
        .map_err(commit_error_response)?;
    Ok(Json(FirstRunResponse {
        node_id: outcome.node_id,
        restart_required: true,
        mnemonic: None,
    }))
}

async fn first_run_create(
    _auth: BootstrapAuth,
    State(state): State<Arc<BootstrapState>>,
) -> Result<Json<FirstRunResponse>, BootstrapError> {
    let (mnemonic, _identity) = konsensus_core::NodeIdentity::generate()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mnemonic = Zeroizing::new(mnemonic);
    let outcome = state
        .transition(&mnemonic, CommitFault::None)
        .map_err(commit_error_response)?;
    Ok(Json(FirstRunResponse {
        node_id: outcome.node_id,
        restart_required: true,
        // Returned exactly once, to the paired client that asked for it, over
        // loopback. The phrase is never logged and never sent anywhere else.
        mnemonic: Some(mnemonic),
    }))
}

fn ceremony_error(status: StatusCode, code: &str) -> BootstrapError {
    (status, code.into())
}

async fn create_pending(
    auth: BootstrapAuth,
    State(state): State<Arc<BootstrapState>>,
) -> Result<Json<CreatePendingResponse>, BootstrapError> {
    begin_pending(&state, auth.client_id, None, None).map(Json)
}

/// Remote first run: tunnel only, and the password is committed to up front.
async fn create_pending_remote(
    auth: BootstrapAuth,
    State(state): State<Arc<BootstrapState>>,
    peer: Option<ConnectInfo<SocketAddr>>,
    Json(body): Json<RemoteCreatePendingBody>,
) -> Result<Json<CreatePendingResponse>, BootstrapError> {
    state.tunnel_peer_is(peer, &auth.client_id)?;
    let commitment = (body.password_commitment.len() == 64
        && body.password_commitment == body.password_commitment.to_ascii_lowercase())
    .then(|| blake3::Hash::from_hex(&body.password_commitment).ok())
    .flatten()
    .ok_or_else(|| ceremony_error(StatusCode::BAD_REQUEST, "invalid_password_commitment"))?;
    let sas = match (body.sas_version, body.device) {
        (None, None) => None,
        (Some(1), Some(device)) => {
            let key = crate::sas::device_key(&device.public_key)
                .map_err(|code| ceremony_error(StatusCode::BAD_REQUEST, code))?;
            if device.name.trim().is_empty()
                || device.name.len() > 128
                || device.name.chars().any(char::is_control)
            {
                return Err(ceremony_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_device_name",
                ));
            }
            let binding = state
                .remote
                .as_ref()
                .and_then(|r| peer.and_then(|p| r.tunnel.noise(p.0)))
                .filter(|n| n.client_id.as_ref() == auth.client_id)
                .ok_or_else(|| {
                    ceremony_error(StatusCode::FORBIDDEN, "noise_transcript_required")
                })?;
            Some((key, device.name, binding.binding))
        }
        _ => {
            return Err(ceremony_error(
                StatusCode::BAD_REQUEST,
                "invalid_sas_version_or_device",
            ))
        }
    };
    begin_pending(&state, auth.client_id, Some(*commitment.as_bytes()), sas).map(Json)
}

fn begin_pending(
    state: &BootstrapState,
    client_id: String,
    password_commitment: Option<[u8; 32]>,
    sas_input: Option<([u8; 65], String, crate::sas::NoiseBinding)>,
) -> Result<CreatePendingResponse, BootstrapError> {
    use rand::seq::SliceRandom;
    let _guard = state
        .transition
        .try_lock()
        .map_err(|_| ceremony_error(StatusCode::CONFLICT, "ceremony_in_progress"))?;
    state.ensure_open().map_err(commit_error_response)?;
    let available = match password_commitment {
        Some(_) => state.remote.is_some(),
        None => state.local.is_some(),
    };
    if !available {
        return Err(ceremony_error(StatusCode::CONFLICT, "password_unavailable"));
    }
    // Cancellation may revoke an extracted token while this request waits for the lock.
    if password_commitment.is_some()
        && !state
            .pairing
            .list_clients()
            .iter()
            .any(|c| c.client_id == client_id)
    {
        return Err(ceremony_error(StatusCode::FORBIDDEN, "pairing_revoked"));
    }
    let mut slot = state.pending.lock().unwrap();
    if slot.as_ref().is_some_and(PendingIdentity::expired) {
        *slot = None;
    }
    if slot.is_some() {
        return Err(ceremony_error(StatusCode::CONFLICT, "ceremony_in_progress"));
    }
    if state.sas_failures.load(Ordering::SeqCst) >= 3 {
        return Err(ceremony_error(StatusCode::FORBIDDEN, "setup_closed"));
    }
    if password_commitment.is_some()
        && sas_input.is_none()
        && crate::sas::required(&state.layout.data_dir)
    {
        return Err(ceremony_error(StatusCode::FORBIDDEN, "sas_required"));
    }
    if sas_input.is_some()
        && state.sas_started_at.elapsed() >= std::time::Duration::from_secs(15 * 60)
    {
        return Err(ceremony_error(StatusCode::GONE, "setup_expired"));
    }
    // All inputs and the exclusive pending slot are committed before this RNG call.
    let (sas, box_nonce) = if let Some((device_key, device_name, binding)) = sas_input {
        use rand::RngCore;
        let claim = crate::sas::load(&state.layout.data_dir)
            .map_err(|_| ceremony_error(StatusCode::CONFLICT, "claim_code_unavailable"))?;
        let mut nonce = [0; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let digest = crate::sas::digest(&binding, &device_key, &nonce, &claim.commitment());
        (
            Some(PendingSas {
                box_approved: false,
                device_key,
                device_name,
                binding,
                digest,
            }),
            Some(hex::encode(nonce)),
        )
    } else {
        (None, None)
    };
    let (mnemonic, identity) = konsensus_core::NodeIdentity::generate().map_err(|_| {
        ceremony_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "identity_generation_failed",
        )
    })?;
    let mnemonic = Zeroizing::new(mnemonic);
    let node_id = identity.node_id().to_hex();
    let ceremony_id = uuid::Uuid::new_v4().simple().to_string();
    let mut indices: Vec<usize> = (0..mnemonic.split_whitespace().count()).collect();
    indices.shuffle(&mut rand::thread_rng());
    let backup_check = [indices[0], indices[1], indices[2]];
    *slot = Some(PendingIdentity {
        ceremony_id: ceremony_id.clone(),
        mnemonic: mnemonic.clone(),
        node_id: node_id.clone(),
        fingerprint: pairing::identity_fingerprint(&node_id),
        client_id,
        created_at: tokio::time::Instant::now(),
        backup_check,
        failed_backup_attempts: 0,
        password_commitment,
        sas,
    });
    Ok(CreatePendingResponse {
        ceremony_id,
        node_id,
        mnemonic,
        expires_at: chrono::Utc::now().timestamp()
            + if box_nonce.is_some() {
                900i64.saturating_sub(state.sas_started_at.elapsed().as_secs() as i64)
            } else {
                1800
            },
        backup_check,
        sas_version: box_nonce.as_ref().map(|_| 1),
        box_nonce,
    })
}

async fn finalize(
    auth: BootstrapAuth,
    State(state): State<Arc<BootstrapState>>,
    Json(body): Json<FinalizeBody>,
) -> Result<Json<FinalizeResponse>, BootstrapError> {
    state
        .finalize(&auth.client_id, body, CommitFault::None)
        .map(Json)
}

/// [`FinalizeBody`] plus the password, which is decoded straight into
/// zeroizing memory rather than through serde_json's string scratch.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteFinalizeBody<'a> {
    ceremony_id: String,
    backup_words: [Zeroizing<String>; 3],
    device: Option<DeviceEnrollment>,
    sas_version: Option<u8>,
    sas_digest: Option<String>,
    #[serde(borrow)]
    password: &'a serde_json::value::RawValue,
}

/// Remote first run: refused before the body is read unless the request
/// arrived through the caller's own tunnel. Never `Json<_>`: the aggregate
/// body buffer would not be wiped.
async fn finalize_remote(
    auth: BootstrapAuth,
    State(state): State<Arc<BootstrapState>>,
    peer: Option<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Result<Json<FinalizeResponse>, BootstrapError> {
    state.tunnel_peer_is(peer, &auth.client_id)?;
    let noise = state
        .remote
        .as_ref()
        .and_then(|r| peer.and_then(|p| r.tunnel.noise(p.0)))
        .map(|n| n.binding);
    let bad = || ceremony_error(StatusCode::BAD_REQUEST, "invalid_finalize_body");
    let raw = crate::locked::body::read(request).await.ok_or_else(bad)?;
    let wire: RemoteFinalizeBody<'_> = serde_json::from_slice(&raw).map_err(|_| bad())?;
    let password = crate::locked::body::decode_password(wire.password.get()).map_err(|_| bad())?;
    let body = FinalizeBody {
        ceremony_id: wire.ceremony_id,
        backup_words: wire.backup_words,
        device: wire.device,
        sas_version: wire.sas_version,
        sas_digest: wire.sas_digest,
    };
    state
        .finalize_remote(&auth.client_id, body, password, noise, CommitFault::None)
        .map(Json)
}

async fn cancel_pending(
    auth: BootstrapAuth,
    State(state): State<Arc<BootstrapState>>,
    axum::extract::Path(ceremony_id): axum::extract::Path<String>,
) -> Result<StatusCode, BootstrapError> {
    let _guard = state
        .transition
        .try_lock()
        .map_err(|_| ceremony_error(StatusCode::CONFLICT, "ceremony_in_progress"))?;
    state.ensure_open().map_err(commit_error_response)?;
    let mut slot = state.pending.lock().unwrap();
    if let Some(pending) = slot.as_ref() {
        if pending.client_id != auth.client_id {
            return Err(ceremony_error(
                StatusCode::FORBIDDEN,
                "ceremony_client_mismatch",
            ));
        }
        if pending.expired() {
            *slot = None;
            return Err(ceremony_error(StatusCode::GONE, "ceremony_expired"));
        }
        // A client that lost create-pending's response has no ceremony handle.
        // The authenticated, same-client alias recovers without re-showing it.
        if ceremony_id != "current" && ceremony_id != pending.ceremony_id {
            return Err(ceremony_error(StatusCode::GONE, "ceremony_lost"));
        }
    }
    if slot.as_ref().is_some_and(|p| p.sas.is_some()) {
        state.sas_failures.fetch_add(1, Ordering::SeqCst);
    }
    *slot = None;
    Ok(StatusCode::NO_CONTENT)
}

/// Build the bootstrap router — a **separate, small router**.
///
/// Permitted: the ceremony, `/livez`, `/api/v1/bootstrap/state`, and exactly
/// one of first-run create or restore (both terminal).
///
/// Everything else — payments, messaging and compose, channels, peers, gossip,
/// invites, export, content, calendar, mnemonic reveal, the WebSocket — is
/// **unrouted**, not mounted-and-denied. A node with no keys cannot pay, and
/// mounting those routes to return 403 would manufacture exactly the
/// "looks like a funded node" surface this design avoids. An unrouted path
/// answers 404 because the capability genuinely does not exist yet.
///
/// A remote first run mounts the tunnel-only ceremony and no legacy
/// create/restore: with no startup password those would write a plaintext seed.
pub fn build_bootstrap_router(state: Arc<BootstrapState>) -> Router {
    let mut router = Router::new();
    if state.remote.is_some() {
        router = router
            .route(
                "/api/v1/identity/create-pending",
                post(create_pending_remote),
            )
            .route("/api/v1/identity/finalize", post(finalize_remote))
            .route(
                "/api/v1/identity/pending/:ceremony_id",
                delete(cancel_pending),
            );
    } else {
        if state.local.is_some() {
            router = router
                .route("/api/v1/identity/create-pending", post(create_pending))
                .route("/api/v1/identity/finalize", post(finalize))
                .route(
                    "/api/v1/identity/pending/:ceremony_id",
                    delete(cancel_pending),
                );
        }
        router = router
            .route("/api/v1/identity/restore", post(first_run_restore))
            .route("/api/v1/identity/create", post(first_run_create));
    }
    router
        .route("/livez", get(livez))
        .route("/api/v1/bootstrap/state", get(bootstrap_state))
        .route("/api/v1/pair/request", post(pair_request))
        .route("/api/v1/pair/confirm", post(pair_confirm))
        .route("/api/v1/pair/challenge", get(pair_challenge))
        .route("/api/v1/pair/token", post(pair_token))
        .with_state(state)
}

/// Serve the bootstrap API until the transition commits or shutdown fires.
///
/// Returns the commit outcome, if one happened. The caller — not this function
/// — decides what to do next: the node is **never** auto-started into live
/// operation on the strength of an API call.
pub async fn serve_bootstrap(
    addr: std::net::SocketAddr,
    state: Arc<BootstrapState>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<Option<CommitOutcome>, Box<dyn std::error::Error + Send + Sync>> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    serve_bootstrap_listeners(vec![listener], state, shutdown_rx).await
}

/// [`serve_bootstrap`] on already-bound listeners, e.g. the loopback API and
/// the internal listener a Noise tunnel bridges to. Each connection carries
/// its peer address so tunnel registrations can be resolved.
pub async fn serve_bootstrap_listeners(
    listeners: Vec<tokio::net::TcpListener>,
    state: Arc<BootstrapState>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<Option<CommitOutcome>, Box<dyn std::error::Error + Send + Sync>> {
    let mut servers = tokio::task::JoinSet::new();
    for listener in listeners {
        let addr = listener.local_addr()?;
        tracing::info!(%addr, "node is in identity-free BOOTSTRAP mode — only the pairing ceremony and first-run create/restore are reachable");
        let app = build_bootstrap_router(Arc::clone(&state))
            .into_make_service_with_connect_info::<SocketAddr>();
        let stop = until_terminal(Arc::clone(&state), shutdown_rx.clone());
        servers.spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(stop)
                .await
        });
    }
    while let Some(joined) = servers.join_next().await {
        joined??;
    }
    Ok(state.outcome())
}

/// Resolves on shutdown, or 250 ms after the transition commits so the
/// terminal response can flush before listeners close.
pub async fn until_terminal(
    state: Arc<BootstrapState>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        if state.is_committed() {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            return;
        }
        tokio::select! {
            _ = shutdown_rx.changed() => return,
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
        }
    }
}

/// Separate LAN-only home setup surface; never merged into the API or tunnel router.
pub mod setup;
