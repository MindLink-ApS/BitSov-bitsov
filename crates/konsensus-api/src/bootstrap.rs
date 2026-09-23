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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::{self, Scope};
use crate::pairing::{self, PairingError, PairingService};

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
}

impl DataDirLayout {
    /// Layout for `data_dir`.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
        }
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
        vec![
            self.data_dir.join("mnemonic.txt"),
            self.data_dir.join("mnemonic.enc"),
            self.identity_dir().join("mnemonic.txt"),
            self.identity_dir().join("mnemonic.enc"),
        ]
    }

    /// Wallet, channel and store state. Any of these on a marker-less node
    /// means "deleted key", not "fresh install".
    pub fn state_candidates(&self) -> Vec<PathBuf> {
        vec![
            self.data_dir.join("konsensus.db"),
            self.data_dir.join("ldk"),
            self.data_dir.join("scb-latest.aes"),
            self.data_dir.join("whitelist-latest.aes"),
        ]
    }

    /// The storage database, whose readability is checked on an initialized node.
    pub fn store(&self) -> PathBuf {
        self.data_dir.join("konsensus.db")
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
        let marker_present = layout.marker().exists();
        let identity_material_present = layout.mnemonic_candidates().iter().any(|p| p.exists());
        let wallet_or_channel_state_present = layout.state_candidates().iter().any(|p| p.exists());

        let store = layout.store();
        let store_readable = if store.exists() {
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
        // An empty file is what `File::create` leaves behind before sqlx
        // initialises it; treat it as readable rather than corrupt.
        Err(_) => std::fs::metadata(path)
            .map(|m| m.len() == 0)
            .unwrap_or(false),
        Ok(()) => &header == b"SQLite format 3\0",
    }
}

/// Why a node refuses to start, and what the operator should actually run.
#[derive(Debug, Clone, PartialEq, Eq)]
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
                         initialization marker is absent — most likely a crash after the \
                         transition renamed identity into place but before the marker was \
                         written"
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
    "run `konsensus repair mark-initialized --dir <data-dir> --confirm` to finish the \
     interrupted transition (it writes the marker and nothing else), or move the data \
     directory aside to start over. The node will not write the marker for you, because \
     doing so silently would make a crashed transition indistinguishable from a completed one."
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
    pairing::write_protected(&staging.join("mnemonic.txt"), mnemonic.as_bytes())?;
    pairing::write_protected(
        &staging.join("identity.json"),
        serde_json::json!({
            "identity_fingerprint": fingerprint,
            "committed_at": chrono::Utc::now().timestamp(),
        })
        .to_string()
        .as_bytes(),
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

    Ok(CommitOutcome {
        node_id,
        identity_fingerprint: fingerprint,
        mnemonic_path: target.join("mnemonic.txt"),
    })
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
    /// memory. At transition the live node switches to the identity-derived
    /// secret, so every bootstrap-issued token stops verifying at the same
    /// instant. There is no window in which a bootstrap token outlives
    /// bootstrap.
    pub jwt_secret: String,
    /// Single-flight guard: one transition attempt per process.
    transition: Mutex<()>,
    /// Set once a transition has committed. A second attempt gets 409.
    committed: AtomicBool,
    /// Outcome of the committed transition, for the supervising process.
    outcome: Mutex<Option<CommitOutcome>>,
    /// Startup instant, for `/livez`.
    pub started_at: Instant,
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
        }
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
        if self.committed.load(Ordering::SeqCst) {
            return Err(CommitError::Conflict);
        }
        let outcome =
            commit_first_run_with_fault(&self.layout, mnemonic, Some(&self.pairing), fault)?;
        self.committed.store(true, Ordering::SeqCst);
        if let Ok(mut slot) = self.outcome.lock() {
            *slot = Some(outcome.clone());
        }
        Ok(outcome)
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
        state
            .pairing
            .verify_token_binding(&client_id, epoch, "", &claims.scp)
            .map_err(|_| unauthorized())?;

        Ok(BootstrapAuth { client_id })
    }
}

/// `GET /api/v1/bootstrap/state` response.
#[derive(Debug, Serialize)]
pub struct BootstrapStateResponse {
    /// `"bootstrap"` or `"initialized"`.
    pub state: &'static str,
    /// Whether a first-run restore is available.
    pub can_restore: bool,
    /// Whether a first-run create is available.
    pub can_create: bool,
}

async fn bootstrap_state(State(state): State<Arc<BootstrapState>>) -> Json<BootstrapStateResponse> {
    let open = !state.is_committed();
    Json(BootstrapStateResponse {
        state: if open { "bootstrap" } else { "initialized" },
        can_restore: open,
        can_create: open,
    })
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

fn pairing_error_response(e: PairingError) -> Response {
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
    (status, e.to_string()).into_response()
}

async fn pair_request(
    State(state): State<Arc<BootstrapState>>,
    Json(body): Json<PairRequestBody>,
) -> Result<Json<PairRequestResponse>, Response> {
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
) -> Result<Json<PairConfirmResponse>, Response> {
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
) -> Result<Json<serde_json::Value>, Response> {
    let challenge = state
        .pairing
        .issue_token_challenge(&q.client_id)
        .map_err(pairing_error_response)?;
    Ok(Json(serde_json::json!({ "challenge": challenge })))
}

async fn pair_token(
    State(state): State<Arc<BootstrapState>>,
    Json(body): Json<PairTokenBody>,
) -> Result<Json<PairTokenResponse>, Response> {
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
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstRunRestoreBody {
    /// BIP-39 recovery phrase (12 or 24 words).
    pub mnemonic: String,
}

/// Terminal response from a first-run create or restore.
#[derive(Debug, Serialize)]
pub struct FirstRunResponse {
    /// Node id of the committed identity.
    pub node_id: String,
    /// Always true: the operator starts the live node, the API never does.
    pub restart_required: bool,
    /// For a create, the phrase the user must write down. Absent on restore.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
}

fn commit_error_response(e: CommitError) -> Response {
    let status = match e {
        CommitError::Conflict => StatusCode::CONFLICT,
        CommitError::InvalidMnemonic(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, e.to_string()).into_response()
}

async fn first_run_restore(
    _auth: BootstrapAuth,
    State(state): State<Arc<BootstrapState>>,
    Json(body): Json<FirstRunRestoreBody>,
) -> Result<Json<FirstRunResponse>, Response> {
    let words = body.mnemonic.split_whitespace().count();
    if words != 12 && words != 24 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("mnemonic must be 12 or 24 words, got {words}"),
        )
            .into_response());
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
) -> Result<Json<FirstRunResponse>, Response> {
    let (mnemonic, _identity) = konsensus_core::NodeIdentity::generate()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?;
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
pub fn build_bootstrap_router(state: Arc<BootstrapState>) -> Router {
    Router::new()
        .route("/livez", get(livez))
        .route("/api/v1/bootstrap/state", get(bootstrap_state))
        .route("/api/v1/pair/request", post(pair_request))
        .route("/api/v1/pair/confirm", post(pair_confirm))
        .route("/api/v1/pair/challenge", get(pair_challenge))
        .route("/api/v1/pair/token", post(pair_token))
        .route("/api/v1/identity/restore", post(first_run_restore))
        .route("/api/v1/identity/create", post(first_run_create))
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
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<Option<CommitOutcome>, Box<dyn std::error::Error + Send + Sync>> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "node is in identity-free BOOTSTRAP mode — only the pairing ceremony and first-run create/restore are reachable");

    let app = build_bootstrap_router(Arc::clone(&state));
    let poll_state = Arc::clone(&state);
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            loop {
                if poll_state.is_committed() {
                    // Give the terminal response time to flush before the
                    // listener closes.
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    return;
                }
                tokio::select! {
                    _ = shutdown_rx.changed() => return,
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
                }
            }
        })
        .await?;

    Ok(state.outcome())
}
