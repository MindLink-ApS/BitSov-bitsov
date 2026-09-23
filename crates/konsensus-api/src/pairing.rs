//! Client pairing, durable pairing records, and owner-approved elevation (#76).
//!
//! # What this module buys, stated before the mechanism
//!
//! Before pairing, any process that could open a TCP connection to
//! `127.0.0.1:<port>` could mint a token: a web page doing
//! `fetch('http://127.0.0.1:3141')`, a process belonging to another OS user, a
//! container with host networking, an SSH port-forward. Pairing moves the bar
//! from **"can reach loopback"** to **"can read the owner's data directory"**.
//!
//! That is a large reduction in exposed surface. It is **not** local security.
//! A process running as the same OS user that can read arbitrary files can read
//! whatever credential the app can read, so no design at this tier stops it —
//! closing that needs an OS keychain with a per-application ACL or
//! hardware-backed keys, which are later tiers. The honest claim, preserved
//! verbatim from the design: **less exposure, not solved local security.**
//!
//! # The authorization channel
//!
//! [`PairingService::request_pairing`] writes a fresh 32-byte challenge to
//! `<data_dir>/pairing/challenge-<pair_id>` at mode `0600` and returns only a
//! `pair_id`. Confirming a pairing requires signing that challenge, so the
//! load-bearing control is **read access to the data directory** — nothing
//! secret ever travels over HTTP.
//!
//! The short code printed to the node's stdout is a **tripwire**, not the
//! control (policy lock C). It is deliberately absent from every HTTP response:
//! an app that can read the challenge file derives the same code locally, while
//! a loopback-only caller must not be handed the thing the owner compares
//! against. If anyone later describes the code comparison as *preventing* a
//! pairing, that is an overclaim.
//!
//! # Elevation is not an HTTP capability
//!
//! In the sidecar deployment the app launches the node and owns its stdout and
//! its `data_dir`, so no node-emitted secret can exclude it. Rather than
//! pretend a channel is owner-only when the app can drive it, `spend` and
//! live-identity replacement are simply **unavailable** over HTTP: this module
//! exposes `create_*_request` (writes a pending record, no authority) and
//! reads, while every function that writes a grant or consumes an approval is
//! reachable only from the owner CLI over `<data_dir>/control.sock`
//! (see [`crate::control`]) and refuses outright unless owner-run mode was
//! explicitly enabled.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::auth::{self, Scope, TokenError};

/// Length of the pairing challenge written under `data_dir`.
///
/// 32 bytes of CSPRNG output: the same width as the auth-challenge nonce, and
/// far beyond guessing by a caller that can only reach loopback.
pub const CHALLENGE_LEN: usize = 32;

/// How long a pending pairing request stays confirmable.
///
/// Short on purpose — a pending request is a window during which a process that
/// gains data-directory read access could complete a ceremony, so it closes in
/// about two minutes and is single-use.
pub const PENDING_PAIRING_TTL: Duration = Duration::from_secs(120);

/// Cap on simultaneously-pending pairing requests.
///
/// `/pair/request` is unauthenticated by construction (a client cannot have a
/// token yet), so an attacker can call it in a loop. Each call costs a 32-byte
/// file; this bounds that to a fixed, trivial amount of disk and rejects the
/// rest rather than letting the directory grow without limit.
pub const MAX_PENDING_PAIRINGS: usize = 32;

/// Paired-token lifetime: 10 minutes.
///
/// Minutes, not the 24 hours a loopback token gets. The durable secret is the
/// client key held by the app; a leaked token must stop being useful quickly.
pub const PAIRED_TOKEN_VALIDITY_SECS: i64 = 600;

/// How long a token-issuance challenge stays usable.
pub const TOKEN_CHALLENGE_TTL: Duration = Duration::from_secs(120);

/// Inactivity horizon for a pairing: 180 days.
///
/// An abandoned laptop must stop being a standing grant. A pairing unused for
/// this long expires and requires the ceremony again.
pub const PAIRING_INACTIVITY_SECS: i64 = 180 * 24 * 3600;

/// Default lifetime of an owner-opened pairing window.
pub const DEFAULT_PAIRING_WINDOW: Duration = Duration::from_secs(300);

/// How long a pending elevation request or replacement approval stays valid.
pub const ELEVATION_TTL_SECS: i64 = 900;

/// Default lifetime of an owner-written spend grant: 30 days.
///
/// A grant is neither transferable to another client nor perpetual.
pub const SPEND_GRANT_TTL_SECS: i64 = 30 * 24 * 3600;

/// Scopes a pairing carries by default (policy lock A): `read` + `receive`.
///
/// First run works unattended, and a paired client is no more capable than
/// today's loopback token — it is just the only caller that can get there.
pub fn default_pairing_scopes() -> Vec<Scope> {
    vec![Scope::Read, Scope::Receive]
}

/// Scopes a first-run bootstrap pairing carries.
///
/// `identity` is added **only** while no identity exists, because a node with
/// no keys has nothing to protect. [`PairingService::rebind_to_identity`]
/// strips it back to [`default_pairing_scopes`] as part of the transition
/// commit, so a pairing cannot carry first-run authority into a live node.
pub fn bootstrap_pairing_scopes() -> Vec<Scope> {
    vec![Scope::Read, Scope::Receive, Scope::Identity]
}

/// The only scope an owner may grant to a pairing after the fact (policy lock B).
///
/// `spend` is an explicit per-pairing grant by the owner, not a per-message
/// confirmation: under "payment IS the connection" every message send is a
/// spend, so per-operation prompts would fire on every message and be unusable.
///
/// `identity` is deliberately NOT grantable this way — replacing a live
/// identity is destructive and stays a per-operation approval. `credential`
/// is never grantable at all: a pairing that could mint credentials at least
/// as strong as its own would be the privilege escalation this ticket removes.
pub fn grantable_scopes() -> &'static [Scope] {
    &[Scope::Spend]
}

/// Errors from the pairing and elevation surface.
#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    /// Pairing is not currently accepted (a client is paired and no window is open).
    #[error("pairing is closed: a client is already paired and no pairing window is open")]
    Closed,
    /// Too many pending pairing requests.
    #[error("too many pending pairing requests")]
    TooManyPending,
    /// The `pair_id` is unknown, already used, or expired.
    #[error("pairing request is unknown, already used, or expired")]
    UnknownPending,
    /// Signature verification failed against the challenge.
    #[error("pairing proof did not verify")]
    BadProof,
    /// Malformed client key or signature encoding.
    #[error("malformed input: {0}")]
    Malformed(String),
    /// No such paired client.
    #[error("no such paired client")]
    UnknownClient,
    /// The pairing exists but is no longer valid for token issuance.
    #[error("pairing is no longer valid: {0}")]
    PairingInvalid(String),
    /// A scope was requested that may never be granted this way.
    #[error("scope is not grantable to a pairing: {0}")]
    NotGrantable(String),
    /// No such pending operation.
    #[error("no such pending operation")]
    UnknownOperation,
    /// The typed confirmation did not name this operation.
    #[error("confirmation phrase did not match the pending operation")]
    ConfirmationMismatch,
    /// The approval or request has expired.
    #[error("operation expired")]
    Expired,
    /// The approval exists but has not been confirmed by the owner.
    #[error("operation has not been approved by the owner")]
    NotApproved,
    /// A bound field did not match the approval.
    #[error("approval binding mismatch")]
    BindingMismatch,
    /// Elevation is unavailable in this deployment (sidecar / owner-run disabled).
    #[error(
        "elevation is unavailable: this node was not started in owner-run mode, so no owner \
         control socket exists. A packaged sidecar app is a read+receive client by design — \
         run the node yourself and grant over <data_dir>/control.sock to obtain spend."
    )]
    OwnerChannelUnavailable,
    /// Durable state could not be read or written.
    #[error("pairing store error: {0}")]
    Io(String),
}

impl From<io::Error> for PairingError {
    fn from(e: io::Error) -> Self {
        PairingError::Io(e.to_string())
    }
}

/// A durable record of a paired client.
///
/// The node stores only the client's **public** key. Stealing a pairing does
/// not expose the node identity or the funds, and rotating a client key does
/// not touch the identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairedClient {
    /// Stable id derived from the client public key.
    pub client_id: String,
    /// Human-readable name the client supplied, for the owner's benefit.
    pub name: String,
    /// Ed25519 public key (hex).
    pub client_pubkey: String,
    /// Scopes this pairing carries.
    pub scopes: Vec<Scope>,
    /// Revocation epoch. Bumping it invalidates every outstanding token for
    /// this client immediately, without waiting for expiry.
    pub epoch: u64,
    /// Fingerprint of the identity this pairing was created against.
    pub identity_fingerprint: String,
    /// Unix seconds when the pairing was confirmed.
    pub created_at: i64,
    /// Unix seconds of the last token issuance, if any.
    pub last_seen: Option<i64>,
}

/// An owner-written grant adding a scope to a pairing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendGrant {
    /// The pending operation the owner confirmed to write this grant. Kept so
    /// the requesting client can read its request's status after the pending
    /// record is consumed, without that read being able to change anything.
    pub op_id: String,
    /// Client this grant is bound to. Not transferable.
    pub client_id: String,
    /// Scopes granted.
    pub scopes: Vec<Scope>,
    /// Unix seconds when the owner confirmed it.
    pub granted_at: i64,
    /// Unix seconds after which the grant is inert.
    pub expires_at: i64,
    /// Identity the grant was written against.
    pub identity_fingerprint: String,
    /// Pairing epoch at grant time — a revocation invalidates the grant too.
    pub epoch: u64,
    /// Always `"cli"`: the HTTP surface can never write one of these.
    pub granted_by: String,
}

/// A pending elevation request created over HTTP. Carries **no authority**.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingElevation {
    /// Operation id the owner names in their typed confirmation.
    pub op_id: String,
    /// Requesting client.
    pub client_id: String,
    /// Client name, rendered to the owner by the CLI.
    pub client_name: String,
    /// Scopes requested.
    pub scopes: Vec<Scope>,
    /// Unix seconds when it was requested.
    pub created_at: i64,
    /// Unix seconds after which it can no longer be confirmed.
    pub expires_at: i64,
}

/// A pending live-identity replacement, bound to five fields and single-use.
///
/// The replacement fingerprint is computed from the supplied recovery phrase
/// **before anything is written**, so the owner approves one specific
/// destination identity rather than "whatever the app sends afterwards".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplacementApproval {
    /// Operation id — field 1.
    pub op_id: String,
    /// Requesting client — field 2.
    pub client_id: String,
    /// Identity being replaced — field 3.
    pub current_identity_fingerprint: String,
    /// Identity that will replace it — field 4.
    pub replacement_identity_fingerprint: String,
    /// Expiry, enforced at consumption and not only at creation — field 5.
    pub expires_at: i64,
    /// Whether the owner has confirmed it over the control socket.
    pub approved: bool,
    /// Client name, rendered to the owner by the CLI.
    pub client_name: String,
}

/// Everything durable about pairing, persisted as one atomically-replaced file.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairingFile {
    /// Schema version. A file this node cannot understand is a refusal, never
    /// a silent reset to "no pairings" (which would reopen pairing).
    pub version: u32,
    /// Paired clients.
    pub clients: Vec<PairedClient>,
    /// Owner-written grants.
    pub grants: Vec<SpendGrant>,
    /// Pending elevation requests (no authority).
    pub pending_elevations: Vec<PendingElevation>,
    /// Pending / approved replacement approvals.
    pub replacement_approvals: Vec<ReplacementApproval>,
}

/// Current durable schema version.
pub const PAIRING_FILE_VERSION: u32 = 1;

/// A pending pairing request. Held in memory; the challenge itself lives in the
/// protected file under `data_dir`, which is the actual control.
#[derive(Debug, Clone)]
struct PendingPairing {
    client_pubkey: String,
    name: String,
    challenge: [u8; CHALLENGE_LEN],
    expires_at: Instant,
}

/// What `request_pairing` returns to its caller.
#[derive(Debug, Clone)]
pub struct PairingRequestOutcome {
    /// Opaque id for this ceremony.
    pub pair_id: String,
    /// Unix seconds after which the request can no longer be confirmed.
    pub expires_at: i64,
    /// Short human code derived from the challenge — printed to the node's own
    /// stdout as a tripwire. **Never** returned over HTTP.
    pub short_code: String,
}

/// Which signing path a token issuance takes.
enum TokenKind {
    /// A live node's token, bound to the running identity's fingerprint.
    Live { subject: String },
    /// A bootstrap token: ephemeral secret, `bst` marked, no identity to bind.
    Bootstrap,
}

/// A token issued to a paired client.
#[derive(Debug, Clone)]
pub struct IssuedToken {
    /// The JWT.
    pub token: String,
    /// Unix seconds of expiry.
    pub expires_at: i64,
    /// Scopes actually carried (pairing scopes plus any live grant).
    pub scopes: Vec<Scope>,
}

/// Derive the stable client id from an Ed25519 public key.
pub fn client_id_from_pubkey(pubkey_hex: &str) -> String {
    let digest = blake3::keyed_hash(
        blake3::hash(b"bitsov-pair-client-id-v1").as_bytes(),
        pubkey_hex.as_bytes(),
    );
    hex::encode(&digest.as_bytes()[..16])
}

/// Derive an identity fingerprint from a node id.
///
/// A digest rather than the node id itself: the fingerprint is rendered to the
/// owner by the CLI and stored in pairing records, and `/api/v1/health`
/// deliberately redacts the node id from unauthenticated callers. Reusing the
/// node id here would leak it back out through a less guarded surface.
pub fn identity_fingerprint(node_id_hex: &str) -> String {
    let digest = blake3::keyed_hash(
        blake3::hash(b"bitsov-identity-fingerprint-v1").as_bytes(),
        node_id_hex.as_bytes(),
    );
    hex::encode(&digest.as_bytes()[..16])
}

/// Derive the fingerprint a recovery phrase *would* produce, without writing
/// anything. Used to bind a replacement approval to one specific destination.
pub fn fingerprint_for_mnemonic(mnemonic: &str) -> Result<String, PairingError> {
    let identity = konsensus_core::NodeIdentity::from_mnemonic(mnemonic, "")
        .map_err(|e| PairingError::Malformed(format!("invalid mnemonic: {e}")))?;
    Ok(identity_fingerprint(&identity.node_id().to_hex()))
}

/// The short code the owner compares, derived from the challenge bytes.
///
/// A tripwire, not the control: it is printed to the node's stdout and derived
/// independently by an app that could read the challenge file.
pub fn short_code(challenge: &[u8]) -> String {
    const ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let digest = blake3::keyed_hash(
        blake3::hash(b"bitsov-pair-shortcode-v1").as_bytes(),
        challenge,
    );
    let bytes = digest.as_bytes();
    let mut out = String::with_capacity(9);
    for (i, b) in bytes.iter().take(8).enumerate() {
        if i == 4 {
            out.push('-');
        }
        out.push(ALPHABET[(*b as usize) % ALPHABET.len()] as char);
    }
    out
}

/// Public operation label. Authorization also needs the owner-console nonce.
pub fn grant_confirmation_phrase(op: &PendingElevation) -> String {
    format!("GRANT {} TO {}", scope_list(&op.scopes), op.op_id)
}

/// Public operation label. This is not proof of owner approval by itself.
pub fn replacement_confirmation_phrase(approval: &ReplacementApproval) -> String {
    format!("REPLACE IDENTITY {}", approval.op_id)
}

fn scope_list(scopes: &[Scope]) -> String {
    scopes
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join("+")
}

/// Pairing state for one data directory.
///
/// All durable mutation goes through one mutex and one atomically-replaced
/// file, which is what makes "exactly one consumption can succeed" true rather
/// than merely likely.
pub struct PairingService {
    dir: PathBuf,
    file_path: PathBuf,
    inner: Mutex<Inner>,
    /// Whether the owner control socket exists in this deployment. When false,
    /// every grant-writing and approval-consuming call refuses outright
    /// (`OwnerChannelUnavailable`) — there is no debug flag, config switch or
    /// trusted-client list that widens this.
    owner_control_enabled: bool,
    /// Whether the short code is echoed to stdout. Off in tests so a test run
    /// does not scribble on the harness's output.
    print_short_code: bool,
    owner_console: Mutex<Box<dyn std::io::Write + Send>>,
}

struct Inner {
    file: PairingFile,
    pending: HashMap<String, PendingPairing>,
    token_challenges: HashMap<String, (String, Instant)>,
    window_until: Option<Instant>,
    identity_fingerprint: String,
    // Never serialized or returned by HTTP/control status. Restart invalidates
    // pending console challenges; the owner must request a new operation.
    owner_confirmations: HashMap<String, (blake3::Hash, i64)>,
}

struct OwnerTerminal;

impl std::io::Write for OwnerTerminal {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            // A dedicated owner terminal, never tracing, stdout capture, or a
            // file under data_dir. No terminal means no elevation challenge.
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/tty")?
                .write(bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = bytes;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "owner terminal unavailable",
            ))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl PairingService {
    /// Open (or create) the pairing state under `<data_dir>/pairing/`.
    ///
    /// `identity_fingerprint` is the fingerprint of the running identity, or
    /// the empty string in bootstrap where no identity exists yet.
    pub fn open(
        data_dir: &Path,
        identity_fingerprint: String,
        owner_control_enabled: bool,
    ) -> Result<Self, PairingError> {
        let dir = data_dir.join("pairing");
        std::fs::create_dir_all(&dir)?;
        restrict_dir(&dir)?;
        let file_path = dir.join("clients.json");
        let file = if file_path.exists() {
            let raw = std::fs::read(&file_path)?;
            let parsed: PairingFile = serde_json::from_slice(&raw).map_err(|e| {
                // Fail closed and demand repair. Treating an unreadable pairing
                // file as "no pairings" would reopen the ceremony on a node
                // that has a paired client — exactly the state an attacker
                // would want to induce.
                PairingError::Io(format!(
                    "pairing store at {} is unreadable ({e}). Refusing to treat it as empty, \
                     which would reopen the pairing ceremony. Repair: restore \
                     pairing/clients.json from backup, or delete it deliberately to re-pair \
                     from scratch.",
                    file_path.display()
                ))
            })?;
            if parsed.version > PAIRING_FILE_VERSION {
                return Err(PairingError::Io(format!(
                    "pairing store at {} was written by a newer node (version {} > {}). \
                     Repair: upgrade the node, or remove the file to re-pair from scratch.",
                    file_path.display(),
                    parsed.version,
                    PAIRING_FILE_VERSION
                )));
            }
            parsed
        } else {
            PairingFile {
                version: PAIRING_FILE_VERSION,
                ..PairingFile::default()
            }
        };

        Ok(Self {
            dir,
            file_path,
            inner: Mutex::new(Inner {
                file,
                pending: HashMap::new(),
                token_challenges: HashMap::new(),
                window_until: None,
                identity_fingerprint,
                owner_confirmations: HashMap::new(),
            }),
            owner_control_enabled,
            print_short_code: true,
            owner_console: Mutex::new(Box::new(OwnerTerminal)),
        })
    }

    /// Supply a trusted owner-console transport (also used by disposable test
    /// fixtures). This is not a request field or a configuration override.
    pub fn with_owner_console(mut self, console: Box<dyn std::io::Write + Send>) -> Self {
        self.owner_console = Mutex::new(console);
        self
    }

    fn console_challenge(
        &self,
        inner: &mut Inner,
        op_id: &str,
        label: &str,
        expires_at: i64,
    ) -> Result<(), PairingError> {
        if !self.owner_control_enabled {
            return Ok(());
        }
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let phrase = format!("{label} CODE {}", hex::encode(nonce));
        let mut console = self
            .owner_console
            .lock()
            .map_err(|_| PairingError::Io("owner console unavailable".into()))?;
        console.write_all(
            format!("\nOwner approval (expires {expires_at}):\n{phrase}\n").as_bytes(),
        )?;
        console.flush()?;
        inner
            .owner_confirmations
            .retain(|_, (_, expiry)| *expiry > chrono::Utc::now().timestamp());
        inner.owner_confirmations.insert(
            op_id.to_owned(),
            (blake3::hash(phrase.as_bytes()), expires_at),
        );
        Ok(())
    }

    fn verify_owner_confirmation(
        inner: &Inner,
        op_id: &str,
        confirmation: &str,
    ) -> Result<(), PairingError> {
        let valid = inner
            .owner_confirmations
            .get(op_id)
            .is_some_and(|(digest, expiry)| {
                *expiry > chrono::Utc::now().timestamp()
                    && *digest == blake3::hash(confirmation.trim().as_bytes())
            });
        if valid {
            Ok(())
        } else {
            Err(PairingError::ConfirmationMismatch)
        }
    }

    /// Test/bootstrap helper: suppress the stdout tripwire print.
    pub fn without_stdout_code(mut self) -> Self {
        self.print_short_code = false;
        self
    }

    /// Directory holding the challenge files and the durable store.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether an owner control socket exists in this deployment.
    pub fn owner_control_enabled(&self) -> bool {
        self.owner_control_enabled
    }

    /// Snapshot of the durable state, read through the same lock writers use.
    pub fn snapshot(&self) -> PairingFile {
        self.lock().file.clone()
    }

    /// Re-read the durable state from disk. Used by tests and by the CLI to
    /// assert effects rather than trust an in-memory copy.
    pub fn reload_from_disk(&self) -> Result<PairingFile, PairingError> {
        if !self.file_path.exists() {
            return Ok(PairingFile {
                version: PAIRING_FILE_VERSION,
                ..PairingFile::default()
            });
        }
        let raw = std::fs::read(&self.file_path)?;
        serde_json::from_slice(&raw).map_err(|e| PairingError::Io(e.to_string()))
    }

    /// The identity this service currently binds pairings to.
    pub fn bound_fingerprint(&self) -> String {
        self.lock().identity_fingerprint.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock means a previous holder panicked mid-update. The
        // durable file is only ever replaced atomically, so the on-disk state
        // is still consistent; recovering the guard is preferable to
        // propagating a panic into every later request.
        match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    // ── Pairing windows ────────────────────────────────────────────

    /// Is pairing currently accepted?
    ///
    /// Only while **no client is paired**, or while a window is explicitly
    /// open. Otherwise an attacker could sit on `/pair/request` forever waiting
    /// for a moment of weakness.
    pub fn pairing_open(&self) -> bool {
        let inner = self.lock();
        Self::open_inner(&inner)
    }

    fn open_inner(inner: &Inner) -> bool {
        if inner.file.clients.is_empty() {
            return true;
        }
        matches!(inner.window_until, Some(until) if until > Instant::now())
    }

    /// Open a pairing window. Reachable from the owner CLI and from an
    /// already-paired client holding `admin`.
    pub fn open_pairing_window(&self, for_duration: Duration) -> i64 {
        let mut inner = self.lock();
        inner.window_until = Some(Instant::now() + for_duration);
        chrono::Utc::now().timestamp() + for_duration.as_secs() as i64
    }

    // ── The ceremony ───────────────────────────────────────────────

    /// Step 1–2: record a pending request and write its challenge to a
    /// `0600` file under `data_dir`.
    ///
    /// Nothing secret is returned to the caller. A loopback-only attacker can
    /// call this all day and get nothing usable.
    pub fn request_pairing(
        &self,
        name: &str,
        client_pubkey_hex: &str,
    ) -> Result<PairingRequestOutcome, PairingError> {
        let pubkey = parse_pubkey(client_pubkey_hex)?;
        let _ = pubkey;
        let name = sanitize_name(name);

        let mut challenge = [0u8; CHALLENGE_LEN];
        rand::thread_rng().fill_bytes(&mut challenge);
        let mut pair_id_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut pair_id_bytes);
        let pair_id = hex::encode(pair_id_bytes);

        let now = Instant::now();
        let expires_at_unix = chrono::Utc::now().timestamp() + PENDING_PAIRING_TTL.as_secs() as i64;

        {
            let mut inner = self.lock();
            if !Self::open_inner(&inner) {
                return Err(PairingError::Closed);
            }
            let stale: Vec<String> = inner
                .pending
                .iter()
                .filter(|(_, p)| p.expires_at <= now)
                .map(|(id, _)| id.clone())
                .collect();
            for id in stale {
                inner.pending.remove(&id);
                let _ = std::fs::remove_file(self.challenge_path(&id));
            }
            if inner.pending.len() >= MAX_PENDING_PAIRINGS {
                return Err(PairingError::TooManyPending);
            }
            inner.pending.insert(
                pair_id.clone(),
                PendingPairing {
                    client_pubkey: client_pubkey_hex.to_ascii_lowercase(),
                    name,
                    challenge,
                    expires_at: now + PENDING_PAIRING_TTL,
                },
            );
        }

        write_protected(&self.challenge_path(&pair_id), &challenge)?;

        let code = short_code(&challenge);
        if self.print_short_code {
            // The node's OWN stdout. In the sidecar deployment the app can read
            // this by construction, which is why it is a cross-check and not
            // the control (policy lock C).
            println!("bitsov pairing code for \"{}\": {}", pair_id, code);
            tracing::info!(pair_id = %pair_id, "pairing requested — short code printed to stdout");
        }

        Ok(PairingRequestOutcome {
            pair_id,
            expires_at: expires_at_unix,
            short_code: code,
        })
    }

    /// The bytes a client signs: `pair_id || client_pubkey || challenge`.
    pub fn proof_message(pair_id: &str, client_pubkey_hex: &str, challenge: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(pair_id.len() + client_pubkey_hex.len() + challenge.len());
        msg.extend_from_slice(pair_id.as_bytes());
        msg.extend_from_slice(client_pubkey_hex.as_bytes());
        msg.extend_from_slice(challenge);
        msg
    }

    /// Step 3–4: verify the app's proof, delete the challenge, and record the
    /// client public key with its default scopes.
    ///
    /// Single-use: the pending record and the challenge file are both consumed
    /// before the signature is even checked, so a wrong guess burns the attempt
    /// rather than permitting an unbounded retry against one challenge.
    pub fn confirm_pairing(
        &self,
        pair_id: &str,
        signature_hex: &str,
        scopes: Vec<Scope>,
    ) -> Result<PairedClient, PairingError> {
        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| PairingError::Malformed(format!("invalid signature hex: {e}")))?;
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|e| PairingError::Malformed(format!("invalid signature: {e}")))?;

        let pending = {
            let mut inner = self.lock();
            let pending = inner
                .pending
                .remove(pair_id)
                .ok_or(PairingError::UnknownPending)?;
            if pending.expires_at <= Instant::now() {
                let _ = std::fs::remove_file(self.challenge_path(pair_id));
                return Err(PairingError::UnknownPending);
            }
            pending
        };
        let _ = std::fs::remove_file(self.challenge_path(pair_id));

        let verifying = parse_pubkey(&pending.client_pubkey)?;
        let msg = Self::proof_message(pair_id, &pending.client_pubkey, &pending.challenge);
        verifying
            .verify_strict(&msg, &sig)
            .map_err(|_| PairingError::BadProof)?;

        let now = chrono::Utc::now().timestamp();
        let client_id = client_id_from_pubkey(&pending.client_pubkey);

        let mut inner = self.lock();
        let fingerprint = inner.identity_fingerprint.clone();
        let epoch = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == client_id)
            .map(|c| c.epoch)
            .unwrap_or(0);
        let record = PairedClient {
            client_id: client_id.clone(),
            name: pending.name.clone(),
            client_pubkey: pending.client_pubkey.clone(),
            scopes,
            epoch,
            identity_fingerprint: fingerprint,
            created_at: now,
            last_seen: None,
        };
        inner.file.clients.retain(|c| c.client_id != client_id);
        inner.file.clients.push(record.clone());
        self.persist(&inner.file)?;
        Ok(record)
    }

    /// Issue a token-issuance challenge for a paired client.
    pub fn issue_token_challenge(&self, client_id: &str) -> Result<String, PairingError> {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut inner = self.lock();
        if !inner.file.clients.iter().any(|c| c.client_id == client_id) {
            return Err(PairingError::UnknownClient);
        }
        let now = Instant::now();
        inner.token_challenges.retain(|_, (_, exp)| *exp > now);
        let challenge = format!("bitsov-pair-token-v1:{}", hex::encode(nonce));
        inner.token_challenges.insert(
            challenge.clone(),
            (client_id.to_string(), now + TOKEN_CHALLENGE_TTL),
        );
        Ok(challenge)
    }

    /// Exchange a signed challenge for a short-lived paired token.
    ///
    /// The token carries `cid` (client), `epc` (pairing epoch) and `idf`
    /// (identity fingerprint). A mismatch on any of them at verification time
    /// is a rejection, never a downgrade — the same discipline the scope-less
    /// legacy token gets.
    pub fn issue_token(
        &self,
        subject: &str,
        jwt_secret: &str,
        client_id: &str,
        challenge: &str,
        signature_hex: &str,
    ) -> Result<IssuedToken, PairingError> {
        self.issue_token_kind(
            TokenKind::Live {
                subject: subject.to_string(),
            },
            jwt_secret,
            client_id,
            challenge,
            signature_hex,
        )
    }

    /// Exchange a signed challenge for a bootstrap token (#76).
    ///
    /// Signed with the bootstrap process's ephemeral secret and marked `bst`,
    /// so it stops verifying the instant the identity-derived secret takes over
    /// and is refused outright by the live router even if re-signed.
    pub fn issue_bootstrap_token(
        &self,
        jwt_secret: &str,
        client_id: &str,
        challenge: &str,
        signature_hex: &str,
    ) -> Result<IssuedToken, PairingError> {
        self.issue_token_kind(
            TokenKind::Bootstrap,
            jwt_secret,
            client_id,
            challenge,
            signature_hex,
        )
    }

    fn issue_token_kind(
        &self,
        kind: TokenKind,
        jwt_secret: &str,
        client_id: &str,
        challenge: &str,
        signature_hex: &str,
    ) -> Result<IssuedToken, PairingError> {
        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| PairingError::Malformed(format!("invalid signature hex: {e}")))?;
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|e| PairingError::Malformed(format!("invalid signature: {e}")))?;

        let now_unix = chrono::Utc::now().timestamp();
        let mut inner = self.lock();

        let (owner, expires) = inner
            .token_challenges
            .remove(challenge)
            .ok_or(PairingError::UnknownPending)?;
        if expires <= Instant::now() || owner != client_id {
            return Err(PairingError::UnknownPending);
        }

        let fingerprint = inner.identity_fingerprint.clone();
        let record = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == client_id)
            .cloned()
            .ok_or(PairingError::UnknownClient)?;

        if record.identity_fingerprint != fingerprint {
            return Err(PairingError::PairingInvalid(
                "pairing was created against a different identity".into(),
            ));
        }
        if let Some(last) = record.last_seen {
            if now_unix - last > PAIRING_INACTIVITY_SECS {
                return Err(PairingError::PairingInvalid(
                    "pairing has been unused past its inactivity horizon — re-pair".into(),
                ));
            }
        } else if now_unix - record.created_at > PAIRING_INACTIVITY_SECS {
            return Err(PairingError::PairingInvalid(
                "pairing has been unused past its inactivity horizon — re-pair".into(),
            ));
        }

        let verifying = parse_pubkey(&record.client_pubkey)?;
        verifying
            .verify_strict(challenge.as_bytes(), &sig)
            .map_err(|_| PairingError::BadProof)?;

        let mut scopes = record.scopes.clone();
        for grant in &inner.file.grants {
            if grant.client_id == client_id
                && grant.expires_at > now_unix
                && grant.epoch == record.epoch
                && grant.identity_fingerprint == fingerprint
            {
                for s in &grant.scopes {
                    if !scopes.contains(s) {
                        scopes.push(*s);
                    }
                }
            }
        }

        let token = match &kind {
            TokenKind::Live { subject } => auth::create_paired_token(
                subject,
                jwt_secret,
                scopes.clone(),
                client_id,
                record.epoch,
                &fingerprint,
            ),
            TokenKind::Bootstrap => {
                auth::create_bootstrap_token(jwt_secret, scopes.clone(), client_id, record.epoch)
            }
        }
        .map_err(|e: TokenError| PairingError::Io(e.to_string()))?;

        if let Some(c) = inner
            .file
            .clients
            .iter_mut()
            .find(|c| c.client_id == client_id)
        {
            c.last_seen = Some(now_unix);
        }
        self.persist(&inner.file)?;

        Ok(IssuedToken {
            token,
            expires_at: now_unix + PAIRED_TOKEN_VALIDITY_SECS,
            scopes,
        })
    }

    /// Verify the pairing binding a token claims.
    ///
    /// Called on **every** authenticated request carrying `cid`. A token whose
    /// client is gone, whose epoch is stale, whose identity fingerprint does
    /// not match the running identity, or which claims a scope the pairing no
    /// longer holds, is rejected outright.
    pub fn verify_token_binding(
        &self,
        client_id: &str,
        epoch: u64,
        fingerprint: &str,
        scopes: &[Scope],
    ) -> Result<(), PairingError> {
        let now_unix = chrono::Utc::now().timestamp();
        let inner = self.lock();
        if inner.identity_fingerprint != fingerprint {
            return Err(PairingError::PairingInvalid(
                "token was issued against a different identity".into(),
            ));
        }
        let record = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == client_id)
            .ok_or(PairingError::UnknownClient)?;
        if record.epoch != epoch {
            return Err(PairingError::PairingInvalid(
                "pairing epoch has been bumped — the token is revoked".into(),
            ));
        }
        if record.identity_fingerprint != fingerprint {
            return Err(PairingError::PairingInvalid(
                "pairing is bound to a different identity".into(),
            ));
        }
        let mut permitted = record.scopes.clone();
        for grant in &inner.file.grants {
            if grant.client_id == client_id
                && grant.expires_at > now_unix
                && grant.epoch == record.epoch
                && grant.identity_fingerprint == fingerprint
            {
                for s in &grant.scopes {
                    if !permitted.contains(s) {
                        permitted.push(*s);
                    }
                }
            }
        }
        if let Some(extra) = scopes.iter().find(|s| !permitted.contains(s)) {
            return Err(PairingError::PairingInvalid(format!(
                "token claims scope `{}` the pairing no longer holds",
                extra.as_str()
            )));
        }
        Ok(())
    }

    /// List paired clients (behind `read` on the HTTP surface).
    pub fn list_clients(&self) -> Vec<PairedClient> {
        self.lock().file.clients.clone()
    }

    /// Bump a pairing's epoch, invalidating every outstanding token for it.
    pub fn bump_epoch(&self, client_id: &str) -> Result<u64, PairingError> {
        let mut inner = self.lock();
        let record = inner
            .file
            .clients
            .iter_mut()
            .find(|c| c.client_id == client_id)
            .ok_or(PairingError::UnknownClient)?;
        record.epoch += 1;
        let epoch = record.epoch;
        // A grant is pinned to the epoch it was written against, so a
        // revocation drops the elevation with it rather than leaving a stale
        // `spend` waiting for the next pairing of the same key.
        inner.file.grants.retain(|g| g.client_id != client_id);
        self.persist(&inner.file)?;
        Ok(epoch)
    }

    /// Remove a pairing entirely (and any grant bound to it).
    pub fn revoke(&self, client_id: &str) -> Result<(), PairingError> {
        let mut inner = self.lock();
        if !inner.file.clients.iter().any(|c| c.client_id == client_id) {
            return Err(PairingError::UnknownClient);
        }
        inner.file.clients.retain(|c| c.client_id != client_id);
        inner.file.grants.retain(|g| g.client_id != client_id);
        inner
            .file
            .pending_elevations
            .retain(|e| e.client_id != client_id);
        inner
            .file
            .replacement_approvals
            .retain(|a| a.client_id != client_id);
        self.persist(&inner.file)?;
        Ok(())
    }

    /// Rotate a client key: the new public key is signed by the old one.
    pub fn rotate_client_key(
        &self,
        client_id: &str,
        new_pubkey_hex: &str,
        signature_hex: &str,
    ) -> Result<PairedClient, PairingError> {
        let new_key = parse_pubkey(new_pubkey_hex)?;
        let _ = new_key;
        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| PairingError::Malformed(format!("invalid signature hex: {e}")))?;
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|e| PairingError::Malformed(format!("invalid signature: {e}")))?;

        let mut inner = self.lock();
        let old = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == client_id)
            .cloned()
            .ok_or(PairingError::UnknownClient)?;
        let old_key = parse_pubkey(&old.client_pubkey)?;
        let msg = format!("bitsov-pair-rotate-v1:{client_id}:{new_pubkey_hex}");
        old_key
            .verify_strict(msg.as_bytes(), &sig)
            .map_err(|_| PairingError::BadProof)?;

        let new_id = client_id_from_pubkey(&new_pubkey_hex.to_ascii_lowercase());
        let rotated = PairedClient {
            client_id: new_id.clone(),
            client_pubkey: new_pubkey_hex.to_ascii_lowercase(),
            // The epoch advances on rotation: tokens minted for the old key
            // must stop working the moment the key they prove is retired.
            epoch: old.epoch + 1,
            ..old.clone()
        };
        inner
            .file
            .clients
            .retain(|c| c.client_id != client_id && c.client_id != new_id);
        inner.file.clients.push(rotated.clone());
        // Grants do not survive a key rotation: they were written against a
        // specific client id and epoch by a deliberate owner action.
        inner.file.grants.retain(|g| g.client_id != client_id);
        self.persist(&inner.file)?;
        Ok(rotated)
    }

    /// Re-stamp every pairing onto a newly-committed identity.
    ///
    /// Part of the bootstrap transition commit. First-run `identity` authority
    /// is stripped here: after the commit, replacing a live identity is a
    /// per-operation owner approval, never a consequence of having paired
    /// during bootstrap.
    pub fn rebind_to_identity(&self, fingerprint: &str) -> Result<(), PairingError> {
        let mut inner = self.lock();
        inner.identity_fingerprint = fingerprint.to_string();
        for client in inner.file.clients.iter_mut() {
            client.identity_fingerprint = fingerprint.to_string();
            client.scopes = default_pairing_scopes();
        }
        // Nothing pending from bootstrap carries into the live node.
        inner.file.grants.clear();
        inner.file.pending_elevations.clear();
        inner.file.replacement_approvals.clear();
        inner.owner_confirmations.clear();
        self.persist(&inner.file)?;
        Ok(())
    }

    // ── Elevation: HTTP may request, only the CLI may confirm ───────

    /// Create a pending elevation request. Writes **no** authority.
    pub fn create_elevation_request(
        &self,
        client_id: &str,
        scopes: Vec<Scope>,
    ) -> Result<PendingElevation, PairingError> {
        if scopes.is_empty() {
            return Err(PairingError::NotGrantable("no scopes requested".into()));
        }
        if let Some(bad) = scopes.iter().find(|s| !grantable_scopes().contains(s)) {
            return Err(PairingError::NotGrantable(bad.as_str().to_string()));
        }
        let now = chrono::Utc::now().timestamp();
        let mut op_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut op_bytes);

        let mut inner = self.lock();
        let client = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == client_id)
            .cloned()
            .ok_or(PairingError::UnknownClient)?;
        let op = PendingElevation {
            op_id: hex::encode(op_bytes),
            client_id: client_id.to_string(),
            client_name: client.name.clone(),
            scopes,
            created_at: now,
            expires_at: now + ELEVATION_TTL_SECS,
        };
        self.console_challenge(
            &mut inner,
            &op.op_id,
            &grant_confirmation_phrase(&op),
            op.expires_at,
        )?;
        inner.file.pending_elevations.retain(|e| e.expires_at > now);
        inner.file.pending_elevations.push(op.clone());
        self.persist(&inner.file)?;
        Ok(op)
    }

    /// Read the status of a pending elevation. A read, never a consumption.
    pub fn elevation_status(&self, op_id: &str) -> ElevationStatus {
        let now = chrono::Utc::now().timestamp();
        let inner = self.lock();
        if let Some(op) = inner
            .file
            .pending_elevations
            .iter()
            .find(|e| e.op_id == op_id)
        {
            if op.expires_at <= now {
                return ElevationStatus::Expired;
            }
            if inner
                .file
                .grants
                .iter()
                .any(|g| g.client_id == op.client_id && g.expires_at > now)
            {
                return ElevationStatus::Granted;
            }
            return ElevationStatus::Pending;
        }
        // The pending record is consumed when the owner writes the grant, so a
        // granted operation is found by the `op_id` recorded on the grant.
        if inner
            .file
            .grants
            .iter()
            .any(|g| g.op_id == op_id && g.expires_at > now)
        {
            return ElevationStatus::Granted;
        }
        ElevationStatus::Absent
    }

    /// Write a spend grant. **Owner CLI only.**
    ///
    /// Requires the operation-bound random confirmation printed only to the
    /// owner console. The public operation label is insufficient.
    pub fn grant_elevation(
        &self,
        op_id: &str,
        confirmation: &str,
    ) -> Result<SpendGrant, PairingError> {
        if !self.owner_control_enabled {
            return Err(PairingError::OwnerChannelUnavailable);
        }
        let now = chrono::Utc::now().timestamp();
        let mut inner = self.lock();
        let op = inner
            .file
            .pending_elevations
            .iter()
            .find(|e| e.op_id == op_id)
            .cloned()
            .ok_or(PairingError::UnknownOperation)?;
        if op.expires_at <= now {
            inner.file.pending_elevations.retain(|e| e.op_id != op_id);
            self.persist(&inner.file)?;
            return Err(PairingError::Expired);
        }
        Self::verify_owner_confirmation(&inner, op_id, confirmation)?;
        let client = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == op.client_id)
            .cloned()
            .ok_or(PairingError::UnknownClient)?;
        let grant = SpendGrant {
            op_id: op.op_id.clone(),
            client_id: op.client_id.clone(),
            scopes: op.scopes.clone(),
            granted_at: now,
            expires_at: now + SPEND_GRANT_TTL_SECS,
            identity_fingerprint: inner.identity_fingerprint.clone(),
            epoch: client.epoch,
            granted_by: "cli".to_string(),
        };
        inner.file.pending_elevations.retain(|e| e.op_id != op_id);
        inner.file.grants.retain(|g| g.client_id != grant.client_id);
        inner.file.grants.push(grant.clone());
        self.persist(&inner.file)?;
        inner.owner_confirmations.remove(op_id);
        Ok(grant)
    }

    /// Create a pending live-identity replacement, binding five fields.
    ///
    /// The replacement fingerprint is derived from the phrase here, before
    /// anything is written, and the phrase itself is **not** stored: the caller
    /// must present it again at consumption, where it is re-derived and
    /// compared.
    pub fn create_replacement_request(
        &self,
        client_id: &str,
        current_fingerprint: &str,
        mnemonic: &str,
    ) -> Result<ReplacementApproval, PairingError> {
        let replacement = fingerprint_for_mnemonic(mnemonic)?;
        let now = chrono::Utc::now().timestamp();
        let mut op_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut op_bytes);

        let mut inner = self.lock();
        let client = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == client_id)
            .cloned()
            .ok_or(PairingError::UnknownClient)?;
        let approval = ReplacementApproval {
            op_id: hex::encode(op_bytes),
            client_id: client_id.to_string(),
            client_name: client.name.clone(),
            current_identity_fingerprint: current_fingerprint.to_string(),
            replacement_identity_fingerprint: replacement,
            expires_at: now + ELEVATION_TTL_SECS,
            approved: false,
        };
        self.console_challenge(
            &mut inner,
            &approval.op_id,
            &replacement_confirmation_phrase(&approval),
            approval.expires_at,
        )?;
        inner
            .file
            .replacement_approvals
            .retain(|a| a.expires_at > now);
        inner.file.replacement_approvals.push(approval.clone());
        self.persist(&inner.file)?;
        Ok(approval)
    }

    /// Approve a pending replacement. **Owner CLI only.**
    pub fn approve_replacement(
        &self,
        op_id: &str,
        confirmation: &str,
    ) -> Result<ReplacementApproval, PairingError> {
        if !self.owner_control_enabled {
            return Err(PairingError::OwnerChannelUnavailable);
        }
        let now = chrono::Utc::now().timestamp();
        let mut inner = self.lock();
        let existing = inner
            .file
            .replacement_approvals
            .iter()
            .find(|a| a.op_id == op_id)
            .cloned()
            .ok_or(PairingError::UnknownOperation)?;
        if existing.expires_at <= now {
            inner
                .file
                .replacement_approvals
                .retain(|a| a.op_id != op_id);
            self.persist(&inner.file)?;
            return Err(PairingError::Expired);
        }
        Self::verify_owner_confirmation(&inner, op_id, confirmation)?;
        let approved = ReplacementApproval {
            approved: true,
            ..existing
        };
        inner
            .file
            .replacement_approvals
            .retain(|a| a.op_id != op_id);
        inner.file.replacement_approvals.push(approved.clone());
        self.persist(&inner.file)?;
        Ok(approved)
    }

    /// Read a pending replacement without consuming it (CLI rendering).
    pub fn replacement_approval(&self, op_id: &str) -> Option<ReplacementApproval> {
        self.lock()
            .file
            .replacement_approvals
            .iter()
            .find(|a| a.op_id == op_id)
            .cloned()
    }

    /// Consume an owner approval for a live-identity replacement.
    ///
    /// An atomic compare-and-delete under the one mutex that guards the durable
    /// file, so exactly one consumption can succeed. Every binding is checked
    /// at consumption time, including the expiry:
    ///
    /// - unknown or already-consumed `op_id` → refuse (replay protection)
    /// - approval belongs to another client → refuse, **without** consuming it
    /// - substituted current or replacement fingerprint → refuse, without consuming
    /// - not yet confirmed by the owner → refuse
    /// - expired → refuse
    ///
    /// A failed attempt deliberately leaves a still-valid approval in place: an
    /// attacker guessing wrong must not be able to burn the owner's approval.
    pub fn consume_replacement_approval(
        &self,
        op_id: &str,
        client_id: &str,
        current_fingerprint: &str,
        replacement_fingerprint: &str,
    ) -> Result<ReplacementApproval, PairingError> {
        if !self.owner_control_enabled {
            return Err(PairingError::OwnerChannelUnavailable);
        }
        let now = chrono::Utc::now().timestamp();
        let mut inner = self.lock();
        let idx = inner
            .file
            .replacement_approvals
            .iter()
            .position(|a| a.op_id == op_id)
            .ok_or(PairingError::UnknownOperation)?;

        {
            let a = &inner.file.replacement_approvals[idx];
            if a.expires_at <= now {
                inner.file.replacement_approvals.remove(idx);
                self.persist(&inner.file)?;
                return Err(PairingError::Expired);
            }
            if !a.approved {
                return Err(PairingError::NotApproved);
            }
            if a.client_id != client_id
                || a.current_identity_fingerprint != current_fingerprint
                || a.replacement_identity_fingerprint != replacement_fingerprint
            {
                return Err(PairingError::BindingMismatch);
            }
        }

        let consumed = inner.file.replacement_approvals.remove(idx);
        self.persist(&inner.file)?;
        Ok(consumed)
    }

    // ── Durable persistence ────────────────────────────────────────

    fn challenge_path(&self, pair_id: &str) -> PathBuf {
        self.dir.join(format!("challenge-{pair_id}"))
    }

    /// Replace the durable file atomically: write a temp file in the same
    /// directory, fsync it, then rename over the target. A reader never sees a
    /// half-written store, and a crash mid-write leaves the previous state.
    fn persist(&self, file: &PairingFile) -> Result<(), PairingError> {
        let bytes = serde_json::to_vec_pretty(file)
            .map_err(|e| PairingError::Io(format!("serializing pairing store: {e}")))?;
        let tmp = self.file_path.with_extension("json.tmp");
        write_protected(&tmp, &bytes)?;
        std::fs::rename(&tmp, &self.file_path)?;
        fsync_dir(&self.dir)?;
        Ok(())
    }
}

/// Status of a pending elevation, as reported to the requesting client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ElevationStatus {
    /// Created, awaiting the owner at the control socket.
    Pending,
    /// The owner wrote a grant.
    Granted,
    /// The request window closed without an owner confirmation.
    Expired,
    /// No such operation.
    Absent,
}

fn parse_pubkey(hex_key: &str) -> Result<ed25519_dalek::VerifyingKey, PairingError> {
    let raw = hex::decode(hex_key)
        .map_err(|e| PairingError::Malformed(format!("client key is not hex: {e}")))?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| PairingError::Malformed("client key must be 32 bytes".into()))?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|e| PairingError::Malformed(format!("invalid client key: {e}")))
}

/// Keep a client-supplied name short and printable: it is rendered to the owner
/// in the CLI approval summary, and a name carrying control characters could
/// misrepresent what is being approved.
fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect::<String>()
        .trim()
        .to_string();
    if cleaned.is_empty() {
        "unnamed client".to_string()
    } else {
        cleaned
    }
}

/// Write `bytes` to `path` at mode `0600`, fsyncing before returning.
///
/// The `0600` is the actual security control for the challenge file: the
/// ceremony rests on "the attacker cannot read `data_dir`".
pub fn write_protected(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    // `mode()` applies at creation only; an existing file keeps its old mode,
    // so set it explicitly as well.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Restrict a directory to the owner (`0700`).
pub fn restrict_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// fsync a directory so a rename into it is durable.
pub fn fsync_dir(path: &Path) -> io::Result<()> {
    let dir = std::fs::File::open(path)?;
    // Directory fsync is not supported on every platform/filesystem; the
    // rename itself is still atomic, so a failure here must not fail the
    // operation that already succeeded.
    let _ = dir.sync_all();
    Ok(())
}
