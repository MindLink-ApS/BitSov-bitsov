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
//! The short code is never printed or logged. An app that can read the
//! protected challenge file derives it locally; stdout contains only a safe
//! instruction naming that file. The code remains a cross-check rather than
//! the access control itself.
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
//!
//! The same rule governs grants that already exist on disk. A grant the owner
//! wrote while running the node with the control socket is **not honoured** by
//! a sidecar that later opens the same data directory: token issuance and
//! per-request binding verification both compute the effective scopes from the
//! deployment mode, so `spend` never reaches a sidecar token.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::auth::{self, Scope, TokenError};

pub mod device;
use crate::spend_budget::{
    BudgetRefusal, Charge, GrantBudget, GrantTerms, GrantView, Reservation,
    MAX_SPEND_GRANT_TTL_SECS,
};
pub use device::{
    device_confirmation_phrase, DeviceKey, DeviceKeyStatus, PendingDeviceKey, RelationIntent,
};

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
/// Bound durable pending proposals and owner-console prompts per paired client.
pub const MAX_PENDING_ELEVATIONS_PER_CLIENT: usize = 4;

/// Wrong confirmations per grant request. The last of them cancels it: the
/// request can no longer be approved and the app must ask again.
pub const OWNER_CODE_ATTEMPTS: u8 = 3;

/// Wrong grant confirmations one node run accepts in total, across every
/// request. Past it, the short owner code stops working until restart and only
/// the full `GRANT … CODE <nonce>` line approves. Bounds online guessing by a
/// process that can reach the control socket and create requests at will.
pub const OWNER_CODE_FAILURES_PER_RUN: u32 = 10;

/// Alphabet of the short owner code: no 0/O or 1/I, so it reads aloud and
/// types from a screen. 32 symbols, so a random byte maps without bias.
const OWNER_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

// A spend grant's lifetime is the owner's choice, capped at
// `spend_budget::MAX_SPEND_GRANT_TTL_SECS` (24 h). The 30-day unmetered grant
// this replaced was a durable admission object; see `crate::spend_budget`.

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

/// The only scopes an owner may grant to a pairing after the fact (policy lock B).
///
/// `spend` is an explicit per-pairing grant by the owner, not a per-message
/// confirmation: under "payment IS the connection" every message send is a
/// spend, so per-operation prompts would fire on every message and be unusable.
///
/// `front_door` lets the app publish the owner's front-door card and nothing
/// else. It is granted on its own (never together with `spend`), carries no
/// budget, and is kept in [`PairingFile::front_door_grants`] so no spend path
/// can ever mistake it for a spend grant.
///
/// `identity` is deliberately NOT grantable this way — replacing a live
/// identity is destructive and stays a per-operation approval. `credential`
/// is never grantable at all: a pairing that could mint credentials at least
/// as strong as its own would be the privilege escalation this ticket removes.
pub fn grantable_scopes() -> &'static [Scope] {
    &[Scope::Spend, Scope::FrontDoor]
}

/// Default window of a front-door grant when the owner names none: long enough
/// to publish and correct a card, short enough not to linger.
pub const DEFAULT_FRONT_DOOR_GRANT_TTL_SECS: i64 = 3600;

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
    /// A wrong owner code for a live grant request; attempts left before it
    /// is cancelled.
    #[error(
        "that is not the code the node showed for this request; {0} attempt(s) left before \
         the request is cancelled"
    )]
    WrongOwnerCode(u8),
    /// Nothing can approve this request any more: its owner code was lost to
    /// a restart, or wrong codes cancelled it.
    #[error(
        "this request can no longer be approved: the node restarted after it was made, or \
         too many wrong codes were typed. Nothing was granted. Ask again from the app; it \
         shows a new command"
    )]
    ConfirmationLost,
    /// Device-key registration and relation intents are off node-wide; the
    /// `&str` is the stable reason code (see [`device::SEED_NOT_ENCRYPTED`]).
    #[error("{}", device::device_approvals_off_message(.0))]
    DeviceApprovalsDisabled(&'static str),
    /// Short owner codes are off for this node run (too many wrong codes).
    #[error(
        "short approval codes are off until the node restarts (too many wrong codes were \
         typed). Type the full GRANT ... CODE line from the node's terminal instead"
    )]
    ShortCodesOff,
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
         run the node yourself and grant over <data_dir>/control.sock to obtain spend or \
         front_door."
    )]
    OwnerChannelUnavailable,
    /// No supported owner approval delivery channel is available.
    #[error("owner_approval_unavailable: start with --owner-control and provide an owner terminal or a writable owner-only pairing directory (identity replacement requires an owner terminal)")]
    OwnerApprovalUnavailable,
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
    /// Optional X25519 static public key used by remote-access Noise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_transport_pubkey: Option<String>,
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
    /// The meter. A grant without one (written by a pre-G1 node) is never
    /// honoured and is dropped when the store is opened. In memory, removing
    /// the meter also marks a revoked grant awaiting durable deletion.
    #[serde(default)]
    pub budget: Option<GrantBudget>,
}

impl SpendGrant {
    /// Whether this grant can authorise anything at `now`: metered, unexpired,
    /// and no longer-lived than the 24-hour cap (a hand-edited expiry is not
    /// an extension).
    pub fn is_live(&self, now: i64) -> bool {
        self.budget.is_some()
            && self.expires_at > now
            && self.expires_at - self.granted_at <= MAX_SPEND_GRANT_TTL_SECS
    }
}

/// An owner-written grant of `front_door` to one pairing (publish the node's
/// own front-door card). No budget: it moves no value. Otherwise bound exactly
/// like a [`SpendGrant`]: client, epoch, identity, a window of at most 24 h,
/// written only by the owner CLI, and revoked by every path that revokes
/// grants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontDoorGrant {
    /// The pending operation the owner confirmed.
    pub op_id: String,
    /// Client this grant is bound to. Not transferable.
    pub client_id: String,
    /// Unix seconds when the owner confirmed it.
    pub granted_at: i64,
    /// Unix seconds after which the grant is inert.
    pub expires_at: i64,
    /// Identity the grant was written against.
    pub identity_fingerprint: String,
    /// Pairing epoch at grant time.
    pub epoch: u64,
    /// Always `"cli"`.
    pub granted_by: String,
    /// Set on revocation, so the grant is inert at once even if the durable
    /// deletion has to be retried.
    #[serde(default)]
    pub revoked: bool,
}

impl FrontDoorGrant {
    /// Unrevoked, unexpired, and no longer-lived than the 24-hour cap.
    pub fn is_live(&self, now: i64) -> bool {
        !self.revoked
            && self.expires_at > now
            && self.expires_at - self.granted_at <= MAX_SPEND_GRANT_TTL_SECS
    }
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
    /// Budget the client proposed. Carries no authority: the owner sees it
    /// and may grant it, narrow it, or replace it at the control socket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_terms: Option<GrantTerms>,
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
    /// Owner-written `front_door` grants. Separate from `grants` so that no
    /// budget path can pick one up. Absent in files written before it existed.
    #[serde(default)]
    pub front_door_grants: Vec<FrontDoorGrant>,
    /// Pending elevation requests (no authority).
    pub pending_elevations: Vec<PendingElevation>,
    /// Pending / approved replacement approvals.
    pub replacement_approvals: Vec<ReplacementApproval>,
    /// Highest pairing epoch ever assigned per client id.
    ///
    /// Survives [`PairingService::revoke`] so a re-pair of the same key cannot
    /// recreate an earlier `(client_id, epoch)` and resurrect a revoked JWT.
    #[serde(default)]
    pub last_epoch: BTreeMap<String, u64>,
    /// Owner-approved device keys (see [`device`]).
    #[serde(default)]
    pub device_keys: Vec<DeviceKey>,
    /// Device keys awaiting the owner's one-time approval.
    #[serde(default)]
    pub pending_device_keys: Vec<PendingDeviceKey>,
    /// Registration op id → key id, so the client can read "registered".
    #[serde(default)]
    pub registered_ops: BTreeMap<String, String>,
    /// Used relation-intent nonces (`key_id:nonce` → client, issued_at), kept
    /// an hour for replay refusal and the per-client rate limit.
    #[serde(default)]
    pub intent_nonces: BTreeMap<String, (String, i64)>,
}

impl PairingFile {
    /// Revoke immediately without forgetting a deletion still owed to disk.
    /// A budgetless grant is inert even if the clock moves backwards. Persist
    /// prunes it from a candidate and only removes our record after success;
    /// failed writes leave it here for reads, sweeps and shutdown to retry.
    fn revoke_grants(&mut self, client_id: Option<&str>) -> usize {
        let mut revoked = 0;
        for grant in &mut self.grants {
            if client_id.is_none_or(|id| grant.client_id == id) {
                grant.budget = None;
                revoked += 1;
            }
        }
        for grant in &mut self.front_door_grants {
            if client_id.is_none_or(|id| grant.client_id == id) {
                grant.revoked = true;
                revoked += 1;
            }
        }
        revoked
    }

    /// Any grant, of either kind, that can no longer authorise anything.
    fn has_dead_grant(&self, now: i64) -> bool {
        self.grants.iter().any(|g| !g.is_live(now))
            || self.front_door_grants.iter().any(|g| !g.is_live(now))
    }

    fn retain_live_grants(&mut self, now: i64) {
        self.grants.retain(|g| g.is_live(now));
        self.front_door_grants.retain(|g| g.is_live(now));
    }
}

/// Current durable schema version.
///
/// 2 (G1): grants carry a budget. A pre-G1 node must refuse this file rather
/// than read a metered grant as an unmetered one.
///
/// 3 (device keys): device keys and relation grants. A version-2 node must not
/// read a relation grant as an unrestricted budget, so it refuses the file.
///
/// 4 (remote access): pairings may bind an X25519 transport public key.
pub const PAIRING_FILE_VERSION: u32 = 4;

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
    hosted_by: Option<String>,
    dir: PathBuf,
    file_path: PathBuf,
    box_transport_secret: zeroize::Zeroizing<[u8; 32]>,
    inner: Mutex<Inner>,
    grant_changes: tokio::sync::Notify,
    authority_changes: tokio::sync::watch::Sender<u64>,
    /// Whether the owner control socket exists in this deployment. Console
    /// grants and approvals require this independently of local device authority.
    owner_control_enabled: bool,
    /// Explicit live-start authority for device envelopes and signed delegation.
    local_owner_device: bool,
    /// Whether a safe protected-file instruction is written to stdout. The
    /// code/challenge itself is never printed.
    print_pairing_instruction: bool,
    owner_console: Mutex<Box<dyn std::io::Write + Send>>,
    /// Absolute config path of an owner-run node, for the owner command.
    owner_config: Option<PathBuf>,
    /// Public half of the seed-derived owner-approval key. Device keys are
    /// honoured only under its signature. Never read from `data_dir`.
    owner_approval_key: Option<ed25519_dalek::VerifyingKey>,
    /// Startup-only local delegation signer; its private material zeroizes on drop.
    owner_signing_key: Option<konsensus_core::OwnerApprovalKey>,
    /// Why device authority is off, if it is. Fail closed: off until startup
    /// supplies an owner key derived from a protected seed.
    device_authority_off: Option<&'static str>,
}

struct Inner {
    file: PairingFile,
    pending: HashMap<String, PendingPairing>,
    token_challenges: HashMap<String, (String, Instant)>,
    window_until: Option<Instant>,
    pairing_closed: bool,
    identity_fingerprint: String,
    // Never serialized or returned by HTTP/control status. Restart invalidates
    // pending console challenges; the owner must request a new operation.
    owner_confirmations: HashMap<String, OwnerConfirmation>,
    // Wrong grant confirmations in this run (see `OWNER_CODE_FAILURES_PER_RUN`).
    owner_code_failures: u32,
    // Requests cancelled by wrong codes in this run, so their status reads
    // `lost` (their durable records are deleted, so a restart cannot revive them).
    cancelled_ops: std::collections::HashMap<String, String>,
    // One-time first-contact confirmations, by client id. Memory only: never
    // serialized, dropped on restart (fail closed). See `FirstContactGrant`.
    first_contact: HashMap<String, PendingFirstContact>,
}

type ReservationJournal<'a> = Box<dyn FnOnce(&Reservation) -> Result<(), BudgetRefusal> + 'a>;

/// Authority constraints checked inside the same transaction as the debit.
#[derive(Default)]
struct ReservationAuthority<'a> {
    expected_op_id: Option<&'a str>,
    liquidity: bool,
    before_persist: Option<ReservationJournal<'a>>,
    operation: Option<crate::spend_budget::OperationReservationLink>,
}

/// Consumed, single-use authorization. Its grant identity survives the handoff
/// to reservation; neither replacement nor a different client can reuse it.
#[derive(Debug, PartialEq, Eq)]
pub struct FirstContactAuthorization {
    pub(crate) max_total_msat: u64,
    recipient: String,
    client_id: String,
    epoch: u64,
    budget_op_id: String,
    expires_at: i64,
}

/// A first-contact grant plus the budget grant it was issued under.
struct PendingFirstContact {
    grant: crate::spend_budget::FirstContactGrant,
    epoch: u64,
    budget_op_id: String,
    /// Retain one terminal observation per client; polling cannot revive it.
    consumed: bool,
}

/// Digests of what the owner channel delivered for one pending operation.
struct OwnerConfirmation {
    /// Digest of the full `<label> CODE <nonce>` line.
    phrase: blake3::Hash,
    /// Digest of the normalized short owner code; grant requests only.
    code: Option<blake3::Hash>,
    expires_at: i64,
    /// Wrong confirmations typed for this operation.
    failures: u8,
    /// Present only for a headless elevation; removed when consumed or expired.
    approval_file: Option<OwnerApprovalFile>,
}

/// Owns the lifetime of a headless code file. Never formats its contents.
struct OwnerApprovalFile(PathBuf);

impl Drop for OwnerApprovalFile {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.0) {
            if error.kind() != io::ErrorKind::NotFound {
                tracing::warn!(path = %self.0.display(), %error, "could not remove owner approval file");
            }
        }
    }
}

/// A fresh short owner code, `XXXX-XXXX`: 40 bits from the CSPRNG.
fn new_owner_code() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut out = String::with_capacity(9);
    for (i, b) in bytes.iter().enumerate() {
        if i == 4 {
            out.push('-');
        }
        out.push(OWNER_CODE_ALPHABET[(*b as usize) % OWNER_CODE_ALPHABET.len()] as char);
    }
    out
}

/// The owner's typing, as the code is compared: case, spaces and dashes are
/// not part of it.
fn normalize_owner_code(typed: &str) -> String {
    typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Invisible formatting characters that could hide or reorder what an owner
/// reads (bidi controls, zero-width characters, soft hyphen and the like).
fn invisible_format(c: char) -> bool {
    matches!(c, '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}'
        | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

/// `s` single-quoted for a shell only when it needs it. `None` when it holds a
/// character no owner should be asked to paste (control or invisible
/// formatting) or one that single quotes do not neutralize in every shell.
fn shell_word(s: &str) -> Option<String> {
    // A backslash or quote is refused, not escaped: `'\''` is POSIX-only, and
    // fish would read `\'` inside single quotes as the end of the string.
    if s.is_empty()
        || s.chars()
            .any(|c| c.is_control() || c == '\\' || c == '\'' || invisible_format(c))
    {
        return None;
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+:@%,=".contains(c))
    {
        return Some(s.to_string());
    }
    Some(format!("'{s}'"))
}

struct OwnerTerminal;

impl std::io::Write for OwnerTerminal {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            // A dedicated owner terminal, never tracing, stdout capture, or a
            // file under data_dir. The caller handles headless elevation delivery.
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
        // Old files cannot approve anything after restart. Remove them before
        // reissuing fresh codes, including after an unclean shutdown.
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("owner-approval-")
                && entry.file_type()?.is_file()
            {
                std::fs::remove_file(entry.path())?;
            }
        }
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

        // A crash before rename can leave grant data in the temporary file,
        // even when the authoritative file has no grants to prune. Never
        // promote that uncommitted transaction or retain its expired records.
        match std::fs::remove_file(file_path.with_extension("json.tmp")) {
            Ok(()) => fsync_dir(&dir)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }

        let box_transport_secret = load_box_transport_key(&dir)?;
        let (authority_changes, _) = tokio::sync::watch::channel(0);
        let service = Self {
            hosted_by: None,
            dir,
            file_path,
            box_transport_secret,
            inner: Mutex::new(Inner {
                file,
                pending: HashMap::new(),
                token_challenges: HashMap::new(),
                window_until: None,
                pairing_closed: false,
                identity_fingerprint,
                owner_confirmations: HashMap::new(),
                owner_code_failures: 0,
                cancelled_ops: std::collections::HashMap::new(),
                first_contact: HashMap::new(),
            }),
            grant_changes: tokio::sync::Notify::new(),
            authority_changes,
            owner_control_enabled,
            local_owner_device: false,
            print_pairing_instruction: true,
            owner_console: Mutex::new(Box::new(OwnerTerminal)),
            owner_config: None,
            owner_approval_key: None,
            owner_signing_key: None,
            device_authority_off: Some(device::OWNER_KEY_UNAVAILABLE),
        };
        // A grant that expired while the node was down, or an unmetered
        // pre-G1 grant, must not survive the restart on disk either.
        service.prune_expired_grants()?;
        Ok(service)
    }

    /// Seed-independent Noise responder secret. Never send or log these bytes.
    pub fn box_transport_secret_bytes(&self) -> &[u8; 32] {
        &self.box_transport_secret
    }

    /// Public half of the persistent box transport key, independent of identity.
    pub fn box_transport_pubkey(&self) -> [u8; 32] {
        let secret = x25519_dalek::StaticSecret::from(*self.box_transport_secret);
        x25519_dalek::PublicKey::from(&secret).to_bytes()
    }

    /// Enable device envelopes and delegation without enabling the owner console.
    pub fn with_local_owner_device(mut self) -> Self {
        self.local_owner_device = true;
        self
    }

    /// Whether this process explicitly enables local owner devices.
    pub fn local_owner_device(&self) -> bool {
        self.local_owner_device
    }

    /// Deployment gate shared by scopes, grant views, staging, reservation and dispatch.
    fn permits_spend_grant(&self, grant: &SpendGrant) -> bool {
        self.owner_control_enabled
            || (self.local_owner_device
                && self.owner_approval_key.is_some()
                && grant.granted_by.starts_with("device:")
                && grant
                    .budget
                    .as_ref()
                    .is_some_and(|budget| budget.recipients_only))
    }

    /// Supply a trusted owner-console transport (also used by disposable test
    /// fixtures). This is not a request field or a configuration override.
    pub fn with_owner_console(mut self, console: Box<dyn std::io::Write + Send>) -> Self {
        self.owner_console = Mutex::new(console);
        self
    }

    /// Deliver approval to the terminal, or a protected file for headless
    /// owner-confirmable operations, and remember digests of the delivered codes.
    ///
    /// Every operation gets the full `<label> CODE <nonce>` line. A grant
    /// request (`short_code`) also gets a short code the owner types into
    /// `konsensus grant`. Neither reaches HTTP, control socket replies, or
    /// stdout/stderr. Operations with an owner CLI command (elevations and
    /// device registration) allow file fallback; identity replacement remains
    /// terminal-only and refuses clearly when that delivery is unavailable.
    fn console_challenge(
        &self,
        inner: &mut Inner,
        op_id: &str,
        label: &str,
        expires_at: i64,
        command: Option<String>,
    ) -> Result<(), PairingError> {
        let short_code = command.is_some();
        if !self.owner_control_enabled {
            return Ok(());
        }
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let phrase = format!("{label} CODE {}", hex::encode(nonce));
        let codes_on = inner.owner_code_failures < OWNER_CODE_FAILURES_PER_RUN;
        let code = (short_code && codes_on).then(new_owner_code);
        let mut text = format!("\nOwner approval (expires {expires_at}):\n{phrase}\n");
        if let Some(code) = &code {
            text.push_str(&format!(
                "To approve, run: {}\n  and type this code when it asks: {code}\n",
                command.as_deref().unwrap_or_default()
            ));
        } else if let Some(command) = &command {
            text.push_str(&format!(
                "To approve, run: {command}\n  and paste the {} ... CODE line above (short codes \
                 are off until restart: too many wrong codes)\n",
                label.split(' ').next().unwrap_or("GRANT")
            ));
        }
        let delivered = self
            .owner_console
            .lock()
            .map_err(|_| io::Error::other("owner console unavailable"))
            .and_then(|mut console| {
                console.write_all(text.as_bytes())?;
                console.flush()
            });
        let approval_file = match delivered {
            Ok(()) => None,
            Err(_) if command.is_some() => {
                Some(self.write_owner_approval_file(op_id, expires_at, &text)?)
            }
            Err(_) => return Err(PairingError::OwnerApprovalUnavailable),
        };
        let now = chrono::Utc::now().timestamp();
        inner.owner_confirmations.retain(|_, c| c.expires_at > now);
        inner.owner_confirmations.insert(
            op_id.to_owned(),
            OwnerConfirmation {
                phrase: blake3::hash(phrase.as_bytes()),
                code: code.map(|c| blake3::hash(normalize_owner_code(&c).as_bytes())),
                expires_at,
                failures: 0,
                approval_file,
            },
        );
        Ok(())
    }

    fn write_owner_approval_file(
        &self,
        op_id: &str,
        expires_at: i64,
        text: &str,
    ) -> Result<OwnerApprovalFile, PairingError> {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let path = self.dir.join(format!("owner-approval-{op_id}"));
            // Exclusive creation never follows an existing symlink or writes
            // secrets into an existing file with permissive mode bits.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|_| PairingError::OwnerApprovalUnavailable)?;
            let protected = OwnerApprovalFile(path);
            file.write_all(text.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|_| PairingError::OwnerApprovalUnavailable)?;
            tracing::info!(path = %protected.0.display(), expires_at,
                "owner approval is in this owner-only file; read it privately, then approve over control.sock");
            Ok(protected)
        }
        #[cfg(not(unix))]
        {
            let _ = (op_id, expires_at, text);
            Err(PairingError::OwnerApprovalUnavailable)
        }
    }

    /// Cleanup runs on reads and the once-per-second grant sweeper. Revoked
    /// or rotated clients lose their pending file as well as their authority.
    fn prune_owner_confirmations(inner: &mut Inner) {
        let now = chrono::Utc::now().timestamp();
        inner.owner_confirmations.retain(|op_id, c| {
            c.expires_at > now
                && (c.approval_file.is_none()
                    || inner
                        .file
                        .pending_elevations
                        .iter()
                        .any(|op| &op.op_id == op_id)
                    || inner
                        .file
                        .pending_device_keys
                        .iter()
                        .any(|op| &op.op_id == op_id))
        });
    }

    /// The full console line only (identity replacement).
    fn verify_owner_confirmation(
        inner: &Inner,
        op_id: &str,
        confirmation: &str,
    ) -> Result<(), PairingError> {
        let valid = inner.owner_confirmations.get(op_id).is_some_and(|c| {
            c.expires_at > chrono::Utc::now().timestamp()
                && c.phrase == blake3::hash(confirmation.trim().as_bytes())
        });
        if valid {
            Ok(())
        } else {
            Err(PairingError::ConfirmationMismatch)
        }
    }

    /// A grant request: the short owner code or the full console line.
    ///
    /// Each wrong answer is counted against the request and the node run, and
    /// announced on the owner console. The request is cancelled after
    /// [`OWNER_CODE_ATTEMPTS`]; past [`OWNER_CODE_FAILURES_PER_RUN`] the short
    /// code no longer approves anything in this run. A request made before a
    /// restart has nothing to compare against and is [`PairingError::ConfirmationLost`].
    fn verify_grant_confirmation(
        &self,
        inner: &mut Inner,
        label: &str,
        op_id: &str,
        confirmation: &str,
    ) -> Result<(), PairingError> {
        let now = chrono::Utc::now().timestamp();
        let codes_enabled = inner.owner_code_failures < OWNER_CODE_FAILURES_PER_RUN;
        let Some(expected) = inner
            .owner_confirmations
            .get_mut(op_id)
            .filter(|c| c.expires_at > now)
        else {
            return Err(PairingError::ConfirmationLost);
        };
        let typed = confirmation.trim();
        let phrase_ok = expected.phrase == blake3::hash(typed.as_bytes());
        let code_ok = codes_enabled
            && expected
                .code
                .is_some_and(|d| d == blake3::hash(normalize_owner_code(typed).as_bytes()));
        if phrase_ok || code_ok {
            return Ok(());
        }
        expected.failures = expected.failures.saturating_add(1);
        let left = OWNER_CODE_ATTEMPTS.saturating_sub(expected.failures);
        inner.owner_code_failures = inner.owner_code_failures.saturating_add(1);
        let mut warning = format!(
            "\nWRONG approval code for {label}. If you did not just type it, something on this \
             computer is trying to approve this request.\n"
        );
        if left == 0 {
            inner.owner_confirmations.remove(op_id);
            // Cancel durably: a restart must not re-issue a code for a request
            // someone was guessing at.
            let client_id = inner
                .file
                .pending_elevations
                .iter()
                .find(|e| e.op_id == op_id)
                .map(|e| e.client_id.clone())
                .or_else(|| {
                    inner
                        .file
                        .pending_device_keys
                        .iter()
                        .find(|p| p.op_id == op_id)
                        .map(|p| p.client_id.clone())
                });
            inner.file.pending_elevations.retain(|e| e.op_id != op_id);
            inner.file.pending_device_keys.retain(|p| p.op_id != op_id);
            if let Some(client_id) = client_id {
                inner.cancelled_ops.insert(op_id.to_string(), client_id);
            }
            if let Err(e) = self.persist(&mut inner.file) {
                tracing::warn!(error = %e, op_id, "could not persist a cancelled approval");
            }
            warning.push_str("That request is cancelled; nothing was granted.\n");
        }
        if inner.owner_code_failures == OWNER_CODE_FAILURES_PER_RUN {
            warning.push_str(
                "Too many wrong codes: short codes are off until the node restarts. Approve with \
                 the full GRANT ... CODE line instead.\n",
            );
        }
        if let Ok(mut console) = self.owner_console.lock() {
            let _ = console.write_all(warning.as_bytes());
            let _ = console.flush();
        }
        if left == 0 {
            Err(PairingError::ConfirmationLost)
        } else if !codes_enabled {
            Err(PairingError::ShortCodesOff)
        } else {
            Err(PairingError::WrongOwnerCode(left))
        }
    }

    /// Whether the owner console still holds a live confirmation for `op_id`.
    /// False for a request made before this node run, or cancelled by wrong
    /// codes: nothing can approve it any more.
    pub fn elevation_confirmable(&self, op_id: &str) -> bool {
        let inner = self.lock();
        Self::confirmable(&inner, op_id)
    }

    fn confirmable(inner: &Inner, op_id: &str) -> bool {
        let now = chrono::Utc::now().timestamp();
        inner
            .owner_confirmations
            .get(op_id)
            .is_some_and(|c| c.expires_at > now)
    }

    /// The owner-approval public key, derived from the running identity's
    /// seed (`NodeIdentity::owner_approval_public`).
    pub fn with_owner_approval_key(mut self, key: ed25519_dalek::VerifyingKey) -> Self {
        self.owner_signing_key = None;
        self.owner_approval_key = Some(key);
        self.device_authority_off = None;
        self
    }

    /// Retain the seed-derived signing key only for explicitly enabled local
    /// delegation. No key material is serialized into pairing state.
    pub fn with_owner_signing_key(mut self, key: konsensus_core::OwnerApprovalKey) -> Self {
        self.owner_approval_key = Some(key.verifying_key());
        self.device_authority_off = None;
        self.owner_signing_key = self.local_owner_device.then_some(key);
        self
    }

    /// Turn device-key registration and relation intents off node-wide, with
    /// the reason the app shows (e.g. [`device::SEED_NOT_ENCRYPTED`]).
    pub fn with_device_authority_disabled(mut self, reason: &'static str) -> Self {
        self.owner_approval_key = None;
        self.owner_signing_key = None;
        self.device_authority_off = Some(reason);
        self
    }

    /// `None` when device approvals are on, else the reason code.
    pub fn device_authority_off(&self) -> Option<&'static str> {
        self.device_authority_off
    }

    /// Record the absolute config path this node was started with, so the
    /// owner command it states names it. Owner-run startup only.
    pub fn with_owner_config(mut self, config_path: PathBuf) -> Self {
        self.owner_config = Some(config_path);
        self
    }

    /// The command that approves `op_id`, as the app and the owner console
    /// show it: `konsensus grant --op <id> --config <absolute path>`. The path
    /// is left out when unknown or unsafe to show.
    pub fn owner_grant_command(&self, op_id: &str) -> String {
        self.owner_command("grant", op_id)
    }

    /// `konsensus device approve --op <id> --config <path>`, likewise.
    pub fn owner_device_command(&self, op_id: &str) -> String {
        self.owner_command("device approve", op_id)
    }

    fn owner_command(&self, verb: &str, op_id: &str) -> String {
        let config = self
            .owner_config
            .as_deref()
            .and_then(|p| p.to_str())
            .and_then(shell_word);
        match config {
            Some(path) => format!("konsensus {verb} --op {op_id} --config {path}"),
            None => format!("konsensus {verb} --op {op_id}"),
        }
    }

    /// Test/bootstrap helper: suppress the safe stdout pairing instruction.
    pub fn without_stdout_code(mut self) -> Self {
        self.print_pairing_instruction = false;
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
        let inner = self.lock();
        let mut snapshot = inner.file.clone();
        // Cleanup failures stay retryable internally, never visible as grants.
        snapshot.retain_live_grants(chrono::Utc::now().timestamp());
        snapshot
    }

    /// Re-read the durable state from disk. Used by tests and by the CLI to
    /// assert effects rather than trust an in-memory copy.
    pub fn reload_from_disk(&self) -> Result<PairingFile, PairingError> {
        let mut inner = self.lock_without_cleanup();
        Self::prune_owner_confirmations(&mut inner);
        self.prune_expired_locked(&mut inner.file)?;
        if !self.file_path.exists() {
            return Ok(PairingFile {
                version: PAIRING_FILE_VERSION,
                ..PairingFile::default()
            });
        }
        let raw = std::fs::read(&self.file_path)?;
        let mut file: PairingFile =
            serde_json::from_slice(&raw).map_err(|e| PairingError::Io(e.to_string()))?;
        // Reading/parsing can itself cross the deadline. Do not return stale
        // records or merely hide them while retaining the raw file.
        self.prune_expired_locked(&mut file)?;
        Ok(file)
    }

    /// The identity this service currently binds pairings to.
    pub fn bound_fingerprint(&self) -> String {
        self.lock().identity_fingerprint.clone()
    }

    /// Subscribe to pairing-authority changes that can invalidate a live
    /// remote-access tunnel. Receivers must revalidate their exact captured
    /// authority after every notification.
    pub fn subscribe_authority_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.authority_changes.subscribe()
    }

    fn notify_authority_change(&self) {
        self.authority_changes
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    /// Cosmetic box label, never an authority or custody input.
    pub fn with_hosted_by(mut self, hosted_by: Option<String>) -> Self {
        self.hosted_by = hosted_by;
        self
    }

    pub fn hosted_by(&self) -> Option<&str> {
        self.hosted_by.as_deref()
    }

    pub fn remote_access_link_path(&self) -> PathBuf {
        self.dir.join("remote-access-link")
    }

    /// Store the one-shot remote pairing link under the protected pairing
    /// directory. The link is intentionally never returned by an HTTP route or
    /// written to stdout/journald.
    pub fn write_remote_access_link(&self, link: &str) -> Result<PathBuf, PairingError> {
        let path = self.dir.join("remote-access-link");
        let temporary = self
            .dir
            .join(format!(".remote-access-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> io::Result<()> {
            write_protected(&temporary, link.as_bytes())?;
            std::fs::rename(&temporary, &path)?;
            fsync_dir_strict(&self.dir)
        })();
        let _ = std::fs::remove_file(temporary);
        result?;
        Ok(path)
    }

    /// Remove any live or stale remote pairing link.
    pub fn remove_remote_access_link(&self) -> Result<(), PairingError> {
        let path = self.dir.join("remote-access-link");
        match std::fs::remove_file(path) {
            Ok(()) => fsync_dir_strict(&self.dir)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        let mut inner = self.lock_without_cleanup();
        Self::prune_owner_confirmations(&mut inner);
        // Reads are also cleanup boundaries, including auth and owner status.
        // Keep failed deletions in the private state so the next access retries.
        if let Err(e) = self.prune_expired_locked(&mut inner.file) {
            tracing::warn!(error = %e, "expired spend grant cleanup failed");
        }
        inner
    }

    fn lock_without_cleanup(&self) -> std::sync::MutexGuard<'_, Inner> {
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

    /// Permanently disable all first-pairing ceremonies for this locked run.
    pub fn with_pairing_closed(self) -> Self {
        self.lock().pairing_closed = true;
        self
    }

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
        if inner.pairing_closed {
            return false;
        }
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
        if self.print_pairing_instruction {
            println!(
                "Pairing request {} is available at protected file {} (expires at {}).",
                pair_id,
                self.challenge_path(&pair_id).display(),
                expires_at_unix
            );
            tracing::info!(pair_id = %pair_id, "pairing requested; protected challenge file written");
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
        // Enforce under the final insertion lock: a pending ceremony may already
        // have been removed from the map before `rebind_to_identity` runs, so
        // clearing pending alone cannot close the race. Identity authority is
        // bootstrap-only — refuse it once an identity fingerprint is bound.
        if scopes.contains(&Scope::Identity) && !inner.identity_fingerprint.is_empty() {
            return Err(PairingError::Closed);
        }
        let fingerprint = inner.identity_fingerprint.clone();
        let epoch = {
            let prior = inner
                .file
                .clients
                .iter()
                .find(|c| c.client_id == client_id)
                .map(|c| c.epoch)
                .unwrap_or(0);
            let entry = inner.file.last_epoch.entry(client_id.clone()).or_insert(0);
            *entry = (*entry).max(prior);
            *entry = entry.checked_add(1).ok_or(PairingError::Closed)?;
            *entry
        };
        let record = PairedClient {
            client_id: client_id.clone(),
            name: pending.name.clone(),
            client_pubkey: pending.client_pubkey.clone(),
            remote_transport_pubkey: None,
            scopes,
            epoch,
            identity_fingerprint: fingerprint,
            created_at: now,
            last_seen: None,
        };
        inner.file.clients.retain(|c| c.client_id != client_id);
        inner.file.clients.push(record.clone());
        self.persist(&mut inner.file)?;
        self.notify_authority_change();
        Ok(record)
    }

    /// Atomically create a normal read+receive pairing after the remote
    /// listener has verified its memory-only code and Ed25519 proof.
    pub fn create_verified_remote_pairing(
        &self,
        name: &str,
        client_pubkey_hex: &str,
        remote_transport_pubkey: &[u8; 32],
    ) -> Result<PairedClient, PairingError> {
        self.create_remote_pairing(name, client_pubkey_hex, remote_transport_pubkey, true)
    }

    /// Same pairing, authorized by a consumed one-shot enrollment ticket from
    /// the protected `remote-access-link` file. The ticket is its own grant:
    /// it neither needs nor opens the local `/pair/request` window.
    pub fn create_ticket_remote_pairing(
        &self,
        name: &str,
        client_pubkey_hex: &str,
        remote_transport_pubkey: &[u8; 32],
    ) -> Result<PairedClient, PairingError> {
        self.create_remote_pairing(name, client_pubkey_hex, remote_transport_pubkey, false)
    }

    /// First-run pairing authorized by a consumed pre-bootstrap ticket over the
    /// box-static tunnel. It carries [`bootstrap_pairing_scopes`] only while no
    /// identity is bound and no other client exists; the transition commit
    /// strips `identity` exactly as it does for a loopback bootstrap pairing.
    pub fn create_bootstrap_ticket_pairing(
        &self,
        name: &str,
        client_pubkey_hex: &str,
        remote_transport_pubkey: &[u8; 32],
    ) -> Result<PairedClient, PairingError> {
        let normalized_pubkey = client_pubkey_hex.to_ascii_lowercase();
        parse_pubkey(&normalized_pubkey)?;
        let client_id = client_id_from_pubkey(&normalized_pubkey);
        let mut inner = self.lock();
        if inner.pairing_closed
            || !inner.identity_fingerprint.is_empty()
            || !inner.file.clients.is_empty()
        {
            return Err(PairingError::Closed);
        }
        let previous = inner.file.clone();
        let epoch = {
            let entry = inner.file.last_epoch.entry(client_id.clone()).or_insert(0);
            *entry = entry.checked_add(1).ok_or(PairingError::Closed)?;
            *entry
        };
        let record = PairedClient {
            client_id,
            name: sanitize_name(name),
            client_pubkey: normalized_pubkey,
            remote_transport_pubkey: Some(hex::encode(remote_transport_pubkey)),
            scopes: bootstrap_pairing_scopes(),
            epoch,
            identity_fingerprint: String::new(),
            created_at: chrono::Utc::now().timestamp(),
            last_seen: None,
        };
        inner.file.clients.push(record.clone());
        if let Err(error) = self.persist(&mut inner.file) {
            inner.file = previous;
            return Err(error);
        }
        self.notify_authority_change();
        Ok(record)
    }

    fn create_remote_pairing(
        &self,
        name: &str,
        client_pubkey_hex: &str,
        remote_transport_pubkey: &[u8; 32],
        require_window: bool,
    ) -> Result<PairedClient, PairingError> {
        let normalized_pubkey = client_pubkey_hex.to_ascii_lowercase();
        parse_pubkey(&normalized_pubkey)?;
        let remote_hex = hex::encode(remote_transport_pubkey);
        let client_id = client_id_from_pubkey(&normalized_pubkey);
        let now = chrono::Utc::now().timestamp();

        let mut inner = self.lock();
        let open = if require_window {
            Self::open_inner(&inner)
        } else {
            !inner.pairing_closed
        };
        if !open {
            return Err(PairingError::Closed);
        }
        if inner.file.clients.iter().any(|client| {
            client.remote_transport_pubkey.as_deref() == Some(remote_hex.as_str())
                && client.client_id != client_id
        }) {
            return Err(PairingError::Closed);
        }
        let fingerprint = inner.identity_fingerprint.clone();
        if fingerprint.is_empty() {
            return Err(PairingError::PairingInvalid(
                "remote access requires a live node identity".into(),
            ));
        }
        if let Some(index) = inner
            .file
            .clients
            .iter()
            .position(|client| client.client_id == client_id)
        {
            let existing = &inner.file.clients[index];
            if existing.identity_fingerprint != fingerprint {
                return Err(PairingError::PairingInvalid(
                    "identity fingerprint changed".into(),
                ));
            }
            match existing.remote_transport_pubkey.as_deref() {
                Some(bound) if bound == remote_hex => return Ok(existing.clone()),
                Some(_) => return Err(PairingError::Closed),
                None => {}
            }
            let previous = inner.file.clone();
            inner.file.clients[index].remote_transport_pubkey = Some(remote_hex);
            let record = inner.file.clients[index].clone();
            if let Err(error) = self.persist(&mut inner.file) {
                inner.file = previous;
                return Err(error);
            }
            self.notify_authority_change();
            return Ok(record);
        }
        let previous = inner.file.clone();
        let epoch = {
            let entry = inner.file.last_epoch.entry(client_id.clone()).or_insert(0);
            *entry = entry.checked_add(1).ok_or(PairingError::Closed)?;
            *entry
        };
        let record = PairedClient {
            client_id: client_id.clone(),
            name: sanitize_name(name),
            client_pubkey: normalized_pubkey,
            remote_transport_pubkey: Some(remote_hex),
            scopes: vec![Scope::Read, Scope::Receive],
            epoch,
            identity_fingerprint: fingerprint,
            created_at: now,
            last_seen: None,
        };
        inner.file.clients.push(record.clone());
        if let Err(error) = self.persist(&mut inner.file) {
            inner.file = previous;
            return Err(error);
        }
        self.notify_authority_change();
        Ok(record)
    }

    /// Resolve a live pairing by the X25519 static authenticated by Noise_XX.
    pub fn validate_remote_transport(
        &self,
        remote_transport_pubkey: &[u8; 32],
    ) -> Result<PairedClient, PairingError> {
        let remote_hex = hex::encode(remote_transport_pubkey);
        let inner = self.lock();
        let record = inner
            .file
            .clients
            .iter()
            .find(|client| client.remote_transport_pubkey.as_deref() == Some(remote_hex.as_str()))
            .cloned()
            .ok_or(PairingError::UnknownClient)?;
        if record.identity_fingerprint != inner.identity_fingerprint {
            return Err(PairingError::PairingInvalid(
                "identity fingerprint changed".into(),
            ));
        }
        Ok(record)
    }

    /// Revalidate the exact authority captured when a remote tunnel
    /// authenticated. Matching only the transport key is insufficient: an old
    /// tunnel must not become valid again after revocation and re-pairing.
    pub fn validate_remote_authority(
        &self,
        client_id: &str,
        epoch: u64,
        remote_transport_pubkey: &[u8; 32],
        identity_fingerprint: &str,
    ) -> Result<(), PairingError> {
        let remote_hex = hex::encode(remote_transport_pubkey);
        let inner = self.lock();
        let record = inner
            .file
            .clients
            .iter()
            .find(|client| client.client_id == client_id)
            .ok_or(PairingError::UnknownClient)?;
        if record.epoch != epoch
            || record.remote_transport_pubkey.as_deref() != Some(remote_hex.as_str())
            || record.identity_fingerprint != identity_fingerprint
            || inner.identity_fingerprint != identity_fingerprint
        {
            return Err(PairingError::PairingInvalid(
                "remote tunnel authority changed".into(),
            ));
        }
        Ok(())
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

        let mut inner = self.lock();
        let now_unix = chrono::Utc::now().timestamp();

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

        let scopes = self.effective_scopes(&inner, &record, now_unix);

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
        self.persist(&mut inner.file)?;

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
        let inner = self.lock();
        let now_unix = chrono::Utc::now().timestamp();
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
        let permitted = self.effective_scopes(&inner, record, now_unix);
        if let Some(extra) = scopes.iter().find(|s| !permitted.contains(s)) {
            return Err(PairingError::PairingInvalid(format!(
                "token claims scope `{}` the pairing does not hold in this deployment",
                extra.as_str()
            )));
        }
        Ok(())
    }

    /// Identify the exact live spend grant for volatile staged-file ownership.
    /// Binding and grant are checked under the same lock as revoke/replacement;
    /// a new grant for the same client must not inherit the old grant's bytes.
    pub(crate) fn live_spend_grant_id(&self, binding: &auth::PairingBinding) -> Option<String> {
        let inner = self.lock();
        if inner.identity_fingerprint != binding.fingerprint
            || !inner.file.clients.iter().any(|client| {
                client.client_id == binding.client_id
                    && client.epoch == binding.epoch
                    && client.identity_fingerprint == binding.fingerprint
            })
        {
            return None;
        }
        let now = chrono::Utc::now().timestamp();
        inner
            .file
            .grants
            .iter()
            .find(|grant| {
                self.permits_spend_grant(grant)
                    && grant.client_id == binding.client_id
                    && grant.epoch == binding.epoch
                    && grant.identity_fingerprint == binding.fingerprint
                    && grant.scopes.contains(&Scope::Spend)
                    && grant.is_live(now)
            })
            .map(|grant| grant.op_id.clone())
    }

    /// The scopes a pairing actually carries **in this deployment**, computed
    /// identically at issuance and at per-request verification.
    ///
    /// Console grants require owner control. A local owner device start can
    /// honour only device-granted, recipient-only spend budgets. Grantable
    /// scopes embedded in a base pairing record never widen sidecar authority.
    fn effective_scopes(&self, inner: &Inner, record: &PairedClient, now_unix: i64) -> Vec<Scope> {
        let mut scopes = record.scopes.clone();
        if !self.owner_control_enabled {
            scopes.retain(|s| !grantable_scopes().contains(s));
        }
        for grant in &inner.file.grants {
            if grant.client_id == record.client_id
                && grant.is_live(now_unix)
                && grant.epoch == record.epoch
                && grant.identity_fingerprint == inner.identity_fingerprint
            {
                for s in &grant.scopes {
                    if !scopes.contains(s)
                        && (self.owner_control_enabled
                            || (*s == Scope::Spend && self.permits_spend_grant(grant)))
                    {
                        scopes.push(*s);
                    }
                }
            }
        }
        let front_door = self.owner_control_enabled
            && inner.file.front_door_grants.iter().any(|g| {
                g.client_id == record.client_id
                    && g.is_live(now_unix)
                    && g.epoch == record.epoch
                    && g.identity_fingerprint == inner.identity_fingerprint
            });
        if front_door && !scopes.contains(&Scope::FrontDoor) {
            scopes.push(Scope::FrontDoor);
        }
        scopes
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
        inner.file.last_epoch.insert(client_id.to_string(), epoch);
        // A grant is pinned to the epoch it was written against, so a
        // revocation drops the elevation with it rather than leaving a stale
        // `spend` waiting for the next pairing of the same key.
        inner.file.revoke_grants(Some(client_id));
        self.persist(&mut inner.file)?;
        self.notify_authority_change();
        Ok(epoch)
    }

    /// Remove a pairing entirely (and any grant bound to it).
    pub fn revoke(&self, client_id: &str) -> Result<(), PairingError> {
        let mut inner = self.lock();
        let Some(existing) = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == client_id)
            .cloned()
        else {
            return Err(PairingError::UnknownClient);
        };
        // Retain the generation across deletion so a later re-pair cannot
        // recreate the revoked `(client_id, epoch)` binding.
        let tracked = inner
            .file
            .last_epoch
            .entry(client_id.to_string())
            .or_insert(0);
        *tracked = (*tracked).max(existing.epoch);
        inner.file.clients.retain(|c| c.client_id != client_id);
        inner.file.revoke_grants(Some(client_id));
        inner
            .file
            .pending_elevations
            .retain(|e| e.client_id != client_id);
        inner
            .file
            .replacement_approvals
            .retain(|a| a.client_id != client_id);
        inner.file.device_keys.retain(|k| k.client_id != client_id);
        inner
            .file
            .pending_device_keys
            .retain(|p| p.client_id != client_id);
        let keys: Vec<String> = inner
            .file
            .device_keys
            .iter()
            .map(|k| k.key_id.clone())
            .collect();
        inner.file.registered_ops.retain(|_, k| keys.contains(k));
        self.persist(&mut inner.file)?;
        self.notify_authority_change();
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
        // Allocate above the source epoch *and* any destination history or
        // live record. `old.epoch + 1` alone can recreate a revoked destination
        // binding, or overwrite a higher last_epoch when rotating away later.
        let destination_last = inner.file.last_epoch.get(&new_id).copied().unwrap_or(0);
        let destination_current = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == new_id)
            .map(|c| c.epoch)
            .unwrap_or(0);
        let rotated_epoch = old
            .epoch
            .max(destination_last)
            .max(destination_current)
            .checked_add(1)
            .ok_or(PairingError::Closed)?;
        let rotated = PairedClient {
            client_id: new_id.clone(),
            client_pubkey: new_pubkey_hex.to_ascii_lowercase(),
            // Rotating the Ed25519 pairing identity does not authenticate a
            // replacement Noise static. Retire the old transport binding.
            remote_transport_pubkey: None,
            // The epoch advances on rotation: tokens minted for the old key
            // must stop working the moment the key they prove is retired.
            epoch: rotated_epoch,
            ..old.clone()
        };
        // Never decrease either historical record.
        let source_tracked = inner
            .file
            .last_epoch
            .entry(client_id.to_string())
            .or_insert(0);
        *source_tracked = (*source_tracked).max(old.epoch);
        let new_tracked = inner.file.last_epoch.entry(new_id.clone()).or_insert(0);
        *new_tracked = (*new_tracked).max(rotated_epoch);
        inner
            .file
            .clients
            .retain(|c| c.client_id != client_id && c.client_id != new_id);
        inner.file.clients.push(rotated.clone());
        // Device keys were registered to the old pairing id; retire them so the
        // same device can register again under the rotated one.
        inner.file.device_keys.retain(|k| k.client_id != client_id);
        inner
            .file
            .pending_device_keys
            .retain(|p| p.client_id != client_id);
        // Grants do not survive a key rotation: they were written against a
        // specific client id and epoch by a deliberate owner action.
        inner.file.revoke_grants(Some(client_id));
        self.persist(&mut inner.file)?;
        self.notify_authority_change();
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
        // Nothing pending from bootstrap carries into the live node. Pending
        // ceremonies are also cleared, but that alone is not the identity
        // authority gate — see the final-lock check in `confirm_pairing`.
        inner.pending.clear();
        inner.file.revoke_grants(None);
        inner.file.pending_elevations.clear();
        inner.file.replacement_approvals.clear();
        // Device keys signed for the old identity's pairings; start over.
        inner.file.device_keys.clear();
        inner.file.pending_device_keys.clear();
        inner.file.registered_ops.clear();
        inner.owner_confirmations.clear();
        self.persist(&mut inner.file)?;
        self.notify_authority_change();
        Ok(())
    }

    // ── Elevation: HTTP may request, only the CLI may confirm ───────

    /// Create a pending elevation request. Writes **no** authority.
    pub fn create_elevation_request(
        &self,
        client_id: &str,
        scopes: Vec<Scope>,
    ) -> Result<PendingElevation, PairingError> {
        self.create_budget_elevation_request(client_id, scopes, None)
    }

    /// Create a pending elevation request carrying the budget the client
    /// proposes. Writes **no** authority: the proposal is shown to the owner,
    /// who decides the terms at the control socket.
    pub fn create_budget_elevation_request(
        &self,
        client_id: &str,
        scopes: Vec<Scope>,
        proposed_terms: Option<GrantTerms>,
    ) -> Result<PendingElevation, PairingError> {
        let proposed_terms = proposed_terms
            .map(GrantTerms::normalized)
            .transpose()
            .map_err(PairingError::Malformed)?;
        if scopes.is_empty() {
            return Err(PairingError::NotGrantable("no scopes requested".into()));
        }
        if let Some(bad) = scopes.iter().find(|s| !grantable_scopes().contains(s)) {
            return Err(PairingError::NotGrantable(bad.as_str().to_string()));
        }
        // `front_door` is asked for alone and carries no budget: one request,
        // one kind of authority, rendered to the owner as exactly that.
        if scopes.contains(&Scope::FrontDoor) {
            if scopes.iter().any(|s| *s != Scope::FrontDoor) {
                return Err(PairingError::NotGrantable(
                    "front_door is requested on its own, never together with another scope".into(),
                ));
            }
            if proposed_terms.is_some() {
                return Err(PairingError::Malformed(
                    "a front_door request carries no budget".into(),
                ));
            }
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
        if !self.owner_control_enabled {
            return Err(PairingError::OwnerApprovalUnavailable);
        }
        // Hold the same lock through check and insertion so concurrent requests
        // cannot exceed the cap. Expired proposals do not consume a slot.
        if inner
            .file
            .pending_elevations
            .iter()
            .filter(|e| e.client_id == client_id && e.expires_at > now)
            .count()
            >= MAX_PENDING_ELEVATIONS_PER_CLIENT
        {
            return Err(PairingError::TooManyPending);
        }
        let op = PendingElevation {
            op_id: hex::encode(op_bytes),
            client_id: client_id.to_string(),
            client_name: client.name.clone(),
            scopes,
            created_at: now,
            expires_at: now + ELEVATION_TTL_SECS,
            proposed_terms,
        };
        self.console_challenge(
            &mut inner,
            &op.op_id,
            &grant_confirmation_phrase(&op),
            op.expires_at,
            Some(self.owner_grant_command(&op.op_id)),
        )?;
        inner.file.pending_elevations.retain(|e| e.expires_at > now);
        inner.file.pending_elevations.push(op.clone());
        if let Err(error) = self.persist(&mut inner.file) {
            inner
                .file
                .pending_elevations
                .retain(|e| e.op_id != op.op_id);
            inner.owner_confirmations.remove(&op.op_id);
            return Err(error);
        }
        Ok(op)
    }

    /// Read this client's elevation status. Other clients and unknown IDs receive
    /// the same UnknownOperation refusal. A read, never a consumption.
    ///
    /// On a sidecar a grant is never in effect (see `effective_scopes`), so it
    /// is never reported as granted either: the status must not claim an
    /// authority the token will not carry.
    pub fn elevation_status(
        &self,
        client_id: &str,
        op_id: &str,
    ) -> Result<ElevationStatus, PairingError> {
        let inner = self.lock();
        let owned = inner
            .file
            .pending_elevations
            .iter()
            .any(|e| e.op_id == op_id && e.client_id == client_id)
            || inner
                .file
                .grants
                .iter()
                .any(|g| g.op_id == op_id && g.client_id == client_id)
            || inner
                .file
                .front_door_grants
                .iter()
                .any(|g| g.op_id == op_id && g.client_id == client_id)
            || inner
                .cancelled_ops
                .get(op_id)
                .is_some_and(|owner| owner == client_id);
        if !owned {
            return Err(PairingError::UnknownOperation);
        }
        let now = chrono::Utc::now().timestamp();
        if !self.owner_control_enabled {
            return Ok(
                match inner
                    .file
                    .pending_elevations
                    .iter()
                    .find(|e| e.op_id == op_id)
                {
                    Some(op) if op.expires_at <= now => ElevationStatus::Expired,
                    Some(_) => ElevationStatus::Pending,
                    None => ElevationStatus::Absent,
                },
            );
        }
        if let Some(op) = inner
            .file
            .pending_elevations
            .iter()
            .find(|e| e.op_id == op_id)
        {
            if op.expires_at <= now {
                return Ok(ElevationStatus::Expired);
            }
            let granted = if op.scopes.contains(&Scope::FrontDoor) {
                inner
                    .file
                    .front_door_grants
                    .iter()
                    .any(|g| g.client_id == op.client_id && g.is_live(now))
            } else {
                inner
                    .file
                    .grants
                    .iter()
                    .any(|g| g.client_id == op.client_id && g.is_live(now))
            };
            if granted {
                return Ok(ElevationStatus::Granted);
            }
            if !Self::confirmable(&inner, op_id) {
                return Ok(ElevationStatus::Lost);
            }
            return Ok(ElevationStatus::Pending);
        }
        // The pending record is consumed when the owner writes the grant, so a
        // granted operation is found by the `op_id` recorded on the grant.
        if inner
            .file
            .grants
            .iter()
            .any(|g| g.op_id == op_id && g.is_live(now))
            || inner
                .file
                .front_door_grants
                .iter()
                .any(|g| g.op_id == op_id && g.is_live(now))
        {
            return Ok(ElevationStatus::Granted);
        }
        if inner.cancelled_ops.contains_key(op_id) {
            return Ok(ElevationStatus::Lost);
        }
        Ok(ElevationStatus::Absent)
    }

    /// Write a budget-scoped spend grant. **Owner CLI only.**
    ///
    /// Requires the operation-bound confirmation from the owner terminal or
    /// protected headless file. The public operation label is insufficient. `terms` are
    /// the owner's, not the client's proposal: they bound the budget, the
    /// per-call maximum, per-recipient budgets and the window (≤ 24 h).
    pub fn grant_elevation(
        &self,
        op_id: &str,
        confirmation: &str,
        terms: GrantTerms,
    ) -> Result<SpendGrant, PairingError> {
        if !self.owner_control_enabled {
            return Err(PairingError::OwnerChannelUnavailable);
        }
        let terms = terms.normalized().map_err(PairingError::Malformed)?;
        let mut inner = self.lock();
        let now = chrono::Utc::now().timestamp();
        let op = inner
            .file
            .pending_elevations
            .iter()
            .find(|e| e.op_id == op_id)
            .cloned()
            .ok_or(PairingError::UnknownOperation)?;
        if op.expires_at <= now {
            inner.file.pending_elevations.retain(|e| e.op_id != op_id);
            self.persist(&mut inner.file)?;
            return Err(PairingError::Expired);
        }
        if op.scopes.contains(&Scope::FrontDoor) {
            return Err(PairingError::NotGrantable(
                "this request asks for front_door, which carries no budget; grant it as a \
                 front-door grant"
                    .into(),
            ));
        }
        self.verify_grant_confirmation(
            &mut inner,
            &grant_confirmation_phrase(&op),
            op_id,
            confirmation,
        )?;
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
            expires_at: now + terms.ttl_secs,
            identity_fingerprint: inner.identity_fingerprint.clone(),
            epoch: client.epoch,
            granted_by: "cli".to_string(),
            budget: Some(GrantBudget::from_terms(&terms)),
        };
        inner.file.pending_elevations.retain(|e| e.op_id != op_id);
        // A new budget window replaces the client's old one. A live front-door
        // grant is a different authority and stays.
        for old in &mut inner.file.grants {
            if old.client_id == grant.client_id {
                old.budget = None;
            }
        }
        inner.file.grants.push(grant.clone());
        self.persist(&mut inner.file)?;
        inner.owner_confirmations.remove(op_id);
        if !grant.is_live(chrono::Utc::now().timestamp()) {
            return Err(PairingError::Expired);
        }
        Ok(grant)
    }

    /// Write a `front_door` grant. **Owner CLI only.**
    ///
    /// Same consent as a spend grant: the operation-bound confirmation from the
    /// owner terminal or protected headless file. `ttl_secs` is the owner's window (at most
    /// 24 h). It replaces the client's previous front-door grant and leaves a
    /// live spend grant alone.
    pub fn grant_front_door(
        &self,
        op_id: &str,
        confirmation: &str,
        ttl_secs: i64,
    ) -> Result<FrontDoorGrant, PairingError> {
        if !self.owner_control_enabled {
            return Err(PairingError::OwnerChannelUnavailable);
        }
        if ttl_secs <= 0 || ttl_secs > MAX_SPEND_GRANT_TTL_SECS {
            return Err(PairingError::Malformed(format!(
                "a front-door grant lasts between 1 second and {} hours",
                MAX_SPEND_GRANT_TTL_SECS / 3600
            )));
        }
        let mut inner = self.lock();
        let now = chrono::Utc::now().timestamp();
        let op = inner
            .file
            .pending_elevations
            .iter()
            .find(|e| e.op_id == op_id)
            .cloned()
            .ok_or(PairingError::UnknownOperation)?;
        if op.expires_at <= now {
            inner.file.pending_elevations.retain(|e| e.op_id != op_id);
            self.persist(&mut inner.file)?;
            return Err(PairingError::Expired);
        }
        if op.scopes != [Scope::FrontDoor] {
            return Err(PairingError::NotGrantable(
                "this request does not ask for front_door; grant it with a budget".into(),
            ));
        }
        self.verify_grant_confirmation(
            &mut inner,
            &grant_confirmation_phrase(&op),
            op_id,
            confirmation,
        )?;
        let client = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == op.client_id)
            .cloned()
            .ok_or(PairingError::UnknownClient)?;
        let grant = FrontDoorGrant {
            op_id: op.op_id.clone(),
            client_id: op.client_id.clone(),
            granted_at: now,
            expires_at: now + ttl_secs,
            identity_fingerprint: inner.identity_fingerprint.clone(),
            epoch: client.epoch,
            granted_by: "cli".to_string(),
            revoked: false,
        };
        inner.file.pending_elevations.retain(|e| e.op_id != op_id);
        for old in &mut inner.file.front_door_grants {
            if old.client_id == grant.client_id {
                old.revoked = true;
            }
        }
        inner.file.front_door_grants.push(grant.clone());
        self.persist(&mut inner.file)?;
        inner.owner_confirmations.remove(op_id);
        tracing::info!(
            client_id = %grant.client_id,
            op_id = %grant.op_id,
            expires_at = grant.expires_at,
            "owner granted front_door (publish the front-door card only; no spend)"
        );
        Ok(grant)
    }

    /// The live front-door grants, as the owner sees them.
    pub fn front_door_grants(&self) -> Vec<FrontDoorGrant> {
        let inner = self.lock();
        let now = chrono::Utc::now().timestamp();
        inner
            .file
            .front_door_grants
            .iter()
            .filter(|g| g.is_live(now))
            .cloned()
            .collect()
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
            None,
        )?;
        inner
            .file
            .replacement_approvals
            .retain(|a| a.expires_at > now);
        inner.file.replacement_approvals.push(approval.clone());
        self.persist(&mut inner.file)?;
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
            self.persist(&mut inner.file)?;
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
        self.persist(&mut inner.file)?;
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
                self.persist(&mut inner.file)?;
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
        self.persist(&mut inner.file)?;
        Ok(consumed)
    }

    // ── Budget-scoped spend (G1) ───────────────────────────────────

    /// Reserve a call's charges against the client's live grant, atomically.
    ///
    /// Runs under the one mutex that guards the durable store and persists
    /// before returning, so concurrent calls serialise here and a crash after
    /// this point leaves the reservation counted. On any refusal nothing is
    /// reserved; on a ledger write failure the in-memory tally is rolled back
    /// and the call is refused.
    pub fn reserve_spend(
        &self,
        client_id: &str,
        epoch: u64,
        charges: Vec<Charge>,
    ) -> Result<Reservation, BudgetRefusal> {
        self.reserve_spend_with_clock(client_id, epoch, charges, || chrono::Utc::now().timestamp())
    }

    fn reserve_spend_with_clock(
        &self,
        client_id: &str,
        epoch: u64,
        charges: Vec<Charge>,
        clock: impl FnMut() -> i64,
    ) -> Result<Reservation, BudgetRefusal> {
        let mut inner = self.lock();
        self.reserve_spend_locked(
            &mut inner,
            client_id,
            epoch,
            charges,
            ReservationAuthority::default(),
            clock,
        )
    }

    /// Liquidity authority is checked inside the SAME transaction as its debit.
    pub fn reserve_liquidity_fee(
        &self,
        client_id: &str,
        epoch: u64,
        charges: Vec<Charge>,
    ) -> Result<Reservation, BudgetRefusal> {
        let mut inner = self.lock();
        self.reserve_spend_locked(
            &mut inner,
            client_id,
            epoch,
            charges,
            ReservationAuthority {
                liquidity: true,
                ..Default::default()
            },
            || chrono::Utc::now().timestamp(),
        )
    }

    pub(crate) fn reserve_operation_spend(
        &self,
        client_id: &str,
        epoch: u64,
        charges: Vec<Charge>,
        operation: crate::spend_budget::OperationReservationLink,
    ) -> Result<Reservation, BudgetRefusal> {
        let mut inner = self.lock();
        self.reserve_spend_locked(
            &mut inner,
            client_id,
            epoch,
            charges,
            ReservationAuthority {
                operation: Some(operation),
                ..Default::default()
            },
            || chrono::Utc::now().timestamp(),
        )
    }

    /// Discover even reservations whose async SQL attachment never ran.
    pub(crate) fn pending_operation_reservations(
        &self,
    ) -> Vec<(crate::spend_budget::OperationReservationLink, Reservation)> {
        let inner = self.lock();
        let mut result = Vec::new();
        for grant in &inner.file.grants {
            let Some(budget) = &grant.budget else {
                continue;
            };
            for (id, link) in &budget.operation_links {
                let Some(pending) = budget.pending.get(id) else {
                    continue;
                };
                result.push((
                    link.clone(),
                    Reservation {
                        id: id.clone(),
                        client_id: grant.client_id.clone(),
                        op_id: grant.op_id.clone(),
                        charges: pending
                            .iter()
                            .map(|(recipient, amount_msat)| Charge {
                                recipient: recipient.clone(),
                                amount_msat: *amount_msat,
                            })
                            .collect(),
                    },
                ));
            }
        }
        result
    }

    /// Persist an operation's reconciliation reference before its grant debit.
    /// The callback must not re-enter this service. A crash can leave the
    /// operation reserved without a debit, but never an orphaned grant debit.
    pub(crate) fn reserve_spend_linked(
        &self,
        client_id: &str,
        epoch: u64,
        charges: Vec<Charge>,
        before_persist: impl FnOnce(&Reservation) -> Result<(), BudgetRefusal>,
    ) -> Result<Reservation, BudgetRefusal> {
        let mut inner = self.lock();
        self.reserve_spend_locked(
            &mut inner,
            client_id,
            epoch,
            charges,
            ReservationAuthority {
                before_persist: Some(Box::new(before_persist)),
                ..Default::default()
            },
            || chrono::Utc::now().timestamp(),
        )
    }

    fn reserve_spend_locked(
        &self,
        inner: &mut Inner,
        client_id: &str,
        epoch: u64,
        charges: Vec<Charge>,
        authority: ReservationAuthority<'_>,
        mut clock: impl FnMut() -> i64,
    ) -> Result<Reservation, BudgetRefusal> {
        let now = clock();
        let fingerprint = inner.identity_fingerprint.clone();
        let current_epoch = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == client_id)
            .map(|c| c.epoch);
        if current_epoch != Some(epoch) {
            return Err(BudgetRefusal::NoGrant);
        }
        let Some(idx) = inner.file.grants.iter().position(|g| {
            if authority
                .expected_op_id
                .is_some_and(|op_id| g.op_id != op_id)
            {
                return false;
            }
            self.permits_spend_grant(g)
                && g.client_id == client_id
                && g.epoch == epoch
                && g.identity_fingerprint == fingerprint
                && g.is_live(now)
        }) else {
            return Err(BudgetRefusal::NoGrant);
        };
        if authority.liquidity
            && !inner.file.grants[idx]
                .budget
                .as_ref()
                .is_some_and(|b| b.allow_liquidity_fees)
        {
            return Err(BudgetRefusal::Unpriced(
                "grant does not authorize liquidity fees".into(),
            ));
        }
        let before = inner.file.grants[idx].budget.clone();
        let op_id = inner.file.grants[idx].op_id.clone();
        let id = uuid::Uuid::new_v4().to_string();
        let budget = inner.file.grants[idx]
            .budget
            .as_mut()
            .ok_or(BudgetRefusal::NoGrant)?;
        if budget.pending.len() >= 1024 {
            return Err(BudgetRefusal::Ledger(
                "too many unresolved reservations".into(),
            ));
        }
        budget.reserve_at(&charges, now)?;
        let mut recipients = std::collections::BTreeMap::new();
        for charge in &charges {
            *recipients.entry(charge.recipient.clone()).or_insert(0u64) += charge.amount_msat;
        }
        // An empty fanout moves no value and grants no dispatch authority.
        if !recipients.is_empty() {
            budget.pending.insert(id.clone(), recipients);
            if let Some(link) = authority.operation {
                budget.operation_links.insert(id.clone(), link);
            }
        }
        let reservation = Reservation {
            id,
            client_id: client_id.to_string(),
            op_id: op_id.clone(),
            charges,
        };
        if let Err(e) = authority
            .before_persist
            .map_or(Ok(()), |save| save(&reservation))
        {
            inner.file.grants[idx].budget = before;
            return Err(e);
        }
        if let Err(e) = self.persist_with_clock(&mut inner.file, &mut clock) {
            if let Some(g) = inner.file.grants.iter_mut().find(|g| g.op_id == op_id) {
                g.budget = before;
            }
            return Err(BudgetRefusal::Ledger(e.to_string()));
        }
        // Persistence may have pruned this grant at the expiry boundary.
        // Never return authority for a reservation that did not survive the
        // transaction, or whose deadline passed while syncing the ledger.
        let now = clock();
        if !inner
            .file
            .grants
            .iter()
            .any(|g| g.op_id == op_id && g.is_live(now))
        {
            return Err(BudgetRefusal::NoGrant);
        }
        Ok(reservation)
    }

    /// Issue the owner's one-time first-contact confirmation for `recipient`.
    /// The caller must authenticate the independent owner; paired HTTP callers
    /// cannot reach this operation. `grant_op_id` binds the reviewed budget.
    ///
    /// Only for a client holding a live budget grant, and only within it: the
    /// amount must fit the grant's per-call maximum, what is left of the
    /// budget and, if set, the recipient's budget. Nothing is reserved here;
    /// the send debits the budget grant once, before any invoice or payment.
    /// Replaces any earlier unused first-contact grant of this client.
    ///
    /// `contact_budget_msat` is the per-contact budget the owner chose with this
    /// confirmation. If the grant has no cap for this recipient yet, it becomes
    /// one (bounded by the grant's total). That only narrows the grant, and it
    /// is what makes the contact *budgeted*: a later re-admission after a
    /// reconnect may then be paid from the budget without asking again (see
    /// [`Self::reserve_readmission`]).
    pub fn grant_first_contact(
        &self,
        client_id: &str,
        grant_op_id: &str,
        recipient: &str,
        max_total_msat: u64,
        contact_budget_msat: Option<u64>,
    ) -> Result<crate::spend_budget::FirstContactGrant, BudgetRefusal> {
        use crate::spend_budget::{
            canonical_recipient, FirstContactGrant, FIRST_CONTACT_GRANT_TTL_SECS,
            FIRST_CONTACT_MAX_MSAT,
        };
        if !self.owner_control_enabled {
            return Err(BudgetRefusal::NoGrant);
        }
        let recipient = canonical_recipient(recipient)
            .filter(|key| key.len() == 64)
            .ok_or_else(|| BudgetRefusal::FirstContact("the recipient is not a node id".into()))?;
        if max_total_msat == 0 || max_total_msat > FIRST_CONTACT_MAX_MSAT {
            return Err(BudgetRefusal::FirstContact(format!(
                "a first contact may cover 1..={FIRST_CONTACT_MAX_MSAT} msat"
            )));
        }
        let mut inner = self.lock();
        let now = chrono::Utc::now().timestamp();
        let fingerprint = inner.identity_fingerprint.clone();
        let Some(grant) = inner.file.grants.iter().find(|g| {
            g.client_id == client_id
                && g.op_id == grant_op_id
                && g.identity_fingerprint == fingerprint
                && g.is_live(now)
                && inner
                    .file
                    .clients
                    .iter()
                    .any(|c| c.client_id == client_id && c.epoch == g.epoch)
        }) else {
            return Err(BudgetRefusal::NoGrant);
        };
        let epoch = grant.epoch;
        let budget = grant.budget.as_ref().ok_or(BudgetRefusal::NoGrant)?;
        if max_total_msat > budget.per_call_max_msat {
            return Err(BudgetRefusal::PerCall {
                max_msat: budget.per_call_max_msat,
            });
        }
        if max_total_msat > budget.remaining_msat() {
            return Err(BudgetRefusal::Total {
                remaining_msat: budget.remaining_msat(),
            });
        }
        if let Some(cap) = budget.per_recipient_msat.get(&recipient) {
            let used = budget
                .used_by_recipient
                .get(&recipient)
                .copied()
                .unwrap_or(0);
            let left = cap.saturating_sub(used);
            if max_total_msat > left {
                return Err(BudgetRefusal::Recipient {
                    recipient,
                    remaining_msat: left,
                });
            }
        }
        if let Some(contact_budget) = contact_budget_msat {
            if contact_budget < max_total_msat
                || contact_budget > budget.budget_msat
                || budget
                    .per_recipient_msat
                    .get(&recipient)
                    .is_some_and(|cap| *cap != contact_budget)
            {
                return Err(BudgetRefusal::FirstContact(
                    "contact budget must cover this approval, fit the grant total and match any existing recipient cap".into(),
                ));
            }
        }
        let issued = FirstContactGrant {
            recipient,
            max_total_msat,
            expires_at: (now + FIRST_CONTACT_GRANT_TTL_SECS).min(grant.expires_at),
        };
        let budget_op_id = grant.op_id.clone();
        if let Some(contact_budget) = contact_budget_msat {
            let idx = inner
                .file
                .grants
                .iter()
                .position(|g| g.op_id == budget_op_id)
                .ok_or(BudgetRefusal::NoGrant)?;
            let before = inner.file.grants[idx].budget.clone();
            if let Some(budget) = inner.file.grants[idx].budget.as_mut() {
                if !budget.per_recipient_msat.contains_key(&issued.recipient) {
                    budget
                        .per_recipient_msat
                        .insert(issued.recipient.clone(), contact_budget);
                }
            }
            if inner.file.grants[idx].budget != before {
                if let Err(e) = self.persist(&mut inner.file) {
                    inner.file.grants[idx].budget = before;
                    return Err(BudgetRefusal::Ledger(e.to_string()));
                }
            }
        }
        inner.first_contact.insert(
            client_id.to_string(),
            PendingFirstContact {
                grant: issued.clone(),
                epoch,
                budget_op_id,
                consumed: false,
            },
        );
        Ok(issued)
    }

    /// Observe only this client's approval under an exact live budget operation.
    /// The node's owner control handler writes it; reads never consume it. A
    /// missing/replaced/revoked operation is indistinguishable from another
    /// client's operation. Restart drops approvals, preserving fail-closed use.
    pub fn first_contact_approval_status(
        &self,
        client_id: &str,
        epoch: u64,
        grant_op_id: &str,
        recipient: &str,
    ) -> Option<crate::spend_budget::FirstContactApprovalStatus> {
        use crate::spend_budget::{
            FirstContactApprovalState as State, FirstContactApprovalStatus,
            FIRST_CONTACT_APPROVAL_WINDOW_SECS,
        };
        let recipient = crate::spend_budget::canonical_recipient(recipient)?;
        let inner = self.lock();
        let now = chrono::Utc::now().timestamp();
        if !self.owner_control_enabled
            || !inner
                .file
                .clients
                .iter()
                .any(|c| c.client_id == client_id && c.epoch == epoch)
            || !inner.file.grants.iter().any(|g| {
                g.op_id == grant_op_id
                    && g.client_id == client_id
                    && g.epoch == epoch
                    && g.identity_fingerprint == inner.identity_fingerprint
                    && g.budget.is_some()
                    && g.is_live(now)
            })
        {
            return None;
        }
        let pending = inner.first_contact.get(client_id).filter(|p| {
            p.budget_op_id == grant_op_id && p.epoch == epoch && p.grant.recipient == recipient
        });
        let state = match pending {
            Some(p) if p.consumed => State::Consumed,
            Some(p) if p.grant.expires_at <= now => State::Expired,
            Some(_) => State::Approved,
            None => State::Pending,
        };
        Some(FirstContactApprovalStatus {
            grant_op_id: grant_op_id.to_owned(),
            recipient,
            state,
            approval_window_secs: FIRST_CONTACT_APPROVAL_WINDOW_SECS,
            approval: pending.map(|p| p.grant.clone()),
        })
    }

    /// Whether the grant behind `parent` may pay admission to `recipient`
    /// again (after a reconnect), and for at most how much. `Ok(None)` for a
    /// contact the grant already budgets (a per-contact cap bounds it);
    /// `Ok(Some(max))` when the owner's one-time confirmation for exactly this
    /// contact is pending. A stranger to this grant, with neither, is refused.
    fn readmission_basis(
        inner: &Inner,
        parent: &Reservation,
        recipient: &str,
        now: i64,
    ) -> Result<(u64, Option<u64>), BudgetRefusal> {
        let grant = inner
            .file
            .grants
            .iter()
            .find(|g| {
                g.op_id == parent.op_id
                    && g.client_id == parent.client_id
                    && g.identity_fingerprint == inner.identity_fingerprint
                    && g.is_live(now)
            })
            .ok_or(BudgetRefusal::NoGrant)?;
        let confirmed = inner.first_contact.get(&parent.client_id).filter(|p| {
            !p.consumed
                && p.grant.recipient == recipient
                && p.epoch == grant.epoch
                && p.budget_op_id == grant.op_id
                && p.grant.expires_at > now
        });
        if let Some(pending) = confirmed {
            return Ok((grant.epoch, Some(pending.grant.max_total_msat)));
        }
        let budgeted = grant
            .budget
            .as_ref()
            .is_some_and(|b| b.per_recipient_msat.contains_key(recipient));
        if !budgeted {
            return Err(BudgetRefusal::FirstContact(
                "this contact has no budget in your grant, so paying admission to them again \
                 needs your one-time confirmation (POST /api/v1/pair/first-contact-grant) — \
                 nothing was requested or paid"
                    .into(),
            ));
        }
        Ok((grant.epoch, None))
    }

    /// Check, without reserving, that the grant behind `parent` may pay a
    /// re-admission to `recipient` (see [`Self::reserve_readmission`]). Lets a
    /// send refuse before it asks the recipient for a quote.
    pub fn readmission_allowed(
        &self,
        parent: &Reservation,
        recipient: &str,
    ) -> Result<(), BudgetRefusal> {
        let recipient =
            crate::spend_budget::canonical_recipient(recipient).ok_or(BudgetRefusal::NoGrant)?;
        let inner = self.lock();
        Self::readmission_basis(&inner, parent, &recipient, chrono::Utc::now().timestamp())
            .map(|_| ())
    }

    /// Reserve a re-admission to `recipient` of exactly `amount_msat` (the
    /// recipient's signed quote) against the grant behind `parent`.
    ///
    /// CoS decision (2026-09-27): a budget may pay re-admission for a contact
    /// the owner already budgeted — the grant caps that contact, and the
    /// reservation must fit the cap, the per-call maximum and what is left.
    /// Never for a stranger to the grant without the owner's one-time
    /// confirmation for exactly that contact, which this consumes (single use)
    /// and which bounds the amount. There is no durable admission object: the
    /// admission is re-proven by a new settled payment, debited like any other.
    pub fn reserve_readmission(
        &self,
        parent: &Reservation,
        recipient: &str,
        amount_msat: u64,
        call_reserved_msat: u64,
    ) -> Result<Reservation, BudgetRefusal> {
        self.reserve_readmission_operation(parent, recipient, amount_msat, call_reserved_msat, None)
    }

    pub(crate) fn reserve_readmission_operation(
        &self,
        parent: &Reservation,
        recipient: &str,
        amount_msat: u64,
        call_reserved_msat: u64,
        operation: Option<crate::spend_budget::OperationReservationLink>,
    ) -> Result<Reservation, BudgetRefusal> {
        self.reserve_quoted_readmission(
            parent,
            recipient,
            0,
            amount_msat,
            call_reserved_msat,
            operation,
        )
        .map(|(_, admission)| admission)
    }

    /// Before paying a signed re-admission quote: raise the parent's message
    /// reservation to `quoted_message_all_in` (no-op when already covered) and
    /// reserve `admission_all_in` as its own operation-linked debit. Both share
    /// one grant check and one persist, so a quote whose all-in cannot fit is
    /// refused before any payment and a crash never keeps half of it.
    ///
    /// Returns the new call-reserved total and the admission reservation.
    pub(crate) fn reserve_quoted_readmission(
        &self,
        parent: &Reservation,
        recipient: &str,
        quoted_message_all_in: u64,
        admission_all_in: u64,
        call_reserved_msat: u64,
        operation: Option<crate::spend_budget::OperationReservationLink>,
    ) -> Result<(u64, Reservation), BudgetRefusal> {
        let recipient =
            crate::spend_budget::canonical_recipient(recipient).ok_or(BudgetRefusal::NoGrant)?;
        let mut inner = self.lock();
        let (epoch, confirmed) =
            Self::readmission_basis(&inner, parent, &recipient, chrono::Utc::now().timestamp())?;
        let grant_idx = inner
            .file
            .grants
            .iter()
            .position(|g| g.op_id == parent.op_id)
            .ok_or(BudgetRefusal::NoGrant)?;
        let budget = inner.file.grants[grant_idx]
            .budget
            .as_ref()
            .ok_or(BudgetRefusal::NoGrant)?;
        // A resolved parent cannot start more payments. This also binds the
        // admission to a recipient in the original API call.
        let Some(old_message) = budget
            .pending
            .get(&parent.id)
            .and_then(|p| p.get(&recipient))
            .copied()
        else {
            return Err(BudgetRefusal::NoGrant);
        };
        let message_top_up = quoted_message_all_in.saturating_sub(old_message);
        let max_msat = budget.per_call_max_msat;
        let need = message_top_up
            .checked_add(admission_all_in)
            .ok_or(BudgetRefusal::PerCall { max_msat })?;
        let total = call_reserved_msat
            .checked_add(need)
            .ok_or(BudgetRefusal::PerCall { max_msat })?;
        if total > max_msat {
            return Err(BudgetRefusal::PerCall { max_msat });
        }
        if let Some(max_msat) = confirmed {
            if let Some(pending) = inner.first_contact.get_mut(&parent.client_id) {
                pending.consumed = true;
            }
            if need > max_msat {
                return Err(BudgetRefusal::FirstContact(format!(
                    "the recipient asks {need} msat to admit you again, more than the {max_msat} msat you confirmed — nothing was paid"
                )));
            }
        }
        // The top-up joins the parent's own pending entry (resolved with the
        // message), checked against every grant limit together with the
        // admission below; on any refusal the whole budget is restored.
        let before = inner.file.grants[grant_idx].budget.clone();
        if message_top_up > 0 {
            let budget = inner.file.grants[grant_idx]
                .budget
                .as_mut()
                .ok_or(BudgetRefusal::NoGrant)?;
            if let Err(e) = budget.reserve_at(
                &[Charge {
                    recipient: recipient.clone(),
                    amount_msat: message_top_up,
                }],
                chrono::Utc::now().timestamp(),
            ) {
                inner.file.grants[grant_idx].budget = before;
                return Err(e);
            }
            if let Some(amount) = budget
                .pending
                .get_mut(&parent.id)
                .and_then(|p| p.get_mut(&recipient))
            {
                *amount += message_top_up;
            }
        }
        // Eligibility and reservation share the replacement/revocation mutex.
        let admission = self.reserve_spend_locked(
            &mut inner,
            &parent.client_id,
            epoch,
            vec![Charge {
                recipient,
                amount_msat: admission_all_in,
            }],
            ReservationAuthority {
                expected_op_id: Some(&parent.op_id),
                operation,
                ..Default::default()
            },
            || chrono::Utc::now().timestamp(),
        );
        match admission {
            Ok(admission) => Ok((total, admission)),
            Err(e) => {
                if let Some(g) = inner
                    .file
                    .grants
                    .iter_mut()
                    .find(|g| g.op_id == parent.op_id)
                {
                    g.budget = before;
                }
                Err(e)
            }
        }
    }

    /// Reserve a consumed approval against its exact original grant. The
    /// opaque value is not cloneable and cannot be deserialized from a request.
    pub fn reserve_first_contact(
        &self,
        approval: FirstContactAuthorization,
        cap: Option<u64>,
    ) -> Result<Reservation, BudgetRefusal> {
        self.reserve_first_contact_operation(approval, cap, None)
    }

    pub(crate) fn reserve_first_contact_operation(
        &self,
        approval: FirstContactAuthorization,
        cap: Option<u64>,
        operation: Option<crate::spend_budget::OperationReservationLink>,
    ) -> Result<Reservation, BudgetRefusal> {
        let amount_msat = cap
            .unwrap_or(approval.max_total_msat)
            .min(approval.max_total_msat);
        let mut inner = self.lock();
        if approval.expires_at <= chrono::Utc::now().timestamp() {
            return Err(BudgetRefusal::NoGrant);
        }
        self.reserve_spend_locked(
            &mut inner,
            &approval.client_id,
            approval.epoch,
            vec![Charge {
                recipient: approval.recipient,
                amount_msat,
            }],
            ReservationAuthority {
                expected_op_id: Some(&approval.budget_op_id),
                operation,
                ..Default::default()
            },
            || chrono::Utc::now().timestamp(),
        )
    }

    /// Consume this client's first-contact grant for `recipient`, returning
    /// an opaque authorization bound to its original grant. `None` when absent,
    /// for someone else, or when it has
    /// expired, or the budget grant it was issued under is no longer live
    /// (revoked, replaced, rotated). Single use: a match is marked consumed.
    pub fn take_first_contact(
        &self,
        client_id: &str,
        epoch: u64,
        recipient: &str,
    ) -> Option<FirstContactAuthorization> {
        let recipient = crate::spend_budget::canonical_recipient(recipient)?;
        let mut inner = self.lock();
        let now = chrono::Utc::now().timestamp();
        let pending = inner.first_contact.get(client_id)?;
        if pending.consumed || pending.grant.expires_at <= now {
            return None;
        }
        if pending.grant.recipient != recipient || pending.epoch != epoch {
            return None;
        }
        let fingerprint = inner.identity_fingerprint.clone();
        let op_id = pending.budget_op_id.clone();
        let live = inner.file.grants.iter().any(|g| {
            g.op_id == op_id
                && g.client_id == client_id
                && g.epoch == epoch
                && g.identity_fingerprint == fingerprint
                && g.is_live(now)
        });
        let taken = inner.first_contact.get_mut(client_id)?;
        taken.consumed = true;
        live.then_some(FirstContactAuthorization {
            max_total_msat: taken.grant.max_total_msat,
            recipient,
            client_id: client_id.to_owned(),
            epoch,
            budget_op_id: taken.budget_op_id.clone(),
            expires_at: taken.grant.expires_at,
        })
    }

    /// Validate a persisted reservation and run one synchronous dispatch step
    /// under the same lock used by debit, revoke, rotation and identity rebind.
    /// The closure must never block or re-enter the pairing service. Async
    /// callers poll once here and release the lock before returning Pending.
    pub(crate) fn with_spend_authority<T>(
        &self,
        reservation: &Reservation,
        action: impl FnOnce() -> T,
    ) -> Result<T, BudgetRefusal> {
        self.with_spend_authority_at(reservation, || chrono::Utc::now().timestamp(), action)
    }

    /// [`Self::with_spend_authority`] with an injected clock. The clock is read
    /// **after** the pairing lock is held: a dispatch that waited behind
    /// another writer must judge deadlines at the time it actually runs.
    pub(crate) fn with_spend_authority_at<T>(
        &self,
        reservation: &Reservation,
        clock: impl FnOnce() -> i64,
        action: impl FnOnce() -> T,
    ) -> Result<T, BudgetRefusal> {
        let inner = self.lock();
        let now = clock();
        let valid = inner.file.grants.iter().any(|g| {
            self.permits_spend_grant(g)
                && g.op_id == reservation.op_id
                && g.budget.as_ref().is_some_and(|b| {
                    // A relation grant lives until its latest envelope, so
                    // each recipient's own deadline is rechecked here, at
                    // dispatch: an expired peer never pays on a live one's time.
                    b.pending
                        .get(&reservation.id)
                        .is_some_and(|recipients| b.envelopes_live(recipients.keys(), now))
                })
                && g.client_id == reservation.client_id
                && g.identity_fingerprint == inner.identity_fingerprint
                && g.scopes.contains(&Scope::Spend)
                && g.is_live(now)
                && inner.file.clients.iter().any(|c| {
                    c.client_id == g.client_id
                        && c.epoch == g.epoch
                        && c.identity_fingerprint == inner.identity_fingerprint
                })
        });
        if !valid {
            return Err(BudgetRefusal::NoGrant);
        }
        Ok(action())
    }

    pub(crate) fn reservation_contact_budget(
        &self,
        reservation: &Reservation,
        recipient: &str,
    ) -> Option<u64> {
        let inner = self.lock();
        inner
            .file
            .grants
            .iter()
            .find(|g| g.op_id == reservation.op_id && g.client_id == reservation.client_id)
            .and_then(|g| g.budget.as_ref())?
            .per_recipient_msat
            .get(recipient)
            .copied()
    }

    /// Resolve one recipient's part of a reservation to what was actually
    /// paid (`0` for a refusal before dispatch or a confirmed failure).
    ///
    /// An unknown outcome is simply never resolved. Resolving against a grant
    /// that was revoked, replaced or has expired does nothing: there is no
    /// budget left to return the sats to.
    pub fn resolve_spend(&self, reservation: &Reservation, recipient: &str, actual_msat: u64) {
        if let Err(e) = self.try_resolve_spend(reservation, recipient, actual_msat) {
            tracing::warn!(error = %e, "spend ledger resolution not persisted; reservation retained");
        }
    }

    pub(crate) fn try_resolve_spend(
        &self,
        reservation: &Reservation,
        recipient: &str,
        actual_msat: u64,
    ) -> Result<(), PairingError> {
        let mut inner = self.lock();
        let Some(grant) = inner
            .file
            .grants
            .iter_mut()
            .find(|g| g.op_id == reservation.op_id && g.client_id == reservation.client_id)
        else {
            return Ok(());
        };
        let Some(budget) = grant.budget.as_mut() else {
            return Ok(());
        };
        let before = budget.clone();
        let Some(recipients) = budget.pending.get_mut(&reservation.id) else {
            return Ok(());
        };
        let Some(reserved) = recipients.remove(recipient) else {
            return Ok(());
        };
        if recipients.is_empty() {
            budget.pending.remove(&reservation.id);
            budget.operation_links.remove(&reservation.id);
        }
        budget.resolve(recipient, reserved, actual_msat);
        if let Err(e) = self.persist(&mut inner.file) {
            if let Some(grant) = inner
                .file
                .grants
                .iter_mut()
                .find(|g| g.op_id == reservation.op_id)
            {
                grant.budget = Some(before);
            }
            return Err(e);
        }
        Ok(())
    }

    /// Revoke spend grants now: one client's, or every client's. Returns how
    /// many were removed. Outstanding tokens lose `spend` on their next
    /// request, because binding verification recomputes effective scopes.
    pub fn revoke_grants(&self, client_id: Option<&str>) -> Result<usize, PairingError> {
        let mut inner = self.lock();
        let removed = inner.file.revoke_grants(client_id);
        self.persist(&mut inner.file)?;
        Ok(removed)
    }

    /// Drop grants that can no longer authorise anything and persist, if any
    /// were found. Reads, startup and the deadline scheduler use the same
    /// cleanup transaction; errors keep deletion queued for a later retry.
    pub fn prune_expired_grants(&self) -> Result<usize, PairingError> {
        let mut inner = self.lock_without_cleanup();
        Self::prune_owner_confirmations(&mut inner);
        self.prune_expired_locked(&mut inner.file)
    }

    fn prune_expired_locked(&self, file: &mut PairingFile) -> Result<usize, PairingError> {
        let now = chrono::Utc::now().timestamp();
        let before = file.grants.len() + file.front_door_grants.len();
        if file.has_dead_grant(now) {
            self.persist(file)?;
        }
        Ok(before - file.grants.len() - file.front_door_grants.len())
    }

    /// Delay to the next absolute expiry. Recheck wall-clock changes at least
    /// once a second; a new grant also wakes the scheduler immediately.
    pub(crate) fn grant_cleanup_delay(&self) -> Duration {
        let inner = self.lock_without_cleanup();
        let now = chrono::Utc::now().timestamp_millis();
        let millis = inner
            .file
            .grants
            .iter()
            .map(|g| g.expires_at)
            .chain(inner.file.front_door_grants.iter().map(|g| g.expires_at))
            .map(|at| at.saturating_mul(1000).saturating_sub(now).max(0) as u64)
            .min()
            .unwrap_or(1000);
        Duration::from_millis(millis.min(1000))
    }

    pub(crate) async fn grant_changed(&self) {
        self.grant_changes.notified().await;
    }

    /// The live grants, as the owner sees them. The read purges disk first.
    pub fn grant_views(&self) -> Vec<GrantView> {
        let inner = self.lock();
        let now = chrono::Utc::now().timestamp();
        inner
            .file
            .grants
            .iter()
            .filter(|g| g.is_live(now))
            .filter_map(grant_view)
            .collect()
    }

    /// A client's live grant, if it holds one in this deployment.
    pub fn grant_view_for(&self, client_id: &str) -> Option<GrantView> {
        let inner = self.lock();
        let now = chrono::Utc::now().timestamp();
        inner
            .file
            .grants
            .iter()
            .filter(|g| g.client_id == client_id && g.is_live(now) && self.permits_spend_grant(g))
            .find_map(grant_view)
    }

    // ── Durable persistence ────────────────────────────────────────

    fn challenge_path(&self, pair_id: &str) -> PathBuf {
        self.dir.join(format!("challenge-{pair_id}"))
    }

    /// Replace the durable file atomically: write a temp file in the same
    /// directory, fsync it, then rename over the target. A reader never sees a
    /// half-written store, and a crash mid-write leaves the previous state.
    ///
    /// Recheck expiry after file synchronization and publication, so a slow
    /// write cannot return success with an expired grant in the durable file.
    fn persist(&self, file: &mut PairingFile) -> Result<(), PairingError> {
        self.persist_with_clock(file, || chrono::Utc::now().timestamp())
    }

    fn persist_with_clock(
        &self,
        file: &mut PairingFile,
        mut clock: impl FnMut() -> i64,
    ) -> Result<(), PairingError> {
        // Do not forget a failed deletion: subsequent accesses and the expiry
        // scheduler must still see it until removal is durable.
        let mut candidate = file.clone();
        candidate.version = PAIRING_FILE_VERSION;
        let tmp = self.file_path.with_extension("json.tmp");
        loop {
            let now = clock();
            candidate.retain_live_grants(now);
            let bytes = serde_json::to_vec_pretty(&candidate)
                .map_err(|e| PairingError::Io(format!("serializing pairing store: {e}")))?;
            if let Err(e) = write_protected(&tmp, &bytes) {
                // A partial temporary file must not become a second retained
                // grant store. The authoritative file is still unchanged.
                let _ = std::fs::remove_file(&tmp);
                return Err(e.into());
            }
            let now = clock();
            if candidate.has_dead_grant(now) {
                continue;
            }
            if let Err(e) = std::fs::rename(&tmp, &self.file_path) {
                let _ = std::fs::remove_file(&tmp);
                return Err(e.into());
            }
            fsync_dir(&self.dir)?;
            let now = clock();
            if candidate.has_dead_grant(now) {
                continue;
            }
            *file = candidate;
            self.grant_changes.notify_one();
            return Ok(());
        }
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
    /// Still on file but no longer approvable: the node restarted after it
    /// was made (the owner code lived in memory only) or too many wrong codes
    /// cancelled it. The client should ask again.
    Lost,
    /// No such operation.
    Absent,
}

fn grant_view(g: &SpendGrant) -> Option<GrantView> {
    let b = g.budget.as_ref()?;
    Some(GrantView {
        allow_liquidity_fees: b.allow_liquidity_fees,
        op_id: g.op_id.clone(),
        client_id: g.client_id.clone(),
        granted_at: g.granted_at,
        expires_at: g.expires_at,
        budget_msat: b.budget_msat,
        used_msat: b.used_msat,
        remaining_msat: b.remaining_msat(),
        per_call_max_msat: b.per_call_max_msat,
        per_recipient_msat: b.per_recipient_msat.clone(),
        used_by_recipient: b.used_by_recipient.clone(),
        recipients_only: b.recipients_only,
        per_act_max_by_recipient: b.per_act_max_by_recipient.clone(),
        recipient_expires_at: b.recipient_expires_at.clone(),
    })
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

/// Never truncate or silently replace a persistent transport key. Unlike a
/// disposable challenge, rotating this secret invalidates clients' box pins.
pub fn load_box_transport_key(dir: &Path) -> io::Result<zeroize::Zeroizing<[u8; 32]>> {
    load_box_transport_key_with_sync(dir, fsync_dir_strict)
}

fn load_box_transport_key_with_sync(
    dir: &Path,
    sync_dir: impl Fn(&Path) -> io::Result<()>,
) -> io::Result<zeroize::Zeroizing<[u8; 32]>> {
    load_box_transport_key_with_io(dir, sync_dir, |from, to| std::fs::hard_link(from, to))
}

fn load_box_transport_key_with_io(
    dir: &Path,
    sync_dir: impl Fn(&Path) -> io::Result<()>,
    hard_link: impl Fn(&Path, &Path) -> io::Result<()>,
) -> io::Result<zeroize::Zeroizing<[u8; 32]>> {
    use std::io::{Read, Write};
    let path = dir.join("box-transport.key");
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let temporary = dir.join(format!(".box-transport-{}.tmp", uuid::Uuid::new_v4()));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            let published = (|| -> io::Result<()> {
                let mut secret = zeroize::Zeroizing::new([0u8; 32]);
                rand::thread_rng().fill_bytes(secret.as_mut());
                file.write_all(secret.as_ref())?;
                file.sync_all()?;
                // Publish a complete, synced key without clobbering a winner
                // from a concurrent open. A crash leaves at worst an ignored
                // protected temporary file, never a partial authoritative key.
                match hard_link(&temporary, &path) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
                    Err(error) => Err(io::Error::new(
                        error.kind(),
                        format!(
                            "cannot publish box transport key at {} via hard link: {error}. \
                             The data directory must be on a filesystem that supports hard links; \
                             exFAT/FAT SD cards do not. Use a filesystem such as NTFS, ext4 or APFS",
                            path.display()
                        ),
                    )),
                }
            })();
            drop(file);
            let _ = std::fs::remove_file(&temporary);
            published?;
        }
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    if !std::fs::symlink_metadata(&path)?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "box transport key must be a regular file",
        ));
    }
    let mut file = std::fs::File::open(&path)?;
    if file.metadata()?.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "box transport key must be exactly 32 bytes; restore it from backup",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    file.read_exact(secret.as_mut())?;
    // Also sync on reload: another opener (or a previous failed start) may
    // have published the file without completing its directory synchronization.
    sync_dir(dir)?;
    sync_dir(
        dir.parent()
            .ok_or_else(|| io::Error::other("pairing directory has no parent"))?,
    )?;
    Ok(secret)
}

#[cfg(test)]
mod box_transport_durability_tests {
    use super::*;

    #[cfg(not(unix))]
    #[test]
    fn strict_directory_sync_is_best_effort_on_non_unix() {
        let dir = tempfile::tempdir().unwrap();
        // Windows may reject opening or flushing a read-only directory handle.
        fsync_dir_strict(dir.path()).unwrap();
        assert_eq!(
            fsync_dir_strict(&dir.path().join("missing"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn unsupported_hard_links_explain_filesystem_requirement_and_leave_no_key() {
        let dir = tempfile::tempdir().unwrap();
        let error = load_box_transport_key_with_io(dir.path(), fsync_dir_strict, |_, _| {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "injected unsupported link",
            ))
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let message = error.to_string();
        assert!(message.contains("hard links"), "{message}");
        assert!(message.contains("exFAT"), "{message}");
        assert!(message.contains("injected unsupported link"), "{message}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn strict_directory_sync_does_not_discard_os_errors() {
        // This descriptor opens successfully, but cannot be fsynced.
        assert!(fsync_dir_strict(Path::new("/dev/null")).is_err());
    }

    #[test]
    fn directory_sync_failure_never_returns_a_box_key_or_rotates_it() {
        for existing in [false, true] {
            for fail_parent in [false, true] {
                let data = tempfile::tempdir().unwrap();
                let dir = data.path().join("pairing");
                std::fs::create_dir(&dir).unwrap();
                let path = dir.join("box-transport.key");
                if existing {
                    std::fs::write(&path, [0x42; 32]).unwrap();
                }
                let failed_path = if fail_parent { data.path() } else { &dir };
                let result = load_box_transport_key_with_sync(&dir, |path| {
                    if path == failed_path {
                        Err(io::Error::other("injected directory sync failure"))
                    } else {
                        fsync_dir(path)
                    }
                });
                assert!(result.is_err(), "existing={existing}, parent={fail_parent}");
                let before = std::fs::read(&path).unwrap();
                let recovered = load_box_transport_key(&dir).unwrap();
                assert_eq!(&recovered[..], &before);
            }
        }
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

/// fsync a directory so a rename into it is durable on Unix.
/// On other platforms the directory sync is best-effort; a missing directory still fails.
pub fn fsync_dir_strict(path: &Path) -> io::Result<()> {
    let result = std::fs::File::open(path).and_then(|dir| dir.sync_all());
    #[cfg(unix)]
    {
        result
    }
    #[cfg(not(unix))]
    {
        // std has no directory fsync on Windows: opening a directory without
        // backup semantics, or flushing its handle, fails with platform-specific
        // errors (access denied, invalid handle, ...). The file was already
        // synced before the rename, so only this directory step is best-effort
        // here. A missing directory is still an error. Unix transport pins
        // still require successful directory synchronization.
        match result {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

/// Best-effort directory fsync for existing callers.
pub fn fsync_dir(path: &Path) -> io::Result<()> {
    let dir = std::fs::File::open(path)?;
    // Directory fsync is not supported on every platform/filesystem; the
    // rename itself is still atomic, so a failure here must not fail the
    // operation that already succeeded.
    let _ = dir.sync_all();
    Ok(())
}

#[cfg(test)]
#[path = "pairing/budget_tests.rs"]
mod budget_transaction_tests;

#[cfg(all(test, unix))]
#[path = "pairing/headless_tests.rs"]
mod headless_tests;
