//! The owner control socket: local grants and approval commands (#76, P1-2).
//!
//! # The honest problem, stated before the mechanism
//!
//! The pairing file challenge proves **read access to `data_dir`** — and the
//! app has that by design, because that is how pairing works. So any approval
//! channel gated on `data_dir` access is a channel the app can drive **against
//! itself**, which would defeat policy lock B.
//!
//! That forces a conclusion worth stating rather than engineering around: in
//! the sidecar deployment, where the app launches the node and owns its stdout
//! and its `data_dir`, elevation to `spend` or replacement of a live identity
//! **cannot be made app-proof at this tier**. Any secret the node emits, the
//! app can read.
//!
//! So elevation is defined against a node the **owner** runs (operator lock,
//! option (i)), and the sidecar case is a named limitation rather than a
//! silently weaker path:
//!
//! - The packaged sidecar app is a `read` + `receive` client. It may *request*
//!   elevation and can never obtain it. [`ControlServer`] is not started, so
//!   `<data_dir>/control.sock` does not exist, and every grant-writing call
//!   refuses with [`crate::pairing::PairingError::OwnerChannelUnavailable`].
//! - OS user-presence (Touch ID, Windows Hello) would close the sidecar case
//!   properly. It is explicitly **out of scope for this step** and is not
//!   approximated here.
//!
//! # Why a Unix socket rather than an HTTP route
//!
//! `<data_dir>/control.sock` at mode `0600` is **not reachable over loopback
//! TCP**, which is exactly what excludes the in-scope attacker class: a browser
//! page, another OS user, a container with host networking, an SSH
//! port-forward. Spend elevation and identity replacement have no HTTP approval
//! endpoint. First-contact and gift approvals also have owner-key HTTP paths;
//! paired credentials cannot use them, and this socket never exports a key.
//!
//! # Consent is the typed phrase, not the connection
//!
//! The node never treats "a message arrived on the socket" as consent. Each
//! elevation/replacement request must carry an operation-bound random nonce
//! printed only to the owner node's terminal. HTTP, socket status, and files
//! expose no nonce. Same-uid socket access alone is insufficient for those
//! operations. First-contact and gift commands instead take the complete
//! owner-reviewed tuple as consent; they require an owner-managed node and OS
//! account outside the paired app's control, as the owner-key HTTP paths do.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::pairing::{
    grant_confirmation_phrase, replacement_confirmation_phrase, write_protected, PairingError,
    PairingService,
};
use crate::spend_budget::{self, GrantTerms, GrantView};

/// Socket file name inside the data directory.
pub const SOCKET_FILE: &str = "control.sock";

/// A request from the owner CLI.
#[derive(Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ControlRequest {
    /// List pairings, pending elevations and pending approvals.
    Status,
    /// Render one pending operation so the CLI can show it before asking.
    Describe {
        /// Pending operation id.
        op_id: String,
    },
    /// Write a budget-scoped spend grant for a pending elevation request.
    Grant {
        /// Pending operation id.
        op_id: String,
        /// The phrase the owner typed. Must name `op_id`.
        confirmation: String,
        /// The budget window the owner approves. Always explicit: the node
        /// never falls back to the client's proposal on its own.
        terms: GrantTerms,
    },
    /// Write a `front_door` grant (publish the front-door card only; no
    /// budget, no spend) for a pending request that asked for exactly that.
    GrantFrontDoor {
        /// Pending operation id.
        op_id: String,
        /// The phrase the owner typed. Must name `op_id`.
        confirmation: String,
        /// The window the owner approves, at most 24 h.
        ttl_secs: i64,
    },
    /// Approve one recipient and cap under this exact live budget grant.
    ApproveFirstContact {
        /// Paired client receiving the authorization.
        client_id: String,
        /// Live budget grant reviewed by the owner.
        grant_op_id: String,
        /// Recipient node id.
        recipient: String,
        /// Admission plus first-message ceiling, in msat.
        max_total_msat: u64,
        /// Optional exact per-contact budget, in msat.
        contact_budget_msat: Option<u64>,
    },
    /// Approve the exact frozen sponsor funding intent.
    ApproveGift {
        /// Introduction kit id.
        intro_id: String,
        /// Newcomer's node key.
        newcomer: String,
        /// Invoice payment hash.
        payment_hash: String,
        /// Exact gift, in msat.
        gift_msat: u64,
        /// Exact fee ceiling, in msat.
        fee_max_msat: u64,
        /// Six-digit code compared with the newcomer.
        code: String,
    },
    /// Register a device key the owner reviewed (fingerprint shown by the
    /// app and by the node). The typed code is the owner's approval.
    ApproveDeviceKey {
        /// Pending registration id.
        op_id: String,
        /// The code (or full line) the owner typed.
        confirmation: String,
        /// The owner-approval key's signature over the device tuple, hex.
        owner_signature: String,
    },
    /// Retire a device key; its relation envelopes end with it.
    RevokeDeviceKey {
        /// Key id.
        key_id: String,
    },
    /// Revoke spend grants now — one client's, or every client's.
    RevokeGrant {
        /// Client whose grant to revoke; `None` revokes all.
        #[serde(default)]
        client_id: Option<String>,
    },
    /// Approve **and execute** a pending live-identity replacement.
    ///
    /// The recovery phrase is supplied here, by the **owner**, at the control
    /// socket — never over HTTP, and never stored by the node. Its fingerprint
    /// must equal the `replacement_identity_fingerprint` the pending record was
    /// bound to when the client asked, so the owner cannot be walked onto a
    /// different destination identity than the one they were shown.
    ApproveReplacement {
        /// Pending operation id.
        op_id: String,
        /// The phrase the owner typed. Must name `op_id`.
        confirmation: String,
        /// The recovery phrase of the destination identity.
        mnemonic: Zeroizing<String>,
    },
    /// Revoke a pairing (delete it, or bump its epoch).
    Revoke {
        /// Client to revoke.
        client_id: String,
        /// Keep the pairing and bump its epoch instead of deleting it.
        #[serde(default)]
        keep_pairing: bool,
    },
    /// Open a pairing window so a second client can pair.
    OpenWindow {
        /// Window length in seconds.
        seconds: u64,
    },
}

/// A response to the owner CLI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "kebab-case")]
pub enum ControlResponse {
    /// Current pairing state.
    Status {
        /// Paired clients, as `(client_id, name, scopes, epoch)`.
        clients: Vec<ClientSummary>,
        /// Pending elevation requests awaiting the owner.
        pending_elevations: Vec<PendingSummary>,
        /// Pending replacement approvals awaiting the owner.
        pending_replacements: Vec<ReplacementSummary>,
        /// Live budget grants and what is left of each.
        #[serde(default)]
        grants: Vec<GrantView>,
        /// Live `front_door` grants.
        #[serde(default)]
        front_door_grants: Vec<FrontDoorGrantSummary>,
        /// Registered device keys.
        #[serde(default)]
        device_keys: Vec<DeviceKeySummary>,
        /// Device keys awaiting the owner.
        #[serde(default)]
        pending_device_keys: Vec<PendingDeviceKeySummary>,
    },
    /// A rendered pending operation and public label, never its secret nonce.
    Describe {
        /// Human-readable summary the CLI prints verbatim.
        summary: String,
        /// Public label to match against the owner node's console.
        confirmation_label: String,
        /// The budget the client proposed, if any — a suggestion the owner
        /// may accept, narrow or replace. Carries no authority.
        #[serde(default)]
        proposed_terms: Option<GrantTerms>,
        /// The request asks for `front_door` (no budget), not `spend`.
        #[serde(default)]
        front_door: bool,
        /// A device-key registration: the exact tuple the owner-approval key
        /// signs. The CLI checks `node` against the identity it derives.
        #[serde(default)]
        device: Option<DeviceApprovalTuple>,
    },
    /// The operation succeeded.
    Ok {
        /// What happened, for the CLI to print.
        detail: String,
    },
    /// The operation was refused. Nothing was written.
    Error {
        /// Why.
        message: String,
    },
}

/// A paired client as rendered to the owner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientSummary {
    /// Client id.
    pub client_id: String,
    /// Client name.
    pub name: String,
    /// Scopes the pairing carries.
    pub scopes: Vec<String>,
    /// Revocation epoch.
    pub epoch: u64,
}

/// What the owner-approval key signs for one device registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceApprovalTuple {
    /// Node identity fingerprint.
    pub node: String,
    /// The pairing's client public key.
    pub client_pubkey: String,
    /// The pairing epoch.
    pub epoch: u64,
    /// The device's P-256 public key, hex.
    pub device_public_key: String,
}

/// A registered device key as rendered to the owner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceKeySummary {
    /// Key id.
    pub key_id: String,
    /// Short fingerprint.
    pub fingerprint: String,
    /// Client it belongs to.
    pub client_id: String,
    /// Device name.
    pub name: String,
    /// Unix seconds it was approved.
    pub registered_at: i64,
}

/// A device key awaiting the owner, as rendered to the owner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingDeviceKeySummary {
    /// Operation id.
    pub op_id: String,
    /// Short fingerprint to compare with the app's screen.
    pub fingerprint: String,
    /// Requesting client.
    pub client_id: String,
    /// Requesting client's name.
    pub client_name: String,
    /// Device name.
    pub name: String,
    /// Unix seconds after which it can no longer be approved.
    pub expires_at: i64,
    /// Cancelled by wrong codes.
    #[serde(default)]
    pub lost: bool,
}

/// A live `front_door` grant as rendered to the owner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontDoorGrantSummary {
    /// Operation the owner confirmed.
    pub op_id: String,
    /// Client holding it.
    pub client_id: String,
    /// Unix seconds after which it is inert.
    pub expires_at: i64,
}

/// A pending elevation as rendered to the owner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingSummary {
    /// Operation id.
    pub op_id: String,
    /// Requesting client id.
    pub client_id: String,
    /// Requesting client name.
    pub client_name: String,
    /// Scopes requested.
    pub scopes: Vec<String>,
    /// Unix seconds after which it can no longer be confirmed.
    pub expires_at: i64,
    /// Made before this node run (or cancelled by wrong codes): nothing can
    /// approve it any more, and the app must ask again.
    #[serde(default)]
    pub lost: bool,
}

/// A pending replacement approval as rendered to the owner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplacementSummary {
    /// Operation id — field 1.
    pub op_id: String,
    /// Requesting client — field 2.
    pub client_id: String,
    /// Requesting client name.
    pub client_name: String,
    /// Identity being replaced — field 3.
    pub current_identity_fingerprint: String,
    /// Destination identity — field 4.
    pub replacement_identity_fingerprint: String,
    /// Expiry — field 5.
    pub expires_at: i64,
    /// Whether the owner already confirmed it.
    pub approved: bool,
}

/// What the owner's side of the socket acts on.
///
/// Carries the two things a replacement needs and HTTP must never supply: the
/// fingerprint of the identity actually running, and the data directory the new
/// identity material is written into.
pub struct ControlContext {
    /// Pairing state for this data directory.
    pub service: Arc<PairingService>,
    /// Fingerprint of the running identity.
    pub identity_fingerprint: String,
    /// Node data directory.
    pub data_dir: PathBuf,
    /// Actual configured identity path, including the bootstrap identity directory.
    pub mnemonic_path: PathBuf,
    /// Resolved node storage/key dependencies; never supplied by the requester.
    pub replacement_guard: ReplacementGuard,
}

/// Refuse phrase-file replacement when it would strand wallet or storage keys.
/// This is a refusal policy, not a channel-close or database migration procedure.
pub struct ReplacementGuard {
    /// Same resolved layout used by startup, including external state paths.
    pub layout: crate::bootstrap::DataDirLayout,
    /// LDK entropy or encrypted storage uses the running identity's seed.
    pub uses_identity_derived_keys: bool,
    /// The replacement fingerprint API does not support a BIP-39 passphrase.
    pub has_identity_passphrase: bool,
}

impl ReplacementGuard {
    /// Check before approval or consumption; never consult balance.
    pub fn ensure_replaceable(&self) -> Result<(), String> {
        if self.has_identity_passphrase {
            return Err("identity replacement with a BIP-39 passphrase is unsupported; no approval consumed".into());
        }
        if self.uses_identity_derived_keys {
            return Err(Self::refusal());
        }
        let probe = crate::bootstrap::DataDirProbe::inspect(&self.layout).map_err(|_| {
            "cannot establish that existing wallet/store state is absent; no approval consumed"
                .to_string()
        })?;
        if probe.wallet_or_channel_state_present || !probe.store_readable {
            return Err(Self::refusal());
        }
        Ok(())
    }

    fn refusal() -> String {
        "identity replacement refused: changing the mnemonic can strand Lightning channel monitors and make encrypted history unreadable. This command cannot close channels or migrate/rekey storage. Preserve the existing identity and backups; an explicit operator recovery/migration procedure is required. No approval consumed and no files changed".into()
    }
}

/// Handle one control request.
///
/// Pure request/response so the typed-confirmation rules can be tested without
/// a socket, and so the socket server has no policy of its own.
///
/// Spend elevation and identity replacement are reachable only through owner
/// control: `grant_elevation`, `approve_replacement` and
/// `consume_replacement_approval` each refuse unless owner-run mode put a
/// `0600` socket on disk, and the identity write lives in this function rather
/// than in any handler.
pub fn handle(ctx: &ControlContext, req: ControlRequest) -> ControlResponse {
    let service: &PairingService = &ctx.service;
    match req {
        ControlRequest::Status => {
            let file = service.snapshot();
            ControlResponse::Status {
                clients: file
                    .clients
                    .iter()
                    .map(|c| ClientSummary {
                        client_id: c.client_id.clone(),
                        name: c.name.clone(),
                        scopes: c.scopes.iter().map(|s| s.as_str().to_string()).collect(),
                        epoch: c.epoch,
                    })
                    .collect(),
                pending_elevations: file
                    .pending_elevations
                    .iter()
                    .map(|e| PendingSummary {
                        op_id: e.op_id.clone(),
                        client_id: e.client_id.clone(),
                        client_name: e.client_name.clone(),
                        scopes: e.scopes.iter().map(|s| s.as_str().to_string()).collect(),
                        expires_at: e.expires_at,
                        lost: e.expires_at > chrono::Utc::now().timestamp()
                            && !service.elevation_confirmable(&e.op_id),
                    })
                    .collect(),
                pending_replacements: file
                    .replacement_approvals
                    .iter()
                    .map(|a| ReplacementSummary {
                        op_id: a.op_id.clone(),
                        client_id: a.client_id.clone(),
                        client_name: a.client_name.clone(),
                        current_identity_fingerprint: a.current_identity_fingerprint.clone(),
                        replacement_identity_fingerprint: a
                            .replacement_identity_fingerprint
                            .clone(),
                        expires_at: a.expires_at,
                        approved: a.approved,
                    })
                    .collect(),
                grants: service.grant_views(),
                front_door_grants: service
                    .front_door_grants()
                    .into_iter()
                    .map(|g| FrontDoorGrantSummary {
                        op_id: g.op_id,
                        client_id: g.client_id,
                        expires_at: g.expires_at,
                    })
                    .collect(),
                device_keys: service
                    .device_keys()
                    .into_iter()
                    .map(|k| DeviceKeySummary {
                        fingerprint: crate::pairing::device::key_fingerprint(&k.key_id),
                        key_id: k.key_id,
                        client_id: k.client_id,
                        name: k.name,
                        registered_at: k.registered_at,
                    })
                    .collect(),
                pending_device_keys: service
                    .pending_device_keys()
                    .into_iter()
                    .filter(|p| p.expires_at > chrono::Utc::now().timestamp())
                    .map(|p| PendingDeviceKeySummary {
                        lost: !service.elevation_confirmable(&p.op_id),
                        fingerprint: crate::pairing::device::key_fingerprint(&p.key_id),
                        op_id: p.op_id,
                        client_id: p.client_id,
                        client_name: p.client_name,
                        name: p.name,
                        expires_at: p.expires_at,
                    })
                    .collect(),
            }
        }
        ControlRequest::Describe { op_id } => describe(service, &op_id),
        ControlRequest::Grant {
            op_id,
            confirmation,
            terms,
        } => match service.grant_elevation(&op_id, &confirmation, terms) {
            Ok(g) => ControlResponse::Ok {
                detail: format!(
                    "granted {} to client {} until {} (epoch {}): {} sats, at most {} sats per \
                     call. Revoke any time with: konsensus grant-revoke --client-id {}",
                    g.scopes
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join("+"),
                    g.client_id,
                    g.expires_at,
                    g.epoch,
                    g.budget
                        .as_ref()
                        .map(|b| spend_budget::sats(b.budget_msat))
                        .unwrap_or_default(),
                    g.budget
                        .as_ref()
                        .map(|b| spend_budget::sats(b.per_call_max_msat))
                        .unwrap_or_default(),
                    g.client_id,
                ),
            },
            Err(e) => error(e),
        },
        ControlRequest::GrantFrontDoor {
            op_id,
            confirmation,
            ttl_secs,
        } => match service.grant_front_door(&op_id, &confirmation, ttl_secs) {
            Ok(g) => ControlResponse::Ok {
                detail: format!(
                    "granted front_door to client {} until {} (epoch {}): it may publish or \
                     update this node's front-door card and nothing else; it moves no value. \
                     Revoke any time with: konsensus grant-revoke --client-id {}",
                    g.client_id, g.expires_at, g.epoch, g.client_id,
                ),
            },
            Err(e) => error(e),
        },
        ControlRequest::ApproveFirstContact {
            client_id, grant_op_id, recipient, max_total_msat, contact_budget_msat,
        } => match service.grant_first_contact(
            &client_id, &grant_op_id, &recipient, max_total_msat, contact_budget_msat,
        ) {
            Ok(grant) => ControlResponse::Ok {
                detail: format!("approved first contact for client {client_id}, grant {grant_op_id}, recipient {}, maximum {} msat; expires at {} (single use)",
                    grant.recipient, grant.max_total_msat, grant.expires_at),
            },
            Err(e) => ControlResponse::Error { message: e.to_string() },
        },
        ControlRequest::ApproveGift { .. } => ControlResponse::Error {
            message: "gift approval requires the running node's sponsor service".into(),
        },
        ControlRequest::ApproveDeviceKey { op_id, confirmation, owner_signature } => {
            match service.approve_device_key(&op_id, &confirmation, &owner_signature) {
                Ok(k) => ControlResponse::Ok {
                    detail: format!(
                        "registered device key {} ({:?}) for client {}. The app can now open \
                         per-contact spend envelopes with Touch ID; each one is a signature the \
                         node checks. Revoke any time with: konsensus device revoke --key {}",
                        crate::pairing::device::key_fingerprint(&k.key_id),
                        k.name,
                        k.client_id,
                        k.key_id
                    ),
                },
                Err(e) => error(e),
            }
        }
        ControlRequest::RevokeDeviceKey { key_id } => match service.revoke_device_key(&key_id, None) {
            Ok(()) => ControlResponse::Ok {
                detail: format!(
                    "revoked device key {key_id}; its client's relation envelopes stop on the next request"
                ),
            },
            Err(e) => error(e),
        },
        ControlRequest::RevokeGrant { client_id } => {
            match service.revoke_grants(client_id.as_deref()) {
                Ok(n) => ControlResponse::Ok {
                    detail: format!(
                        "revoked {n} grant(s){} (spend and front_door) — they stop on the client's next request",
                        client_id
                            .map(|id| format!(" for {id}"))
                            .unwrap_or_default()
                    ),
                },
                Err(e) => error(e),
            }
        }
        ControlRequest::ApproveReplacement {
            op_id,
            confirmation,
            mnemonic,
        } => approve_and_execute_replacement(ctx, &op_id, &confirmation, &mnemonic),
        ControlRequest::Revoke {
            client_id,
            keep_pairing,
        } => {
            let outcome = if keep_pairing {
                service.bump_epoch(&client_id).map(|epoch| {
                    format!("bumped pairing epoch for {client_id} to {epoch} — every outstanding token for it is now rejected")
                })
            } else {
                service
                    .revoke(&client_id)
                    .map(|()| format!("revoked pairing {client_id}"))
            };
            match outcome {
                Ok(detail) => ControlResponse::Ok { detail },
                Err(e) => error(e),
            }
        }
        ControlRequest::OpenWindow { seconds } => {
            let until = service.open_pairing_window(std::time::Duration::from_secs(seconds));
            ControlResponse::Ok {
                detail: format!("pairing window open until {until}"),
            }
        }
    }
}

/// Approve, consume and execute a live-identity replacement, in that order.
///
/// The ordering is the safety property:
///
/// 1. Derive the destination fingerprint from the phrase the owner supplied and
///    check it against the fingerprint the pending record was bound to. A
///    mismatch stops here, before the owner's confirmation is spent.
/// 2. Record the owner's consent (`approve_replacement`) — the typed phrase
///    must name this `op_id`.
/// 3. Consume the approval by atomic compare-and-delete, re-checking all five
///    bound fields including the expiry. Exactly one consumption can succeed.
/// 4. Only then write the identity material.
///
/// A failure at any step leaves no identity material on disk, which is what the
/// seven negative tests assert by effect rather than by status code.
fn approve_and_execute_replacement(
    ctx: &ControlContext,
    op_id: &str,
    confirmation: &str,
    mnemonic: &str,
) -> ControlResponse {
    let service: &PairingService = &ctx.service;
    if let Err(message) = ctx.replacement_guard.ensure_replaceable() {
        return ControlResponse::Error { message };
    }
    if ctx
        .mnemonic_path
        .extension()
        .is_some_and(|ext| ext == "enc")
    {
        return ControlResponse::Error {
            message: "encrypted identity replacement requires operator-managed re-encryption; no approval consumed".into(),
        };
    }

    let Some(pending) = service.replacement_approval(op_id) else {
        return ControlResponse::Error {
            message: format!("no pending operation with id {op_id}"),
        };
    };

    let replacement_fp = match crate::pairing::fingerprint_for_mnemonic(mnemonic) {
        Ok(fp) => fp,
        Err(e) => return error(e),
    };
    if replacement_fp != pending.replacement_identity_fingerprint {
        return ControlResponse::Error {
            message: format!(
                "the recovery phrase supplied derives identity {replacement_fp}, but this \
                 operation is bound to {}. Nothing was written.",
                pending.replacement_identity_fingerprint
            ),
        };
    }

    if let Err(e) = service.approve_replacement(op_id, confirmation) {
        return error(e);
    }

    let consumed = match service.consume_replacement_approval(
        op_id,
        &pending.client_id,
        &ctx.identity_fingerprint,
        &replacement_fp,
    ) {
        Ok(c) => c,
        Err(e) => return error(e),
    };

    // The write. Mode `0600`, in the data directory, and only after a consumed
    // approval — there is no other code path in the node that performs it.
    let path = &ctx.mnemonic_path;
    if let Err(e) = write_protected(path, mnemonic.as_bytes()) {
        return ControlResponse::Error {
            message: format!(
                "approval {op_id} was consumed but writing the identity material to {} failed: \
                 {e}. Re-request the replacement; nothing was partially applied.",
                path.display()
            ),
        };
    }

    ControlResponse::Ok {
        detail: format!(
            "replaced identity {} with {} for client {} (op {}). Restart the node for the new \
             identity to take effect — this command does not start or stop a node.",
            consumed.current_identity_fingerprint,
            consumed.replacement_identity_fingerprint,
            consumed.client_id,
            consumed.op_id
        ),
    }
}

fn error(e: PairingError) -> ControlResponse {
    ControlResponse::Error {
        message: e.to_string(),
    }
}

fn describe(service: &PairingService, op_id: &str) -> ControlResponse {
    let file = service.snapshot();
    // Say so before the owner reads terms and types a code that cannot work.
    let now = chrono::Utc::now().timestamp();
    if let Some(op) = file.pending_elevations.iter().find(|e| e.op_id == op_id) {
        if op.expires_at <= now {
            return error(PairingError::Expired);
        }
        if !service.elevation_confirmable(op_id) {
            return error(PairingError::ConfirmationLost);
        }
    }
    if let Some(op) = file
        .pending_elevations
        .iter()
        .find(|e| e.op_id == op_id && e.scopes.contains(&crate::auth::Scope::FrontDoor))
    {
        let summary = format!(
            "FRONT DOOR PUBLISH REQUEST\n  operation:   {}\n  client:      {} ({})\n  scopes:      \
             front_door\n  request expires at:  {}\n\nGranting this lets that client publish or \
             update THIS NODE'S FRONT-DOOR CARD, signed with the node's key: the display name, \
             profile, links and the prices shown on the card. It moves no value, reaches no \
             other route, and lasts until the window closes (1 h unless you pass --for, 24 h at \
             most). Revoke with konsensus grant-revoke.",
            op.op_id, op.client_name, op.client_id, op.expires_at
        );
        return ControlResponse::Describe {
            confirmation_label: grant_confirmation_phrase(op),
            summary,
            proposed_terms: None,
            front_door: true,
            device: None,
        };
    }
    if let Some(op) = file.pending_elevations.iter().find(|e| e.op_id == op_id) {
        let proposal = match &op.proposed_terms {
            Some(t) => format!(
                "\n\nThe client proposes:\n{}",
                spend_budget::describe_terms(t)
            ),
            None => "\n\nThe client proposed no budget; you set it.".to_string(),
        };
        let summary = format!(
            "SPEND BUDGET REQUEST\n  operation:   {}\n  client:      {} ({})\n  scopes:      {}\n  \
             request expires at:  {}{proposal}\n\nGranting this lets that client MOVE VALUE \
             without asking again, up to the budget you set, until the window closes (24 h at \
             most). The node debits every paid call before it pays and refuses with \
             budget_exceeded once the budget is spent.",
            op.op_id,
            op.client_name,
            op.client_id,
            op.scopes
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("+"),
            op.expires_at
        );
        return ControlResponse::Describe {
            confirmation_label: grant_confirmation_phrase(op),
            summary,
            proposed_terms: op.proposed_terms.clone(),
            front_door: false,
            device: None,
        };
    }
    if let Some(p) = file.pending_device_keys.iter().find(|p| p.op_id == op_id) {
        if p.expires_at <= now {
            return error(PairingError::Expired);
        }
        if !service.elevation_confirmable(op_id) {
            return error(PairingError::ConfirmationLost);
        }
        let summary = format!(
            "DEVICE KEY REGISTRATION\n  operation:    {}\n  client:       {} ({})\n  device:       \
             {:?}\n  fingerprint:  {}\n  expires at:   {}\n\nCompare the fingerprint with the \
             one the app shows. Approving lets that device open per-contact spend envelopes \
             on this node by signing them (Touch ID on the device, for each one), without \
             coming back to this terminal. Each envelope is capped per contact, per act and \
             in time, and the node checks every signature. Revoke with: konsensus device \
             revoke --key {}.",
            p.op_id,
            p.client_name,
            p.client_id,
            p.name,
            crate::pairing::device::key_fingerprint(&p.key_id),
            p.expires_at,
            p.key_id
        );
        return ControlResponse::Describe {
            confirmation_label: crate::pairing::device_confirmation_phrase(p),
            summary,
            proposed_terms: None,
            front_door: false,
            device: Some(DeviceApprovalTuple {
                node: service.bound_fingerprint(),
                // The pairing's key now, not at request time: the signature must
                // match the pairing the node will check it against.
                client_pubkey: file
                    .clients
                    .iter()
                    .find(|c| c.client_id == p.client_id)
                    .map(|c| c.client_pubkey.clone())
                    .unwrap_or_default(),
                epoch: p.epoch,
                device_public_key: p.public_key.clone(),
            }),
        };
    }
    if let Some(a) = file.replacement_approvals.iter().find(|a| a.op_id == op_id) {
        let summary = format!(
            "LIVE IDENTITY REPLACEMENT\n  operation:    {}\n  client:       {} ({})\n  \
             current id:   {}\n  replacement:  {}\n  expires at:   {}\n\nThis REPLACES the \
             identity of a node that may hold funds and relationships. The destination \
             identity above was computed from the recovery phrase the client supplied — \
             approving binds this operation to that one identity and nothing else.\n\n\
             WARNING: replacing a mnemonic changes Lightning and storage keys. This command \
             refuses nodes using LDK/encrypted storage or carrying existing state; it does \
             not close channels or migrate/rekey history.",
            a.op_id,
            a.client_name,
            a.client_id,
            a.current_identity_fingerprint,
            a.replacement_identity_fingerprint,
            a.expires_at
        );
        return ControlResponse::Describe {
            confirmation_label: replacement_confirmation_phrase(a),
            summary,
            proposed_terms: None,
            front_door: false,
            device: None,
        };
    }
    ControlResponse::Error {
        message: format!("no pending operation with id {op_id}"),
    }
}

/// The owner control socket server.
///
/// Unix only. On a platform without Unix domain sockets there is no owner
/// channel, and elevation is therefore unavailable rather than approximated by
/// a weaker one.
#[cfg(unix)]
pub struct ControlServer {
    path: PathBuf,
    listener: tokio::net::UnixListener,
    ctx: Arc<ControlContext>,
    approval_state: Option<Arc<crate::state::AppState>>,
}

#[cfg(unix)]
impl ControlServer {
    /// Bind `<data_dir>/control.sock` at mode `0600`.
    ///
    /// A stale socket from a previous run is removed first — a socket file left
    /// by a crashed node must not make the owner channel permanently
    /// unavailable. The mode is set immediately after bind and verified by
    /// `tests/pairing_tests.rs::owner_control_socket_permissions`.
    pub fn bind(data_dir: &Path, ctx: Arc<ControlContext>) -> std::io::Result<Self> {
        let path = data_dir.join(SOCKET_FILE);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        let listener = tokio::net::UnixListener::bind(&path)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::info!(
            socket = %path.display(),
            "owner control socket listening (mode 0600) — the only channel that can write a grant"
        );
        Ok(Self {
            path,
            listener,
            ctx,
            approval_state: None,
        })
    }

    /// Attach the running node's services for owner-local sponsor approval.
    /// This does not expose an HTTP route or issue a transferable credential.
    pub fn with_approval_state(mut self, state: Arc<crate::state::AppState>) -> Self {
        self.approval_state = Some(state);
        self
    }

    /// The socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serve until `shutdown_rx` fires.
    pub async fn serve(self, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok((stream, _addr)) => {
                            let ctx = Arc::clone(&self.ctx);
                            let approval_state = self.approval_state.clone();
                            tokio::spawn(async move {
                                if let Err(e) = serve_connection(stream, ctx, approval_state).await {
                                    tracing::warn!(error = %e, "control socket connection failed");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "control socket accept failed");
                            break;
                        }
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Delete expired grants at their next deadline, on startup and after changes.
/// Reads independently purge expired records. Failed deletions remain queued
/// and are retried, including when no API request arrives.
pub async fn sweep_expired_grants(
    service: Arc<PairingService>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        let delay = match service.prune_expired_grants() {
            Ok(n) => {
                if n > 0 {
                    tracing::info!(removed = n, "expired spend grants removed");
                }
                service.grant_cleanup_delay()
            }
            Err(e) => {
                tracing::warn!(error = %e, "expired spend grant cleanup failed");
                std::time::Duration::from_secs(1)
            }
        };
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            _ = service.grant_changed() => {},
            _ = tokio::time::sleep(delay) => {},
        }
    }
    // Shutdown is a cleanup opportunity even if signalled before our first
    // poll or while we slept. Live grants and their tallies survive restart.
    if let Err(e) = service.prune_expired_grants() {
        tracing::warn!(error = %e, "expired spend grant cleanup failed at shutdown");
    }
}

/// One newline-delimited JSON request, one newline-delimited JSON response.
#[cfg(unix)]
async fn serve_connection(
    stream: tokio::net::UnixStream,
    ctx: Arc<ControlContext>,
    approval_state: Option<Arc<crate::state::AppState>>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<ControlRequest>(&line) {
            Ok(req) => handle_local(&ctx, approval_state.as_ref(), req).await,
            Err(e) => ControlResponse::Error {
                message: format!("malformed control request: {e}"),
            },
        };
        let mut bytes = serde_json::to_vec(&response).unwrap_or_else(|_| {
            br#"{"result":"error","message":"failed to encode response"}"#.to_vec()
        });
        bytes.push(b'\n');
        write_half.write_all(&bytes).await?;
        write_half.flush().await?;
    }
    Ok(())
}

// Keep wire encoding at the transport boundary: the secret-bearing request
// deliberately does not implement Serialize, Debug, or Clone.
#[cfg(unix)]
fn encode_request(req: &ControlRequest) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
    use serde::ser::{SerializeMap, Serializer};

    let mut bytes = Zeroizing::new(Vec::new());
    let mut serializer = serde_json::Serializer::new(&mut *bytes);
    let mut map = serializer.serialize_map(None)?;
    macro_rules! fields {
        ($op:literal $(, $field:ident)* $(,)?) => {{
            map.serialize_entry("op", $op)?;
            $(map.serialize_entry(stringify!($field), $field)?;)*
        }};
    }
    match req {
        ControlRequest::Status => fields!("status"),
        ControlRequest::Describe { op_id } => fields!("describe", op_id),
        ControlRequest::Grant {
            op_id,
            confirmation,
            terms,
        } => fields!("grant", op_id, confirmation, terms),
        ControlRequest::GrantFrontDoor {
            op_id,
            confirmation,
            ttl_secs,
        } => fields!("grant-front-door", op_id, confirmation, ttl_secs),
        ControlRequest::ApproveFirstContact {
            client_id,
            grant_op_id,
            recipient,
            max_total_msat,
            contact_budget_msat,
        } => fields!(
            "approve-first-contact",
            client_id,
            grant_op_id,
            recipient,
            max_total_msat,
            contact_budget_msat
        ),
        ControlRequest::ApproveGift {
            intro_id,
            newcomer,
            payment_hash,
            gift_msat,
            fee_max_msat,
            code,
        } => fields!(
            "approve-gift",
            intro_id,
            newcomer,
            payment_hash,
            gift_msat,
            fee_max_msat,
            code
        ),
        ControlRequest::ApproveDeviceKey {
            op_id,
            confirmation,
            owner_signature,
        } => fields!("approve-device-key", op_id, confirmation, owner_signature),
        ControlRequest::RevokeDeviceKey { key_id } => fields!("revoke-device-key", key_id),
        ControlRequest::RevokeGrant { client_id } => fields!("revoke-grant", client_id),
        ControlRequest::ApproveReplacement {
            op_id,
            confirmation,
            mnemonic,
        } => {
            fields!("approve-replacement", op_id, confirmation);
            map.serialize_entry("mnemonic", mnemonic.as_str())?;
        }
        ControlRequest::Revoke {
            client_id,
            keep_pairing,
        } => fields!("revoke", client_id, keep_pairing),
        ControlRequest::OpenWindow { seconds } => fields!("open-window", seconds),
    }
    map.end()?;
    Ok(bytes)
}

/// Send one request to a node's control socket and read the reply.
///
/// Used by the owner CLI. Connecting requires the ability to open a `0600`
/// socket owned by the node user — which is the point.
#[cfg(unix)]
pub async fn send(socket: &Path, req: &ControlRequest) -> std::io::Result<ControlResponse> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let stream = tokio::net::UnixStream::connect(socket).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut bytes = encode_request(req)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    bytes.push(b'\n');
    write_half.write_all(&bytes).await?;
    write_half.flush().await?;

    let mut lines = BufReader::new(read_half).lines();
    let line = lines.next_line().await?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "control socket closed without a response",
        )
    })?;
    serde_json::from_str(&line).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Socket-only dispatch. HTTP authentication never calls this function.
#[cfg(unix)]
async fn handle_local(
    ctx: &ControlContext,
    state: Option<&Arc<crate::state::AppState>>,
    req: ControlRequest,
) -> ControlResponse {
    let ControlRequest::ApproveGift {
        intro_id, newcomer, payment_hash, gift_msat, fee_max_msat, code,
    } = req else {
        return handle(ctx, req);
    };
    let Some(state) = state.filter(|state| {
        ctx.service.owner_control_enabled()
            && state.pairing.as_ref().is_some_and(|service| Arc::ptr_eq(service, &ctx.service))
    }) else {
        return ControlResponse::Error { message: "owner sponsor service unavailable".into() };
    };
    let body = crate::handlers::sponsor::ApproveRequest {
        intro_id, newcomer, payment_hash, gift_msat, fee_max_msat, code,
    };
    let auth = crate::metered::MeteredSpend::owner_control(state);
    match crate::handlers::sponsor::approve_owner(auth, Arc::clone(state), body).await {
        Ok(axum::Json(paid)) => ControlResponse::Ok {
            detail: format!("gift {}: {:?}; paid {} msat, fee {} msat, payment hash {}",
                paid.intro_id, paid.state, paid.paid_msat, paid.fee_paid_msat, paid.payment_hash),
        },
        Err(e) => ControlResponse::Error { message: e.to_string() },
    }
}

#[cfg(all(test, unix))]
mod wire_tests {
    use super::*;

    #[test]
    fn transport_encoding_preserves_all_request_variants() {
        let fixtures = [
            r#"{"op":"status"}"#,
            r#"{"op":"describe","op_id":"test"}"#,
            r#"{"op":"grant","op_id":"test","confirmation":"yes","terms":{"allow_liquidity_fees":false,"budget_msat":1000,"per_call_max_msat":100,"per_recipient_msat":{},"ttl_secs":60}}"#,
            r#"{"op":"grant-front-door","op_id":"test","confirmation":"yes","ttl_secs":60}"#,
            r#"{"op":"approve-first-contact","client_id":"client","grant_op_id":"grant","recipient":"recipient","max_total_msat":100,"contact_budget_msat":null}"#,
            r#"{"op":"approve-gift","intro_id":"intro","newcomer":"node","payment_hash":"hash","gift_msat":100,"fee_max_msat":1,"code":"123456"}"#,
            r#"{"op":"approve-device-key","op_id":"test","confirmation":"yes","owner_signature":"sig"}"#,
            r#"{"op":"revoke-device-key","key_id":"key"}"#,
            r#"{"op":"revoke-grant","client_id":null}"#,
            r#"{"op":"approve-replacement","op_id":"test","confirmation":"yes","mnemonic":"abandon \" \\ \n about"}"#,
            r#"{"op":"revoke","client_id":"client","keep_pairing":false}"#,
            r#"{"op":"open-window","seconds":60}"#,
        ];
        for fixture in fixtures {
            let request: ControlRequest = serde_json::from_str(fixture).unwrap();
            let bytes: Zeroizing<Vec<u8>> = encode_request(&request).unwrap();
            let round_trip: ControlRequest = serde_json::from_slice(&bytes).unwrap();
            assert!(request == round_trip);
            let expected: serde_json::Value = serde_json::from_str(fixture).unwrap();
            let actual: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(actual, expected);
        }
    }
}
