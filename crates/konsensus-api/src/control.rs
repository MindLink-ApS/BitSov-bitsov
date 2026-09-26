//! The owner control socket: the only channel that can write a grant (#76, P1-2).
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
//! port-forward. There is no authenticated HTTP endpoint that does what this
//! socket does, because the requesting app could call it.
//!
//! # Consent is the typed phrase, not the connection
//!
//! The node never treats "a message arrived on the socket" as consent. Each
//! elevation/replacement request must carry an operation-bound random nonce
//! printed only to the owner node's terminal. HTTP, socket status, and files
//! expose no nonce. Same-uid socket access alone is insufficient.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::pairing::{
    grant_confirmation_phrase, replacement_confirmation_phrase, write_protected, PairingError,
    PairingService,
};

/// Socket file name inside the data directory.
pub const SOCKET_FILE: &str = "control.sock";

/// A request from the owner CLI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum ControlRequest {
    /// List pairings, pending elevations and pending approvals.
    Status,
    /// Render one pending operation so the CLI can show it before asking.
    Describe {
        /// Pending operation id.
        op_id: String,
    },
    /// Write a spend grant for a pending elevation request.
    Grant {
        /// Pending operation id.
        op_id: String,
        /// The phrase the owner typed. Must name `op_id`.
        confirmation: String,
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
        mnemonic: String,
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
    },
    /// A rendered pending operation and public label, never its secret nonce.
    Describe {
        /// Human-readable summary the CLI prints verbatim.
        summary: String,
        /// Public label to match against the owner node's console.
        confirmation_label: String,
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
/// Every mutating arm below is reachable ONLY from here. There is no HTTP path
/// into any of them: `grant_elevation`, `approve_replacement` and
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
            }
        }
        ControlRequest::Describe { op_id } => describe(service, &op_id),
        ControlRequest::Grant {
            op_id,
            confirmation,
        } => match service.grant_elevation(&op_id, &confirmation) {
            Ok(g) => ControlResponse::Ok {
                detail: format!(
                    "granted {} to client {} until {} (epoch {})",
                    g.scopes
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join("+"),
                    g.client_id,
                    g.expires_at,
                    g.epoch
                ),
            },
            Err(e) => error(e),
        },
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
    if let Some(op) = file.pending_elevations.iter().find(|e| e.op_id == op_id) {
        let summary = format!(
            "ELEVATION REQUEST\n  operation:   {}\n  client:      {} ({})\n  scopes:      {}\n  \
             expires at:  {}\n\nGranting this lets that client MOVE VALUE without asking again \
             until the grant expires.",
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
        })
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
                            tokio::spawn(async move {
                                if let Err(e) = serve_connection(stream, ctx).await {
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

/// One newline-delimited JSON request, one newline-delimited JSON response.
#[cfg(unix)]
async fn serve_connection(
    stream: tokio::net::UnixStream,
    ctx: Arc<ControlContext>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<ControlRequest>(&line) {
            Ok(req) => handle(&ctx, req),
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

/// Send one request to a node's control socket and read the reply.
///
/// Used by the owner CLI. Connecting requires the ability to open a `0600`
/// socket owned by the node user — which is the point.
#[cfg(unix)]
pub async fn send(socket: &Path, req: &ControlRequest) -> std::io::Result<ControlResponse> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let stream = tokio::net::UnixStream::connect(socket).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut bytes = serde_json::to_vec(req)
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
