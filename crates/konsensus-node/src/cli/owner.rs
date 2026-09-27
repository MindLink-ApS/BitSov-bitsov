//! Owner-side CLI: the control socket client, and the bootstrap serve mode (#76).
//!
//! Everything here runs on the **owner's** side of the trust boundary. The
//! commands connect to `<data-dir>/control.sock` — a Unix socket at mode `0600`
//! owned by the node user, deliberately not reachable over loopback TCP, which
//! is what excludes the attacker class this ticket is about (a browser page
//! calling localhost, another OS user, a container with host networking, an SSH
//! port-forward).
//!
//! A message arriving on that socket is not consent by itself. Each mutating
//! elevation/replacement command renders the pending operation and requires a
//! confirmation containing the random nonce printed only to the owner node's
//! controlling terminal. The public operation id alone is not consent.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::{NodeConfig, NodeTier, StorageConfig};
use konsensus_api::bootstrap::{self, DataDirLayout, StartupMode};
use konsensus_api::control::{self, ControlRequest, ControlResponse};
use konsensus_api::pairing::PairingService;
use konsensus_api::spend_budget::{self, GrantTerms};

/// Prepare startup without constructing a wallet, node or listener.
pub fn prepare_start(config_path: &Path) -> Result<(StartupMode, NodeConfig)> {
    let data_dir = data_dir_of(config_path);
    let layout = DataDirLayout::new(&data_dir);
    let config = if config_path.try_exists()? {
        NodeConfig::load_before_identity_validation(config_path)?
    } else {
        NodeConfig::default_for_tier(
            NodeTier::Full,
            layout.identity_dir().join("mnemonic.txt"),
            &data_dir,
        )
    };
    let layout = configured_layout(&data_dir, &config);
    let probe = bootstrap::DataDirProbe::inspect(&layout)?;
    for stray in &probe.stray_staging {
        tracing::warn!(path = %stray.display(), "ignoring interrupted bootstrap staging");
    }
    let mode = match bootstrap::classify(&probe) {
        StartupMode::Refuse(r) => {
            anyhow::bail!(
                "refusing to start: {} ({}). Repair: {}",
                r.detail,
                r.reason,
                r.repair
            );
        }
        mode => mode,
    };
    if mode == StartupMode::Initialized {
        config.validate()?;
    } else {
        // Bootstrap: passphrase layouts disagree with first-run commit (empty
        // passphrase), and the bootstrap API is loopback-only.
        if !config.identity.passphrase.is_empty() {
            anyhow::bail!(
                "bootstrap does not support identity.passphrase: first-run commit derives with an \
                 empty passphrase, so a configured passphrase would produce a different live \
                 identity. Clear identity.passphrase, or initialize with `konsensus init` / \
                 `konsensus restore`."
            );
        }
        if !config.api.listen_addr.ip().is_loopback() {
            anyhow::bail!("bootstrap requires a loopback API listen address");
        }
    }
    Ok((mode, config))
}

fn configured_layout(data_dir: &Path, config: &NodeConfig) -> DataDirLayout {
    // The configured store is a connection string, not a path: the runtime
    // hands it to sqlx, which strips a `sqlite:` / `sqlite://` scheme and any
    // query parameters before opening the file. Resolve it the same way, so the
    // retained-state probe looks at the file the runtime actually created. An
    // unresolvable string (in-memory, or one the runtime would reject) is
    // treated like a remote store: it cannot be proven empty, so no bootstrap.
    let sqlite = match &config.storage {
        StorageConfig::Sqlite { path, .. } => konsensus_storage::sqlite::sqlite_file_path(path),
        StorageConfig::Postgres { .. } => None,
    };
    DataDirLayout::new(data_dir).with_configured_paths(
        config.identity.mnemonic_file.clone(),
        sqlite,
        PathBuf::from(&config.backup.scb_dir),
    )
}

#[cfg(unix)]
pub fn replacement_guard(data_dir: &Path, config: &NodeConfig) -> control::ReplacementGuard {
    let encrypted = match &config.storage {
        StorageConfig::Sqlite { encrypted, .. } | StorageConfig::Postgres { encrypted, .. } => {
            *encrypted
        }
    };
    control::ReplacementGuard {
        layout: configured_layout(data_dir, config),
        // Do not race a running LDK node's next persistence write or assume an
        // empty encrypted database makes rotating its key harmless.
        uses_identity_derived_keys: encrypted
            || matches!(config.lightning, crate::config::LightningConfig::Ldk { .. }),
        has_identity_passphrase: !config.identity.passphrase.is_empty(),
    }
}

/// The data directory is the config file's directory, matching `AppState::data_dir`.
fn data_dir_of(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn socket_path(config_path: &Path) -> PathBuf {
    data_dir_of(config_path).join(control::SOCKET_FILE)
}

#[cfg(unix)]
async fn send(config_path: &Path, req: ControlRequest) -> Result<ControlResponse> {
    let socket = socket_path(config_path);
    control::send(&socket, &req).await.with_context(|| {
        format!(
            "could not reach the owner control socket at {}.\n\
             The node must be running and must have been started with `--owner-control`.\n\
             A packaged sidecar node does not create this socket: in that deployment the app \
             is a read+receive client and elevation is unavailable by design.",
            socket.display()
        )
    })
}

#[cfg(not(unix))]
async fn send(_config_path: &Path, _req: ControlRequest) -> Result<ControlResponse> {
    anyhow::bail!(
        "the owner control socket requires Unix domain sockets, which this platform does not \
         provide. Elevation is unavailable here rather than approximated by a weaker channel."
    )
}

/// Print a response, returning an error if the node refused.
fn report(resp: ControlResponse) -> Result<()> {
    match resp {
        ControlResponse::Ok { detail } => {
            println!("{detail}");
            Ok(())
        }
        ControlResponse::Error { message } => {
            anyhow::bail!("refused: {message}")
        }
        other => {
            println!("{}", serde_json::to_string_pretty(&other)?);
            Ok(())
        }
    }
}

/// `konsensus pair-status` — what is paired, and what awaits the owner.
pub async fn cmd_pair_status(config_path: &Path) -> Result<()> {
    match send(config_path, ControlRequest::Status).await? {
        ControlResponse::Status {
            clients,
            pending_elevations,
            pending_replacements,
            grants,
        } => {
            if clients.is_empty() {
                println!("no paired clients");
            }
            for c in &clients {
                println!(
                    "client {}  name={:?}  scopes={}  epoch={}",
                    c.client_id,
                    c.name,
                    c.scopes.join("+"),
                    c.epoch
                );
            }
            for g in &grants {
                println!(
                    "SPEND GRANT client={}  {} of {} sats left  per-call<={} sats  \
                     expires_at={}\n  revoke with: konsensus grant-revoke --client-id {}",
                    g.client_id,
                    spend_budget::sats(g.remaining_msat),
                    spend_budget::sats(g.budget_msat),
                    spend_budget::sats(g.per_call_max_msat),
                    g.expires_at,
                    g.client_id
                );
            }
            for e in &pending_elevations {
                println!(
                    "PENDING ELEVATION op={}  client={} ({})  scopes={}  expires_at={}\n  \
                     approve with: konsensus grant --op {}",
                    e.op_id,
                    e.client_name,
                    e.client_id,
                    e.scopes.join("+"),
                    e.expires_at,
                    e.op_id
                );
            }
            for r in &pending_replacements {
                println!(
                    "PENDING IDENTITY REPLACEMENT op={}  client={} ({})  current={}  \
                     replacement={}  expires_at={}  approved={}\n  \
                     approve with: konsensus approve-replacement --op {}",
                    r.op_id,
                    r.client_name,
                    r.client_id,
                    r.current_identity_fingerprint,
                    r.replacement_identity_fingerprint,
                    r.expires_at,
                    r.approved,
                    r.op_id
                );
            }
            Ok(())
        }
        other => report(other),
    }
}

/// A pending operation as the socket describes it.
struct Described {
    summary: String,
    label: String,
    proposed_terms: Option<GrantTerms>,
}

async fn describe(config_path: &Path, op_id: &str) -> Result<Described> {
    match send(
        config_path,
        ControlRequest::Describe {
            op_id: op_id.to_string(),
        },
    )
    .await?
    {
        ControlResponse::Describe {
            summary,
            confirmation_label,
            proposed_terms,
        } => Ok(Described {
            summary,
            label: confirmation_label,
            proposed_terms,
        }),
        ControlResponse::Error { message } => anyhow::bail!("refused: {message}"),
        other => anyhow::bail!("unexpected control response: {other:?}"),
    }
}

/// Render a pending operation and read the owner's typed confirmation.
///
/// Only the public label comes from the socket. The unpredictable confirmation
/// must be copied from the owner-run node's terminal, never this API response.
async fn confirm_interactively(config_path: &Path, op_id: &str) -> Result<String> {
    let described = describe(config_path, op_id).await?;
    println!("\n{}\n", described.summary);
    read_confirmation(&described.label)
}

fn read_confirmation(phrase: &str) -> Result<String> {
    println!("On the owner node's console, find {phrase}.\nType its full confirmation, including CODE and the random nonce.\n");
    print!("> ");
    std::io::stdout().flush().ok();

    let mut typed = String::new();
    std::io::stdin()
        .read_line(&mut typed)
        .context("failed to read the confirmation phrase from stdin")?;
    Ok(typed.trim().to_string())
}

/// The owner's flags for `konsensus grant`.
#[derive(Debug, Default)]
pub struct GrantFlags {
    /// `--budget <sats>`.
    pub budget_sats: Option<u64>,
    /// `--for <duration>`.
    pub window: Option<String>,
    /// `--per-call <sats>`.
    pub per_call_sats: Option<u64>,
    /// `--recipient <key>=<sats>`, repeatable.
    pub recipients: Vec<String>,
    /// `--yes`: skip the terms question (never the console code).
    pub yes: bool,
}

fn sats_to_msat(sats: u64, what: &str) -> Result<u64> {
    sats.checked_mul(1000)
        .with_context(|| format!("{what} of {sats} sats is too large"))
}

/// Resolve the terms the owner is granting: each flag overrides the client's
/// proposal field by field; with neither, `--budget` is required.
pub fn resolve_terms(flags: &GrantFlags, proposal: Option<&GrantTerms>) -> Result<GrantTerms> {
    let budget_msat = match (flags.budget_sats, proposal) {
        (Some(sats), _) => sats_to_msat(sats, "--budget")?,
        (None, Some(p)) => p.budget_msat,
        (None, None) => anyhow::bail!(
            "the client proposed no budget; pass --budget <sats> (and optionally --for 24h)"
        ),
    };
    let ttl_secs = match (&flags.window, proposal) {
        (Some(w), _) => spend_budget::parse_duration(w).map_err(anyhow::Error::msg)?,
        (None, Some(p)) => p.ttl_secs,
        (None, None) => spend_budget::MAX_SPEND_GRANT_TTL_SECS,
    };
    let per_call_max_msat = match (flags.per_call_sats, proposal) {
        (Some(sats), _) => sats_to_msat(sats, "--per-call")?,
        (None, Some(p)) => p.per_call_max_msat.min(budget_msat),
        (None, None) => budget_msat,
    };
    let per_recipient_msat = if flags.recipients.is_empty() {
        proposal
            .map(|p| p.per_recipient_msat.clone())
            .unwrap_or_default()
    } else {
        let mut map = std::collections::BTreeMap::new();
        for entry in &flags.recipients {
            let (key, sats) = entry
                .split_once('=')
                .with_context(|| format!("--recipient {entry:?} must be <key>=<sats>"))?;
            let sats: u64 = sats
                .trim()
                .parse()
                .with_context(|| format!("--recipient {entry:?}: {sats:?} is not a whole number of sats"))?;
            map.insert(key.trim().to_string(), sats_to_msat(sats, "--recipient")?);
        }
        map
    };
    GrantTerms {
        budget_msat,
        per_call_max_msat,
        per_recipient_msat,
        ttl_secs,
    }
    .normalized()
    .map_err(anyhow::Error::msg)
}

/// `konsensus grant --op <id> [--budget <sats>] [--for 24h]` — write one
/// budget-scoped spend window.
pub async fn cmd_grant(config_path: &Path, op_id: &str, flags: GrantFlags) -> Result<()> {
    let described = describe(config_path, op_id).await?;
    let terms = resolve_terms(&flags, described.proposed_terms.as_ref())?;
    println!("\n{}\n", described.summary);
    println!(
        "YOU ARE GRANTING (the node debits every paid call before paying and refuses \
         with budget_exceeded when it runs out):\n{}\n",
        spend_budget::describe_terms(&terms)
    );
    if !flags.yes {
        print!("Grant these terms? [y/N] ");
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("failed to read the answer from stdin")?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            println!("not granted");
            return Ok(());
        }
    }
    let confirmation = read_confirmation(&described.label)?;
    report(
        send(
            config_path,
            ControlRequest::Grant {
                op_id: op_id.to_string(),
                confirmation,
                terms,
            },
        )
        .await?,
    )
}

/// `konsensus grant-revoke --client-id <id> | --all` — stop spend now.
pub async fn cmd_grant_revoke(config_path: &Path, client_id: Option<&str>, all: bool) -> Result<()> {
    if client_id.is_none() && !all {
        anyhow::bail!("pass --client-id <id> or --all");
    }
    report(
        send(
            config_path,
            ControlRequest::RevokeGrant {
                client_id: client_id.map(str::to_string),
            },
        )
        .await?,
    )
}

/// `konsensus approve-replacement --op <id>` — replace a LIVE identity.
pub async fn cmd_approve_replacement(
    config_path: &Path,
    op_id: &str,
    mnemonic: Option<&str>,
) -> Result<()> {
    let confirmation = confirm_interactively(config_path, op_id).await?;
    let phrase = match mnemonic {
        Some(m) => m.to_string(),
        None => {
            println!(
                "\nEnter the recovery phrase of the destination identity (input hidden).\n\
                 It is checked against the identity shown above; only an accepted replacement writes it to the identity file."
            );
            rpassword::read_password().context("failed to read the recovery phrase")?
        }
    };
    report(
        send(
            config_path,
            ControlRequest::ApproveReplacement {
                op_id: op_id.to_string(),
                confirmation,
                mnemonic: phrase.trim().to_string(),
            },
        )
        .await?,
    )
}

/// `konsensus pair-revoke --client-id <id>` — revoke a pairing.
pub async fn cmd_pair_revoke(
    config_path: &Path,
    client_id: &str,
    keep_pairing: bool,
) -> Result<()> {
    report(
        send(
            config_path,
            ControlRequest::Revoke {
                client_id: client_id.to_string(),
                keep_pairing,
            },
        )
        .await?,
    )
}

/// `konsensus pair-window --seconds <n>` — accept one more pairing.
pub async fn cmd_pair_window(config_path: &Path, seconds: u64) -> Result<()> {
    report(send(config_path, ControlRequest::OpenWindow { seconds }).await?)
}

/// `konsensus repair mark-initialized` — finish an interrupted transition.
///
/// Writes the marker and nothing else, and only when identity material is
/// actually present. This is the repair the refusal names; it is an operator
/// action precisely because a node doing it silently would make a crashed
/// transition indistinguishable from a completed one.
///
/// `config_path` is the same path `konsensus start -c` uses: the data directory
/// is derived from it, and a present config supplies the configured identity
/// layout (including a custom mnemonic path outside the data directory).
pub fn cmd_repair_mark_initialized(config_path: &Path, confirm: bool) -> Result<()> {
    let dir = data_dir_of(config_path);
    let layout = if config_path.try_exists()? {
        let config = NodeConfig::load_before_identity_validation(config_path)?;
        configured_layout(&dir, &config)
    } else {
        DataDirLayout::new(&dir)
    };
    let probe = bootstrap::DataDirProbe::inspect(&layout)
        .with_context(|| format!("failed to inspect {}", dir.display()))?;

    if probe.marker_present {
        println!(
            "{} already exists — nothing to repair.",
            layout.marker().display()
        );
        return Ok(());
    }
    if !probe.identity_material_present {
        anyhow::bail!(
            "refusing to write the marker: no identity material exists in {}. Writing it would \
             declare an empty directory initialized, which locks first-run restore out of a \
             node that never had an identity.",
            dir.display()
        );
    }
    if !confirm {
        anyhow::bail!(
            "this changes how the node classifies {} — re-run with --confirm",
            dir.display()
        );
    }

    konsensus_api::pairing::write_protected(
        &layout.marker(),
        serde_json::json!({
            "initialized_at": chrono::Utc::now().timestamp(),
            "repaired_by": "konsensus repair mark-initialized",
        })
        .to_string()
        .as_bytes(),
    )
    .with_context(|| format!("failed to write {}", layout.marker().display()))?;
    konsensus_api::pairing::fsync_dir(&layout.data_dir).ok();

    println!(
        "wrote {} — the interrupted first-run transition is now complete. Start the node as usual.",
        layout.marker().display()
    );
    Ok(())
}

/// Align a node config's mnemonic path with the identity a transition just wrote.
///
/// Uses [`NodeConfig::save`]'s atomic durable replace so the aligned config
/// reaches stable storage before the caller publishes `NODE_INITIALIZED`.
fn align_config_mnemonic(config_path: &Path, mnemonic_path: &Path) -> Result<()> {
    if !config_path.try_exists()? {
        return Ok(());
    }
    let mut updated = NodeConfig::load_before_identity_validation(config_path)?;
    if updated.identity.mnemonic_file != mnemonic_path {
        updated.identity.mnemonic_file = mnemonic_path.to_path_buf();
        updated
            .save(config_path)
            .with_context(|| format!("failed to update {}", config_path.display()))?;
    }
    Ok(())
}

/// Serve the identity-free bootstrap API.
///
/// Returns the committed identity when a first-run create or restore lands. The
/// caller does **not** continue into live operation with it: the node is never
/// auto-started off the back of an API call, the operator starts it.
///
/// `config_path` is the real `-c` path the operator started with. The transition
/// durably aligns that file with the committed mnemonic **before** publishing
/// the success marker, so a completed bootstrap is always restartable with the
/// same filename.
pub async fn serve_bootstrap_mode(config_path: &Path, config: &NodeConfig) -> Result<()> {
    if !config.identity.passphrase.is_empty() {
        anyhow::bail!(
            "bootstrap does not support identity.passphrase: first-run commit derives with an \
             empty passphrase, so a configured passphrase would produce a different live \
             identity. Clear identity.passphrase, or initialize with `konsensus init` / \
             `konsensus restore`."
        );
    }
    let api_addr = config.api.listen_addr;
    let data_dir = data_dir_of(config_path);
    let layout = configured_layout(&data_dir, config);
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("failed to create {}", data_dir.display()))?;

    // No identity exists, so the pairing service binds to the empty
    // fingerprint; the transition commit rebinds every record to the committed
    // identity. Owner control is off: there is nothing to elevate on a node
    // with no keys, and first-run authority is already scoped to bootstrap.
    let pairing = std::sync::Arc::new(
        PairingService::open(&data_dir, String::new(), false)
            .map_err(|e| anyhow::anyhow!("failed to open pairing state: {e}"))?,
    );
    let align_path = config_path.to_path_buf();
    let state = std::sync::Arc::new(
        konsensus_api::bootstrap::BootstrapState::new(layout, pairing).with_before_marker(
            move |outcome| {
                align_config_mnemonic(&align_path, &outcome.mnemonic_path).map_err(|e| {
                    konsensus_api::bootstrap::CommitError::Io(e.to_string())
                })
            },
        ),
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = shutdown_tx.send(true);
        }
    });

    println!(
        "This node has no identity yet. Only the pairing ceremony and a one-time \
         create/restore are reachable on {api_addr}."
    );

    let outcome = konsensus_api::bootstrap::serve_bootstrap(api_addr, state, shutdown_rx)
        .await
        .map_err(|e| anyhow::anyhow!("bootstrap API failed: {e}"))?;

    match outcome {
        Some(o) => {
            println!(
                "identity committed: node {} (fingerprint {}).\n\
                 Mnemonic written to {}.\n\
                 Start the node normally to bring it online — bootstrap does not start a live node.",
                o.node_id,
                o.identity_fingerprint,
                o.mnemonic_path.display()
            );
            Ok(())
        }
        None => {
            println!("bootstrap ended without an identity being committed");
            Ok(())
        }
    }
}

#[cfg(test)]
mod startup_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn replacement_policy_uses_actual_node_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default_for_tier(
            NodeTier::Full,
            dir.path().join("mnemonic.txt"),
            dir.path(),
        );
        assert!(replacement_guard(dir.path(), &config)
            .ensure_replaceable()
            .is_err());
        // LDK alone is enough, even before its next write creates state.
        if let StorageConfig::Sqlite { encrypted, .. } = &mut config.storage {
            *encrypted = false;
        }
        assert!(replacement_guard(dir.path(), &config)
            .ensure_replaceable()
            .is_err());
        config.lightning = crate::config::LightningConfig::Mock {
            initial_balance_msat: 0,
        };
        assert!(replacement_guard(dir.path(), &config)
            .ensure_replaceable()
            .is_ok());
        if let StorageConfig::Sqlite { encrypted, .. } = &mut config.storage {
            *encrypted = true;
        }
        assert!(replacement_guard(dir.path(), &config)
            .ensure_replaceable()
            .is_err());
        if let StorageConfig::Sqlite { encrypted, .. } = &mut config.storage {
            *encrypted = false;
        }
        config.identity.passphrase = "public test passphrase".into();
        assert!(replacement_guard(dir.path(), &config)
            .ensure_replaceable()
            .is_err());
        config.identity.passphrase.clear();
        config.storage = StorageConfig::Postgres {
            url: "postgres://unused.invalid/test".into(),
            encrypted: false,
            retention_days: 0,
        };
        assert!(replacement_guard(dir.path(), &config)
            .ensure_replaceable()
            .is_err());
    }

    #[test]
    fn empty_install_prepares_bootstrap_without_identity_or_config() {
        let dir = tempfile::tempdir().unwrap();
        let (mode, config) = prepare_start(&dir.path().join("konsensus.toml")).unwrap();
        assert_eq!(mode, StartupMode::Bootstrap);
        assert!(config.api.listen_addr.ip().is_loopback());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn config_does_not_auto_adopt_existing_identity() {
        let dir = tempfile::tempdir().unwrap();
        let phrase = dir.path().join("mnemonic.txt");
        std::fs::write(&phrase, "existing identity material").unwrap();
        let config = NodeConfig::default_for_tier(NodeTier::Full, phrase, dir.path());
        let path = dir.path().join("konsensus.toml");
        config.save(&path).unwrap();
        let err = prepare_start(&path)
            .err()
            .expect("markerless identity must refuse");
        assert!(err.to_string().contains("refusing to start"));
        assert!(!DataDirLayout::new(dir.path()).marker().exists());
    }

    #[test]
    fn committed_bootstrap_identity_prepares_normal_start() {
        let dir = tempfile::tempdir().unwrap();
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let layout = DataDirLayout::new(dir.path());
        let outcome = bootstrap::commit_first_run(&layout, phrase, None).unwrap();
        let (mode, config) = prepare_start(&dir.path().join("konsensus.toml")).unwrap();
        assert_eq!(mode, StartupMode::Initialized);
        assert_eq!(config.identity.mnemonic_file, outcome.mnemonic_path);
    }

    #[test]
    fn bootstrap_probes_nested_and_configured_channel_state() {
        for external in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let other = tempfile::tempdir().unwrap();
            let identity_dir = if external {
                other.path().to_path_buf()
            } else {
                dir.path().join("identity")
            };
            let config = NodeConfig::default_for_tier(
                NodeTier::Full,
                identity_dir.join("mnemonic.txt"),
                dir.path(),
            );
            let path = dir.path().join("konsensus.toml");
            config.save(&path).unwrap();
            assert_eq!(prepare_start(&path).unwrap().0, StartupMode::Bootstrap);
            let ldk = identity_dir.join("ldk");
            std::fs::create_dir_all(&ldk).unwrap();
            let monitor = ldk.join("channel-monitor-fixture");
            std::fs::write(&monitor, b"retained channel state").unwrap();
            assert!(prepare_start(&path)
                .unwrap_err()
                .to_string()
                .contains("state_without_identity"));
            assert_eq!(std::fs::read(&monitor).unwrap(), b"retained channel state");
            assert!(!dir.path().join("NODE_INITIALIZED").exists());
        }
    }

    /// P1-3: a store configured as a `sqlite://` URI is probed at the file the
    /// runtime opens, not at a literal path spelled `sqlite:///...`. With a
    /// real runtime-created database retained, deleting the mnemonic and the
    /// marker is a deleted key, and must refuse rather than reopen bootstrap.
    #[tokio::test]
    async fn sqlite_uri_store_cannot_bypass_retained_state_detection() {
        for spelling in ["uri", "literal"] {
            let dir = tempfile::tempdir().unwrap();
            let other = tempfile::tempdir().unwrap();
            let store_file = other.path().join("external.sqlite");
            let configured = match spelling {
                "uri" => format!("sqlite://{}", store_file.display()),
                _ => store_file.to_string_lossy().into_owned(),
            };
            if spelling == "uri" {
                assert!(configured.starts_with("sqlite:///"), "{configured}");
            }
            let layout = DataDirLayout::new(dir.path());
            let mut config = NodeConfig::default_for_tier(
                NodeTier::Full,
                layout.identity_dir().join("mnemonic.txt"),
                dir.path(),
            );
            config.storage = StorageConfig::Sqlite {
                path: configured.clone(),
                encrypted: true,
                retention_days: 0,
            };
            let path = dir.path().join("konsensus.toml");
            config.save(&path).unwrap();
            assert_eq!(prepare_start(&path).unwrap().0, StartupMode::Bootstrap);

            // A committed identity, then the database the runtime creates
            // through the very same connection string.
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let outcome = bootstrap::commit_first_run(&layout, phrase, None).unwrap();
            let _store = konsensus_storage::SqliteStorage::open(&configured)
                .await
                .unwrap();
            assert!(store_file.exists(), "{spelling}: runtime store not created");
            assert_eq!(
                prepare_start(&path).unwrap().0,
                StartupMode::Initialized,
                "{spelling}"
            );

            // Delete the key and the marker; the store stays behind.
            std::fs::remove_file(&outcome.mnemonic_path).unwrap();
            std::fs::remove_dir_all(layout.identity_dir()).unwrap();
            std::fs::remove_file(layout.marker()).unwrap();
            let err = prepare_start(&path)
                .expect_err("retained store with no identity must refuse")
                .to_string();
            assert!(
                err.contains("state_without_identity"),
                "{spelling}: expected a retained-state refusal, got: {err}"
            );
            assert!(!layout.marker().exists());
            assert!(!layout.identity_dir().exists());
            assert!(store_file.exists(), "{spelling}: the probe must not touch the store");
        }
    }

    #[tokio::test]
    async fn bootstrap_probes_configured_store_and_backup_paths() {
        for artifact in ["sqlite", "scb-latest.aes", "whitelist-latest.aes"] {
            let dir = tempfile::tempdir().unwrap();
            let other = tempfile::tempdir().unwrap();
            let mut config = NodeConfig::default_for_tier(
                NodeTier::Full,
                dir.path().join("mnemonic.txt"),
                dir.path(),
            );
            let store_path = other.path().join("messages.sqlite");
            config.storage = StorageConfig::Sqlite {
                path: store_path.to_string_lossy().into_owned(),
                encrypted: true,
                retention_days: 0,
            };
            let backup_dir = other.path().join("recovery");
            config.backup.scb_dir = backup_dir.to_string_lossy().into_owned();
            let path = dir.path().join("konsensus.toml");
            config.save(&path).unwrap();
            assert_eq!(prepare_start(&path).unwrap().0, StartupMode::Bootstrap);
            let _store = if artifact == "sqlite" {
                Some(
                    konsensus_storage::SqliteStorage::open(store_path.to_str().unwrap())
                        .await
                        .unwrap(),
                )
            } else {
                std::fs::create_dir(&backup_dir).unwrap();
                std::fs::write(backup_dir.join(artifact), b"encrypted backup fixture").unwrap();
                None
            };
            assert!(prepare_start(&path)
                .unwrap_err()
                .to_string()
                .contains("state_without_identity"));
            assert!(!dir.path().join("NODE_INITIALIZED").exists());
            assert!(!dir.path().join("identity").exists());
        }
    }

    #[test]
    fn bootstrap_rejects_configured_passphrase_before_commit() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default_for_tier(
            NodeTier::Full,
            dir.path().join("mnemonic.txt"),
            dir.path(),
        );
        config.identity.passphrase = "public test passphrase".into();
        let path = dir.path().join("konsensus.toml");
        config.save(&path).unwrap();
        let err = prepare_start(&path).expect_err("passphrase layout must fail closed");
        assert!(
            err.to_string().contains("passphrase"),
            "expected passphrase refusal, got: {err}"
        );
    }

    #[test]
    fn bootstrap_commit_aligns_custom_config_filename_before_marker() {
        let dir = tempfile::tempdir().unwrap();
        let custom_mnemonic = dir.path().join("custom-mnemonic.txt");
        let mut config =
            NodeConfig::default_for_tier(NodeTier::Full, custom_mnemonic.clone(), dir.path());
        config.api.listen_addr = "127.0.0.1:0".parse().unwrap();
        let path = dir.path().join("custom.toml");
        config.save(&path).unwrap();
        assert_eq!(prepare_start(&path).unwrap().0, StartupMode::Bootstrap);

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let pairing = std::sync::Arc::new(
            PairingService::open(dir.path(), String::new(), false)
                .unwrap()
                .without_stdout_code(),
        );
        let align_path = path.clone();
        let state = bootstrap::BootstrapState::new(configured_layout(dir.path(), &config), pairing)
            .with_before_marker(move |outcome| {
                align_config_mnemonic(&align_path, &outcome.mnemonic_path)
                    .map_err(|e| bootstrap::CommitError::Io(e.to_string()))
            });

        let outcome = state.transition(phrase, bootstrap::CommitFault::None).unwrap();
        assert!(
            DataDirLayout::new(dir.path()).marker().exists(),
            "marker must publish only after config alignment"
        );
        assert_ne!(custom_mnemonic, outcome.mnemonic_path);
        assert!(!custom_mnemonic.exists());

        let aligned = NodeConfig::load_before_identity_validation(&path).unwrap();
        assert_eq!(aligned.identity.mnemonic_file, outcome.mnemonic_path);

        let (mode, started) = prepare_start(&path).unwrap();
        assert_eq!(mode, StartupMode::Initialized);
        assert_eq!(started.identity.mnemonic_file, outcome.mnemonic_path);
    }

    #[test]
    fn failed_config_alignment_does_not_publish_marker() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default_for_tier(
            NodeTier::Full,
            dir.path().join("custom-mnemonic.txt"),
            dir.path(),
        );
        config.api.listen_addr = "127.0.0.1:0".parse().unwrap();
        let path = dir.path().join("custom.toml");
        config.save(&path).unwrap();

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let pairing = std::sync::Arc::new(
            PairingService::open(dir.path(), String::new(), false)
                .unwrap()
                .without_stdout_code(),
        );
        let state = bootstrap::BootstrapState::new(configured_layout(dir.path(), &config), pairing)
            .with_before_marker(|_| Err(bootstrap::CommitError::Io("align failed".into())));

        let err = state
            .transition(phrase, bootstrap::CommitFault::None)
            .expect_err("alignment failure must abort the transition");
        assert!(matches!(err, bootstrap::CommitError::Io(_)));
        assert!(
            !DataDirLayout::new(dir.path()).marker().exists(),
            "a failed alignment must not leave a completed marker"
        );
        // Identity material may exist (rename already happened); config must
        // still be the pre-align custom path so prepare_start refuses rather
        // than claiming Initialized with a missing mnemonic.
        let loaded = NodeConfig::load_before_identity_validation(&path).unwrap();
        assert_eq!(
            loaded.identity.mnemonic_file,
            dir.path().join("custom-mnemonic.txt")
        );
    }

    #[test]
    fn failed_config_dir_sync_does_not_publish_marker() {
        let dir = tempfile::tempdir().unwrap();
        let custom_mnemonic = dir.path().join("custom-mnemonic.txt");
        let mut config =
            NodeConfig::default_for_tier(NodeTier::Full, custom_mnemonic.clone(), dir.path());
        config.api.listen_addr = "127.0.0.1:0".parse().unwrap();
        let path = dir.path().join("custom.toml");
        config.save(&path).unwrap();

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let pairing = std::sync::Arc::new(
            PairingService::open(dir.path(), String::new(), false)
                .unwrap()
                .without_stdout_code(),
        );
        let align_path = path.clone();
        let state = bootstrap::BootstrapState::new(configured_layout(dir.path(), &config), pairing)
            .with_before_marker(move |outcome| {
                crate::config::fail_next_config_dir_sync();
                align_config_mnemonic(&align_path, &outcome.mnemonic_path).map_err(|e| {
                    bootstrap::CommitError::Io(format!("{e:#}"))
                })
            });

        let err = state
            .transition(phrase, bootstrap::CommitFault::None)
            .expect_err("a failed config directory sync must abort before the marker");
        assert!(
            matches!(&err, bootstrap::CommitError::Io(msg) if msg.contains("sync")),
            "expected sync failure, got: {err:?}"
        );
        assert!(
            !DataDirLayout::new(dir.path()).marker().exists(),
            "NODE_INITIALIZED must not publish when config sync fails"
        );
        // No leftover temp sibling from the durable save path.
        assert!(!path.with_extension("toml.tmp").exists());
    }

    #[test]
    fn repair_mark_initialized_finds_identity_via_custom_config() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let custom = other.path().join("sole-identity.txt");
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        std::fs::write(&custom, phrase).unwrap();
        let config = NodeConfig::default_for_tier(NodeTier::Full, custom.clone(), dir.path());
        let path = dir.path().join("custom.toml");
        config.save(&path).unwrap();

        let err = prepare_start(&path)
            .expect_err("markerless custom identity must refuse")
            .to_string();
        assert!(err.contains("identity_without_marker") || err.contains("refusing to start"));

        // Default-name repair cannot see custom.toml; the start -c path can.
        cmd_repair_mark_initialized(&path, true).unwrap();
        assert!(DataDirLayout::new(dir.path()).marker().exists());
        let (mode, started) = prepare_start(&path).unwrap();
        assert_eq!(mode, StartupMode::Initialized);
        assert_eq!(started.identity.mnemonic_file, custom);
    }

    // ── G1: `konsensus grant` terms ─────────────────────────────────

    fn flags(budget: Option<u64>, window: Option<&str>) -> GrantFlags {
        GrantFlags {
            budget_sats: budget,
            window: window.map(str::to_string),
            ..GrantFlags::default()
        }
    }

    #[test]
    fn grant_terms_default_to_24h_and_the_whole_budget_per_call() {
        let t = resolve_terms(&flags(Some(2_000), None), None).unwrap();
        assert_eq!(t.budget_msat, 2_000_000);
        assert_eq!(t.per_call_max_msat, 2_000_000);
        assert_eq!(t.ttl_secs, 24 * 3600);
        assert!(t.per_recipient_msat.is_empty());
    }

    #[test]
    fn grant_needs_a_budget_from_the_owner_or_the_proposal() {
        let err = resolve_terms(&flags(None, Some("1h")), None).unwrap_err();
        assert!(err.to_string().contains("--budget"), "{err}");
        let proposal = GrantTerms::new(5_000_000).per_call(100_000).for_secs(3600);
        let t = resolve_terms(&flags(None, None), Some(&proposal)).unwrap();
        assert_eq!(t, proposal.clone().normalized().unwrap());
        // Owner flags override field by field; a smaller budget also narrows
        // the proposal's per-call maximum rather than failing.
        let t = resolve_terms(&flags(Some(50), Some("30m")), Some(&proposal)).unwrap();
        assert_eq!((t.budget_msat, t.per_call_max_msat, t.ttl_secs), (50_000, 50_000, 1800));
    }

    #[test]
    fn grant_refuses_windows_over_24h_and_malformed_recipients() {
        assert!(resolve_terms(&flags(Some(10), Some("25h")), None).is_err());
        assert!(resolve_terms(&flags(Some(10), Some("2d")), None).is_err());
        let mut f = flags(Some(100), None);
        f.recipients = vec!["nothex=5".into()];
        assert!(resolve_terms(&f, None).is_err());
        f.recipients = vec![format!("{}=5", "ab".repeat(32))];
        let t = resolve_terms(&f, None).unwrap();
        assert_eq!(t.per_recipient_msat[&"ab".repeat(32)], 5_000);
        f.per_call_sats = Some(101);
        assert!(resolve_terms(&f, None).is_err(), "per-call above the budget");
    }
}
