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
//! secret printed only to the owner node's controlling terminal: for a grant,
//! the short owner code (or the full `GRANT … CODE <nonce>` line); for an
//! identity replacement, the full line. The public operation id alone is not
//! consent.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::{NodeConfig, NodeTier, StorageConfig};
use konsensus_api::bootstrap::{self, DataDirLayout, StartupMode};
use konsensus_api::control::{self, ControlRequest, ControlResponse};
use konsensus_api::pairing::PairingService;
use konsensus_api::rate_limit::RemoteTunnelClients;
use konsensus_api::spend_budget::{self, GrantTerms};

/// Prepare startup without constructing a wallet, node or listener.
pub fn prepare_start(config_path: &Path, home_profile: bool) -> Result<(StartupMode, NodeConfig)> {
    let data_dir = data_dir_of(config_path);
    let layout = DataDirLayout::new(&data_dir);
    let mut config = if config_path.try_exists()? {
        NodeConfig::load_before_identity_validation(config_path)?
    } else {
        NodeConfig::default_for_tier(
            NodeTier::Full,
            layout.identity_dir().join("mnemonic.txt"),
            &data_dir,
        )
    };
    // Resolve the home floor before generic W0 validation, bootstrap serving,
    // or locked mode, so even a value below 144 reports the home floor of 288.
    config.lightning.apply_home_to_self_delay(home_profile)?;
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

#[cfg(test)]
mod to_self_delay_tests {
    use super::*;
    use crate::config::LightningConfig;

    #[test]
    fn home_to_self_delay_is_applied_before_bootstrap_or_identity_validation() {
        for (setting, expected) in [
            (None, Some(2016)),
            (Some(200), None),
            (Some(143), None),
            (Some(288), Some(288)),
            (Some(500), Some(500)),
            (Some(2017), None),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("konsensus.toml");
            let mut config = NodeConfig::default_for_tier(
                NodeTier::Full,
                dir.path().join("identity/mnemonic.txt"),
                dir.path(),
            );
            if let LightningConfig::Ldk {
                our_to_self_delay_blocks,
                ..
            } = &mut config.lightning
            {
                *our_to_self_delay_blocks = setting;
            }
            config.save(&path).unwrap();
            match expected {
                Some(expected) => {
                    let (_, config) = prepare_start(&path, true).unwrap();
                    assert!(
                        matches!(config.lightning, LightningConfig::Ldk { our_to_self_delay_blocks: Some(value), .. } if value == expected)
                    );
                    // Applying the runtime profile must not write a default to disk.
                    let saved = NodeConfig::load_before_identity_validation(&path).unwrap();
                    assert!(
                        matches!(saved.lightning, LightningConfig::Ldk { our_to_self_delay_blocks, .. } if our_to_self_delay_blocks == setting)
                    );
                }
                None => {
                    let error = prepare_start(&path, true).unwrap_err().to_string();
                    assert!(
                        error.contains("lightning.our_to_self_delay_blocks"),
                        "{error}"
                    );
                    assert!(error.contains("288"), "{error}");
                }
            }
        }
    }
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

/// Resolve a config path to an absolute path without following symlinks.
///
/// Relative paths (`konsensus start --config konsensus.toml`) otherwise make
/// `config_path.parent()` the empty path. Every durable write that fsyncs that
/// parent then fails with `os error 2`, including the admission journal.
///
/// Do not `canonicalize`: a config that is a symlink must keep the *link's*
/// parent as `data_dir` (e.g. `/srv/node/konsensus.toml` → `/etc/node.toml`
/// still uses `/srv/node`), matching pre-fix startup.
pub fn absolute_config_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .with_context(|| format!("current directory for config {}", path.display()))?
            .join(path))
    }
}

/// The data directory is the config file's directory, matching `AppState::data_dir`.
/// Always absolute when the process cwd is known, so it is never the empty path.
pub fn data_dir_of(config_path: &Path) -> PathBuf {
    let absolute = absolute_config_path(config_path).unwrap_or_else(|_| {
        if config_path.is_absolute() {
            config_path.to_path_buf()
        } else {
            PathBuf::from(".")
        }
    });
    absolute
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
            "could not reach the owner control socket at {:?}.\n\
             The node must be running and must have been started with `--owner-control`.\n\
             A packaged sidecar node does not create this socket: in that deployment the app \
             is a read+receive client and elevation is unavailable by design.",
            socket
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

/// Text from the control socket, made safe for a terminal. The socket is not
/// trusted (a same-user process could replace it), so control characters
/// (ANSI escapes included) and invisible or bidi formatting are shown
/// escaped, never interpreted. Newlines stay.
pub fn terminal_safe(text: &str) -> String {
    text.chars()
        .map(|c| {
            let invisible = matches!(c, '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}');
            if (c.is_control() && c != '\n') || invisible {
                c.escape_unicode().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// `println!` for lines that carry control-socket text: the whole line goes
/// through [`terminal_safe`].
macro_rules! safe_println {
    ($($arg:tt)*) => { println!("{}", terminal_safe(&format!($($arg)*))) };
}

/// Print a response, returning an error if the node refused.
fn report(resp: ControlResponse) -> Result<()> {
    match resp {
        ControlResponse::Ok { detail } => {
            println!("{}", terminal_safe(&detail));
            Ok(())
        }
        ControlResponse::Error { message } => {
            anyhow::bail!("refused: {}", terminal_safe(&message))
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
            front_door_grants,
            device_keys,
            pending_device_keys,
        } => {
            for k in &device_keys {
                safe_println!(
                    "DEVICE KEY {}  {:?}  client={}",
                    k.fingerprint,
                    k.name,
                    k.client_id
                );
            }
            for p in pending_device_keys.iter().filter(|p| !p.lost) {
                safe_println!(
                    "PENDING DEVICE KEY {}  {:?}  client={}\n  approve with: konsensus device approve --op {}",
                    p.fingerprint, p.name, p.client_id, p.op_id
                );
            }
            if clients.is_empty() {
                safe_println!("no paired clients");
            }
            for c in &clients {
                safe_println!(
                    "client {}  name={:?}  scopes={}  epoch={}",
                    c.client_id,
                    c.name,
                    c.scopes.join("+"),
                    c.epoch
                );
            }
            for g in &grants {
                safe_println!(
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
            for g in &grants {
                let b = &g.breakers;
                safe_println!("  BREAKERS client={} paused={} failures={}/{} unresolved={} minute={}/{} hour={}/{} velocity={}/{} sats per 10 min\n  reset with: konsensus grant-reset-breakers --client-id {} --op {}",
                    g.client_id, b.paused, b.consecutive_failures, b.limits.max_consecutive_failures,
                    b.unresolved_payments, b.payments_last_minute, b.limits.max_payments_per_minute,
                    b.payments_last_hour, b.limits.max_payments_per_hour,
                    spend_budget::sats(b.reserved_msat_last_10_minutes), spend_budget::sats(b.limits.max_msat_per_10_minutes), g.client_id, g.op_id);
            }
            for g in &front_door_grants {
                safe_println!(
                    "FRONT DOOR GRANT client={}  may publish the front-door card only  \
                     expires_at={}\n  revoke with: konsensus grant-revoke --client-id {}",
                    g.client_id,
                    g.expires_at,
                    g.client_id
                );
            }
            for e in &pending_elevations {
                let next = if e.lost {
                    "cancelled by wrong codes; ask again from the app".to_string()
                } else {
                    format!("approve with: konsensus grant --op {}", e.op_id)
                };
                safe_println!(
                    "PENDING ELEVATION op={}  client={} ({})  scopes={}  expires_at={}\n  {next}",
                    e.op_id,
                    e.client_name,
                    e.client_id,
                    e.scopes.join("+"),
                    e.expires_at,
                );
            }
            for r in &pending_replacements {
                safe_println!(
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
    front_door: bool,
    device: Option<control::DeviceApprovalTuple>,
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
            front_door,
            device,
        } => Ok(Described {
            summary,
            label: confirmation_label,
            proposed_terms,
            front_door,
            device,
        }),
        ControlResponse::Error { message } => anyhow::bail!("refused: {}", terminal_safe(&message)),
        other => anyhow::bail!("unexpected control response: {other:?}"),
    }
}

/// Render a pending operation and read the owner's typed confirmation.
///
/// Only the public label comes from the socket. The unpredictable confirmation
/// must be copied from the owner-run node's terminal, never this API response.
async fn confirm_interactively(config_path: &Path, op_id: &str) -> Result<String> {
    let described = describe(config_path, op_id).await?;
    println!("\n{}\n", terminal_safe(&described.summary));
    read_confirmation(&described.label)
}

fn read_confirmation(phrase: &str) -> Result<String> {
    safe_println!("On the owner node's console, find {phrase}.\nType its full confirmation, including CODE and the random nonce.\n");
    print!("> ");
    std::io::stdout().flush().ok();

    let mut typed = String::new();
    std::io::stdin()
        .read_line(&mut typed)
        .context("failed to read the confirmation phrase from stdin")?;
    Ok(typed.trim().to_string())
}

/// Read the grant confirmation: the short code the node printed on its own
/// terminal (or, as a fallback, that terminal's full `GRANT … CODE` line).
/// Typing it after reading the terms is the approval; an empty line cancels.
fn read_owner_code() -> Result<Option<String>> {
    println!(
        "To grant, type the approval code shown in the node's terminal (the window running \
         the node, or the app that started it), e.g. K7QM-3XWD.\n\
         The full GRANT ... CODE line printed there also works. Press Enter to cancel.\n"
    );
    print!("code> ");
    std::io::stdout().flush().ok();
    let mut typed = String::new();
    std::io::stdin()
        .read_line(&mut typed)
        .context("failed to read the approval code from stdin")?;
    let typed = typed.trim();
    Ok((!typed.is_empty()).then(|| typed.to_string()))
}

/// The owner's flags for `konsensus grant`.
#[derive(Debug, Default)]
pub struct GrantFlags {
    pub max_payments_per_minute: Option<u64>,
    pub max_payments_per_hour: Option<u64>,
    pub max_consecutive_failures: Option<u64>,
    pub max_sats_per_10_minutes: Option<u64>,
    /// Exclusive allowed payees; replaces a proposal's allowlist when supplied.
    pub payees: Vec<String>,
    pub deny_all_payees: bool,
    /// Explicit opt-in; never inherited from an app proposal.
    pub allow_liquidity_fees: bool,
    /// `--budget <sats>`.
    pub budget_sats: Option<u64>,
    /// `--for <duration>`.
    pub window: Option<String>,
    /// `--per-call <sats>`.
    pub per_call_sats: Option<u64>,
    /// `--recipient <key>=<sats>`, repeatable.
    pub recipients: Vec<String>,
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
            let sats: u64 = sats.trim().parse().with_context(|| {
                format!("--recipient {entry:?}: {sats:?} is not a whole number of sats")
            })?;
            map.insert(key.trim().to_string(), sats_to_msat(sats, "--recipient")?);
        }
        map
    };
    // Breakers are chosen by the owner, never widened by an app proposal.
    let defaults = spend_budget::BreakerLimits::default();
    let breakers = spend_budget::BreakerLimits {
        max_payments_per_minute: flags
            .max_payments_per_minute
            .unwrap_or(defaults.max_payments_per_minute),
        max_payments_per_hour: flags
            .max_payments_per_hour
            .unwrap_or(defaults.max_payments_per_hour),
        max_consecutive_failures: flags
            .max_consecutive_failures
            .unwrap_or(defaults.max_consecutive_failures),
        max_msat_per_10_minutes: flags
            .max_sats_per_10_minutes
            .map(|s| sats_to_msat(s, "--max-sats-per-10-minutes"))
            .transpose()?
            .unwrap_or(defaults.max_msat_per_10_minutes),
    };
    GrantTerms {
        breakers,
        payee_allowlist: if flags.deny_all_payees {
            Some(Default::default())
        } else if !flags.payees.is_empty() {
            Some(flags.payees.iter().cloned().collect())
        } else {
            proposal.and_then(|p| p.payee_allowlist.clone())
        },
        allow_liquidity_fees: flags.allow_liquidity_fees,
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
    if described.front_door {
        return grant_front_door(config_path, op_id, &flags, &described).await;
    }
    let terms = resolve_terms(&flags, described.proposed_terms.as_ref())?;
    println!("\n{}\n", terminal_safe(&described.summary));
    println!(
        "YOU ARE GRANTING (the node debits every paid call before paying and refuses \
         with budget_exceeded when it runs out):\n{}\n",
        spend_budget::describe_terms(&terms)
    );
    let Some(confirmation) = read_owner_code()? else {
        println!("not granted");
        return Ok(());
    };
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

/// The window of a front-door grant: `--for`, else one hour. Budget flags are
/// refused: a front-door grant moves no value, so a budget would only mislead.
pub fn front_door_ttl(flags: &GrantFlags) -> Result<i64> {
    if flags.max_payments_per_minute.is_some()
        || flags.max_payments_per_hour.is_some()
        || flags.max_consecutive_failures.is_some()
        || flags.max_sats_per_10_minutes.is_some()
        || flags.budget_sats.is_some()
        || flags.per_call_sats.is_some()
        || !flags.recipients.is_empty()
        || !flags.payees.is_empty()
        || flags.deny_all_payees
        || flags.allow_liquidity_fees
    {
        anyhow::bail!(
            "this request asks for front_door only, which carries no budget; drop circuit-breaker flags, --budget, \
             --per-call, --recipient, --payee, --deny-all-payees and --allow-liquidity-fees (keep --for)"
        );
    }
    let ttl = match &flags.window {
        Some(w) => spend_budget::parse_duration(w).map_err(anyhow::Error::msg)?,
        None => konsensus_api::pairing::DEFAULT_FRONT_DOOR_GRANT_TTL_SECS,
    };
    if ttl <= 0 || ttl > spend_budget::MAX_SPEND_GRANT_TTL_SECS {
        anyhow::bail!("--for must be at most 24h");
    }
    Ok(ttl)
}

async fn grant_front_door(
    config_path: &Path,
    op_id: &str,
    flags: &GrantFlags,
    described: &Described,
) -> Result<()> {
    let ttl_secs = front_door_ttl(flags)?;
    println!("\n{}\n", terminal_safe(&described.summary));
    println!(
        "YOU ARE GRANTING: publish or update this node's front-door card, for {} minutes. \
         No spend, no other route.\n",
        ttl_secs / 60
    );
    let Some(confirmation) = read_owner_code()? else {
        println!("not granted");
        return Ok(());
    };
    report(
        send(
            config_path,
            ControlRequest::GrantFrontDoor {
                op_id: op_id.to_string(),
                confirmation,
                ttl_secs,
            },
        )
        .await?,
    )
}

/// `konsensus device approve|list|revoke`.
pub async fn cmd_device(command: crate::cli::DeviceCommand) -> Result<()> {
    use crate::cli::DeviceCommand;
    match command {
        DeviceCommand::Approve { op_id, config } => {
            // Fail closed before anything is shown or asked.
            protected_owner_secret(&config)?;
            let described = describe(&config, &op_id).await?;
            let tuple = described
                .device
                .context("that operation is not a device-key registration")?;
            // The socket is not trusted: nothing it wrote is printed in this
            // flow. Every approval-critical term below is computed here, from
            // the exact bytes that get signed.
            let device = hex::decode(&tuple.device_public_key)
                .ok()
                .filter(|k| k.len() == 65 && k[0] == 0x04)
                .context("the node described a malformed device key; nothing was signed")?;
            let client = hex::decode(&tuple.client_pubkey)
                .ok()
                .filter(|k| k.len() == 32)
                .context("the node described a malformed pairing key; nothing was signed")?;
            use konsensus_api::pairing::device::{key_fingerprint, key_id_for};
            println!(
                "YOU ARE SIGNING (computed by this command, not by the node):\n  device fingerprint:  {}\n  \
                 pairing key:         {}\n  pairing epoch:       {}\nCompare the device fingerprint with \
                 the one the app shows. If they differ, press Enter to cancel.\n",
                key_fingerprint(&key_id_for(&device)),
                key_fingerprint(&key_id_for(&client)),
                tuple.epoch
            );
            let Some(confirmation) = read_owner_code()? else {
                println!("not registered");
                return Ok(());
            };
            let owner_signature = sign_device_approval(&config, &tuple)?;
            report(
                send(
                    &config,
                    ControlRequest::ApproveDeviceKey {
                        op_id,
                        confirmation,
                        owner_signature,
                    },
                )
                .await?,
            )
        }
        DeviceCommand::Revoke { key_id, config } => {
            report(send(&config, ControlRequest::RevokeDeviceKey { key_id }).await?)
        }
        DeviceCommand::List { config } => match send(&config, ControlRequest::Status).await? {
            ControlResponse::Status {
                device_keys,
                pending_device_keys,
                ..
            } => {
                if device_keys.is_empty() && pending_device_keys.is_empty() {
                    safe_println!("no device keys");
                }
                for k in &device_keys {
                    safe_println!(
                        "DEVICE KEY {}  {:?}  client={}  registered_at={}\n  revoke with: konsensus device revoke --key {}",
                        k.fingerprint, k.name, k.client_id, k.registered_at, k.key_id
                    );
                }
                for p in &pending_device_keys {
                    let next = if p.lost {
                        "cancelled by wrong codes; ask again from the app".to_string()
                    } else {
                        format!("approve with: konsensus device approve --op {}", p.op_id)
                    };
                    safe_println!(
                        "PENDING DEVICE KEY {}  {:?}  client={} ({})  expires_at={}\n  {next}",
                        p.fingerprint,
                        p.name,
                        p.client_name,
                        p.client_id,
                        p.expires_at
                    );
                }
                Ok(())
            }
            other => report(other),
        },
    }
}

/// The node's config, if its owner secret is protected from a same-user app:
/// an encrypted recovery phrase with no plaintext copy beside it. Checked
/// before the owner is asked anything.
fn protected_owner_secret(config_path: &Path) -> Result<NodeConfig> {
    let config = NodeConfig::load_before_identity_validation(config_path)
        .with_context(|| format!("failed to load config from {}", config_path.display()))?;
    let path = &config.identity.mnemonic_file;
    if !crate::mnemonic_crypto::is_encrypted_path(path) {
        anyhow::bail!(
            "refusing to sign: the recovery phrase at {} is not encrypted, so any program running \
             as this user could derive the owner-approval key and approve devices itself. \
             Device approval needs an encrypted recovery phrase (a node created with \
             `konsensus init --encrypt` or `konsensus restore --encrypt`). Nothing was signed.",
            path.display()
        );
    }
    let plaintext = path.with_extension("txt");
    if plaintext.exists() {
        anyhow::bail!(
            "refusing to sign: a plaintext copy of the recovery phrase is still at {}. Remove it \
             (after confirming your backup and that the node starts from the encrypted file). \
             Nothing was signed.",
            plaintext.display()
        );
    }
    Ok(config)
}

/// Sign a device registration with the owner-approval key, derived here from
/// the seed and dropped when this returns. Refuses if the node on the socket
/// is not the identity this seed derives: the owner signs only for their node.
///
/// Fails closed unless the owner secret is protected from a same-user app:
/// the recovery phrase must be encrypted (`.enc`, `konsensus init --encrypt`),
/// no plaintext copy may sit beside it, and its password is typed at this
/// prompt. There is no flag, environment variable or config field for it.
fn sign_device_approval(
    config_path: &Path,
    tuple: &control::DeviceApprovalTuple,
) -> Result<String> {
    sign_device_approval_with(config_path, tuple, || {
        print!("Password for the encrypted recovery phrase: ");
        std::io::stdout().flush().ok();
        Ok(zeroize::Zeroizing::new(
            rpassword::read_password().context("failed to read the password from the terminal")?,
        ))
    })
}

fn sign_device_approval_with(
    config_path: &Path,
    tuple: &control::DeviceApprovalTuple,
    password: impl FnOnce() -> Result<zeroize::Zeroizing<String>>,
) -> Result<String> {
    let config = protected_owner_secret(config_path)?;
    let path = &config.identity.mnemonic_file;
    let password = password()?;
    let mnemonic = crate::mnemonic_crypto::read_mnemonic(path, Some(password.as_str()))
        .with_context(|| {
            format!(
                "failed to decrypt the recovery phrase at {}",
                path.display()
            )
        })?;
    // The BIP-39 passphrase is a derivation input shared with the node, not
    // the protection; the protection is the encryption password above.
    let passphrase = config.identity.passphrase.as_str();
    let node = konsensus_core::NodeIdentity::from_mnemonic(&mnemonic, passphrase)
        .context("failed to derive the node identity")?;
    let fingerprint = konsensus_api::pairing::identity_fingerprint(&node.node_id().to_hex());
    if fingerprint != tuple.node {
        anyhow::bail!(
            "the node on this socket ({}) is not the identity this recovery phrase derives \
             ({fingerprint}); nothing was signed",
            terminal_safe(&tuple.node)
        );
    }
    let secret = crate::mnemonic_crypto::owner_secret(password.as_str(), &node.node_id().to_hex())
        .context("failed to derive the owner secret")?;
    let owner = konsensus_core::OwnerApprovalKey::from_mnemonic(&mnemonic, passphrase, &secret)
        .context("failed to derive the owner-approval key")?;
    let message = konsensus_api::pairing::device::owner_approval_message(
        &tuple.node,
        &tuple.client_pubkey,
        tuple.epoch,
        &tuple.device_public_key,
    );
    Ok(hex::encode(owner.sign(message.as_bytes()).to_bytes()))
}

/// `konsensus grant-revoke --client-id <id> | --all` — stop spend now.
pub async fn cmd_grant_revoke(
    config_path: &Path,
    client_id: Option<&str>,
    all: bool,
) -> Result<()> {
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

pub async fn cmd_grant_reset_breakers(
    config_path: &Path,
    client_id: String,
    grant_op_id: String,
) -> Result<()> {
    report(
        send(
            config_path,
            ControlRequest::ResetGrantBreakers {
                client_id,
                grant_op_id,
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
    let phrase = zeroize::Zeroizing::new(match mnemonic {
        Some(m) => m.to_string(),
        None => {
            println!(
                "\nEnter the recovery phrase of the destination identity (input hidden).\n\
                 It is checked against the identity shown above; only an accepted replacement writes it to the identity file."
            );
            rpassword::read_password().context("failed to read the recovery phrase")?
        }
    });
    report(
        send(
            config_path,
            ControlRequest::ApproveReplacement {
                op_id: op_id.to_string(),
                confirmation,
                mnemonic: zeroize::Zeroizing::new(phrase.trim().to_string()),
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
pub(crate) fn align_config_mnemonic(config_path: &Path, mnemonic_path: &Path) -> Result<()> {
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

/// Startup-only password handoff. Never accepted from HTTP or configuration.
pub struct LocalOwnerBootstrap {
    pub password: zeroize::Zeroizing<String>,
    pub enroll_device: bool,
}

impl LocalOwnerBootstrap {
    fn into_hooks(self) -> Result<bootstrap::LocalOwnerHooks> {
        // write_mnemonic intentionally supports plaintext for an empty password;
        // this ceremony must never reach that fallback.
        anyhow::ensure!(
            !self.password.is_empty(),
            "bootstrap password must not be empty"
        );
        let password = std::sync::Arc::new(self.password);
        let signing_password = password.clone();
        Ok(bootstrap::LocalOwnerHooks {
            encrypt_seed: Box::new(move |phrase, staging| {
                let path = crate::mnemonic_crypto::write_mnemonic(
                    &staging.join("mnemonic.enc"),
                    phrase,
                    Some(password.as_str()),
                )
                .map_err(|_| bootstrap::CommitError::Io("seed encryption failed".into()))?;
                std::fs::File::open(&path)?.sync_all()?;
                Ok(path)
            }),
            sign_owner_approval: Box::new(move |phrase, node_id, message| {
                let secret =
                    crate::mnemonic_crypto::owner_secret(signing_password.as_str(), node_id)
                        .map_err(|_| {
                            bootstrap::CommitError::Io("owner key derivation failed".into())
                        })?;
                let key = konsensus_core::OwnerApprovalKey::from_mnemonic(phrase, "", &secret)
                    .map_err(|_| {
                        bootstrap::CommitError::Io("owner key derivation failed".into())
                    })?;
                Ok(hex::encode(key.sign(message.as_bytes()).to_bytes()))
            }),
            enroll_device: self.enroll_device,
        })
    }
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
///
/// With `remote_unlock` (P2) there is no startup password: the box-static
/// Noise tunnel is bound beside the loopback API, and the password reaches
/// `finalize` through that tunnel only. Returns `true` when such a remote
/// first run committed, so the caller exits for a restart into locked mode.
pub async fn serve_bootstrap_mode(
    config_path: &Path,
    config: &NodeConfig,
    local: Option<LocalOwnerBootstrap>,
    remote_unlock: bool,
    home: bool,
) -> Result<bool> {
    anyhow::ensure!(!remote_unlock || home,
        "remote first run requires --home for LAN box approval; use --home instead of --remote-unlock --local-owner-device on an empty box");
    if !config.identity.passphrase.is_empty() {
        anyhow::bail!(
            "bootstrap does not support identity.passphrase: first-run commit derives with an \
             empty passphrase, so a configured passphrase would produce a different live \
             identity. Clear identity.passphrase, or initialize with `konsensus init` / \
             `konsensus restore`."
        );
    }
    let api_addr = config.api.listen_addr;
    anyhow::ensure!(
        api_addr.ip().is_loopback(),
        "bootstrap requires a loopback API listen address"
    );
    let hooks = local.map(LocalOwnerBootstrap::into_hooks).transpose()?;
    let data_dir = data_dir_of(config_path);
    let layout = configured_layout(&data_dir, config);
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("failed to create {}", data_dir.display()))?;

    crate::claim_code::initialize(&data_dir)?;

    // No identity exists, so the pairing service binds to the empty
    // fingerprint; the transition commit rebinds every record to the committed
    // identity. Owner control is off: there is nothing to elevate on a node
    // with no keys, and first-run authority is already scoped to bootstrap.
    let pairing = std::sync::Arc::new(
        PairingService::open(&data_dir, String::new(), false)
            .map_err(|e| anyhow::anyhow!("failed to open pairing state: {e}"))?
            .with_hosted_by(config.node.hosted_by.clone()),
    );
    let align_path = config_path.to_path_buf();
    let mut state = konsensus_api::bootstrap::BootstrapState::new(layout, pairing)
        .with_before_marker(move |outcome| {
            align_config_mnemonic(&align_path, &outcome.mnemonic_path)
                .map_err(|e| konsensus_api::bootstrap::CommitError::Io(e.to_string()))
        });
    if let Some(hooks) = hooks {
        state = state.with_local_owner(hooks);
    }
    let tunnel_clients = std::sync::Arc::new(RemoteTunnelClients::default());
    if remote_unlock {
        anyhow::ensure!(
            config.remote_access.listen_addr.is_some(),
            "remote bootstrap requires remote_access.listen_addr"
        );
        state = state.with_remote_owner(bootstrap::RemoteOwner {
            hooks: Box::new(|password| {
                LocalOwnerBootstrap {
                    password,
                    enroll_device: true,
                }
                .into_hooks()
                .map_err(|_| bootstrap::CommitError::Io("bootstrap password rejected".into()))
            }),
            tunnel: tunnel_clients.clone(),
        });
    }
    let state = std::sync::Arc::new(state);

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

    let api = tokio::net::TcpListener::bind(api_addr)
        .await
        .with_context(|| format!("could not bind bootstrap API at {api_addr}"))?;
    let mut listeners = vec![api];
    let mut tunnel = None;
    let mut _home_page = None;
    if remote_unlock {
        let internal = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let mut server = crate::remote_access::RemoteAccessServer::bind_bootstrap(
            &config.remote_access,
            state.pairing.clone(),
            internal.local_addr()?,
            tunnel_clients,
        )
        .await?;
        if home {
            let tickets = server.enable_home_setup(&config.remote_access, state.clone())?;
            _home_page = Some(
                crate::setup_page::start(
                    config,
                    Some(state.clone()),
                    Some(tickets),
                    "SETUP".into(),
                )
                .await?,
            );
        }
        listeners.push(internal);
        // Stop the tunnel with the bootstrap listeners so no bridge outlives
        // the terminal response.
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let terminal = bootstrap::until_terminal(state.clone(), shutdown_rx.clone());
        tokio::spawn(async move {
            terminal.await;
            let _ = stop_tx.send(true);
        });
        tunnel = Some(tokio::spawn(server.serve(stop_rx)));
        println!("Remote first run is reachable through the box-static Noise tunnel.");
    }

    let outcome =
        konsensus_api::bootstrap::serve_bootstrap_listeners(listeners, state, shutdown_rx)
            .await
            .map_err(|e| anyhow::anyhow!("bootstrap API failed: {e}"))?;
    if let Some(tunnel) = tunnel {
        tunnel.await.context("remote bootstrap tunnel failed")?;
    }

    match outcome {
        Some(o) if remote_unlock => {
            println!(
                "identity committed: node {} (fingerprint {}).\n\
                 Encrypted seed written to {}.\n\
                 Exiting for a supervised restart into locked mode; unlock from the enrolled device.",
                o.node_id,
                o.identity_fingerprint,
                o.mnemonic_path.display()
            );
            Ok(true)
        }
        Some(o) => {
            println!(
                "identity committed: node {} (fingerprint {}).\n\
                 Mnemonic written to {}.\n\
                 Start the node normally to bring it online — bootstrap does not start a live node.",
                o.node_id,
                o.identity_fingerprint,
                o.mnemonic_path.display()
            );
            Ok(false)
        }
        None => {
            println!("bootstrap ended without an identity being committed");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod startup_tests {
    use super::*;

    #[test]
    fn relative_config_path_yields_absolute_data_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let result = std::panic::catch_unwind(|| {
            std::fs::write("konsensus.toml", "# test\n").unwrap();
            let absolute = absolute_config_path(Path::new("konsensus.toml")).unwrap();
            assert!(absolute.is_absolute());
            assert!(absolute.ends_with("konsensus.toml"));
            let data = data_dir_of(Path::new("konsensus.toml"));
            assert!(data.is_absolute());
            assert!(!data.as_os_str().is_empty());
            assert_eq!(
                data.canonicalize().unwrap(),
                tmp.path().canonicalize().unwrap()
            );
        });
        std::env::set_current_dir(prev).unwrap();
        result.unwrap();
    }

    /// Config symlink must not relocate `data_dir` to the target's parent.
    /// `/srv/node/konsensus.toml` → `/etc/node.toml` still uses `/srv/node`.
    #[cfg(unix)]
    #[test]
    fn symlinked_config_keeps_link_parent_as_data_dir() {
        let node = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let layout = DataDirLayout::new(node.path());
        let outcome = bootstrap::commit_first_run(&layout, phrase, None).unwrap();

        // Real file lives elsewhere; only a symlink sits beside NODE_INITIALIZED.
        let real_config = elsewhere.path().join("node.toml");
        NodeConfig::default_for_tier(NodeTier::Full, outcome.mnemonic_path.clone(), node.path())
            .save(&real_config)
            .unwrap();
        let link = node.path().join("konsensus.toml");
        std::os::unix::fs::symlink(&real_config, &link).unwrap();

        let absolute = absolute_config_path(&link).unwrap();
        assert_eq!(absolute, link);
        assert!(absolute.is_absolute());
        // Following the symlink would select `elsewhere` as data_dir — must not.
        assert_eq!(
            absolute.canonicalize().unwrap(),
            real_config.canonicalize().unwrap()
        );
        assert_ne!(
            absolute.canonicalize().unwrap().parent().unwrap(),
            absolute.parent().unwrap()
        );

        let data = data_dir_of(&link);
        assert_eq!(data, node.path());
        assert_ne!(
            data.canonicalize().unwrap(),
            elsewhere.path().canonicalize().unwrap()
        );
        assert!(DataDirLayout::new(&data).marker().exists());

        let (mode, _) = prepare_start(&link, false).unwrap();
        assert_eq!(
            mode,
            StartupMode::Initialized,
            "marker beside the symlink must still classify as initialized"
        );
    }

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
        let (mode, config) = prepare_start(&dir.path().join("konsensus.toml"), false).unwrap();
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
        let err = prepare_start(&path, false).expect_err("markerless identity must refuse");
        assert!(err.to_string().contains("refusing to start"));
        assert!(!DataDirLayout::new(dir.path()).marker().exists());
    }

    #[test]
    fn committed_bootstrap_identity_prepares_normal_start() {
        let dir = tempfile::tempdir().unwrap();
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let layout = DataDirLayout::new(dir.path());
        let outcome = bootstrap::commit_first_run(&layout, phrase, None).unwrap();
        let (mode, config) = prepare_start(&dir.path().join("konsensus.toml"), false).unwrap();
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
            assert_eq!(
                prepare_start(&path, false).unwrap().0,
                StartupMode::Bootstrap
            );
            let ldk = identity_dir.join("ldk");
            std::fs::create_dir_all(&ldk).unwrap();
            let monitor = ldk.join("channel-monitor-fixture");
            std::fs::write(&monitor, b"retained channel state").unwrap();
            assert!(prepare_start(&path, false)
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
            assert_eq!(
                prepare_start(&path, false).unwrap().0,
                StartupMode::Bootstrap
            );

            // A committed identity, then the database the runtime creates
            // through the very same connection string.
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let outcome = bootstrap::commit_first_run(&layout, phrase, None).unwrap();
            let _store = konsensus_storage::SqliteStorage::open(&configured)
                .await
                .unwrap();
            assert!(store_file.exists(), "{spelling}: runtime store not created");
            assert_eq!(
                prepare_start(&path, false).unwrap().0,
                StartupMode::Initialized,
                "{spelling}"
            );

            // Delete the key and the marker; the store stays behind.
            std::fs::remove_file(&outcome.mnemonic_path).unwrap();
            std::fs::remove_dir_all(layout.identity_dir()).unwrap();
            std::fs::remove_file(layout.marker()).unwrap();
            let err = prepare_start(&path, false)
                .expect_err("retained store with no identity must refuse")
                .to_string();
            assert!(
                err.contains("state_without_identity"),
                "{spelling}: expected a retained-state refusal, got: {err}"
            );
            assert!(!layout.marker().exists());
            assert!(!layout.identity_dir().exists());
            assert!(
                store_file.exists(),
                "{spelling}: the probe must not touch the store"
            );
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
            assert_eq!(
                prepare_start(&path, false).unwrap().0,
                StartupMode::Bootstrap
            );
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
            assert!(prepare_start(&path, false)
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
        let err = prepare_start(&path, false).expect_err("passphrase layout must fail closed");
        assert!(
            err.to_string().contains("passphrase"),
            "expected passphrase refusal, got: {err}"
        );
    }

    #[test]
    fn encrypted_bootstrap_hooks_reject_empty_password_and_sign_owner() {
        use zeroize::Zeroizing;
        assert!(LocalOwnerBootstrap {
            password: Zeroizing::new(String::new()),
            enroll_device: true
        }
        .into_hooks()
        .is_err());
        let password = "bootstrap-test-password";
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let dir = tempfile::tempdir().unwrap();
        let hooks = LocalOwnerBootstrap {
            password: Zeroizing::new(password.into()),
            enroll_device: true,
        }
        .into_hooks()
        .unwrap();
        let path = (hooks.encrypt_seed)(phrase, dir.path()).unwrap();
        assert_eq!(path, dir.path().join("mnemonic.enc"));
        assert!(!dir.path().join("mnemonic.txt").exists());
        assert_eq!(
            crate::mnemonic_crypto::read_mnemonic(&path, Some(password))
                .unwrap()
                .as_str(),
            phrase
        );
        let node_id = konsensus_core::NodeIdentity::from_mnemonic(phrase, "")
            .unwrap()
            .node_id()
            .to_hex();
        let secret = crate::mnemonic_crypto::owner_secret(password, &node_id).unwrap();
        let owner = konsensus_core::OwnerApprovalKey::from_mnemonic(phrase, "", &secret).unwrap();
        let sig = (hooks.sign_owner_approval)(phrase, &node_id, "bound owner message").unwrap();
        konsensus_api::pairing::device::verify_owner_approval(
            &owner.verifying_key(),
            "bound owner message",
            &sig,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn encrypted_crash_repair_preserves_pairing_and_config_safety_gates() {
        use ed25519_dalek::{Signer, SigningKey};
        use konsensus_api::{auth::Scope, pairing};
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        for before_rebind in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let config_path = dir.path().join("custom.toml");
            let config = NodeConfig::default_for_tier(
                NodeTier::Full,
                dir.path().join("original.txt"),
                dir.path(),
            );
            config.save(&config_path).unwrap();
            let original_config = std::fs::read(&config_path).unwrap();
            let pairing = std::sync::Arc::new(
                PairingService::open(dir.path(), String::new(), false)
                    .unwrap()
                    .without_stdout_code(),
            );
            let key = SigningKey::from_bytes(&[51; 32]);
            let public = hex::encode(key.verifying_key().to_bytes());
            let request = pairing.request_pairing("app", &public).unwrap();
            let challenge =
                std::fs::read(pairing.dir().join(format!("challenge-{}", request.pair_id)))
                    .unwrap();
            let sig = hex::encode(
                key.sign(&PairingService::proof_message(
                    &request.pair_id,
                    &public,
                    &challenge,
                ))
                .to_bytes(),
            );
            let client = pairing
                .confirm_pairing(&request.pair_id, &sig, pairing::bootstrap_pairing_scopes())
                .unwrap();
            let hooks = LocalOwnerBootstrap {
                password: zeroize::Zeroizing::new("crash-test-password".into()),
                enroll_device: true,
            }
            .into_hooks()
            .unwrap();
            let state =
                bootstrap::BootstrapState::new(configured_layout(dir.path(), &config), pairing)
                    .with_local_owner(hooks)
                    .with_before_marker(|_| {
                        Err(bootstrap::CommitError::Io(
                            "injected pre-config failure".into(),
                        ))
                    });
            let fault = if before_rebind {
                bootstrap::CommitFault::AbortAfterRename
            } else {
                bootstrap::CommitFault::None
            };
            assert!(state.transition(phrase, fault).is_err());
            assert!(!state.layout.marker().exists());
            assert!(state.pairing.device_keys().is_empty());
            drop(state);
            assert!(prepare_start(&config_path, false).is_err());
            assert!(cmd_repair_mark_initialized(&config_path, false).is_err());
            cmd_repair_mark_initialized(&config_path, true).unwrap();
            assert_eq!(
                std::fs::read(&config_path).unwrap(),
                original_config,
                "repair only writes marker"
            );
            assert!(
                prepare_start(&config_path, false).is_err(),
                "repair must not guess a new config path"
            );
            align_config_mnemonic(&config_path, &dir.path().join("identity/mnemonic.enc")).unwrap();
            let (mode, repaired) = prepare_start(&config_path, false).unwrap();
            assert_eq!(mode, StartupMode::Initialized);
            let node_id = konsensus_core::NodeIdentity::from_mnemonic(phrase, "")
                .unwrap()
                .node_id()
                .to_hex();
            let fp = pairing::identity_fingerprint(&node_id);
            let verifier = crate::owner_approval_key(
                &repaired,
                Some("crash-test-password"),
                crate::PasswordSource::Descriptor,
                true,
            )
            .unwrap();
            let live = PairingService::open(dir.path(), fp, false)
                .unwrap()
                .with_local_owner_device()
                .with_owner_signing_key(verifier.signing_key.unwrap());
            assert!(live.device_keys().is_empty());
            let challenge = live.issue_token_challenge(&client.client_id).unwrap();
            let sig = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
            let token = live.issue_token(
                &node_id,
                "test-secret-at-least-32-bytes-long",
                &client.client_id,
                &challenge,
                &sig,
            );
            if before_rebind {
                assert!(
                    matches!(token, Err(pairing::PairingError::PairingInvalid(_))),
                    "old empty fingerprint requires explicit owner recovery"
                );
            } else {
                let token = token.unwrap();
                assert!(token.scopes.contains(&Scope::Read));
                assert!(token.scopes.contains(&Scope::Receive));
                assert!(!token.scopes.contains(&Scope::Identity));
                assert!(!token.scopes.contains(&Scope::Spend));
            }
        }
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
        assert_eq!(
            prepare_start(&path, false).unwrap().0,
            StartupMode::Bootstrap
        );

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

        let outcome = state
            .transition(phrase, bootstrap::CommitFault::None)
            .unwrap();
        assert!(
            DataDirLayout::new(dir.path()).marker().exists(),
            "marker must publish only after config alignment"
        );
        assert_ne!(custom_mnemonic, outcome.mnemonic_path);
        assert!(!custom_mnemonic.exists());

        let aligned = NodeConfig::load_before_identity_validation(&path).unwrap();
        assert_eq!(aligned.identity.mnemonic_file, outcome.mnemonic_path);

        let (mode, started) = prepare_start(&path, false).unwrap();
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
                align_config_mnemonic(&align_path, &outcome.mnemonic_path)
                    .map_err(|e| bootstrap::CommitError::Io(format!("{e:#}")))
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

        let err = prepare_start(&path, false)
            .expect_err("markerless custom identity must refuse")
            .to_string();
        assert!(err.contains("identity_without_marker") || err.contains("refusing to start"));

        // Default-name repair cannot see custom.toml; the start -c path can.
        cmd_repair_mark_initialized(&path, true).unwrap();
        assert!(DataDirLayout::new(dir.path()).marker().exists());
        let (mode, started) = prepare_start(&path, false).unwrap();
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
    fn owner_payee_flags_override_proposals_and_display_exact_authority() {
        let mut proposal = GrantTerms::new(10_000);
        proposal.payee_allowlist = Some(["aa".repeat(32)].into());
        let mut flags = GrantFlags::default();
        assert_eq!(
            resolve_terms(&flags, Some(&proposal))
                .unwrap()
                .payee_allowlist,
            proposal.payee_allowlist
        );
        flags.payees = vec!["BB".repeat(32)];
        let terms = resolve_terms(&flags, Some(&proposal)).unwrap();
        assert_eq!(terms.payee_allowlist, Some(["bb".repeat(32)].into()));
        let summary = spend_budget::describe_terms(&terms);
        assert!(summary.contains(&"bb".repeat(32)));
        assert!(!summary.contains("any, within the total"));
        flags.payees.clear();
        flags.deny_all_payees = true;
        assert_eq!(
            resolve_terms(&flags, Some(&proposal))
                .unwrap()
                .payee_allowlist,
            Some(Default::default())
        );
        assert!(front_door_ttl(&flags).is_err());
    }

    #[test]
    fn a_front_door_grant_takes_a_window_and_refuses_budget_flags() {
        assert_eq!(front_door_ttl(&flags(None, None)).unwrap(), 3600);
        assert_eq!(front_door_ttl(&flags(None, Some("10m"))).unwrap(), 600);
        assert!(front_door_ttl(&flags(None, Some("25h"))).is_err());
        let err = front_door_ttl(&flags(Some(100), Some("10m")))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no budget"), "{err}");
        let per_call = GrantFlags {
            per_call_sats: Some(1),
            ..GrantFlags::default()
        };
        assert!(front_door_ttl(&per_call).is_err());
        let fees = GrantFlags {
            allow_liquidity_fees: true,
            ..GrantFlags::default()
        };
        assert!(front_door_ttl(&fees).is_err());
    }

    #[test]
    fn proposals_cannot_widen_breakers_and_front_door_refuses_them() {
        let mut proposal = GrantTerms::new(1_000);
        proposal.breakers = spend_budget::BreakerLimits::legacy();
        let f = GrantFlags::default();
        let terms = resolve_terms(&f, Some(&proposal)).unwrap();
        assert_eq!(terms.breakers, spend_budget::BreakerLimits::default());
        let f = GrantFlags {
            max_payments_per_hour: Some(0),
            ..f
        };
        assert!(resolve_terms(&f, Some(&proposal)).is_err());
        assert!(front_door_ttl(&f).is_err());
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
        assert_eq!(
            (t.budget_msat, t.per_call_max_msat, t.ttl_secs),
            (50_000, 50_000, 1800)
        );
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
        assert!(
            resolve_terms(&f, None).is_err(),
            "per-call above the budget"
        );
    }
}

#[cfg(test)]
mod liquidity_authority_tests {
    use super::*;
    #[test]
    fn app_proposal_cannot_silently_enable_liquidity_fees() {
        let mut proposal = GrantTerms::new(10_000);
        proposal.allow_liquidity_fees = true;
        let mut flags = GrantFlags::default();
        assert!(
            !resolve_terms(&flags, Some(&proposal))
                .unwrap()
                .allow_liquidity_fees
        );
        flags.allow_liquidity_fees = true;
        assert!(
            resolve_terms(&flags, Some(&proposal))
                .unwrap()
                .allow_liquidity_fees
        );
    }
}

/// Print the complete reviewed tuple, flush it, then act over the owner socket.
/// The explicit flags are the owner's consent; no paired credential is accepted.
pub async fn cmd_approve(command: crate::cli::ApprovalCommand) -> Result<()> {
    use crate::cli::ApprovalCommand;
    let (config, request, summary) = match command {
        ApprovalCommand::FirstContact {
            client,
            op,
            to,
            max_msat,
            contact_budget_msat,
            config,
        } => {
            let summary = format!(
                "Approve first contact: client {client:?}, grant {op:?}, recipient {to:?}, maximum {max_msat} msat, contact budget {}.",
                contact_budget_msat.map(|n| format!("{n} msat")).unwrap_or_else(|| "unchanged".into())
            );
            (
                config,
                ControlRequest::ApproveFirstContact {
                    client_id: client,
                    grant_op_id: op,
                    recipient: to,
                    max_total_msat: max_msat,
                    contact_budget_msat,
                },
                summary,
            )
        }
        ApprovalCommand::Gift {
            intro,
            newcomer,
            hash,
            gift_msat,
            fee_max_msat,
            code,
            config,
        } => {
            let summary = format!(
                "Approve gift: introduction {intro:?}, newcomer {newcomer:?}, payment hash {hash:?}, gift {gift_msat} msat, maximum fee {fee_max_msat} msat, code {code:?}."
            );
            (
                config,
                ControlRequest::ApproveGift {
                    intro_id: intro,
                    newcomer,
                    payment_hash: hash,
                    gift_msat,
                    fee_max_msat,
                    code,
                },
                summary,
            )
        }
    };
    println!("{summary}");
    std::io::stdout().flush()?;
    report(send(&config, request).await?)
}

#[cfg(all(test, unix))]
mod connection_error_tests {
    use super::*;

    #[tokio::test]
    async fn socket_errors_escape_controls_even_without_approval_parsing() {
        let dir = tempfile::tempdir().unwrap();
        for control in ['\u{061c}', '\u{feff}', '\r', '\n', '\u{1b}']
            .into_iter()
            .chain('\u{200b}'..='\u{200f}')
            .chain('\u{202a}'..='\u{202e}')
            .chain('\u{2066}'..='\u{2069}')
        {
            let config = dir
                .path()
                .join(format!("missing{control}dir"))
                .join("konsensus.toml");
            let error = send(&config, ControlRequest::Status).await.unwrap_err();
            let diagnostic = format!("{error:#}");
            assert!(diagnostic.contains("owner control socket"));
            assert!(
                !diagnostic.contains(&format!("missing{control}dir")),
                "{diagnostic:?}"
            );
            assert!(
                diagnostic.contains(&control.escape_debug().to_string()),
                "{diagnostic:?}"
            );
        }
    }
}

#[cfg(test)]
mod owner_signing_tests {
    use super::*;

    const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const DEVICE: &str = "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A node directory whose recovery phrase is encrypted with `password`
    /// (or plaintext when `None`).
    fn node(password: Option<&str>) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let phrase_path = crate::mnemonic_crypto::write_mnemonic(
            &dir.path().join("mnemonic.txt"),
            PHRASE,
            password,
        )
        .unwrap();
        let config_path = dir.path().join("konsensus.toml");
        NodeConfig::default_for_tier(NodeTier::Light, phrase_path, dir.path())
            .save(&config_path)
            .unwrap();
        (dir, config_path)
    }

    fn tuple(node: String) -> control::DeviceApprovalTuple {
        control::DeviceApprovalTuple {
            node,
            client_pubkey: "11".repeat(32),
            epoch: 3,
            device_public_key: DEVICE.into(),
        }
    }

    fn fingerprint() -> String {
        let id = konsensus_core::NodeIdentity::from_mnemonic(PHRASE, "").unwrap();
        konsensus_api::pairing::identity_fingerprint(&id.node_id().to_hex())
    }

    fn typed(pw: &'static str) -> impl FnOnce() -> Result<zeroize::Zeroizing<String>> {
        move || Ok(zeroize::Zeroizing::new(pw.to_string()))
    }

    #[test]
    fn signs_with_the_owner_key_only_behind_the_typed_password() {
        let (_dir, config) = node(Some("correct horse"));
        let sig = sign_device_approval_with(&config, &tuple(fingerprint()), typed("correct horse"))
            .unwrap();
        let message = konsensus_api::pairing::device::owner_approval_message(
            &fingerprint(),
            &"11".repeat(32),
            3,
            DEVICE,
        );
        let sig = ed25519_dalek::Signature::from_slice(&hex::decode(sig).unwrap()).unwrap();
        let id = konsensus_core::NodeIdentity::from_mnemonic(PHRASE, "").unwrap();
        let secret =
            crate::mnemonic_crypto::owner_secret("correct horse", &id.node_id().to_hex()).unwrap();
        let owner = konsensus_core::OwnerApprovalKey::from_mnemonic(PHRASE, "", &secret).unwrap();
        assert!(owner
            .verifying_key()
            .verify_strict(message.as_bytes(), &sig)
            .is_ok());
        assert!(id
            .ed25519_verifying_key()
            .verify_strict(message.as_bytes(), &sig)
            .is_err());
        // A wrong password signs nothing.
        assert!(sign_device_approval_with(&config, &tuple(fingerprint()), typed("wrong")).is_err());
        // Nor for a node that is not this identity.
        let err =
            sign_device_approval_with(&config, &tuple("0".repeat(32)), typed("correct horse"))
                .unwrap_err();
        assert!(err.to_string().contains("nothing was signed"), "{err}");
    }

    #[test]
    fn fails_closed_on_a_plaintext_phrase_without_asking_for_a_password() {
        let (_dir, config) = node(None);
        let asked = std::cell::Cell::new(false);
        let err = sign_device_approval_with(&config, &tuple(fingerprint()), || {
            asked.set(true);
            Ok(zeroize::Zeroizing::new(String::new()))
        })
        .unwrap_err();
        assert!(err.to_string().contains("not encrypted"), "{err}");
        assert!(!asked.get(), "no password prompt before the refusal");
    }

    #[test]
    fn terminal_safe_escapes_controls_and_bidi_but_keeps_text() {
        let raw = "fp: AAAA\x1b[8m hidden \u{202E}rev\u{200B}\nnext";
        let safe = terminal_safe(raw);
        assert!(
            !safe.contains('\x1b') && !safe.contains('\u{202E}') && !safe.contains('\u{200B}'),
            "{safe}"
        );
        assert!(
            safe.contains("\\u{1b}[8m") && safe.contains("\\u{202e}") && safe.contains("\nnext"),
            "{safe}"
        );
    }
}
