//! konsensus-node — the BitSov v2 node binary.
//!
//! Entry point for `konsensus init` and `konsensus start`.

mod admission_quotes;
mod claim_code;
mod cli;
mod config;
mod content_server;
mod contracts;
mod delivery_prices;
mod endpoints;
mod guarded_lightning;
mod housekeeping;
mod invoice_refusals;
#[path = "cli/locked.rs"]
mod locked_cmd;
mod logging;
#[cfg(feature = "mdns")]
mod mdns;
mod mnemonic_crypto;
#[path = "cli/move_home.rs"]
mod move_home_cmd;
mod msg_handler;
mod node;
mod offline_safety;
mod onboarding;
#[path = "cli/owner.rs"]
mod owner_cmd;
mod password;
mod peer_exchange;
mod pending_handler;
mod profile_handler;
mod relay;
mod remote_access;
mod restore_fence;
mod safety;
#[path = "cli/scb_restore.rs"]
mod scb_restore;
#[path = "cli/seed.rs"]
mod seed_cmd;
mod session_handler;
mod stun;
#[path = "cli/ticket.rs"]
mod ticket_cmd;
#[path = "cli/whitelist.rs"]
mod whitelist_cmd;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use crate::cli::{Cli, Command, RepairCommand, ScbCommand, WhitelistCommand};
use crate::config::{LightningConfig, NodeConfig, NodeTier};
use crate::node::KonsensusNode;
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::types::NodeId;

/// Bridges `konsensus_storage::Storage` → `konsensus_crypto::SessionStore`.
///
/// This adapter lets the SessionManager (in konsensus-crypto) persist session
/// state through the Storage trait (in konsensus-storage) without a direct
/// dependency between the two crates.
struct StorageSessionAdapter {
    storage: Arc<dyn konsensus_storage::Storage>,
}

#[async_trait::async_trait]
impl konsensus_crypto::SessionStore for StorageSessionAdapter {
    async fn save_session(
        &self,
        peer_id: &NodeId,
        state_json: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.storage
            .store_session(peer_id, state_json)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    async fn load_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        self.storage
            .load_session(peer_id)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    async fn delete_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.storage
            .delete_session(peer_id)
            .await
            .map(|_| ())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    async fn list_sessions(&self) -> Result<Vec<NodeId>, Box<dyn std::error::Error + Send + Sync>> {
        self.storage
            .list_sessions()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let file_logging = logging::init();
    let cli = Cli::parse();

    match cli.command {
        Command::ClaimCode { config, show: _ } => claim_code::show(&config)?,
        Command::RebindInstance { config } => restore_fence::rebind_instance(&config)?,
        Command::Init {
            dir,
            non_interactive,
            tier,
            encrypt,
            password_fd,
        } => {
            let password = password_fd.map(password::read_password_fd).transpose()?;
            cmd_init(&dir, non_interactive, tier.as_deref(), encrypt, password)?;
        }
        Command::Start {
            config,
            password,
            password_file,
            password_fd,
            admission_mode,
            owner_control,
            local_owner_device,
            remote_unlock,
            home,
        } => {
            // Home mode is the existing remote state machine plus device authority.
            // Console authority remains exclusively controlled by --owner-control.
            let local_owner_device = local_owner_device || home;
            let password_source = if remote_unlock || home {
                PasswordSource::RemoteUnlock
            } else if password_fd.is_some() {
                PasswordSource::Descriptor
            } else if password_file.is_some() {
                PasswordSource::File
            } else if password.is_some() {
                PasswordSource::Flag
            } else {
                PasswordSource::None
            };
            let password = password.map(Zeroizing::new);
            let password = match &password_file {
                Some(path) => {
                    eprintln!(
                        "WARNING: reading the recovery-phrase password from {}. Any program running as \
                         this user can read that file, so the seed is protected from other OS users \
                         only. Prompting at start is the stronger setting.",
                        path.display()
                    );
                    Some(seed_cmd::read_password_file(path)?)
                }
                None => match password_fd {
                    Some(fd) => Some(password::read_password_fd(fd)?),
                    None => password,
                },
            };
            cmd_start(
                &config,
                password,
                password_source,
                admission_mode.as_deref(),
                owner_control,
                local_owner_device,
                home,
                &file_logging,
            )
            .await?;
        }
        Command::Approve { command } => {
            owner_cmd::cmd_approve(command).await?;
        }
        Command::Seed {
            command: cli::SeedCommand::Encrypt { config },
        } => {
            seed_cmd::cmd_seed_encrypt(&config)?;
        }
        Command::Device { command } => {
            owner_cmd::cmd_device(command).await?;
        }
        Command::PairStatus { config } => {
            owner_cmd::cmd_pair_status(&config).await?;
        }
        Command::Grant {
            payee,
            deny_all_payees,
            op_id,
            budget,
            for_,
            per_call,
            recipient,
            yes: _,
            config,
            allow_liquidity_fees,
        } => {
            let flags = owner_cmd::GrantFlags {
                payees: payee,
                deny_all_payees,
                allow_liquidity_fees,
                budget_sats: budget,
                window: for_,
                per_call_sats: per_call,
                recipients: recipient,
            };
            owner_cmd::cmd_grant(&config, &op_id, flags).await?;
        }
        Command::GrantRevoke {
            client_id,
            all,
            config,
        } => {
            owner_cmd::cmd_grant_revoke(&config, client_id.as_deref(), all).await?;
        }
        Command::ApproveReplacement {
            op_id,
            mnemonic,
            config,
        } => {
            owner_cmd::cmd_approve_replacement(&config, &op_id, mnemonic.as_deref()).await?;
        }
        Command::PairRevoke {
            client_id,
            keep_pairing,
            config,
        } => {
            owner_cmd::cmd_pair_revoke(&config, &client_id, keep_pairing).await?;
        }
        Command::PairTicket {
            config,
            qr,
            ttl,
            legacy,
        } => {
            ticket_cmd::cmd_pair_ticket(&config, qr, ttl, legacy)?;
        }
        Command::PairWindow { seconds, config } => {
            owner_cmd::cmd_pair_window(&config, seconds).await?;
        }
        Command::Repair { command } => match command {
            RepairCommand::MarkInitialized { config, confirm } => {
                owner_cmd::cmd_repair_mark_initialized(&config, confirm)?;
            }
        },
        Command::Restore {
            dir,
            mnemonic,
            tier,
            encrypt,
        } => {
            cmd_restore(&dir, mnemonic.as_deref(), tier.as_deref(), encrypt)?;
        }
        Command::NodeId {
            mnemonic,
            config,
            passphrase,
        } => {
            let mnemonic_path = resolve_mnemonic_path(mnemonic, config)?;
            cmd_node_id(&mnemonic_path, &passphrase)?;
        }
        Command::SignChallenge {
            challenge,
            mnemonic,
            config,
            passphrase,
        } => {
            let mnemonic_path = resolve_mnemonic_path(mnemonic, config)?;
            cmd_sign_challenge(&mnemonic_path, &passphrase, &challenge)?;
        }
        Command::MoveHome(args) => move_home_cmd::run(args).await?,
        Command::Scb { command } => match command {
            ScbCommand::Restore {
                from,
                config,
                restore_dir,
                password,
                confirm,
            } => {
                scb_restore::cmd_scb_restore(
                    &config,
                    password.as_deref(),
                    &from,
                    restore_dir.as_deref(),
                    confirm,
                )
                .await?;
            }
        },
        Command::Whitelist { command } => match command {
            WhitelistCommand::Backup {
                config,
                out,
                password,
            } => {
                whitelist_cmd::cmd_whitelist_backup(&config, password.as_deref(), out.as_deref())
                    .await?;
            }
            WhitelistCommand::Restore {
                from,
                config,
                password,
            } => {
                whitelist_cmd::cmd_whitelist_restore(&config, password.as_deref(), &from).await?;
            }
        },
    }

    Ok(())
}

/// `konsensus init` — generate identity and create config file.
fn cmd_init(
    dir: &Path,
    non_interactive: bool,
    tier_arg: Option<&str>,
    encrypt: Option<Option<String>>,
    password: Option<Zeroizing<String>>,
) -> Result<()> {
    let encrypt = encrypt.map(|value| value.map(Zeroizing::new));
    use crate::config::NodeTier;

    // Create directory if needed
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create directory: {}", dir.display()))?;

    let config_path = dir.join("konsensus.toml");
    let mnemonic_path = dir.join("mnemonic.txt");

    // Check if already initialized
    if config_path.exists() {
        anyhow::bail!(
            "node already initialized: {} exists. Remove it to re-initialize.",
            config_path.display()
        );
    }

    // Hold the state lease through initialization; bind before writing identity.
    let _state_lease = safety::ensure_generation(dir, safety::STATE_GENERATION)?;
    konsensus_lightning::ldk::ensure_no_move_home(&dir.join("ldk"))?;
    restore_fence::ensure_bound(dir)?;

    claim_code::initialize(dir)?;

    // Select tier: CLI flag > interactive prompt > default
    let tier = if let Some(t) = tier_arg {
        match t {
            "cloud" => NodeTier::Cloud,
            "light" => NodeTier::Light,
            "full" => NodeTier::Full,
            other => anyhow::bail!(
                "unknown tier '{}'. Valid options: cloud, light, full",
                other
            ),
        }
    } else if non_interactive {
        NodeTier::Light
    } else {
        prompt_tier_selection()?
    };

    // Generate new identity
    let (mnemonic, identity) =
        konsensus_core::NodeIdentity::generate().context("failed to generate identity")?;

    // In interactive mode, display the mnemonic and require 3-word confirmation.
    // Relay/cloud compatibility never means operator-held keys.
    if !non_interactive {
        confirm_mnemonic_backup(&mnemonic)?;
    }

    // Descriptor input implies encryption; clap rejects combining it with
    // --encrypt. All owned password buffers are scrubbed on errors as well.
    let password = match (password, encrypt) {
        (Some(pw), _) | (None, Some(Some(pw))) => Some(pw),
        (None, Some(None)) if !non_interactive => {
            println!("Enter a password to encrypt your mnemonic (leave empty for plaintext):");
            let mut raw = Zeroizing::new(String::new());
            std::io::stdin().read_line(&mut raw)?;
            let pw = Zeroizing::new(raw.trim().to_owned());
            if pw.is_empty() {
                None
            } else {
                Some(pw)
            }
        }
        _ => None,
    };

    let final_mnemonic_path = mnemonic_crypto::write_mnemonic(
        &mnemonic_path,
        &mnemonic,
        password.as_deref().map(String::as_str),
    )
    .with_context(|| format!("failed to write mnemonic to {}", mnemonic_path.display()))?;
    drop(password); // Last use: do not retain the password during config I/O.

    // Generate tier-specific config
    let config = NodeConfig::default_for_tier(tier, final_mnemonic_path.clone(), dir);
    config
        .save(&config_path)
        .with_context(|| format!("failed to write config to {}", config_path.display()))?;

    // #76: the marker is the sole authority signal for "this directory is
    // initialized". `init` writes it last, after the identity and config exist,
    // so a node created here is never mistaken for a fresh install — and never
    // reopens first-run pairing.
    finalize_initialized_directory(dir, "konsensus init")?;

    println!();
    println!("Node initialized successfully!");
    println!();
    println!("  Tier:       {}", tier.description());
    println!("  Node ID:    {}", identity.node_id().to_hex());
    println!("  Config:     {}", config_path.display());
    println!("  Mnemonic:   {}", final_mnemonic_path.display());
    if mnemonic_crypto::is_encrypted_path(&final_mnemonic_path) {
        println!("  Encrypted:  yes (AES-256-GCM + argon2id)");
    }
    println!();
    println!("IMPORTANT: Back up your mnemonic file securely.");
    println!("           It is the ONLY way to recover your identity.");
    println!();

    match tier {
        NodeTier::Cloud => {
            println!("Cloud/Relay mode: starts with mock backends. Hosted custody: this machine holds the seed.");
            println!("Next steps:");
            println!("  1. Run: konsensus start -c {}", config_path.display());
            println!("  2. Pair with a relay or configure a user-controlled Lightning provider.");
        }
        NodeTier::Light => {
            println!("Next steps:");
            println!("  1. Run: konsensus start -c {}", config_path.display());
            println!("     (starts with mock Lightning — works immediately)");
            println!("  2. Edit {} for production:", config_path.display());
            println!("     - Switch lightning backend to 'ldk' or 'lnd' with a node you control");
            println!("     - Add peer entries for nodes you want to connect to");
        }
        NodeTier::Full => {
            println!("Next steps:");
            println!("  1. Use embedded LDK or set up your own LND for Lightning payments");
            println!("  2. Edit {} to configure:", config_path.display());
            println!(
                "     - Keep lightning backend 'ldk', or use 'lnd' for direct LND REST access"
            );
            println!("     - Chain backend is set to 'esplora'; use your own provider for full sovereignty");
            println!("     - Storage encryption is ON by default");
            println!("  3. Run: konsensus start -c {}", config_path.display());
        }
    }

    Ok(())
}

/// `konsensus restore` — recover a node from an existing mnemonic.
fn cmd_restore(
    dir: &Path,
    mnemonic_arg: Option<&str>,
    tier_arg: Option<&str>,
    encrypt: Option<Option<String>>,
) -> Result<()> {
    use crate::config::NodeTier;

    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create directory: {}", dir.display()))?;

    let config_path = dir.join("konsensus.toml");
    let mnemonic_path = dir.join("mnemonic.txt");

    if config_path.exists() {
        anyhow::bail!(
            "node already initialized: {} exists. Remove it to re-initialize.",
            config_path.display()
        );
    }

    // Get mnemonic: from CLI arg or interactive prompt
    let mnemonic = if let Some(m) = mnemonic_arg {
        m.to_string()
    } else {
        use std::io::{self, BufRead, Write};
        println!();
        println!("Enter your 24-word recovery phrase (space-separated):");
        print!("> ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input)?;
        let trimmed = input.trim().to_string();
        let word_count = trimmed.split_whitespace().count();
        if word_count < 12 {
            anyhow::bail!(
                "mnemonic must be at least 12 words (got {word_count}). \
                 A standard recovery phrase is 12 or 24 words."
            );
        }
        if word_count != 12
            && word_count != 15
            && word_count != 18
            && word_count != 21
            && word_count != 24
        {
            anyhow::bail!(
                "invalid word count ({word_count}). BIP-39 mnemonics must be \
                 12, 15, 18, 21, or 24 words."
            );
        }
        trimmed
    };

    // Derive identity — validates BIP-39 checksum and derives all keys
    let identity = konsensus_core::NodeIdentity::from_mnemonic(&mnemonic, "").context(
        "invalid mnemonic — BIP-39 checksum failed. Please check for \
             typos or missing/extra words in your recovery phrase.",
    )?;

    // Select tier
    let tier = if let Some(t) = tier_arg {
        match t {
            "cloud" => NodeTier::Cloud,
            "light" => NodeTier::Light,
            "full" => NodeTier::Full,
            other => anyhow::bail!(
                "unknown tier '{}'. Valid options: cloud, light, full",
                other
            ),
        }
    } else {
        prompt_tier_selection()?
    };

    // Determine encryption password
    let password: Option<String> = match &encrypt {
        Some(Some(pw)) => Some(pw.clone()),
        Some(None) => {
            use std::io::{self, BufRead, Write};
            println!("Enter a password to encrypt your mnemonic (leave empty for plaintext):");
            let mut pw = String::new();
            io::stdout().flush()?;
            io::stdin().lock().read_line(&mut pw)?;
            let pw = pw.trim().to_string();
            if pw.is_empty() {
                None
            } else {
                Some(pw)
            }
        }
        _ => None,
    };
    let password_ref = password.as_deref();

    // Write mnemonic to file
    let final_mnemonic_path =
        mnemonic_crypto::write_mnemonic(&mnemonic_path, &mnemonic, password_ref)
            .with_context(|| format!("failed to write mnemonic to {}", mnemonic_path.display()))?;

    // Generate tier-specific config
    let config = NodeConfig::default_for_tier(tier, final_mnemonic_path.clone(), dir);
    config
        .save(&config_path)
        .with_context(|| format!("failed to write config to {}", config_path.display()))?;

    // Same marker-last finalization as `init`: restore into a fresh directory
    // must be classifiable as Initialized by `prepare_start` without a repair.
    finalize_initialized_directory(dir, "konsensus restore")?;

    println!();
    println!("Node restored successfully!");
    println!();
    println!("  Tier:       {}", tier.description());
    println!("  Node ID:    {}", identity.node_id().to_hex());
    println!("  Config:     {}", config_path.display());
    println!("  Mnemonic:   {}", final_mnemonic_path.display());
    if mnemonic_crypto::is_encrypted_path(&final_mnemonic_path) {
        println!("  Encrypted:  yes (AES-256-GCM + argon2id)");
    }
    println!();
    println!("Run: konsensus start -c {}", config_path.display());
    println!();

    Ok(())
}

/// Write `NODE_INITIALIZED` last, after identity and config are on disk.
fn finalize_initialized_directory(dir: &Path, initialized_by: &str) -> Result<()> {
    let marker = konsensus_api::bootstrap::DataDirLayout::new(dir).marker();
    konsensus_api::pairing::write_protected(
        &marker,
        serde_json::json!({
            "initialized_at": chrono::Utc::now().timestamp(),
            "initialized_by": initialized_by,
        })
        .to_string()
        .as_bytes(),
    )
    .with_context(|| format!("failed to write {}", marker.display()))?;
    Ok(())
}

/// Interactive tier selection prompt.
fn prompt_tier_selection() -> Result<crate::config::NodeTier> {
    use crate::config::NodeTier;
    use std::io::{self, BufRead, Write};

    println!();
    println!("How do you want to run BitSov?");
    println!();
    println!("  [1] Cloud/Relay — Paired remote access.");
    println!("                    Hosted custody: the server holds the seed.");
    println!();
    println!("  [2] Light    — Your device, user-selected Lightning.");
    println!("                 Your keys, your data. Recommended for most users.");
    println!();
    println!("  [3] Full     — Maximum sovereignty.");
    println!("                 Your keys, your channels, your chain data.");
    println!();
    println!("  You can change this later in Settings.");
    println!();

    loop {
        print!("Select tier [1/2/3] (default: 2): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().lock().read_line(&mut input)?;
        let trimmed = input.trim();

        match trimmed {
            "" | "2" => return Ok(NodeTier::Light),
            "1" => return Ok(NodeTier::Cloud),
            "3" => return Ok(NodeTier::Full),
            _ => println!("  Please enter 1, 2, or 3."),
        }
    }
}

/// Display the 24-word mnemonic and require the user to type back 3 random words.
///
/// This ensures the user has actually written down their recovery phrase
/// before the node finishes initialization. Non-interactive init is allowed for
/// scripts, but users should run the confirmation ceremony before funding.
fn confirm_mnemonic_backup(mnemonic: &str) -> Result<()> {
    use std::io::{self, BufRead, Write};

    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    if words.len() < 12 {
        // Not a standard mnemonic — skip confirmation
        return Ok(());
    }

    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  YOUR 24-WORD RECOVERY PHRASE                          ║");
    println!("║  Write these down on paper. NEVER store digitally.     ║");
    println!("║  This is the ONLY way to recover your identity.        ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    for (i, word) in words.iter().enumerate() {
        print!("  {:>2}. {:<12}", i + 1, word);
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    println!();

    // Pick 3 random word positions for verification
    let mut indices = Vec::new();
    let mut rng_state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    while indices.len() < 3 {
        // Simple LCG for picking indices — no crypto needed here
        rng_state = rng_state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let idx = (rng_state as usize >> 16) % words.len();
        if !indices.contains(&idx) {
            indices.push(idx);
        }
    }
    indices.sort_unstable();

    println!("Confirm your backup — type the requested words:");
    println!();

    let max_attempts = 3;
    for attempt in 1..=max_attempts {
        let mut all_correct = true;

        for &idx in &indices {
            print!("  Word #{}: ", idx + 1);
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().lock().read_line(&mut input)?;
            let trimmed = input.trim().to_lowercase();

            if trimmed != words[idx].to_lowercase() {
                all_correct = false;
            }
        }

        if all_correct {
            println!();
            println!("  Backup confirmed. Your recovery phrase is verified.");
            return Ok(());
        }

        if attempt < max_attempts {
            println!();
            println!(
                "  One or more words didn't match. Please try again ({}/{}).",
                attempt, max_attempts
            );
            println!();
        }
    }

    anyhow::bail!(
        "mnemonic confirmation failed after {} attempts. \
         Run `konsensus init` again to start over.",
        max_attempts
    );
}

/// Resolve the mnemonic file path from either `--mnemonic` or `--config`.
///
/// When `--config` is provided, reads the config file and extracts
/// `identity.mnemonic_file`. This is more ergonomic for scripts that
/// already know the config path but not the mnemonic location.
fn resolve_mnemonic_path(mnemonic: Option<PathBuf>, config: Option<PathBuf>) -> Result<PathBuf> {
    match (mnemonic, config) {
        (Some(m), _) => Ok(m),
        (None, Some(c)) => {
            let cfg = NodeConfig::load(&c)
                .with_context(|| format!("failed to load config from {}", c.display()))?;
            Ok(cfg.identity.mnemonic_file)
        }
        (None, None) => {
            anyhow::bail!("either --mnemonic or --config must be provided")
        }
    }
}

/// `konsensus node-id` — print the node ID from a mnemonic file.
fn cmd_node_id(mnemonic_path: &Path, passphrase: &str) -> Result<()> {
    let mnemonic = mnemonic_crypto::read_mnemonic(mnemonic_path, None)
        .with_context(|| format!("failed to read mnemonic from {}", mnemonic_path.display()))?;

    let identity = konsensus_core::NodeIdentity::from_mnemonic(&mnemonic, passphrase)
        .context("failed to derive identity from mnemonic")?;

    // Print just the hex node ID — designed for script consumption
    println!("{}", identity.node_id().to_hex());
    Ok(())
}

/// `konsensus sign-challenge` — sign a live `/auth/challenge` string; print hex.
///
/// The mnemonic file is read for key material only and is never written to stdout.
fn cmd_sign_challenge(mnemonic_path: &Path, passphrase: &str, challenge: &str) -> Result<()> {
    let signature = sign_auth_challenge(mnemonic_path, passphrase, challenge)?;
    println!("{signature}");
    Ok(())
}

/// True iff `challenge` matches the server format from `GET /api/v1/auth/challenge`:
/// `bitsov-auth-v1:<64 lowercase hex nonce>:<unix expiry digits>`.
fn is_well_formed_auth_challenge(challenge: &str) -> bool {
    const PREFIX: &str = "bitsov-auth-v1:";
    let Some(rest) = challenge.strip_prefix(PREFIX) else {
        return false;
    };
    let Some((nonce, exp)) = rest.split_once(':') else {
        return false;
    };
    nonce.len() == 64
        && nonce
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        && !exp.is_empty()
        && exp.bytes().all(|b| b.is_ascii_digit())
}

/// Produce the hex Ed25519 signature `/api/v1/auth/token` expects for `challenge`.
fn sign_auth_challenge(mnemonic_path: &Path, passphrase: &str, challenge: &str) -> Result<String> {
    let challenge = challenge.trim();
    if challenge.is_empty() {
        anyhow::bail!("challenge is required (from GET /api/v1/auth/challenge)");
    }
    // Refuse to sign anything that is not the exact live challenge wire format.
    if !is_well_formed_auth_challenge(challenge) {
        anyhow::bail!(
            "challenge must match ^bitsov-auth-v1:[0-9a-f]{{64}}:[0-9]+$ from GET /api/v1/auth/challenge"
        );
    }

    let mnemonic = mnemonic_crypto::read_mnemonic(mnemonic_path, None)
        .with_context(|| format!("failed to read mnemonic from {}", mnemonic_path.display()))?;

    let identity = konsensus_core::NodeIdentity::from_mnemonic(&mnemonic, passphrase)
        .context("failed to derive identity from mnemonic")?;

    let signature = identity.sign(challenge.as_bytes());
    Ok(hex::encode(signature.to_bytes()))
}

/// Provenance is authority: descriptor input is trusted only with the explicit
/// local owner device flag. It never enables console authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PasswordSource {
    Typed,
    Descriptor,
    RemoteUnlock,
    Flag,
    File,
    None,
}

/// Lockable starts are always hub-only, regardless of the configured opt-out.
fn channel_peers_for_start(
    lightning: &LightningConfig,
    source: PasswordSource,
) -> anyhow::Result<guarded_lightning::ChannelPeers> {
    if source == PasswordSource::RemoteUnlock
        && matches!(lightning, LightningConfig::Ldk { lsps2_service, .. } if lsps2_service.enabled)
    {
        anyhow::bail!("HUB_ONLY_WHILE_LOCKABLE: --remote-unlock cannot run an LSPS2 service");
    }
    if source == PasswordSource::RemoteUnlock {
        guarded_lightning::ChannelPeers::hub_only(lightning)
    } else {
        guarded_lightning::ChannelPeers::from_config(lightning)
    }
}

/// Startup flags select the breach-window profile, independently of password provenance.
fn is_home_profile(source: PasswordSource, local_owner_device: bool) -> bool {
    source == PasswordSource::RemoteUnlock || local_owner_device
}

/// Authority selected for this invocation, never loaded from configuration.
struct StartAuthority {
    device_authority: std::result::Result<OwnerDeviceAuthority, &'static str>,
    owner_control: bool,
    local_owner_device: bool,
}

/// Private signing material is retained only for explicit local delegation.
struct OwnerDeviceAuthority {
    verifying_key: ed25519_dalek::VerifyingKey,
    signing_key: Option<konsensus_core::OwnerApprovalKey>,
}

impl std::fmt::Debug for OwnerDeviceAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerDeviceAuthority")
            .field("verifying_key", &self.verifying_key)
            .finish_non_exhaustive()
    }
}

/// The owner authority, or why device approvals stay off.
///
/// Only an encrypted recovery phrase, with no plaintext copy beside it, whose
/// password was typed, supplied by descriptor, or remotely unlocked with explicit
/// local owner authority, yields a key. The local launcher must protect the password:
/// seed plus password derives the key (see `mnemonic_crypto::owner_secret`).
fn owner_approval_key(
    config: &NodeConfig,
    password: Option<&str>,
    source: PasswordSource,
    local_owner_device: bool,
) -> std::result::Result<OwnerDeviceAuthority, &'static str> {
    use konsensus_api::pairing::device::{
        OWNER_KEY_UNAVAILABLE, SEED_NOT_ENCRYPTED, SEED_PASSWORD_NOT_TYPED,
    };
    let path = &config.identity.mnemonic_file;
    if !mnemonic_crypto::is_encrypted_path(path) || path.with_extension("txt").exists() {
        return Err(SEED_NOT_ENCRYPTED);
    }
    if source != PasswordSource::Typed
        && !(matches!(
            source,
            PasswordSource::Descriptor | PasswordSource::RemoteUnlock
        ) && local_owner_device)
    {
        return Err(SEED_PASSWORD_NOT_TYPED);
    }
    let password = password.ok_or(OWNER_KEY_UNAVAILABLE)?;
    let mnemonic =
        mnemonic_crypto::read_mnemonic(path, Some(password)).map_err(|_| OWNER_KEY_UNAVAILABLE)?;
    let identity =
        konsensus_core::NodeIdentity::from_mnemonic(&mnemonic, &config.identity.passphrase)
            .map_err(|_| OWNER_KEY_UNAVAILABLE)?;
    let secret = mnemonic_crypto::owner_secret(password, &identity.node_id().to_hex())
        .map_err(|_| OWNER_KEY_UNAVAILABLE)?;
    konsensus_core::OwnerApprovalKey::from_mnemonic(&mnemonic, &config.identity.passphrase, &secret)
        .map(|key| OwnerDeviceAuthority {
            verifying_key: key.verifying_key(),
            signing_key: local_owner_device.then_some(key),
        })
        .map_err(|_| OWNER_KEY_UNAVAILABLE)
}

/// Where this node's seed lives, for the owner's badge
/// (`docs/protocol/REMOTE-SIGNER.md` §2). A hosted node holding its seed is
/// `hosted_custody` even when the seed is encrypted: it decrypts into the
/// operator's memory. Nothing here yields `remote_signer` or `money_signer`;
/// no signer exists (REMOTE-SIGNER.md §2 gate).
fn custody_mode(config: &NodeConfig) -> konsensus_api::custody::CustodyMode {
    use konsensus_api::custody::CustodyMode;
    let path = &config.identity.mnemonic_file;
    if config.identity.hosted || matches!(config.tier, NodeTier::Cloud) {
        CustodyMode::HostedCustody
    } else if mnemonic_crypto::is_encrypted_path(path) && !path.with_extension("txt").exists() {
        CustodyMode::EncryptedSeed
    } else {
        CustodyMode::LocalSeed
    }
}

/// Exit status after a remote first run commits: restart into locked mode.
const REMOTE_BOOTSTRAP_RESTART_EXIT: i32 = 75;

/// `konsensus start` — boot the node.
#[allow(clippy::too_many_arguments)]
async fn cmd_start(
    config_path: &Path,
    password: Option<Zeroizing<String>>,
    mut password_source: PasswordSource,
    admission_mode: Option<&str>,
    owner_control: bool,
    local_owner_device: bool,
    home: bool,
    file_logging: &logging::FileLogging,
) -> Result<()> {
    // Relative configs must become absolute before any parent()/data_dir use.
    let config_path = owner_cmd::absolute_config_path(config_path)?;
    let config_path = config_path.as_path();
    let (startup_mode, mut config) = owner_cmd::prepare_start(
        config_path,
        is_home_profile(password_source, local_owner_device),
    )
    .with_context(|| format!("failed to prepare startup from {}", config_path.display()))?;

    config.remote_access.apply_home(home);

    // ── First-run / partial-state gate (#76) ───────────────────────
    // Before any component is built, classify the data directory from file
    // facts alone. Three outcomes: serve identity-free bootstrap, start
    // normally, or REFUSE with the concrete repair action. A refusal is never
    // answered by reopening first-run authority, because "no mnemonic on a node
    // holding channel state" is a deleted key, not a fresh install.
    //
    // Balance is not consulted, here or in `classify`: an initialized node with
    // no funds is initialized.
    let data_dir = owner_cmd::data_dir_of(config_path);
    match startup_mode {
        konsensus_api::bootstrap::StartupMode::Bootstrap => {
            // A positively empty directory with --remote-unlock serves the
            // remote first run; the password then arrives only through
            // the Noise tunnel and --local-owner-device applies after unlock.
            let remote = password_source == PasswordSource::RemoteUnlock;
            let local = password.map(|password| owner_cmd::LocalOwnerBootstrap {
                password,
                enroll_device: local_owner_device,
            });
            if local_owner_device
                && !remote
                && (password_source != PasswordSource::Descriptor || local.is_none())
            {
                anyhow::bail!("--local-owner-device requires --password-fd");
            }
            file_logging
                .enable(&config_path.with_file_name("node.log"), config.logging)
                .context("failed to initialize bounded node logging")?;
            if owner_cmd::serve_bootstrap_mode(config_path, &config, local, remote).await? {
                // EX_TEMPFAIL: `Restart=on-failure` restarts the same
                // `--remote-unlock` command, which now serves locked mode.
                std::process::exit(REMOTE_BOOTSTRAP_RESTART_EXIT);
            }
            return Ok(());
        }
        konsensus_api::bootstrap::StartupMode::Initialized => {}
        // `prepare_start` has already turned this into an error.
        konsensus_api::bootstrap::StartupMode::Refuse(_) => unreachable!(),
    }

    // Fail before waiting for unlock; construction checks again under its lifetime lease.
    {
        let state_dir = config
            .identity
            .mnemonic_file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let _lease = safety::ensure_generation(state_dir, safety::STATE_GENERATION)?;
        konsensus_lightning::ldk::ensure_no_move_home(&state_dir.join("ldk"))?;
        restore_fence::ensure_bound(state_dir)?;
    }

    let channel_peers = channel_peers_for_start(&config.lightning, password_source)?;

    let password = if password_source == PasswordSource::RemoteUnlock {
        // No node, wallet, peer transport or live API exists before this returns.
        let signal = shutdown_signal()?;
        tokio::pin!(signal);
        tokio::select! {
            biased;
            result = &mut signal => { result?; return Ok(()); }
            result = locked_cmd::serve_locked_mode(config_path, &config) => Some(result?),
        }
    } else {
        password
    };

    // M1a: apply the optional `--admission-mode` CLI override BEFORE building the
    // node, so the configured mode reaches every wall (gate carrier + handshake +
    // connect). Absence leaves the config-file value (default Whitelist) — this is
    // the only way besides `konsensus.toml` to enable price-admission, and it stays
    // off-by-default. `clap`'s value_parser already constrains the input to
    // {whitelist, price-open}; the `_` arm is a defensive fail-closed to Whitelist.
    if let Some(m) = admission_mode {
        config.admission_mode = match m {
            "price-open" => konsensus_message::ReachabilityMode::PriceOpen,
            _ => konsensus_message::ReachabilityMode::Whitelist,
        };
        info!(admission_mode = ?config.admission_mode, "admission mode overridden via CLI");
        // RE-VALIDATE: NodeConfig::load already validated the FILE, but this
        // override mutates admission_mode afterwards and from_config does not
        // re-validate. Without this, `--admission-mode price-open` on a
        // settlement-off (e.g. Mock) backend would bypass the fail-closed
        // settlement guard and admit strangers preimage-only (Principle 2).
        config
            .validate()
            .context("config invalid after --admission-mode override")?;
    }

    // If the mnemonic file is encrypted and no password was provided via CLI,
    // prompt interactively. This avoids silently using an empty password which
    // would produce a decryption error.
    let mnemonic_password = if mnemonic_crypto::is_encrypted_path(&config.identity.mnemonic_file) {
        match password {
            Some(pw) => Some(pw),
            None => {
                eprintln!("Encrypted mnemonic file detected. Enter password:");
                let password =
                    rpassword::read_password().context("failed to read password from terminal")?;
                password_source = PasswordSource::Typed;
                Some(Zeroizing::new(password))
            }
        }
    } else {
        drop(password);
        None
    };

    // Validate explicit local authority before file logging, state-generation
    // markers, wallet/storage construction or listeners can write/start.
    let device_authority = owner_approval_key(
        &config,
        mnemonic_password.as_deref().map(String::as_str),
        password_source,
        local_owner_device,
    );
    if local_owner_device {
        if let Err(reason) = device_authority {
            anyhow::bail!(
                "--local-owner-device requires an available owner verifier ({reason}): {}",
                konsensus_api::pairing::device::device_approvals_off_message(reason)
            );
        }
    }
    file_logging
        .enable(&config_path.with_file_name("node.log"), config.logging)
        .context("failed to initialize bounded node logging")?;

    info!(
        config = %config_path.display(),
        node_tier = %config.tier,
        sovereignty_tier = ?config.tier.to_sovereignty_tier(),
        "starting konsensus node"
    );
    if let Some(hubs) = channel_peers.allowlist() {
        info!(
            code = konsensus_core::traits::lightning::HUB_ONLY_WHILE_LOCKABLE,
            hubs = hubs.len(),
            "new channels limited to the configured hub/LSP"
        );
    }

    // Install shutdown handling before construction: startup may now be waiting
    // in bounded chain-source backoff. Dropping construction cancels that retry;
    // readiness/API serving is only established after construction succeeds.
    // Poll signals independently of startup/cleanup I/O so the process deadline
    // also covers a stalled startup and Tokio's blocking-pool teardown.
    let signal_task = tokio::spawn(shutdown_signal()?);
    let shutdown_signal = async move { signal_task.await.context("shutdown signal task failed")? };
    tokio::pin!(shutdown_signal);
    let node = tokio::select! {
        biased;
        result = &mut shutdown_signal => {
            result?;
            info!(code = "BOOT_CANCELLED", "startup cancelled before readiness");
            return Ok(());
        }
        result = KonsensusNode::from_config_with_channel_peers(config.clone(), mnemonic_password.as_deref().map(String::as_str), channel_peers) => {
            result.context("failed to build node")?
        }
    };

    info!(node_id = %node.node_id(), "node built");

    drop(mnemonic_password); // Local mode retains only the zeroizing signer, not the password.
    let services = start_node_services(
        &node,
        &config,
        config_path,
        data_dir,
        StartAuthority {
            device_authority,
            owner_control,
            local_owner_device,
        },
    );
    run_node_lifecycle(
        services,
        &mut shutdown_signal,
        || node.shutdown(),
        node.lightning().as_ref(),
    )
    .await?;
    info!("konsensus node stopped");
    Ok(())
}

/// Start services without owning the node, so cancellation always leaves its
/// Lightning provider available to the explicit shutdown path.
async fn start_node_services<'a>(
    node: &'a KonsensusNode,
    config: &'a NodeConfig,
    config_path: &Path,
    data_dir: PathBuf,
    authority: StartAuthority,
) -> Result<(
    impl std::future::Future<Output = Result<()>>,
    impl std::future::Future<Output = Result<()>> + 'a,
    impl FnOnce() -> Result<()>,
)> {
    let StartAuthority {
        device_authority,
        owner_control,
        local_owner_device,
    } = authority;
    // ── Lightning health check ─────────────────────────────────────
    // Verify Lightning connectivity at startup so users get a clear
    // error message if their wallet is misconfigured.
    let lightning_backend = config.lightning.backend_name();
    match node.lightning().get_balance_msat().await {
        Ok(balance_msat) => {
            info!(
                backend = lightning_backend,
                balance_msat, "lightning health check passed"
            );
        }
        Err(e) => {
            if config.lightning.is_mock() {
                // Mock should never fail, but log just in case
                warn!(error = %e, "mock lightning health check failed (unexpected)");
            } else {
                // Real backend failure — give a helpful error message per tier
                let fix_hint = match config.tier {
                    crate::config::NodeTier::Cloud => {
                        "Cloud tier: check your hosted node URL and ensure the service is running."
                    }
                    crate::config::NodeTier::Light => {
                        "Light tier: check your LDK or LND settings in konsensus.toml.\n  \
                         If using hosted Lightning, ensure your configured provider is reachable.\n  \
                         You can switch to mock Lightning for testing: set [lightning] backend = \"mock\"."
                    }
                    crate::config::NodeTier::Full => {
                        "Full tier: LDK embedded Lightning is enabled by default. Your node IS its own Lightning node.\n  \
                         Keys are derived from your mnemonic. Fund the on-chain wallet to open channels.\n  \
                         To use your own LND instead, set [lightning] backend = \"lnd\" and configure its REST credentials."
                    }
                };
                warn!(
                    backend = lightning_backend,
                    error = %e,
                    "lightning health check FAILED — payments will not work"
                );
                warn!("Fix: {}", fix_hint);
                // Don't abort — the node can still operate for non-payment tasks,
                // but the payment gate will reject all messages.
            }
        }
    }

    // Replay invite-derived whitelist entries before the listener accepts
    // inbound traffic. `transport.add_to_whitelist` is dynamic in-memory
    // state; accepted invites are the persistent source of truth.
    let now_unix = current_unix_secs()?;
    let replayed_whitelist = replay_accepted_invite_whitelist(
        node.storage().as_ref(),
        node.transport().as_ref(),
        node.peer_registry().as_ref(),
        now_unix,
    )
    .await
    .context("failed to replay accepted-invite whitelist")?;
    if replayed_whitelist > 0 {
        info!(
            count = replayed_whitelist,
            "replayed accepted-invite peers into transport whitelist"
        );
    }

    // Start P2P transport
    node.start().await.context("failed to start node")?;

    // Build API state
    let (ws_tx, _ws_rx) = broadcast::channel::<Arc<konsensus_api::state::WsMessage>>(512);
    let (ws_delivery_tx, _ws_delivery_rx) =
        broadcast::channel::<Arc<konsensus_api::state::WsDeliveryStatus>>(128);

    // JWT secret: use configured value, or derive deterministically from identity
    // so that tokens survive node restarts without exposing secrets in config.
    let jwt_secret = config.api.jwt_secret.clone().unwrap_or_else(|| {
        let derived = node.identity().derive_jwt_secret();
        debug!("derived JWT secret from node identity (tokens survive restart)");
        hex::encode(derived)
    });

    // Rate limiter
    let rate_limiter = Arc::new(konsensus_api::RateLimiter::new(config.api.rate_limit_rps));

    // Audit log
    let audit_log = Arc::new(
        konsensus_api::AuditLog::open(&config.api.audit_log_path)
            .context("failed to open audit log")?,
    );
    audit_log.record(
        konsensus_api::audit::events::NODE_STARTED,
        &node.node_id().to_hex(),
        Some(serde_json::json!({
            "tier": format!("{:?}", config.network.tier),
            "p2p_addr": config.network.listen_addr.to_string(),
            "api_addr": config.api.listen_addr.to_string(),
        })),
    );

    // E2EE session manager with persistent storage
    let session_store: Arc<dyn konsensus_crypto::SessionStore> = Arc::new(StorageSessionAdapter {
        storage: Arc::clone(node.storage()),
    });
    let session_manager = Arc::new(konsensus_crypto::SessionManager::with_store(
        Arc::clone(node.identity()),
        session_store,
    ));

    // Restore E2EE sessions from previous run
    let restored = session_manager.restore_sessions().await;
    if restored > 0 {
        info!(count = restored, "restored E2EE sessions from storage");
    }

    // Initialize sovereign browser content server (if enabled)
    let content_server: Option<Arc<content_server::ContentServer>> = if config.web.enabled {
        let cs_config = content_server::ContentServerConfig {
            content_dir: std::path::PathBuf::from(&config.web.content_dir),
            max_file_size: config.web.max_page_size,
            cache_seconds: config.web.page_cache_secs,
            site_name: config.web.site_name.clone(),
        };
        match content_server::ContentServer::new(cs_config) {
            Ok(cs) => {
                info!(
                    content_dir = %config.web.content_dir,
                    "sovereign browser content server enabled"
                );
                Some(Arc::new(cs))
            }
            Err(e) => {
                warn!(error = %e, "failed to initialize content server — disabled");
                None
            }
        }
    } else {
        None
    };

    let peer_prices = Arc::new(konsensus_pricing::PeerPriceCache::new());

    // Gossip protocol validator — deduplication, rate limiting, timestamp freshness
    let gossip_validator = Arc::new(konsensus_gossip::GossipValidator::new(
        konsensus_gossip::GossipConfig::default(),
    ));

    // ── Pairing (#76) ──────────────────────────────────────────────
    // Bound to the running identity's fingerprint, so a pairing made against a
    // different identity is rejected outright at token issuance rather than
    // downgraded. `owner_control` decides whether elevation can EVER be
    // written on this node: with the flag off there is no control socket, and
    // console grant-writing calls refuse. Local device envelopes have their
    // own explicit flag; neither authority can be enabled through config.
    let identity_fingerprint =
        konsensus_api::pairing::identity_fingerprint(&node.node_id().to_hex());
    let pairing_service = Arc::new({
        let service = konsensus_api::pairing::PairingService::open(
            &data_dir,
            identity_fingerprint.clone(),
            owner_control,
        )
        .map_err(|e| anyhow::anyhow!("failed to open pairing state: {e}"))?
        // The owner command the app and console show names this exact config.
        .with_owner_config(config_path.to_path_buf())
        .with_hosted_by(config.node.hosted_by.clone());
        let service = if local_owner_device {
            service.with_local_owner_device()
        } else {
            service
        };
        match device_authority {
            Ok(key) => {
                info!("device approvals (Touch ID) enabled: owner key from the encrypted seed");
                if let Some(signer) = key.signing_key {
                    service.with_owner_signing_key(signer)
                } else {
                    service.with_owner_approval_key(key.verifying_key)
                }
            }
            Err(reason) => {
                warn!(
                    reason,
                    "device approvals (Touch ID) are OFF: {}",
                    konsensus_api::pairing::device::device_approvals_off_message(reason)
                );
                service.with_device_authority_disabled(reason)
            }
        }
    });
    remote_access::write_identity_metadata(&data_dir, node.identity(), &pairing_service)
        .context("failed to publish signed box transport identity")?;
    // Approvals are durable; only their codes lived in memory. Print fresh
    // codes for any that survived the restart instead of losing them.
    if owner_control {
        match pairing_service.reissue_owner_challenges() {
            Ok(0) => {}
            Ok(n) => info!(pending = n, "re-issued owner approval codes after restart"),
            Err(e) => warn!(error = %e, "could not re-issue owner approval codes"),
        }
    }

    // Calls: bind the owner's STUN responder before the API reports its port.
    // A configured address that cannot be bound fails boot, like the P2P port.
    let stun_socket =
        match config.calls.stun_listen {
            Some(addr) => Some(stun::bind(addr).await.map_err(|e| {
                anyhow::anyhow!("[calls] stun_listen {addr} could not be bound: {e}")
            })?),
            None => None,
        };

    // Peer endpoint for introductions and front-door cards. A configured one
    // (advertised_addr, else a concrete listen_addr) is final. Otherwise, with
    // an owner-set `stun_server`, learn the public IP once now (bounded, never
    // blocks boot) and keep it fresh in the background.
    let (configured_endpoint, configured_source) = match config.network.configured_endpoint() {
        Some((endpoint, source)) => (Some(endpoint), Some(source)),
        None => (None, None),
    };
    let introduction = konsensus_api::handlers::introduction::IntroductionSettings {
        network: config.lightning.bitcoin_network(),
        configured_endpoint,
        configured_source,
        discovered: Default::default(),
    };
    let stun_discovery = match (
        &introduction.configured_endpoint,
        config.network.stun_server_addr(),
    ) {
        (None, Ok(Some(server))) => {
            introduction.set_discovered(
                konsensus_api::handlers::introduction::PeerEndpointView::missing(
                    konsensus_api::handlers::introduction::reason::STUN_PENDING,
                ),
            );
            let peer_port = config.network.listen_addr.port();
            let family = stun::ListenerFamily::of(config.network.listen_addr);
            let first =
                stun::discover_peer_endpoint(&server, peer_port, stun::ATTEMPT_TIMEOUT, family)
                    .await;
            let ok = stun::record(&introduction, first);
            Some((server, peer_port, family, ok))
        }
        _ => None,
    };

    let api_state = Arc::new(konsensus_api::AppState {
        identity: Arc::clone(node.identity()),
        pairing: Some(Arc::clone(&pairing_service)),
        storage: Arc::clone(node.storage()),
        lightning: Arc::clone(node.lightning()),
        chain: Arc::clone(node.chain()),
        pricing: Arc::clone(node.pricing()),
        gate: Arc::clone(node.gate()),
        peer_registry: Arc::clone(node.peer_registry()),
        transport: Arc::clone(node.transport())
            as Arc<dyn konsensus_core::traits::transport::MessageTransport>,
        session_manager,
        jwt_secret,
        file_staging: Default::default(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        cors_enabled: config.api.cors_enabled,
        operator_probes_enabled: config
            .api
            .operator_probes_enabled
            .unwrap_or(matches!(config.tier, NodeTier::Cloud)),
        sensitive_identity_routes_enabled: config.tier.is_self_hosted(),
        has_identity_passphrase: !config.identity.passphrase.is_empty(),
        ws_broadcast: ws_tx.clone(),
        ws_delivery_broadcast: ws_delivery_tx.clone(),
        rate_limiter,
        mnemonic_reveal_limiter: Arc::new(
            konsensus_api::rate_limit::RateLimiter::mnemonic_reveal_default(),
        ),
        audit_log: Arc::clone(&audit_log),
        started_at: std::time::Instant::now(),
        content_dir: if config.web.enabled {
            Some(std::path::PathBuf::from(&config.web.content_dir))
        } else {
            None
        },
        web_page_price_msat: if config.web.enabled {
            Some(config.web.page_price_msat)
        } else {
            None
        },
        peer_prices: Arc::clone(&peer_prices),
        routing: Arc::clone(node.routing()),
        plaintext_cipher: Some(Arc::new(konsensus_crypto::PlaintextCacheCipher::new(
            node.identity().aes_key(),
        ))),
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        data_dir: Some(data_dir.clone()),
        backup_dir: Some(std::path::PathBuf::from(&config.backup.scb_dir)),
        lightning_backend: config.lightning.backend_name().to_string(),
        chain_backend: config.chain.backend_name().to_string(),
        gossip_validator: Some(Arc::clone(&gossip_validator)),
        introduction: introduction.clone(),
        front_door: konsensus_api::handlers::front_door::FrontDoorStore::load(
            if config.web.enabled {
                Some(std::path::Path::new(&config.web.content_dir))
            } else {
                None
            },
            Some(data_dir.as_path()),
            &node.identity().node_id().to_hex(),
        ),
        // Validated at config load; an over-ceiling policy never starts.
        sponsor: config.sponsor.policy().map_err(|e| anyhow::anyhow!(e))?,
        stun_port: stun_socket
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.port()),
        custody_mode: custody_mode(config),
    });

    // Public remote access is Noise only. Decrypted bytes go to an ephemeral
    // loopback router that deliberately omits `/api/v1/auth/local`.
    let (remote_internal_handle, remote_access_handle) = if config
        .remote_access
        .listen_addr
        .is_some()
    {
        let internal_listener =
            tokio::net::TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .context("failed to bind internal remote API listener")?;
        let internal_addr = internal_listener
            .local_addr()
            .context("failed to read internal remote API address")?;
        let tunnel_clients = Arc::new(konsensus_api::rate_limit::RemoteTunnelClients::default());
        let server = remote_access::RemoteAccessServer::bind(
            &config.remote_access,
            Arc::clone(node.identity()),
            Arc::clone(&pairing_service),
            internal_addr,
            Arc::clone(&tunnel_clients),
        )
        .await?;
        let public_addr = server.local_addr()?;
        if let Some(path) = server.pair_link_path() {
            let expires_secs = server
                .pairing_expires_in()
                .map_or(0, |duration| duration.as_secs());
            println!(
                "Remote pairing is available once at protected file {} (expires in {} seconds).",
                path.display(),
                expires_secs
            );
        }
        info!(%public_addr, "remote access Noise listener started");

        let remote_limiter = Arc::new(konsensus_api::RateLimiter::new(config.api.rate_limit_rps));
        let remote_router =
            konsensus_api::build_remote_router_with_limiter(Arc::clone(&api_state), remote_limiter)
                .layer(axum::middleware::from_fn_with_state(
                    tunnel_clients,
                    konsensus_api::rate_limit::remote_tunnel_identity,
                ))
                .into_make_service_with_connect_info::<std::net::SocketAddr>();
        let mut internal_shutdown = node.shutdown_rx();
        let internal_handle = tokio::spawn(async move {
            if let Err(error) = axum::serve(internal_listener, remote_router)
                .with_graceful_shutdown(async move {
                    let _ = internal_shutdown.changed().await;
                })
                .await
            {
                error!(%error, "internal remote API listener failed");
            }
        });
        let remote_handle = tokio::spawn(server.serve(node.shutdown_rx()));
        (Some(internal_handle), Some(remote_handle))
    } else {
        (None, None)
    };

    // Calls: the owner's STUN binding responder, if configured.
    let stun_handle = stun_socket.map(|socket| {
        tokio::spawn(stun::serve(
            socket,
            stun::Limits::default(),
            node.shutdown_rx(),
        ))
    });

    let stun_discovery_handle = stun_discovery.map(|(server, peer_port, family, ok)| {
        tokio::spawn(stun::refresh_loop(
            introduction.clone(),
            server,
            peer_port,
            family,
            ok,
            node.shutdown_rx(),
        ))
    });

    // ── Spawn background tasks ─────────────────────────────────────────

    let offline_safety_handle = tokio::spawn(offline_safety::run(
        Arc::clone(node.lightning()),
        Arc::clone(node.chain()),
        data_dir.clone(),
        node.shutdown_rx(),
    ));

    // R3 SEAM-B (Route B, default-off). Build the relay engine ONLY when
    // `[relay] enabled`; a disabled node holds `None`, allocates no engine/store,
    // and its receive path is byte-identical to a non-relay build. The backend is
    // operator-selected: the durable SQLite store (P8.1) when `[relay]
    // durable_db_path` is set, else the non-durable in-memory store (smoke-test
    // only; held mail lost on restart). The node NEVER creates the durable DB or
    // schema — that is the operator's `[MANUAL]` CREATE TABLE migration, and a
    // missing file/schema fails boot loudly rather than silently degrading.
    let relay_engine = if config.relay.enabled {
        let store: Arc<dyn relay::RelayBindingStore> = match config.relay.durable_db_path.as_deref()
        {
            Some(path) => {
                let pool = relay::open_durable_pool(path).await.map_err(|e| {
                    anyhow::anyhow!(
                        "[relay] durable_db_path is set to {} but the durable store could \
                             not be opened ({e:?}) — run the [MANUAL] CREATE TABLE migration first",
                        path.display()
                    )
                })?;
                info!(path = %path.display(), "[relay] using DURABLE SQLite store");
                Arc::new(relay::SqliteRelayStore::new(pool))
            }
            None => {
                warn!(
                    "[relay] enabled with a NON-DURABLE in-memory store — held mail is LOST \
                         on restart; smoke-test only (set [relay] durable_db_path for production \
                         relay)"
                );
                Arc::new(relay::InMemoryRelayStore::new())
            }
        };
        Some(Arc::new(relay::RelayEngine::new(
            store,
            relay::RelayPolicy::inert_default(),
        )))
    } else {
        None
    };

    // Calls: settle or release call reservations a crash left (from the
    // operation journal) before the receive loop and the outbox resend start.
    match konsensus_api::calls::recover(node.storage().as_ref()).await {
        Ok((committed, released)) if committed + released > 0 => {
            info!(committed, released, "recovered call reservations")
        }
        Ok(_) => {}
        Err(e) => {
            warn!(error = %e, "call state recovery failed; reservations stay for a same-operation retry")
        }
    }
    // Incoming call signals still held were never admitted (refusal cleanup
    // failed, or a crash): withdraw them before anything can read them.
    match konsensus_api::calls::withdraw_held(node.storage().as_ref(), true).await {
        Ok(n) if n > 0 => warn!(
            withdrawn = n,
            "withdrew call signals whose admission never finished"
        ),
        Ok(_) => {}
        Err(e) => {
            warn!(error = %e, "held call signals not withdrawn yet; they stay invisible until the next sweep")
        }
    }

    // Incoming message handler (routes P2P messages through payment gate to storage + WS)
    let msg_handle = tokio::spawn(msg_handler::run(msg_handler::MsgHandlerDeps {
        transport: Arc::clone(node.transport()),
        transport_ack: Arc::clone(node.transport()),
        storage: Arc::clone(node.storage()),
        gate: Arc::clone(node.gate()),
        pricing: Arc::clone(node.pricing()),
        lightning: Arc::clone(node.lightning()),
        chain: Arc::clone(node.chain()),
        peer_registry: Arc::clone(node.peer_registry()),
        session_manager: Arc::clone(&api_state.session_manager),
        nonce_adapter: Arc::new(konsensus_storage::StorageNonceAdapter::new(Arc::clone(
            node.storage(),
        ))),
        content_server: content_server.clone(),
        front_door: api_state.front_door.clone(),
        routing: Arc::clone(node.routing()),
        identity: Arc::clone(node.identity()),
        plaintext_cipher: Arc::new(konsensus_crypto::PlaintextCacheCipher::new(
            node.identity().aes_key(),
        )),
        ws_tx,
        audit_log: Arc::clone(&audit_log),
        // M1a: wire the configured admission mode into the receive-path gate carrier.
        // Without this the field would be a latent no-op.
        admission_mode: config.admission_mode,
        // R3 SEAM-B: backend selected above (durable SQLite vs in-memory).
        relay_engine,
        shutdown_rx: node.shutdown_rx(),
    }));

    // Pending delivery flusher — delivers queued messages when peers reconnect
    let (pending_tx, pending_rx) = tokio::sync::mpsc::channel::<NodeId>(64);
    let pending_handle = tokio::spawn(pending_handler::run(pending_handler::PendingHandlerDeps {
        identity: Arc::clone(node.identity()),
        storage: Arc::clone(node.storage()),
        transport: Arc::clone(node.transport()) as Arc<dyn MessageTransport>,
        audit_log: Arc::clone(&audit_log),
        send_timestamps: Arc::clone(&api_state.send_timestamps),
        pending_rx,
        shutdown_rx: node.shutdown_rx(),
    }));

    let (auto_channel_tx, auto_channel_rx) =
        tokio::sync::mpsc::channel::<onboarding::auto_channel::AutoChannelEvent>(64);
    let auto_channel_notifier = Arc::new(onboarding::notify::LocalUiNotifier::new(
        ws_delivery_tx.clone(),
    ));
    let auto_channel_handle = tokio::spawn(onboarding::auto_channel::run(
        onboarding::auto_channel::AutoChannelDeps {
            storage: Arc::clone(node.storage()),
            lightning: Arc::clone(node.lightning()),
            chain: Arc::clone(node.chain()),
            notifier: auto_channel_notifier,
            event_rx: auto_channel_rx,
            shutdown_rx: node.shutdown_rx(),
            subsidy: config.onboarding_subsidy.clone(),
        },
    ));
    let advertised_lightning_addr = config.lightning.advertised_lightning_addr();

    let hosting_ws_delivery_tx = ws_delivery_tx.clone();

    // Session/control event handler — E2EE negotiation, pricing, invoices, peer exchange, gossip
    let session_handle = tokio::spawn(session_handler::run(session_handler::SessionHandlerDeps {
        content_server: content_server.clone(),
        front_door: api_state.front_door.clone(),
        min_admission_cost_msat: node.gate().min_admission_cost_msat(),
        privacy: config.privacy.clone(),
        peer_exchange_floor: config.payment_gate.min_admission_cost_msat.unwrap_or(0),
        transport: Arc::clone(node.transport()),
        session_manager: Arc::clone(&api_state.session_manager),
        storage: Arc::clone(node.storage()),
        our_node_id: *node.node_id(),
        identity: Arc::clone(node.identity()),
        audit_log: Arc::clone(&audit_log),
        pricing: Arc::clone(node.pricing()),
        chain: Arc::clone(node.chain()),
        peer_prices: Arc::clone(&peer_prices),
        peer_registry: Arc::clone(node.peer_registry()),
        routing: Arc::clone(node.routing()),
        gossip_validator: Arc::clone(&gossip_validator),
        send_timestamps: Arc::clone(&api_state.send_timestamps),
        lightning: Arc::clone(node.lightning()),
        lightning_addr: advertised_lightning_addr,
        mock_lightning: config.lightning.is_mock(),
        invoice_requests: Arc::clone(&api_state.invoice_requests),
        peer_ln_pubkeys: Arc::clone(&api_state.peer_ln_pubkeys),
        ws_broadcast: api_state.ws_broadcast.clone(),
        ws_delivery_tx,
        pending_tx,
        auto_channel_tx,
        shutdown_rx: node.shutdown_rx(),
    }));

    // ── Owner control socket (#76) ──────────────────────────────────
    // Started ONLY under `--owner-control`. This is the single channel that can
    // write a console spend grant or execute a live-identity replacement, and it is a
    // Unix socket at mode 0600 rather than an HTTP route precisely because the
    // requesting app could call an HTTP route.
    //
    // A failure to bind is fatal rather than a silent downgrade: an owner who
    // asked for the channel must not end up running without it and discover
    // later that nothing can be approved.
    if owner_control {
        #[cfg(unix)]
        {
            let ctx = Arc::new(konsensus_api::control::ControlContext {
                service: Arc::clone(&pairing_service),
                identity_fingerprint: identity_fingerprint.clone(),
                data_dir: data_dir.clone(),
                mnemonic_path: config.identity.mnemonic_file.clone(),
                replacement_guard: owner_cmd::replacement_guard(&data_dir, config),
            });
            let server =
                konsensus_api::control::ControlServer::bind(&data_dir, ctx).with_context(|| {
                    format!(
                        "failed to bind the owner control socket at {}",
                        data_dir.join(konsensus_api::control::SOCKET_FILE).display()
                    )
                })?;
            info!(
                socket = %server.path().display(),
                "owner-run mode: elevation can be granted at this socket"
            );
            tokio::spawn(
                server
                    .with_approval_state(Arc::clone(&api_state))
                    .serve(node.shutdown_rx()),
            );
        }
        #[cfg(not(unix))]
        {
            anyhow::bail!(
                "--owner-control requires Unix domain sockets, which this platform does not \
                 provide. Elevation is unavailable here rather than served over a weaker channel."
            );
        }
    } else {
        info!(
            "no owner control socket (start with --owner-control to enable one). Paired clients \
             may request elevation and cannot obtain it in this deployment."
        );
    }

    // G1: inherited owner grants need expiry cleanup in sidecar mode too.
    // Reads/startup also purge; failed deletions remain retryable.
    let grant_cleanup_handle = tokio::spawn(konsensus_api::control::sweep_expired_grants(
        Arc::clone(&pairing_service),
        node.shutdown_rx(),
    ));

    // API server — fatal error if it fails (node is unusable without API)
    let api_addr = config.api.listen_addr;
    let shutdown_rx_api = node.shutdown_rx();
    let (api_fatal_tx, api_fatal_rx) = tokio::sync::oneshot::channel::<String>();
    let send_timestamps_for_cleanup = Arc::clone(&api_state.send_timestamps);
    let peer_ln_pubkeys_for_cleanup = Arc::clone(&api_state.peer_ln_pubkeys);
    let invoice_requests_for_cleanup = Arc::clone(&api_state.invoice_requests);

    let api_handle = tokio::spawn(async move {
        if let Err(e) = konsensus_api::serve(api_addr, api_state, shutdown_rx_api).await {
            error!(error = %e, "API server fatal error — node cannot operate without API");
            let _ = api_fatal_tx.send(e.to_string());
        }
    });

    // ── Housekeeping tasks ──────────────────────────────────────────────

    let nonce_cleanup_handle = tokio::spawn(housekeeping::run_nonce_cleanup(
        Arc::clone(node.storage()),
        node.shutdown_rx(),
    ));

    let pending_cleanup_handle = tokio::spawn(housekeeping::run_pending_cleanup(
        Arc::clone(node.storage()),
        node.shutdown_rx(),
    ));

    let timestamps_cleanup_handle = tokio::spawn(housekeeping::run_timestamps_cleanup(
        send_timestamps_for_cleanup,
        node.shutdown_rx(),
    ));

    let retention_days = config.storage.retention_days();
    let retention_handle = tokio::spawn(housekeeping::run_retention_cleanup(
        Arc::clone(node.storage()),
        retention_days,
        node.shutdown_rx(),
    ));

    let price_refresh_handle = tokio::spawn(housekeeping::run_price_refresh(
        Arc::clone(node.storage()),
        Arc::clone(node.transport()),
        Arc::clone(node.pricing()),
        Arc::clone(node.chain()),
        Arc::clone(node.routing()),
        config.clone(),
        node.shutdown_rx(),
    ));

    let gossip_eviction_handle = tokio::spawn(housekeeping::run_gossip_eviction(
        Arc::clone(&gossip_validator),
        node.shutdown_rx(),
    ));

    let peer_ln_cleanup_handle = tokio::spawn(housekeeping::run_peer_ln_pubkeys_cleanup(
        peer_ln_pubkeys_for_cleanup,
        Arc::clone(node.transport()),
        node.shutdown_rx(),
    ));

    let invoice_req_cleanup_handle = tokio::spawn(housekeeping::run_invoice_requests_cleanup(
        invoice_requests_for_cleanup,
        node.shutdown_rx(),
    ));

    let fiat_provider: Arc<dyn konsensus_fiat::FiatRateProvider> =
        Arc::new(konsensus_fiat::providers::MempoolSpaceProvider::new());
    let fiat_snapshot_handle = tokio::spawn(housekeeping::run_fiat_rate_snapshot(
        Arc::clone(node.storage()),
        fiat_provider,
        node.shutdown_rx(),
    ));

    let hosting_payment_handle = tokio::spawn(contracts::hosting_pay::run_daily_payment_task(
        contracts::hosting_pay::HostingPaymentTaskDeps {
            storage: Arc::clone(node.storage()),
            lightning: Arc::clone(node.lightning()),
            ws_delivery_tx: hosting_ws_delivery_tx,
            shutdown_rx: node.shutdown_rx(),
        },
    ));

    // RV-RESTORE producer: keep an encrypted whitelist sidecar next to the SCB so a
    // mnemonic+SCB restore onto fresh hardware also recovers peers + accepted
    // invites (the SCB carries only LDK channel state). Best-effort; never fatal.
    let whitelist_backup_handle = tokio::spawn(housekeeping::run_whitelist_backup(
        Arc::clone(node.storage()),
        Arc::clone(node.identity()),
        Path::new(&config.backup.scb_dir).join(whitelist_cmd::WHITELIST_BACKUP_NAME),
        node.shutdown_rx(),
    ));

    info!(
        p2p_addr = %config.network.listen_addr,
        api_addr = %api_addr,
        node_id = %node.node_id(),
        "konsensus node running"
    );

    // Warn if running with mock Lightning — payments are simulated, not real.
    if config.lightning.is_mock() {
        warn!(
            tier = ?config.tier,
            "running with mock Lightning — payments are simulated. \
             Edit konsensus.toml to configure a real Lightning backend \
             (LDK or LND) for production use. LNbits cannot enforce routing-fee ceilings and is rejected at startup."
        );
    }

    let service_failure = async move {
        match api_fatal_rx.await {
            Ok(err_msg) => anyhow::bail!("API server failed to start: {err_msg}"),
            Err(_) => anyhow::bail!("API server exited unexpectedly"),
        }
    };
    let cleanup = async move {
        audit_log.record(
            konsensus_api::audit::events::NODE_SHUTDOWN,
            &node.node_id().to_hex(),
            None,
        );

        // Persist fee rate EMA snapshot before shutdown — prevents losing up to
        // 10 minutes of smoothing history (the periodic save interval).
        if let Some(chain_engine) = node
            .pricing()
            .as_any()
            .downcast_ref::<konsensus_pricing::ChainAwarePricingEngine>()
        {
            if let Some(snapshot) = chain_engine.snapshot().await {
                KonsensusNode::save_fee_rate_snapshot(config, &snapshot);
                debug!("fee rate EMA snapshot saved on shutdown");
            }
        }

        // The lifecycle gives snapshots and task joins 10s; the final grant
        // prune runs separately even if this future is dropped at the deadline.
        if let Err(e) = msg_handle.await {
            warn!(error = %e, "message handler task panicked");
        }
        if let Err(e) = pending_handle.await {
            warn!(error = %e, "pending delivery task panicked");
        }
        if let Err(e) = auto_channel_handle.await {
            warn!(error = %e, "auto-channel task panicked");
        }
        if let Err(e) = session_handle.await {
            warn!(error = %e, "session handler task panicked");
        }
        if let Err(e) = offline_safety_handle.await {
            warn!(error = %e, "offline safety task panicked");
        }
        if let Err(e) = nonce_cleanup_handle.await {
            warn!(error = %e, "nonce cleanup task panicked");
        }
        if let Err(e) = pending_cleanup_handle.await {
            warn!(error = %e, "pending cleanup task panicked");
        }
        if let Err(e) = timestamps_cleanup_handle.await {
            warn!(error = %e, "timestamps cleanup task panicked");
        }
        if let Err(e) = retention_handle.await {
            warn!(error = %e, "retention cleanup task panicked");
        }
        if let Err(e) = price_refresh_handle.await {
            warn!(error = %e, "price refresh task panicked");
        }
        if let Err(e) = gossip_eviction_handle.await {
            warn!(error = %e, "gossip eviction task panicked");
        }
        if let Err(e) = peer_ln_cleanup_handle.await {
            warn!(error = %e, "peer_ln_pubkeys cleanup task panicked");
        }
        if let Err(e) = invoice_req_cleanup_handle.await {
            warn!(error = %e, "invoice_requests cleanup task panicked");
        }
        if let Err(e) = fiat_snapshot_handle.await {
            warn!(error = %e, "fiat rate snapshot task panicked");
        }
        if let Err(e) = hosting_payment_handle.await {
            warn!(error = %e, "operator hosting payment task panicked");
        }
        if let Err(e) = whitelist_backup_handle.await {
            warn!(error = %e, "whitelist backup task panicked");
        }
        if let Err(e) = api_handle.await {
            warn!(error = %e, "API server task panicked");
        }
        if let Err(e) = grant_cleanup_handle.await {
            warn!(error = %e, "grant cleanup task panicked");
        }
        if let Some(h) = stun_discovery_handle {
            if let Err(e) = h.await {
                warn!(error = %e, "STUN discovery task panicked");
            }
        }
        if let Some(h) = stun_handle {
            if let Err(e) = h.await {
                warn!(error = %e, "STUN responder task panicked");
            }
        }
        if let Some(h) = remote_access_handle {
            if let Err(e) = h.await {
                warn!(error = %e, "remote access task panicked");
            }
        }
        if let Some(h) = remote_internal_handle {
            if let Err(e) = h.await {
                warn!(error = %e, "internal remote API task panicked");
            }
        }
        Ok(())
    };
    let finalize = move || {
        // A grant can expire while the API/backend tasks drain, after the sweeper
        // has stopped. Purge once more before returning from graceful shutdown;
        // surface an I/O failure instead of claiming that cleanup succeeded.
        pairing_service
            .prune_expired_grants()
            .context("failed to purge expired spend grants at shutdown")?;

        Ok(())
    };
    Ok((service_failure, cleanup, finalize))
}

// 15s for monitor persistence + 10s for task cleanup, with a 30s wall-clock
// backstop. Keep this comfortably below docs/operations/konsensus.service's 45s.
const SHUTDOWN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

fn arm_shutdown_deadline() {
    static ARMED: std::sync::Once = std::sync::Once::new();
    ARMED.call_once(|| {
        // A Tokio timeout cannot interrupt synchronous I/O or Runtime::drop
        // waiting for spawn_blocking. This thread intentionally lives until
        // process exit, including after cmd_start returns successfully.
        std::thread::spawn(|| {
            std::thread::sleep(SHUTDOWN_DEADLINE);
            eprintln!("shutdown deadline exceeded; forcing exit; channel monitor persistence may be incomplete");
            std::process::exit(1);
        });
    });
}

/// Register both Unix handlers before returning, including SIGINT during startup.
fn shutdown_signal() -> Result<impl std::future::Future<Output = Result<()>>> {
    #[cfg(unix)]
    let (mut sigint, mut sigterm) = (
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .context("failed to install SIGINT handler")?,
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("failed to install SIGTERM handler")?,
    );
    Ok(async move {
        #[cfg(unix)]
        tokio::select! {
            signal = sigint.recv() => { signal.context("SIGINT stream closed")?; }
            signal = sigterm.recv() => { signal.context("SIGTERM stream closed")?; }
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c()
            .await
            .context("failed to listen for Ctrl+C")?;
        arm_shutdown_deadline();
        Ok(())
    })
}

/// Own the whole post-construction lifecycle: cancellation during startup must
/// persist Lightning state too. Cleanup exists only once services are ready.
async fn run_node_lifecycle<Failure, Cleanup, Finalize>(
    startup: impl std::future::Future<Output = Result<(Failure, Cleanup, Finalize)>>,
    signal: impl std::future::Future<Output = Result<()>>,
    stop_work: impl FnOnce(),
    lightning: &dyn konsensus_core::traits::lightning::LightningProvider,
) -> Result<()>
where
    Failure: std::future::Future<Output = Result<()>>,
    Cleanup: std::future::Future<Output = Result<()>>,
    Finalize: FnOnce() -> Result<()>,
{
    tokio::pin!(signal);
    let (run_result, cleanup) = tokio::select! {
        biased;
        result = &mut signal => (result, None),
        result = startup => match result {
            Err(e) => (Err(e), None),
            Ok((failure, cleanup, finalize)) => {
                let result = tokio::select! {
                    biased;
                    result = &mut signal => result,
                    result = failure => {
                        if let Err(e) = result {
                            error!(error = %e, "API server failed — shutting down node");
                        }
                        // Preserve a clean exit for API bind/serve failures:
                        // Restart=on-failure must not loop on a busy port.
                        Ok(())
                    },
                };
                (result, Some((cleanup, finalize)))
            }
        },
    };
    info!("initiating graceful shutdown");
    let lightning_result = shutdown_node(stop_work, lightning).await;
    if let Err(e) = &lightning_result {
        warn!(error = %e, "Lightning shutdown failed; channel monitor persistence may be incomplete");
    }
    let cleanup_result = if let Some((cleanup, finalize)) = cleanup {
        let drain_result = tokio::time::timeout(std::time::Duration::from_secs(10), cleanup)
            .await
            .context("node cleanup timed out after 10s")
            .and_then(|result| result);
        // Grants can expire while tasks drain. This must run outside the join
        // timeout, including on error; the process-wide deadline still applies.
        let finalize_result = finalize();
        finalize_result.and(drain_result)
    } else {
        Ok(())
    };
    // All cleanup runs even when startup, the API, or Lightning failed.
    run_result?;
    lightning_result?;
    cleanup_result
}

/// Stop new work before persisting monitors, while the Tokio runtime is alive.
async fn shutdown_node(
    stop_work: impl FnOnce(),
    lightning: &dyn konsensus_core::traits::lightning::LightningProvider,
) -> Result<()> {
    // Also bound shutdown initiated by a fatal API error rather than a signal.
    arm_shutdown_deadline();
    stop_work();
    tokio::time::timeout(std::time::Duration::from_secs(15), lightning.shutdown())
        .await
        .context("Lightning shutdown timed out after 15s")?
        .context("Lightning shutdown returned error")?;
    info!("Lightning provider shut down cleanly");
    Ok(())
}

fn current_unix_secs() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before UNIX_EPOCH")?
        .as_secs())
}

async fn replay_accepted_invite_whitelist(
    storage: &dyn konsensus_storage::Storage,
    transport: &dyn MessageTransport,
    peer_registry: &tokio::sync::RwLock<konsensus_message::PeerRegistry>,
    now_unix: u64,
) -> Result<usize> {
    let records = storage
        .list_active_accepted_invites(now_unix)
        .await
        .context("list active accepted invites")?;

    for record in &records {
        let inviter = NodeId::from_bytes(record.inviter_pubkey);
        let peer = match storage.get_peer(&inviter).await? {
            Some(peer) => peer,
            None => {
                let peer = konsensus_storage::Peer::new(inviter);
                storage
                    .upsert_peer(&peer)
                    .await
                    .with_context(|| format!("upsert accepted-invite peer {}", inviter.to_hex()))?;
                peer
            }
        };

        {
            let mut registry = peer_registry.write().await;
            if registry.get(&inviter).is_none() {
                let addr = peer
                    .address
                    .as_deref()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
                registry.add(konsensus_message::PeerEntry {
                    node_id: inviter,
                    addr,
                    label: peer.display_name.clone(),
                    auto_connect: false,
                });
            }
        }
        transport.add_to_whitelist(&inviter).await;
    }

    Ok(records.len())
}

#[cfg(test)]
mod whitelist_replay_tests {
    use super::*;
    use async_trait::async_trait;
    use konsensus_core::traits::transport::TransportError;
    use konsensus_core::UkmEnvelope;
    use konsensus_storage::{AcceptedInviteRecord, SqliteStorage, Storage};
    use std::collections::HashSet;
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct RecordingTransport {
        whitelist: Mutex<HashSet<NodeId>>,
    }

    #[async_trait]
    impl MessageTransport for RecordingTransport {
        async fn send(
            &self,
            _peer: &NodeId,
            _envelope: &UkmEnvelope,
        ) -> Result<(), TransportError> {
            Err(TransportError::Other(
                "not implemented in test transport".into(),
            ))
        }

        async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
            Err(TransportError::Other(
                "not implemented in test transport".into(),
            ))
        }

        async fn connect(&self, _peer: &NodeId, _addr: &str) -> Result<(), TransportError> {
            Err(TransportError::Other(
                "not implemented in test transport".into(),
            ))
        }

        async fn disconnect(&self, _peer: &NodeId) -> Result<(), TransportError> {
            Ok(())
        }

        async fn is_connected(&self, _peer: &NodeId) -> bool {
            false
        }

        async fn connected_peers(&self) -> Vec<NodeId> {
            Vec::new()
        }

        async fn add_to_whitelist(&self, peer: &NodeId) {
            self.whitelist.lock().await.insert(*peer);
        }
    }

    #[tokio::test]
    async fn whitelist_replay_adds_active_accepted_invites_and_skips_expired() {
        let storage = SqliteStorage::in_memory().await.expect("sqlite");
        let active_pubkey = [2u8; 32];
        let expired_pubkey = [3u8; 32];
        let active_inviter = NodeId::from_bytes(active_pubkey);
        let expired_inviter = NodeId::from_bytes(expired_pubkey);

        storage
            .add_accepted_invite(&AcceptedInviteRecord {
                nonce: [9u8; 16],
                inviter_pubkey: active_pubkey,
                expiry_unix: 200,
                accepted_at: 10,
            })
            .await
            .expect("insert active invite");
        storage
            .add_accepted_invite(&AcceptedInviteRecord {
                nonce: [8u8; 16],
                inviter_pubkey: expired_pubkey,
                expiry_unix: 99,
                accepted_at: 11,
            })
            .await
            .expect("insert expired invite");

        let transport = RecordingTransport::default();
        let registry = tokio::sync::RwLock::new(konsensus_message::PeerRegistry::new());
        let replayed = replay_accepted_invite_whitelist(&storage, &transport, &registry, 100)
            .await
            .expect("replay whitelist");

        let whitelist = transport.whitelist.lock().await;
        assert_eq!(replayed, 1);
        assert!(whitelist.contains(&active_inviter));
        assert!(!whitelist.contains(&expired_inviter));
        drop(whitelist);

        assert!(
            storage
                .get_peer(&active_inviter)
                .await
                .expect("active accepted-invite peer")
                .is_some(),
            "startup replay must repair the durable peer row"
        );
        assert!(
            registry.read().await.whitelist().contains(&active_inviter),
            "startup replay must repair the gate PeerRegistry"
        );
        assert!(
            storage
                .get_peer(&expired_inviter)
                .await
                .expect("expired accepted-invite peer")
                .is_none(),
            "expired accepted invites must not be replayed into peers"
        );
    }

    async fn make_storage(path: &str, encrypted: bool, key: &[u8; 32]) -> Arc<dyn Storage> {
        let sqlite = SqliteStorage::open(path).await.expect("open sqlite");
        if encrypted {
            Arc::new(konsensus_storage::EncryptedStorage::new(sqlite, key))
        } else {
            Arc::new(sqlite)
        }
    }

    /// RV-RESTORE end-to-end: a node backed up with `write_whitelist_backup`, then
    /// restored onto FRESH hardware with `read_whitelist_backup`, recovers BOTH
    /// admission paths — the REST `/peers` peer (gate whitelist via the P3-2
    /// boot-load) AND the invite-only peer (transport whitelist via accepted-invite
    /// replay). The invite-only half is the path the SCB never covered: without this
    /// sidecar a restored node rejected every invite-onboarded peer `NotWhitelisted`.
    /// Parameterized over plaintext and EncryptedStorage so the wrapper layer that
    /// the running node actually uses is exercised too.
    async fn fresh_hardware_recovery(encrypted: bool) {
        use crate::node::merge_persisted_peers;
        use konsensus_message::PeerRegistry;
        use konsensus_storage::Peer;

        let dir = tempfile::tempdir().expect("tempdir");
        let storage_key = [0x42u8; 32]; // mnemonic-derived AES storage key (same on A and B)
        let backup_key = [0x11u8; 32]; // mnemonic-derived sidecar seal key
        let sidecar = dir.path().join(crate::whitelist_cmd::WHITELIST_BACKUP_NAME);

        let rest_pubkey = [21u8; 32];
        let inviter_pubkey = [77u8; 32];
        let rest_peer = NodeId::from_bytes(rest_pubkey);
        let inviter = NodeId::from_bytes(inviter_pubkey);

        // Source node A: one REST peer + one invite-only peer. Producer writes sidecar.
        {
            let a = make_storage(
                dir.path().join("a.db").to_str().unwrap(),
                encrypted,
                &storage_key,
            )
            .await;
            let mut peer = Peer::new(rest_peer);
            peer.address = Some("203.0.113.50:9735".into());
            a.upsert_peer(&peer).await.expect("upsert rest peer");
            a.add_accepted_invite(&AcceptedInviteRecord {
                nonce: [5u8; 16],
                inviter_pubkey,
                expiry_unix: 4_000_000_000,
                accepted_at: 1_800_000_000,
            })
            .await
            .expect("add invite");

            crate::whitelist_cmd::write_whitelist_backup(a.as_ref(), &backup_key, &sidecar)
                .await
                .expect("write sidecar");
        }

        // Fresh node B: empty DB (new hardware). Consumer restores the sidecar.
        let b = make_storage(
            dir.path().join("b.db").to_str().unwrap(),
            encrypted,
            &storage_key,
        )
        .await;
        assert!(
            b.list_peers().await.unwrap().is_empty(),
            "fresh node must start with an empty whitelist"
        );
        let restored =
            crate::whitelist_cmd::read_whitelist_backup(b.as_ref(), &backup_key, &sidecar)
                .await
                .expect("read sidecar");
        assert_eq!(restored, 1, "the REST peer row is restored");

        // Gate half: the REST peer lands in the boot-loaded gate whitelist (P3-2).
        let mut registry = PeerRegistry::new();
        merge_persisted_peers(&mut registry, b.list_peers().await.unwrap());
        assert!(
            registry.whitelist().contains(&rest_peer),
            "REST peer must recover into the gate whitelist (encrypted={encrypted})"
        );

        // Invite-only half: the accepted-invite inviter is replayed into the
        // gate registry and transport whitelist at boot — the relationship the
        // SCB alone lost.
        let transport = RecordingTransport::default();
        let registry = tokio::sync::RwLock::new(registry);
        let replayed =
            replay_accepted_invite_whitelist(b.as_ref(), &transport, &registry, 1_900_000_000)
                .await
                .expect("replay invites");
        assert_eq!(replayed, 1, "the accepted invite is replayed");
        assert!(
            registry.read().await.whitelist().contains(&inviter),
            "invite-only peer must recover into the gate whitelist (encrypted={encrypted})"
        );
        assert!(
            transport.whitelist.lock().await.contains(&inviter),
            "invite-only peer must recover into the transport whitelist (encrypted={encrypted})"
        );
    }

    #[tokio::test]
    async fn fresh_hardware_restore_recovers_invite_only_peer_plaintext() {
        fresh_hardware_recovery(false).await;
    }

    #[tokio::test]
    async fn fresh_hardware_restore_recovers_invite_only_peer_encrypted() {
        fresh_hardware_recovery(true).await;
    }

    /// Coupling guard pinned to DBH1 (#207). This wiring is correct, but the
    /// *completeness* of the backup above 1000 peers depends on DBH1: on this
    /// branch base (origin/main) `list_peers()` still caps at `LIMIT 1000`, so
    /// `WhitelistBackup::collect` truncates a >1000-peer whitelist BEFORE this
    /// producer ever seals it. `#[ignore]`d so the coupling is documented, not
    /// hidden — un-ignore once DBH1 is on the base (the full 1500-peer backup
    /// round-trip is already proven in konsensus-storage by #207).
    #[tokio::test]
    #[ignore = "requires DBH1 (#207): origin/main list_peers still caps at LIMIT 1000"]
    async fn recovery_is_complete_above_1000_peers_after_dbh1() {
        use konsensus_storage::Peer;

        let dir = tempfile::tempdir().expect("tempdir");
        let backup_key = [0x11u8; 32];
        let sidecar = dir.path().join(crate::whitelist_cmd::WHITELIST_BACKUP_NAME);

        let src = SqliteStorage::open(dir.path().join("src.db").to_str().unwrap())
            .await
            .expect("open src");
        for i in 0u32..1500 {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&i.to_be_bytes());
            src.upsert_peer(&Peer::new(NodeId::from_bytes(bytes)))
                .await
                .expect("seed peer");
        }
        crate::whitelist_cmd::write_whitelist_backup(&src, &backup_key, &sidecar)
            .await
            .expect("write sidecar");

        let dst = SqliteStorage::open(dir.path().join("dst.db").to_str().unwrap())
            .await
            .expect("open dst");
        crate::whitelist_cmd::read_whitelist_backup(&dst, &backup_key, &sidecar)
            .await
            .expect("read sidecar");
        assert_eq!(
            dst.list_peers().await.unwrap().len(),
            1500,
            "a >1000-peer whitelist must survive backup+restore once DBH1 removes the cap"
        );
    }
}

#[cfg(test)]
#[path = "tests/main_tests.rs"]
mod tests;

#[cfg(test)]
mod owner_key_startup_tests {
    use super::*;
    use konsensus_api::pairing::device::{SEED_NOT_ENCRYPTED, SEED_PASSWORD_NOT_TYPED};

    #[test]
    fn home_channels_are_hub_only_and_only_non_lockable_starts_can_opt_out() {
        let default: LightningConfig = toml::from_str("backend = 'ldk'").unwrap();
        let opt_out: LightningConfig =
            toml::from_str("backend = 'ldk'\nhub_only_channels = false").unwrap();
        for source in [
            PasswordSource::Typed,
            PasswordSource::Descriptor,
            PasswordSource::RemoteUnlock,
            PasswordSource::Flag,
            PasswordSource::File,
            PasswordSource::None,
        ] {
            assert_eq!(
                channel_peers_for_start(&default, source)
                    .unwrap()
                    .allowlist(),
                Some(vec![]),
                "{source:?}"
            );
            assert_eq!(
                channel_peers_for_start(&opt_out, source)
                    .unwrap()
                    .allowlist(),
                if source == PasswordSource::RemoteUnlock {
                    Some(vec![])
                } else {
                    None
                },
                "{source:?}"
            );
        }
    }

    #[test]
    fn home_profile_all_password_sources() {
        for (source, without_local_owner) in [
            (PasswordSource::Typed, false),
            (PasswordSource::Descriptor, false),
            (PasswordSource::RemoteUnlock, true),
            (PasswordSource::Flag, false),
            (PasswordSource::File, false),
            (PasswordSource::None, false),
        ] {
            assert_eq!(
                is_home_profile(source, false),
                without_local_owner,
                "{source:?}"
            );
            assert!(is_home_profile(source, true), "{source:?}");
        }
    }

    const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn config(password: Option<&str>) -> (tempfile::TempDir, NodeConfig) {
        let dir = tempfile::tempdir().unwrap();
        let path =
            mnemonic_crypto::write_mnemonic(&dir.path().join("mnemonic.txt"), PHRASE, password)
                .unwrap();
        let config = NodeConfig::default_for_tier(crate::config::NodeTier::Light, path, dir.path());
        (dir, config)
    }

    fn node_id() -> String {
        konsensus_core::NodeIdentity::from_mnemonic(PHRASE, "")
            .unwrap()
            .node_id()
            .to_hex()
    }

    #[test]
    fn device_approvals_stay_off_unless_the_seed_is_encrypted_and_the_password_typed() {
        // Plaintext seed: off, whatever the password.
        let (_d, plain) = config(None);
        assert_eq!(
            owner_approval_key(&plain, None, PasswordSource::Typed, false).unwrap_err(),
            SEED_NOT_ENCRYPTED
        );
        // Encrypted, but a plaintext copy is still beside it: off.
        let (dir, enc) = config(Some("correct horse"));
        std::fs::write(dir.path().join("mnemonic.txt"), PHRASE).unwrap();
        assert_eq!(
            owner_approval_key(&enc, Some("correct horse"), PasswordSource::Typed, false)
                .unwrap_err(),
            SEED_NOT_ENCRYPTED
        );
        std::fs::remove_file(dir.path().join("mnemonic.txt")).unwrap();
        // Encrypted, password from a flag or file: off.
        assert_eq!(
            owner_approval_key(
                &enc,
                Some("correct horse"),
                PasswordSource::Descriptor,
                false
            )
            .unwrap_err(),
            SEED_PASSWORD_NOT_TYPED
        );
        // Encrypted and typed: on, and it is exactly the key the owner CLI signs with.
        let node_key =
            owner_approval_key(&enc, Some("correct horse"), PasswordSource::Typed, false).unwrap();
        let secret = mnemonic_crypto::owner_secret("correct horse", &node_id()).unwrap();
        let cli_key = konsensus_core::OwnerApprovalKey::from_mnemonic(PHRASE, "", &secret)
            .unwrap()
            .verifying_key();
        assert_eq!(node_key.verifying_key, cli_key);
        // A wrong password yields no key at all.
        assert!(owner_approval_key(&enc, Some("wrong"), PasswordSource::Typed, false).is_err());
    }

    #[test]
    fn only_local_owner_start_retains_the_delegation_signer() {
        let (_dir, enc) = config(Some("correct horse"));
        let typed =
            owner_approval_key(&enc, Some("correct horse"), PasswordSource::Typed, false).unwrap();
        assert!(typed.signing_key.is_none());
        let local = owner_approval_key(
            &enc,
            Some("correct horse"),
            PasswordSource::Descriptor,
            true,
        )
        .unwrap();
        let signer = local
            .signing_key
            .as_ref()
            .expect("local delegation needs the signer");
        assert_eq!(signer.verifying_key(), typed.verifying_key);
        let message = b"local owner delegation startup wiring";
        typed
            .verifying_key
            .verify_strict(message, &signer.sign(message))
            .unwrap();
    }

    #[test]
    fn local_owner_authority_cannot_be_enabled_by_config() {
        let (_dir, cfg) = config(None);
        for flag in ["home", "local_owner_device", "remote_unlock"] {
            let mut value = toml::Value::try_from(&cfg).unwrap();
            let _: NodeConfig = value.clone().try_into().unwrap();
            value
                .as_table_mut()
                .unwrap()
                .insert(flag.into(), true.into());
            let error = value.try_into::<NodeConfig>().unwrap_err().to_string();
            assert!(
                error.contains(&format!("unknown field `{flag}`")),
                "{error}"
            );
        }
    }

    #[test]
    fn local_descriptor_derives_the_typed_key_only_with_explicit_authority() {
        let (dir, enc) = config(Some("correct horse"));
        let typed =
            owner_approval_key(&enc, Some("correct horse"), PasswordSource::Typed, false).unwrap();
        assert_eq!(
            owner_approval_key(
                &enc,
                Some("correct horse"),
                PasswordSource::Descriptor,
                true
            )
            .unwrap()
            .verifying_key,
            typed.verifying_key
        );
        for source in [
            PasswordSource::Descriptor,
            PasswordSource::Flag,
            PasswordSource::File,
            PasswordSource::None,
        ] {
            assert_eq!(
                owner_approval_key(&enc, Some("correct horse"), source, false).unwrap_err(),
                SEED_PASSWORD_NOT_TYPED
            );
        }
        for source in [
            PasswordSource::Flag,
            PasswordSource::File,
            PasswordSource::None,
        ] {
            assert_eq!(
                owner_approval_key(&enc, Some("correct horse"), source, true).unwrap_err(),
                SEED_PASSWORD_NOT_TYPED
            );
        }
        assert!(owner_approval_key(&enc, Some("wrong"), PasswordSource::Descriptor, true).is_err());
        std::fs::write(dir.path().join("mnemonic.txt"), PHRASE).unwrap();
        assert_eq!(
            owner_approval_key(
                &enc,
                Some("correct horse"),
                PasswordSource::Descriptor,
                true
            )
            .unwrap_err(),
            SEED_NOT_ENCRYPTED
        );
        let (_dir, plain) = config(None);
        assert_eq!(
            owner_approval_key(
                &plain,
                Some("correct horse"),
                PasswordSource::Descriptor,
                true
            )
            .unwrap_err(),
            SEED_NOT_ENCRYPTED
        );
    }

    #[test]
    fn an_old_plaintext_copy_of_the_seed_does_not_yield_the_owner_key() {
        // Whoever copied mnemonic.txt before `seed encrypt` has the seed but not
        // the password; the owner key needs both.
        let (_d, enc) = config(Some("correct horse"));
        let node_key =
            owner_approval_key(&enc, Some("correct horse"), PasswordSource::Typed, false).unwrap();
        for guess in [[0u8; 32], [1u8; 32]] {
            let from_seed_only =
                konsensus_core::OwnerApprovalKey::from_mnemonic(PHRASE, "", &guess).unwrap();
            assert_ne!(from_seed_only.verifying_key(), node_key.verifying_key);
        }
        let other_password = mnemonic_crypto::owner_secret("another password", &node_id()).unwrap();
        assert_ne!(
            konsensus_core::OwnerApprovalKey::from_mnemonic(PHRASE, "", &other_password)
                .unwrap()
                .verifying_key(),
            node_key.verifying_key
        );
    }
}

#[cfg(test)]
mod custody_mode_tests {
    use super::*;
    use konsensus_api::custody::CustodyMode;

    const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn config(password: Option<&str>, tier: NodeTier) -> (tempfile::TempDir, NodeConfig) {
        let dir = tempfile::tempdir().unwrap();
        let path =
            mnemonic_crypto::write_mnemonic(&dir.path().join("mnemonic.txt"), PHRASE, password)
                .unwrap();
        let config = NodeConfig::default_for_tier(tier, path, dir.path());
        (dir, config)
    }

    #[test]
    fn the_seed_on_disk_decides_local_or_encrypted() {
        let (_d, plain) = config(None, NodeTier::Light);
        assert_eq!(custody_mode(&plain), CustodyMode::LocalSeed);
        let (dir, enc) = config(Some("correct horse"), NodeTier::Full);
        assert_eq!(custody_mode(&enc), CustodyMode::EncryptedSeed);
        // A plaintext copy beside the .enc is still a plaintext seed.
        std::fs::write(dir.path().join("mnemonic.txt"), PHRASE).unwrap();
        assert_eq!(custody_mode(&enc), CustodyMode::LocalSeed);
    }

    #[test]
    fn a_hosted_node_is_hosted_custody_even_with_an_encrypted_seed() {
        let (_d, mut enc) = config(Some("correct horse"), NodeTier::Light);
        enc.identity.hosted = true;
        assert_eq!(custody_mode(&enc), CustodyMode::HostedCustody);
        let (_d, cloud) = config(Some("correct horse"), NodeTier::Cloud);
        assert_eq!(custody_mode(&cloud), CustodyMode::HostedCustody);
        let (_d, cloud_plain) = config(None, NodeTier::Cloud);
        assert_eq!(custody_mode(&cloud_plain), CustodyMode::HostedCustody);
    }

    #[test]
    fn no_config_claims_a_remote_signer() {
        for tier in [NodeTier::Cloud, NodeTier::Light, NodeTier::Full] {
            for password in [None, Some("correct horse")] {
                for hosted in [false, true] {
                    let (_d, mut c) = config(password, tier);
                    c.identity.hosted = hosted;
                    assert_ne!(custody_mode(&c), CustodyMode::RemoteSigner);
                    assert_ne!(custody_mode(&c), CustodyMode::MoneySigner);
                }
            }
        }
    }

    #[test]
    fn hosted_is_read_from_the_identity_section_and_omitted_when_false() {
        let (_d, c) = config(None, NodeTier::Light);
        let text = toml::to_string(&c).unwrap();
        assert!(
            !text.contains("hosted"),
            "a default config does not mention hosted"
        );
        let hosted: NodeConfig =
            toml::from_str(&text.replace("[identity]\n", "[identity]\nhosted = true\n")).unwrap();
        assert!(hosted.identity.hosted);
        assert_eq!(custody_mode(&hosted), CustodyMode::HostedCustody);
    }
}

#[cfg(all(test, feature = "regtest-e2e"))]
#[path = "tests/regtest_e2e.rs"]
mod regtest_e2e;

#[cfg(test)]
#[path = "tests/shutdown.rs"]
mod shutdown_tests;
