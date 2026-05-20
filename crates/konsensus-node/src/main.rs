//! konsensus-node — the BitSov v2 node binary.
//!
//! Entry point for `konsensus init` and `konsensus start`.

mod cli;
mod config;
mod contracts;
mod content_server;
mod housekeeping;
mod mnemonic_crypto;
mod msg_handler;
mod node;
mod onboarding;
mod pending_handler;
mod profile_handler;
mod session_handler;
#[path = "cli/scb_restore.rs"]
mod scb_restore;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::types::NodeId;
use crate::cli::{Cli, Command, ScbCommand};
use crate::config::{NodeConfig, NodeTier};
use crate::node::KonsensusNode;

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

    async fn list_sessions(
        &self,
    ) -> Result<Vec<NodeId>, Box<dyn std::error::Error + Send + Sync>> {
        self.storage
            .list_sessions()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing.
    //
    // Two layers are composed:
    // 1. `fmt` layer — structured JSON-compatible log output with env-filter.
    // 2. `PlaintextGuardLayer` (Principle 4) — shuts the node down immediately
    //    if any log event records a non-empty `plaintext` field, preventing
    //    accidental exfiltration of E2EE message content through the log stream.
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,konsensus=debug"));

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_filter(env_filter),
        )
        .with(konsensus_api::metrics::PlaintextGuardLayer)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Init { dir, non_interactive, tier, encrypt } => {
            cmd_init(&dir, non_interactive, tier.as_deref(), encrypt)?;
        }
        Command::Start { config, password } => {
            cmd_start(&config, password.as_deref()).await?;
        }
        Command::Restore { dir, mnemonic, tier, encrypt } => {
            cmd_restore(&dir, mnemonic.as_deref(), tier.as_deref(), encrypt)?;
        }
        Command::NodeId { mnemonic, config, passphrase } => {
            let mnemonic_path = resolve_mnemonic_path(mnemonic, config)?;
            cmd_node_id(&mnemonic_path, &passphrase)?;
        }
        Command::SignChallenge { mnemonic, config, passphrase } => {
            let mnemonic_path = resolve_mnemonic_path(mnemonic, config)?;
            cmd_sign_challenge(&mnemonic_path, &passphrase)?;
        }
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
    }

    Ok(())
}

/// `konsensus init` — generate identity and create config file.
fn cmd_init(dir: &Path, non_interactive: bool, tier_arg: Option<&str>, encrypt: Option<Option<String>>) -> Result<()> {
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
    let (mnemonic, identity) = konsensus_core::NodeIdentity::generate()
        .context("failed to generate identity")?;

    // In interactive mode, display the mnemonic and require 3-word confirmation.
    // Relay/cloud compatibility never means operator-held keys.
    if !non_interactive {
        confirm_mnemonic_backup(&mnemonic)?;
    }

    // Determine encryption password
    let password: Option<String> = match &encrypt {
        Some(Some(pw)) => Some(pw.clone()),
        Some(None) if !non_interactive => {
            // Prompt for password interactively
            println!("Enter a password to encrypt your mnemonic (leave empty for plaintext):");
            let mut pw = String::new();
            std::io::stdin().read_line(&mut pw)?;
            let pw = pw.trim().to_string();
            if pw.is_empty() { None } else { Some(pw) }
        }
        _ => None,
    };
    let password_ref = password.as_deref();

    // Write mnemonic to file (encrypted if password provided)
    let final_mnemonic_path = mnemonic_crypto::write_mnemonic(
        &mnemonic_path,
        &mnemonic,
        password_ref,
    )
    .with_context(|| format!("failed to write mnemonic to {}", mnemonic_path.display()))?;

    // Generate tier-specific config
    let config = NodeConfig::default_for_tier(tier, final_mnemonic_path.clone(), dir);
    config
        .save(&config_path)
        .with_context(|| format!("failed to write config to {}", config_path.display()))?;

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
            println!("Cloud/Relay mode: starts with mock backends and user-held keys.");
            println!("Next steps:");
            println!("  1. Run: konsensus start -c {}", config_path.display());
            println!("  2. Pair with a relay or configure a user-controlled Lightning provider.");
        }
        NodeTier::Light => {
            println!("Next steps:");
            println!("  1. Run: konsensus start -c {}", config_path.display());
            println!("     (starts with mock Lightning — works immediately)");
            println!("  2. Edit {} for production:", config_path.display());
            println!("     - Switch lightning backend to 'ldk', 'lnbits', or another provider you control");
            println!("     - Add peer entries for nodes you want to connect to");
        }
        NodeTier::Full => {
            println!("Next steps:");
            println!("  1. Set up LND or CLN for Lightning payments");
            println!("  2. Edit {} to configure:", config_path.display());
            println!("     - Switch lightning backend to 'lnbits' (pointing to your LND)");
            println!("     - Chain backend is set to 'esplora' (mempool.space)");
            println!("     - Storage encryption is ON by default");
            println!("  3. Run: konsensus start -c {}", config_path.display());
        }
    }

    Ok(())
}

/// `konsensus restore` — recover a node from an existing mnemonic.
fn cmd_restore(dir: &Path, mnemonic_arg: Option<&str>, tier_arg: Option<&str>, encrypt: Option<Option<String>>) -> Result<()> {
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
        if word_count != 12 && word_count != 15 && word_count != 18 && word_count != 21 && word_count != 24 {
            anyhow::bail!(
                "invalid word count ({word_count}). BIP-39 mnemonics must be \
                 12, 15, 18, 21, or 24 words."
            );
        }
        trimmed
    };

    // Derive identity — validates BIP-39 checksum and derives all keys
    let identity = konsensus_core::NodeIdentity::from_mnemonic(&mnemonic, "")
        .context(
            "invalid mnemonic — BIP-39 checksum failed. Please check for \
             typos or missing/extra words in your recovery phrase."
        )?;

    // Select tier
    let tier = if let Some(t) = tier_arg {
        match t {
            "cloud" => NodeTier::Cloud,
            "light" => NodeTier::Light,
            "full" => NodeTier::Full,
            other => anyhow::bail!("unknown tier '{}'. Valid options: cloud, light, full", other),
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
            if pw.is_empty() { None } else { Some(pw) }
        }
        _ => None,
    };
    let password_ref = password.as_deref();

    // Write mnemonic to file
    let final_mnemonic_path = mnemonic_crypto::write_mnemonic(&mnemonic_path, &mnemonic, password_ref)
        .with_context(|| format!("failed to write mnemonic to {}", mnemonic_path.display()))?;

    // Generate tier-specific config
    let config = NodeConfig::default_for_tier(tier, final_mnemonic_path.clone(), dir);
    config
        .save(&config_path)
        .with_context(|| format!("failed to write config to {}", config_path.display()))?;

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

/// Interactive tier selection prompt.
fn prompt_tier_selection() -> Result<crate::config::NodeTier> {
    use crate::config::NodeTier;
    use std::io::{self, BufRead, Write};

    println!();
    println!("How do you want to run BitSov?");
    println!();
    println!("  [1] Cloud/Relay — Paired remote access.");
    println!("                    Your keys stay yours; relay support is optional.");
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
            println!("  One or more words didn't match. Please try again ({}/{}).", attempt, max_attempts);
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
fn resolve_mnemonic_path(
    mnemonic: Option<PathBuf>,
    config: Option<PathBuf>,
) -> Result<PathBuf> {
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

/// `konsensus sign-challenge` — sign "konsensus-auth" and print hex signature.
fn cmd_sign_challenge(mnemonic_path: &Path, passphrase: &str) -> Result<()> {
    let mnemonic = mnemonic_crypto::read_mnemonic(mnemonic_path, None)
        .with_context(|| format!("failed to read mnemonic from {}", mnemonic_path.display()))?;

    let identity = konsensus_core::NodeIdentity::from_mnemonic(&mnemonic, passphrase)
        .context("failed to derive identity from mnemonic")?;

    let signature = identity.sign(b"konsensus-auth");
    println!("{}", hex::encode(signature.to_bytes()));
    Ok(())
}

/// `konsensus start` — boot the node.
async fn cmd_start(config_path: &Path, password: Option<&str>) -> Result<()> {
    // Load configuration
    let config = NodeConfig::load(config_path)
        .with_context(|| format!("failed to load config from {}", config_path.display()))?;

    // If the mnemonic file is encrypted and no password was provided via CLI,
    // prompt interactively. This avoids silently using an empty password which
    // would produce a decryption error.
    let mnemonic_password: Option<String> = if mnemonic_crypto::is_encrypted_path(&config.identity.mnemonic_file) {
        match password {
            Some(pw) => Some(pw.to_string()),
            None => {
                eprintln!("Encrypted mnemonic file detected. Enter password:");
                let pw = rpassword::read_password()
                    .context("failed to read password from stdin")?;
                Some(pw)
            }
        }
    } else {
        password.map(String::from)
    };

    info!(
        config = %config_path.display(),
        node_tier = %config.tier,
        sovereignty_tier = ?config.tier.to_sovereignty_tier(),
        "starting konsensus node"
    );

    // Build the node
    let node = KonsensusNode::from_config(config.clone(), mnemonic_password.as_deref())
        .await
        .context("failed to build node")?;

    info!(node_id = %node.node_id(), "node built");

    // ── Lightning health check ─────────────────────────────────────
    // Verify Lightning connectivity at startup so users get a clear
    // error message if their wallet is misconfigured.
    let lightning_backend = config.lightning.backend_name();
    match node.lightning().get_balance_msat().await {
        Ok(balance_msat) => {
            info!(
                backend = lightning_backend,
                balance_msat,
                "lightning health check passed"
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
                        "Light tier: check your LNbits API URL and admin key in konsensus.toml.\n  \
                         If using hosted Lightning, ensure https://lightning.konsensus.network is reachable.\n  \
                         You can switch to mock Lightning for testing: set [lightning] backend = \"mock\"."
                    }
                    crate::config::NodeTier::Full => {
                        "Full tier: LDK embedded Lightning is enabled by default. Your node IS its own Lightning node.\n  \
                         Keys are derived from your mnemonic. Fund the on-chain wallet to open channels.\n  \
                         To use LNbits instead, edit konsensus.toml and set [lightning] backend = \"lnbits\"."
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
    let (ws_delivery_tx, _ws_delivery_rx) = broadcast::channel::<Arc<konsensus_api::state::WsDeliveryStatus>>(128);

    // JWT secret: use configured value, or derive deterministically from identity
    // so that tokens survive node restarts without exposing secrets in config.
    let jwt_secret = config
        .api
        .jwt_secret
        .clone()
        .unwrap_or_else(|| {
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

    let api_state = Arc::new(konsensus_api::AppState {
        identity: Arc::clone(node.identity()),
        storage: Arc::clone(node.storage()),
        lightning: Arc::clone(node.lightning()),
        chain: Arc::clone(node.chain()),
        pricing: Arc::clone(node.pricing()),
        gate: Arc::clone(node.gate()),
        peer_registry: Arc::clone(node.peer_registry()),
        transport: Arc::clone(node.transport()) as Arc<dyn konsensus_core::traits::transport::MessageTransport>,
        session_manager,
        jwt_secret,
        cors_enabled: config.api.cors_enabled,
        operator_probes_enabled: config
            .api
            .operator_probes_enabled
            .unwrap_or(matches!(config.tier, NodeTier::Cloud)),
        sensitive_identity_routes_enabled: config.tier.is_self_hosted(),
        ws_broadcast: ws_tx.clone(),
        ws_delivery_broadcast: ws_delivery_tx.clone(),
        rate_limiter,
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
        data_dir: config_path.parent().map(|p| p.to_path_buf()),
        lightning_backend: config.lightning.backend_name().to_string(),
        chain_backend: config.chain.backend_name().to_string(),
        gossip_validator: Some(Arc::clone(&gossip_validator)),
    });

    // ── Spawn background tasks ─────────────────────────────────────────

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
        nonce_adapter: Arc::new(konsensus_storage::StorageNonceAdapter::new(
            Arc::clone(node.storage()),
        )),
        content_server: content_server.clone(),
        routing: Arc::clone(node.routing()),
        identity: Arc::clone(node.identity()),
        plaintext_cipher: Arc::new(konsensus_crypto::PlaintextCacheCipher::new(
            node.identity().aes_key(),
        )),
        ws_tx,
        audit_log: Arc::clone(&audit_log),
        shutdown_rx: node.shutdown_rx(),
    }));

    // Pending delivery flusher — delivers queued messages when peers reconnect
    let (pending_tx, pending_rx) = tokio::sync::mpsc::channel::<NodeId>(64);
    let pending_handle = tokio::spawn(pending_handler::run(pending_handler::PendingHandlerDeps {
        storage: Arc::clone(node.storage()),
        transport: Arc::clone(node.transport()) as Arc<dyn MessageTransport>,
        audit_log: Arc::clone(&audit_log),
        send_timestamps: Arc::clone(&api_state.send_timestamps),
        pending_rx,
        shutdown_rx: node.shutdown_rx(),
    }));

    let (auto_channel_tx, auto_channel_rx) =
        tokio::sync::mpsc::channel::<onboarding::auto_channel::AutoChannelEvent>(64);
    let auto_channel_notifier =
        Arc::new(onboarding::notify::LocalUiNotifier::new(ws_delivery_tx.clone()));
    let auto_channel_handle = tokio::spawn(onboarding::auto_channel::run(
        onboarding::auto_channel::AutoChannelDeps {
            storage: Arc::clone(node.storage()),
            lightning: Arc::clone(node.lightning()),
            chain: Arc::clone(node.chain()),
            notifier: auto_channel_notifier,
            event_rx: auto_channel_rx,
            shutdown_rx: node.shutdown_rx(),
        },
    ));
    let advertised_lightning_addr = config.lightning.advertised_lightning_addr();

    let hosting_ws_delivery_tx = ws_delivery_tx.clone();

    // Session/control event handler — E2EE negotiation, pricing, invoices, peer exchange, gossip
    let session_handle = tokio::spawn(session_handler::run(session_handler::SessionHandlerDeps {
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
        invoice_requests: Arc::clone(&api_state.invoice_requests),
        peer_ln_pubkeys: Arc::clone(&api_state.peer_ln_pubkeys),
        ws_broadcast: api_state.ws_broadcast.clone(),
        ws_delivery_tx,
        pending_tx,
        auto_channel_tx,
        shutdown_rx: node.shutdown_rx(),
    }));

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
             (LNbits or LDK) for production use."
        );
    }

    // Wait for shutdown signal (SIGINT, SIGTERM, or API server fatal error).
    // SIGTERM is what `kill`, systemd, and container runtimes send.
    // SIGINT is Ctrl+C in a terminal.
    // API fatal error means the API server could not start (e.g. port in use)
    // and the node is unusable without it.
    {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate())
                .context("failed to install SIGTERM handler")?;
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("received SIGINT (Ctrl+C)");
                }
                _ = sigterm.recv() => {
                    info!("received SIGTERM");
                }
                result = api_fatal_rx => {
                    if let Ok(err_msg) = result {
                        error!(error = %err_msg, "API server failed to start — shutting down node");
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    result.context("failed to listen for Ctrl+C")?;
                    info!("received SIGINT (Ctrl+C)");
                }
                result = api_fatal_rx => {
                    if let Ok(err_msg) = result {
                        error!(error = %err_msg, "API server failed to start — shutting down node");
                    }
                }
            }
        }
    }

    info!("shutdown signal received, initiating graceful shutdown");
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
            KonsensusNode::save_fee_rate_snapshot(&config, &snapshot);
            debug!("fee rate EMA snapshot saved on shutdown");
        }
    }

    node.shutdown();

    // L0e (2026-04-30): cleanly stop the Lightning backend BEFORE the
    // tokio runtime begins tearing down. LDK queues `ChannelMonitor`
    // persistence calls during shutdown; if we wait for `Drop`, the
    // runtime is already half-gone and those persistence calls can be
    // silently lost — real-fund-loss class on a live channel. Bound by
    // 15s wall clock so a misbehaving backend cannot block process exit.
    let lightning_shutdown_deadline = std::time::Duration::from_secs(15);
    match tokio::time::timeout(
        lightning_shutdown_deadline,
        node.lightning().shutdown(),
    )
    .await
    {
        Ok(Ok(())) => debug!("Lightning provider shut down cleanly"),
        Ok(Err(e)) => warn!(error = %e, "Lightning shutdown returned error"),
        Err(_) => warn!(
            "Lightning shutdown timed out after {}s — channel monitor persistence may be incomplete",
            lightning_shutdown_deadline.as_secs()
        ),
    }

    // Wait for all background tasks with a timeout to prevent hanging.
    // 10 seconds is generous — all tasks should exit within milliseconds
    // once the shutdown watch channel fires.
    let shutdown_timeout = std::time::Duration::from_secs(10);
    let join_result = tokio::time::timeout(
        shutdown_timeout,
        async {
            if let Err(e) = msg_handle.await { warn!(error = %e, "message handler task panicked"); }
            if let Err(e) = pending_handle.await { warn!(error = %e, "pending delivery task panicked"); }
            if let Err(e) = auto_channel_handle.await { warn!(error = %e, "auto-channel task panicked"); }
            if let Err(e) = session_handle.await { warn!(error = %e, "session handler task panicked"); }
            if let Err(e) = nonce_cleanup_handle.await { warn!(error = %e, "nonce cleanup task panicked"); }
            if let Err(e) = pending_cleanup_handle.await { warn!(error = %e, "pending cleanup task panicked"); }
            if let Err(e) = timestamps_cleanup_handle.await { warn!(error = %e, "timestamps cleanup task panicked"); }
            if let Err(e) = retention_handle.await { warn!(error = %e, "retention cleanup task panicked"); }
            if let Err(e) = price_refresh_handle.await { warn!(error = %e, "price refresh task panicked"); }
            if let Err(e) = gossip_eviction_handle.await { warn!(error = %e, "gossip eviction task panicked"); }
            if let Err(e) = peer_ln_cleanup_handle.await { warn!(error = %e, "peer_ln_pubkeys cleanup task panicked"); }
            if let Err(e) = invoice_req_cleanup_handle.await { warn!(error = %e, "invoice_requests cleanup task panicked"); }
            if let Err(e) = fiat_snapshot_handle.await { warn!(error = %e, "fiat rate snapshot task panicked"); }
            if let Err(e) = hosting_payment_handle.await { warn!(error = %e, "operator hosting payment task panicked"); }
            if let Err(e) = api_handle.await { warn!(error = %e, "API server task panicked"); }
        },
    )
    .await;

    if join_result.is_err() {
        warn!("shutdown timed out after {}s, forcing exit", shutdown_timeout.as_secs());
    }

    info!("konsensus node stopped");
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
    now_unix: u64,
) -> Result<usize> {
    let records = storage
        .list_active_accepted_invites(now_unix)
        .await
        .context("list active accepted invites")?;

    for record in &records {
        let inviter = NodeId::from_bytes(record.inviter_pubkey);
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
        async fn send(&self, _peer: &NodeId, _envelope: &UkmEnvelope) -> Result<(), TransportError> {
            Err(TransportError::Other("not implemented in test transport".into()))
        }

        async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
            Err(TransportError::Other("not implemented in test transport".into()))
        }

        async fn connect(&self, _peer: &NodeId, _addr: &str) -> Result<(), TransportError> {
            Err(TransportError::Other("not implemented in test transport".into()))
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
        let replayed = replay_accepted_invite_whitelist(&storage, &transport, 100)
            .await
            .expect("replay whitelist");

        let whitelist = transport.whitelist.lock().await;
        assert_eq!(replayed, 1);
        assert!(whitelist.contains(&NodeId::from_bytes(active_pubkey)));
        assert!(!whitelist.contains(&NodeId::from_bytes(expired_pubkey)));
    }
}

#[cfg(test)]
#[path = "tests/main_tests.rs"]
mod tests;
