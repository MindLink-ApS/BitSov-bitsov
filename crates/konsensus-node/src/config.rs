//! Node configuration — parsed from `konsensus.toml`.
//!
//! The config file drives all behavior: sovereignty tier selection, which
//! provider backends to use, peer list, API settings, and pricing. All 4
//! sovereignty tiers emerge from the same configuration structure with
//! different backend choices.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use konsensus_message::wire::SovereigntyTier;
use serde::{Deserialize, Serialize};

/// User-facing onboarding tier.
///
/// This determines the default configuration and UI presentation.
/// - **Cloud/Relay**: paired remote access with user-held keys
/// - **Light**: local node with user-selected Lightning
/// - **Full**: fully sovereign node with own Lightning (maximum sovereignty)
///
/// The tier can be changed later in Settings. Identity is preserved across
/// tier changes — the mnemonic always belongs to the user.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeTier {
    /// Relay-compatible remote access mode.
    /// The operator may provide reachability but must not hold user keys.
    Cloud,
    /// Local node with hosted Lightning.
    /// Your keys, your data, hosted wallet.
    #[default]
    Light,
    /// Fully sovereign — own Lightning, own chain data.
    /// Maximum sovereignty and independence.
    Full,
}

impl std::fmt::Display for NodeTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cloud => write!(f, "cloud"),
            Self::Light => write!(f, "light"),
            Self::Full => write!(f, "full"),
        }
    }
}

impl NodeTier {
    /// Returns true when the node's API is controlled by the user who owns the
    /// mnemonic and can safely expose local recovery endpoints.
    pub fn is_self_hosted(self) -> bool {
        matches!(self, Self::Light | Self::Full)
    }

    /// Map user-facing tier to wire-protocol sovereignty tier.
    pub fn to_sovereignty_tier(self) -> SovereigntyTier {
        match self {
            Self::Cloud => SovereigntyTier::T1,
            Self::Light => SovereigntyTier::T1,
            Self::Full => SovereigntyTier::T2,
        }
    }

    /// Short human-readable description of the tier.
    pub fn description(self) -> &'static str {
        match self {
            Self::Cloud => "Cloud/Relay — paired remote access, user-held keys",
            Self::Light => "Light Node — your device, user-selected Lightning",
            Self::Full => "Full Node — fully sovereign",
        }
    }
}

/// Top-level node configuration, matching `konsensus.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// User-facing onboarding tier (cloud, light, full).
    /// Determines default backends and UI presentation.
    #[serde(default)]
    pub tier: NodeTier,

    /// Node identity and key storage.
    pub identity: IdentityConfig,

    /// Network configuration (listen address, tier).
    pub network: NetworkConfig,

    /// Lightning provider configuration.
    pub lightning: LightningConfig,

    /// Chain data provider configuration.
    pub chain: ChainConfig,

    /// Pricing engine configuration.
    #[serde(default)]
    pub pricing: PricingConfig,

    /// Storage backend configuration.
    pub storage: StorageConfig,

    /// Local encrypted backup configuration.
    #[serde(default)]
    pub backup: BackupConfig,

    /// HTTP/WebSocket API configuration.
    #[serde(default)]
    pub api: ApiConfig,

    /// Sovereign browser / web content server configuration.
    #[serde(default)]
    pub web: WebConfig,

    /// Static peer list.
    #[serde(default)]
    pub peers: Vec<PeerConfigEntry>,
}

/// Identity configuration — where the mnemonic is stored.
///
/// `deny_unknown_fields` protects against typos in the `passphrase` field —
/// a misspelled field name would silently use an empty passphrase, producing
/// a completely different identity from the same mnemonic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Path to the file containing the BIP-39 mnemonic (24 words).
    /// The file should contain only the mnemonic phrase. Permissions
    /// should be restricted (0600) to prevent key leakage.
    pub mnemonic_file: PathBuf,

    /// Optional BIP-39 passphrase for additional seed derivation.
    /// This is NOT the encryption password — it changes the derived keys.
    #[serde(default)]
    pub passphrase: String,
}

/// Network configuration — listen address and sovereignty tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Address to listen on for peer-to-peer connections.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,

    /// Sovereignty tier to advertise to peers.
    #[serde(default = "default_tier")]
    pub tier: SovereigntyTier,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            tier: SovereigntyTier::T1,
        }
    }
}

/// Lightning provider backend selection.
///
/// `deny_unknown_fields` prevents typos in optional fields (e.g., `lsp_nod_id`
/// instead of `lsp_node_id`) from being silently ignored with a default value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", deny_unknown_fields)]
pub enum LightningConfig {
    /// LNbits HTTP REST API (simplest, works for T1-T2).
    #[serde(rename = "lnbits")]
    Lnbits {
        /// Base URL of the LNbits instance.
        ///
        /// For Light tier, defaults to the hosted MindLink instance.
        /// For Full tier, point this to your own LNbits.
        api_url: String,
        /// Admin API key for the wallet.
        admin_key: String,
    },
    /// Mock provider — self-contained, auto-settling, no external deps.
    /// For testnet, development, and integration testing.
    #[serde(rename = "mock")]
    Mock {
        /// Initial simulated balance in millisatoshis (default: 100 BTC).
        #[serde(default = "default_mock_balance")]
        initial_balance_msat: u64,
    },
    /// LND direct REST API — no LNbits middleman, direct LND communication.
    /// For Full tier nodes running their own LND daemon.
    #[serde(rename = "lnd")]
    Lnd {
        /// Base URL of the LND REST API (e.g. `https://localhost:8080`).
        api_url: String,
        /// Hex-encoded macaroon for authentication.
        macaroon_hex: String,
        /// Optional path to TLS cert for self-signed LND certificates.
        #[serde(default)]
        tls_cert_path: Option<String>,
    },
    /// LDK embedded Lightning node — fully sovereign, no external daemon.
    /// The node IS its own Lightning node. Keys derived from the same mnemonic.
    #[serde(rename = "ldk")]
    Ldk {
        /// Bitcoin network: "bitcoin", "testnet", "signet", "regtest".
        #[serde(default = "default_ldk_network")]
        network: String,
        /// Esplora server URL for chain data.
        #[serde(default = "default_ldk_esplora")]
        esplora_url: String,
        /// Optional fallback Esplora URL. Used by `LdkProvider::new` (L4b)
        /// when the primary endpoint fails its startup fee-fetch probe —
        /// the root cause of the 2026-04-23 alpha crash-loop.
        #[serde(default)]
        esplora_url_fallback: Option<String>,
        /// Optional RapidGossipSync server URL for faster network graph sync.
        #[serde(default)]
        rgs_url: Option<String>,
        /// Optional LSPS2 LSP node ID (hex pubkey) for automatic inbound liquidity.
        #[serde(default)]
        lsp_node_id: Option<String>,
        /// Optional LSPS2 LSP address (host:port).
        #[serde(default)]
        lsp_address: Option<String>,
        /// Optional LSPS2 LSP token.
        #[serde(default)]
        lsp_token: Option<String>,
        /// Listening address for Lightning P2P (e.g., "0.0.0.0:9735").
        #[serde(default)]
        listening_address: Option<String>,
        /// Public Lightning P2P address advertised to peers for channel opens.
        ///
        /// `listening_address` may be a local bind address such as
        /// `0.0.0.0:9735`, which is not dialable by a remote peer. Set this to
        /// the externally reachable `host:port` when ONB5 auto-channel-open is
        /// enabled.
        #[serde(default)]
        advertised_address: Option<String>,
    },
}

impl LightningConfig {
    /// Check if this is the mock provider.
    pub fn is_mock(&self) -> bool {
        matches!(self, Self::Mock { .. })
    }

    /// Human-readable backend name for diagnostics.
    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Lnbits { .. } => "lnbits",
            Self::Lnd { .. } => "lnd",
            Self::Mock { .. } => "mock",
            Self::Ldk { .. } => "ldk",
        }
    }

    /// Dialable Lightning address to announce in `Frame::LightningInfo`.
    ///
    /// Prefer the explicit public address. Falling back to `listening_address`
    /// is only safe when it is not a wildcard bind.
    pub fn advertised_lightning_addr(&self) -> Option<String> {
        match self {
            Self::Ldk {
                advertised_address,
                listening_address,
                ..
            } => advertised_address.clone().or_else(|| {
                listening_address.as_ref().and_then(|addr| {
                    let host = addr.rsplit_once(':').map(|(host, _)| host).unwrap_or(addr);
                    if host == "0.0.0.0" || host == "::" || host == "[::]" {
                        None
                    } else {
                        Some(addr.clone())
                    }
                })
            }),
            _ => None,
        }
    }
}

/// Chain data provider backend selection.
///
/// `deny_unknown_fields` ensures typos in optional fields cause a parse error.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", deny_unknown_fields)]
pub enum ChainConfig {
    /// Esplora/mempool.space compatible HTTP API.
    #[serde(rename = "esplora")]
    Esplora {
        /// Base URL of the primary Esplora instance (e.g. `https://mempool.space`).
        /// The `/api` path prefix is added automatically — do not include it.
        ///
        /// Backward compatibility: accepts legacy `api_url`.
        #[serde(default = "default_esplora_url", alias = "esplora_url_primary")]
        api_url: String,
        /// Optional fallback Esplora base URL used if primary is unavailable.
        #[serde(default)]
        esplora_url_fallback: Option<String>,
    },
    /// Mock provider — static block data, no network calls.
    /// For testnet, development, and offline operation.
    #[serde(rename = "mock")]
    Mock,
    // Future: electrum, bitcoind variants
}

impl ChainConfig {
    /// Human-readable backend name for diagnostics.
    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Esplora { .. } => "esplora",
            Self::Mock => "mock",
        }
    }
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self::Esplora {
            api_url: default_esplora_url(),
            esplora_url_fallback: None,
        }
    }
}

/// Pricing engine mode selection.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PricingMode {
    /// Fixed prices from config (default). No chain queries.
    #[default]
    Static,
    /// Base prices adjusted by Bitcoin fee rate from ChainProvider.
    /// Higher mempool congestion → higher message prices (Principle 5).
    ChainAware,
}

/// Pricing engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PricingConfig {
    /// Pricing mode: "static" (default) or "chain_aware".
    /// "chain_aware" adjusts base prices using Bitcoin fee rates.
    #[serde(default)]
    pub mode: PricingMode,

    /// Default fee estimation target in blocks (default: 6, ~1 hour).
    /// Only used when mode = "chain_aware". Lower targets react more
    /// aggressively to congestion. Per-category overrides can be set
    /// in `category_fee_targets`.
    #[serde(default = "default_fee_target_blocks")]
    pub fee_target_blocks: u32,

    /// How often to refresh the fee rate from the chain provider, in seconds.
    /// Only used when mode = "chain_aware". Default: 60.
    #[serde(default = "default_fee_cache_secs")]
    pub fee_cache_secs: u64,

    /// Maximum price multiplier over base price (default: 5.0).
    /// Caps the chain-adjusted price to prevent runaway pricing during
    /// extreme mempool events. Set to 0 to disable the cap.
    /// Only used when mode = "chain_aware".
    #[serde(default = "default_max_price_multiplier")]
    pub max_price_multiplier: f64,

    /// EMA smoothing factor for fee rates (default: 0.3, range 0.0–1.0).
    /// Lower values = more smoothing (slower reaction to fee spikes).
    /// 1.0 = no smoothing (raw fee rates used directly).
    /// Only used when mode = "chain_aware".
    #[serde(default = "default_fee_rate_ema_alpha")]
    pub fee_rate_ema_alpha: f64,

    /// Per-category fee confirmation targets (category name → target blocks).
    ///
    /// Categories not listed here use `fee_target_blocks` as the default.
    /// Different message types have different settlement urgency:
    ///
    /// ```toml
    /// [pricing.category_fee_targets]
    /// files_media = 25    # Economy: files can wait ~4 hours
    /// control = 144       # Deep economy: control messages ~1 day
    /// ```
    ///
    /// Category names: "communication", "structured_data", "files_media",
    /// "collaboration", "control", "app_extension".
    /// Only used when mode = "chain_aware".
    #[serde(default)]
    pub category_fee_targets: std::collections::HashMap<String, u32>,

    /// Price for chat messages (kinds 0-99) in millisatoshis.
    #[serde(default = "default_chat_msat")]
    pub chat_msat: u64,
    /// Price for long-form messages (kinds 100-199) in millisatoshis.
    #[serde(default = "default_longform_msat")]
    pub longform_msat: u64,
    /// Price for calendar events in millisatoshis.
    #[serde(default = "default_calendar_msat")]
    pub calendar_msat: u64,
    /// Price for file references (kinds 200-299) in millisatoshis.
    #[serde(default = "default_file_ref_msat")]
    pub file_ref_msat: u64,
    /// Price for control messages (kinds 900-999) in millisatoshis.
    #[serde(default = "default_control_msat")]
    pub control_msat: u64,
    /// Price for collaboration messages (kinds 300-399) in millisatoshis.
    #[serde(default = "default_collab_msat")]
    pub collaboration_msat: u64,
    /// Price for application extension messages (kinds 1000+) in millisatoshis.
    #[serde(default = "default_app_ext_msat")]
    pub app_ext_msat: u64,
    /// Price for web content messages (kinds 500-599) in millisatoshis.
    /// Used by the sovereign browser.
    #[serde(default = "default_web_content_msat")]
    pub web_content_msat: u64,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            mode: PricingMode::default(),
            fee_target_blocks: default_fee_target_blocks(),
            fee_cache_secs: default_fee_cache_secs(),
            max_price_multiplier: default_max_price_multiplier(),
            fee_rate_ema_alpha: default_fee_rate_ema_alpha(),
            category_fee_targets: std::collections::HashMap::new(),
            chat_msat: default_chat_msat(),
            longform_msat: default_longform_msat(),
            calendar_msat: default_calendar_msat(),
            file_ref_msat: default_file_ref_msat(),
            control_msat: default_control_msat(),
            collaboration_msat: default_collab_msat(),
            app_ext_msat: default_app_ext_msat(),
            web_content_msat: default_web_content_msat(),
        }
    }
}

/// Storage backend selection.
///
/// `deny_unknown_fields` prevents typos in optional fields (e.g., `encrypred`
/// instead of `encrypted`) from silently using the default value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", deny_unknown_fields)]
pub enum StorageConfig {
    /// SQLite (T1 Light, development, single-node).
    #[serde(rename = "sqlite")]
    Sqlite {
        /// Path to the SQLite database file.
        #[serde(default = "default_sqlite_path")]
        path: String,
        /// Enable AES-256-GCM at-rest encryption.
        #[serde(default)]
        encrypted: bool,
        /// Message retention in days. 0 = keep forever (default).
        #[serde(default)]
        retention_days: u32,
    },
    /// PostgreSQL (T2+, production, scalable).
    #[serde(rename = "postgres")]
    Postgres {
        /// PostgreSQL connection URL.
        url: String,
        /// Enable AES-256-GCM at-rest encryption.
        #[serde(default)]
        encrypted: bool,
        /// Message retention in days. 0 = keep forever (default).
        #[serde(default)]
        retention_days: u32,
    },
}

impl StorageConfig {
    /// Get the retention period in days (0 = keep forever).
    pub fn retention_days(&self) -> u32 {
        match self {
            Self::Sqlite { retention_days, .. } | Self::Postgres { retention_days, .. } => {
                *retention_days
            }
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::Sqlite {
            path: default_sqlite_path(),
            encrypted: false,
            retention_days: 0,
        }
    }
}

/// Local backup configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupConfig {
    /// Directory for encrypted SCB rotation files.
    ///
    /// Defaults to `<data_dir>/backups/` when generated by `konsensus init`.
    /// If omitted in a hand-written config, this falls back to `backups`.
    #[serde(default = "default_backup_scb_dir")]
    pub scb_dir: String,
    /// Number of timestamped encrypted SCB snapshots to retain.
    #[serde(default = "default_scb_rotation_count")]
    pub rotation_count: usize,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            scb_dir: default_backup_scb_dir(),
            rotation_count: default_scb_rotation_count(),
        }
    }
}

/// HTTP/WebSocket API configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// Address to listen on for API connections.
    #[serde(default = "default_api_addr")]
    pub listen_addr: SocketAddr,

    /// JWT secret for API authentication. If not set, a random secret
    /// is generated at startup (tokens won't survive restarts).
    pub jwt_secret: Option<String>,

    /// Maximum requests per second per client IP.
    #[serde(default = "default_rate_limit")]
    pub rate_limit_rps: u32,

    /// Enable CORS for browser-based frontends.
    #[serde(default = "default_true")]
    pub cors_enabled: bool,

    /// Enable unauthenticated cheap operator liveness probes.
    ///
    /// `None` means infer from the node tier: enabled for Cloud/relay
    /// configs and disabled for local Light/Full sovereign defaults.
    #[serde(default)]
    pub operator_probes_enabled: Option<bool>,

    /// Path to the audit log file (append-only, JSON-lines format).
    #[serde(default = "default_audit_log_path")]
    pub audit_log_path: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_api_addr(),
            jwt_secret: None,
            rate_limit_rps: default_rate_limit(),
            cors_enabled: true,
            operator_probes_enabled: None,
            audit_log_path: default_audit_log_path(),
        }
    }
}

/// Sovereign browser / web content server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebConfig {
    /// Whether the content server is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Directory containing content files (markdown pages).
    /// Relative paths are resolved from the node's working directory.
    #[serde(default = "default_content_dir")]
    pub content_dir: String,

    /// Maximum file size to serve, in bytes. Default: 4 MiB.
    #[serde(default = "default_max_page_size")]
    pub max_page_size: u64,

    /// Cache duration hint for served pages, in seconds. Default: 300.
    #[serde(default = "default_page_cache_secs")]
    pub page_cache_secs: u64,

    /// Human-readable site name for the web manifest.
    #[serde(default = "default_site_name")]
    pub site_name: String,

    /// Default price per page in millisatoshi. Default: 50 msat.
    #[serde(default = "default_page_price_msat")]
    pub page_price_msat: u64,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            content_dir: default_content_dir(),
            max_page_size: default_max_page_size(),
            page_cache_secs: default_page_cache_secs(),
            site_name: default_site_name(),
            page_price_msat: default_page_price_msat(),
        }
    }
}

fn default_content_dir() -> String {
    "pages".to_string()
}

fn default_max_page_size() -> u64 {
    4 * 1024 * 1024
}

fn default_page_cache_secs() -> u64 {
    300
}

fn default_site_name() -> String {
    "BitSov Node".to_string()
}

fn default_page_price_msat() -> u64 {
    50
}

/// A peer entry in the config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfigEntry {
    /// Hex-encoded Ed25519 public key (64 hex chars = 32 bytes).
    pub node_id: String,
    /// Network address (host:port).
    pub addr: SocketAddr,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Automatically connect on startup.
    #[serde(default = "default_true")]
    pub auto_connect: bool,
}

impl NodeConfig {
    /// Load configuration from a TOML file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration for common errors that would cause startup failures.
    fn validate(&self) -> anyhow::Result<()> {
        // Check mnemonic file exists and is readable
        if !self.identity.mnemonic_file.exists() {
            anyhow::bail!(
                "mnemonic file not found: {}. Run 'konsensus init' to generate one.",
                self.identity.mnemonic_file.display()
            );
        }

        // Warn if mnemonic file has overly permissive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&self.identity.mnemonic_file) {
                let mode = metadata.permissions().mode();
                // Check if group or other has read/write/execute access
                if mode & 0o077 != 0 {
                    tracing::warn!(
                        path = %self.identity.mnemonic_file.display(),
                        mode = format!("{mode:04o}"),
                        "mnemonic file has overly permissive permissions — should be 0600. \
                         Fix with: chmod 600 {}",
                        self.identity.mnemonic_file.display()
                    );
                }
            }
        }

        // Check P2P and API ports don't collide
        if self.network.listen_addr.port() == self.api.listen_addr.port()
            && (self.network.listen_addr.ip().is_unspecified()
                || self.api.listen_addr.ip().is_unspecified()
                || self.network.listen_addr.ip() == self.api.listen_addr.ip())
        {
            anyhow::bail!(
                "P2P listen address ({}) and API listen address ({}) use the same port",
                self.network.listen_addr,
                self.api.listen_addr
            );
        }

        // Validate peer node IDs are valid hex
        for (i, peer) in self.peers.iter().enumerate() {
            if konsensus_core::types::NodeId::from_hex(&peer.node_id).is_err() {
                anyhow::bail!(
                    "peers[{}]: invalid node_id '{}' — must be 64 hex characters (32 bytes Ed25519 public key)",
                    i, peer.node_id
                );
            }
        }

        // Validate pricing (all prices must be > 0 for payment gate)
        if self.pricing.chat_msat == 0
            || self.pricing.longform_msat == 0
            || self.pricing.file_ref_msat == 0
            || self.pricing.control_msat == 0
        {
            anyhow::bail!(
                "all pricing values must be > 0 (Principle 2: payment gate is fail-closed)"
            );
        }

        if self.backup.rotation_count == 0 {
            anyhow::bail!("backup.rotation_count must be at least 1");
        }
        if self.backup.scb_dir.trim().is_empty() {
            anyhow::bail!("backup.scb_dir must not be empty");
        }

        Ok(())
    }

    /// Write configuration to a TOML file.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Generate a default configuration with absolute paths rooted in `node_dir`.
    ///
    /// Uses mock Lightning and chain backends so the node starts immediately
    /// Generate a tier-appropriate default configuration.
    ///
    /// Each tier pre-configures different backend defaults:
    /// - **Cloud/Relay**: mock backends until paired with a relay/LSP
    /// - **Light**: mock Lightning until user configures a provider, SQLite storage
    /// - **Full**: mock Lightning (user switches to LND), Esplora chain, encrypted SQLite
    pub fn default_for_tier(tier: NodeTier, mnemonic_file: PathBuf, node_dir: &Path) -> Self {
        let abs_dir = std::fs::canonicalize(node_dir).unwrap_or_else(|_| node_dir.to_path_buf());
        let db_path = abs_dir.join("konsensus.db");
        let audit_path = abs_dir.join("audit.jsonl");
        let backup_path = abs_dir.join("backups");

        let (lightning, chain, storage, network_tier) = match tier {
            NodeTier::Cloud => (
                LightningConfig::Mock {
                    initial_balance_msat: default_mock_balance(),
                },
                ChainConfig::Mock,
                StorageConfig::Sqlite {
                    path: db_path.to_string_lossy().into_owned(),
                    encrypted: false,
                    retention_days: 0,
                },
                SovereigntyTier::T1,
            ),
            NodeTier::Light => (
                LightningConfig::Mock {
                    initial_balance_msat: default_mock_balance(),
                },
                ChainConfig::Mock,
                StorageConfig::Sqlite {
                    path: db_path.to_string_lossy().into_owned(),
                    encrypted: false,
                    retention_days: 0,
                },
                SovereigntyTier::T1,
            ),
            NodeTier::Full => (
                LightningConfig::Ldk {
                    network: default_ldk_network(),
                    esplora_url: default_ldk_esplora(),
                    esplora_url_fallback: None,
                    rgs_url: None,
                    lsp_node_id: None,
                    lsp_address: None,
                    lsp_token: None,
                    listening_address: Some("0.0.0.0:9735".to_string()),
                    advertised_address: None,
                },
                ChainConfig::default(),
                StorageConfig::Sqlite {
                    path: db_path.to_string_lossy().into_owned(),
                    encrypted: true,
                    retention_days: 0,
                },
                SovereigntyTier::T2,
            ),
        };

        Self {
            tier,
            identity: IdentityConfig {
                mnemonic_file,
                passphrase: String::new(),
            },
            network: NetworkConfig {
                listen_addr: default_listen_addr(),
                tier: network_tier,
            },
            lightning,
            chain,
            pricing: PricingConfig::default(),
            storage,
            backup: BackupConfig {
                scb_dir: backup_path.to_string_lossy().into_owned(),
                rotation_count: default_scb_rotation_count(),
            },
            api: ApiConfig {
                audit_log_path: audit_path.to_string_lossy().into_owned(),
                operator_probes_enabled: Some(matches!(tier, NodeTier::Cloud)),
                ..ApiConfig::default()
            },
            web: WebConfig::default(),
            peers: match tier {
                NodeTier::Cloud => Vec::new(),
                _ => Self::bootstrap_peers(),
            },
        }
    }

    /// Default bootstrap peers — the BitSov test network.
    ///
    /// Light and Full tier configs include these by default so new nodes
    /// can discover the mesh immediately. Cloud tier doesn't need them
    /// (the hosted node manages its own peer list).
    ///
    /// These are the real Ed25519 node IDs from the live 3-node test network
    /// running on GCP. Ports match the actual P2P listen addresses.
    fn bootstrap_peers() -> Vec<PeerConfigEntry> {
        vec![
            PeerConfigEntry {
                node_id: "0dc0122d1a5635ba9c6f31eb206b5fb18993a1272998ca8d108f98389b8ca687"
                    .to_string(),
                addr: SocketAddr::from(([35, 188, 185, 67], 9736)),
                label: Some("BitSov Alpha (bootstrap)".to_string()),
                auto_connect: true,
            },
            PeerConfigEntry {
                node_id: "6821e99a22b2b4b15c42db766d85769710437c002ff1763518347a47fcdaa1cb"
                    .to_string(),
                addr: SocketAddr::from(([35, 224, 118, 190], 9737)),
                label: Some("BitSov Beta (bootstrap)".to_string()),
                auto_connect: true,
            },
            PeerConfigEntry {
                node_id: "354597aab1cdcaedb4fd903836735cab9ab508bfbf90406bb9633a6cd8dcb536"
                    .to_string(),
                addr: SocketAddr::from(([34, 135, 251, 102], 9737)),
                label: Some("BitSov Gamma (bootstrap)".to_string()),
                auto_connect: true,
            },
        ]
    }
}

// ─── Default value functions ────────────────────────────────────────────────

fn default_tier() -> SovereigntyTier {
    SovereigntyTier::T1
}

fn default_listen_addr() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 9735))
}

fn default_api_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 3141))
}

fn default_esplora_url() -> String {
    "https://mempool.space".into()
}

fn default_sqlite_path() -> String {
    "konsensus.db".into()
}

fn default_rate_limit() -> u32 {
    60
}

fn default_audit_log_path() -> String {
    "audit.jsonl".into()
}

fn default_backup_scb_dir() -> String {
    "backups".into()
}

fn default_scb_rotation_count() -> usize {
    24
}

fn default_true() -> bool {
    true
}

fn default_mock_balance() -> u64 {
    100_000_000_000 // 1 BTC in msat
}

fn default_ldk_network() -> String {
    "bitcoin".to_string()
}

fn default_ldk_esplora() -> String {
    "https://mempool.space/api".to_string()
}

fn default_fee_target_blocks() -> u32 {
    6
}
fn default_fee_cache_secs() -> u64 {
    60
}
fn default_max_price_multiplier() -> f64 {
    5.0
}
fn default_fee_rate_ema_alpha() -> f64 {
    0.3
}
fn default_chat_msat() -> u64 {
    10
}
fn default_longform_msat() -> u64 {
    50
}
fn default_calendar_msat() -> u64 {
    25
}
fn default_file_ref_msat() -> u64 {
    100
}
fn default_control_msat() -> u64 {
    1
}
fn default_collab_msat() -> u64 {
    25
}
fn default_app_ext_msat() -> u64 {
    10
}
fn default_web_content_msat() -> u64 {
    50
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
