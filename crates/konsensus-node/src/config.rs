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

#[cfg(test)]
thread_local! {
    /// When set, the next [`NodeConfig::save`] fails after the atomic rename
    /// and before the parent-directory fsync, simulating a sync failure.
    pub(crate) static FAIL_CONFIG_DIR_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arm a one-shot failure of the config parent-directory sync in [`NodeConfig::save`].
///
/// Used by bootstrap regressions to prove a non-durable alignment cannot publish
/// `NODE_INITIALIZED`.
#[cfg(test)]
pub(crate) fn fail_next_config_dir_sync() {
    FAIL_CONFIG_DIR_SYNC.set(true);
}

/// User-facing onboarding tier.
///
/// This determines the default configuration and UI presentation.
/// - **Cloud/Relay**: paired remote access; until a remote signer exists the
///   node holds its seed, so it reports `hosted_custody` (REMOTE-SIGNER.md)
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
    /// Until a remote signer exists it does, so the node reports
    /// `hosted_custody` (`docs/protocol/REMOTE-SIGNER.md`).
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
            Self::Cloud => "Cloud/Relay — paired remote access, hosted custody (the server holds the seed)",
            Self::Light => "Light Node — your device, user-selected Lightning",
            Self::Full => "Full Node — fully sovereign",
        }
    }
}

/// Top-level node configuration, matching `konsensus.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Size limits for node.log and ldk_node.log.
    #[serde(default)]
    pub logging: konsensus_core::logging::LoggingConfig,

    /// Refuse new paid work below this many available bytes beside the mnemonic/LDK state.
    #[serde(default = "default_disk_free_floor_bytes")]
    pub disk_free_floor_bytes: u64,

    /// Ordinary Lightning routing fees; sponsor gifts use their separately approved cap.
    #[serde(default)]
    pub routing_fees: konsensus_core::traits::lightning::RoutingFeePolicy,

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

    /// Private peer discovery policy; disabled unless the owner opts in.
    #[serde(default)]
    pub privacy: PrivacyConfig,

    /// Payment gate enforcement configuration.
    #[serde(default)]
    pub payment_gate: PaymentGateConfig,

    /// Storage backend configuration.
    pub storage: StorageConfig,

    /// Local encrypted backup configuration.
    #[serde(default)]
    pub backup: BackupConfig,

    /// HTTP/WebSocket API configuration.
    #[serde(default)]
    pub api: ApiConfig,

    /// Noise-protected remote API tunnel. Closed unless `listen_addr` is set.
    #[serde(default)]
    pub remote_access: RemoteAccessConfig,

    /// Sovereign browser / web content server configuration.
    #[serde(default)]
    pub web: WebConfig,

    /// Static peer list.
    #[serde(default)]
    pub peers: Vec<PeerConfigEntry>,

    /// Operator-selectable admission mode. `whitelist` (default, closed mesh) or
    /// `price_open` (strangers admitted unprivileged; per-message payment is the gate).
    ///
    /// The `#[serde(default)]` is MANDATORY: `NodeConfig` carries
    /// `deny_unknown_fields`, so without a default every existing live-mesh
    /// `konsensus.toml` that omits this field would fail to parse. Reuses the
    /// re-exported `konsensus_message::ReachabilityMode` so config and transport
    /// never diverge.
    #[serde(default)]
    pub admission_mode: konsensus_message::ReachabilityMode,

    /// Pre-Noise anti-DoS cookie (doorway hardening #2) — `disabled` (default) or
    /// `required`. When `required`, this node demands a stateless return-
    /// routability cookie before it spends a Noise DH on an inbound connection
    /// (operator opt-in; availability defense, never admission — it changes no
    /// payment-gate semantics). `#[serde(default)]` is MANDATORY (`NodeConfig` is
    /// `deny_unknown_fields`) so every existing `konsensus.toml` that omits this
    /// field keeps parsing. Reuses the re-exported `konsensus_message::CookieMode`
    /// so config and transport never diverge.
    #[serde(default)]
    pub cookie_mode: konsensus_message::CookieMode,

    /// Onboarding channel-open subsidy (R1-a) — OFF by default.
    ///
    /// When disabled (the mesh-wide default), an invite's `Pending` membership
    /// NEVER authorizes the auto-channel worker to spend operator sats: the
    /// worker is inert. Enabling it requires the operator to ALSO set the
    /// `max_*` spend caps and a non-empty `allowlist`; any of those left at its
    /// fail-closed default keeps every open suppressed.
    ///
    /// `#[serde(default)]` is MANDATORY (`NodeConfig` is `deny_unknown_fields`):
    /// every existing live-mesh `konsensus.toml` omits this block and must keep
    /// parsing.
    #[serde(default)]
    pub onboarding_subsidy: SubsidyConfig,

    /// K1 slice 2: sponsor a newcomer's start with a small, capped gift of
    /// this node's own bitcoin. OFF by default; only the owner turns it on,
    /// here. Clamped to the spec's ceilings (50,000 sats per kit with fees,
    /// 100,000 sats per rolling 24 h, two kits a day). `#[serde(default)]`
    /// is mandatory for the same reason as `onboarding_subsidy`.
    #[serde(default)]
    pub sponsor: SponsorConfig,

    /// Relay role gate (T2R8 / R3 SEAM-B) — OFF by default.
    ///
    /// When enabled, the node advertises `Capability::Relay` and mounts the
    /// gated kind-600+ relay-control dispatch behind the normal payment gate.
    /// The backend is operator-selected via `RelayConfig::durable_db_path`:
    /// set ⇒ the durable `SqliteRelayStore`; unset ⇒ the non-durable in-memory
    /// store (smoke-test only). On a real (non-Mock) Lightning backend an unset
    /// path is a fail-closed config error (`validate()`), never a silent
    /// production fallback that would lose held mail on restart. Either store
    /// never decrypts relay payloads or holds user keys.
    #[serde(default)]
    pub relay: RelayConfig,

    /// Calls (`[calls]`): optional STUN binding responder so the owner's apps
    /// can find their public address without a third-party server. OFF by
    /// default. `#[serde(default)]` is mandatory (`deny_unknown_fields`).
    #[serde(default)]
    pub calls: CallsConfig,
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

    /// The machine this node runs on is operated for the owner (a cloud VM),
    /// so whoever runs it can spend. The node then reports `hosted_custody`
    /// (`docs/protocol/REMOTE-SIGNER.md` §6). The Cloud tier implies it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hosted: bool,
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

    /// Dialable `host:port` for `listen_addr`, signed into this node's
    /// introduction (K1 door card). Needed when `listen_addr` is a wildcard
    /// bind such as `0.0.0.0:9000`. Never the API address.
    #[serde(default)]
    pub advertised_addr: Option<String>,

    /// Owner-chosen STUN server (`stun:host:port` or `host:port`, UDP) used to
    /// learn this node's public IP when `advertised_addr` is unset and
    /// `listen_addr` is a wildcard bind. There is no default and no third-party
    /// fallback; it may be another node's `[calls] stun_listen`. Never
    /// overrides `advertised_addr`. See [`crate::stun`] for what is (and is
    /// not) discovered.
    #[serde(default)]
    pub stun_server: Option<String>,
}

impl NetworkConfig {
    /// The peer endpoint fixed by configuration, without any network access:
    /// `advertised_addr` (trimmed, non-empty), else `listen_addr` unless it is
    /// a wildcard bind, with where it came from. Never consults (or is changed
    /// by) STUN discovery.
    pub fn configured_endpoint(&self) -> Option<(String, &'static str)> {
        use konsensus_api::handlers::introduction::source;
        self.advertised_addr
            .as_ref()
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .map(|a| (a, source::ADVERTISED))
            .or_else(|| {
                (!self.listen_addr.ip().is_unspecified()).then(|| (self.listen_addr.to_string(), source::LISTEN))
            })
    }

    /// The validated `host:port` of `stun_server`, if the owner set one.
    pub fn stun_server_addr(&self) -> Result<Option<String>, String> {
        match self.stun_server.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => parse_stun_server(raw).map(Some),
            None => Ok(None),
        }
    }
}

/// Parse `[network] stun_server`: `stun:host:port` or plain `host:port`
/// (IPv6 in brackets). Returns `host:port` for resolution at query time, so a
/// DNS name is looked up afresh on every refresh.
///
/// `stuns:` is rejected until TLS STUN with server-identity verification is
/// supported — accepting it would silently downgrade to cleartext UDP.
pub fn parse_stun_server(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("stuns:") {
        return Err(format!(
            "[network] stun_server {raw:?}: stuns: (TLS STUN) is not supported yet; use stun:host:port until server identity verification is available"
        ));
    }
    let rest = if lower.starts_with("stun:") {
        &raw["stun:".len()..]
    } else {
        raw
    };
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or_else(|| format!("[network] stun_server {raw:?} must be host:port"))?;
    let port: u16 = port
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("[network] stun_server {raw:?} has an invalid port"))?;
    let host_ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6.parse::<std::net::Ipv6Addr>().is_ok(),
        None => {
            !host.is_empty()
                && host.len() <= 253
                && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        }
    };
    if !host_ok {
        return Err(format!("[network] stun_server {raw:?} has an invalid host"));
    }
    Ok(format!("{host}:{port}"))
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            tier: SovereigntyTier::T1,
            advertised_addr: None,
            stun_server: None,
        }
    }
}

/// Lightning provider backend selection.
///
/// `deny_unknown_fields` prevents typos in optional fields (e.g., `lsp_nod_id`
/// instead of `lsp_node_id`) from being silently ignored with a default value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", deny_unknown_fields)]
// Config is parsed once at startup; boxing a variant would only complicate the
// internally tagged serde shape for no runtime benefit.
#[allow(clippy::large_enum_variant)]
pub enum LightningConfig {
    /// Legacy LNbits HTTP REST API. Fee-limited payments fail closed because
    /// LNbits cannot enforce per-payment routing-fee ceilings. Selecting this
    /// backend is rejected at configuration/startup; use LDK or LND instead.
    #[serde(rename = "lnbits")]
    Lnbits {
        /// Base URL of the LNbits instance.
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
    /// Local-only, no-funds integration backend with a shared settlement ledger.
    #[serde(rename = "shared_mock")]
    SharedMock {
        ledger_path: PathBuf,
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
        /// Bounded LSPS2 bootstrap; disabled unless explicitly enabled.
        #[serde(default)]
        liquidity: konsensus_lightning::liquidity::LiquidityConfig,
        /// Bitcoin network: "bitcoin", "testnet", "signet", "regtest".
        #[serde(default = "default_ldk_network")]
        network: String,
        /// Esplora server URL for chain data.
        #[serde(default = "default_ldk_esplora")]
        esplora_url: String,
        /// Optional fallback Esplora URL. Used by `LdkProvider::new` (L4b)
        /// when the primary endpoint fails its startup fee-fetch probe — the
        /// root cause of the 2026-04-23 alpha crash-loop.
        ///
        /// #66: `init` WRITES a fallback into fresh configs (see the `Default`
        /// impl), but parsing deliberately leaves this `None` when a config
        /// omits it. Injecting a default here would silently point an existing
        /// operator's node at a third-party endpoint they never chose — the
        /// node would disclose its existence and query pattern to a public
        /// service behind the operator's back. Resilience is offered at `init`,
        /// never imposed on an existing configuration.
        #[serde(default)]
        esplora_url_fallback: Option<String>,
        /// Esplora on-chain wallet polling interval (10..=3600 seconds; LDK default 80).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        onchain_wallet_sync_interval_secs: Option<u64>,
        /// Esplora Lightning wallet polling interval (10..=3600 seconds; LDK default 30).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lightning_wallet_sync_interval_secs: Option<u64>,
        /// Esplora fee-cache refresh interval (10..=3600 seconds; LDK default 600).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fee_rate_cache_update_interval_secs: Option<u64>,
        /// Owner-only OAuth client credentials for the primary Esplora source.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credentials_file: Option<PathBuf>,
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
    /// Keep the TOML fields explicit so `deny_unknown_fields` remains effective.
    pub(crate) fn esplora_sync_intervals(&self) -> konsensus_lightning::ldk::EsploraSyncIntervals {
        match self {
            Self::Ldk {
                onchain_wallet_sync_interval_secs,
                lightning_wallet_sync_interval_secs,
                fee_rate_cache_update_interval_secs,
                ..
            } => konsensus_lightning::ldk::EsploraSyncIntervals {
                onchain_wallet_sync_interval_secs: *onchain_wallet_sync_interval_secs,
                lightning_wallet_sync_interval_secs: *lightning_wallet_sync_interval_secs,
                fee_rate_cache_update_interval_secs: *fee_rate_cache_update_interval_secs,
            },
            _ => Default::default(),
        }
    }

    /// Check if this is the mock provider.
    pub fn is_mock(&self) -> bool {
        matches!(self, Self::Mock { .. } | Self::SharedMock { .. })
    }

    /// Human-readable backend name for diagnostics.
    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Lnbits { .. } => "lnbits",
            Self::Lnd { .. } => "lnd",
            Self::Mock { .. } => "mock",
            Self::SharedMock { .. } => "shared_mock",
            Self::Ldk { .. } => "ldk",
        }
    }

    /// Bitcoin network this backend pays on, when it states one. Mock
    /// backends are regtest; LND and LNbits do not say.
    pub fn bitcoin_network(&self) -> Option<String> {
        match self {
            Self::Ldk { network, .. } => match network.to_ascii_lowercase().as_str() {
                "bitcoin" | "mainnet" => Some("bitcoin".into()),
                "testnet" | "testnet3" => Some("testnet".into()),
                "signet" => Some("signet".into()),
                "regtest" => Some("regtest".into()),
                _ => None,
            },
            Self::Mock { .. } | Self::SharedMock { .. } => Some("regtest".into()),
            Self::Lnbits { .. } | Self::Lnd { .. } => None,
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
        /// Optional fallback Esplora base URL used if the primary is
        /// unavailable or returns unusable data. #66: written by `init` for
        /// fresh configs; never injected when parsing an existing one (see the
        /// LDK field above for why).
        #[serde(default, alias = "api_url_fallback")]
        esplora_url_fallback: Option<String>,
        /// Owner-only OAuth client credentials for the primary Esplora source.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credentials_file: Option<PathBuf>,
    },
    /// Mock provider — static block data, no network calls.
    /// For testnet, development, and offline operation.
    #[serde(rename = "mock")]
    Mock,
    /// Own pruned or full Bitcoin Core; also selects LDK's chain source.
    #[serde(rename = "bitcoind")]
    Bitcoind(konsensus_chain::BitcoindConfig),
    /// Explicit Electrum server; also selects LDK's chain source.
    #[serde(rename = "electrum")]
    Electrum(konsensus_chain::ElectrumConfig),
}

impl ChainConfig {
    /// Explicit chain fallback wins. Otherwise reuse only endpoints already
    /// selected by the operator for LDK; serde defaults remain unchanged.
    pub fn esplora_fallbacks(&self, lightning: &LightningConfig) -> Vec<String> {
        match self {
            Self::Esplora { esplora_url_fallback: Some(url), .. } => vec![url.clone()],
            Self::Esplora { .. } => match lightning {
                LightningConfig::Ldk { esplora_url, esplora_url_fallback, .. } => {
                    std::iter::once(esplora_url.clone())
                        .chain(esplora_url_fallback.iter().cloned()).collect()
                }
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    /// Human-readable backend name for diagnostics.
    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Esplora { .. } => "esplora",
            Self::Bitcoind(_) => "bitcoind",
            Self::Electrum(_) => "electrum",
            Self::Mock => "mock",
        }
    }
}

impl Default for ChainConfig {
    fn default() -> Self {
        // Construction-only path (`chain` has no serde default — the stanza is
        // required), so the fresh pair is safe here. #66.
        Self::Esplora {
            api_url: FRESH_CHAIN_PRIMARY.to_string(),
            esplora_url_fallback: Some(FRESH_CHAIN_FALLBACK.to_string()),
            credentials_file: None,
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
    /// "collaboration", "realtime_signaling", "control", "app_extension".
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
    /// Price for real-time signaling messages (kinds 400-499) in millisatoshis.
    #[serde(default = "default_realtime_signal_msat")]
    pub realtime_signal_msat: u64,
    /// Per-call admission: what a call offer (kind 400) to this node costs,
    /// in millisatoshis. Paid once per call; answers, ICE and hangups keep
    /// `realtime_signal_msat`.
    #[serde(default = "default_call_msat")]
    pub call_msat: u64,
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
            realtime_signal_msat: default_realtime_signal_msat(),
            call_msat: default_call_msat(),
            app_ext_msat: default_app_ext_msat(),
            web_content_msat: default_web_content_msat(),
        }
    }
}

/// Payment gate runtime configuration.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentGateConfig {
    /// Verify each accepted proof against the receiver-side Lightning backend.
    ///
    /// `None` means infer from the Lightning backend: enabled for real
    /// backends and disabled for `mock` so local/dev configs stay ergonomic.
    #[serde(default)]
    pub verify_lightning_settlement: Option<bool>,

    /// Absolute minimum admission price in msat — the node's modeled marginal
    /// cost of processing one inbound paid contact (doorway hardening #4).
    ///
    /// `None`/omitted ⇒ `0` (off): no floor, pricing identical to before. Set
    /// this to your node's measured per-admission cost so an attacker cannot
    /// pay less than it costs to serve them (pay-to-DoS asymmetry). The floor
    /// can only ever raise the required price — never admit something the base
    /// price would reject — so enabling it is strictly fail-closed.
    #[serde(default)]
    pub min_admission_cost_msat: Option<u64>,
}

/// Onboarding channel-open subsidy policy (R1-a). OFF by default — see the doc
/// on [`NodeConfig::onboarding_subsidy`].
///
/// Every field is independently fail-closed: `enabled = false`, zero spend caps,
/// and an empty `allowlist` each on their own keep the auto-channel worker from
/// spending a single operator sat. An operator running the ChainBridge subsidy
/// loop must consciously set `enabled`, the `max_*` caps, AND a non-empty
/// `allowlist` before any channel opens.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubsidyConfig {
    /// Master switch. When `false` (default), the worker is inert mesh-wide and
    /// an invite's `Pending` membership never authorizes a channel open. Payment,
    /// never membership, is what may move sats.
    #[serde(default)]
    pub enabled: bool,

    /// Per-channel spend ceiling (sats). The invitee-supplied `channel_size_hint`
    /// is clamped DOWN to this value — a larger hint can never raise the spend.
    /// `0` (default) clamps every open to zero, so nothing opens (fail-closed).
    #[serde(default)]
    pub max_channel_sats: u64,

    /// Aggregate ceiling (sats) summed across all in-flight (`Opening`) subsidised
    /// opens. `0` (default) means the very first open exceeds it (fail-closed).
    #[serde(default)]
    pub max_total_budget_sats: u64,

    /// Maximum funding fee rate (sat/vB). Zero (default) forbids new opens.
    /// The worker enforces the lower of this operator ceiling and the invite's
    /// ceiling, and requests the checked rate from the Lightning backend.
    /// Backends unable to enforce that request must refuse before dispatch.
    #[serde(default)]
    pub max_funding_fee_rate_sat_per_vb: u32,

    /// Maximum subsidised channel opens per invited peer. Defaults to 1.
    #[serde(default = "default_per_peer_max_opens")]
    pub per_peer_max_opens: u32,

    /// Hex-encoded BitSov NodeIds (64 lowercase hex chars) eligible for subsidy.
    /// Invite membership is necessary but NOT sufficient — the peer must also be
    /// listed here. Empty (default) ⇒ nobody is eligible.
    #[serde(default)]
    pub allowlist: Vec<String>,
}

impl Default for SubsidyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_channel_sats: 0,
            max_total_budget_sats: 0,
            max_funding_fee_rate_sat_per_vb: 0,
            per_peer_max_opens: default_per_peer_max_opens(),
            allowlist: Vec::new(),
        }
    }
}

impl SubsidyConfig {
    /// True iff `pubkey` (a 32-byte BitSov NodeId) is in the operator allowlist.
    /// Comparison is over the lowercase-hex encoding, case-insensitive; a
    /// malformed allowlist entry simply never matches (fail-closed).
    pub fn is_allowlisted(&self, pubkey: &[u8; 32]) -> bool {
        let want = hex::encode(pubkey);
        self.allowlist
            .iter()
            .any(|entry| entry.trim().eq_ignore_ascii_case(&want))
    }
}

fn default_per_peer_max_opens() -> u32 {
    1
}

/// Relay role policy.
///
/// Fail-closed by default: ordinary nodes do not advertise `Capability::Relay`
/// and do not construct a relay engine. An operator must explicitly set
/// `[relay] enabled = true` before the node announces relay support and mounts
/// the gated kind-600+ relay-control dispatch. The backend is selected by
/// `durable_db_path`: unset ⇒ the non-durable in-memory store (smoke-test only);
/// set ⇒ the durable SQLite store. Either way the relay never decrypts payloads
/// or holds user keys.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Enable relay advertisement and gated relay-control dispatch.
    #[serde(default)]
    pub enabled: bool,

    /// Path to the durable relay SQLite DB (P8.1 / design SEAM-C). Ignored unless
    /// `enabled = true`.
    ///
    /// `None` (default) ⇒ the non-durable in-memory store: held mail is lost on
    /// restart (smoke-test only). `Some(path)` ⇒ the durable `SqliteRelayStore`.
    /// **The node never creates this DB or its schema** — an operator runs the
    /// `[MANUAL]` `CREATE TABLE` migration (design §4) and points this at the
    /// resulting file. A missing file/schema is a fail-closed boot error, never a
    /// silent fallback to the in-memory store.
    #[serde(default)]
    pub durable_db_path: Option<PathBuf>,
}

/// Calls configuration (`[calls]`).
///
/// Media never touches the node (see `docs/v2/CALLS-PROTOTYPE.md`). The only
/// optional service is a minimal STUN binding responder (RFC 5389 binding
/// request/response only: no TURN, no relay, no auth, no per-caller state). It
/// tells a caller the public address its request came from, which is all an
/// app needs to connect directly across a router. Off unless `stun_listen` is set.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallsConfig {
    /// UDP address for the STUN responder, for example `0.0.0.0:3478`.
    /// `None` (default): no UDP socket is opened.
    #[serde(default)]
    pub stun_listen: Option<SocketAddr>,
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
        #[serde(default = "default_true")]
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
        #[serde(default = "default_true")]
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
            encrypted: true,
            retention_days: 0,
        }
    }
}

/// Local backup configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupConfig {
    /// Directory for the durable disaster-recovery artifacts — the encrypted SCB
    /// rotation files and the whitelist sidecar (RV-RESTORE).
    ///
    /// Defaults to `<data_dir>/backups/` when generated by `konsensus init`.
    /// If omitted in a hand-written config, this falls back to the relative
    /// `backups`, which [`NodeConfig::load`] then anchors to the config file's
    /// own directory (never the process CWD) so the only recovery material a node
    /// holds cannot land in an ephemeral location like `/tmp`.
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

/// Public Noise listener for remote app access.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteAccessConfig {
    #[serde(default)]
    pub listen_addr: Option<SocketAddr>,
    #[serde(default)]
    pub advertised_endpoint: Option<String>,
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

    /// Maximum file size to serve, in bytes. Default and ceiling: 256 KiB,
    /// the porch reply cap (BROWSE.md §6).
    #[serde(default = "default_max_page_size")]
    pub max_page_size: u64,

    /// Cache duration hint for served pages, in seconds. Default: 300.
    #[serde(default = "default_page_cache_secs")]
    pub page_cache_secs: u64,

    /// Human-readable site name for the web manifest.
    #[serde(default = "default_site_name")]
    pub site_name: String,

    /// Default price per page in millisatoshi. Default: 1,000 msat (1 sat).
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
    konsensus_core::payloads::content::MAX_PORCH_BODY_BYTES as u64
}

fn default_page_cache_secs() -> u64 {
    300
}

fn default_site_name() -> String {
    "BitSov Node".to_string()
}

fn default_page_price_msat() -> u64 {
    1_000
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

/// Owner-controlled export policy. Admission never implies sharing consent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyConfig {
    #[serde(default)]
    pub peer_exchange: PeerExchangeMode,
    /// Only these node IDs may be exported. Empty by default.
    #[serde(default)]
    pub shareable_peers: Vec<konsensus_core::types::NodeId>,
    /// Labels require separate consent and only apply to shareable peers.
    #[serde(default)]
    pub share_peer_labels: Vec<konsensus_core::types::NodeId>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerExchangeMode {
    #[default]
    Off,
    Paid,
}

impl NodeConfig {
    /// Load configuration from a TOML file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let config = Self::load_before_identity_validation(path)?;
        config.validate()?;
        Ok(config)
    }

    /// Bootstrap must inspect configured paths before requiring an identity.
    pub(crate) fn load_before_identity_validation(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        // TOML errors include the source line, which may contain a rejected
        // inline password. Never attach the raw parser error to startup logs.
        let mut config: Self = toml::from_str(&content)
            .map_err(|_| anyhow::anyhow!("invalid node configuration; check field names, types and file-based credentials"))?;
        config.anchor_relative_backup_dir(path);
        Ok(config)
    }

    /// Anchor a relative `backup.scb_dir` to the config file's own directory
    /// rather than the process working directory.
    ///
    /// `scb_dir` holds the node's durable disaster-recovery artifacts — the SCB
    /// channel backups and the encrypted whitelist sidecar (RV-RESTORE). The
    /// serde default (`"backups"`) is *relative*, so a node launched as a service
    /// from an ephemeral CWD (e.g. `/tmp`) would silently write its only recovery
    /// material somewhere that vanishes on reboot — defeating recovery while the
    /// node looks perfectly healthy. `konsensus init` already writes an absolute
    /// path; this protects hand-written or upgraded configs that omit `[backup]`.
    /// Absolute paths are left untouched.
    fn anchor_relative_backup_dir(&mut self, config_path: &Path) {
        if Path::new(&self.backup.scb_dir).is_absolute() {
            return;
        }
        // The config file exists (we just read it), so canonicalize resolves to an
        // absolute path; its parent is the node's own directory — durable by
        // construction (it already holds the config, DB, and mnemonic).
        let Ok(canonical) = std::fs::canonicalize(config_path) else {
            return;
        };
        if let Some(base) = canonical.parent() {
            let resolved = base.join(&self.backup.scb_dir);
            self.backup.scb_dir = resolved.to_string_lossy().into_owned();
        }
    }

    /// Validate configuration for common errors that would cause startup failures.
    /// `pub(crate)` so callers that mutate the config AFTER [`NodeConfig::load`]
    /// (e.g. the `--admission-mode` CLI override in `cmd_start`) can RE-validate
    /// the final config — `from_config` does not validate, so a post-load mutation
    /// would otherwise escape the fail-closed guards.
    pub(crate) fn validate_routing_fee_backend(&self) -> anyhow::Result<()> {
        if matches!(self.lightning, LightningConfig::Lnbits { .. }) {
            anyhow::bail!("not_supported: LNbits cannot enforce per-payment routing fee ceilings; configure LDK or LND");
        }
        Ok(())
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        self.validate_routing_fee_backend()?;
        self.lightning.esplora_sync_intervals().to_sync_config()?;
        self.sponsor.policy().map_err(|e| anyhow::anyhow!(e))?;
        self.network.stun_server_addr().map_err(|e| anyhow::anyhow!(e))?;
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
        if tcp_addrs_collide(self.network.listen_addr, self.api.listen_addr) {
            anyhow::bail!(
                "P2P listen address ({}) and API listen address ({}) use the same port",
                self.network.listen_addr,
                self.api.listen_addr
            );
        }

        if let Some(remote_addr) = self.remote_access.listen_addr {
            if !self.api.listen_addr.ip().is_loopback() {
                anyhow::bail!(
                    "[api].listen_addr must be loopback when [remote_access] is enabled; \
                     plaintext HTTP may not be exposed remotely"
                );
            }
            let endpoint = self
                .remote_access
                .advertised_endpoint
                .as_deref()
                .map(str::trim)
                .filter(|endpoint| !endpoint.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "[remote_access].advertised_endpoint is required when listen_addr is set"
                    )
                })?;
            validate_remote_endpoint(endpoint).map_err(anyhow::Error::msg)?;
            for (label, other) in [
                ("P2P", self.network.listen_addr),
                ("API", self.api.listen_addr),
            ] {
                if tcp_addrs_collide(remote_addr, other) {
                    anyhow::bail!(
                        "remote access listen address ({remote_addr}) and {label} listen address \
                         ({other}) use the same TCP port"
                    );
                }
            }
        } else if self.remote_access.advertised_endpoint.is_some() {
            anyhow::bail!(
                "[remote_access].advertised_endpoint requires listen_addr; omit both to keep \
                 remote access closed"
            );
        }

        // Check P2P and Lightning (LDK) ports don't collide.
        //
        // A fresh full-tier config leaves BOTH the P2P network listener and the
        // LDK Lightning listener on 0.0.0.0:9735 (see `default_listen_addr` and
        // `default_for_tier(Full)`, which sets `listening_address =
        // Some("0.0.0.0:9735")`).
        // Since #56 the P2P default is 9736, so fresh defaults no longer collide; the
        // guard stays for hand-edited configs. Without this guard the collision passes
        // validation, then at runtime the LDK node and the P2P transport both
        // try to bind 9735: the LDK node starts and immediately shuts down, and
        // `transport.start_listener().await` hangs forever, so the API never
        // binds — a silent hang with no error. Fail closed with an actionable
        // message instead (reproduced on 2 hosts during R4.5 staging).
        //
        // Only the explicit `Some(addr)` case is guarded: when
        // `listening_address` is `None`, `LdkProvider::new`
        // (crates/konsensus-lightning/src/ldk.rs) skips
        // `set_listening_addresses` entirely, so LDK binds no Lightning P2P
        // listener and no port collision is possible. Non-LDK backends
        // (mock/lnd/lnbits) run no embedded P2P listener, so they are exempt.
        if let LightningConfig::Ldk {
            listening_address: Some(ln_addr),
            ..
        } = &self.lightning
        {
            // Accept either a full SocketAddr ("0.0.0.0:9735") or a bare
            // "host:port"; extract the port and IP the same way the LDK builder
            // parses it. A value we cannot parse as a SocketAddr is left to
            // `LdkProvider::new`, which surfaces its own "invalid listening
            // address" error — we do not want to reject IPv6/hostname forms here.
            if let Ok(ln_socket) = ln_addr.parse::<SocketAddr>() {
                if self.network.listen_addr.port() == ln_socket.port()
                    && (self.network.listen_addr.ip().is_unspecified()
                        || ln_socket.ip().is_unspecified()
                        || self.network.listen_addr.ip() == ln_socket.ip())
                {
                    anyhow::bail!(
                        "P2P listen address ({}) and Lightning listening address ({}) use the \
                         same port; set a different port for one (e.g. P2P 9736, Lightning 9735)",
                        self.network.listen_addr,
                        ln_socket
                    );
                }
                if let Some(remote_addr) = self.remote_access.listen_addr {
                    if tcp_addrs_collide(remote_addr, ln_socket) {
                        anyhow::bail!(
                            "remote access listen address ({remote_addr}) and Lightning listening \
                             address ({ln_socket}) use the same TCP port"
                        );
                    }
                }
            }
        }

        if matches!(self.tier, NodeTier::Cloud) {
            let encrypted = match &self.storage {
                StorageConfig::Sqlite { encrypted, .. }
                | StorageConfig::Postgres { encrypted, .. } => *encrypted,
            };
            if !encrypted {
                anyhow::bail!(
                    "cloud tier requires encrypted storage (Principle 4: operator-held data must be ciphertext)"
                );
            }
        }

        // Validate peer node IDs are valid hex
        for (i, peer) in self.peers.iter().enumerate() {
            if konsensus_core::types::NodeId::from_hex(&peer.node_id).is_err() {
                anyhow::bail!(
                    "peers[{}]: invalid node_id '{}' — must be 64 hex characters (32 bytes Ed25519 public key)",
                    i,
                    peer.node_id
                );
            }
        }

        // Validate pricing (all prices must be > 0 for payment gate)
        if self.pricing.chat_msat == 0
            || self.pricing.longform_msat == 0
            || self.pricing.calendar_msat == 0
            || self.pricing.file_ref_msat == 0
            || self.pricing.control_msat == 0
            || self.pricing.collaboration_msat == 0
            || self.pricing.realtime_signal_msat == 0
            || self.pricing.call_msat == 0
            || self.pricing.app_ext_msat == 0
        {
            anyhow::bail!(
                "all pricing values must be > 0 (Principle 2: payment gate is fail-closed)"
            );
        }

        // BROWSE.md §3: porch reads cost at least 1 sat before any answer.
        if self.pricing.web_content_msat < 1_000 {
            anyhow::bail!(
                "pricing.web_content_msat must be at least 1000 msat (1 sat): porch read floor (BROWSE.md §3)"
            );
        }

        if self.backup.rotation_count == 0 {
            anyhow::bail!("backup.rotation_count must be at least 1");
        }
        if self.backup.scb_dir.trim().is_empty() {
            anyhow::bail!("backup.scb_dir must not be empty");
        }

        // SEC3: refuse a real (non-Mock) Lightning backend with settlement
        // verification explicitly disabled. `payment_gate_runtime_config` resolves the
        // flag via `.unwrap_or(!is_mock)`, so a TOML `Some(false)` against an
        // Ldk/Lnd/Lnbits backend silently downgrades the gate to preimage-only — a
        // forged or un-settled payment proof would then pass (Principle 2 fail-open).
        let resolved_verify_settlement = self
            .payment_gate
            .verify_lightning_settlement
            .unwrap_or(!matches!(self.lightning, LightningConfig::Mock { .. }));
        if !matches!(self.lightning, LightningConfig::Mock { .. }) && !resolved_verify_settlement {
            anyhow::bail!(
                "payment_gate.verify_lightning_settlement = false is not allowed with a non-Mock \
                 Lightning backend ({}): it downgrades the payment gate to preimage-only and lets \
                 unsettled proofs pass (Principle 2). Remove the override or set it to true.",
                self.lightning.backend_name()
            );
        }

        // 2d (Codex #3): the ciphertext relay and price-open admission are
        // SETTLEMENT-GATED — they admit strangers (price_open) or hold paid
        // deposits (relay) on the strength of a settled, recipient-bound payment.
        // With settlement verification resolving OFF (the default for a Mock
        // backend), the gate degrades to preimage-only and a forged or un-settled
        // proof would admit — "payment is the connection" fails open. So a node
        // must NOT mount either with settlement off; on a Mock backend that means
        // the operator must EXPLICITLY opt in (verify_lightning_settlement = true,
        // the dev/smoke escape) before enabling them. Fail closed.
        let price_open = matches!(
            self.admission_mode,
            konsensus_message::ReachabilityMode::PriceOpen
        );
        if (self.relay.enabled || price_open) && !resolved_verify_settlement {
            anyhow::bail!(
                "{} require payment_gate.verify_lightning_settlement = true: this admission \
                 path is settlement-gated, but verification resolves OFF (the default for a \
                 Mock backend: {}), which would admit unsettled/forged proofs (Principle 2). \
                 Set verify_lightning_settlement = true to opt in explicitly (dev/smoke mode), \
                 or disable [relay].enabled / use whitelist admission.",
                match (self.relay.enabled, price_open) {
                    (true, true) => "[relay].enabled and admission_mode = price_open",
                    (true, false) => "[relay].enabled",
                    _ => "admission_mode = price_open",
                },
                self.lightning.backend_name()
            );
        }

        // Live-tier relay must be DURABLE. With `[relay].enabled` but no
        // `durable_db_path`, the node falls back to the in-memory relay store,
        // which LOSES all held ciphertext mail on restart (main.rs:840 warns but
        // proceeds). That is acceptable only for a smoke/dev node on the Mock
        // backend; on a real (non-Mock) Lightning backend it is a silent
        // production data-loss foot-gun. Require an operator-migrated durable DB
        // there. Fail closed. (The node still never creates the DB/schema — a
        // missing file is a separate loud boot error at open time.)
        if self.relay.enabled
            && self.relay.durable_db_path.is_none()
            && !matches!(self.lightning, LightningConfig::Mock { .. })
        {
            anyhow::bail!(
                "[relay].enabled with no relay.durable_db_path on a non-Mock Lightning backend \
                 ({}): the in-memory relay store loses held mail on every restart and is \
                 smoke-test only. Point relay.durable_db_path at the operator-migrated SQLite DB \
                 (run the [MANUAL] CREATE TABLE migration first), or disable [relay].enabled.",
                self.lightning.backend_name()
            );
        }
        // Reject an explicitly-configured empty or too-short JWT secret
        // (fail-closed). Omitting api.jwt_secret is fine — the node then
        // derives a 32-byte secret from its identity at startup. But an
        // operator who *sets* a weak secret must be stopped, not silently
        // trusted: an empty or sub-32-byte HMAC key makes token forgery
        // cheap (Principle 1: the node is the undisputable identity anchor).
        if let Some(secret) = &self.api.jwt_secret {
            konsensus_api::auth::validate_jwt_secret(secret)
                .map_err(|reason| anyhow::anyhow!("api.jwt_secret: {reason}"))?;
        }

        Ok(())
    }

    /// Build the runtime payment gate config for this node.
    pub fn payment_gate_runtime_config(&self) -> konsensus_core::gate::GateConfig {
        konsensus_core::gate::GateConfig {
            verify_lightning_settlement: self
                .payment_gate
                .verify_lightning_settlement
                .unwrap_or(!matches!(self.lightning, LightningConfig::Mock { .. })),
            min_admission_cost_msat: self.payment_gate.min_admission_cost_msat.unwrap_or(0),
            ..Default::default()
        }
    }

    /// Write configuration to a TOML file.
    ///
    /// Durable atomic replace: serialize, write a temporary sibling at mode
    /// `0600`, fsync that file, rename over `path`, then fsync the parent
    /// directory. Bootstrap alignment relies on this completing before
    /// `NODE_INITIALIZED` is published — a plain `fs::write` is not enough.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        Self::write_atomic(path, content.as_bytes())
    }

    /// Atomically replace `path` with `bytes`, fsyncing the file and its
    /// parent directory. Failures propagate so callers can refuse to publish a
    /// success marker against a non-durable config.
    /// The temporary file [`Self::write_atomic`] writes (and removes) next to
    /// `path`. Anything that must not be clobbered by a config save (the
    /// recovery phrase in `seed encrypt`) is checked against it.
    pub(crate) fn write_atomic_temp(path: &Path) -> PathBuf {
        path.with_extension("toml.tmp")
    }

        fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        // Sibling temp in the same directory so rename is atomic on the volume.
        let tmp = Self::write_atomic_temp(path);
        let _ = std::fs::remove_file(&tmp);

        konsensus_api::pairing::write_protected(&tmp, bytes).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            anyhow::anyhow!("failed to write temporary config {}: {e}", tmp.display())
        })?;

        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            anyhow::bail!("failed to publish config {}: {e}", path.display());
        }

        // Injected sync failure (tests only): rename already happened; the
        // caller must still treat this as a failed durable save so bootstrap
        // does not publish NODE_INITIALIZED.
        #[cfg(test)]
        {
            if FAIL_CONFIG_DIR_SYNC.replace(false) {
                anyhow::bail!(
                    "failed to sync config directory {}: injected sync failure",
                    parent.display()
                );
            }
        }

        let dir = std::fs::File::open(parent).map_err(|e| {
            anyhow::anyhow!(
                "failed to open config directory {} for sync: {e}",
                parent.display()
            )
        })?;
        dir.sync_all().map_err(|e| {
            anyhow::anyhow!(
                "failed to sync config directory {}: {e}",
                parent.display()
            )
        })?;
        Ok(())
    }

    /// Generate a default configuration with absolute paths rooted in `node_dir`.
    ///
    /// Uses mock Lightning and chain backends so the node starts immediately
    /// Generate a tier-appropriate default configuration.
    ///
    /// Each tier pre-configures different backend defaults:
    /// - **Cloud/Relay**: mock backends until paired with a relay/LSP, encrypted SQLite
    /// - **Light**: mock Lightning until user configures a provider, encrypted SQLite
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
                    encrypted: true,
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
                    encrypted: true,
                    retention_days: 0,
                },
                SovereigntyTier::T1,
            ),
            NodeTier::Full => (
                LightningConfig::Ldk {
                    network: default_ldk_network(),
                    // #66: a fresh node ships with two chain providers, written
                    // into the generated konsensus.toml so the operator can see
                    // and change them. Never injected into an existing config —
                    // the serde defaults above stay on the legacy provider.
                    esplora_url: FRESH_LDK_PRIMARY.to_string(),
                    esplora_url_fallback: Some(FRESH_LDK_FALLBACK.to_string()),
                    credentials_file: None,
                    onchain_wallet_sync_interval_secs: None,
                    lightning_wallet_sync_interval_secs: None,
                    fee_rate_cache_update_interval_secs: None,
                    rgs_url: None,
                    lsp_node_id: None,
                    lsp_address: None,
                    lsp_token: None,
                    liquidity: Default::default(),
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

        let verify_lightning_settlement = !matches!(&lightning, LightningConfig::Mock { .. });

        Self {
            logging: Default::default(),
            privacy: PrivacyConfig::default(),
            disk_free_floor_bytes: default_disk_free_floor_bytes(),
            routing_fees: Default::default(),
            tier,
            identity: IdentityConfig {
                mnemonic_file,
                passphrase: String::new(),
                hosted: false,
            },
            network: NetworkConfig {
                listen_addr: default_listen_addr(),
                tier: network_tier,
                advertised_addr: None,
                stun_server: None,
            },
            lightning,
            chain,
            pricing: PricingConfig::default(),
            payment_gate: PaymentGateConfig {
                verify_lightning_settlement: Some(verify_lightning_settlement),
                min_admission_cost_msat: None,
            },
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
            remote_access: RemoteAccessConfig::default(),
            web: WebConfig::default(),
            // Boundary invariant (PUB-1): no bootstrap peers are compiled into
            // the binary. Embedding live node IDs/IPs here would publish the
            // operator's mesh topology in the open-core repo and make every
            // downloader auto-dial private infrastructure. Operators supply
            // peers via config ([[peers]]) or environment at deploy time.
            peers: Vec::new(),
            // M1a: closed mesh by default (fail-closed). Operators opt into
            // price-admission via konsensus.toml or `--admission-mode price-open`.
            admission_mode: konsensus_message::ReachabilityMode::Whitelist,
            cookie_mode: konsensus_message::CookieMode::Disabled,
            // R1-a: onboarding channel-open subsidy OFF by default — generated
            // configs never auto-spend operator sats on invite membership.
            onboarding_subsidy: SubsidyConfig::default(),
            sponsor: SponsorConfig::default(),
            // T2R8: relay advertisement OFF by default — generated configs do
            // not present this node as a relay.
            relay: RelayConfig::default(),
            // No STUN responder unless the owner sets `[calls] stun_listen`.
            calls: CallsConfig::default(),
        }
    }
}

// ─── Default value functions ────────────────────────────────────────────────

fn default_tier() -> SovereigntyTier {
    SovereigntyTier::T1
}

/// Default BitSov P2P listener. 9736, not 9735: 9735 is the Lightning P2P convention and
/// is what `default_for_tier(Full)` gives the LDK listener, and `validate` fail-closes on a
/// shared port — so a 9735 default made every fresh `init --tier full` unbootable without
/// a manual edit (genome issue #56).
fn default_listen_addr() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 9736))
}

fn default_api_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 3141))
}

fn tcp_addrs_collide(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && (a.ip().is_unspecified() || b.ip().is_unspecified() || a.ip() == b.ip())
}

fn validate_remote_endpoint(endpoint: &str) -> Result<(), String> {
    if endpoint.bytes().any(|b| b.is_ascii_whitespace()) || endpoint.contains("://") {
        return Err(format!(
            "[remote_access].advertised_endpoint {endpoint:?} must be a bare host:port"
        ));
    }
    let (host, port) = endpoint.rsplit_once(':').ok_or_else(|| {
        format!("[remote_access].advertised_endpoint {endpoint:?} must be host:port")
    })?;
    let valid_host = if host.starts_with('[') && host.ends_with(']') {
        host[1..host.len() - 1]
            .parse::<std::net::Ipv6Addr>()
            .is_ok()
    } else {
        host.parse::<std::net::Ipv4Addr>().is_ok()
            || (host.len() <= 253
                && host.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }))
    };
    let valid_port = port.parse::<u16>().is_ok_and(|port| port != 0);
    if !valid_host || !valid_port {
        return Err(format!(
            "[remote_access].advertised_endpoint {endpoint:?} must be a valid host:port"
        ));
    }
    Ok(())
}

/// DESERIALIZATION default — frozen. An existing `[chain]` stanza that omits
/// `api_url` must keep resolving to what it resolved to before, or upgrading
/// the binary silently moves that operator to a different provider. #66 changes
/// what `init` WRITES (see `FRESH_CHAIN_PRIMARY`), never what an existing
/// configuration means.
fn default_esplora_url() -> String {
    "https://mempool.space".into()
}

/// DESERIALIZATION default — frozen, same reason as [`default_esplora_url`].
fn default_ldk_esplora() -> String {
    "https://mempool.space/api".to_string()
}

// --- genome #66: the provider pair `init` WRITES into a fresh config ---------
//
// A fresh node ships with two chain providers. mempool.space alone refused to
// boot nodes on datacenter/VPS IPs (observed on GitHub-hosted runners,
// 2026-09-13): it answered 2xx while its payload was unusable to LDK, so the
// node died on its startup fee fetch. These constants are used ONLY by
// construction paths — `default_for_tier` and `ChainConfig::default` — and are
// deliberately NOT wired to any `#[serde(default = ...)]`.

/// Base URL (no `/api`; the chain client appends it).
const FRESH_CHAIN_PRIMARY: &str = "https://blockstream.info";
/// Base URL (no `/api`).
const FRESH_CHAIN_FALLBACK: &str = "https://mempool.space";
/// LDK takes the full API URL, `/api` included.
const FRESH_LDK_PRIMARY: &str = "https://blockstream.info/api";
/// LDK takes the full API URL, `/api` included.
const FRESH_LDK_FALLBACK: &str = "https://mempool.space/api";

fn default_sqlite_path() -> String {
    "konsensus.db".into()
}

fn default_rate_limit() -> u32 {
    60
}

fn default_audit_log_path() -> String {
    "audit.jsonl".into()
}

/// Relative fallback for `backup.scb_dir`. [`NodeConfig::load`] anchors this to
/// the config file's directory, so the effective path is durable even though the
/// literal default is relative.
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
fn default_call_msat() -> u64 {
    10_000
}

fn default_realtime_signal_msat() -> u64 {
    50
}
fn default_app_ext_msat() -> u64 {
    10
}
fn default_web_content_msat() -> u64 {
    1_000
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;

/// `[sponsor]`: the owner's sponsoring policy (K1 slice 2). See
/// `konsensus_api::handlers::sponsor`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SponsorConfig {
    #[serde(default)]
    pub enabled: bool,
    /// The fixed gift per kit, sats.
    #[serde(default = "default_sponsor_gift_sats")]
    pub gift_sats: u64,
    /// Route-fee ceiling reserved on top of each gift, sats.
    #[serde(default = "default_sponsor_fee_sats")]
    pub fee_sats: u64,
    /// Rolling 24-hour purse, gifts + fees + unresolved, sats.
    #[serde(default = "default_sponsor_purse_sats")]
    pub purse_sats: u64,
    #[serde(default = "default_sponsor_kits_per_day")]
    pub kits_per_day: u32,
}

fn default_sponsor_gift_sats() -> u64 { 20_000 }
fn default_sponsor_fee_sats() -> u64 { 100 }
fn default_sponsor_purse_sats() -> u64 { 100_000 }
fn default_sponsor_kits_per_day() -> u32 { 2 }

impl Default for SponsorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            gift_sats: default_sponsor_gift_sats(),
            fee_sats: default_sponsor_fee_sats(),
            purse_sats: default_sponsor_purse_sats(),
            kits_per_day: default_sponsor_kits_per_day(),
        }
    }
}

impl SponsorConfig {
    /// The policy the API enforces; refuses anything above a spec ceiling.
    pub fn policy(&self) -> Result<konsensus_api::handlers::sponsor::SponsorPolicy, String> {
        let msat = |sats: u64| sats.checked_mul(1000).ok_or_else(|| "[sponsor] amount too large".to_string());
        konsensus_api::handlers::sponsor::SponsorPolicy::new(
            self.enabled,
            msat(self.gift_sats)?,
            msat(self.fee_sats)?,
            msat(self.purse_sats)?,
            self.kits_per_day,
        )
    }
}

fn default_disk_free_floor_bytes() -> u64 { 2 * 1024 * 1024 * 1024 }
