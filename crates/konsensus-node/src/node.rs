//! Node assembly — wires all components based on configuration.
//!
//! The `KonsensusNode` is the running instance of a BitSov v2 node.
//! It owns the identity, storage, payment gate, transport, and API server.
//! Configuration determines which backend implementations are used.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{watch, RwLock};
use tracing::{info, warn};

use konsensus_chain::{EsploraConfig, EsploraProvider, MockChainProvider};
use konsensus_core::gate::PaymentGate;
use konsensus_core::identity::NodeIdentity;
use konsensus_core::traits::chain::ChainProvider;
use konsensus_core::traits::lightning::LightningProvider;
use konsensus_core::traits::pricing::PricingEngine;
use konsensus_core::types::NodeId;
use konsensus_lightning::{LdkConfig, LdkProvider, LndConfig, LndProvider, LnbitsProvider, MockLightningConfig, MockLightningProvider};
use konsensus_message::wire::Capability;
use konsensus_message::{NoiseTransport, PeerRegistry, TransportConfig};
use konsensus_pricing::{ChainAwarePricingConfig, ChainAwarePricingEngine, StaticPricingEngine};
use konsensus_routing::RoutingTable;
use konsensus_storage::Storage;

use crate::config::{ChainConfig, LightningConfig, NodeConfig, PricingMode, StorageConfig};

/// A running BitSov v2 node.
///
/// Owns all components and manages their lifecycle. Created via
/// [`KonsensusNode::from_config`], started with [`KonsensusNode::start`].
pub struct KonsensusNode {
    /// The node's cryptographic identity.
    identity: Arc<NodeIdentity>,

    /// The full configuration.
    config: NodeConfig,

    /// Storage backend (type-erased).
    storage: Arc<dyn Storage>,

    /// Lightning provider (type-erased).
    lightning: Arc<dyn LightningProvider>,

    /// Chain data provider (type-erased).
    chain: Arc<dyn ChainProvider>,

    /// Pricing engine (type-erased).
    pricing: Arc<dyn PricingEngine>,

    /// Payment gate (Principle 2 enforcement).
    gate: Arc<PaymentGate>,

    /// Peer registry (known peers + whitelist).
    peer_registry: Arc<RwLock<PeerRegistry>>,

    /// P2P transport.
    transport: Arc<NoiseTransport>,

    /// Synaptic routing table (bio-inspired adaptive routing).
    routing: Arc<RoutingTable>,

    /// Shutdown signal.
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl KonsensusNode {
    /// Build a node from configuration.
    ///
    /// This wires all components together based on the config file's
    /// backend selections. The node is not started yet — call [`Self::start`] next.
    pub async fn from_config(config: NodeConfig, mnemonic_password: Option<&str>) -> Result<Self> {
        // ── 1. Load identity ────────────────────────────────────────────
        let mnemonic = crate::mnemonic_crypto::read_mnemonic(
            &config.identity.mnemonic_file,
            mnemonic_password,
        )
        .with_context(|| {
            format!(
                "failed to read mnemonic from {} (encrypted: {})",
                config.identity.mnemonic_file.display(),
                crate::mnemonic_crypto::is_encrypted_path(&config.identity.mnemonic_file),
            )
        })?;

        let identity = Arc::new(
            NodeIdentity::from_mnemonic(&mnemonic, &config.identity.passphrase)
                .with_context(|| "failed to derive identity from mnemonic")?,
        );

        info!(node_id = %identity.node_id(), "identity loaded");

        // ── 2. Initialize storage ───────────────────────────────────────
        let storage: Arc<dyn Storage> = match &config.storage {
            StorageConfig::Sqlite { path, encrypted, .. } => {
                let sqlite = konsensus_storage::SqliteStorage::open(path)
                    .await
                    .with_context(|| format!("failed to open SQLite at {path}"))?;
                if *encrypted {
                    Arc::new(konsensus_storage::EncryptedStorage::new(
                        sqlite,
                        identity.aes_key(),
                    ))
                } else {
                    Arc::new(sqlite)
                }
            }
            StorageConfig::Postgres { url, encrypted, .. } => {
                let pg = konsensus_storage::PostgresStorage::connect(url)
                    .await
                    .with_context(|| "failed to connect to PostgreSQL")?;
                if *encrypted {
                    Arc::new(konsensus_storage::EncryptedStorage::new(
                        pg,
                        identity.aes_key(),
                    ))
                } else {
                    Arc::new(pg)
                }
            }
        };

        info!("storage initialized");

        // ── 3. Initialize Lightning provider ────────────────────────────
        let lightning: Arc<dyn LightningProvider> = match &config.lightning {
            LightningConfig::Lnbits { api_url, admin_key } => {
                let lnbits_config = konsensus_lightning::LnbitsConfig {
                    api_url: api_url.clone(),
                    admin_key: admin_key.clone(),
                };
                info!(backend = "lnbits", api_url = %api_url, "lightning provider");
                let provider = LnbitsProvider::new(lnbits_config).map_err(|e| anyhow::anyhow!("lnbits provider: {e}"))?;
                provider.probe_payment_capability().await;
                Arc::new(provider)
            }
            LightningConfig::Lnd { api_url, macaroon_hex, tls_cert_path } => {
                let lnd_config = LndConfig {
                    api_url: api_url.clone(),
                    macaroon_hex: macaroon_hex.clone(),
                    tls_cert_path: tls_cert_path.clone(),
                };
                info!(backend = "lnd", api_url = %api_url, "lightning provider (direct LND REST)");
                let provider = LndProvider::new(lnd_config).map_err(|e| anyhow::anyhow!("lnd provider: {e}"))?;
                provider.probe_payment_capability().await;
                Arc::new(provider)
            }
            LightningConfig::Mock {
                initial_balance_msat,
            } => {
                info!(backend = "mock", balance_msat = initial_balance_msat, "lightning provider (testnet)");
                Arc::new(MockLightningProvider::with_config(MockLightningConfig {
                    initial_balance_msat: *initial_balance_msat,
                }))
            }
            LightningConfig::Ldk {
                network,
                esplora_url,
                esplora_url_fallback,
                rgs_url,
                lsp_node_id,
                lsp_address,
                lsp_token,
                listening_address,
                advertised_address: _,
            } => {
                let data_dir = config
                    .identity
                    .mnemonic_file
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| {
                        warn!("mnemonic_file has no parent directory — using current directory for LDK state");
                        std::path::Path::new(".")
                    });
                let ldk_storage_dir = data_dir.join("ldk");
                let ldk_config = LdkConfig {
                    storage_dir: ldk_storage_dir,
                    scb_backup_dir: Some(std::path::PathBuf::from(&config.backup.scb_dir)),
                    scb_rotation_count: config.backup.rotation_count,
                    mnemonic: mnemonic.to_string(),
                    passphrase: Some(config.identity.passphrase.clone()).filter(|s| !s.is_empty()),
                    network: network.clone(),
                    esplora_url: esplora_url.clone(),
                    esplora_url_fallback: esplora_url_fallback.clone(),
                    rgs_url: rgs_url.clone(),
                    lsp_node_id: lsp_node_id.clone(),
                    lsp_address: lsp_address.clone(),
                    lsp_token: lsp_token.clone(),
                    listening_address: listening_address.clone(),
                };
                info!(
                    backend = "ldk",
                    network = %network,
                    esplora = %esplora_url,
                    esplora_fallback = esplora_url_fallback.as_deref().unwrap_or("none"),
                    "lightning provider (embedded)"
                );
                Arc::new(
                    LdkProvider::new(ldk_config)
                        .await
                        .map_err(|e| anyhow::anyhow!("ldk provider: {e}"))?,
                )
            }
        };

        info!("lightning provider initialized");

        // ── 4. Initialize Chain provider ────────────────────────────────
        let chain: Arc<dyn ChainProvider> = match &config.chain {
            ChainConfig::Esplora { api_url, .. } => {
                let esplora_config = EsploraConfig::custom(
                    api_url.clone(),
                    konsensus_core::traits::chain::TrustLevel::ServerTrust,
                );
                info!(backend = "esplora", api_url = %api_url, "chain provider");
                Arc::new(EsploraProvider::new(esplora_config).map_err(|e| anyhow::anyhow!("esplora provider: {e}"))?)
            }
            ChainConfig::Mock => {
                info!(backend = "mock", "chain provider (testnet)");
                Arc::new(MockChainProvider::new())
            }
        };

        info!("chain provider initialized");

        // ── 5. Initialize Pricing engine ────────────────────────────────
        let base_pricing_config = konsensus_pricing::StaticPricingConfig {
            chat_msat: config.pricing.chat_msat,
            longform_msat: config.pricing.longform_msat,
            calendar_msat: config.pricing.calendar_msat,
            file_ref_msat: config.pricing.file_ref_msat,
            control_msat: config.pricing.control_msat,
            collaboration_msat: config.pricing.collaboration_msat,
            realtime_signal_msat: config.pricing.realtime_signal_msat,
            app_ext_msat: config.pricing.app_ext_msat,
            web_content_msat: config.pricing.web_content_msat,
        };
        let pricing: Arc<dyn PricingEngine> = match config.pricing.mode {
            PricingMode::Static => {
                info!(mode = "static", "pricing engine");
                Arc::new(StaticPricingEngine::new(base_pricing_config))
            }
            PricingMode::ChainAware => {
                info!(
                    mode = "chain_aware",
                    fee_target_blocks = config.pricing.fee_target_blocks,
                    fee_cache_secs = config.pricing.fee_cache_secs,
                    "pricing engine"
                );
                let chain_pricing_config = ChainAwarePricingConfig {
                    base: base_pricing_config,
                    fee_target_blocks: config.pricing.fee_target_blocks,
                    cache_ttl: std::time::Duration::from_secs(config.pricing.fee_cache_secs),
                    max_price_multiplier: config.pricing.max_price_multiplier,
                    fee_rate_ema_alpha: config.pricing.fee_rate_ema_alpha,
                    category_fee_targets: config.pricing.category_fee_targets.clone(),
                };
                let engine = ChainAwarePricingEngine::new(
                    chain_pricing_config,
                    Arc::clone(&chain),
                );

                // Load EMA snapshot from previous run if available.
                // This prevents cold-start pricing spikes after restarts.
                let snapshot_path = Self::fee_rate_snapshot_path(&config);
                if let Some(snapshot) = Self::load_fee_rate_snapshot(&snapshot_path) {
                    engine.seed_ema(snapshot).await;
                }

                Arc::new(engine)
            }
        };

        info!("pricing engine initialized");

        // ── 6. Build peer registry ──────────────────────────────────────
        let mut peer_registry = PeerRegistry::new();
        for peer_cfg in &config.peers {
            let node_id = NodeId::from_hex(&peer_cfg.node_id)
                .with_context(|| format!("invalid node_id hex: {}", peer_cfg.node_id))?;
            peer_registry.add(konsensus_message::PeerEntry {
                node_id,
                addr: peer_cfg.addr,
                label: peer_cfg.label.clone(),
                auto_connect: peer_cfg.auto_connect,
            });
        }

        info!(peers = peer_registry.len(), "peer registry loaded");

        // ── 7. Build transport ──────────────────────────────────────────
        let transport_config = TransportConfig {
            listen_addr: config.network.listen_addr,
            tier: config.network.tier,
            capabilities: vec![Capability::X3dh],
            whitelist: peer_registry.whitelist(),
            version: 2,
        };

        let transport = Arc::new(NoiseTransport::new(
            Arc::clone(&identity),
            transport_config,
        ));

        // ── 8. Build payment gate ───────────────────────────────────────
        let gate = Arc::new(PaymentGate::new());

        // ── 9. Build routing table ─────────────────────────────────────
        let routing = Arc::new(RoutingTable::with_defaults());
        info!("routing table initialized");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Ok(Self {
            identity,
            config,
            storage,
            lightning,
            chain,
            pricing,
            gate,
            peer_registry: Arc::new(RwLock::new(peer_registry)),
            transport,
            routing,
            shutdown_tx,
            shutdown_rx,
        })
    }

    /// Start the node — begins listening for peer connections and starts
    /// the connection supervisor for auto-connect peers.
    ///
    /// The supervisor monitors each peer's connection health, reconnects
    /// with exponential backoff on drops, and sends keepalive pings.
    pub async fn start(&self) -> Result<()> {
        // Start P2P transport listener
        self.transport.start_listener().await
            .context("failed to start transport listener")?;

        info!(addr = %self.config.network.listen_addr, "P2P transport listening");

        // Start supervised connections for auto-connect peers
        let registry = self.peer_registry.read().await;
        let supervised: Vec<_> = registry.auto_connect_peers()
            .into_iter()
            .map(|e| (e.node_id, e.addr))
            .collect();
        drop(registry);

        if !supervised.is_empty() {
            info!(
                count = supervised.len(),
                "starting connection supervisor for auto-connect peers"
            );
            self.transport.start_supervisor(supervised);
        }

        // Start routing table maintenance (periodic decay + pruning)
        self.routing.spawn_maintenance();
        info!("routing table maintenance tasks started");

        Ok(())
    }

    /// Get a handle to the shutdown receiver (for graceful shutdown).
    pub fn shutdown_rx(&self) -> watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }

    /// Signal all components to shut down.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        self.transport.shutdown();
        info!("node shutdown signaled");
    }

    // ── Accessors for API layer ─────────────────────────────────────────

    /// The node's identity.
    pub fn identity(&self) -> &Arc<NodeIdentity> {
        &self.identity
    }

    /// The node's ID (Ed25519 public key).
    pub fn node_id(&self) -> &NodeId {
        self.identity.node_id()
    }

    /// The storage backend.
    pub fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }

    /// The Lightning provider.
    pub fn lightning(&self) -> &Arc<dyn LightningProvider> {
        &self.lightning
    }

    /// The chain provider.
    pub fn chain(&self) -> &Arc<dyn ChainProvider> {
        &self.chain
    }

    /// The pricing engine.
    pub fn pricing(&self) -> &Arc<dyn PricingEngine> {
        &self.pricing
    }

    /// The payment gate.
    pub fn gate(&self) -> &Arc<PaymentGate> {
        &self.gate
    }

    /// The peer registry.
    pub fn peer_registry(&self) -> &Arc<RwLock<PeerRegistry>> {
        &self.peer_registry
    }

    /// The P2P transport.
    pub fn transport(&self) -> &Arc<NoiseTransport> {
        &self.transport
    }

    /// The synaptic routing table.
    pub fn routing(&self) -> &Arc<RoutingTable> {
        &self.routing
    }

    /// The full node configuration.
    #[allow(dead_code)]
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Derive the fee rate snapshot file path from the node config.
    ///
    /// Stored alongside the database file for co-locality.
    fn fee_rate_snapshot_path(config: &NodeConfig) -> std::path::PathBuf {
        let base_dir = match &config.storage {
            StorageConfig::Sqlite { path, .. } => {
                std::path::Path::new(path)
                    .parent()
                    .unwrap_or(std::path::Path::new("."))
                    .to_path_buf()
            }
            StorageConfig::Postgres { .. } => {
                // For PostgreSQL, use the current working directory
                std::path::PathBuf::from(".")
            }
        };
        base_dir.join("fee_rate_snapshot.json")
    }

    /// Load a fee rate snapshot from disk, if it exists.
    fn load_fee_rate_snapshot(
        path: &std::path::Path,
    ) -> Option<konsensus_pricing::FeeRateSnapshot> {
        let data = std::fs::read_to_string(path).ok()?;
        match serde_json::from_str(&data) {
            Ok(snapshot) => {
                tracing::info!(path = %path.display(), "loaded fee rate snapshot");
                Some(snapshot)
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to parse fee rate snapshot, ignoring"
                );
                None
            }
        }
    }

    /// Save a fee rate snapshot to disk.
    pub fn save_fee_rate_snapshot(
        config: &NodeConfig,
        snapshot: &konsensus_pricing::FeeRateSnapshot,
    ) {
        let path = Self::fee_rate_snapshot_path(config);
        match serde_json::to_string(snapshot) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to save fee rate snapshot"
                    );
                } else {
                    tracing::debug!(path = %path.display(), "saved fee rate snapshot");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialize fee rate snapshot");
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/node.rs"]
mod tests;
