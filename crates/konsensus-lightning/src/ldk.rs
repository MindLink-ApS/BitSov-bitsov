//! LDK-based embedded Lightning provider.
//!
//! Implements `LightningProvider` using `ldk-node` — a fully sovereign Lightning node
//! embedded directly in the BitSov binary. No external LND/CLN/LNbits needed.
//!
//! Key design decisions (ADR-013):
//! - Uses the same BIP-39 mnemonic as BitSov identity (different derivation path via LDK)
//! - Persists state to a subdirectory of the node's data directory
//! - Esplora chain source by default (same as BitSov ChainProvider)
//! - RapidGossipSync for network graph data (avoids P2P gossip bandwidth)
//! - LSPS2 liquidity source for automatic inbound channel provisioning

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::Rng;

use async_trait::async_trait;
use bip39::Mnemonic;
use futures::stream::BoxStream;
use futures::StreamExt;
use ldk_node::config::{BackgroundSyncConfig, EsploraSyncConfig};
use ldk_node::lightning_invoice::{
    Bolt11InvoiceDescription as LdkInvoiceDescription, Description as LdkDescription,
};
use ldk_node::payment::PaymentKind as LdkPaymentKind;
use ldk_node::payment::PaymentStatus as LdkPaymentStatus;
use ldk_node::{Builder as LdkBuilder, CustomTlvRecord, Node as LdkNode};
use tokio::sync::broadcast;
use tracing::{debug, error, info, instrument, warn};
use zeroize::Zeroizing;

use crate::liquidity::{JitBackend, LiquidityClient, LiquidityConfig};
use konsensus_core::traits::liquidity::{LiquidityInfo, LiquidityQuote, LiquidityReceipt};

use crate::scb_export::write_monitor_store_scb;
use crate::scb_rotate::{rotate_scb_backup, ScbRotationConfig};
use konsensus_core::fee_rate::validate_fee_rate_sat_per_vb;
use konsensus_core::traits::lightning::{
    ChannelInfo, InboundPayment, Invoice, LightningError, LightningProvider, PaymentDetails,
    PaymentDirection, PaymentStatus, WalletBalanceBreakdown, WalletSync,
};

/// Configuration for the embedded LDK Lightning provider.
#[derive(Debug, Clone)]
pub struct LdkConfig {
    /// Opt in to forwarding into private channels, without enabling announcements.
    pub forward_to_private_channels: bool,
    /// Shared per-file diagnostic log limits.
    pub logging: konsensus_core::logging::LoggingConfig,
    /// Own Bitcoin Core overrides Esplora, including probes and fallback.
    pub bitcoind: Option<konsensus_chain::BitcoindConfig>,
    /// Explicit Electrum source overrides Esplora; mutually exclusive with Core.
    pub electrum: Option<konsensus_chain::ElectrumConfig>,
    /// Explicit LSPS2 provider registry (off by default).
    pub liquidity: LiquidityConfig,
    /// Opt-in hub service; mutually exclusive with the LSPS2 client.
    pub lsps2_service: crate::lsps2_service::Lsps2ServiceConfig,
    /// When set, new channels in either direction are limited to these node ids
    /// (`--remote-unlock`: the configured hub/LSPs). Excludes the hub service role.
    pub channel_peers: Option<Vec<String>>,
    /// Path to store LDK state (channel monitors, network graph, scorer, etc.).
    pub storage_dir: PathBuf,
    /// Directory where encrypted SCB snapshots are rotated.
    pub scb_backup_dir: Option<PathBuf>,
    /// Number of encrypted SCB snapshots to retain.
    pub scb_rotation_count: usize,
    /// BIP-39 mnemonic for key derivation.
    pub mnemonic: String,
    /// Optional BIP-39 passphrase.
    pub passphrase: Option<String>,
    /// Bitcoin network: "bitcoin", "testnet", "signet", "regtest".
    pub network: String,
    /// Esplora server URL for chain data.
    pub esplora_url: String,
    /// Optional fallback Esplora server URL. If the primary `esplora_url` is
    /// unreachable at startup (L4b — covers the 2026-04-23 alpha crash-loop
    /// caused by mempool.space fee-fetch timeouts), `LdkProvider::new`
    /// switches to this URL on preflight or actual startup fee-fetch failure.
    pub esplora_url_fallback: Option<String>,
    /// Optional background polling overrides, used only with Esplora.
    pub esplora_sync_intervals: EsploraSyncIntervals,
    /// Owner-only OAuth credentials for the primary Esplora source.
    pub credentials_file: Option<PathBuf>,
    /// Optional RapidGossipSync server URL.
    pub rgs_url: Option<String>,
    /// Optional LSPS2 LSP node ID (hex pubkey) for automatic inbound liquidity.
    pub lsp_node_id: Option<String>,
    /// Optional LSPS2 LSP address (host:port).
    pub lsp_address: Option<String>,
    /// Optional LSPS2 LSP token.
    pub lsp_token: Option<String>,
    /// Listening address for Lightning P2P (e.g., "0.0.0.0:9735").
    pub listening_address: Option<String>,
}

impl LdkConfig {
    fn node_config(
        &self,
        admission: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    ) -> ldk_node::config::Config {
        ldk_node::config::Config {
            accept_forwards_to_priv_channels: self.forward_to_private_channels,
            work_admission: admission.map(ldk_node::config::WorkAdmissionCheck::new),
            ..Default::default()
        }
    }
}

/// Independent Esplora polling overrides. Omitted values retain LDK's defaults.
#[derive(Debug, Clone, Copy, Default)]
pub struct EsploraSyncIntervals {
    pub onchain_wallet_sync_interval_secs: Option<u64>,
    pub lightning_wallet_sync_interval_secs: Option<u64>,
    pub fee_rate_cache_update_interval_secs: Option<u64>,
}

impl EsploraSyncIntervals {
    /// Validate before starting any network work, keeping background sync enabled.
    pub fn to_sync_config(self) -> Result<EsploraSyncConfig, LightningError> {
        let mut background = BackgroundSyncConfig::default();
        for (field, value, target) in [
            (
                "onchain_wallet_sync_interval_secs",
                self.onchain_wallet_sync_interval_secs,
                &mut background.onchain_wallet_sync_interval_secs,
            ),
            (
                "lightning_wallet_sync_interval_secs",
                self.lightning_wallet_sync_interval_secs,
                &mut background.lightning_wallet_sync_interval_secs,
            ),
            (
                "fee_rate_cache_update_interval_secs",
                self.fee_rate_cache_update_interval_secs,
                &mut background.fee_rate_cache_update_interval_secs,
            ),
        ] {
            if let Some(value) = value {
                if !(10..=3600).contains(&value) {
                    return Err(LightningError::InvalidStartupConfig(format!(
                        "lightning.{field} must be between 10 and 3600 seconds (inclusive)"
                    )));
                }
                *target = value;
            }
        }
        Ok(EsploraSyncConfig {
            background_sync_config: Some(background),
        })
    }
}

fn sync_status_is_ready(
    status: &ldk_node::NodeStatus,
    baseline: (Option<u64>, Option<u64>),
    sync_intervals: &BackgroundSyncConfig,
    now: u64,
) -> bool {
    // Require both wallets to synchronize in this startup, and revoke readiness
    // if updates stop. Allow two normal sync periods before declaring stale.
    let fresh = |timestamp: Option<u64>, period: u64| {
        timestamp.is_some_and(|t| now.saturating_sub(t) <= period.saturating_mul(2))
    };
    status.is_running
        && status.latest_lightning_wallet_sync_timestamp != baseline.0
        && status.latest_onchain_wallet_sync_timestamp != baseline.1
        && fresh(
            status.latest_fee_rate_cache_update_timestamp,
            sync_intervals.fee_rate_cache_update_interval_secs,
        )
        && fresh(
            status.latest_lightning_wallet_sync_timestamp,
            sync_intervals.lightning_wallet_sync_interval_secs,
        )
        && fresh(
            status.latest_onchain_wallet_sync_timestamp,
            sync_intervals.onchain_wallet_sync_interval_secs,
        )
}

/// Application keysend TLV type carrying the BitSov payment→envelope *binding*
/// (R2 / ADR-037, **Proposed**). MUST be ODD (BOLT 1: odd = "it's ok to be odd",
/// optional/forward-compatible) and distinct from the keysend preimage record
/// `5482373484`. The TLV carries a binding (payment_hash / envelope-id pointer),
/// NOT the full `UkmEnvelope` — the bulk ciphertext rides the out-of-band
/// transport, linked by `payment_hash`. Pinned here until ADR-037 ratifies it;
/// the send side (pushing this record on keysend) is a later seam.
const BITSOV_BINDING_TLV_TYPE: u64 = 0x4253_4F56_0001; // "BSOV" + 0x0001, odd

/// Bounded fan-out for inbound keysend subscribers. Lag is observable and
/// fail-closed downstream; the event drainer itself remains backpressured.
const INBOUND_BROADCAST_CAPACITY: usize = 256;

/// Fan-out for outgoing settle/fail wake-up hints. Lag only costs a spurious
/// re-check (see [`LightningProvider::outgoing_payment_updates`]).
const OUTGOING_BROADCAST_CAPACITY: usize = 256;

/// ADR-037 binding values are pointers/digests, not envelopes. Keep the copy
/// into `InboundPayment` bounded so a peer cannot turn a paid contact into a
/// large allocation/logging surface.
const BITSOV_BINDING_TLV_MAX_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingTlvError {
    Duplicate,
    TooLarge { len: usize },
}

/// Extract the BitSov binding payload from a received payment's custom TLV
/// records, if exactly one is present. Ignores unrelated records (e.g. the
/// keysend preimage record). Duplicate or oversized records are explicit
/// errors, so admission cannot accidentally treat ambiguous/large bindings as a
/// bare keysend. Pure — unit-testable without an LDK node.
fn extract_binding_tlv(
    custom_records: &[CustomTlvRecord],
) -> Result<Option<Vec<u8>>, BindingTlvError> {
    let mut matches = custom_records
        .iter()
        .filter(|r| r.type_num == BITSOV_BINDING_TLV_TYPE);
    let Some(first) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(BindingTlvError::Duplicate);
    }
    if first.value.len() > BITSOV_BINDING_TLV_MAX_BYTES {
        return Err(BindingTlvError::TooLarge {
            len: first.value.len(),
        });
    }
    Ok(Some(first.value.clone()))
}

/// Construct the single BitSov binding TLV record (ADR-037) the send-half
/// (`keysend_with_binding`, seam-3b) attaches to a keysend. Kept next to
/// [`extract_binding_tlv`] so send and receive share one definition of the
/// record shape: what this emits, that extracts. Pure — unit-testable without
/// an LDK node; the seam-3b contract test asserts the round-trip.
fn binding_tlv_record(binding: &[u8]) -> CustomTlvRecord {
    CustomTlvRecord {
        type_num: BITSOV_BINDING_TLV_TYPE,
        value: binding.to_vec(),
    }
}

/// Construct the outbound binding TLV record after applying the same cap the
/// receive-half enforces. This is the send-side preflight used before calling
/// LDK, so an oversized binding fails closed before any sats are spent.
fn binding_tlv_record_for_send(binding: &[u8]) -> Result<CustomTlvRecord, LightningError> {
    if binding.is_empty() {
        return Err(LightningError::Backend(
            "binding-TLV keysend requires a non-empty binding".into(),
        ));
    }

    if binding.len() > BITSOV_BINDING_TLV_MAX_BYTES {
        return Err(LightningError::Backend(format!(
            "binding TLV too large: {} > {BITSOV_BINDING_TLV_MAX_BYTES} bytes (receiver would reject as BindingTooLarge)",
            binding.len()
        )));
    }

    Ok(binding_tlv_record(binding))
}

/// Construct an in-flight spontaneous payment fallback when LDK has returned a
/// `PaymentId` but its payment store has not surfaced the record yet. LDK Node
/// sets spontaneous `PaymentId` bytes to the generated payment hash bytes, so a
/// binding path must preserve those bytes instead of returning an empty hash.
fn in_flight_spontaneous_payment_details(
    payment_hash: [u8; 32],
    amount_msat: u64,
    timestamp: u64,
) -> PaymentDetails {
    PaymentDetails {
        payment_hash: hex::encode(payment_hash),
        preimage: None,
        amount_msat,
        status: PaymentStatus::InFlight,
        direction: PaymentDirection::Outgoing,
        timestamp,
        memo: None,
        fee_msat: None,
    }
}

/// `watch_inbound_keysend` may only surface payment records that are already
/// admissible proof material for the downstream gate: settled, incoming, and
/// carrying the preimage that proves settlement.
fn is_admittable_inbound_payment(details: &PaymentDetails) -> bool {
    details.status == PaymentStatus::Settled
        && details.direction == PaymentDirection::Incoming
        && details.amount_msat > 0
        && details.preimage.is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundPaymentRejection {
    MissingStoreRecord,
    MalformedStoreHash,
    HashMismatch,
    EventStoreAmountMismatch,
    NotAdmittableProof,
    DuplicateBinding,
    BindingTooLarge { len: usize },
}

fn payment_hash_bytes_from_details(
    details: &PaymentDetails,
) -> Result<[u8; 32], InboundPaymentRejection> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(&details.payment_hash, &mut bytes)
        .map_err(|_| InboundPaymentRejection::MalformedStoreHash)?;
    Ok(bytes)
}

fn inbound_payment_from_received_event(
    event_payment_hash: [u8; 32],
    event_amount_msat: u64,
    details: Option<&PaymentDetails>,
    custom_records: &[CustomTlvRecord],
) -> Result<InboundPayment, InboundPaymentRejection> {
    let Some(details) = details else {
        return Err(InboundPaymentRejection::MissingStoreRecord);
    };
    if payment_hash_bytes_from_details(details)? != event_payment_hash {
        return Err(InboundPaymentRejection::HashMismatch);
    }
    if details.amount_msat != event_amount_msat {
        return Err(InboundPaymentRejection::EventStoreAmountMismatch);
    }
    if !is_admittable_inbound_payment(details) {
        return Err(InboundPaymentRejection::NotAdmittableProof);
    }
    let binding_tlv = extract_binding_tlv(custom_records).map_err(|e| match e {
        BindingTlvError::Duplicate => InboundPaymentRejection::DuplicateBinding,
        BindingTlvError::TooLarge { len } => InboundPaymentRejection::BindingTooLarge { len },
    })?;
    Ok(InboundPayment {
        details: details.clone(),
        binding_tlv,
    })
}

/// Embedded LDK Lightning provider — the node IS its own Lightning node.
///
/// This is the most sovereign option: no external Lightning daemon needed.
/// The LDK node runs in-process, derives keys from the same mnemonic,
/// and manages channels automatically via LSP.
///
/// Tracks payment capability via an atomic flag that gets set to `false`
/// when a payment fails due to a channel/funding issue. The flag is cleared
/// on any successful payment. This ensures `is_available()` reflects actual
/// payment capability, not just whether the LDK node is running.
pub struct LdkProvider {
    sync_baseline: (Option<u64>, Option<u64>),
    sync_intervals: BackgroundSyncConfig,
    routing_fee_policy: konsensus_core::traits::lightning::RoutingFeePolicy,
    liquidity: Option<LiquidityClient>,
    liquidity_info: LiquidityInfo,
    node: Arc<LdkNode>,
    /// Set to `false` when a payment fails due to a channel/funding issue.
    /// Reset to `true` on successful payment.
    payment_capable: AtomicBool,
    bitcoind: Option<Arc<konsensus_chain::BitcoindProvider>>,
    electrum: Option<Arc<konsensus_chain::ElectrumProvider>>,
    onchain_operations: crate::onchain::OnchainOperations,
    /// L0g (2026-04-30): set to `true` to signal the dedicated event
    /// drainer task to exit. Set during graceful shutdown BEFORE
    /// `node.stop()` so the drainer doesn't try to call into a stopped
    /// node. Also set in `from_node` (test path) so tests don't spawn
    /// a drainer that would touch an external node they don't own.
    drainer_shutdown: Arc<AtomicBool>,
    /// R2 seam-2: broadcast sender for SETTLED, INBOUND payments surfaced by
    /// [`LightningProvider::watch_inbound_keysend`]. The event drainer's async
    /// consumer emits an [`InboundPayment`] here on each `Event::PaymentReceived`
    /// (it FEEDS the stream from the single mpsc consumer, preserving the
    /// drainer's backpressure for the log/SCB path — the broadcast is fan-out).
    inbound_tx: broadcast::Sender<InboundPayment>,
    /// Hex payment hash of each outgoing `PaymentSuccessful`/`PaymentFailed`,
    /// fed by the same consumer; a wake-up hint for settlement polls only.
    outgoing_tx: broadcast::Sender<String>,
}

impl std::fmt::Debug for LdkProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdkProvider")
            .field("running", &self.node.status().is_running)
            .field(
                "payment_capable",
                &self.payment_capable.load(Ordering::Relaxed),
            )
            .finish()
    }
}

// The fresh-hash check and send share a lock with ordinary invoice payments.
// A capped sponsor payment must never retry an older failed attempt: LDK may
// initiate HTLCs before persisting its replacement Pending record.
static INVOICE_DISPATCH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl LdkProvider {
    /// A monitor can survive funding that never reached the chain. Value a
    /// removed channel only after checking its funding, without changing LDK's
    /// monitor/recovery state. Queries use the configured backend exclusively.
    async fn funded_balances(
        &self,
        channels: &[ldk_node::ChannelDetails],
    ) -> Result<ldk_node::BalanceDetails, LightningError> {
        let mut balances = self.node.list_balances();
        let open: std::collections::HashSet<_> = channels.iter().map(|ch| ch.channel_id).collect();
        crate::balance::verify_closed_funding(&mut balances, &open, |channel_id| async move {
            let funding = self
                .node
                .channel_funding_outpoint(channel_id)
                .ok_or_else(|| {
                    LightningError::Backend("channel funding monitor unavailable".into())
                })?;
            self.funding_present(&funding.txid.to_string()).await
        })
        .await?;
        Ok(balances)
    }

    async fn funding_present(&self, txid: &str) -> Result<bool, LightningError> {
        let txid = txid
            .parse()
            .map_err(|_| LightningError::Backend("invalid funding txid".into()))?;
        self.node.funding_present(txid).await.map_err(|error| {
            LightningError::Backend(format!("funding presence unavailable: {error}"))
        })
    }

    /// Configure the ordinary payment fee ceiling before sharing this provider.
    pub fn with_routing_fee_policy(
        mut self,
        policy: konsensus_core::traits::lightning::RoutingFeePolicy,
    ) -> Self {
        self.routing_fee_policy = policy;
        self
    }

    async fn pay_invoice_routed(
        &self,
        bolt11: &str,
        max_fee_msat: u64,
        fresh_hash: bool,
    ) -> Result<PaymentDetails, LightningError> {
        let invoice: ldk_node::lightning_invoice::Bolt11Invoice = bolt11
            .parse()
            .map_err(|e| LightningError::InvalidBolt11(format!("{e}")))?;

        let payment_hash_hex = hex::encode(AsRef::<[u8]>::as_ref(invoice.payment_hash()));
        let amount_msat = invoice.amount_milli_satoshis().unwrap_or(0);

        let _dispatch = INVOICE_DISPATCH_LOCK.lock().map_err(|_| {
            LightningError::PaymentNotDispatched("invoice dispatch lock poisoned".into())
        })?;
        let payment_id_bytes: [u8; 32] =
            AsRef::<[u8]>::as_ref(invoice.payment_hash())
                .try_into()
                .map_err(|_| LightningError::PaymentNotDispatched("invalid payment hash".into()))?;
        if fresh_hash
            && self
                .node
                .payment(&ldk_node::lightning::ln::channelmanager::PaymentId(
                    payment_id_bytes,
                ))
                .is_some()
        {
            return Err(LightningError::PaymentNotDispatched(
                "capped payments require a fresh invoice hash".into(),
            ));
        }
        let payment_id =
            dispatch_invoice_with_fee_limit(&invoice, max_fee_msat, |invoice, route| {
                self.node.bolt11_payment().send(invoice, route)
            })
            .map_err(|e| classify_dispatch_error(e, &self.payment_capable))?;

        // Successful send — ensure the capability flag is set
        self.payment_capable.store(true, Ordering::Relaxed);

        // Poll for completion (LDK processes payments asynchronously)
        // We return InFlight immediately; callers should use get_payment_status to poll.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check if the payment completed quickly
        if let Some(details) = self.node.payment(&payment_id) {
            return Ok(convert_payment_details(&details));
        }

        Ok(PaymentDetails {
            payment_hash: payment_hash_hex,
            preimage: None,
            amount_msat,
            status: PaymentStatus::InFlight,
            direction: PaymentDirection::Outgoing,
            timestamp: now,
            memo: None,
            fee_msat: None,
        })
    }

    fn stored_payment(
        &self,
        hash: &str,
    ) -> Result<ldk_node::payment::PaymentDetails, LightningError> {
        let bytes = hex::decode(hash).map_err(|_| LightningError::PaymentNotFound(hash.into()))?;
        let id: [u8; 32] = bytes
            .try_into()
            .map_err(|_| LightningError::PaymentNotFound(hash.into()))?;
        self.node
            .payment(&ldk_node::lightning::ln::channelmanager::PaymentId(id))
            .ok_or_else(|| LightningError::PaymentNotFound(hash.into()))
    }

    /// Create and start a new LDK provider from the given config.
    ///
    /// Key derivation: The BIP-39 mnemonic is converted to a 64-byte seed,
    /// then blake3 KDF with context `"konsensus-v2 ldk-lightning"` derives
    /// a 64-byte LDK-specific entropy seed. This ensures LDK keys are
    /// deterministically derived from the same mnemonic as the BitSov
    /// identity, but on a separate derivation domain — recovering the
    /// mnemonic recovers both the node identity and the Lightning wallet.
    pub async fn new(config: LdkConfig) -> Result<Self, LightningError> {
        Self::new_with_work_admission(config, None).await
    }

    /// Node-local disk policy, checked before inbound settlement and channel acceptance.
    pub async fn new_with_work_admission(
        config: LdkConfig,
        admission: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    ) -> Result<Self, LightningError> {
        Self::new_inner(config, admission, false).await
    }

    /// Owner-console maintenance only. Caller holds the existing live-state
    /// process lease; keep it captured by `deny_work` until LDK has stopped.
    pub async fn new_for_move_home(
        mut config: LdkConfig,
        deny_work: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Self, LightningError> {
        config.liquidity = Default::default();
        config.lsps2_service = Default::default();
        config.lsp_node_id = None;
        config.lsp_address = None;
        config.lsp_token = None;
        config.forward_to_private_channels = false;
        Self::new_inner(config, Some(deny_work), true).await
    }

    async fn new_inner(
        mut config: LdkConfig,
        admission: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
        moving_home: bool,
    ) -> Result<Self, LightningError> {
        if !moving_home {
            ensure_no_move_home(&config.storage_dir)?;
        }
        // Move the plaintext seed phrase out of `config` into a `Zeroizing`
        // wrapper so the inbound `String` copy is scrubbed from memory when
        // this function returns (HARD-9), regardless of which branch we take.
        // The parsed `bip39::Mnemonic` (built with the `zeroize` feature) is
        // itself `ZeroizeOnDrop`.
        let mnemonic_phrase = Zeroizing::new(std::mem::take(&mut config.mnemonic));
        let esplora_sync_config = config.esplora_sync_intervals.to_sync_config()?;
        let sync_intervals = if config.bitcoind.is_some() || config.electrum.is_some() {
            BackgroundSyncConfig::default()
        } else {
            esplora_sync_config
                .background_sync_config
                .expect("background sync is enabled")
        };
        let lsps2_service = config.lsps2_service.to_ldk(config.liquidity.enabled)?;
        let channel_peer_allowlist = channel_peer_allowlist(
            config.channel_peers.as_deref(),
            lsps2_service.is_some(),
        )?;
        let mnemonic = Mnemonic::from_str(&mnemonic_phrase)
            .map_err(|e| LightningError::InvalidStartupConfig(format!("invalid mnemonic: {e}")))?;

        // Derive BIP-39 seed (64 bytes) from mnemonic + passphrase.
        //
        // Wrapped in `Zeroizing` so the raw seed bytes are scrubbed from
        // memory when this function returns (HARD-9). A `[u8; 64]` is `Copy`
        // and never runs `Drop`, so without this the seed would linger on the
        // stack until the frame is overwritten by chance.
        let passphrase = config.passphrase.as_deref().unwrap_or("");
        let bip39_seed = Zeroizing::new(mnemonic.to_seed(passphrase));

        // Derive LDK-specific 64-byte entropy via blake3 KDF with domain separation.
        // This keeps LDK keys deterministically linked to the mnemonic but isolated
        // from the BitSov identity keys (which use different context strings).
        // Also `Zeroizing` — it is just as sensitive as the BIP-39 seed.
        let ldk_seed = Zeroizing::new(derive_ldk_entropy(&*bip39_seed));

        let network = parse_network(&config.network)?;
        let auth = config
            .credentials_file
            .as_deref()
            .map(konsensus_chain::bearer::BearerAuth::from_file)
            .transpose()
            .map_err(|e| LightningError::InvalidStartupConfig(e.to_string()))?;
        let auth_transport = auth
            .as_ref()
            .map(|auth| {
                konsensus_chain::bearer::BearerFailover::new(
                    auth.clone(),
                    &config.esplora_url,
                    config.esplora_url_fallback.iter().cloned().collect(),
                )
            })
            .transpose()
            .map_err(|e| LightningError::InvalidStartupConfig(e.to_string()))?;
        if config.bitcoind.is_some() && config.electrum.is_some() {
            return Err(LightningError::InvalidStartupConfig(
                "select only one of bitcoind or electrum".into(),
            ));
        }
        if config.bitcoind.is_none() && config.electrum.is_none() {
            validate_startup_url("esplora_url", &config.esplora_url)?;
            if let Some(url) = &config.esplora_url_fallback {
                validate_startup_url("esplora_url_fallback", url)?;
            }
        }
        let bitcoind = config
            .bitcoind
            .clone()
            .map(konsensus_chain::BitcoindProvider::new)
            .transpose()
            .map_err(|e| LightningError::InvalidStartupConfig(e.to_string()))?;
        let electrum = config
            .electrum
            .clone()
            .map(konsensus_chain::ElectrumProvider::new)
            .transpose()
            .map_err(|e| LightningError::InvalidStartupConfig(e.to_string()))?
            .map(Arc::new);
        if let Some(url) = &config.rgs_url {
            validate_startup_url("rgs_url", url)?;
        }

        // Ensure the LDK storage directory exists
        std::fs::create_dir_all(&config.storage_dir).map_err(|e| {
            LightningError::Backend(format!(
                "failed to create LDK storage dir {}: {e}",
                config.storage_dir.display()
            ))
        })?;

        info!(
            storage_dir = %config.storage_dir.display(),
            "LDK entropy derived from mnemonic via blake3 KDF (context: {:?})",
            LDK_KDF_CONTEXT,
        );

        let mut node_config = config.node_config(admission);
        node_config.cooperative_close_only = moving_home;
        node_config.channel_peer_allowlist = channel_peer_allowlist;
        let mut builder = LdkBuilder::from_config(node_config);
        builder.set_network(network);
        builder.set_entropy_seed_bytes(*ldk_seed);
        builder.set_storage_dir_path(
            config
                .storage_dir
                .to_str()
                .ok_or_else(|| {
                    LightningError::Backend("storage dir path is not valid UTF-8".into())
                })?
                .to_string(),
        );

        // Gossip source — RGS if configured, otherwise P2P
        if let Some(ref rgs_url) = config.rgs_url {
            builder.set_gossip_source_rgs(rgs_url.clone());
        } else {
            builder.set_gossip_source_p2p();
        }

        if let Some(service) = lsps2_service {
            builder.set_liquidity_provider_lsps2(service);
        }

        let mut log_level = ldk_node::config::DEFAULT_LOG_LEVEL;

        // The old singleton fields never enabled invoice issuance. Require the
        // new explicit switch, and reject ambiguous migrations instead of silently
        // choosing a peer. Existing operators get a clear configuration error.
        if config.lsp_node_id.is_some()
            || config.lsp_address.is_some()
            || config.lsp_token.is_some()
        {
            return Err(LightningError::InvalidStartupConfig("migrate legacy lsp_* fields to liquidity.providers and explicitly enable liquidity".into()));
        }
        if let Some(lsp) = config
            .liquidity
            .selected()
            .map_err(|e| LightningError::InvalidStartupConfig(e.to_string()))?
        {
            builder.set_liquidity_source_lsps2(
                lsp.node_id
                    .parse()
                    .map_err(|_| LightningError::InvalidStartupConfig("invalid LSP key".into()))?,
                lsp.address.parse().map_err(|_| {
                    LightningError::InvalidStartupConfig("invalid LSP address".into())
                })?,
                lsp.token.clone(),
            );
            // LDK logs the full JIT invoice at INFO. Private previews must never
            // leak a payable invoice via logs before fee authorization.
            log_level = ldk_node::logger::LogLevel::Warn;
        }

        let logger = crate::ldk_logging::BoundedLdkLogger::open(
            &config.storage_dir.join("ldk_node.log"),
            config.logging,
            log_level,
        )
        .map_err(|_| LightningError::Backend("failed to initialize bounded LDK logging".into()))?;
        builder.set_custom_logger(Arc::new(logger));

        // Listening address for Lightning P2P
        if let Some(ref addr) = config.listening_address {
            let socket_addr = addr.parse().map_err(|e| {
                LightningError::InvalidStartupConfig(format!("invalid listening address: {e}"))
            })?;
            builder
                .set_listening_addresses(vec![socket_addr])
                .map_err(|e| {
                    LightningError::InvalidStartupConfig(format!(
                        "failed to set listening address: {e}"
                    ))
                })?;
        }

        // Validate all local settings before the first network request. The budget
        // includes preflight; only the two Esplora fee-barrier errors are retried.
        let started = Instant::now();
        let (node, _, baseline) = if let Some(rpc) = &config.bitcoind {
            let (user, password) = rpc
                .credentials()
                .map_err(|e| LightningError::InvalidStartupConfig(e.to_string()))?;
            builder.set_chain_source_bitcoind_rpc(
                rpc.rpc_host.clone(),
                rpc.rpc_port,
                user.to_string(),
                password.to_string(),
            );
            let node = builder.build().map_err(startup_build_error)?;
            let baseline = node.status();
            node.start()
                .map_err(|_| LightningError::ChainSourceUnavailable {
                    network: config.network.clone(),
                    service: "bitcoind".into(),
                    attempts: 1,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    cause: "Bitcoin Core RPC startup failed".into(),
                })?;
            tokio::task::yield_now().await;
            (node, String::new(), baseline)
        } else if let Some(server) = &config.electrum {
            builder.set_chain_source_electrum(server.server_url.clone(), None);
            let node = builder.build().map_err(startup_build_error)?;
            let baseline = node.status();
            node.start()
                .map_err(|_| LightningError::ChainSourceUnavailable {
                    network: config.network.clone(),
                    service: "electrum".into(),
                    attempts: 1,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    cause: "Electrum startup failed".into(),
                })?;
            tokio::task::yield_now().await;
            (node, String::new(), baseline)
        } else {
            // Authenticated sources use LDK's real fee barrier as the probe, with live auth.
            let chosen = if auth_transport.is_some() {
                config.esplora_url.clone()
            } else {
                select_esplora_endpoint(&config.esplora_url, config.esplora_url_fallback.as_deref())
                    .await
            };
            start_esplora_with_retry(builder, &config, chosen, started, auth_transport).await?
        };
        info!(network = %config.network, chain_backend = if bitcoind.is_some() { "bitcoind" } else if electrum.is_some() { "electrum" } else { "esplora" }, "LDK embedded Lightning node started");

        let node = Arc::new(node);
        let drainer_shutdown = Arc::new(AtomicBool::new(false));
        let scb_producer = Arc::new(ScbProducer::new(
            config.storage_dir,
            config.scb_backup_dir,
            config.scb_rotation_count,
            &ldk_seed,
        ));
        // `ldk_seed` and `bip39_seed` are no longer needed; drop them now so
        // their `Zeroizing` wrappers scrub the raw entropy from memory before
        // the node begins serving (HARD-9). `ScbProducer::new` has already
        // derived and retained only the rotation key it needs.
        drop(ldk_seed);
        drop(bip39_seed);

        // L0g (2026-04-30): spawn the dedicated LDK-event drainer ONCE at
        // init. Replaces the synchronous `process_events()` calls that
        // used to fire at the top of every async trait method (which
        // stalled a tokio runtime worker thread for the duration of the
        // ChannelMonitor fsync — tens of ms under disk pressure).
        // R2 seam-2: inbound-payment fan-out. The initial receiver is dropped;
        // subscribers come from `watch_inbound_keysend` via `.subscribe()`.
        let (inbound_tx, _) = broadcast::channel(INBOUND_BROADCAST_CAPACITY);
        let (outgoing_tx, _) = broadcast::channel(OUTGOING_BROADCAST_CAPACITY);
        Self::spawn_event_drainer(
            Arc::clone(&node),
            Arc::clone(&drainer_shutdown),
            Arc::clone(&scb_producer),
            inbound_tx.clone(),
            outgoing_tx.clone(),
            config.lsps2_service.clone(),
        );
        Self::spawn_scb_timer(Arc::clone(&drainer_shutdown), scb_producer);

        let liquidity = config.liquidity.selected()?.map(|p| {
            LiquidityClient::new(
                p.node_id.clone(),
                Arc::new(LdkJitBackend(Arc::clone(&node))),
            )
        });
        let bitcoind = bitcoind.map(Arc::new);
        if bitcoind.is_some() || electrum.is_some() {
            let rpc = bitcoind.clone();
            let server = electrum.clone();
            node.set_funding_verifier(move |txid| {
                let rpc = rpc.clone();
                let server = server.clone();
                async move {
                    if let Some(rpc) = rpc {
                        rpc.funding_present(&txid.to_string())
                            .await
                            .map_err(|_| ldk_node::NodeError::TxSyncFailed)
                    } else if let Some(server) = server {
                        // Detached Electrum work retains its permit after outer cancellation.
                        static VERIFY: tokio::sync::Semaphore =
                            tokio::sync::Semaphore::const_new(1);
                        let permit = VERIFY
                            .acquire()
                            .await
                            .map_err(|_| ldk_node::NodeError::TxSyncFailed)?;
                        tokio::spawn(async move {
                            let _permit = permit;
                            server
                                .funding_present(&txid.to_string())
                                .await
                                .map_err(|_| ldk_node::NodeError::TxSyncFailed)
                        })
                        .await
                        .map_err(|_| ldk_node::NodeError::TxSyncFailed)?
                    } else {
                        Err(ldk_node::NodeError::TxSyncFailed)
                    }
                }
            });
        }

        let provider = Self {
            sync_intervals,
            sync_baseline: (
                baseline.latest_lightning_wallet_sync_timestamp,
                baseline.latest_onchain_wallet_sync_timestamp,
            ),
            routing_fee_policy: Default::default(),
            liquidity,
            liquidity_info: config.liquidity.info(),
            onchain_operations: crate::onchain::OnchainOperations::new(
                node.onchain_operation_lock(),
            ),
            node,
            payment_capable: AtomicBool::new(true),
            bitcoind,
            electrum,
            drainer_shutdown,
            inbound_tx,
            outgoing_tx,
        };
        // Reconcile durable reservations against the selected chain source on
        // startup, then retry periodically. Source failure never unlocks coins.
        if !moving_home {
            let mut cursor = None;
            crate::onchain::reconcile_local_spends(
                &provider.node,
                &provider.chain_visibility(),
                &mut cursor,
            )
            .await;
            provider.spawn_reservation_reconciler(cursor);
        }
        Ok(provider)
    }

    /// Create an LdkProvider from an already-started LDK node (for testing).
    ///
    /// Test path — does NOT spawn the L0g event drainer. Tests that
    /// instantiate LdkProvider via this constructor are responsible for
    /// their own event handling if they need it; spawning a drainer here
    /// would (a) require an active tokio runtime that the test may not
    /// have, and (b) call `next_event()` against a node the test may
    /// have constructed without expecting the wider lifecycle.
    pub fn from_node(node: Arc<LdkNode>) -> Self {
        // Test path does not spawn the drainer, so nothing emits here; the
        // inbound stream simply stays empty.
        let (inbound_tx, _) = broadcast::channel(INBOUND_BROADCAST_CAPACITY);
        let (outgoing_tx, _) = broadcast::channel(OUTGOING_BROADCAST_CAPACITY);
        Self {
            sync_baseline: (None, None),
            sync_intervals: BackgroundSyncConfig::default(),
            routing_fee_policy: Default::default(),
            liquidity: None,
            liquidity_info: LiquidityInfo::default(),
            onchain_operations: crate::onchain::OnchainOperations::new(
                node.onchain_operation_lock(),
            ),
            node,
            payment_capable: AtomicBool::new(true),
            bitcoind: None,
            electrum: None,
            // Pre-set to `true` so any consumer wrapping a from_node-constructed
            // provider sees the drainer as already-shutdown.
            drainer_shutdown: Arc::new(AtomicBool::new(true)),
            inbound_tx,
            outgoing_tx,
        }
    }

    fn chain_visibility(&self) -> crate::onchain::ChainVisibility {
        crate::onchain::ChainVisibility {
            node: self.node.clone(),
            bitcoind: self.bitcoind.clone(),
            electrum: self.electrum.clone(),
        }
    }

    fn spawn_reservation_reconciler(&self, mut cursor: Option<ldk_node::bitcoin::Txid>) {
        let node = self.node.clone();
        let chain = self.chain_visibility();
        let shutdown = self.drainer_shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                crate::onchain::reconcile_local_spends(&node, &chain, &mut cursor).await;
            }
        });
    }

    /// L0g (2026-04-30): the LDK event drainer.
    ///
    /// Spawns two tasks:
    /// 1. A `spawn_blocking` task that owns `node.next_event()` polling.
    ///    It drains every available event in a tight inner loop, then
    ///    sleeps 50ms when idle so the shutdown flag is checked at least
    ///    every 50ms. We intentionally avoid `wait_next_event()` (which
    ///    blocks indefinitely) so shutdown can complete promptly without
    ///    waiting for the next event to arrive.
    /// 2. A `tokio::spawn` async consumer that receives events from the
    ///    mpsc channel and logs them. Replaces the inline match block from
    ///    the old `process_events()`. Future code can fan out to additional
    ///    consumers (gossip, metrics, plasticity feedback) by extending
    ///    this consumer or by replacing the channel with a `broadcast`.
    ///
    /// The mpsc channel is bounded at 64. If the consumer is slow, the
    /// drainer blocks on `blocking_send` — backpressure flows naturally
    /// and no events are dropped. LDK's `event_handled()` is called only
    /// AFTER the event has been accepted into the channel, so a crash
    /// between accept and handled-mark would re-deliver the event on
    /// next start.
    fn spawn_event_drainer(
        node: Arc<LdkNode>,
        shutdown: Arc<AtomicBool>,
        scb_producer: Arc<ScbProducer>,
        inbound_tx: broadcast::Sender<InboundPayment>,
        outgoing_tx: broadcast::Sender<String>,
        lsps2_service: crate::lsps2_service::Lsps2ServiceConfig,
    ) {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ldk_node::Event>(64);

        // Drainer (blocking pool) — owns event reception.
        let drain_node = Arc::clone(&node);
        let drain_shutdown = Arc::clone(&shutdown);
        tokio::task::spawn_blocking(move || {
            // Sweep on startup too: a crash can happen after LDK persists the
            // channel but before the application handles ChannelReady.
            let mut tariff_retry = crate::lsps2_service::TariffRetry::new(Instant::now());
            let mut next_metrics = Instant::now();
            while !drain_shutdown.load(Ordering::Relaxed) {
                if lsps2_service.enabled && Instant::now() >= next_metrics {
                    crate::lsps2_service::record_metrics(&drain_node);
                    next_metrics = Instant::now() + Duration::from_secs(1);
                }
                tariff_retry
                    .apply_if_due(Instant::now(), || lsps2_service.apply_tariffs(&drain_node));
                let mut drained_any = false;
                while let Some(event) = drain_node.next_event() {
                    drained_any = true;
                    if matches!(event, ldk_node::Event::ChannelReady { .. }) {
                        tariff_retry.request(Instant::now());
                    }
                    // Also service retries under a continuously busy event queue.
                    // Failures never hold ChannelReady or unrelated payment events.
                    tariff_retry
                        .apply_if_due(Instant::now(), || lsps2_service.apply_tariffs(&drain_node));
                    if tx.blocking_send(event).is_err() {
                        // Consumer dropped (shutdown or panic) — exit cleanly.
                        debug!("LDK event drainer: consumer gone, exiting");
                        return;
                    }
                    if let Err(e) = drain_node.event_handled() {
                        warn!(error = %e, "LDK: failed to mark event as handled");
                    }
                }
                if !drained_any {
                    // Idle — yield briefly and re-check shutdown.
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
            debug!("LDK event drainer task exiting");
        });

        // Consumer (async) — logs events AND (R2 seam-2) feeds the inbound
        // payment stream. Emitting from THIS single mpsc consumer preserves the
        // drainer's `blocking_send` backpressure for the log/SCB path (no event
        // dropped); the broadcast is pure fan-out for `watch_inbound_keysend`.
        let consumer_node = Arc::clone(&node);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                Self::log_event(&event);
                if let Some(hash) = outgoing_update_hash(&event) {
                    // Err only means no settlement poll is waiting right now.
                    let _ = outgoing_tx.send(hash);
                }
                if let ldk_node::Event::PaymentReceived {
                    payment_id,
                    payment_hash,
                    amount_msat,
                    custom_records,
                } = &event
                {
                    let event_payment_hash = payment_hash.0;
                    let event_payment_hash_hex = hex::encode(event_payment_hash);
                    // PaymentReceived is the settled inbound claim. The stream
                    // is admission-adjacent, so it never fabricates a proof from
                    // event fields alone: it emits only when LDK's payment store
                    // contains a Settled+Incoming record with a preimage.
                    let details = payment_id
                        .and_then(|pid| consumer_node.payment(&pid))
                        .map(|p| convert_payment_details(&p));
                    let inbound = match inbound_payment_from_received_event(
                        event_payment_hash,
                        *amount_msat,
                        details.as_ref(),
                        custom_records,
                    ) {
                        Ok(inbound) => inbound,
                        Err(InboundPaymentRejection::MissingStoreRecord) => {
                            warn!(
                                payment_id = ?payment_id,
                                payment_hash = %event_payment_hash_hex,
                                amount_msat,
                                "LDK PaymentReceived without poll-verifiable store record; skipping inbound admission stream item"
                            );
                            continue;
                        }
                        Err(InboundPaymentRejection::MalformedStoreHash) => {
                            if let Some(details) = &details {
                                warn!(
                                    payment_id = ?payment_id,
                                    event_payment_hash = %event_payment_hash_hex,
                                    store_payment_hash = %details.payment_hash,
                                    "LDK PaymentReceived store record hash is not canonical 32-byte hex; skipping inbound admission stream item"
                                );
                            }
                            continue;
                        }
                        Err(InboundPaymentRejection::HashMismatch) => {
                            if let Some(details) = &details {
                                warn!(
                                    payment_id = ?payment_id,
                                    event_payment_hash = %event_payment_hash_hex,
                                    store_payment_hash = %details.payment_hash,
                                    "LDK PaymentReceived store record hash mismatch; skipping inbound admission stream item"
                                );
                            }
                            continue;
                        }
                        Err(InboundPaymentRejection::EventStoreAmountMismatch) => {
                            if let Some(details) = &details {
                                warn!(
                                    payment_id = ?payment_id,
                                    payment_hash = %details.payment_hash,
                                    event_amount_msat = amount_msat,
                                    store_amount_msat = details.amount_msat,
                                    "LDK PaymentReceived event/store amount mismatch; skipping inbound admission stream item"
                                );
                            }
                            continue;
                        }
                        Err(InboundPaymentRejection::NotAdmittableProof) => {
                            if let Some(details) = &details {
                                warn!(
                                    payment_id = ?payment_id,
                                    payment_hash = %details.payment_hash,
                                    amount_msat = details.amount_msat,
                                    status = ?details.status,
                                    direction = ?details.direction,
                                    has_preimage = details.preimage.is_some(),
                                    admission_reconcile_required = true,
                                    "LDK PaymentReceived store record is not settled incoming proof material; skipping inbound admission stream item; durable reconciliation must recover if this was an event/store ordering race"
                                );
                            }
                            continue;
                        }
                        Err(InboundPaymentRejection::DuplicateBinding) => {
                            if let Some(details) = &details {
                                warn!(
                                    payment_id = ?payment_id,
                                    payment_hash = %details.payment_hash,
                                    "LDK PaymentReceived carried duplicate BitSov binding TLVs; skipping inbound admission stream item"
                                );
                            }
                            continue;
                        }
                        Err(InboundPaymentRejection::BindingTooLarge { len }) => {
                            if let Some(details) = &details {
                                warn!(
                                    payment_id = ?payment_id,
                                    payment_hash = %details.payment_hash,
                                    binding_len = len,
                                    max_binding_len = BITSOV_BINDING_TLV_MAX_BYTES,
                                    "LDK PaymentReceived BitSov binding TLV exceeds size cap; skipping inbound admission stream item"
                                );
                            }
                            continue;
                        }
                    };
                    // Err only means no current subscriber; record is still
                    // observable via the get_payment_status poll path.
                    let _ = inbound_tx.send(inbound);
                }
                if is_channel_state_change_event(&event) {
                    if let Err(e) = scb_producer.produce_once().await {
                        warn!(error = %e, "SCB producer failed on channel state-change event");
                    }
                }
            }
            debug!("LDK event consumer task exiting");
        });
    }

    fn spawn_scb_timer(shutdown: Arc<AtomicBool>, scb_producer: Arc<ScbProducer>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                if let Err(e) = scb_producer.produce_once().await {
                    warn!(error = %e, "SCB producer failed on periodic timer");
                }
            }
            debug!("LDK SCB producer timer exiting");
        });
    }

    /// L0g: log a single LDK event. Centralized so any future consumer
    /// (metrics, plasticity feedback, gossip) can observe the same set
    /// of fields. Behavior matches the pre-L0g `process_events()` match.
    fn log_event(event: &ldk_node::Event) {
        match event {
            ldk_node::Event::PaymentReceived {
                payment_id,
                amount_msat,
                ..
            } => {
                info!(
                    payment_id = ?payment_id,
                    amount_msat = amount_msat,
                    "LDK: payment received"
                );
            }
            ldk_node::Event::PaymentSuccessful {
                payment_id,
                fee_paid_msat,
                ..
            } => {
                info!(
                    payment_id = ?payment_id,
                    fee_msat = ?fee_paid_msat,
                    "LDK: payment sent successfully"
                );
            }
            ldk_node::Event::PaymentFailed {
                payment_id, reason, ..
            } => {
                warn!(
                    payment_id = ?payment_id,
                    reason = ?reason,
                    "LDK: payment failed"
                );
            }
            ldk_node::Event::ChannelReady {
                channel_id,
                counterparty_node_id,
                ..
            } => {
                info!(
                    channel_id = %channel_id,
                    peer = ?counterparty_node_id,
                    "LDK: channel ready"
                );
            }
            ldk_node::Event::ChannelClosed {
                channel_id, reason, ..
            } => {
                warn!(
                    channel_id = %channel_id,
                    reason = ?reason,
                    "LDK: channel closed"
                );
            }
            other => {
                debug!(event = ?other, "LDK: event");
            }
        }
    }

    /// Get a reference to the underlying LDK node.
    pub fn node(&self) -> &LdkNode {
        &self.node
    }

    /// Process pending LDK events.
    ///
    /// L0g (2026-04-30): now a no-op. The dedicated drainer task spawned
    /// at `LdkProvider::new()` (see `spawn_event_drainer`) owns event
    /// reception and emits events via an mpsc channel. Calling this
    /// method is harmless; it stays in the public API for backward
    /// compatibility with any external caller, but does nothing.
    ///
    /// The internal trait methods that used to call this every time
    /// (9 sites prior to L0g) no longer do — those calls were removed
    /// because each invocation stalled a tokio runtime worker thread
    /// during the synchronous LDK event drain (which fsync's
    /// `ChannelMonitor` updates — tens of ms under disk pressure).
    #[deprecated(note = "L0g: events are drained by the dedicated event-drainer \
                task spawned at LdkProvider::new(). This method is now \
                a no-op kept for API back-compat.")]
    pub fn process_events(&self) {
        // No-op. See doc comment + spawn_event_drainer.
    }
}

/// The hash a settlement poll tracks (`get_payment_status` key) for an
/// outgoing payment that just settled or failed. ldk-node updates its payment
/// store before queueing these events, so the re-read sees the new state.
fn outgoing_update_hash(event: &ldk_node::Event) -> Option<String> {
    match event {
        ldk_node::Event::PaymentSuccessful { payment_hash, .. } => {
            Some(hex::encode(payment_hash.0))
        }
        ldk_node::Event::PaymentFailed {
            payment_hash: Some(hash),
            ..
        } => Some(hex::encode(hash.0)),
        // Payment ids of invoice payments are their hashes; for any other
        // payment an empty hint re-checks whatever is waiting.
        ldk_node::Event::PaymentFailed { payment_id, .. } => {
            Some(payment_id.map(|id| hex::encode(id.0)).unwrap_or_default())
        }
        _ => None,
    }
}

fn is_channel_state_change_event(event: &ldk_node::Event) -> bool {
    matches!(
        event,
        ldk_node::Event::ChannelPending { .. }
            | ldk_node::Event::ChannelReady { .. }
            | ldk_node::Event::ChannelClosed { .. }
    )
}

struct ScbProducer {
    rotation: ScbRotationConfig,
    master_key: [u8; 32],
    lock: tokio::sync::Mutex<()>,
}

impl ScbProducer {
    fn new(
        storage_dir: PathBuf,
        backup_dir: Option<PathBuf>,
        rotation_count: usize,
        ldk_seed: &[u8; 64],
    ) -> Self {
        let master_key = blake3::derive_key("konsensus-v2 scb-rotation", ldk_seed);
        let backup_dir = backup_dir.unwrap_or_else(|| storage_dir.join("backups"));
        Self {
            rotation: ScbRotationConfig {
                scb_path: storage_dir.join("scb.bin"),
                backup_dir,
                rotation_count,
            },
            master_key,
            lock: tokio::sync::Mutex::new(()),
        }
    }

    async fn produce_once(&self) -> Result<(), LightningError> {
        let _guard = self.lock.lock().await;
        let storage_dir = self
            .rotation
            .scb_path
            .parent()
            .ok_or_else(|| LightningError::Backend("invalid SCB path (no parent dir)".into()))?
            .to_path_buf();
        let scb_path = self.rotation.scb_path.clone();
        let rotate_cfg = self.rotation.clone();
        let master_key = self.master_key;
        tokio::task::spawn_blocking(move || {
            write_monitor_store_scb(&storage_dir, &scb_path)
                .map_err(|e| LightningError::Backend(format!("SCB monitor export failed: {e}")))?;
            rotate_scb_backup(&rotate_cfg, &master_key)
                .map_err(|e| LightningError::Backend(format!("SCB rotation failed: {e}")))?;
            Ok::<(), LightningError>(())
        })
        .await
        .map_err(|e| LightningError::Backend(format!("SCB producer join error: {e}")))?
    }
}

impl Drop for LdkProvider {
    /// Fallback safety net only — the graceful-shutdown path in
    /// `crates/konsensus-node/src/main.rs` calls
    /// `LightningProvider::shutdown()` BEFORE the tokio runtime begins
    /// tearing down, which is the path that actually completes
    /// `ChannelMonitor::persist()`. Drop is reached too late (runtime
    /// already exiting) for that persistence to be reliable. Keep Drop
    /// as a defensive cleanup for panic / abort paths where the explicit
    /// shutdown didn't run, but treat it as best-effort.
    fn drop(&mut self) {
        self.drainer_shutdown.store(true, Ordering::Relaxed);
        match self.node.stop() {
            Ok(()) => warn!(
                "LDK node stopped in Drop — panic-path fallback; explicit shutdown did not stop it"
            ),
            // stop() is not idempotent: this is the expected result after
            // LightningProvider::shutdown has already persisted and stopped it.
            Err(ldk_node::NodeError::NotRunning) => debug!("LDK node already stopped before Drop"),
            Err(e) => error!(
                error = %e,
                "LDK node.stop() in Drop failed — this is the panic-path fallback; \
                 graceful shutdown should have called LightningProvider::shutdown() \
                 earlier"
            ),
        }
    }
}

#[async_trait]
impl LightningProvider for LdkProvider {
    fn chain_sync_status(&self) -> Option<konsensus_core::traits::lightning::ChainSyncStatus> {
        self.node.status().chain_sync_failure.map(|failure| {
            konsensus_core::traits::lightning::ChainSyncStatus::Stalled {
                since: failure.since,
                last_error_kind: if failure.rate_limited {
                    konsensus_core::traits::lightning::ChainSyncErrorKind::RateLimited
                } else {
                    konsensus_core::traits::lightning::ChainSyncErrorKind::SyncFailed
                },
            }
        })
    }

    async fn money_ready(&self) -> bool {
        let status = self.node.status();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        sync_status_is_ready(&status, self.sync_baseline, &self.sync_intervals, now)
    }

    fn routing_fee_policy(&self) -> konsensus_core::traits::lightning::RoutingFeePolicy {
        self.routing_fee_policy
    }
    fn liquidity_info(&self) -> LiquidityInfo {
        self.liquidity_info.clone()
    }

    async fn quote_liquidity(
        &self,
        owner: &str,
        gross_msat: u64,
        max_fee_msat: u64,
    ) -> Result<LiquidityQuote, LightningError> {
        self.liquidity
            .as_ref()
            .ok_or_else(|| LightningError::Backend("LSPS2 liquidity disabled".into()))?
            .quote(owner, gross_msat, max_fee_msat)
            .await
    }

    fn liquidity_quote(&self, owner: &str, id: &str) -> Result<LiquidityQuote, LightningError> {
        self.liquidity
            .as_ref()
            .ok_or_else(|| LightningError::Backend("LSPS2 liquidity disabled".into()))?
            .terms(owner, id)
    }

    async fn accept_liquidity(&self, owner: &str, id: &str) -> Result<Invoice, LightningError> {
        self.liquidity
            .as_ref()
            .ok_or_else(|| LightningError::PaymentNotDispatched("LSPS2 liquidity disabled".into()))?
            .accept(owner, id)
    }

    async fn is_funding_payment(&self, hash: &str) -> Result<bool, LightningError> {
        let details = self.stored_payment(hash)?;
        Ok(matches!(details.kind, LdkPaymentKind::Bolt11Jit { .. }))
    }

    async fn liquidity_receipt(
        &self,
        hash: &str,
    ) -> Result<Option<LiquidityReceipt>, LightningError> {
        let p = self.stored_payment(hash)?;
        jit_receipt(&p)
    }

    /// L0e (2026-04-30): graceful shutdown of the embedded LDK node.
    ///
    /// `node.stop()` is synchronous and fsyncs `ChannelMonitor` updates +
    /// channel state to disk. We MUST run it before the tokio runtime
    /// tears down (otherwise queued persistence calls are silently
    /// dropped — channel state divergence on next restart). Wrapping in
    /// `tokio::task::spawn_blocking` keeps the sync work off the runtime
    /// worker pool while still being awaitable from the async caller.
    async fn shutdown(&self) -> Result<(), LightningError> {
        // L0g (2026-04-30): signal the event-drainer task to exit BEFORE
        // calling `node.stop()`. Otherwise the drainer would call
        // `node.next_event()` against a stopped node, which could either
        // log spurious errors or — worse — race with shutdown's
        // `event_handled()` calls. The drainer checks the flag at most
        // every 50ms (the idle sleep), so it exits within ~50ms of this
        // store.
        self.drainer_shutdown.store(true, Ordering::Relaxed);

        let node = Arc::clone(&self.node);
        tokio::task::spawn_blocking(move || node.stop())
            .await
            .map_err(|e| LightningError::Backend(format!("LDK shutdown join error: {e}")))?
            .map_err(|e| LightningError::Backend(format!("LDK node.stop() failed: {e}")))?;
        info!("LDK node stopped cleanly");
        Ok(())
    }

    #[instrument(skip(self), fields(amount_msat, description))]
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        let desc_inner = LdkDescription::new(description.to_string())
            .map_err(|e| LightningError::InvoiceCreation(format!("invalid description: {e}")))?;
        let desc = LdkInvoiceDescription::Direct(desc_inner);

        let ldk_invoice = self
            .node
            .bolt11_payment()
            .receive(amount_msat, &desc, expiry_secs)
            .map_err(|e| LightningError::InvoiceCreation(format!("{e}")))?;

        let payment_hash = hex::encode(AsRef::<[u8]>::as_ref(ldk_invoice.payment_hash()));
        let bolt11 = ldk_invoice.to_string();
        let created_at = ldk_invoice.duration_since_epoch().as_secs();

        Ok(Invoice {
            bolt11,
            payment_hash,
            amount_msat,
            description: description.to_string(),
            expiry_secs,
            created_at,
        })
    }

    async fn create_stateless_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        let desc = LdkInvoiceDescription::Direct(
            LdkDescription::new(description.to_owned())
                .map_err(|e| LightningError::InvoiceCreation(e.to_string()))?,
        );
        let signed = self
            .node
            .bolt11_payment()
            .receive_stateless(amount_msat, &desc, expiry_secs)
            .map_err(|e| LightningError::InvoiceCreation(e.to_string()))?;
        Ok(Invoice {
            payment_hash: signed.payment_hash().to_string(),
            bolt11: signed.to_string(),
            amount_msat,
            description: description.to_owned(),
            expiry_secs,
            created_at: signed.duration_since_epoch().as_secs(),
        })
    }

    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        let invoice: ldk_node::lightning_invoice::Bolt11Invoice = bolt11
            .parse()
            .map_err(|e| LightningError::InvalidBolt11(format!("{e}")))?;
        let amount = invoice
            .amount_milli_satoshis()
            .ok_or_else(|| LightningError::PaymentNotDispatched("amountless invoice".into()))?;
        self.pay_invoice_routed(bolt11, self.routing_fee_policy.ceiling(amount, None), false)
            .await
    }

    async fn pay_invoice_with_fee_limit(
        &self,
        bolt11: &str,
        max_fee_msat: u64,
    ) -> Result<PaymentDetails, LightningError> {
        self.pay_invoice_routed(bolt11, max_fee_msat, true).await
    }

    #[instrument(skip(self), fields(payment_hash))]
    async fn get_payment_status(
        &self,
        payment_hash: &str,
    ) -> Result<PaymentDetails, LightningError> {
        let hash_bytes = hex::decode(payment_hash).map_err(|e| {
            LightningError::PaymentNotFound(format!("invalid payment hash hex: {e}"))
        })?;

        // Search through all payments for matching hash
        let payments = self.node.list_payments();
        for payment in &payments {
            if let Some(hash) = payment_hash_from_kind(&payment.kind) {
                if hash.0 == hash_bytes.as_slice() {
                    return Ok(convert_payment_details(payment));
                }
            }
        }

        Err(LightningError::PaymentNotFound(payment_hash.to_string()))
    }

    #[instrument(skip(self))]
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        let balances = self.funded_balances(&self.node.list_channels()).await?;
        // Legacy aggregate, excluding removed-channel claims without confirmed
        // funding. This remains claimable value, not spendable LN capacity.
        let lightning_msat = balances.total_lightning_balance_sats * 1000;
        let onchain_msat = balances.spendable_onchain_balance_sats * 1000;

        Ok(lightning_msat + onchain_msat)
    }

    async fn get_balance_breakdown(&self) -> Result<WalletBalanceBreakdown, LightningError> {
        let channels = self.node.list_channels();
        let balances = self.funded_balances(&channels).await?;
        Ok(crate::balance::breakdown(
            &balances,
            channels
                .iter()
                .map(|ch| (ch.channel_id, ch.is_usable, ch.outbound_capacity_msat)),
        ))
    }

    #[instrument(skip(self), fields(limit))]
    async fn list_payments(&self, limit: u32) -> Result<Vec<PaymentDetails>, LightningError> {
        let mut payments: Vec<PaymentDetails> = self
            .node
            .list_payments()
            .iter()
            .map(convert_payment_details)
            .collect();

        // Sort by timestamp descending (most recent first)
        payments.sort_by_key(|p| std::cmp::Reverse(p.timestamp));

        // Apply limit
        payments.truncate(limit as usize);

        Ok(payments)
    }

    #[instrument(skip(self))]
    async fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
        let channels = self
            .node
            .list_channels()
            .into_iter()
            .map(|ch| {
                let capacity_sats = ch.channel_value_sats;
                let outbound_msat = ch.outbound_capacity_msat;
                let inbound_msat = ch.inbound_capacity_msat;
                let scid = ch.short_channel_id.map(|id| id.to_string());

                ChannelInfo {
                    // Same formatting `open_channel` returns and `close_channel`
                    // parses back (UserChannelId Display).
                    channel_id: format!("{}", ch.user_channel_id),
                    peer_pubkey: ch.counterparty_node_id.to_string(),
                    capacity_msat: capacity_sats * 1000,
                    local_balance_msat: outbound_msat,
                    remote_balance_msat: inbound_msat,
                    active: ch.is_usable,
                    short_channel_id: scid,
                }
            })
            .collect();

        Ok(channels)
    }

    async fn is_available(&self) -> bool {
        self.node.status().is_running
    }

    /// Balance and channels are served from LDK's locally synced wallets;
    /// they are as current as the older of the two last syncs.
    async fn wallet_sync(&self) -> WalletSync {
        let status = self.node.status();
        wallet_sync_from_timestamps(
            status.latest_lightning_wallet_sync_timestamp,
            status.latest_onchain_wallet_sync_timestamp,
        )
    }

    async fn is_payment_capable(&self) -> bool {
        self.payment_capable.load(Ordering::Relaxed)
    }

    async fn keysend(
        &self,
        dest_pubkey: &str,
        amount_msat: u64,
        memo: Option<&str>,
    ) -> Result<PaymentDetails, LightningError> {
        self.keysend_with_fee_limit(
            dest_pubkey,
            amount_msat,
            memo,
            self.routing_fee_policy.ceiling(amount_msat, None),
        )
        .await
    }

    async fn keysend_with_fee_limit(
        &self,
        dest_pubkey: &str,
        amount_msat: u64,
        _memo: Option<&str>,
        max_fee_msat: u64,
    ) -> Result<PaymentDetails, LightningError> {
        let pubkey: bitcoin::secp256k1::PublicKey = dest_pubkey.parse().map_err(|e| {
            LightningError::PaymentNotDispatched(format!("invalid destination pubkey: {e}"))
        })?;

        let payment_id = dispatch_keysend_with_fee_limit(
            amount_msat,
            pubkey,
            max_fee_msat,
            |amount, dest, route| self.node.spontaneous_payment().send(amount, dest, route),
        )
        .map_err(|e| classify_dispatch_error(e, &self.payment_capable))?;

        // Successful send — ensure the capability flag is set
        self.payment_capable.store(true, Ordering::Relaxed);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check if the payment completed quickly
        if let Some(details) = self.node.payment(&payment_id) {
            return Ok(convert_payment_details(&details));
        }

        Ok(PaymentDetails {
            payment_hash: String::new(),
            preimage: None,
            amount_msat,
            status: PaymentStatus::InFlight,
            direction: PaymentDirection::Outgoing,
            timestamp: now,
            memo: None,
            fee_msat: None,
        })
    }

    /// R2 seam-3b: send-half of ADR-037 over a real LDK node. Mirrors
    /// [`keysend`](Self::keysend), but attaches the BitSov payment→envelope
    /// *binding* as a single custom (odd) keysend TLV record
    /// ([`BITSOV_BINDING_TLV_TYPE`]) so the recipient's seam-2
    /// `watch_inbound_keysend` can pair the settled HTLC to the out-of-band
    /// `UkmEnvelope`.
    ///
    /// Fails closed BEFORE spending if the binding exceeds
    /// [`BITSOV_BINDING_TLV_MAX_BYTES`]: the receive-half rejects an oversized
    /// binding as `BindingTooLarge`, so sending it would burn the sender's sats
    /// on a payment the recipient can never bind. This method supplies exactly
    /// one binding record, so the receiver's duplicate guard never trips on our
    /// own send.
    async fn keysend_with_binding(
        &self,
        dest_pubkey: &str,
        amount_msat: u64,
        binding_tlv: &[u8],
    ) -> Result<PaymentDetails, LightningError> {
        let custom_tlvs = vec![binding_tlv_record_for_send(binding_tlv)?];

        let pubkey: bitcoin::secp256k1::PublicKey = dest_pubkey
            .parse()
            .map_err(|e| LightningError::Backend(format!("invalid destination pubkey: {e}")))?;

        let payment_id = dispatch_keysend_with_fee_limit(
            amount_msat,
            pubkey,
            self.routing_fee_policy.ceiling(amount_msat, None),
            |amount, dest, route| {
                self.node.spontaneous_payment().send_with_custom_tlvs(
                    amount,
                    dest,
                    route,
                    custom_tlvs,
                )
            },
        )
        .map_err(|e| classify_dispatch_error(e, &self.payment_capable))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check if the payment completed quickly
        if let Some(details) = self.node.payment(&payment_id) {
            return Ok(convert_payment_details(&details));
        }

        Ok(in_flight_spontaneous_payment_details(
            payment_id.0,
            amount_msat,
            now,
        ))
    }

    /// R2 seam-2: subscribe to settled inbound payments. The event drainer's
    /// consumer feeds `inbound_tx` on each `Event::PaymentReceived`; this
    /// returns a stream over a fresh subscription. A lagged subscriber skips
    /// missed items (the authoritative no-drop guarantee for admission belongs
    /// to the downstream receive→admit wiring, not this fan-out).
    async fn watch_inbound_keysend(
        &self,
    ) -> Result<BoxStream<'static, InboundPayment>, LightningError> {
        let rx = self.inbound_tx.subscribe();
        let stream = futures::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(item) => return Some((item, rx)),
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(
                            skipped,
                            "inbound_keysend stream lagged; subscriber skipped settled inbound payments"
                        );
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        });
        Ok(stream.boxed())
    }

    fn outgoing_payment_updates(&self) -> Option<BoxStream<'static, String>> {
        let rx = self.outgoing_tx.subscribe();
        Some(
            futures::stream::unfold(rx, |mut rx| async move {
                match rx.recv().await {
                    Ok(hash) => Some((hash, rx)),
                    // Dropped hints: wake every waiter to re-check.
                    Err(broadcast::error::RecvError::Lagged(_)) => Some((String::new(), rx)),
                    Err(broadcast::error::RecvError::Closed) => None,
                }
            })
            .boxed(),
        )
    }

    async fn get_node_pubkey(&self) -> Option<String> {
        // The node's Lightning public key is a stable identity, valid whenever the
        // node object exists (it was built successfully or this provider would not
        // exist). It must NOT gate on the transient `status().is_running` flag:
        // that flag can read `false` on an otherwise fully operational,
        // payment-capable node. Observed live on mainnet 2026-07-15 — a single
        // `/health` response reported `lightning_available = true` (which also reads
        // `status().is_running`, via `is_available`) yet `lightning_node_pubkey =
        // null` here, i.e. `status().is_running` flapped between the two reads in the
        // same request. Report the pubkey unconditionally so `/health`'s
        // `lightning_node_pubkey` and hosting's operator pubkey are reliable.
        //
        // NOTE: the same flap also affects `is_available()` (which returns
        // `status().is_running` directly); that is a more sensitive operational gate
        // and is left for separate review rather than widened here.
        Some(self.node.node_id().to_string())
    }

    async fn get_funding_address(&self) -> Option<String> {
        match self.node.onchain_payment().new_address() {
            Ok(addr) => Some(addr.to_string()),
            Err(e) => {
                tracing::warn!(error = %e, "failed to generate LDK funding address");
                None
            }
        }
    }

    async fn send_onchain(
        &self,
        address: &str,
        amount_sats: u64,
        fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<String, LightningError> {
        use std::str::FromStr;
        let addr = ldk_node::bitcoin::Address::from_str(address)
            .map_err(|e| LightningError::PaymentNotDispatched(format!("invalid address: {e}")))?
            .assume_checked();
        // Track L0a (2026-04-30): the previous `r as u64` cast silently
        // floored fractional rates (`0.5 → 0`), producing transactions LDK
        // accepted but the network would not propagate. The shared validator
        // rejects NaN/Inf, enforces a 1.0–10_000.0 sat/vB band, and ceil-rounds.
        let fee_rate = fee_rate_sat_per_vb
            .map(|r| {
                let rate_u64 = validate_fee_rate_sat_per_vb(r)
                    .map_err(|e| LightningError::PaymentNotDispatched(e.to_string()))?;
                ldk_node::bitcoin::FeeRate::from_sat_per_vb(rate_u64).ok_or_else(|| {
                    LightningError::PaymentNotDispatched(format!(
                        "fee_rate_sat_per_vb {rate_u64} overflows FeeRate"
                    ))
                })
            })
            .transpose()?;
        let node = self.node.clone();
        let chain = self.chain_visibility();
        self.onchain_operations
            .run(async move {
                let sender = node.clone();
                let txid = tokio::task::spawn_blocking(move || {
                    sender
                        .onchain_payment()
                        .send_to_address(&addr, amount_sats, fee_rate)
                })
                .await
                .map_err(|e| LightningError::Backend(format!("send_onchain worker failed: {e}")))?
                .map_err(|e| LightningError::Backend(format!("send_onchain failed: {e}")))?;
                // Vendored Wallet records and persists this spend before returning.
                // Chain acceptance is separate evidence, checked against the selected source.
                let txid_string = txid.to_string();
                crate::onchain::verify_broadcast(&txid_string, |id| chain.tx_visible(id)).await?;
                node.transaction_broadcast_verified(txid).map_err(|e| {
                    LightningError::Backend(format!(
                        "transaction {txid} accepted but wallet reservation update failed: {e}"
                    ))
                })?;
                tracing::info!(%txid, amount_sats, "on-chain send verified");
                Ok(txid_string)
            })
            .await
    }

    async fn open_channel(
        &self,
        peer_pubkey: &str,
        peer_addr: &str,
        amount_sats: u64,
        announce: bool,
        fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<String, LightningError> {
        Ok(self
            .open_channel_with_status(
                peer_pubkey,
                peer_addr,
                amount_sats,
                announce,
                fee_rate_sat_per_vb,
            )
            .await?
            .channel_id)
    }

    async fn open_channel_with_status(
        &self,
        peer_pubkey: &str,
        peer_addr: &str,
        amount_sats: u64,
        announce: bool,
        fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<konsensus_core::traits::lightning::ChannelOpenResult, LightningError> {
        let node = self.node.clone();
        let chain = self.chain_visibility();
        let peer_pubkey = peer_pubkey.to_owned();
        let peer_addr = peer_addr.to_owned();
        self.onchain_operations.run(async move {
            let opener = node.clone();
            let channel_id = tokio::task::spawn_blocking(move || open_ldk_channel(
                opener.as_ref(), &peer_pubkey, &peer_addr, amount_sats, announce, fee_rate_sat_per_vb,
            )).await.map_err(|e| LightningError::Backend(format!("open_channel worker failed: {e}")))??;
            let pending_id = channel_id.clone();
            crate::onchain::finish_channel_open(channel_id, || {
                let channel = node.list_channels().into_iter()
                    .find(|ch| ch.user_channel_id.to_string() == pending_id)
                    .ok_or_else(|| LightningError::Backend(format!(
                        "channel {pending_id} disappeared before funding was verified; inspect channel events before retrying"
                    )))?;
                Ok(channel.funding_txo.map(|outpoint| outpoint.txid.to_string()))
            }, |id| {
                let chain = &chain;
                let node = &node;
                async move {
                let visible = chain.tx_visible(id.clone()).await?;
                if visible {
                    let txid = id.parse().map_err(|e| format!("invalid funding txid: {e}"))?;
                    if let Err(error) = node.transaction_broadcast_verified(txid) {
                        tracing::warn!(%txid, %error, "funding visible but reservation persistence failed");
                    }
                }
                Ok(visible)
                }
            }).await
        }).await
    }

    async fn funding_fee_quote(
        &self,
        options: konsensus_core::traits::lightning::FundingOptions,
    ) -> Result<konsensus_core::traits::lightning::FundingFeeEstimate, LightningError> {
        Ok(funding_estimate(&select_funding_policy(
            &self.node, options,
        )?))
    }

    async fn open_channel_with_funding(
        &self,
        peer_pubkey: &str,
        peer_addr: &str,
        amount_sats: u64,
        announce: bool,
        options: konsensus_core::traits::lightning::FundingOptions,
    ) -> Result<konsensus_core::traits::lightning::ChannelOpenResult, LightningError> {
        let node = self.node.clone();
        let chain = self.chain_visibility();
        let peer_pubkey = peer_pubkey.to_owned();
        let peer_addr = peer_addr.to_owned();
        self.onchain_operations.run(async move {
            validate_channel_announcement(node.as_ref(), announce)?;
            let policy = select_funding_policy(&node, options)?;
            let estimate = funding_estimate(&policy);
            let opener = node.clone();
            let channel_id = tokio::task::spawn_blocking(move || open_ldk_channel_with_policy(
                opener.as_ref(), &peer_pubkey, &peer_addr, amount_sats, announce, Some(policy),
            )).await.map_err(|e| LightningError::Backend(format!("open_channel worker failed: {e}")))??;
            let pending_id = channel_id.clone();
            let mut result = crate::onchain::finish_channel_open(channel_id, || {
                let id = pending_id.parse::<u128>().map(ldk_node::UserChannelId)
                    .map_err(|e| LightningError::Backend(format!("invalid channel id: {e}")))?;
                if let Some(reason) = node.channel_funding_failure(id)
                    .map_err(|e| LightningError::Backend(format!("funding outcome unavailable: {e}")))? {
                    return Err(LightningError::PaymentNotDispatched(format!("channel {pending_id}: {reason}; funding not dispatched")));
                }
                let channel = node.list_channels().into_iter()
                    .find(|ch| ch.user_channel_id.to_string() == pending_id)
                    .ok_or_else(|| LightningError::Backend(format!(
                        "channel {pending_id} disappeared before funding was verified; inspect channel events before retrying"
                    )))?;
                Ok(channel.funding_txo.map(|outpoint| outpoint.txid.to_string()))
            }, |id| {
                let chain = &chain;
                let node = &node;
                async move {
                let visible = chain.tx_visible(id.clone()).await?;
                if visible {
                    let txid = id.parse().map_err(|e| format!("invalid funding txid: {e}"))?;
                    if let Err(error) = node.transaction_broadcast_verified(txid) {
                        tracing::warn!(%txid, %error, "funding visible but reservation persistence failed");
                    }
                }
                Ok(visible)
                }
            }).await?;
            result.funding_fee = Some(estimate);
            Ok(result)
        }).await
    }

    fn local_spend_diagnostics(&self) -> konsensus_core::traits::lightning::LocalSpendDiagnostics {
        use konsensus_core::traits::lightning::{LocalSpendDiagnostics, LocalSpendReservation};
        LocalSpendDiagnostics {
            unreadable_rows: self.node.local_spend_unreadable_rows(),
            reservations: self
                .node
                .local_spend_reservations()
                .into_iter()
                .map(|r| LocalSpendReservation {
                    txid: r.txid.to_string(),
                    created_at: r.created_at,
                    last_seen_at: r.last_seen_at,
                })
                .collect(),
        }
    }

    async fn release_local_spend(&self, txid: &str) -> Result<(), LightningError> {
        let txid = txid
            .parse()
            .map_err(|_| LightningError::Backend("invalid reservation txid".into()))?;
        let node = self.node.clone();
        let chain = self.chain_visibility();
        self.onchain_operations
            .run(async move {
                crate::onchain::release_local_spend_with(node, txid, |id| chain.tx_visible(id))
                    .await
            })
            .await
    }

    async fn close_channel(
        &self,
        channel_id: &str,
        force: bool,
    ) -> Result<Option<String>, LightningError> {
        let user_channel_id_num = if let Some(inner) = channel_id
            .strip_prefix("UserChannelId(")
            .and_then(|s| s.strip_suffix(')'))
        {
            inner
        } else {
            channel_id
        }
        .parse::<u128>()
        .map_err(|e| LightningError::Backend(format!("invalid channel_id: {e}")))?;
        let user_channel_id = ldk_node::UserChannelId(user_channel_id_num);

        let node = self.node.clone();
        let channel_id = channel_id.to_owned();
        self.onchain_operations
            .run(async move {
                let closer = node.clone();
                tokio::task::spawn_blocking(move || {
                    let counterparty_pubkey = closer
                        .list_channels()
                        .into_iter()
                        .find(|ch| ch.user_channel_id == user_channel_id)
                        .map(|ch| ch.counterparty_node_id)
                        .ok_or_else(|| {
                            LightningError::Backend(format!(
                                "channel not found for user_channel_id {user_channel_id}"
                            ))
                        })?;
                    if force {
                        closer.force_close_channel(&user_channel_id, counterparty_pubkey, None)
                    } else {
                        closer.close_channel(&user_channel_id, counterparty_pubkey)
                    }
                    .map_err(|e| LightningError::Backend(format!("close_channel failed: {e}")))
                })
                .await
                .map_err(|e| {
                    LightningError::Backend(format!("close_channel worker failed: {e}"))
                })??;
                crate::onchain::finish_channel_close(&channel_id, || {
                    node.list_channels()
                        .iter()
                        .any(|ch| ch.user_channel_id == user_channel_id)
                })
                .await
            })
            .await
    }
}

// --- Helper functions ---

fn validate_startup_url(field: &str, value: &str) -> Result<(), LightningError> {
    let valid = reqwest::Url::parse(value)
        .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some());
    if !valid {
        // Do not include potentially authenticated URLs in user-facing errors.
        return Err(LightningError::InvalidStartupConfig(format!(
            "{field} must be an absolute HTTP(S) URL with a host"
        )));
    }
    Ok(())
}

fn startup_build_error(error: ldk_node::BuildError) -> LightningError {
    use ldk_node::BuildError;
    match error {
        BuildError::InvalidSeedBytes
        | BuildError::InvalidSeedFile
        | BuildError::InvalidListeningAddresses
        | BuildError::InvalidAnnouncementAddresses
        | BuildError::InvalidNodeAlias
        | BuildError::NetworkMismatch
        | BuildError::AsyncPaymentsConfigMismatch => {
            LightningError::InvalidStartupConfig(error.to_string())
        }
        _ => LightningError::Backend(format!("failed to build LDK node: {error}")),
    }
}

/// Retry ONLY Esplora's startup fee barrier. In pinned LDK 0.7 these
/// errors return before any background task is spawned, and Esplora's
/// ChainSource::start is a no-op. Never extend this to arbitrary start errors
/// or Electrum without re-auditing that ordering.
///
/// Five fee requests (LDK bounds each at 5s) and 2/4/8/8s backoff with ±20%
/// jitter fit in ~60s including the two 4s preflight probes. A deadline check
/// reserves a full fee-request window before each attempt. Local disk I/O is
/// outside the network timeouts. No detached retry/spawn_blocking job is used:
/// dropping this future during backoff drops the unstarted node. Cancellation
/// during synchronous Node::start is observed at the next yield (at most the
/// in-flight fee timeout on a failing chain service).
async fn start_esplora_with_retry(
    mut builder: LdkBuilder,
    config: &LdkConfig,
    mut endpoint: String,
    started: Instant,
    auth_transport: Option<Arc<konsensus_chain::bearer::BearerFailover>>,
) -> Result<(LdkNode, String, ldk_node::NodeStatus), LightningError> {
    let sync_config = config.esplora_sync_intervals.to_sync_config()?;
    const BUDGET: Duration = Duration::from_secs(60);
    const FEE_WINDOW: Duration = Duration::from_secs(5);
    const DELAYS: [u64; 4] = [2, 4, 8, 8];
    let mut node = None;
    let mut attempts = 0;
    let mut cause = "startup connectivity budget exhausted".to_string();
    loop {
        if started.elapsed() + FEE_WINDOW > BUDGET {
            break;
        }
        if node.is_none() {
            if let Some(transport) = auth_transport
                .as_ref()
                .filter(|_| endpoint == config.esplora_url)
            {
                builder.set_chain_source_esplora_with_transport(
                    endpoint.clone(),
                    Some(sync_config),
                    transport.clone(),
                );
            } else {
                builder.set_chain_source_esplora(endpoint.clone(), Some(sync_config));
            }
            node = Some(builder.build().map_err(startup_build_error)?);
        }
        if started.elapsed() + FEE_WINDOW > BUDGET {
            break;
        }
        attempts += 1;
        let baseline = node.as_ref().expect("node was built").status();
        let result = node.as_ref().expect("node was built").start();
        // Deliver pending cancellation even if the synchronous call succeeded.
        // Dropping a successfully started Node invokes stop before returning.
        tokio::task::yield_now().await;
        match result {
            Ok(()) => return Ok((node.expect("node was built"), endpoint, baseline)),
            Err(
                error @ (ldk_node::NodeError::FeerateEstimationUpdateFailed
                | ldk_node::NodeError::FeerateEstimationUpdateTimeout
                | ldk_node::NodeError::ChainRateLimited),
            ) => {
                cause = error.to_string();
                warn!(
                    code = "BOOT_CHAIN_SOURCE_RETRY",
                    attempt = attempts,
                    network = %config.network,
                    service = %startup_service(&endpoint),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    error = %error,
                    "Bitcoin chain service unavailable during startup; node remains not ready"
                );
            }
            Err(ldk_node::NodeError::InvalidSocketAddress) => {
                return Err(LightningError::InvalidStartupConfig(
                    "listening_address could not be resolved or bound; use a local address and an available port".into(),
                ));
            }
            Err(error) => {
                // Later start phases may already own tasks. Never retry them.
                return Err(LightningError::Backend(format!(
                    "failed to start LDK node: {error}"
                )));
            }
        }
        let Some(delay_secs) = DELAYS.get(attempts - 1) else {
            break;
        };
        let jitter = rand::thread_rng().gen_range(0.8..=1.2);
        let delay = Duration::from_secs_f64(*delay_secs as f64 * jitter);
        if started.elapsed() + delay + FEE_WINDOW > BUDGET {
            break;
        }
        tokio::time::sleep(delay).await;
        if let Some(fallback) = config
            .esplora_url_fallback
            .as_ref()
            .filter(|url| auth_transport.is_none() && **url != endpoint)
        {
            // Only switch away from the primary. Never re-probe and bounce back.
            // Drop the old instance/store before rebuilding with the SAME
            // builder entropy and directory; no reinitialization or new identity.
            drop(node.take());
            endpoint = fallback.clone();
        }
    }
    Err(LightningError::ChainSourceUnavailable {
        network: config.network.clone(),
        service: startup_service(&endpoint),
        attempts,
        elapsed_ms: started.elapsed().as_millis() as u64,
        cause,
    })
}

fn startup_service(endpoint: &str) -> String {
    reqwest::Url::parse(endpoint)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "configured chain service".into())
}

/// blake3 KDF context for LDK Lightning entropy derivation.
///
/// This context string provides domain separation from the BitSov identity
/// keys (which use contexts like "konsensus-v2 ed25519 signing key", etc.).
const LDK_KDF_CONTEXT: &str = "konsensus-v2 ldk-lightning";

/// Derive a 64-byte LDK entropy seed from a BIP-39 seed using blake3 KDF.
///
/// Uses blake3's XOF (extendable output function) in derive-key mode to produce
/// exactly 64 bytes — the size required by `ldk-node`'s `set_entropy_seed_bytes`.
fn derive_ldk_entropy(bip39_seed: &[u8]) -> [u8; 64] {
    let mut output = [0u8; 64];
    let mut reader = blake3::Hasher::new_derive_key(LDK_KDF_CONTEXT)
        .update(bip39_seed)
        .finalize_xof();
    reader.fill(&mut output);
    output
}

/// Parse a network string into a bitcoin::Network.
fn parse_network(network: &str) -> Result<bitcoin::Network, LightningError> {
    match network.to_lowercase().as_str() {
        "bitcoin" | "mainnet" => Ok(bitcoin::Network::Bitcoin),
        "testnet" | "testnet3" => Ok(bitcoin::Network::Testnet),
        "signet" => Ok(bitcoin::Network::Signet),
        "regtest" => Ok(bitcoin::Network::Regtest),
        other => Err(LightningError::InvalidStartupConfig(format!(
            "unknown network: {other}"
        ))),
    }
}

/// Extract payment hash from an LDK PaymentKind.
fn payment_hash_from_kind(
    kind: &LdkPaymentKind,
) -> Option<ldk_node::lightning_types::payment::PaymentHash> {
    match kind {
        LdkPaymentKind::Bolt11 { hash, .. } => Some(*hash),
        LdkPaymentKind::Bolt11Jit { hash, .. } => Some(*hash),
        LdkPaymentKind::Bolt12Offer { hash, .. } => *hash,
        LdkPaymentKind::Bolt12Refund { hash, .. } => *hash,
        LdkPaymentKind::Spontaneous { hash, .. } => Some(*hash),
        _ => None,
    }
}

/// Extract preimage from an LDK PaymentKind.
fn preimage_from_kind(
    kind: &LdkPaymentKind,
) -> Option<ldk_node::lightning_types::payment::PaymentPreimage> {
    match kind {
        LdkPaymentKind::Bolt11 { preimage, .. } => *preimage,
        LdkPaymentKind::Bolt11Jit { preimage, .. } => *preimage,
        LdkPaymentKind::Bolt12Offer { preimage, .. } => *preimage,
        LdkPaymentKind::Bolt12Refund { preimage, .. } => *preimage,
        LdkPaymentKind::Spontaneous { preimage, .. } => *preimage,
        _ => None,
    }
}

/// Wallet freshness from LDK's two last-successful-sync timestamps (Unix
/// seconds). `get_balance_msat` sums the Lightning and on-chain balances, so
/// the figures are only as current as the older sync; until both wallets have
/// synced once, no time is known.
fn wallet_sync_from_timestamps(lightning: Option<u64>, onchain: Option<u64>) -> WalletSync {
    match (lightning, onchain) {
        (Some(ln), Some(oc)) => WalletSync::SyncedAt(ln.min(oc)),
        _ => WalletSync::NeverSynced,
    }
}

/// Convert LDK PaymentStatus to BitSov PaymentStatus.
fn convert_status(status: LdkPaymentStatus) -> PaymentStatus {
    match status {
        LdkPaymentStatus::Pending => PaymentStatus::Pending,
        LdkPaymentStatus::Succeeded => PaymentStatus::Settled,
        LdkPaymentStatus::Failed => PaymentStatus::Failed,
    }
}

/// Convert LDK PaymentDirection to BitSov PaymentDirection.
fn convert_direction(direction: ldk_node::payment::PaymentDirection) -> PaymentDirection {
    match direction {
        ldk_node::payment::PaymentDirection::Inbound => PaymentDirection::Incoming,
        ldk_node::payment::PaymentDirection::Outbound => PaymentDirection::Outgoing,
    }
}

/// Convert an LDK PaymentDetails to a BitSov PaymentDetails.
fn convert_payment_details(details: &ldk_node::payment::PaymentDetails) -> PaymentDetails {
    let payment_hash = payment_hash_from_kind(&details.kind)
        .map(|h| hex::encode(h.0))
        .unwrap_or_default();

    let preimage = if details.status == LdkPaymentStatus::Succeeded
        && !matches!(details.kind, LdkPaymentKind::Bolt11Jit { .. })
    {
        preimage_from_kind(&details.kind).map(|p| hex::encode(p.0))
    } else {
        None
    };

    PaymentDetails {
        payment_hash,
        preimage,
        amount_msat: details.amount_msat.unwrap_or(0),
        status: convert_status(details.status),
        direction: convert_direction(details.direction),
        timestamp: details.latest_update_timestamp,
        memo: None,
        fee_msat: details.fee_paid_msat,
    }
}

/// L4b (2026-05-11): Probe an Esplora endpoint by GETting `/fee-estimates`.
///
/// LDK fetches fee estimates from the configured Esplora endpoint as part
/// of its startup chain-sync. If that call times out or errors, LDK
/// crash-loops (see the 2026-04-23 alpha incident). We mirror the same
/// call here from `LdkProvider::new` so we can detect an unreachable
/// primary BEFORE handing the URL to LDK, and fall over to the optional
/// secondary endpoint.
///
/// Returns `Ok(())` only when the endpoint answers with **fee data LDK can
/// actually use**: HTTP 2xx *and* a JSON object of confirmation-target →
/// fee-rate (sat/vB) with at least one finite, positive entry.
///
/// genome #66: the original probe accepted any 2xx without reading the body.
/// An endpoint can answer 200/203 with a payload LDK cannot consume — a
/// deprecation notice, a rate-limit document, an HTML error page, or an empty
/// object — the probe passed, LDK was handed that endpoint, and LDK's own
/// fetch then failed with `Failed to update fee rate estimates`, refusing to
/// start. The fallback was never consulted, because as far as the probe was
/// concerned the primary was healthy. Validating the payload is what makes the
/// fallback reachable at all.
///
/// `Err(_)` on transport error, timeout, non-2xx, unparsable body, or a body
/// carrying no usable fee rate. Caller treats `Err` as "endpoint unusable" and
/// may try the fallback. The timeout is intentionally tight (4 s) so node
/// startup doesn't stall on a single slow endpoint.
///
/// LIMIT, deliberately not addressed here: this probe is a SEPARATE request from
/// the fetch LDK makes moments later. It selects an endpoint at startup; it is
/// not continuous failover, and an endpoint that degrades between the probe and
/// LDK's fetch will still fail startup. Runtime failover is a distinct change,
/// out of scope for #66.
pub async fn probe_esplora_fee_estimates(esplora_url: &str) -> Result<(), String> {
    let trimmed = esplora_url.trim_end_matches('/');
    let url = format!("{trimmed}/fee-estimates");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(4))
        .build()
        .map_err(|e| format!("reqwest client: {e}"))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("non-2xx status {status} from {url}"));
    }
    // Read and validate the payload — a 2xx alone proves nothing (#66).
    let body = resp
        .text()
        .await
        .map_err(|e| format!("reading body of {url}: {e}"))?;
    // Deserialize into LDK's OWN type. esplora-client 0.12.3 (pinned via ldk-node
    // 0.7) parses the whole response as `HashMap<u16, f64>` (`src/async.rs:526`),
    // so a single key LDK cannot represent fails the WHOLE fetch. Accepting "at
    // least one usable entry" against a looser `HashMap<String, f64>` would let
    // `{"1":10.0,"invalid":1.0}` or `{"1":10.0,"65536":1.0}` pass here and still
    // kill LDK startup — the exact defect #66 is about, one layer in. Mirror the
    // consumer's contract: if LDK cannot parse it, neither do we.
    let estimates: std::collections::HashMap<u16, f64> =
        serde_json::from_str(&body).map_err(|e| {
            let preview: String = body.chars().take(120).collect();
            format!(
                "{url} returned {status} but LDK cannot deserialize the body as an Esplora fee-estimate map \
                 (confirmation target -> sat/vB): {e}; first 120 bytes: {preview:?}"
            )
        })?;
    let usable = estimates
        .values()
        .filter(|rate| rate.is_finite() && **rate > 0.0)
        .count();
    if usable == 0 {
        return Err(format!(
            "{url} returned {status} with a parsable but unusable fee-estimate map \
             ({} entries, none of them a positive finite rate) — LDK would fail its \
             startup fee fetch against this endpoint",
            estimates.len()
        ));
    }
    Ok(())
}

/// L4b (2026-05-11): Select between primary and fallback Esplora endpoints.
///
/// Probes `primary` via `probe_esplora_fee_estimates`. On success, returns it.
/// On failure:
///   - logs INFO `"esplora primary unreachable, switching to fallback"` with
///     the primary error,
///   - if a `fallback` is configured, probes it; on success returns the
///     fallback URL; on failure logs WARN and still returns the fallback
///     (best-effort — LDK will surface its own startup error if the
///     fallback is also broken, but at least the operator's chosen
///     fallback gets exercised),
///   - if no `fallback` is configured, logs WARN and returns the primary
///     anyway (LDK will then crash-loop with its real error, identical to
///     pre-L4b behavior).
///
/// This is always best-effort — a transient probe failure shouldn't pin
/// the node to a degraded endpoint forever. If the primary recovers, the
/// next restart will pick it up again.
pub async fn select_esplora_endpoint(primary: &str, fallback: Option<&str>) -> String {
    match probe_esplora_fee_estimates(primary).await {
        Ok(()) => primary.to_string(),
        Err(primary_err) => match fallback {
            Some(fb) => {
                info!(
                    primary = %primary,
                    fallback = %fb,
                    error = %primary_err,
                    "esplora primary unreachable, switching to fallback"
                );
                if let Err(fallback_err) = probe_esplora_fee_estimates(fb).await {
                    warn!(
                        primary = %primary,
                        fallback = %fb,
                        primary_error = %primary_err,
                        fallback_error = %fallback_err,
                        // LightningConfig is internally tagged: the table is
                        // [lightning] with backend = "ldk", NOT [lightning.ldk]
                        // — and the config denies unknown fields, so following
                        // the old text would fail to parse. LDK takes the full
                        // API URL including /api; [chain] api_url is a BASE URL
                        // and appends /api itself.
                        remedy = "in konsensus.toml set [lightning] (backend = \"ldk\") \
                                  esplora_url / esplora_url_fallback — full API URLs \
                                  including /api — and [chain] api_url / \
                                  esplora_url_fallback — base URLs, /api is appended \
                                  — to Esplora endpoints reachable from this host, \
                                  then restart",
                        "both esplora endpoints returned unusable fee data — the node will \
                         refuse to start (genome #66). Neither endpoint answered with a \
                         usable confirmation-target -> sat/vB map."
                    );
                }
                fb.to_string()
            }
            None => {
                warn!(
                    primary = %primary,
                    error = %primary_err,
                    "esplora primary unreachable and no fallback configured — LDK startup likely to fail"
                );
                primary.to_string()
            }
        },
    }
}

/// Query transaction presence. Only a configured endpoint's explicit HTTP 404
/// proves absence; missing configuration and failed lookups are inconclusive.
pub async fn esplora_tx_visible(esplora_url: &str, txid: &str) -> Result<bool, String> {
    if esplora_url.trim().trim_end_matches('/').is_empty() {
        return Err("no chain source configured".into());
    }
    let trimmed = esplora_url.trim_end_matches('/');
    let url = format!("{trimmed}/tx/{txid}");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|e| format!("reqwest client: {e}"))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    match resp.status().as_u16() {
        200 => Ok(true),
        404 => Ok(false),
        other => Err(format!("unexpected status {other} from {url}")),
    }
}

#[cfg(test)]
#[path = "tests/ldk.rs"]
mod tests;

/// Runs the pinned lightning-liquidity LSPS2 client through LDK Node's event
/// loop/peer manager, sharing exactly one node, seed and channel monitor store.
struct LdkJitBackend(Arc<LdkNode>);

#[async_trait]
impl JitBackend for LdkJitBackend {
    async fn prepare(
        &self,
        gross_msat: u64,
        max_fee_msat: u64,
        expiry_secs: u32,
    ) -> Result<(Invoice, u64), LightningError> {
        let node = Arc::clone(&self.0);
        tokio::task::spawn_blocking(move || {
            let description = "BitSov wallet funding";
            let desc =
                LdkInvoiceDescription::Direct(LdkDescription::new(description.into()).map_err(
                    |_| LightningError::InvoiceCreation("invalid funding description".into()),
                )?);
            // Internally: lightning_liquidity::lsps2 client get_info -> fee
            // selection/absolute limit -> buy -> persisted Bolt11Jit record.
            let inv = node
                .bolt11_payment()
                .receive_via_jit_channel(gross_msat, &desc, expiry_secs, Some(max_fee_msat))
                .map_err(|e| LightningError::InvoiceCreation(e.to_string()))?;
            let hash_bytes: [u8; 32] = *AsRef::<[u8; 32]>::as_ref(inv.payment_hash());
            let stored = node
                .payment(&ldk_node::lightning::ln::channelmanager::PaymentId(
                    hash_bytes,
                ))
                .ok_or_else(|| LightningError::Backend("JIT purpose was not persisted".into()))?;
            let fee = match stored.kind {
                LdkPaymentKind::Bolt11Jit { lsp_fee_limits, .. } => lsp_fee_limits
                    .max_total_opening_fee_msat
                    .ok_or_else(|| LightningError::Backend("missing fixed JIT fee".into()))?,
                _ => {
                    return Err(LightningError::Backend(
                        "missing JIT payment purpose".into(),
                    ))
                }
            };
            Ok((
                Invoice {
                    bolt11: inv.to_string(),
                    payment_hash: hex::encode(hash_bytes),
                    amount_msat: gross_msat,
                    description: description.into(),
                    expiry_secs,
                    created_at: inv.duration_since_epoch().as_secs(),
                },
                fee,
            ))
        })
        .await
        .map_err(|_| LightningError::Backend("JIT worker failed".into()))?
    }
}

fn jit_receipt(
    p: &ldk_node::payment::PaymentDetails,
) -> Result<Option<LiquidityReceipt>, LightningError> {
    if let LdkPaymentKind::Bolt11Jit {
        counterparty_skimmed_fee_msat,
        ..
    } = p.kind
    {
        if p.status == LdkPaymentStatus::Succeeded {
            // The vendored handler records each eligible JIT attempt's skim,
            // including zero. Older zero-fee receipts may still contain None.
            let fee = counterparty_skimmed_fee_msat.unwrap_or(0);
            let net = p
                .amount_msat
                .ok_or_else(|| LightningError::Backend("missing settled JIT amount".into()))?;
            let gross = net
                .checked_add(fee)
                .ok_or_else(|| LightningError::Backend("JIT amount overflow".into()))?;
            return Ok(Some(LiquidityReceipt {
                net_received_msat: net,
                lsp_fee_msat: fee,
                gross_msat: gross,
            }));
        }
    }
    Ok(None)
}

/// Always provide an explicit LDK override: its default includes a 50,000 msat floor.
fn routing_fee_parameters(
    max_fee_msat: u64,
) -> ldk_node::lightning::routing::router::RouteParametersConfig {
    ldk_node::lightning::routing::router::RouteParametersConfig {
        max_total_routing_fee_msat: Some(max_fee_msat),
        ..Default::default()
    }
}

// Small dispatch seams let tests capture the exact arguments delivered to LDK.
fn dispatch_invoice_with_fee_limit<T>(
    invoice: &ldk_node::lightning_invoice::Bolt11Invoice,
    max_fee_msat: u64,
    send: impl FnOnce(
        &ldk_node::lightning_invoice::Bolt11Invoice,
        Option<ldk_node::lightning::routing::router::RouteParametersConfig>,
    ) -> T,
) -> T {
    send(invoice, Some(routing_fee_parameters(max_fee_msat)))
}
fn dispatch_keysend_with_fee_limit<T>(
    amount: u64,
    dest: bitcoin::secp256k1::PublicKey,
    max_fee_msat: u64,
    send: impl FnOnce(
        u64,
        bitcoin::secp256k1::PublicKey,
        Option<ldk_node::lightning::routing::router::RouteParametersConfig>,
    ) -> T,
) -> T {
    send(amount, dest, Some(routing_fee_parameters(max_fee_msat)))
}

/// Pinned ldk-node bolt11/spontaneous send paths return PaymentSendingFailed
/// only for RetryableSendFailure BEFORE any HTLC dispatch (including RouteNotFound).
/// PersistenceFailed can occur after dispatch; DuplicatePayment can refer to an
/// earlier live attempt. Neither proves that the liability is absent.
fn classify_dispatch_error(
    error: ldk_node::NodeError,
    payment_capable: &AtomicBool,
) -> LightningError {
    use ldk_node::NodeError::*;
    match error {
        PaymentSendingFailed | InvalidInvoice | InvalidAmount | InvalidCustomTlvs | NotRunning => {
            LightningError::PaymentNotDispatched(error.to_string())
        }
        DuplicatePayment => LightningError::PaymentFailed(error.to_string()),
        _ => {
            payment_capable.store(false, Ordering::Relaxed);
            LightningError::PaymentFailed(error.to_string())
        }
    }
}

// Keep the LDK API boundary injectable so tests observe calls without connecting
// peers or funding channels. The production implementation uses LDK's methods.
#[cfg_attr(test, mockall::automock)]
trait ChannelOpener {
    fn has_node_alias(&self) -> bool;
    fn has_listening_addresses(&self) -> bool;
    fn open_with_funding_policy(
        &self,
        peer: bitcoin::secp256k1::PublicKey,
        addr: ldk_node::lightning::ln::msgs::SocketAddress,
        amount_sats: u64,
        announce: bool,
        policy: ldk_node::funding::FundingPolicy,
    ) -> Result<ldk_node::UserChannelId, ldk_node::NodeError>;

    fn open_channel(
        &self,
        peer: bitcoin::secp256k1::PublicKey,
        addr: ldk_node::lightning::ln::msgs::SocketAddress,
        amount_sats: u64,
        push_msat: Option<u64>,
        config: Option<ldk_node::config::ChannelConfig>,
    ) -> Result<ldk_node::UserChannelId, ldk_node::NodeError>;
    fn open_announced_channel(
        &self,
        peer: bitcoin::secp256k1::PublicKey,
        addr: ldk_node::lightning::ln::msgs::SocketAddress,
        amount_sats: u64,
        push_msat: Option<u64>,
        config: Option<ldk_node::config::ChannelConfig>,
    ) -> Result<ldk_node::UserChannelId, ldk_node::NodeError>;
}

impl ChannelOpener for LdkNode {
    fn has_node_alias(&self) -> bool {
        self.node_alias().is_some()
    }

    fn has_listening_addresses(&self) -> bool {
        self.listening_addresses()
            .is_some_and(|addrs| !addrs.is_empty())
    }

    fn open_with_funding_policy(
        &self,
        peer: bitcoin::secp256k1::PublicKey,
        addr: ldk_node::lightning::ln::msgs::SocketAddress,
        amount_sats: u64,
        announce: bool,
        policy: ldk_node::funding::FundingPolicy,
    ) -> Result<ldk_node::UserChannelId, ldk_node::NodeError> {
        self.open_channel_with_funding_policy(peer, addr, amount_sats, announce, policy)
    }

    fn open_channel(
        &self,
        peer: bitcoin::secp256k1::PublicKey,
        addr: ldk_node::lightning::ln::msgs::SocketAddress,
        amount_sats: u64,
        push_msat: Option<u64>,
        config: Option<ldk_node::config::ChannelConfig>,
    ) -> Result<ldk_node::UserChannelId, ldk_node::NodeError> {
        LdkNode::open_channel(self, peer, addr, amount_sats, push_msat, config)
    }
    fn open_announced_channel(
        &self,
        peer: bitcoin::secp256k1::PublicKey,
        addr: ldk_node::lightning::ln::msgs::SocketAddress,
        amount_sats: u64,
        push_msat: Option<u64>,
        config: Option<ldk_node::config::ChannelConfig>,
    ) -> Result<ldk_node::UserChannelId, ldk_node::NodeError> {
        LdkNode::open_announced_channel(self, peer, addr, amount_sats, push_msat, config)
    }
}

fn open_ldk_channel(
    node: &impl ChannelOpener,
    peer_pubkey: &str,
    peer_addr: &str,
    amount_sats: u64,
    announce: bool,
    fee_rate_sat_per_vb: Option<f32>,
) -> Result<String, LightningError> {
    refuse_exact_funding_rate(fee_rate_sat_per_vb)?;
    open_ldk_channel_with_policy(node, peer_pubkey, peer_addr, amount_sats, announce, None)
}

fn open_ldk_channel_with_policy(
    node: &impl ChannelOpener,
    peer_pubkey: &str,
    peer_addr: &str,
    amount_sats: u64,
    announce: bool,
    policy: Option<ldk_node::funding::FundingPolicy>,
) -> Result<String, LightningError> {
    validate_channel_announcement(node, announce)?;
    use std::str::FromStr;
    let node_pubkey = ldk_node::bitcoin::secp256k1::PublicKey::from_str(peer_pubkey)
        .map_err(|e| LightningError::PaymentNotDispatched(format!("invalid pubkey: {e}")))?;

    // Parse address into LDK SocketAddress
    let socket_addr: std::net::SocketAddr = peer_addr
        .parse()
        .map_err(|e| LightningError::PaymentNotDispatched(format!("invalid address: {e}")))?;
    let ldk_addr = match socket_addr {
        std::net::SocketAddr::V4(a) => ldk_node::lightning::ln::msgs::SocketAddress::TcpIpV4 {
            addr: a.ip().octets(),
            port: a.port(),
        },
        std::net::SocketAddr::V6(a) => ldk_node::lightning::ln::msgs::SocketAddress::TcpIpV6 {
            addr: a.ip().octets(),
            port: a.port(),
        },
    };

    // Open channel (connect + open in one call)
    let user_channel_id = if let Some(policy) = policy {
        node.open_with_funding_policy(node_pubkey, ldk_addr, amount_sats, announce, policy)
    } else if announce {
        node.open_announced_channel(node_pubkey, ldk_addr, amount_sats, None, None)
    } else {
        node.open_channel(node_pubkey, ldk_addr, amount_sats, None, None)
    }
    .map_err(|e| match e {
        // In vendored ldk-node 0.7 this means announcement preflight failed or
        // lightning 0.2.2's create_channel returned Err, before queuing an open
        // message. Other errors (e.g. peer persistence AFTER creation) may be
        // post-dispatch and must retain the conservative Backend classification.
        ldk_node::NodeError::ChannelCreationFailed => {
            LightningError::PaymentNotDispatched(format!("open_channel failed: {e}"))
        }
        _ => LightningError::Backend(format!("open_channel failed: {e}")),
    })?;

    let channel_id = format!("{}", user_channel_id);
    tracing::info!(channel_id = %channel_id, amount_sats, peer = %peer_pubkey, "Lightning channel opening initiated");
    Ok(channel_id)
}

fn select_funding_policy(
    node: &LdkNode,
    options: konsensus_core::traits::lightning::FundingOptions,
) -> Result<ldk_node::funding::FundingPolicy, LightningError> {
    node.funding_fee_quote(ldk_funding_priority(options.priority), options.max_funding_fee_sats).map_err(|error| LightningError::PaymentNotDispatched(format!(
        "funding estimate unavailable or invalid (fresh LDK estimate and valid fee cap required): {error}"
    )))
}

fn funding_estimate(
    policy: &ldk_node::funding::FundingPolicy,
) -> konsensus_core::traits::lightning::FundingFeeEstimate {
    use konsensus_core::traits::lightning::{FundingFeeEstimate, FundingPriority as Core};
    use ldk_node::funding::FundingPriority as Ldk;
    let priority = match policy.priority() {
        Ldk::Economy => Core::Economy,
        Ldk::Normal => Core::Normal,
        Ldk::Fast => Core::Fast,
    };
    let blocks = policy.priority().confirmation_target_blocks();
    FundingFeeEstimate {
        priority,
        confirmation_target_blocks: blocks,
        expected_confirmation_minutes: blocks * 10,
        estimated_fee_rate_sat_per_vb: policy.estimated_fee_rate_sat_per_kwu() as f64 / 250.0,
        max_funding_fee_sats: policy.max_fee_sats(),
    }
}

fn ldk_funding_priority(
    priority: konsensus_core::traits::lightning::FundingPriority,
) -> ldk_node::funding::FundingPriority {
    use konsensus_core::traits::lightning::FundingPriority as Core;
    use ldk_node::funding::FundingPriority as Ldk;
    match priority {
        Core::Economy => Ldk::Economy,
        Core::Normal => Ldk::Normal,
        Core::Fast => Ldk::Fast,
    }
}

fn validate_channel_announcement(
    node: &impl ChannelOpener,
    announce: bool,
) -> Result<(), LightningError> {
    // Preserve the existing announcement refusal before estimating or dispatching.
    if announce && (!node.has_node_alias() || !node.has_listening_addresses()) {
        return Err(LightningError::PaymentNotDispatched(
            "announce_unavailable: public channel announcement requires a node alias and nonempty listening addresses".into(),
        ));
    }
    Ok(())
}

fn refuse_exact_funding_rate(rate: Option<f32>) -> Result<(), LightningError> {
    // Only estimator-selected funding policies are supported. An exact caller
    // rate cannot promise final sat/vB after transaction rounding/dust change.
    if rate.is_some() {
        return Err(LightningError::PaymentNotDispatched(
            "LDK cannot enforce an exact caller-supplied funding fee rate; use funding_priority"
                .into(),
        ));
    }
    Ok(())
}

/// The hub service opens JIT channels to arbitrary clients, so it cannot run hub-only.
fn channel_peer_allowlist(
    peers: Option<&[String]>,
    hub_service: bool,
) -> Result<Option<Vec<ldk_node::bitcoin::secp256k1::PublicKey>>, LightningError> {
    use konsensus_core::traits::lightning::HUB_ONLY_WHILE_LOCKABLE;
    let Some(peers) = peers else { return Ok(None) };
    if hub_service {
        return Err(LightningError::InvalidStartupConfig(format!(
            "{HUB_ONLY_WHILE_LOCKABLE}: lsps2_service opens channels to any client; disable it to start with --remote-unlock"
        )));
    }
    peers
        .iter()
        .map(|peer| peer.parse())
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
        .map_err(|_| {
            LightningError::InvalidStartupConfig(format!(
                "{HUB_ONLY_WHILE_LOCKABLE}: invalid hub/LSP node id"
            ))
        })
}

/// Migration consent remains attached to this store even after completion.
/// Fail before building LDK: normal startup must not reopen channels or spend.
pub fn ensure_no_move_home(storage_dir: &std::path::Path) -> Result<(), LightningError> {
    if storage_dir
        .join(crate::move_home::JOURNAL_FILE)
        .try_exists()
        .map_err(|e| LightningError::InvalidStartupConfig(e.to_string()))?
    {
        return Err(LightningError::InvalidStartupConfig(
            "move-home migration journal exists; resume `konsensus move-home` with the original destination. Do not delete the journal or restore historical state.".into()));
    }
    Ok(())
}
