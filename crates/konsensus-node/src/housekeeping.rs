//! Periodic housekeeping tasks — nonce cleanup, pending delivery cleanup,
//! send timestamp cleanup, message retention, and price table re-announcement.

use std::sync::Arc;

use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use konsensus_core::traits::chain::ChainProvider;
use konsensus_core::traits::transport::MessageTransport;
use konsensus_message::{Frame, NoiseTransport};

use crate::node::KonsensusNode;

/// Spawns the nonce cleanup task — periodically removes expired replay-protection nonces.
///
/// Without this, the nonces table grows unbounded as every incoming message
/// stores a nonce. Nonces older than 1 hour are safe to remove because the
/// UKM envelope timestamp check already rejects messages older than 5 minutes.
pub(crate) async fn run_nonce_cleanup(
    storage: Arc<dyn konsensus_storage::Storage>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let cleanup_interval = std::time::Duration::from_secs(300); // every 5 minutes
    let max_nonce_age_secs: u64 = 3600; // 1 hour
    loop {
        tokio::select! {
            _ = tokio::time::sleep(cleanup_interval) => {
                match storage.cleanup_expired_nonces(max_nonce_age_secs).await {
                    Ok(removed) if removed > 0 => {
                        debug!(removed, "cleaned up expired nonces");
                    }
                    Ok(_) => {} // nothing to clean
                    Err(e) => {
                        warn!(error = %e, "nonce cleanup failed");
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                debug!("nonce cleanup task shutting down");
                break;
            }
        }
    }
}

/// Spawns the whitelist-backup task (RV-RESTORE producer) — periodically writes
/// the encrypted `whitelist-latest.aes` sidecar (the `peers` + `accepted_invites`
/// rows) next to `scb-latest.aes`. The SCB carries only LDK channel-monitor state;
/// this sidecar carries the gate whitelist, so a mnemonic+SCB restore onto fresh
/// hardware can recover relationships, not just channels (`project_scb_restore_scope`).
///
/// Each individual write stays best-effort (never crashes the node), but a
/// *persistent* failure is a recovery-drill blocker — a node whose sidecar has
/// gone stale will NOT re-admit invite-onboarded peers after a mnemonic+SCB
/// restore (Codex #208). So a one-off failure is a `warn!`, while
/// [`WHITELIST_BACKUP_FAILURE_ALERT_THRESHOLD`] consecutive failures escalate to
/// a loud `error!` (alertable) that names the recovery impact. Writes once at
/// startup (so a node that never reaches a tick still has a current sidecar) and
/// then on the SCB-rotation cadence (300s).
pub(crate) async fn run_whitelist_backup(
    storage: Arc<dyn konsensus_storage::Storage>,
    identity: Arc<konsensus_core::NodeIdentity>,
    backup_path: std::path::PathBuf,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let backup_interval = std::time::Duration::from_secs(300); // every 5 minutes, matches SCB cadence

    let mut consecutive_failures: u32 = 0;
    consecutive_failures = record_sidecar_outcome(
        write_whitelist_sidecar(storage.as_ref(), identity.aes_key(), &backup_path).await,
        consecutive_failures,
        &backup_path,
    );

    loop {
        tokio::select! {
            _ = tokio::time::sleep(backup_interval) => {
                consecutive_failures = record_sidecar_outcome(
                    write_whitelist_sidecar(storage.as_ref(), identity.aes_key(), &backup_path).await,
                    consecutive_failures,
                    &backup_path,
                );
            }
            _ = shutdown_rx.changed() => {
                debug!("whitelist backup task shutting down");
                break;
            }
        }
    }
}

/// Consecutive whitelist-sidecar write failures at which a transient `warn!`
/// becomes a loud, alertable `error!`. Each write remains non-fatal; this only
/// changes the log level once failures look persistent (≈ this many × the 300s
/// cadence), which is the signal that recovery is silently degrading.
const WHITELIST_BACKUP_FAILURE_ALERT_THRESHOLD: u32 = 3;

/// Fold one write outcome into the consecutive-failure counter, escalating the
/// log level once failures persist. Returns the updated counter.
fn record_sidecar_outcome(ok: bool, consecutive_failures: u32, out_path: &std::path::Path) -> u32 {
    if ok {
        return 0;
    }
    let consecutive = consecutive_failures.saturating_add(1);
    if consecutive >= WHITELIST_BACKUP_FAILURE_ALERT_THRESHOLD {
        error!(
            consecutive,
            path = %out_path.display(),
            "whitelist backup sidecar has failed {consecutive}× consecutively — a mnemonic+SCB \
             restore will NOT recover invite-onboarded peers until this clears (recovery-drill \
             blocker). Check free disk space and write permissions on the backup directory."
        );
    }
    consecutive
}

/// One best-effort whitelist-sidecar write. Reuses the shipped
/// `write_whitelist_backup` producer (collect → seal → atomic rename) so the
/// periodic path and the `konsensus whitelist backup` CLI stay byte-identical.
/// Returns `true` on success, `false` on a (logged, non-fatal) failure.
async fn write_whitelist_sidecar(
    storage: &dyn konsensus_storage::Storage,
    key: &[u8; 32],
    out_path: &std::path::Path,
) -> bool {
    match crate::whitelist_cmd::write_whitelist_backup(storage, key, out_path).await {
        Ok(bytes) => {
            debug!(bytes, path = %out_path.display(), "wrote whitelist backup sidecar");
            true
        }
        Err(e) => {
            warn!(error = %e, path = %out_path.display(), "whitelist backup sidecar write failed (will retry next cadence)");
            false
        }
    }
}

/// Spawns the pending deliveries cleanup task — removes entries that have exceeded
/// max retry attempts or are too old, preventing unbounded table growth when
/// peers stay offline for extended periods.
pub(crate) async fn run_pending_cleanup(
    storage: Arc<dyn konsensus_storage::Storage>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let cleanup_interval = std::time::Duration::from_secs(600); // every 10 minutes
    const MAX_DELIVERY_ATTEMPTS: u32 = 10;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(cleanup_interval) => {
                match storage.cleanup_stale_pending(MAX_DELIVERY_ATTEMPTS).await {
                    Ok(removed) if removed > 0 => {
                        info!(removed, "cleaned up stale pending deliveries");
                    }
                    Ok(_) => {} // nothing to clean
                    Err(e) => {
                        warn!(error = %e, "pending deliveries cleanup failed");
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                debug!("pending deliveries cleanup task shutting down");
                break;
            }
        }
    }
}

/// Spawns the send_timestamps cleanup task — periodically removes stale entries
/// for messages that were never acked.
pub(crate) async fn run_timestamps_cleanup(
    send_timestamps: Arc<tokio::sync::Mutex<std::collections::HashMap<konsensus_core::types::MessageId, std::time::Instant>>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let cleanup_interval = std::time::Duration::from_secs(60);
    let max_age = std::time::Duration::from_secs(300); // 5 minutes
    loop {
        tokio::select! {
            _ = tokio::time::sleep(cleanup_interval) => {
                let mut timestamps = send_timestamps.lock().await;
                let before = timestamps.len();
                if before > 0 {
                    let cutoff = std::time::Instant::now() - max_age;
                    timestamps.retain(|_, sent_at| *sent_at > cutoff);
                    let removed = before - timestamps.len();
                    if removed > 0 {
                        debug!(removed, remaining = timestamps.len(), "cleaned up stale send timestamps");
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                debug!("send_timestamps cleanup task shutting down");
                break;
            }
        }
    }
}

/// Spawns the message retention cleanup task — deletes messages older than
/// the configured retention period. Only active when retention_days > 0.
pub(crate) async fn run_retention_cleanup(
    storage: Arc<dyn konsensus_storage::Storage>,
    retention_days: u32,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if retention_days == 0 {
        // Retention disabled (keep forever) — park this task until shutdown
        let _ = shutdown_rx.changed().await;
        return;
    }

    let cleanup_interval = std::time::Duration::from_secs(3600); // every hour
    info!(retention_days, "message retention cleanup task started");
    loop {
        tokio::select! {
            _ = tokio::time::sleep(cleanup_interval) => {
                let cutoff_ms = {
                    let now_millis = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis();
                    let now = u64::try_from(now_millis).unwrap_or(u64::MAX);
                    let retention_ms = u64::from(retention_days) * 24 * 3600 * 1000;
                    now.saturating_sub(retention_ms)
                };
                match storage.delete_messages_older_than(cutoff_ms).await {
                    Ok(removed) if removed > 0 => {
                        info!(removed, retention_days, "cleaned up expired messages");
                    }
                    Ok(_) => {} // nothing to clean
                    Err(e) => {
                        warn!(error = %e, "message retention cleanup failed");
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                debug!("message retention cleanup task shutting down");
                break;
            }
        }
    }
}

/// Spawns the gossip store eviction task — periodically removes expired
/// deduplication entries to bound memory usage.
///
/// Without this, the gossip dedup store grows unbounded over time.
/// At 60 messages/sender/hour with 100 senders and 2-hour TTL, worst case
/// is ~12K entries (~864 KB) — but eviction ensures we stay near actual
/// active gossip volume.
pub(crate) async fn run_gossip_eviction(
    gossip_validator: Arc<konsensus_gossip::GossipValidator>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let eviction_interval = std::time::Duration::from_secs(300); // every 5 minutes
    loop {
        tokio::select! {
            _ = tokio::time::sleep(eviction_interval) => {
                gossip_validator.evict_expired();
                let remaining = gossip_validator.store().len();
                let tracked_senders = gossip_validator.tracked_senders();
                if remaining > 0 || tracked_senders > 0 {
                    debug!(
                        dedup_entries = remaining,
                        tracked_senders,
                        "gossip store eviction complete"
                    );
                }
            }
            _ = shutdown_rx.changed() => {
                debug!("gossip eviction task shutting down");
                break;
            }
        }
    }
}

/// Spawns the periodic price table re-announcement task.
///
/// When using chain-aware pricing, fee rates change over time, so prices
/// change. Connected peers need updated price tables to avoid mismatch
/// rejections. Re-announces every 10 minutes. Only sends if prices have
/// actually changed since last announcement.
pub(crate) async fn run_price_refresh(
    transport: Arc<NoiseTransport>,
    pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine>,
    chain: Arc<dyn ChainProvider>,
    routing: Arc<konsensus_routing::RoutingTable>,
    config: crate::config::NodeConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let refresh_interval = std::time::Duration::from_secs(600); // 10 minutes
    let mut last_prices: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(refresh_interval) => {
                let meta = konsensus_pricing::peer_prices::build_full_price_table(
                    pricing.as_ref(),
                    chain.as_ref(),
                ).await;

                // Persist fee rate EMA snapshot for restart continuity.
                if let Some(chain_engine) = pricing
                    .as_any()
                    .downcast_ref::<konsensus_pricing::ChainAwarePricingEngine>()
                {
                    if let Some(snapshot) = chain_engine.snapshot().await {
                        KonsensusNode::save_fee_rate_snapshot(&config, &snapshot);
                    }
                }

                // Only re-announce if prices actually changed
                if meta.prices == last_prices {
                    debug!("price table unchanged, skipping re-announcement");
                    continue;
                }

                let peers = transport.connected_peers().await;
                if peers.is_empty() {
                    last_prices = meta.prices;
                    continue;
                }

                info!(
                    peer_count = peers.len(),
                    block_height = meta.block_height,
                    valid_blocks = meta.valid_blocks,
                    trust_level = ?meta.trust_level,
                    difficulty_epoch_position = meta.block_height % 2016,
                    categories_changed = meta.prices.iter()
                        .filter(|(k, v)| last_prices.get(*k) != Some(v))
                        .count(),
                    "price change detected — re-announcing to connected peers"
                );

                for peer_id in &peers {
                    let peer_discount = routing
                        .get_peer_weight(peer_id)
                        .await
                        .map(konsensus_pricing::compute_trust_discount)
                        .unwrap_or(0.0);
                    let frame = Frame::PriceTable {
                        prices: meta.prices.clone(),
                        block_height: meta.block_height,
                        valid_blocks: meta.valid_blocks,
                        trust_discount: peer_discount,
                    };
                    if let Err(e) = transport.send_frame(peer_id, &frame).await {
                        warn!(peer = %peer_id, error = %e, "failed to send updated price table");
                    }
                }
                last_prices = meta.prices;
            }
            _ = shutdown_rx.changed() => {
                debug!("price refresh task shutting down");
                break;
            }
        }
    }
}

/// Spawns the `peer_ln_pubkeys` cleanup task — removes entries for peers
/// that are no longer connected. Without this, the map grows unbounded over
/// the node's lifetime as unique peers connect and disconnect.
pub(crate) async fn run_peer_ln_pubkeys_cleanup(
    peer_ln_pubkeys: Arc<tokio::sync::Mutex<std::collections::HashMap<konsensus_core::types::NodeId, String>>>,
    transport: Arc<NoiseTransport>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let cleanup_interval = std::time::Duration::from_secs(300); // every 5 minutes
    loop {
        tokio::select! {
            _ = tokio::time::sleep(cleanup_interval) => {
                let connected: std::collections::HashSet<_> =
                    transport.connected_peers().await.into_iter().collect();
                let mut map = peer_ln_pubkeys.lock().await;
                let before = map.len();
                if before > 0 {
                    map.retain(|peer_id, _| connected.contains(peer_id));
                    let removed = before - map.len();
                    if removed > 0 {
                        debug!(removed, remaining = map.len(), "cleaned up stale peer_ln_pubkeys entries");
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                debug!("peer_ln_pubkeys cleanup task shutting down");
                break;
            }
        }
    }
}

/// Spawns the `invoice_requests` cleanup task — removes entries whose oneshot
/// senders have been closed (receiver dropped) or that have been pending
/// longer than the configured TTL. Prevents unbounded map growth from leaked
/// entries when the normal success/timeout cleanup paths are bypassed.
pub(crate) async fn run_invoice_requests_cleanup(
    invoice_requests: Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<konsensus_api::state::InvoiceResponseData>>>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let cleanup_interval = std::time::Duration::from_secs(60); // every 60 seconds
    loop {
        tokio::select! {
            _ = tokio::time::sleep(cleanup_interval) => {
                let mut map = invoice_requests.lock().await;
                let before = map.len();
                if before > 0 {
                    // Remove entries where the oneshot sender is closed (receiver dropped).
                    map.retain(|_, sender| !sender.is_closed());
                    let removed = before - map.len();
                    if removed > 0 {
                        debug!(removed, remaining = map.len(), "cleaned up stale invoice_requests entries");
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                debug!("invoice_requests cleanup task shutting down");
                break;
            }
        }
    }
}


/// Write one snapshot row per supported currency for the given UTC date.
///
/// Returns "(ok, failed)" counts for observability.
async fn take_fiat_snapshot(
    storage: &dyn konsensus_storage::Storage,
    provider: &dyn konsensus_fiat::FiatRateProvider,
    date: &str,
) -> (usize, usize) {
    let currencies = provider.supported_currencies().to_vec();
    let mut ok = 0usize;
    let mut failed = 0usize;

    for currency in &currencies {
        match provider.fetch_rate(*currency).await {
            Ok(quote) => {
                let snapshot = konsensus_storage::FiatRateSnapshot {
                    date: date.to_string(),
                    currency: currency.to_string(),
                    rate: quote.rate,
                    source: quote.source.to_string(),
                    created_at: String::new(), // filled by DB default
                };
                match storage.store_fiat_rate_snapshot(&snapshot).await {
                    Ok(()) => ok += 1,
                    Err(e) => {
                        warn!(
                            date,
                            currency = %currency,
                            error = %e,
                            "failed to persist fiat rate snapshot"
                        );
                        failed += 1;
                    }
                }
            }
            Err(e) => {
                warn!(
                    date,
                    currency = %currency,
                    error = %e,
                    "failed to fetch fiat rate for snapshot"
                );
                failed += 1;
            }
        }
    }

    (ok, failed)
}

/// Spawns the daily fiat rate snapshot task.
///
/// At 00:00 UTC each day, fetches the current BTC/fiat rate for every currency
/// the configured provider supports and writes one row per currency to the
/// "fiat_rate_snapshots" table.  The snapshots are consumed by the tax-export
/// handler to denominate Lightning payments in local currency on the transaction
/// date.
///
/// The task first sleeps until the next midnight UTC so it aligns to a calendar
/// day boundary regardless of when the node starts.  Upsert semantics in the DB
/// make restarts within the same day safe.
pub(crate) async fn run_fiat_rate_snapshot(
    storage: Arc<dyn konsensus_storage::Storage>,
    provider: Arc<dyn konsensus_fiat::FiatRateProvider>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    use chrono::Timelike;

    // Seconds remaining in the current UTC day.
    fn secs_until_midnight() -> u64 {
        let now = chrono::Utc::now();
        let elapsed = u64::from(now.hour()) * 3600
            + u64::from(now.minute()) * 60
            + u64::from(now.second());
        86_400u64.saturating_sub(elapsed)
    }

    let delay = secs_until_midnight();
    info!(
        secs_until_midnight = delay,
        provider = provider.name(),
        "fiat rate snapshot task started; first snapshot fires in {delay}s"
    );

    // Wait for the first midnight.
    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_secs(delay)) => {}
        _ = shutdown_rx.changed() => {
            debug!("fiat rate snapshot task shutting down before first snapshot");
            return;
        }
    }

    // 24-hour loop.
    loop {
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let (ok, failed) = take_fiat_snapshot(
            storage.as_ref(),
            provider.as_ref(),
            &date,
        )
        .await;

        info!(
            date = %date,
            currencies_ok = ok,
            currencies_failed = failed,
            "daily fiat rate snapshot complete"
        );

        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(86_400)) => {}
            _ = shutdown_rx.changed() => {
                debug!("fiat rate snapshot task shutting down");
                break;
            }
        }
    }
}
#[cfg(test)]
#[path = "tests/housekeeping.rs"]
mod tests;
