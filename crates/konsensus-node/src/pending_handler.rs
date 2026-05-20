//! Pending delivery flusher — delivers queued messages when peers reconnect.
//!
//! This runs as a separate task that receives peer_id notifications via
//! an mpsc channel. When a peer connects (or reconnects), the session
//! handler sends their NodeId to this channel, and the flusher loads
//! all pending messages from storage and attempts to deliver them.

use std::sync::Arc;

use tokio::sync::watch;
use tracing::{debug, info, warn};

use konsensus_api::audit::AuditLog;
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::types::NodeId;

/// All dependencies needed by the pending delivery flusher task.
pub(crate) struct PendingHandlerDeps {
    pub storage: Arc<dyn konsensus_storage::Storage>,
    pub transport: Arc<dyn MessageTransport>,
    pub audit_log: Arc<AuditLog>,
    pub send_timestamps: Arc<tokio::sync::Mutex<std::collections::HashMap<konsensus_core::types::MessageId, std::time::Instant>>>,
    pub pending_rx: tokio::sync::mpsc::Receiver<NodeId>,
    pub shutdown_rx: watch::Receiver<bool>,
}

/// Runs the pending delivery flusher loop.
pub(crate) async fn run(deps: PendingHandlerDeps) {
    let PendingHandlerDeps {
        storage,
        transport,
        audit_log: audit,
        send_timestamps,
        mut pending_rx,
        mut shutdown_rx,
    } = deps;

    // Periodic scan interval — safety net for missed channel notifications.
    // If a PeerConnected send to the channel fails (capacity 64), the periodic
    // scan picks up any connected peers with pending deliveries.
    let mut periodic_scan = tokio::time::interval(tokio::time::Duration::from_secs(60));
    periodic_scan.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            Some(peer_id) = pending_rx.recv() => {
                flush_peer(&peer_id, storage.as_ref(), transport.as_ref(), &audit, &send_timestamps).await;
            }
            _ = periodic_scan.tick() => {
                // Check all connected peers for pending deliveries
                let connected = transport.connected_peers().await;
                for peer_id in &connected {
                    flush_peer(peer_id, storage.as_ref(), transport.as_ref(), &audit, &send_timestamps).await;
                }
            }
            _ = shutdown_rx.changed() => {
                info!("pending delivery flusher shutting down");
                break;
            }
        }
    }
}

/// Flush all pending deliveries for a single peer.
async fn flush_peer(
    peer_id: &NodeId,
    storage: &dyn konsensus_storage::Storage,
    transport: &dyn MessageTransport,
    audit: &AuditLog,
    send_timestamps: &tokio::sync::Mutex<std::collections::HashMap<konsensus_core::types::MessageId, std::time::Instant>>,
) {
    let pending = match storage.get_pending_for_peer(peer_id).await {
        Ok(p) => p,
        Err(e) => {
            warn!(peer = %peer_id, error = %e, "failed to load pending deliveries");
            return;
        }
    };

    if pending.is_empty() {
        return;
    }

    info!(
        peer = %peer_id,
        count = pending.len(),
        "flushing pending deliveries"
    );

    for (message_id, _recipient_id) in &pending {
        // Load the full envelope from storage
        let envelope = match storage.get_message(message_id).await {
            Ok(Some(env)) => env,
            Ok(None) => {
                // Envelope was deleted (retention cleanup?) — remove stale pending entry
                debug!(
                    peer = %peer_id,
                    msg_id = %message_id,
                    "pending message no longer in storage, removing"
                );
                if let Err(e) = storage.remove_pending_delivery(message_id, peer_id).await {
                    warn!(error = %e, "failed to remove stale pending delivery");
                }
                continue;
            }
            Err(e) => {
                warn!(
                    peer = %peer_id,
                    msg_id = %message_id,
                    error = %e,
                    "failed to load pending envelope"
                );
                if let Err(e) = storage.increment_pending_attempts(message_id, peer_id).await {
                    warn!(error = %e, "failed to increment pending attempts");
                }
                continue;
            }
        };

        match transport.send(peer_id, &envelope).await {
            Ok(()) => {
                info!(
                    peer = %peer_id,
                    msg_id = %message_id,
                    "delivered pending message"
                );
                if let Err(e) = storage.remove_pending_delivery(message_id, peer_id).await {
                    warn!(error = %e, "failed to remove delivered pending entry");
                }
                // Record send timestamp for STDP latency measurement
                send_timestamps.lock().await.insert(*message_id, std::time::Instant::now());
                audit.record(
                    "pending_delivered",
                    &peer_id.to_hex(),
                    Some(serde_json::json!({
                        "message_id": message_id.to_hex(),
                    })),
                );
            }
            Err(e) => {
                warn!(
                    peer = %peer_id,
                    msg_id = %message_id,
                    error = %e,
                    "failed to deliver pending message"
                );
                if let Err(inc_err) = storage.increment_pending_attempts(message_id, peer_id).await {
                    warn!(error = %inc_err, "failed to increment pending attempts");
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/pending_handler.rs"]
mod tests;
