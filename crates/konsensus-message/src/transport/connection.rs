//! TCP listener, incoming connection handler.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use konsensus_crypto::noise::NoiseSession;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use konsensus_core::traits::transport::TransportError;

use super::{
    ControlEvent, PeerConnection, TransportCtx,
    BAN_EVICTION_INTERVAL, HANDSHAKE_TIMEOUT, MAX_CONCURRENT_INBOUND,
};
use super::handshake::{noise_handshake_responder, perform_federation_handshake_responder};
use super::messaging::spawn_reader_task;

// ─── impl NoiseTransport — listener / connection management ─────────────────

use super::NoiseTransport;

impl NoiseTransport {
    /// Start the TCP listener for incoming connections.
    ///
    /// Spawns a background task that accepts connections, performs the Noise + federation
    /// handshake, and registers authenticated peers.
    pub async fn start_listener(&self) -> Result<(), TransportError> {
        let listener = TcpListener::bind(self.config.listen_addr)
            .await
            .map_err(|e| TransportError::ConnectionFailed(format!("bind failed: {e}")))?;

        let actual_addr = listener
            .local_addr()
            .map_err(|e| TransportError::ConnectionFailed(format!("local_addr failed: {e}")))?;
        if self.actual_listen_addr.send(Some(actual_addr)).is_err() {
            warn!(addr = %actual_addr, "failed to broadcast actual listen address");
        }

        info!(addr = %actual_addr, "transport listener started");

        if self.whitelist.read().await.is_empty() {
            warn!("no peers configured — your node is isolated and will reject all connections");
        }

        let ctx = TransportCtx {
            identity: Arc::clone(&self.identity),
            config: self.config.clone(),
            whitelist: Arc::clone(&self.whitelist),
            peers: Arc::clone(&self.peers),
            banned_peers: Arc::clone(&self.banned_peers),
            incoming_tx: self.incoming_tx.clone(),
            control_tx: self.control_tx.clone(),
        };
        let mut shutdown_rx = self.shutdown.subscribe();

        // Spawn periodic ban map eviction — prevents unbounded growth when
        // many peers are banned and never reconnect (memory leak fix).
        {
            let banned = Arc::clone(&self.banned_peers);
            let mut eviction_shutdown = self.shutdown.subscribe();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(BAN_EVICTION_INTERVAL) => {
                            let now = Instant::now();
                            let mut bans = banned.write().await;
                            let before = bans.len();
                            bans.retain(|_, expiry| *expiry > now);
                            let evicted = before - bans.len();
                            if evicted > 0 {
                                debug!(evicted, remaining = bans.len(), "evicted expired bans");
                            }
                        }
                        _ = eviction_shutdown.changed() => {
                            break;
                        }
                    }
                }
            });
        }

        tokio::spawn(async move {
            let conn_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_INBOUND));
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                debug!(%addr, "incoming connection");
                                let ctx = ctx.clone();
                                let permit = match conn_semaphore.clone().try_acquire_owned() {
                                    Ok(permit) => permit,
                                    Err(_) => {
                                        warn!(%addr, "rejecting connection: too many concurrent inbound handshakes");
                                        drop(stream);
                                        continue;
                                    }
                                };

                                tokio::spawn(async move {
                                    let _permit = permit; // held until task completes
                                    if let Err(e) = handle_incoming(
                                        stream, addr, ctx,
                                    ).await {
                                        warn!(%addr, error = %e, "incoming connection failed");
                                    }
                                });
                            }
                            Err(e) => {
                                error!(error = %e, "accept failed");
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        info!("transport listener shutting down");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Shut down the listener and disconnect all peers.
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Return the actual listen address after `start_listener()` completes.
    ///
    /// If the transport was configured with port 0, the OS assigns an ephemeral port.
    /// This method returns the real address including the assigned port.
    /// Returns `None` if `start_listener()` has not been called yet.
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        *self.actual_listen_addr_rx.borrow()
    }

    /// Receive the next control event (session frames, connection lifecycle).
    ///
    /// Used by the application layer to handle E2EE session establishment
    /// and delivery confirmations. Blocks until an event is available.
    pub async fn recv_control(&self) -> Option<ControlEvent> {
        let mut rx = self.control_rx.lock().await;
        rx.recv().await
    }
}

// ─── handle_incoming ────────────────────────────────────────────────────────

/// Handle an incoming TCP connection (responder side).
pub(super) async fn handle_incoming(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    ctx: TransportCtx,
) -> Result<(), TransportError> {
    let (reader, writer) = tokio::io::split(stream);

    // Noise handshake as responder — with timeout to prevent slot exhaustion
    let noise = NoiseSession::responder(ctx.identity.x25519_secret_bytes())
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;

    let (reader, writer, noise) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        noise_handshake_responder(reader, writer, noise),
    )
    .await
    .map_err(|_| TransportError::NoiseError(format!(
        "handshake timed out after {}s from {addr}",
        HANDSHAKE_TIMEOUT.as_secs()
    )))?
    ?;

    // Federation handshake — also under timeout
    let (peer_node_id, tier, capabilities, reader, writer, noise) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        perform_federation_handshake_responder(reader, writer, noise, &ctx.identity, &ctx.config, &ctx.whitelist),
    )
    .await
    .map_err(|_| TransportError::NoiseError(format!(
        "federation handshake timed out after {}s from {addr}",
        HANDSHAKE_TIMEOUT.as_secs()
    )))?
    ?;

    // Whitelist check is now done inside perform_federation_handshake_responder
    // BEFORE sending HelloAck, preventing identity leak to unauthorized peers (QA-M5).

    // Ban check — reject peers temporarily banned for exceeding frame validation budget
    {
        let mut bans = ctx.banned_peers.write().await;
        if let Some(&expiry) = bans.get(&peer_node_id) {
            if Instant::now() < expiry {
                warn!(peer = %peer_node_id, %addr, "rejected: temporarily banned (frame validation budget exceeded)");
                return Err(TransportError::Rejected(format!(
                    "peer {} is temporarily banned",
                    peer_node_id.to_hex()
                )));
            }
            // Ban expired — remove stale entry to prevent unbounded map growth
            bans.remove(&peer_node_id);
        }
    }

    // Register connection
    let now = Instant::now();
    let conn = Arc::new(Mutex::new(PeerConnection {
        noise,
        writer,
        tier,
        capabilities,
        last_recv: now,
        pending_ping: None,
        invalid_frame_count: 0,
        invalid_frame_window_start: now,
        bytes_received: 0,
        memory_budget_window_start: now,
    }));

    ctx.peers.write().await.insert(peer_node_id, Arc::clone(&conn));

    // Spawn reader task
    spawn_reader_task(
        peer_node_id, reader, conn,
        Arc::clone(&ctx.peers), Arc::clone(&ctx.banned_peers),
        ctx.incoming_tx.clone(), ctx.control_tx.clone(),
    );

    // Notify application layer of new peer connection
    if let Err(e) = ctx.control_tx
        .send(ControlEvent::PeerConnected {
            peer_id: peer_node_id,
        })
        .await
    {
        warn!(peer = %peer_node_id, error = %e, "failed to send PeerConnected control event");
    }

    info!(peer = %peer_node_id, %addr, "incoming peer authenticated");
    Ok(())
}
