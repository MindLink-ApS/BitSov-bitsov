//! Peer supervision — reconnect loop and keepalive pings.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use konsensus_core::types::NodeId;

use crate::wire::Frame;

use super::{
    write_noise_message,
    TransportCtx,
    KEEPALIVE_INTERVAL, KEEPALIVE_TIMEOUT,
    RECONNECT_MAX_DELAY, RECONNECT_MIN_DELAY,
};
use super::handshake::connect_to_peer;
use super::NoiseTransport;

impl NoiseTransport {
    /// Start the connection supervisor for a set of peers.
    ///
    /// For each peer, spawns a background task that:
    /// 1. Monitors connection health
    /// 2. Reconnects with exponential backoff if the connection drops
    /// 3. Sends periodic keepalive pings on idle connections
    ///
    /// This is the key mechanism for test network stability — nodes recover
    /// from restarts, temporary network partitions, and connection drops.
    pub fn start_supervisor(&self, supervised_peers: Vec<(NodeId, SocketAddr)>) {
        for (node_id, addr) in supervised_peers {
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
            let ping_counter = Arc::clone(&self.ping_counter);

            tokio::spawn(async move {
                let mut backoff = RECONNECT_MIN_DELAY;

                loop {
                    // Check if connected
                    let connected = ctx.peers.read().await.contains_key(&node_id);

                    if !connected {
                        info!(
                            peer = %node_id,
                            delay_ms = backoff.as_millis(),
                            "supervisor: attempting connection"
                        );

                        match connect_to_peer(&node_id, &addr, &ctx).await
                        {
                            Ok(()) => {
                                info!(peer = %node_id, "supervisor: connected");
                                // backoff is reset after the keepalive loop exits
                            }
                            Err(e) => {
                                warn!(
                                    peer = %node_id,
                                    error = %e,
                                    retry_in_ms = backoff.as_millis(),
                                    "supervisor: connection failed, will retry"
                                );
                                // Wait with backoff before retrying
                                tokio::select! {
                                    _ = tokio::time::sleep(backoff) => {}
                                    _ = shutdown_rx.changed() => {
                                        debug!(peer = %node_id, "supervisor: shutdown");
                                        return;
                                    }
                                }
                                // Exponential backoff with cap
                                backoff = (backoff * 2).min(RECONNECT_MAX_DELAY);
                                continue;
                            }
                        }
                    }

                    // Connection is up — monitor health and send keepalives.
                    // Check connection status every second (fast detection),
                    // send keepalive pings at KEEPALIVE_INTERVAL.
                    let mut last_ping = Instant::now();
                    let mut waiting_for_pong = false;
                    let mut pong_deadline = Instant::now();

                    loop {
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                                // Fast check: is the peer still in the connection map?
                                let still_connected = ctx.peers.read().await.contains_key(&node_id);
                                if !still_connected {
                                    info!(peer = %node_id, "supervisor: peer disconnected, will reconnect");
                                    break; // Back to reconnect loop
                                }

                                // Check pong timeout
                                if waiting_for_pong && Instant::now() >= pong_deadline {
                                    // Clone Arc so the RwLock read guard is not held
                                    // across the connection Mutex lock.
                                    let conn_arc = {
                                        let peers_read = ctx.peers.read().await;
                                        peers_read.get(&node_id).map(Arc::clone)
                                    };
                                    let alive = if let Some(conn) = conn_arc {
                                        let conn = conn.lock().await;
                                        conn.pending_ping.is_none()
                                            || conn.last_recv.elapsed() < KEEPALIVE_INTERVAL
                                    } else {
                                        false
                                    };

                                    if !alive {
                                        warn!(peer = %node_id, "supervisor: keepalive timeout, peer is dead");
                                        ctx.peers.write().await.remove(&node_id);
                                        break;
                                    }
                                    waiting_for_pong = false;
                                }

                                // Time to send a keepalive ping?
                                if !waiting_for_pong && last_ping.elapsed() >= KEEPALIVE_INTERVAL {
                                    let nonce = ping_counter.fetch_add(1, Ordering::Relaxed);

                                    // Clone Arc so the RwLock read guard is not held
                                    // across network I/O (write_noise_message).
                                    let conn_arc = {
                                        let peers_read = ctx.peers.read().await;
                                        peers_read.get(&node_id).map(Arc::clone)
                                    };
                                    let ping_sent = if let Some(conn) = conn_arc {
                                        let mut conn = conn.lock().await;
                                        conn.pending_ping = Some(nonce);
                                        let ping = Frame::Ping { nonce };
                                        if let Ok(bytes) = ping.to_bytes() {
                                            if let Ok(encrypted) = conn.noise.encrypt(&bytes) {
                                                write_noise_message(&mut conn.writer, &encrypted)
                                                    .await
                                                    .is_ok()
                                            } else {
                                                false
                                            }
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    };

                                    if !ping_sent {
                                        warn!(peer = %node_id, "supervisor: ping send failed, reconnecting");
                                        ctx.peers.write().await.remove(&node_id);
                                        break;
                                    }

                                    debug!(peer = %node_id, %nonce, "supervisor: sent keepalive ping");
                                    last_ping = Instant::now();
                                    waiting_for_pong = true;
                                    pong_deadline = Instant::now() + KEEPALIVE_TIMEOUT;
                                }
                            }
                            _ = shutdown_rx.changed() => {
                                debug!(peer = %node_id, "supervisor: shutdown");
                                return;
                            }
                        }
                    }

                    // After disconnection, reset backoff and wait briefly before reconnecting
                    backoff = RECONNECT_MIN_DELAY;
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = shutdown_rx.changed() => {
                            debug!(peer = %node_id, "supervisor: shutdown");
                            return;
                        }
                    }
                }
            });
        }
    }

    /// Start connection supervision for a single peer added after startup.
    ///
    /// This spawns the same per-peer supervisor task as `start_supervisor` but
    /// for a single dynamically-added peer. Used when a peer is added via
    /// invite redemption so they get automatic reconnection with exponential
    /// backoff and keepalive monitoring — identical to config-file peers.
    pub fn supervise_single_peer(&self, node_id: NodeId, addr: SocketAddr) {
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
        let ping_counter = Arc::clone(&self.ping_counter);

        tokio::spawn(async move {
            let mut backoff = RECONNECT_MIN_DELAY;

            loop {
                let connected = ctx.peers.read().await.contains_key(&node_id);

                if !connected {
                    info!(
                        peer = %node_id,
                        delay_ms = backoff.as_millis(),
                        "supervisor: attempting connection (dynamic peer)"
                    );

                    match connect_to_peer(&node_id, &addr, &ctx).await {
                        Ok(()) => {
                            info!(peer = %node_id, "supervisor: connected (dynamic peer)");
                        }
                        Err(e) => {
                            warn!(
                                peer = %node_id,
                                error = %e,
                                retry_in_ms = backoff.as_millis(),
                                "supervisor: connection failed, will retry"
                            );
                            tokio::select! {
                                _ = tokio::time::sleep(backoff) => {}
                                _ = shutdown_rx.changed() => {
                                    debug!(peer = %node_id, "supervisor: shutdown");
                                    return;
                                }
                            }
                            backoff = (backoff * 2).min(RECONNECT_MAX_DELAY);
                            continue;
                        }
                    }
                }

                // Connection is up — monitor health and send keepalives
                let mut last_ping = Instant::now();
                let mut waiting_for_pong = false;
                let mut pong_deadline = Instant::now();

                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {
                            let still_connected = ctx.peers.read().await.contains_key(&node_id);
                            if !still_connected {
                                info!(peer = %node_id, "supervisor: peer disconnected, will reconnect");
                                break;
                            }

                            if waiting_for_pong && Instant::now() >= pong_deadline {
                                // Clone Arc so the RwLock read guard is not held
                                // across the connection Mutex lock.
                                let conn_arc = {
                                    let peers_read = ctx.peers.read().await;
                                    peers_read.get(&node_id).map(Arc::clone)
                                };
                                let alive = if let Some(conn) = conn_arc {
                                    let conn = conn.lock().await;
                                    conn.pending_ping.is_none()
                                        || conn.last_recv.elapsed() < KEEPALIVE_INTERVAL
                                } else {
                                    false
                                };

                                if !alive {
                                    warn!(peer = %node_id, "supervisor: keepalive timeout, peer is dead");
                                    ctx.peers.write().await.remove(&node_id);
                                    break;
                                }
                                waiting_for_pong = false;
                            }

                            if !waiting_for_pong && last_ping.elapsed() >= KEEPALIVE_INTERVAL {
                                let nonce = ping_counter.fetch_add(1, Ordering::Relaxed);

                                // Clone Arc so the RwLock read guard is not held
                                // across network I/O (write_noise_message).
                                let conn_arc = {
                                    let peers_read = ctx.peers.read().await;
                                    peers_read.get(&node_id).map(Arc::clone)
                                };
                                let ping_sent = if let Some(conn) = conn_arc {
                                    let mut conn = conn.lock().await;
                                    conn.pending_ping = Some(nonce);
                                    let ping = Frame::Ping { nonce };
                                    if let Ok(bytes) = ping.to_bytes() {
                                        if let Ok(encrypted) = conn.noise.encrypt(&bytes) {
                                            write_noise_message(&mut conn.writer, &encrypted)
                                                .await
                                                .is_ok()
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                };

                                if !ping_sent {
                                    warn!(peer = %node_id, "supervisor: ping send failed, reconnecting");
                                    ctx.peers.write().await.remove(&node_id);
                                    break;
                                }

                                debug!(peer = %node_id, %nonce, "supervisor: sent keepalive ping");
                                last_ping = Instant::now();
                                waiting_for_pong = true;
                                pong_deadline = Instant::now() + KEEPALIVE_TIMEOUT;
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            debug!(peer = %node_id, "supervisor: shutdown");
                            return;
                        }
                    }
                }

                backoff = RECONNECT_MIN_DELAY;
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown_rx.changed() => {
                        debug!(peer = %node_id, "supervisor: shutdown");
                        return;
                    }
                }
            }
        });
    }

    /// Check if a node ID is in the whitelist.
    ///
    /// Returns `false` when the whitelist is empty — a node with no configured
    /// peers rejects all connections (Principle 3: closed mesh). This prevents
    /// a freshly initialized node from being open to the world.
    pub(super) async fn is_whitelisted(&self, node_id: &NodeId) -> bool {
        let wl = self.whitelist.read().await;
        !wl.is_empty() && wl.contains(node_id)
    }
}
