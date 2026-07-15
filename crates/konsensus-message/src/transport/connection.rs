//! TCP listener, incoming connection handler.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use konsensus_crypto::noise::NoiseSession;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use konsensus_core::traits::transport::TransportError;

use super::{
    ControlEvent, PeerConnection, TransportCtx,
    BAN_EVICTION_INTERVAL, HANDSHAKE_TIMEOUT, INBOUND_HANDSHAKE_BURST_PER_SUBNET,
    INBOUND_HANDSHAKE_RATE_PER_SUBNET, MAX_CONCURRENT_INBOUND, MAX_TRACKED_SUBNETS,
};
use super::handshake::{noise_handshake_responder, perform_federation_handshake_responder};
use super::messaging::spawn_reader_task;

// ─── impl NoiseTransport — listener / connection management ─────────────────

use super::NoiseTransport;

/// Maximum concurrent inbound handshakes accepted from a single source IP.
///
/// This is a pre-admission anti-DoS resource cap, **not** payment clearance.
/// Under "payment is the connection" the TCP+Noise pipe is a quarantined knock
/// that yields nothing privileged until a settled, recipient-bound payment binds
/// the peer; this cap only stops one source from starving the global
/// [`MAX_CONCURRENT_INBOUND`] budget while that quarantined handshake runs. It
/// consults no identity and no operator list — availability defense, never
/// admission. (See CODEX.md: endpoint knowledge is free; endpoint service is paid.)
const MAX_INBOUND_PER_IP: u32 = 8;

/// Concurrent-inbound-handshake counts keyed by source IP.
type PerIpCounts = Arc<StdMutex<HashMap<IpAddr, u32>>>;

/// RAII guard for the per-IP inbound handshake cap.
///
/// Acquiring increments the count for `ip`; dropping decrements it (and removes
/// the entry at zero so the map cannot grow unbounded). Held for the lifetime
/// of the spawned handshake task, mirroring the global semaphore permit.
struct PerIpGuard {
    counts: PerIpCounts,
    ip: IpAddr,
}

impl PerIpGuard {
    /// Returns `Some(guard)` if `ip` is below `cap` (count incremented), or
    /// `None` if the source already holds `cap` concurrent handshakes.
    fn try_acquire(counts: &PerIpCounts, ip: IpAddr, cap: u32) -> Option<Self> {
        let mut map = counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = map.entry(ip).or_insert(0);
        if *count >= cap {
            return None;
        }
        *count += 1;
        Some(Self {
            counts: Arc::clone(counts),
            ip,
        })
    }
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let mut map = self.counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = map.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Collapse a source IP to its rate-limit aggregation key: the IPv4 `/24`
/// network or the IPv6 `/64` network. Aggregating here is what makes the
/// limiter resistant to an attacker who rotates addresses inside one block.
fn subnet_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], 0))
        }
        IpAddr::V6(v6) => {
            let s = v6.octets();
            let mut masked = [0u8; 16];
            masked[..8].copy_from_slice(&s[..8]);
            IpAddr::V6(Ipv6Addr::from(masked))
        }
    }
}

/// One subnet's token bucket: `tokens` available now, `last_refill` for lazy refill.
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

/// Token-bucket inbound-handshake **rate** limiter, aggregated per subnet
/// (IPv4 `/24`, IPv6 `/64`).
///
/// This extends — it does not replace — the exact-IP **concurrency** cap
/// ([`PerIpGuard`]). The concurrency cap stops one IP holding many simultaneous
/// handshake slots; this limiter stops a whole subnet (or a botnet within one
/// block) from sustaining a high *rate* of fresh handshakes by rotating source
/// addresses. It is pre-auth and identity-blind — it consults only the source
/// subnet, never a node id or operator list: availability defense, never
/// admission. It changes no wire bytes, no Noise handshake, and no payment-gate
/// semantics. Parameters are constructor-injected (the listener seeds them from
/// the centralized constants in `mod.rs`, matching how the sibling inbound caps
/// `MAX_INBOUND_PER_IP` / `MAX_CONCURRENT_INBOUND` are defined); wiring them onto
/// operator `TransportConfig` is a mechanical follow-up, not done here.
struct SubnetRateLimiter {
    buckets: StdMutex<HashMap<IpAddr, TokenBucket>>,
    /// Bucket size (max burst).
    capacity: f64,
    /// Sustained refill, tokens per second.
    refill_per_sec: f64,
    /// Hard ceiling on tracked subnets; enforced by evicting idle-then-nearest-idle
    /// buckets, so the map cannot grow unbounded even under an active wide flood.
    max_tracked: usize,
}

impl SubnetRateLimiter {
    fn new(capacity: f64, refill_per_sec: f64, max_tracked: usize) -> Self {
        Self {
            buckets: StdMutex::new(HashMap::new()),
            capacity,
            refill_per_sec,
            max_tracked,
        }
    }

    /// Returns `true` if a token was available for this source's subnet (the
    /// connection may proceed), or `false` if the subnet has exceeded its rate
    /// (the caller should drop the connection cheaply, before the Noise DH).
    ///
    /// `now` is injected so the refill math is deterministically testable.
    fn try_admit(&self, ip: IpAddr, now: Instant) -> bool {
        let key = subnet_key(ip);
        let mut map = self.buckets.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        // Keep `max_tracked` a HARD ceiling, even under an active wide-source
        // flood (the case where pruning only idle buckets is not enough).
        if map.len() >= self.max_tracked && !map.contains_key(&key) {
            let cap = self.capacity;
            let refill = self.refill_per_sec;
            // Effective tokens after lazy refill — used only for ranking here.
            let eff = |b: &TokenBucket| -> f64 {
                let elapsed = now.saturating_duration_since(b.last_refill).as_secs_f64();
                (b.tokens + elapsed * refill).min(cap)
            };
            // 1) Drop fully-refilled (idle) buckets first — a subnet at rest, so
            //    forgetting it only forgoes carried-over burst, never the cap.
            map.retain(|_, b| eff(b) < cap);
            // 2) If the map is STILL at the ceiling, every tracked subnet is being
            //    actively throttled. Evict the buckets nearest full (highest tokens
            //    = least-actively-throttled, safest to forget), leaving 1/8 headroom
            //    so we do not evict on every subsequent insert. This bounds memory
            //    strictly; the worst case for an attacker cycling > max_tracked
            //    subnets is that the limiter degrades to the global concurrency cap.
            if map.len() >= self.max_tracked {
                let target = (self.max_tracked - self.max_tracked / 8).max(1);
                let to_drop = map.len().saturating_sub(target);
                if to_drop > 0 {
                    let mut ranked: Vec<(IpAddr, f64)> =
                        map.iter().map(|(k, b)| (*k, eff(b))).collect();
                    // Highest effective tokens first.
                    ranked.sort_unstable_by(|a, b| {
                        b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
                    });
                    for (k, _) in ranked.into_iter().take(to_drop) {
                        map.remove(&k);
                    }
                }
            }
        }

        let cap = self.capacity;
        let refill = self.refill_per_sec;
        let bucket = map.entry(key).or_insert_with(|| TokenBucket {
            tokens: cap,
            last_refill: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill).min(cap);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

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
            cookie_keyring: Arc::clone(&self.cookie_keyring),
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
            let per_ip_counts: PerIpCounts = Arc::new(StdMutex::new(HashMap::new()));
            // Per-subnet handshake RATE limiter (IPv4 /24, IPv6 /64). Extends the
            // exact-IP concurrency cap below so a subnet/botnet cannot evade it by
            // rotating addresses. Conservative, configurable defaults.
            let subnet_limiter = SubnetRateLimiter::new(
                INBOUND_HANDSHAKE_BURST_PER_SUBNET,
                INBOUND_HANDSHAKE_RATE_PER_SUBNET,
                MAX_TRACKED_SUBNETS,
            );
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                debug!(%addr, "incoming connection");
                                let ctx = ctx.clone();
                                // Per-source-IP concurrency cap first, so one source
                                // cannot drain the global inbound budget — a pre-auth
                                // DoS the energy gate cannot close. Anonymous and
                                // content-blind: it consults no node identity and no
                                // operator list, only the source IP.
                                let ip_guard = match PerIpGuard::try_acquire(
                                    &per_ip_counts,
                                    addr.ip(),
                                    MAX_INBOUND_PER_IP,
                                ) {
                                    Some(guard) => guard,
                                    None => {
                                        warn!(%addr, "rejecting connection: too many concurrent inbound handshakes from this source IP");
                                        drop(stream);
                                        continue;
                                    }
                                };
                                let permit = match conn_semaphore.clone().try_acquire_owned() {
                                    Ok(permit) => permit,
                                    Err(_) => {
                                        warn!(%addr, "rejecting connection: too many concurrent inbound handshakes");
                                        drop(stream);
                                        continue;
                                    }
                                };
                                // Per-subnet handshake-RATE limit LAST: a token is
                                // consumed only by a connection that already passed the
                                // per-IP and global concurrency caps, so a single noisy
                                // host (bounded by the per-IP cap) cannot drain a whole
                                // /24 (IPv4) or /64 (IPv6) bucket and starve legitimate
                                // peers. Bounds the *rate* of fresh handshakes per subnet
                                // so an attacker cannot evade the exact-IP cap by rotating
                                // addresses. Identity-blind, pre-auth — availability
                                // defense, never admission. On reject, `ip_guard` and
                                // `permit` drop here, releasing the slots.
                                if !subnet_limiter.try_admit(addr.ip(), Instant::now()) {
                                    warn!(%addr, "rejecting connection: inbound handshake rate exceeded for source subnet");
                                    drop(stream);
                                    continue;
                                }

                                tokio::spawn(async move {
                                    let _permit = permit; // held until task completes
                                    let _ip_guard = ip_guard; // per-IP slot held until task completes
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
    let (mut reader, mut writer) = tokio::io::split(stream);

    // Pre-Noise anti-DoS cookie gate (doorway hardening #2), only when the
    // operator opted in. Runs BEFORE the Noise DH and holds no per-connection
    // state until the cookie validates, so a spoofed/unproven source is dropped
    // without this node spending an X25519 DH. Skipped (byte-identical to
    // pre-cookie) under the default `CookieMode::Disabled`.
    if ctx.config.cookie_mode == super::CookieMode::Required {
        tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            super::cookie::cookie_gate_responder(
                &mut reader,
                &mut writer,
                addr.ip(),
                &ctx.cookie_keyring,
            ),
        )
        .await
        .map_err(|_| {
            TransportError::Rejected(format!(
                "pre-Noise cookie gate timed out after {}s from {addr}",
                HANDSHAKE_TIMEOUT.as_secs()
            ))
        })??;
    }

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

    // Federation handshake — also under timeout. `privileged` reflects whether the
    // peer is in our whitelist; in PriceOpen mode a non-whitelisted peer completes
    // the handshake unprivileged (per-message payment is the gate).
    let (peer_node_id, tier, capabilities, reader, writer, noise, privileged) = tokio::time::timeout(
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
        privileged,
        noise,
        writer,
        tier,
        capabilities,
        last_recv: now,
        pending_ping: None,
        invalid_frame_level: 0.0,
        invalid_frame_last_leak: now,
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

    // Notify application layer of new peer connection. M1b: carry the privilege
    // tag so the session handler does NOT volunteer X3DH/onboarding to a stranger
    // (PriceOpen, privileged == false) until they pay (promote-on-paid).
    if let Err(e) = ctx.control_tx
        .send(ControlEvent::PeerConnected {
            peer_id: peer_node_id,
            privileged,
        })
        .await
    {
        warn!(peer = %peer_node_id, error = %e, "failed to send PeerConnected control event");
    }

    info!(peer = %peer_node_id, %addr, "incoming peer authenticated");
    Ok(())
}

#[cfg(test)]
mod per_ip_cap_tests {
    use super::*;

    fn counts() -> PerIpCounts {
        Arc::new(StdMutex::new(HashMap::new()))
    }

    #[test]
    fn per_ip_handshake_cap_blocks_beyond_limit() {
        let counts = counts();
        let ip: IpAddr = "10.0.0.1".parse().expect("valid ip");
        let cap = 3;

        // Acquire exactly `cap` concurrent handshakes from one source.
        let g1 = PerIpGuard::try_acquire(&counts, ip, cap);
        let g2 = PerIpGuard::try_acquire(&counts, ip, cap);
        let g3 = PerIpGuard::try_acquire(&counts, ip, cap);
        assert!(g1.is_some() && g2.is_some() && g3.is_some());

        // The (cap + 1)-th from the same source is rejected.
        assert!(
            PerIpGuard::try_acquire(&counts, ip, cap).is_none(),
            "source IP past the cap must be rejected"
        );

        // A different source IP is unaffected by the first source's saturation.
        let other: IpAddr = "10.0.0.2".parse().expect("valid ip");
        assert!(
            PerIpGuard::try_acquire(&counts, other, cap).is_some(),
            "a distinct source IP must not be starved"
        );

        // Dropping one guard frees exactly one slot for that source.
        drop(g1);
        assert!(
            PerIpGuard::try_acquire(&counts, ip, cap).is_some(),
            "releasing a handshake must free a per-IP slot"
        );
    }

    #[test]
    fn per_ip_entry_removed_at_zero() {
        let counts = counts();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid ip");
        {
            let _g = PerIpGuard::try_acquire(&counts, ip, MAX_INBOUND_PER_IP);
            assert_eq!(
                *counts.lock().expect("lock").get(&ip).expect("entry"),
                1
            );
        }
        // Once the last guard drops, the entry is removed so the map cannot
        // grow unbounded across many short-lived sources.
        assert!(
            counts.lock().expect("lock").get(&ip).is_none(),
            "per-IP entry must be removed when its count returns to zero"
        );
    }
}

#[cfg(test)]
mod subnet_rate_limit_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn subnet_key_masks_ipv4_to_24_and_ipv6_to_64() {
        let a: IpAddr = "203.0.113.7".parse().expect("valid ip");
        let b: IpAddr = "203.0.113.250".parse().expect("valid ip");
        assert_eq!(subnet_key(a), subnet_key(b), "same /24 must share a key");
        assert_eq!(subnet_key(a), "203.0.113.0".parse::<IpAddr>().expect("valid ip"));

        let c: IpAddr = "203.0.114.7".parse().expect("valid ip");
        assert_ne!(subnet_key(a), subnet_key(c), "different /24 must differ");

        let v6a: IpAddr = "2001:db8:abcd:1234::1".parse().expect("valid ip");
        let v6b: IpAddr = "2001:db8:abcd:1234:ffff::9".parse().expect("valid ip");
        assert_eq!(subnet_key(v6a), subnet_key(v6b), "same /64 must share a key");
        let v6c: IpAddr = "2001:db8:abcd:9999::1".parse().expect("valid ip");
        assert_ne!(subnet_key(v6a), subnet_key(v6c), "different /64 must differ");
    }

    #[test]
    fn burst_from_same_subnet_is_capped_even_across_rotating_ips() {
        // capacity 3, refill 1/s. Rotating the host octet stays inside one /24.
        let rl = SubnetRateLimiter::new(3.0, 1.0, 1024);
        let t0 = Instant::now();
        assert!(rl.try_admit("198.51.100.1".parse().expect("valid ip"), t0));
        assert!(rl.try_admit("198.51.100.2".parse().expect("valid ip"), t0));
        assert!(rl.try_admit("198.51.100.3".parse().expect("valid ip"), t0));
        // A fourth rotated IP in the SAME /24 is throttled — rotation does not win,
        // because the bucket aggregates the whole subnet.
        assert!(
            !rl.try_admit("198.51.100.4".parse().expect("valid ip"), t0),
            "rotating IPs within one /24 must not exceed the subnet rate"
        );
    }

    #[test]
    fn bucket_refills_over_time() {
        let rl = SubnetRateLimiter::new(2.0, 1.0, 1024); // 2 burst, 1 token/sec
        let ip: IpAddr = "192.0.2.10".parse().expect("valid ip");
        let t0 = Instant::now();
        assert!(rl.try_admit(ip, t0));
        assert!(rl.try_admit(ip, t0));
        assert!(!rl.try_admit(ip, t0), "burst exhausted");
        // After one second exactly one token refills.
        let t1 = t0 + Duration::from_secs(1);
        assert!(rl.try_admit(ip, t1), "one token should have refilled");
        assert!(!rl.try_admit(ip, t1), "only one token refilled");
    }

    #[test]
    fn subnets_are_independent() {
        let rl = SubnetRateLimiter::new(1.0, 1.0, 1024);
        let t0 = Instant::now();
        assert!(rl.try_admit("203.0.113.1".parse().expect("valid ip"), t0));
        assert!(
            !rl.try_admit("203.0.113.2".parse().expect("valid ip"), t0),
            "same /24 shares the bucket"
        );
        assert!(
            rl.try_admit("203.0.114.1".parse().expect("valid ip"), t0),
            "a different /24 has its own bucket"
        );
    }

    #[test]
    fn legitimate_low_rate_peer_always_admitted() {
        // Production defaults: 10/s sustained, 40 burst. A legitimate peer
        // reconnecting ~once per second is never throttled over a long run.
        let rl = SubnetRateLimiter::new(
            INBOUND_HANDSHAKE_BURST_PER_SUBNET,
            INBOUND_HANDSHAKE_RATE_PER_SUBNET,
            MAX_TRACKED_SUBNETS,
        );
        let ip: IpAddr = "198.51.100.20".parse().expect("valid ip");
        let mut t = Instant::now();
        for _ in 0..1000 {
            assert!(
                rl.try_admit(ip, t),
                "a ~1/sec legitimate peer must never be throttled"
            );
            t += Duration::from_secs(1);
        }
    }

    #[test]
    fn idle_buckets_pruned_when_over_soft_cap() {
        // Tiny soft cap so the prune path runs. Idle (full) buckets are dropped,
        // keeping the limiter's memory bounded under a wide-source flood.
        let rl = SubnetRateLimiter::new(4.0, 1.0, 2);
        let t0 = Instant::now();
        assert!(rl.try_admit("10.0.0.1".parse().expect("valid ip"), t0));
        assert!(rl.try_admit("10.0.1.1".parse().expect("valid ip"), t0));
        // Far in the future the first two subnets have refilled to full (idle).
        let t1 = t0 + Duration::from_secs(100);
        assert!(rl.try_admit("10.0.2.1".parse().expect("valid ip"), t1));
        assert!(rl.try_admit("10.0.3.1".parse().expect("valid ip"), t1));
        let tracked = rl.buckets.lock().expect("lock").len();
        assert!(
            tracked <= 3,
            "idle buckets must be pruned to keep memory bounded, got {tracked}"
        );
    }

    #[test]
    fn hard_ceiling_bounds_map_under_active_flood() {
        // The hard case Codex flagged: every tracked subnet stays *actively*
        // throttled (burst spent, no refill), so idle-pruning alone cannot bound
        // the map — the hard ceiling must evict nearest-idle buckets regardless.
        let max_tracked = 8;
        let rl = SubnetRateLimiter::new(1.0, 0.0, max_tracked); // burst 1, no refill
        let t0 = Instant::now();
        for i in 0..200u32 {
            // 200 distinct /24s, each consuming its single token (left throttled).
            let ip: IpAddr = format!("10.0.{}.1", i & 0xff)
                .parse()
                .expect("valid ip");
            rl.try_admit(ip, t0);
            let tracked = rl.buckets.lock().expect("lock").len();
            assert!(
                tracked <= max_tracked,
                "map must never exceed the hard ceiling, got {tracked}"
            );
        }
    }
}
