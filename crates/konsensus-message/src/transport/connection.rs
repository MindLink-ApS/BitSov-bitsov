//! TCP listener, incoming connection handler.

use std::collections::HashMap;
#[cfg(test)]
use std::net::Ipv4Addr;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use konsensus_crypto::noise::NoiseSession;
use tokio::net::TcpListener;

use tracing::{debug, error, info, warn};

use konsensus_core::traits::transport::TransportError;

use super::handshake::{noise_handshake_responder, perform_federation_handshake_responder};
use super::messaging::spawn_reader_task;
use super::{ControlEvent, PeerConnection, TransportCtx, BAN_EVICTION_INTERVAL};

// ─── impl NoiseTransport — listener / connection management ─────────────────

use super::NoiseTransport;

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
        let ip = ip.to_canonical();
        let mut map = counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
        let mut map = self
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = map.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Collapse a source IP to its rate-limit aggregation key: the full IPv4
/// address or the IPv6 `/64` network. Aggregating here is what makes the
/// limiter resistant to an attacker who rotates addresses inside one block.
fn subnet_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
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

/// Bounded token buckets using the API rate_limit.rs mutex pattern. Like the
/// remote-access HandshakeLimiter, never forget active debt to admit a new IP.
/// Both exact addresses and subnet keys use this implementation, independently.
struct SubnetRateLimiter {
    buckets: StdMutex<HashMap<IpAddr, TokenBucket>>,
    /// Bucket size (max burst).
    capacity: f64,
    /// Sustained refill, tokens per second.
    refill_per_sec: f64,
    /// Hard ceiling; only fully replenished budgets may be forgotten.
    max_tracked: usize,
    last_cleanup: StdMutex<Option<Instant>>,
}

impl SubnetRateLimiter {
    fn new(capacity: f64, refill_per_sec: f64, max_tracked: usize) -> Self {
        Self {
            buckets: StdMutex::new(HashMap::new()),
            capacity,
            refill_per_sec,
            max_tracked,
            last_cleanup: StdMutex::new(None),
        }
    }

    /// Returns `true` if a token was available for this source's subnet (the
    /// connection may proceed), or `false` if the subnet has exceeded its rate
    /// (the caller should drop the connection cheaply, before the Noise DH).
    ///
    /// `now` is injected so the refill math is deterministically testable.
    fn try_admit(&self, ip: IpAddr, now: Instant) -> bool {
        self.try_admit_key(subnet_key(ip), now)
    }

    fn try_admit_key(&self, key: IpAddr, now: Instant) -> bool {
        let key = key.to_canonical();
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if self.max_tracked == 0 {
            return false;
        }
        if map.len() >= self.max_tracked && !map.contains_key(&key) {
            // At most one bounded scan per second, including under IP churn.
            let mut last = self.last_cleanup.lock().unwrap_or_else(|e| e.into_inner());
            if last.is_none_or(|t| now.saturating_duration_since(t).as_secs() >= 1) {
                map.retain(|_, b| {
                    b.tokens
                        + now.saturating_duration_since(b.last_refill).as_secs_f64()
                            * self.refill_per_sec
                        < self.capacity
                });
                *last = Some(now);
            }
            if map.len() >= self.max_tracked {
                return false;
            }
        }

        let cap = self.capacity;
        let refill = self.refill_per_sec;
        let bucket = map.entry(key).or_insert_with(|| TokenBucket {
            tokens: cap,
            last_refill: now,
        });
        // Shared handshake callers may capture time before acquiring this lock.
        // Never rewind the refill clock if those calls are scheduled out of order.
        let now = now.max(bucket.last_refill);
        let elapsed = now
            .saturating_duration_since(bucket.last_refill)
            .as_secs_f64();
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

/// Apply both source budgets together so their ordering is testable.
struct SourceRateLimiter {
    ips: SubnetRateLimiter,
    subnets: SubnetRateLimiter,
}

impl SourceRateLimiter {
    fn new(capacity: f64, rate: f64, max_tracked: usize) -> Self {
        Self {
            ips: SubnetRateLimiter::new(capacity, rate, max_tracked),
            subnets: SubnetRateLimiter::new(capacity, rate, max_tracked),
        }
    }

    fn try_admit(&self, ip: IpAddr, now: Instant) -> bool {
        // A rejected /64 must not allocate an exact-IP entry for every rotated
        // host address and thereby deny unrelated sources the bounded table.
        self.subnets.try_admit(ip, now) && self.ips.try_admit_key(ip, now)
    }
}

impl NoiseTransport {
    /// Start the TCP listener for incoming connections.
    ///
    /// Spawns a background task that accepts connections, performs the Noise + federation
    /// handshake, and registers authenticated peers.
    pub async fn start_listener(&self) -> Result<(), TransportError> {
        self.config
            .dos_edge
            .validate()
            .map_err(TransportError::Rejected)?;
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
            dial_locks: Arc::clone(&self.dial_locks),
            shutdown: self.shutdown.subscribe(),
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
            let limits = &ctx.config.dos_edge;
            let pending = Arc::new(tokio::sync::Semaphore::new(limits.max_pending));
            let handshakes = Arc::new(tokio::sync::Semaphore::new(limits.max_handshakes));
            let optimistic = Arc::new(tokio::sync::Semaphore::new(limits.cookie_threshold));
            let per_ip_counts: PerIpCounts = Arc::new(StdMutex::new(HashMap::new()));
            let per_subnet_counts: PerIpCounts = Arc::new(StdMutex::new(HashMap::new()));
            let connections = SourceRateLimiter::new(
                limits.connection_burst as f64,
                limits.connections_per_second,
                limits.max_tracked_sources,
            );
            let noise_rates = Arc::new(SourceRateLimiter::new(
                limits.handshake_burst as f64,
                limits.handshakes_per_second,
                limits.max_tracked_sources,
            ));
            let mut under_load_until = Instant::now();
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                // Reap completed tasks before admitting another socket;
                                // JoinSet outputs are also part of the memory bound.
                                while tasks.try_join_next().is_some() {}
                                let now = Instant::now();
                                let ip = addr.ip().to_canonical();
                                // Charge all accepted sockets, even ones subsequently refused.
                                // No task, Noise session or peer state exists at this point.
                                if !connections.try_admit(ip, now) {
                                    under_load_until = now + std::time::Duration::from_secs(1);
                                    continue;
                                }
                                let Ok(pending_slot) = pending.clone().try_acquire_owned() else {
                                    under_load_until = now + std::time::Duration::from_secs(1);
                                    continue;
                                };
                                let Some(ip_guard) = PerIpGuard::try_acquire(&per_ip_counts, ip, ctx.config.dos_edge.max_per_ip) else {
                                    under_load_until = now + std::time::Duration::from_secs(1);
                                    continue;
                                };
                                let Some(subnet_guard) = PerIpGuard::try_acquire(&per_subnet_counts, subnet_key(ip), ctx.config.dos_edge.max_per_subnet) else {
                                    under_load_until = now + std::time::Duration::from_secs(1);
                                    continue;
                                };
                                let optimistic_slot = if ctx.config.cookie_mode == super::CookieMode::Adaptive && now >= under_load_until {
                                    optimistic.clone().try_acquire_owned().ok()
                                } else {
                                    None
                                };
                                let require_cookie = match ctx.config.cookie_mode {
                                    super::CookieMode::Disabled => false,
                                    super::CookieMode::Required => true,
                                    super::CookieMode::Adaptive => optimistic_slot.is_none(),
                                };
                                let ctx = ctx.clone();
                                let handshakes = handshakes.clone();
                                let noise_rates = noise_rates.clone();
                                tasks.spawn(async move {
                                    let _pending_slot = pending_slot;
                                    let _ip_guard = ip_guard;
                                    let _subnet_guard = subnet_guard;
                                    let _optimistic_slot = optimistic_slot;
                                    let deadline = std::time::Duration::from_secs(ctx.config.dos_edge.handshake_timeout_secs);
                                    let result = tokio::time::timeout(deadline, handle_incoming(
                                        stream, addr, ctx, require_cookie, handshakes, noise_rates,
                                    )).await;
                                    // Floods must not amplify into warning-log/disk floods.
                                    if !matches!(result, Ok(Ok(()))) {
                                        debug!(%addr, "inbound handshake refused or timed out");
                                    }
                                });
                            }
                            Err(e) => {
                                error!(error = %e, "accept failed");
                            }
                        }
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {}
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
        self.shutdown.send_replace(true);
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
async fn handle_incoming(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    ctx: TransportCtx,
    require_cookie: bool,
    handshakes: Arc<tokio::sync::Semaphore>,
    noise_rates: Arc<SourceRateLimiter>,
) -> Result<(), TransportError> {
    let (mut reader, mut writer) = stream.into_split();

    // The cookie has no stored challenge record. Only bounded TCP/framing
    // resources exist here; no Noise/DH or peer registration before verification.
    if require_cookie {
        tokio::time::timeout(
            std::time::Duration::from_secs(ctx.config.dos_edge.cookie_timeout_secs),
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
                ctx.config.dos_edge.cookie_timeout_secs
            ))
        })??;
    }

    // Never wait in an unbounded queue for expensive work. Optimistic callers
    // can occupy at most cookie_threshold slots; verified callers use the rest.
    let _handshake_slot = handshakes
        .try_acquire_owned()
        .map_err(|_| TransportError::Rejected("global handshake limit".into()))?;
    let now = Instant::now();
    if !noise_rates.try_admit(addr.ip(), now) {
        return Err(TransportError::Rejected(
            "source handshake rate limit".into(),
        ));
    }

    // Noise handshake as responder — with timeout to prevent slot exhaustion
    let noise = NoiseSession::responder(ctx.identity.x25519_secret_bytes())
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;

    let (reader, writer, noise) = noise_handshake_responder(reader, writer, noise).await?;

    // The outer deadline spans cookie, Noise and federation. A slow client
    // cannot renew its budget at each phase. Payment admission is unchanged.
    let (peer_node_id, tier, capabilities, reader, writer, noise, privileged) =
        perform_federation_handshake_responder(
            reader,
            writer,
            noise,
            &ctx.identity,
            &ctx.config,
            &ctx.whitelist,
        )
        .await?;

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

    // Reserve lifecycle delivery before registration. The total deadline may
    // cancel this wait, but must never leave a registered peer without its event.
    let connected_event = ctx
        .control_tx
        .reserve()
        .await
        .map_err(|_| TransportError::Rejected("connection event receiver closed".into()))?;

    // Register connection
    let now = Instant::now();
    let conn = super::Connection::new(
        PeerConnection {
            advertised_trust_discount: None,
            source_ip: addr.ip(),
            privileged,
            noise,
            writer,
            tier,
            capabilities,
            connected_at: now,
            last_recv: now,
            pending_ping: None,
            invalid_frame_level: 0.0,
            invalid_frame_last_leak: now,
            bytes_received: 0,
            memory_budget_window_start: now,
        },
        peer_node_id,
        Arc::clone(&ctx.peers),
        false,
    )?;

    if !conn
        .register(ctx.identity.node_id(), &peer_node_id, &ctx.peers)
        .await
    {
        return Ok(());
    }

    // Spawn reader task
    spawn_reader_task(peer_node_id, reader, conn, ctx.clone());

    // Notify application layer of new peer connection. M1b: carry the privilege
    // tag so the session handler does NOT volunteer X3DH/onboarding to a stranger
    // (PriceOpen, privileged == false) until they pay (promote-on-paid).
    connected_event.send(ControlEvent::PeerConnected {
        peer_id: peer_node_id,
        privileged,
    });

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
            let _g = PerIpGuard::try_acquire(&counts, ip, 4);
            assert_eq!(*counts.lock().expect("lock").get(&ip).expect("entry"), 1);
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
    fn subnet_key_preserves_ipv4_and_masks_ipv6_to_64() {
        let a: IpAddr = "203.0.113.7".parse().expect("valid ip");
        let b: IpAddr = "203.0.113.250".parse().expect("valid ip");
        assert_ne!(
            subnet_key(a),
            subnet_key(b),
            "IPv4 neighbors have independent budgets"
        );
        assert_eq!(subnet_key(a), a);

        let c: IpAddr = "203.0.114.7".parse().expect("valid ip");
        assert_ne!(subnet_key(a), subnet_key(c), "different /24 must differ");

        let v6a: IpAddr = "2001:db8:abcd:1234::1".parse().expect("valid ip");
        let v6b: IpAddr = "2001:db8:abcd:1234:ffff::9".parse().expect("valid ip");
        assert_eq!(
            subnet_key(v6a),
            subnet_key(v6b),
            "same /64 must share a key"
        );
        let v6c: IpAddr = "2001:db8:abcd:9999::1".parse().expect("valid ip");
        assert_ne!(
            subnet_key(v6a),
            subnet_key(v6c),
            "different /64 must differ"
        );
    }

    #[test]
    fn burst_from_same_subnet_is_capped_even_across_rotating_ips() {
        // capacity 3, refill 1/s. Rotating the host bits stays inside one /64.
        let rl = SubnetRateLimiter::new(3.0, 1.0, 1024);
        let t0 = Instant::now();
        assert!(rl.try_admit("2001:db8::1".parse().expect("valid ip"), t0));
        assert!(rl.try_admit("2001:db8::2".parse().expect("valid ip"), t0));
        assert!(rl.try_admit("2001:db8::3".parse().expect("valid ip"), t0));
        // A fourth rotated IP in the SAME /64 is throttled — rotation does not win,
        // because the bucket aggregates the whole subnet.
        assert!(
            !rl.try_admit("2001:db8::4".parse().expect("valid ip"), t0),
            "rotating IPs within one /64 must not exceed the subnet rate"
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
            !rl.try_admit("203.0.113.1".parse().expect("valid ip"), t0),
            "same IPv4 shares the bucket"
        );
        assert!(
            rl.try_admit("203.0.114.1".parse().expect("valid ip"), t0),
            "a different IPv4 has its own bucket"
        );
    }

    #[test]
    fn legitimate_low_rate_peer_always_admitted() {
        // Production defaults: 10/s sustained, 40 burst. A legitimate peer
        // reconnecting ~once per second is never throttled over a long run.
        let rl = SubnetRateLimiter::new(40.0, 10.0, 4096);
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
        // Every tracked source has active debt. New sources must be refused
        // without growing the table or forgetting an existing budget.
        let max_tracked = 8;
        let rl = SubnetRateLimiter::new(1.0, 0.0, max_tracked); // burst 1, no refill
        let t0 = Instant::now();
        for i in 0..200u32 {
            // 200 distinct /24s, each consuming its single token (left throttled).
            let ip: IpAddr = format!("10.0.{}.1", i & 0xff).parse().expect("valid ip");
            rl.try_admit(ip, t0);
            let tracked = rl.buckets.lock().expect("lock").len();
            assert!(
                tracked <= max_tracked,
                "map must never exceed the hard ceiling, got {tracked}"
            );
        }
    }
}

#[cfg(test)]
mod edge_regressions {
    use super::*;

    #[test]
    fn scheduler_reordering_cannot_refill_twice() {
        let limiter = SubnetRateLimiter::new(1.0, 1.0, 4);
        let now = Instant::now();
        let ip = "192.0.2.1".parse().unwrap();
        assert!(limiter.try_admit(ip, now));
        assert!(limiter.try_admit(ip, now + std::time::Duration::from_secs(1)));
        assert!(!limiter.try_admit(ip, now));
        assert!(!limiter.try_admit(ip, now + std::time::Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn full_event_queue_cannot_leave_a_registered_peer_without_event() {
        use konsensus_core::identity::NodeIdentity;
        use konsensus_core::traits::transport::MessageTransport;
        let alice = Arc::new(NodeIdentity::generate().unwrap().1);
        let bob = Arc::new(NodeIdentity::generate().unwrap().1);
        let mut config = super::super::TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            whitelist: vec![*alice.node_id()],
            ..Default::default()
        };
        config.dos_edge.handshake_timeout_secs = 1;
        config.dos_edge.cookie_timeout_secs = 1;
        let responder = NoiseTransport::new(bob.clone(), config);
        responder.start_listener().await.unwrap();
        while responder
            .control_tx
            .try_send(ControlEvent::PeerConnected {
                peer_id: *bob.node_id(),
                privileged: false,
            })
            .is_ok()
        {}
        let initiator = NoiseTransport::new(
            alice.clone(),
            super::super::TransportConfig {
                whitelist: vec![*bob.node_id()],
                ..Default::default()
            },
        );
        initiator
            .connect(bob.node_id(), &responder.listen_addr().unwrap().to_string())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        assert!(
            !responder.is_connected(alice.node_id()).await,
            "deadline must drop an unannounced connection before peer registration"
        );
        responder.shutdown();
        initiator.shutdown();
    }

    #[test]
    fn rejected_ipv6_rotation_cannot_fill_the_exact_ip_table() {
        let limiter = SourceRateLimiter::new(1.0, 1.0, 4);
        let now = Instant::now();
        assert!(limiter.try_admit("2001:db8:1::1".parse().unwrap(), now));
        for host in 2..100 {
            assert!(!limiter.try_admit(format!("2001:db8:1::{host}").parse().unwrap(), now));
        }
        assert!(
            limiter.try_admit("2001:db8:2::1".parse().unwrap(), now),
            "a flood from one /64 must not fill the exact-IP table"
        );
        assert_eq!(limiter.ips.buckets.lock().unwrap().len(), 2);
    }

    #[test]
    fn ipv4_flood_does_not_spend_neighbors_budget() {
        let limiter = SubnetRateLimiter::new(1.0, 1.0, 8);
        let now = Instant::now();
        assert!(limiter.try_admit("192.0.2.1".parse().unwrap(), now));
        assert!(!limiter.try_admit("192.0.2.1".parse().unwrap(), now));
        assert!(limiter.try_admit("192.0.2.2".parse().unwrap(), now));
    }

    #[test]
    fn one_entry_table_never_grows_or_forgets_active_debt() {
        let limiter = SubnetRateLimiter::new(1.0, 1.0, 1);
        let now = Instant::now();
        let first = "192.0.2.1".parse().unwrap();
        assert!(limiter.try_admit(first, now));
        for n in 0..100 {
            let other = IpAddr::V4(Ipv4Addr::new(10, n, 0, 1));
            assert!(!limiter.try_admit(other, now));
            assert_eq!(limiter.buckets.lock().unwrap().len(), 1);
            assert!(!limiter.try_admit(first, now));
        }
        assert!(limiter.try_admit(
            "198.51.100.1".parse().unwrap(),
            now + std::time::Duration::from_secs(1)
        ));
    }

    #[test]
    fn mapped_ipv4_cannot_bypass_source_concurrency() {
        let counts = Arc::new(StdMutex::new(HashMap::new()));
        let _guard = PerIpGuard::try_acquire(&counts, "192.0.2.1".parse().unwrap(), 1).unwrap();
        assert!(PerIpGuard::try_acquire(&counts, "::ffff:192.0.2.1".parse().unwrap(), 1).is_none());
    }
}
