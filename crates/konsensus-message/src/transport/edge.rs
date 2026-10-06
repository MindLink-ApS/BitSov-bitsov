//! Configuration for the unpaid TCP doorway. These limits confer no admission.

/// Bounds on work and memory before a peer can present payment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DosEdgeConfig {
    /// New TCP connections per second per IP (also per IPv6 /64).
    pub connections_per_second: f64,
    pub connection_burst: u32,
    /// Noise starts per second, independently budgeted after the cookie step.
    pub handshakes_per_second: f64,
    pub handshake_burst: u32,
    /// Includes cookie exchanges and Noise/federation handshakes, never peers.
    pub max_pending: usize,
    pub max_handshakes: usize,
    pub max_per_ip: u32,
    pub max_per_subnet: u32,
    /// Maximum optimistic handshakes; remaining slots require a valid cookie.
    pub cookie_threshold: usize,
    /// Entries in each rate table. Active budgets are never evicted.
    pub max_tracked_sources: usize,
    pub cookie_timeout_secs: u64,
    /// Total deadline for cookie + Noise + federation, not renewed per read.
    pub handshake_timeout_secs: u64,
}

impl Default for DosEdgeConfig {
    fn default() -> Self {
        Self {
            connections_per_second: 10.0,
            connection_burst: 40,
            handshakes_per_second: 2.0,
            handshake_burst: 8,
            max_pending: 128,
            max_handshakes: 64,
            max_per_ip: 4,
            max_per_subnet: 8,
            cookie_threshold: 32,
            max_tracked_sources: 4096,
            cookie_timeout_secs: 3,
            handshake_timeout_secs: 10,
        }
    }
}

impl DosEdgeConfig {
    /// Reject unusable or unsafe bounds before binding the listener.
    pub fn validate(&self) -> Result<(), String> {
        if !self.connections_per_second.is_finite()
            || !self.handshakes_per_second.is_finite()
            || !(0.001..=10_000.0).contains(&self.connections_per_second)
            || !(0.001..=10_000.0).contains(&self.handshakes_per_second)
            || !(1..=100_000).contains(&self.connection_burst)
            || !(1..=100_000).contains(&self.handshake_burst)
            || !(2..=4096).contains(&self.max_pending)
            || !(2..=4096).contains(&self.max_handshakes)
            || self.max_handshakes > self.max_pending
            || self.cookie_threshold == 0
            || self.cookie_threshold >= self.max_handshakes
            || self.max_per_ip == 0
            || self.max_per_ip > self.max_per_subnet
            || self.max_per_subnet > 4096
            || !(1..=65_536).contains(&self.max_tracked_sources)
            || !(1..=30).contains(&self.cookie_timeout_secs)
            || !(1..=60).contains(&self.handshake_timeout_secs)
            || self.cookie_timeout_secs > self.handshake_timeout_secs
        {
            return Err("invalid dos_edge limits: require finite positive rates, bounded nonzero capacities, per-IP <= per-subnet <= 4096, handshakes <= pending, 0 < cookie_threshold < handshakes, and cookie timeout <= total timeout".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_rates_capacities_and_missing_reserved_capacity() {
        for field in ["connections_per_second", "handshakes_per_second"] {
            for value in [0.0, -1.0, f64::NAN, f64::INFINITY] {
                let mut config = DosEdgeConfig::default();
                if field == "connections_per_second" {
                    config.connections_per_second = value;
                } else {
                    config.handshakes_per_second = value;
                }
                assert!(config.validate().is_err());
            }
        }
        for config in [
            DosEdgeConfig {
                max_tracked_sources: 0,
                ..Default::default()
            },
            DosEdgeConfig {
                max_pending: 0,
                ..Default::default()
            },
            DosEdgeConfig {
                max_per_ip: 0,
                ..Default::default()
            },
            DosEdgeConfig {
                cookie_threshold: 64,
                ..Default::default()
            },
            DosEdgeConfig {
                cookie_timeout_secs: 11,
                ..Default::default()
            },
        ] {
            assert!(config.validate().is_err());
        }
        assert!(DosEdgeConfig::default().validate().is_ok());
    }
}
