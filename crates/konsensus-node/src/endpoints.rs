//! Local interface discovery for remote-access endpoint hints.

use crate::config::RemoteAccessConfig;
use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr};

pub fn interfaces() -> Result<Vec<IpAddr>> {
    Ok(if_addrs::get_if_addrs()
        .context("could not enumerate local interfaces")?
        .into_iter()
        .filter(|iface| iface.is_oper_up())
        .map(|iface| iface.ip())
        .collect())
}

pub fn discover(config: &RemoteAccessConfig, bound: SocketAddr) -> Result<Vec<String>> {
    ordered(config.advertised_endpoint.as_deref(), bound, &interfaces()?)
}

pub fn is_tailscale(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => (u32::from(ip) & 0xffc0_0000) == 0x6440_0000,
        IpAddr::V6(ip) => ip.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

pub fn usable(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(ip) => !ip.is_broadcast() && ip.octets()[0] != 0,
            // A link-local IPv6 address needs a client-local scope id, which cannot
            // be transported as a portable endpoint. IPv4 link-local is usable.
            IpAddr::V6(ip) => !ip.is_unicast_link_local(),
        }
}

pub fn reachable(bound: SocketAddr, ips: &[IpAddr]) -> Vec<IpAddr> {
    let mut candidates: Vec<_> = ips
        .iter()
        .copied()
        .filter(|ip| {
            usable(*ip)
                && (ip.is_ipv4() == bound.is_ipv4()
                    || (bound.is_ipv6() && bound.ip().is_unspecified()))
                && (bound.ip().is_unspecified() || bound.ip() == *ip)
        })
        .collect();
    // A deliberately loopback-bound listener remains useful for local tests
    // and sidecars, but must never advertise unrelated LAN interfaces.
    if bound.ip().is_loopback() {
        candidates.push(bound.ip());
    }
    candidates.sort_by_key(|ip| (is_tailscale(*ip), *ip));
    candidates.dedup();
    candidates
}

pub fn ordered(configured: Option<&str>, bound: SocketAddr, ips: &[IpAddr]) -> Result<Vec<String>> {
    let mut result = Vec::new();
    if let Some(endpoint) = configured {
        konsensus_api::remote_access::validate_endpoint(endpoint).map_err(anyhow::Error::msg)?;
        result.push(endpoint.to_owned());
    }
    for ip in reachable(bound, ips) {
        let endpoint = SocketAddr::new(ip, bound.port()).to_string();
        if !result.contains(&endpoint) {
            result.push(endpoint);
        }
    }
    anyhow::ensure!(
        !result.is_empty(),
        "no reachable remote-access endpoints; configure advertised_endpoint"
    );
    anyhow::ensure!(result.len() <= 32, "too many remote-access endpoints");
    anyhow::ensure!(
        bound.port() != 0,
        "remote-access endpoint port must be nonzero"
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdns_is_home_only_and_can_be_disabled() {
        let mut config = RemoteAccessConfig::default();
        assert!(!config.mdns_enabled());
        config.apply_home(false);
        assert!(!config.mdns_enabled());
        config.apply_home(true);
        assert_eq!(config.mdns_enabled(), cfg!(feature = "mdns"));
        let mut disabled: RemoteAccessConfig = toml::from_str("mdns = false").unwrap();
        disabled.apply_home(true);
        assert!(!disabled.mdns_enabled());
        let mut explicit: RemoteAccessConfig = toml::from_str("mdns = true").unwrap();
        explicit.apply_home(false);
        assert!(!explicit.mdns_enabled());
    }

    #[test]
    fn configured_then_sorted_lan_then_tailscale_deduplicated() {
        let ips = [
            "100.101.2.3",
            "192.168.2.9",
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "192.168.2.8",
            "192.168.2.9",
            "::1",
            "fd00::2",
        ]
        .map(|ip| ip.parse().unwrap());
        assert_eq!(
            ordered(
                Some("192.168.2.9:9737"),
                "0.0.0.0:9737".parse().unwrap(),
                &ips
            )
            .unwrap(),
            ["192.168.2.9:9737", "192.168.2.8:9737", "100.101.2.3:9737"]
        );
    }

    #[test]
    fn bind_address_and_family_limit_candidates() {
        let ips = [
            "192.168.2.8",
            "192.168.2.9",
            "fd00::2",
            "fd7a:115c:a1e0::2",
            "fe80::1",
        ]
        .map(|ip| ip.parse().unwrap());
        assert_eq!(
            ordered(None, "192.168.2.9:9737".parse().unwrap(), &ips).unwrap(),
            ["192.168.2.9:9737"]
        );
        assert_eq!(
            ordered(None, "[::]:9737".parse().unwrap(), &ips).unwrap(),
            [
                "192.168.2.8:9737",
                "192.168.2.9:9737",
                "[fd00::2]:9737",
                "[fd7a:115c:a1e0::2]:9737"
            ]
        );
        assert!(ordered(None, "0.0.0.0:9737".parse().unwrap(), &[]).is_err());
        assert!(ordered(Some("bad"), "0.0.0.0:9737".parse().unwrap(), &ips).is_err());
    }
}
