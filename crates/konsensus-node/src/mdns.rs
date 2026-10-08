//! Optional LAN discovery. DNS answers are untrusted transport hints, never pins.

use crate::{config::RemoteAccessConfig, endpoints};
use anyhow::Result;
use konsensus_api::pairing::PairingService;
use mdns_sd::{IfKind, ServiceDaemon, ServiceInfo};
use std::net::{IpAddr, SocketAddr};

pub struct Advertisement {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Advertisement {
    pub fn start(
        config: &RemoteAccessConfig,
        bound: SocketAddr,
        pairing: &PairingService,
    ) -> Option<Self> {
        if !config.mdns_enabled() {
            return None;
        }
        match Self::try_start(bound, pairing) {
            Ok(advertisement) => advertisement,
            Err(error) => {
                tracing::warn!(%error, "LAN discovery unavailable; remote access remains enabled");
                None
            }
        }
    }

    fn try_start(bound: SocketAddr, pairing: &PairingService) -> Result<Option<Self>> {
        let ips: Vec<_> = endpoints::reachable(bound, &endpoints::interfaces()?)
            .into_iter()
            .filter(|ip| lan_address(*ip))
            .collect();
        if ips.is_empty() {
            return Ok(None);
        }
        let fingerprint = if pairing.bound_fingerprint().is_empty() {
            blake3::hash(&pairing.box_transport_pubkey())
                .to_hex()
                .to_string()
        } else {
            pairing.bound_fingerprint().to_owned()
        };
        let service = service_info(&fingerprint[..12], bound.port(), &ips)?;
        let advertisement = Self {
            daemon: ServiceDaemon::new()?,
            fullname: service.get_fullname().to_owned(),
        };
        // Allow only the selected LAN addresses, never all interfaces or addr_auto:
        // the latter could leak the service onto a VPN after an interface change.
        advertisement.daemon.disable_interface(IfKind::All)?;
        for ip in ips {
            advertisement.daemon.enable_interface(IfKind::Addr(ip))?;
        }
        advertisement.daemon.register(service)?;
        Ok(Some(advertisement))
    }
}

fn lan_address(ip: IpAddr) -> bool {
    endpoints::usable(ip)
        && !endpoints::is_tailscale(ip)
        && match ip {
            IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
            IpAddr::V6(ip) => ip.is_unique_local(),
        }
}

fn service_info(prefix: &str, port: u16, ips: &[IpAddr]) -> Result<ServiceInfo> {
    anyhow::ensure!(
        prefix.len() == 12 && prefix.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid discovery fingerprint prefix"
    );
    Ok(ServiceInfo::new(
        "_bitsov._tcp.local.",
        &format!("bitsov-{prefix}"),
        "bitsov.local.",
        ips,
        port,
        &[("fp", prefix)][..],
    )?)
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertisement_addresses_exclude_tailscale_loopback_and_public_routes() {
        for ip in [
            "192.168.1.3",
            "10.2.3.4",
            "172.16.1.1",
            "169.254.2.3",
            "fd00::2",
        ] {
            assert!(lan_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "100.64.0.1",
            "100.127.255.254",
            "fd7a:115c:a1e0::2",
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "224.0.0.1",
            "203.0.113.3",
            "fe80::2",
            "2001:db8::1",
        ] {
            assert!(!lan_address(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn loopback_responder_exposes_only_fingerprint_and_port() {
        use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent};
        use std::time::{Duration, Instant};
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let server = ServiceDaemon::new_with_port(port).unwrap();
        server.disable_interface(IfKind::All).unwrap();
        server.enable_interface(IfKind::LoopbackV4).unwrap();
        let client = ServiceDaemon::new_with_port(port).unwrap();
        client.disable_interface(IfKind::All).unwrap();
        client.enable_interface(IfKind::LoopbackV4).unwrap();
        let receiver = client.browse("_bitsov._tcp.local.").unwrap();
        let service = service_info("abcdef012345", 9737, &["127.0.0.1".parse().unwrap()]).unwrap();
        let name = service.get_fullname().to_owned();
        let advertisement = Advertisement {
            daemon: server,
            fullname: name.clone(),
        };
        advertisement.daemon.register(service).unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let event = receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap();
            if let ServiceEvent::ServiceResolved(info) = event {
                assert_eq!(info.get_fullname(), &name);
                assert_eq!(info.get_hostname(), "bitsov.local.");
                assert_eq!(info.get_port(), 9737);
                assert_eq!(info.get_properties().len(), 1);
                assert_eq!(info.get_property_val_str("fp"), Some("abcdef012345"));
                break;
            }
        }
        drop(advertisement);
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let event = receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap();
            if let ServiceEvent::ServiceRemoved(_, removed) = event {
                assert_eq!(removed, name);
                break;
            }
        }
        client.shutdown().unwrap();
    }
}
