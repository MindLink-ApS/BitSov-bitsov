//! Bound refusal traffic across identities and source addresses.
use konsensus_core::NodeId;
use std::{collections::HashMap, net::IpAddr, time::Duration};
use tokio::time::Instant;

const WINDOW: Duration = Duration::from_secs(1);
const SOURCE_BURST: usize = 4;
const GLOBAL_BURST: usize = 32;
const MAX_SOURCES: usize = 1024;

#[derive(Default)]
pub(crate) struct RefusalLimits {
    sources: HashMap<IpAddr, (Instant, usize)>,
    global: Option<(Instant, usize)>,
    events: HashMap<NodeId, Instant>,
}
impl RefusalLimits {
    pub(crate) fn permit(&mut self, source: IpAddr, now: Instant) -> bool {
        let source = match source {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(source),
            _ => source,
        };
        self.sources
            .retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
        let global = self.global.get_or_insert((now, 0));
        if now.duration_since(global.0) >= WINDOW {
            *global = (now, 0);
        }
        if global.1 >= GLOBAL_BURST
            || (!self.sources.contains_key(&source) && self.sources.len() >= MAX_SOURCES)
        {
            return false;
        }
        let count = self.sources.entry(source).or_insert((now, 0));
        if count.1 >= SOURCE_BURST {
            return false;
        }
        count.1 += 1;
        global.1 += 1;
        true
    }
    pub(crate) fn event(
        &mut self,
        peer: &NodeId,
        now: Instant,
        membrane: &konsensus_api::membrane::Membrane,
    ) {
        self.events
            .retain(|_, at| now.duration_since(*at) < Duration::from_secs(10));
        if self.events.len() < 32 && !self.events.contains_key(peer) {
            self.events.insert(*peer, now);
            membrane.admission_required(peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refusal_source_limit_survives_identity_rotation_and_normalizes_mapped_ips() {
        let mut limits = RefusalLimits::default();
        let now = Instant::now();
        for _ in 0..SOURCE_BURST {
            assert!(limits.permit("127.0.0.1".parse().unwrap(), now));
        }
        assert!(!limits.permit("::ffff:127.0.0.1".parse().unwrap(), now));
        assert!(limits.permit("127.0.0.2".parse().unwrap(), now));
        assert!(limits.permit("127.0.0.1".parse().unwrap(), now + WINDOW));
    }
    #[test]
    fn refusal_global_limit_bounds_rotating_sources_and_memory() {
        let mut limits = RefusalLimits::default();
        let now = Instant::now();
        for i in 0..GLOBAL_BURST {
            assert!(limits.permit(IpAddr::from([10, 0, 0, i as u8]), now));
        }
        for i in 0..10000u32 {
            assert!(!limits.permit(IpAddr::V4(std::net::Ipv4Addr::from(i)), now));
        }
        assert_eq!(limits.sources.len(), GLOBAL_BURST);
    }
}
