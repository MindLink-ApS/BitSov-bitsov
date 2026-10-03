//! Ephemeral quarantine counters, never peer/contact/session records or quotes.
//! Hashes prevent repeat issuance within an attempt's validity; hard bounds
//! refuse new work rather than evicting live rate/replay guards.
use konsensus_core::{admission_quote, NodeId};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::IpAddr, time::Duration};
use tokio::time::Instant;
const WINDOW: Duration = Duration::from_secs(10);
const GLOBAL_BURST: usize = 16;
const MAX_GUARDS: usize = 1024;
pub(crate) struct AdmissionQuotes {
    sources: HashMap<IpAddr, Instant>,
    attempts: HashMap<[u8; 32], u64>,
    window: Instant,
    count: usize,
    started_at_unix: u64,
}
impl Default for AdmissionQuotes {
    fn default() -> Self {
        Self {
            sources: HashMap::new(),
            attempts: HashMap::new(),
            window: Instant::now(),
            count: 0,
            started_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}
impl AdmissionQuotes {
    pub(crate) fn permit(
        &mut self,
        source: IpAddr,
        recipient: &NodeId,
        sender: &NodeId,
        id: &str,
        now: Instant,
        unix: u64,
    ) -> bool {
        let Some(expiry) = admission_quote::expires_at(id, recipient, sender, unix) else {
            return false;
        };
        // No durable replay database for strangers. An attempt issued before
        // this process started cannot reopen after restart. Strict comparison
        // also closes same-second restarts (one second of startup quarantine).
        if expiry - u64::from(admission_quote::EXPIRY_SECS) <= self.started_at_unix {
            return false;
        }
        let source = match source {
            IpAddr::V6(ip) => ip.to_ipv4().map(IpAddr::V4).unwrap_or(source),
            _ => source,
        };
        self.sources
            .retain(|_, last| now.saturating_duration_since(*last) < WINDOW);
        self.attempts.retain(|_, end| *end > unix);
        if now.saturating_duration_since(self.window) >= WINDOW {
            self.window = now;
            self.count = 0;
        }
        let digest: [u8; 32] = Sha256::digest(id.as_bytes()).into();
        if self.count >= GLOBAL_BURST
            || self.sources.contains_key(&source)
            || self.attempts.contains_key(&digest)
            || self.sources.len() >= MAX_GUARDS
            || self.attempts.len() >= MAX_GUARDS
        {
            return false;
        }
        self.sources.insert(source, now);
        self.attempts.insert(digest, expiry);
        self.count += 1;
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_identity_rotation_global_flood_and_replay_are_bounded() {
        let mut q = AdmissionQuotes {
            started_at_unix: 99,
            ..Default::default()
        };
        let t = Instant::now();
        let target = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let id = admission_quote::request_id(&target, &peer, 100);
        assert!(q.permit(ip, &target, &peer, &id, t, 100));
        let other = NodeId::from_bytes([3; 32]);
        assert!(!q.permit(
            ip,
            &target,
            &other,
            &admission_quote::request_id(&target, &other, 100),
            t,
            100
        ));
        assert!(!q.permit(
            "::ffff:127.0.0.1".parse().unwrap(),
            &target,
            &other,
            &admission_quote::request_id(&target, &other, 100),
            t,
            100
        ));
        for i in 1..16 {
            assert!(q.permit(
                IpAddr::from([192, 0, 2, i]),
                &target,
                &peer,
                &admission_quote::request_id(&target, &peer, 100),
                t,
                100
            ));
        }
        assert!(!q.permit(
            IpAddr::from([192, 0, 2, 99]),
            &target,
            &peer,
            &admission_quote::request_id(&target, &peer, 100),
            t,
            100
        ));
        assert!(q.sources.len() <= 16 && q.attempts.len() <= 16);
        assert!(
            !q.permit(ip, &target, &peer, &id, t + WINDOW, 110),
            "same attempt cannot mint another invoice after source cooldown"
        );
        assert!(
            !q.permit(ip, &target, &peer, &id, t + Duration::from_secs(300), 400),
            "expired nonce never reopens"
        );
        assert!(q.permit(
            ip,
            &target,
            &peer,
            &admission_quote::request_id(&target, &peer, 400),
            t + Duration::from_secs(300),
            400
        ));
    }
}

#[cfg(test)]
mod restart_tests {
    use super::*;
    #[test]
    fn restart_never_reopens_a_live_attempt() {
        let target = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        let source = "127.0.0.1".parse().unwrap();
        let now = Instant::now();
        let id = admission_quote::request_id(&target, &peer, 100);
        let mut before = AdmissionQuotes {
            started_at_unix: 99,
            ..Default::default()
        };
        assert!(before.permit(source, &target, &peer, &id, now, 100));
        for restart in [100, 110] {
            let mut after = AdmissionQuotes {
                started_at_unix: restart,
                ..Default::default()
            };
            assert!(!after.permit(source, &target, &peer, &id, now, restart));
            let fresh = admission_quote::request_id(&target, &peer, restart + 1);
            assert!(after.permit(source, &target, &peer, &fresh, now, restart + 1));
        }
    }
}
