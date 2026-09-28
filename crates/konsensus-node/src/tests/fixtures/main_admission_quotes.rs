// Compatibility oracle from main 696d57a4e7c427a086538118933e6a562132050d.
// Ephemeral quarantine counters, never peer/contact/session records or quotes.
// Hashes prevent repeat issuance within an attempt's validity; hard bounds
// refuse new work rather than evicting live rate/replay guards.
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
