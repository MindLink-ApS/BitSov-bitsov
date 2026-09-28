//! Bounded volatile receptor counters and request-ID digests, never records of
//! peers, contacts, sessions or pending payments. Live guards are never evicted.
use crate::config::{ReceptorActConfig, ReceptorConfig};
use konsensus_core::{admission_quote, NodeId};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::IpAddr, time::Duration};
use tokio::time::Instant;
const MAX_GUARDS: usize = 1024;
const GLOBAL_BURST: usize = 16;
const WINDOW: Duration = Duration::from_secs(10);

pub(crate) struct AdmissionQuotes {
    config: ReceptorConfig,
    shared_sources: HashMap<IpAddr, Instant>,
    shared_window: (Instant, usize),
    sources: HashMap<(u16, IpAddr), (Instant, usize)>,
    attempts: HashMap<[u8; 32], u64>,
    windows: HashMap<u16, (Instant, usize)>,
    started_at_unix: u64,
}
impl Default for AdmissionQuotes {
    fn default() -> Self {
        Self::new(ReceptorConfig::default())
    }
}
impl AdmissionQuotes {
    pub(crate) fn new(config: ReceptorConfig) -> Self {
        let now = Instant::now();
        let windows = config
            .acts
            .iter()
            .filter(|act| act.enabled)
            .map(|act| (act.kind, (now, 0)))
            .collect();
        Self {
            config,
            shared_sources: HashMap::new(),
            shared_window: (now, 0),
            sources: HashMap::new(),
            attempts: HashMap::new(),
            windows,
            started_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub(crate) fn act(&self, kind: u16) -> Option<&ReceptorActConfig> {
        let mut matching = self.config.acts.iter().filter(|act| act.kind == kind);
        let act = matching.next()?;
        (matching.next().is_none()
            && act.enabled
            && act.window_secs > 0
            && act.per_source > 0
            && act.global > 0)
            .then_some(act)
    }

    pub(crate) fn omit_route_hints(&self, kind: u16) -> bool {
        kind != konsensus_core::kind::KIND_CHAT
            && matches!(
                self.config.route_hints,
                crate::config::ReceptorRouteHints::None
            )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn permit_act(
        &mut self,
        kind: u16,
        source: IpAddr,
        recipient: &NodeId,
        sender: &NodeId,
        id: &str,
        now: Instant,
        unix: u64,
    ) -> bool {
        let Some(act) = self.act(kind).cloned() else {
            return false;
        };
        let Some(expiry) = admission_quote::expires_at(id, recipient, sender, unix) else {
            return false;
        };
        // Startup quarantine prevents a live attempt reopening after restart,
        // including restarts within the same second, without a durable database.
        if expiry - u64::from(admission_quote::EXPIRY_SECS) <= self.started_at_unix {
            return false;
        }
        let source = match source {
            IpAddr::V6(ip) => ip.to_ipv4().map(IpAddr::V4).unwrap_or(source),
            _ => source,
        };
        self.sources.retain(|(kind, _), (last, _)| {
            self.config
                .acts
                .iter()
                .find(|a| a.kind == *kind)
                .is_some_and(|a| {
                    now.saturating_duration_since(*last) < Duration::from_secs(a.window_secs)
                })
        });
        self.shared_sources
            .retain(|_, start| now.saturating_duration_since(*start) < WINDOW);
        self.attempts.retain(|_, end| *end > unix);
        if now.saturating_duration_since(self.shared_window.0) >= WINDOW {
            self.shared_window = (now, 0);
        }
        // F1 resets the requested act's window before replay/source refusal.
        // A refused request at the boundary must still start the next window.
        let current = self.windows.entry(kind).or_insert((now, 0));
        if now.saturating_duration_since(current.0) >= Duration::from_secs(act.window_secs) {
            *current = (now, 0);
        }
        let digest: [u8; 32] = Sha256::digest(id.as_bytes()).into();
        let key = (kind, source);
        if self.shared_window.1 >= GLOBAL_BURST
            || self.shared_sources.contains_key(&source)
            || self.shared_sources.len() >= MAX_GUARDS
            || self
                .windows
                .get(&kind)
                .is_some_and(|(_, n)| *n >= act.global)
            || self
                .sources
                .get(&key)
                .is_some_and(|(_, n)| *n >= act.per_source)
            || self.attempts.contains_key(&digest)
            || (self.sources.len() >= MAX_GUARDS && !self.sources.contains_key(&key))
            || self.attempts.len() >= MAX_GUARDS
        {
            return false;
        }
        // All shared/per-act budgets, guard capacity and replay checks passed.
        // Only successful permits consume any budget or request ID.
        self.shared_sources.insert(source, now);
        self.shared_window.1 += 1;
        // Per-source fixed window begins at its first permitted request.
        let source_count = self.sources.entry(key).or_insert((now, 0));
        source_count.1 += 1;
        self.attempts.insert(digest, expiry);
        self.windows.entry(kind).or_insert((now, 0)).1 += 1;
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
        assert!(q.permit_act(
            konsensus_core::kind::KIND_CHAT,
            ip,
            &target,
            &peer,
            &id,
            t,
            100
        ));
        let other = NodeId::from_bytes([3; 32]);
        assert!(!q.permit_act(
            konsensus_core::kind::KIND_CHAT,
            ip,
            &target,
            &other,
            &admission_quote::request_id(&target, &other, 100),
            t,
            100
        ));
        assert!(!q.permit_act(
            konsensus_core::kind::KIND_CHAT,
            "::ffff:127.0.0.1".parse().unwrap(),
            &target,
            &other,
            &admission_quote::request_id(&target, &other, 100),
            t,
            100
        ));
        for i in 1..16 {
            assert!(q.permit_act(
                konsensus_core::kind::KIND_CHAT,
                IpAddr::from([192, 0, 2, i]),
                &target,
                &peer,
                &admission_quote::request_id(&target, &peer, 100),
                t,
                100
            ));
        }
        assert!(!q.permit_act(
            konsensus_core::kind::KIND_CHAT,
            IpAddr::from([192, 0, 2, 99]),
            &target,
            &peer,
            &admission_quote::request_id(&target, &peer, 100),
            t,
            100
        ));
        assert!(q.sources.len() <= 16 && q.attempts.len() <= 16);
        assert!(
            !q.permit_act(
                konsensus_core::kind::KIND_CHAT,
                ip,
                &target,
                &peer,
                &id,
                t + WINDOW,
                110
            ),
            "same attempt cannot mint another invoice after source cooldown"
        );
        assert!(
            !q.permit_act(
                konsensus_core::kind::KIND_CHAT,
                ip,
                &target,
                &peer,
                &id,
                t + Duration::from_secs(60),
                160
            ),
            "expired nonce never reopens"
        );
        assert!(q.permit_act(
            konsensus_core::kind::KIND_CHAT,
            ip,
            &target,
            &peer,
            &admission_quote::request_id(&target, &peer, 160),
            t + Duration::from_secs(60),
            160
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
        assert!(before.permit_act(
            konsensus_core::kind::KIND_CHAT,
            source,
            &target,
            &peer,
            &id,
            now,
            100
        ));
        for restart in [100, 110] {
            let mut after = AdmissionQuotes {
                started_at_unix: restart,
                ..Default::default()
            };
            assert!(!after.permit_act(
                konsensus_core::kind::KIND_CHAT,
                source,
                &target,
                &peer,
                &id,
                now,
                restart
            ));
            let fresh = admission_quote::request_id(&target, &peer, restart + 1);
            assert!(after.permit_act(
                konsensus_core::kind::KIND_CHAT,
                source,
                &target,
                &peer,
                &fresh,
                now,
                restart + 1
            ));
        }
    }
}

#[cfg(test)]
mod receptor_tests {
    use super::*;

    fn two_acts() -> AdmissionQuotes {
        let config =
            toml::from_str("[[acts]]\nkind=0\nenabled=true\n[[acts]]\nkind=200\nenabled=true")
                .unwrap();
        let mut q = AdmissionQuotes::new(config);
        q.started_at_unix = 99;
        q
    }

    #[test]
    fn shared_budget_caps_reviewer_32_permit_probe() {
        let mut q = two_acts();
        let t = Instant::now();
        let target = NodeId::from_bytes([1; 32]);
        let mut accepted = 0;
        for kind in [0, 200] {
            for i in 1..=16u8 {
                let sender = NodeId::from_bytes([i + (kind / 10) as u8; 32]);
                let id = admission_quote::request_id(&target, &sender, 100);
                accepted += usize::from(q.permit_act(
                    kind,
                    IpAddr::from([192, 0, 2, i]),
                    &target,
                    &sender,
                    &id,
                    t,
                    100,
                ));
            }
        }
        assert_eq!(
            accepted, 16,
            "act and identity rotation must not multiply the envelope"
        );
    }

    #[test]
    fn shared_budget_bounds_rotating_acts_sources_and_identities() {
        let mut q = two_acts();
        let t = Instant::now();
        let target = NodeId::from_bytes([1; 32]);
        for i in 1..=17u8 {
            let sender = NodeId::from_bytes([i; 32]);
            let kind = if i % 2 == 0 { 0 } else { 200 };
            let id = admission_quote::request_id(&target, &sender, 100);
            assert_eq!(
                q.permit_act(
                    kind,
                    IpAddr::from([192, 0, 2, i]),
                    &target,
                    &sender,
                    &id,
                    t,
                    100
                ),
                i <= 16
            );
            let rotated = NodeId::from_bytes([i + 50; 32]);
            let fresh = admission_quote::request_id(&target, &rotated, 100);
            assert!(!q.permit_act(
                200 - kind,
                IpAddr::from([192, 0, 2, i]),
                &target,
                &rotated,
                &fresh,
                t,
                100
            ));
        }
        let id = admission_quote::request_id(&target, &target, 110);
        assert!(q.permit_act(
            200,
            IpAddr::from([192, 0, 2, 1]),
            &target,
            &target,
            &id,
            t + WINDOW,
            110
        ));
    }

    #[test]
    fn chat_window_resets_before_a_replay_refusal_as_in_f1() {
        let mut q = AdmissionQuotes {
            started_at_unix: 99,
            ..Default::default()
        };
        let t = q.windows[&0].0;
        let target = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        let source = "127.0.0.1".parse().unwrap();
        let id = admission_quote::request_id(&target, &peer, 100);
        assert!(q.permit_act(
            0,
            source,
            &target,
            &peer,
            &id,
            t + Duration::from_secs(1),
            100
        ));
        assert!(!q.permit_act(
            0,
            source,
            &target,
            &peer,
            &id,
            t + Duration::from_secs(11),
            110
        ));
        for i in 1..=16 {
            let fresh = admission_quote::request_id(&target, &peer, 114);
            assert!(q.permit_act(
                0,
                IpAddr::from([192, 0, 2, i]),
                &target,
                &peer,
                &fresh,
                t + Duration::from_secs(15),
                114
            ));
        }
        let fresh = admission_quote::request_id(&target, &peer, 120);
        assert!(
            q.permit_act(
                0,
                source,
                &target,
                &peer,
                &fresh,
                t + Duration::from_secs(21),
                120
            ),
            "F1 reset the global window on the refused replay at t=11"
        );
    }

    #[test]
    fn rejected_act_does_not_consume_shared_or_other_act_budgets() {
        let mut q = two_acts();
        for act in &mut q.config.acts {
            act.global = 1;
        }
        let t = Instant::now();
        let target = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        let source = IpAddr::from([192, 0, 2, 1]);
        let other = IpAddr::from([192, 0, 2, 2]);
        let fresh = || admission_quote::request_id(&target, &peer, 100);
        let id = fresh();
        assert!(q.permit_act(200, source, &target, &peer, &id, t, 100));
        // Replay must not reserve the other source or the chat budget.
        assert!(!q.permit_act(0, other, &target, &peer, &id, t, 100));
        // Exhausted shared source must not consume chat's only permit.
        assert!(!q.permit_act(0, source, &target, &peer, &fresh(), t, 100));
        // Exhausted act must not consume the other source's shared permit or ID.
        let retry = fresh();
        assert!(!q.permit_act(200, other, &target, &peer, &retry, t, 100));
        assert!(q.permit_act(0, other, &target, &peer, &retry, t, 100));
    }

    #[test]
    fn shared_global_rejection_does_not_consume_longer_act_budget() {
        let mut q = two_acts();
        q.config.acts[1].window_secs = 20;
        q.config.acts[1].global = 1;
        let t = Instant::now();
        let target = NodeId::from_bytes([1; 32]);
        for i in 1..=16 {
            let id = admission_quote::request_id(&target, &target, 100);
            assert!(q.permit_act(
                0,
                IpAddr::from([192, 0, 2, i]),
                &target,
                &target,
                &id,
                t,
                100
            ));
        }
        let id = admission_quote::request_id(&target, &target, 100);
        let source = IpAddr::from([192, 0, 2, 17]);
        assert!(!q.permit_act(200, source, &target, &target, &id, t, 100));
        assert!(q.permit_act(200, source, &target, &target, &id, t + WINDOW, 110));
        let fresh = admission_quote::request_id(&target, &target, 110);
        assert!(!q.permit_act(200, source, &target, &target, &fresh, t + WINDOW, 110));
    }
}
