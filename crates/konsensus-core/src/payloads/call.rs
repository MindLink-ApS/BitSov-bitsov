//! 1:1 call signalling payloads (kinds 400-403) and the per-call admission
//! state that makes an offer single-use.
//!
//! Media never touches the node: the two apps open a direct WebRTC path and
//! only exchange SDP (and optionally trickled ICE) through these paid UKMs.
//! The payment gate already makes every envelope paid, recipient-bound and
//! single-use. [`CallRegistry`] adds the call semantics on top:
//!
//! - an offer (400) opens a call exactly once per `(peer, call_id)`; a second
//!   offer with the same id — even freshly paid — is a replay and is refused;
//! - an answer (401) is accepted only by the side that sent the offer, while it
//!   is still ringing;
//! - ICE (402) and hangup (403) are accepted only for a live call with that peer;
//! - a hangup ends the call; its id stays burned until the tombstone expires.
//!
//! The offer is priced at the recipient's `call_msat`; 401-403 keep the
//! ordinary realtime signalling price (29 Sep overnight default).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::kind::{KIND_CALL_ANSWER, KIND_CALL_HANGUP, KIND_CALL_INVITE, KIND_ICE_CANDIDATE};
use crate::types::NodeId;

/// Payload schema version.
pub const CALL_SIGNAL_VERSION: u8 = 1;
/// Largest SDP accepted in an offer or answer.
pub const MAX_SDP_BYTES: usize = 16 * 1024;
/// Largest single ICE candidate line.
pub const MAX_CANDIDATE_BYTES: usize = 1024;
/// How long an unanswered offer rings.
pub const RING_TIMEOUT_MS: u64 = 60_000;
/// Longest a call stays live without a hangup.
pub const MAX_CALL_MS: u64 = 4 * 60 * 60 * 1000;
/// How long an ended or expired call id stays burned.
pub const TOMBSTONE_MS: u64 = 24 * 60 * 60 * 1000;
/// Bound on tracked calls (live + tombstones).
pub const MAX_TRACKED_CALLS: usize = 4096;

/// What media an offer asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CallMedia {
    Audio,
    Video,
}

/// The JSON inside a 400-403 envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallSignal {
    pub v: u8,
    /// 32 lowercase hex characters (16 random bytes), chosen by the caller.
    pub call_id: String,
    /// 400 only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<CallMedia>,
    /// 400 and 401: the full SDP (vanilla ICE: candidates included).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdp: Option<String>,
    /// 402 only: one trickled candidate line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdp_mid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdp_mline_index: Option<u16>,
    /// 403 only: why the call ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<HangupReason>,
}

/// Why a call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HangupReason {
    Hangup,
    Declined,
    Busy,
    Timeout,
    Failed,
}

/// Why a call signal was refused. Nothing here is ever forwarded to the app.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallRefusal {
    #[error("not a call signalling kind")]
    NotCallKind,
    #[error("invalid call signal: {0}")]
    Invalid(&'static str),
    #[error("call offer replayed: this call id was already used")]
    Replayed,
    #[error("no live call with that id")]
    UnknownCall,
    #[error("the call is not ringing")]
    NotRinging,
    #[error("only the callee answers a call")]
    WrongSide,
    #[error("too many calls tracked; try again later")]
    Full,
}

fn is_call_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl CallSignal {
    /// Parse and check the fields `kind` requires, and only those.
    pub fn parse(kind: u16, plaintext: &str) -> Result<Self, CallRefusal> {
        if !(KIND_CALL_INVITE..=KIND_CALL_HANGUP).contains(&kind) {
            return Err(CallRefusal::NotCallKind);
        }
        if plaintext.len() > MAX_SDP_BYTES + 1024 {
            return Err(CallRefusal::Invalid("payload too large"));
        }
        let s: CallSignal = serde_json::from_str(plaintext).map_err(|_| CallRefusal::Invalid("not a call signal"))?;
        if s.v != CALL_SIGNAL_VERSION {
            return Err(CallRefusal::Invalid("unsupported version"));
        }
        if !is_call_id(&s.call_id) {
            return Err(CallRefusal::Invalid("call_id must be 32 lowercase hex"));
        }
        let sdp_ok = |sdp: &Option<String>| sdp.as_deref().is_some_and(|x| !x.is_empty() && x.len() <= MAX_SDP_BYTES);
        let none_but = |media: bool, sdp: bool, cand: bool, reason: bool| {
            (media || s.media.is_none())
                && (sdp || s.sdp.is_none())
                && (cand || (s.candidate.is_none() && s.sdp_mid.is_none() && s.sdp_mline_index.is_none()))
                && (reason || s.reason.is_none())
        };
        let ok = match kind {
            KIND_CALL_INVITE => s.media.is_some() && sdp_ok(&s.sdp) && none_but(true, true, false, false),
            KIND_CALL_ANSWER => sdp_ok(&s.sdp) && none_but(false, true, false, false),
            KIND_ICE_CANDIDATE => {
                s.candidate.as_deref().is_some_and(|c| c.len() <= MAX_CANDIDATE_BYTES)
                    && s.sdp_mid.as_deref().is_none_or(|m| m.len() <= 64)
                    && none_but(false, false, true, false)
            }
            _ => none_but(false, false, false, true),
        };
        if ok { Ok(s) } else { Err(CallRefusal::Invalid("fields do not match the kind")) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    /// We sent the offer.
    Caller,
    /// We received the offer.
    Callee,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Ringing,
    Live,
    Ended,
}

#[derive(Debug, Clone, Copy)]
struct Call {
    side: Side,
    phase: Phase,
    /// Ringing/live deadline, or tombstone expiry once ended.
    until_ms: u64,
}

/// Which way a signal travels through this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Composed here, about to be paid and sent.
    Outgoing,
    /// Received, paid and accepted by the gate, about to reach the app.
    Incoming,
}

/// Per-call state for this node. Pure: time is passed in.
#[derive(Debug, Default)]
pub struct CallRegistry {
    calls: HashMap<(NodeId, String), Call>,
}

impl CallRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit one signal, updating call state. On `Err` nothing changes.
    pub fn admit(&mut self, dir: Direction, peer: &NodeId, kind: u16, signal: &CallSignal, now_ms: u64) -> Result<(), CallRefusal> {
        self.expire(now_ms);
        let key = (*peer, signal.call_id.clone());
        let own = match dir { Direction::Outgoing => Side::Caller, Direction::Incoming => Side::Callee };
        match kind {
            KIND_CALL_INVITE => {
                if self.calls.contains_key(&key) {
                    return Err(CallRefusal::Replayed);
                }
                if self.calls.len() >= MAX_TRACKED_CALLS && !self.evict_one_tombstone() {
                    return Err(CallRefusal::Full);
                }
                self.calls.insert(key, Call { side: own, phase: Phase::Ringing, until_ms: now_ms.saturating_add(RING_TIMEOUT_MS) });
                Ok(())
            }
            KIND_CALL_ANSWER => {
                let call = self.live(&key)?;
                if call.phase != Phase::Ringing {
                    return Err(CallRefusal::NotRinging);
                }
                // Outgoing answers come from the callee; incoming ones reach the caller.
                let answering_side = match dir { Direction::Outgoing => Side::Callee, Direction::Incoming => Side::Caller };
                if call.side != answering_side {
                    return Err(CallRefusal::WrongSide);
                }
                call.phase = Phase::Live;
                call.until_ms = now_ms.saturating_add(MAX_CALL_MS);
                Ok(())
            }
            KIND_ICE_CANDIDATE => self.live(&key).map(|_| ()),
            KIND_CALL_HANGUP => {
                let call = self.live(&key)?;
                call.phase = Phase::Ended;
                call.until_ms = now_ms.saturating_add(TOMBSTONE_MS);
                Ok(())
            }
            _ => Err(CallRefusal::NotCallKind),
        }
    }

    /// Whether `(peer, call_id)` is ringing or live.
    pub fn is_live(&self, peer: &NodeId, call_id: &str, now_ms: u64) -> bool {
        self.calls
            .get(&(*peer, call_id.to_string()))
            .is_some_and(|c| c.phase != Phase::Ended && c.until_ms > now_ms)
    }

    fn live(&mut self, key: &(NodeId, String)) -> Result<&mut Call, CallRefusal> {
        match self.calls.get_mut(key) {
            Some(c) if c.phase != Phase::Ended => Ok(c),
            _ => Err(CallRefusal::UnknownCall),
        }
    }

    /// Ringing/live calls past their deadline become tombstones; old tombstones go.
    fn expire(&mut self, now_ms: u64) {
        self.calls.retain(|_, c| c.phase != Phase::Ended || c.until_ms > now_ms);
        for c in self.calls.values_mut() {
            if c.phase != Phase::Ended && c.until_ms <= now_ms {
                c.phase = Phase::Ended;
                c.until_ms = now_ms.saturating_add(TOMBSTONE_MS);
            }
        }
    }

    fn evict_one_tombstone(&mut self) -> bool {
        let oldest = self.calls.iter().filter(|(_, c)| c.phase == Phase::Ended).min_by_key(|(_, c)| c.until_ms).map(|(k, _)| k.clone());
        oldest.is_some_and(|k| self.calls.remove(&k).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";
    const ID2: &str = "fedcba9876543210fedcba9876543210";

    fn peer(b: u8) -> NodeId {
        NodeId::from_bytes([b; 32])
    }
    fn offer(id: &str) -> CallSignal {
        CallSignal::parse(400, &format!(r#"{{"v":1,"call_id":"{id}","media":"audio","sdp":"v=0"}}"#)).unwrap()
    }
    fn sig(kind: u16, id: &str) -> CallSignal {
        let body = match kind {
            401 => format!(r#"{{"v":1,"call_id":"{id}","sdp":"v=0"}}"#),
            402 => format!(r#"{{"v":1,"call_id":"{id}","candidate":"candidate:1 1 udp 1 10.0.0.1 9 typ host","sdp_mid":"0","sdp_mline_index":0}}"#),
            _ => format!(r#"{{"v":1,"call_id":"{id}","reason":"hangup"}}"#),
        };
        CallSignal::parse(kind, &body).unwrap()
    }

    #[test]
    fn each_kind_carries_only_its_own_fields() {
        assert_eq!(offer(ID).media, Some(CallMedia::Audio));
        assert!(CallSignal::parse(400, &format!(r#"{{"v":1,"call_id":"{ID}","sdp":"v=0"}}"#)).is_err(), "offer needs media");
        assert!(CallSignal::parse(401, &format!(r#"{{"v":1,"call_id":"{ID}","media":"audio","sdp":"v=0"}}"#)).is_err());
        assert!(CallSignal::parse(403, &format!(r#"{{"v":1,"call_id":"{ID}","sdp":"v=0"}}"#)).is_err());
        assert!(CallSignal::parse(402, &format!(r#"{{"v":1,"call_id":"{ID}"}}"#)).is_err());
        assert!(CallSignal::parse(400, &format!(r#"{{"v":2,"call_id":"{ID}","media":"audio","sdp":"v=0"}}"#)).is_err());
        assert!(CallSignal::parse(400, r#"{"v":1,"call_id":"ABC","media":"audio","sdp":"v=0"}"#).is_err());
        assert!(CallSignal::parse(400, &format!(r#"{{"v":1,"call_id":"{ID}","media":"audio","sdp":"v=0","x":1}}"#)).is_err());
        let big = "a".repeat(MAX_SDP_BYTES + 1);
        assert!(CallSignal::parse(401, &format!(r#"{{"v":1,"call_id":"{ID}","sdp":"{big}"}}"#)).is_err());
        assert_eq!(CallSignal::parse(0, "{}"), Err(CallRefusal::NotCallKind));
        assert_eq!(CallSignal::parse(404, "{}"), Err(CallRefusal::NotCallKind));
    }

    #[test]
    fn an_offer_opens_a_call_exactly_once() {
        let mut r = CallRegistry::new();
        r.admit(Direction::Incoming, &peer(1), 400, &offer(ID), 0).unwrap();
        assert_eq!(r.admit(Direction::Incoming, &peer(1), 400, &offer(ID), 1), Err(CallRefusal::Replayed));
        // Still burned after the call ended, until the tombstone expires.
        r.admit(Direction::Incoming, &peer(1), 403, &sig(403, ID), 2).unwrap();
        assert_eq!(r.admit(Direction::Incoming, &peer(1), 400, &offer(ID), 3), Err(CallRefusal::Replayed));
        // Another peer's id space is separate; a new id is a new call.
        r.admit(Direction::Incoming, &peer(2), 400, &offer(ID), 3).unwrap();
        r.admit(Direction::Incoming, &peer(1), 400, &offer(ID2), 3).unwrap();
        assert!(r.admit(Direction::Incoming, &peer(1), 400, &offer(ID), 2 + TOMBSTONE_MS + 1).is_ok());
    }

    #[test]
    fn signals_need_a_live_call_with_that_peer() {
        let mut r = CallRegistry::new();
        for k in [401, 402, 403] {
            assert_eq!(r.admit(Direction::Incoming, &peer(1), k, &sig(k, ID), 0), Err(CallRefusal::UnknownCall));
            assert_eq!(r.admit(Direction::Outgoing, &peer(1), k, &sig(k, ID), 0), Err(CallRefusal::UnknownCall));
        }
        r.admit(Direction::Outgoing, &peer(1), 400, &offer(ID), 0).unwrap();
        assert_eq!(r.admit(Direction::Incoming, &peer(2), 401, &sig(401, ID), 1), Err(CallRefusal::UnknownCall));
    }

    #[test]
    fn only_the_callee_answers_and_only_while_ringing() {
        let mut r = CallRegistry::new();
        // We called: our own answer is refused; theirs is accepted once.
        r.admit(Direction::Outgoing, &peer(1), 400, &offer(ID), 0).unwrap();
        assert_eq!(r.admit(Direction::Outgoing, &peer(1), 401, &sig(401, ID), 1), Err(CallRefusal::WrongSide));
        r.admit(Direction::Incoming, &peer(1), 402, &sig(402, ID), 1).unwrap();
        r.admit(Direction::Incoming, &peer(1), 401, &sig(401, ID), 2).unwrap();
        assert_eq!(r.admit(Direction::Incoming, &peer(1), 401, &sig(401, ID), 3), Err(CallRefusal::NotRinging));
        assert!(r.is_live(&peer(1), ID, 3));
        r.admit(Direction::Outgoing, &peer(1), 403, &sig(403, ID), 4).unwrap();
        assert!(!r.is_live(&peer(1), ID, 5));
        assert_eq!(r.admit(Direction::Incoming, &peer(1), 402, &sig(402, ID), 5), Err(CallRefusal::UnknownCall));
        // They called: we answer.
        r.admit(Direction::Incoming, &peer(1), 400, &offer(ID2), 6).unwrap();
        assert_eq!(r.admit(Direction::Incoming, &peer(1), 401, &sig(401, ID2), 7), Err(CallRefusal::WrongSide));
        r.admit(Direction::Outgoing, &peer(1), 401, &sig(401, ID2), 7).unwrap();
    }

    #[test]
    fn an_unanswered_offer_stops_ringing() {
        let mut r = CallRegistry::new();
        r.admit(Direction::Outgoing, &peer(1), 400, &offer(ID), 0).unwrap();
        assert_eq!(r.admit(Direction::Incoming, &peer(1), 401, &sig(401, ID), RING_TIMEOUT_MS), Err(CallRefusal::UnknownCall));
        assert_eq!(r.admit(Direction::Outgoing, &peer(1), 400, &offer(ID), RING_TIMEOUT_MS + 1), Err(CallRefusal::Replayed));
    }

    #[test]
    fn the_registry_is_bounded() {
        let mut r = CallRegistry::new();
        for i in 0..MAX_TRACKED_CALLS {
            r.admit(Direction::Incoming, &peer(1), 400, &offer(&format!("{i:032x}")), 0).unwrap();
        }
        assert_eq!(r.admit(Direction::Incoming, &peer(2), 400, &offer(ID), 1), Err(CallRefusal::Full));
        r.admit(Direction::Incoming, &peer(1), 403, &sig(403, &format!("{:032x}", 0)), 1).unwrap();
        r.admit(Direction::Incoming, &peer(2), 400, &offer(ID), 2).unwrap();
    }
}
