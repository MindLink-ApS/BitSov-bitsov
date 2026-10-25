//! 1:1 call signalling payloads (kinds 400-403) and the per-call state that
//! makes an offer single-use.
//!
//! Media never touches the node: the two apps open a direct WebRTC path and
//! only exchange SDP (and optionally trickled ICE) through these paid UKMs.
//! The payment gate already makes every envelope paid, recipient-bound and
//! single-use. The call state adds, per `(peer, call_id)`:
//!
//! - an offer (400) opens a call exactly once; a second offer with the same
//!   id — even freshly paid — is a replay and is refused until the id's
//!   replay deadline passes (24 h after the call ends);
//! - an incoming offer does not ring yet. It waits
//!   [`DEVICE_RING_GRACE_MS`] for one of the callee's paired devices to
//!   fetch that invite. The callee's 60 s ring clock starts at that fetch.
//!   The caller's 60 s clock starts when the ringing acknowledgement of
//!   that fetch arrives, so the two deadlines are the same instant and a
//!   fetch 10 s after payment cannot expire the caller while the callee
//!   is still ringing. Until that ack the caller's deadline is only a
//!   safety cap (grace + 60 s), not the ring clock. If no device fetches
//!   the invite, the caller is told [`NOT_REACHABLE`] — not a ring timeout;
//! - an answer (401) is accepted only from the callee, while it rings;
//! - ICE (402) only for a ringing or live call; hangup (403) also while the
//!   invite is still waiting for a device;
//! - our own signals are **reserved** under their operation id before any
//!   payment and **committed** only once the payment settled. A definite
//!   nonpayment releases the reservation; an ambiguous one keeps it so a retry
//!   of the same operation recovers without a second charge. A reserved (not
//!   yet paid) offer does not accept answers.
//!
//! These are pure transitions over one [`CallEntry`]; the node stores entries
//! durably (restart keeps used ids and live calls) and bounds them per peer
//! and in total, never evicting unexpired replay protection.
//!
//! The offer is priced at the recipient's `call_msat`; 401-403 keep the
//! ordinary realtime signalling price (29 Sep overnight default).

use serde::{Deserialize, Serialize};

use crate::kind::{KIND_CALL_ANSWER, KIND_CALL_HANGUP, KIND_CALL_INVITE, KIND_ICE_CANDIDATE};
use crate::types::NodeId;

/// Payload schema version.
pub const CALL_SIGNAL_VERSION: u8 = 1;
/// Largest SDP accepted in an offer or answer.
pub const MAX_SDP_BYTES: usize = 16 * 1024;
/// Largest single ICE candidate line.
pub const MAX_CANDIDATE_BYTES: usize = 1024;
/// How long an unanswered offer rings, measured from the moment a paired
/// device fetches the invite — not from when the invite reached the node.
pub const RING_TIMEOUT_MS: u64 = 60_000;
/// How long an admitted invite waits for a paired device to fetch it.
/// Past this, the caller is answered [`NOT_REACHABLE`] and the ring clock
/// never starts.
pub const DEVICE_RING_GRACE_MS: u64 = 15_000;
/// Caller-facing outcome when no paired device fetches the invite within
/// [`DEVICE_RING_GRACE_MS`]. Distinct from a ring that times out with no
/// answer: the 60 s clock did not run.
pub const NOT_REACHABLE: &str = "not reachable";
/// Longest a call stays live without a hangup.
pub const MAX_CALL_MS: u64 = 4 * 60 * 60 * 1000;
/// How long an ended or expired call id stays burned.
pub const TOMBSTONE_MS: u64 = 24 * 60 * 60 * 1000;
/// Every burned id stays burned at least this long, whatever the pressure.
/// Past it, and only when a burned-id bound is reached, the oldest burned ids
/// make room; otherwise they stay burned for [`TOMBSTONE_MS`].
pub const BURN_MIN_MS: u64 = 60 * 60 * 1000;
/// Open calls (reserved, ringing, live, or with a signal of ours being paid)
/// in total. Open calls are never evicted.
pub const MAX_OPEN_CALLS: u64 = 4096;
/// Open calls per peer, so one paying peer cannot fill the node's table.
/// Kept small relative to [`MAX_OPEN_CALLS`]: at 4, filling the global 4096
/// bound needs at least 1024 distinct peers.
pub const MAX_OPEN_CALLS_PER_PEER: u64 = 4;
/// Burned ids (ended calls still under replay protection) per peer.
pub const MAX_BURNED_PER_PEER: u64 = 256;
/// Burned ids in total.
pub const MAX_BURNED_CALLS: u64 = 65_536;
/// Most participants in a mesh meeting (host included). Every pair is one
/// ordinary 1:1 call, so upload grows with each extra participant.
pub const MAX_MEETING_PARTICIPANTS: usize = 4;
/// Advertised by a node that accepts the `meeting` field on offers: as
/// `Capability::Custom` in its federation Hello (peers see it in
/// `GET /api/v1/peers` as `Custom("call_meeting_v1")`) and in its own
/// `/status` `api_capabilities`. A node without it refuses (withdraws) a
/// meeting offer after it was paid, so apps must not send it one.
pub const MEETING_CAPABILITY: &str = "call_meeting_v1";

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
    /// 400 only: this call is one leg of a mesh meeting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meeting: Option<Meeting>,
}

/// A mesh meeting is a set of ordinary 1:1 calls ("legs") that share an id
/// and a fixed roster. Each pair of participants is one leg, placed and paid
/// (at the callee's `call_msat`) by the participant earlier in the roster, so
/// every leg has exactly one payer and two participants never ring each other.
/// The node keeps no meeting state: it only refuses a leg that breaks the
/// roster rule ([`CallSignal::check_leg`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meeting {
    /// 32 lowercase hex characters, chosen by the host.
    pub id: String,
    /// Node ids (64 lowercase hex), host first; 2 to
    /// [`MAX_MEETING_PARTICIPANTS`], all distinct.
    pub roster: Vec<String>,
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
    #[error("another signal for this call is still being paid")]
    InFlight,
}

fn is_lower_hex(id: &str, len: usize) -> bool {
    id.len() == len && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_call_id(id: &str) -> bool {
    is_lower_hex(id, 32)
}

impl Meeting {
    fn valid(&self) -> bool {
        let n = self.roster.len();
        is_call_id(&self.id)
            && (2..=MAX_MEETING_PARTICIPANTS).contains(&n)
            && self.roster.iter().all(|id| is_lower_hex(id, 64))
            && (1..n).all(|i| !self.roster[..i].contains(&self.roster[i]))
    }

    fn position(&self, node: &NodeId) -> Option<usize> {
        let hex = node.to_hex();
        self.roster.iter().position(|id| *id == hex)
    }
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
        let s: CallSignal = crate::wire_json::from_str(plaintext).map_err(|_| CallRefusal::Invalid("not a call signal"))?;
        if s.v != CALL_SIGNAL_VERSION {
            return Err(CallRefusal::Invalid("unsupported version"));
        }
        if !is_call_id(&s.call_id) {
            return Err(CallRefusal::Invalid("call_id must be 32 lowercase hex"));
        }
        let sdp_ok = |sdp: &Option<String>| sdp.as_deref().is_some_and(|x| !x.is_empty() && x.len() <= MAX_SDP_BYTES);
        let none_but = |media: bool, sdp: bool, cand: bool, reason: bool| {
            (media || (s.media.is_none() && s.meeting.is_none()))
                && (sdp || s.sdp.is_none())
                && (cand || (s.candidate.is_none() && s.sdp_mid.is_none() && s.sdp_mline_index.is_none()))
                && (reason || s.reason.is_none())
        };
        let ok = match kind {
            KIND_CALL_INVITE => {
                s.media.is_some() && sdp_ok(&s.sdp) && none_but(true, true, false, false) && s.meeting.as_ref().is_none_or(Meeting::valid)
            }
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

    /// A meeting leg must be placed by the earlier of its two participants,
    /// both in the roster. Plain 1:1 calls always pass.
    pub fn check_leg(&self, caller: &NodeId, callee: &NodeId) -> Result<(), CallRefusal> {
        let Some(m) = &self.meeting else { return Ok(()) };
        match (m.position(caller), m.position(callee)) {
            (Some(a), Some(b)) if a < b => Ok(()),
            (Some(_), Some(_)) => Err(CallRefusal::Invalid("a meeting leg is placed by the earlier participant")),
            _ => Err(CallRefusal::Invalid("both ends of a meeting leg must be in its roster")),
        }
    }
}

/// Which side of the call this node is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// We sent the offer.
    Caller,
    /// We received the offer.
    Callee,
}

impl Side {
    pub fn as_str(self) -> &'static str {
        match self { Side::Caller => "caller", Side::Callee => "callee" }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s { "caller" => Some(Side::Caller), "callee" => Some(Side::Callee), _ => None }
    }
}

/// Where the call is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Our offer is reserved but not yet paid: nobody has been rung.
    Reserved,
    /// Incoming invite is admitted, but no paired device has fetched it.
    /// The ring clock has not started; `deadline_ms` is the end of
    /// [`DEVICE_RING_GRACE_MS`].
    AwaitingDevice,
    Ringing,
    Live,
    Ended,
    /// No paired device fetched the invite before the grace period. The id
    /// is burned, like [`Phase::Ended`], and this is not a no-answer timeout.
    Unreachable,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Reserved => "reserved",
            Phase::AwaitingDevice => "awaiting_device",
            Phase::Ringing => "ringing",
            Phase::Live => "live",
            Phase::Ended => "ended",
            Phase::Unreachable => "unreachable",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "reserved" => Some(Phase::Reserved),
            "awaiting_device" => Some(Phase::AwaitingDevice),
            "ringing" => Some(Phase::Ringing),
            "live" => Some(Phase::Live),
            "ended" => Some(Phase::Ended),
            "unreachable" => Some(Phase::Unreachable),
            _ => None,
        }
    }
}

/// One of our own signals, reserved under its operation id and not yet paid.
/// Bound to the exact request (`request_hash`, the operation journal's
/// digest), so a concurrent request sharing the operation id but carrying
/// another payload never shares, commits or releases it (Codex delta2 #2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub operation_id: String,
    pub kind: u16,
    /// Empty only for rows written before the binding existed.
    pub request_hash: String,
}

impl Pending {
    /// Whether this reservation belongs to exactly this request.
    pub fn is(&self, operation_id: &str, request_hash: &str) -> bool {
        self.operation_id == operation_id && (self.request_hash == request_hash || self.request_hash.is_empty())
    }
}

/// The state of one `(peer, call_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEntry {
    pub side: Side,
    pub phase: Phase,
    /// End of ringing / live, or of the replay tombstone once ended.
    ///
    /// On the caller, this is the ring deadline only once [`Self::ring_anchored`]
    /// is set. Before the ringing acknowledgement it is a safety cap of
    /// grace plus [`RING_TIMEOUT_MS`], measured from payment.
    pub deadline_ms: u64,
    pub pending: Option<Pending>,
    /// The 60 s ring clock has been anchored: the callee's device fetch, or
    /// the caller's first ringing acknowledgement. A paid invite can already
    /// be [`Phase::Ringing`] and still be unanchored.
    pub ring_anchored: bool,
}

impl CallEntry {
    /// Until when this id must stay burned (the row may not be dropped before).
    pub fn replay_until_ms(&self) -> u64 {
        match self.phase {
            Phase::Ended | Phase::Unreachable => self.deadline_ms,
            Phase::Reserved | Phase::AwaitingDevice | Phase::Ringing | Phase::Live => self.deadline_ms.saturating_add(TOMBSTONE_MS),
        }
    }

    /// The entry as of `now_ms`: a ringing/live/reserved call past its deadline
    /// is ended (its tombstone runs from the deadline); an invite no device
    /// fetched is [`Phase::Unreachable`] instead, so a missed device is not a
    /// no-answer. An expired tombstone is gone. A pending payment survives
    /// expiry so it can still be settled or released.
    pub fn at(self, now_ms: u64) -> Option<CallEntry> {
        match self.phase {
            Phase::Ended | Phase::Unreachable if self.deadline_ms <= now_ms && self.pending.is_none() => None,
            Phase::Ended | Phase::Unreachable => Some(self),
            Phase::AwaitingDevice if self.deadline_ms <= now_ms => {
                let until = self.deadline_ms.saturating_add(TOMBSTONE_MS);
                (until > now_ms || self.pending.is_some()).then_some(CallEntry { phase: Phase::Unreachable, deadline_ms: until, ..self })
            }
            Phase::Reserved | Phase::Ringing | Phase::Live if self.deadline_ms <= now_ms => {
                let until = self.deadline_ms.saturating_add(TOMBSTONE_MS);
                (until > now_ms || self.pending.is_some()).then_some(CallEntry { phase: Phase::Ended, deadline_ms: until, ..self })
            }
            Phase::Reserved | Phase::AwaitingDevice | Phase::Ringing | Phase::Live => Some(self),
        }
    }

    fn open(&self) -> bool {
        matches!(self.phase, Phase::Ringing | Phase::Live)
    }
}

/// Reserve one of our own signals before paying for it. `entry` is the
/// current state (already passed through [`CallEntry::at`]). Returns the entry
/// to store. The same operation reserving again is idempotent (a retry).
pub fn reserve(entry: Option<CallEntry>, kind: u16, operation_id: &str, request_hash: &str, now_ms: u64) -> Result<CallEntry, CallRefusal> {
    let pending = Pending { operation_id: operation_id.to_string(), kind, request_hash: request_hash.to_string() };
    let mine = |e: &CallEntry| e.pending.as_ref().is_some_and(|p| p.is(operation_id, request_hash) && p.kind == kind);
    match kind {
        KIND_CALL_INVITE => match entry {
            None => Ok(CallEntry { side: Side::Caller, phase: Phase::Reserved, deadline_ms: now_ms.saturating_add(RING_TIMEOUT_MS), pending: Some(pending), ring_anchored: false }),
            Some(e) if e.phase == Phase::Reserved && mine(&e) => Ok(e),
            Some(_) => Err(CallRefusal::Replayed),
        },
        KIND_CALL_ANSWER | KIND_ICE_CANDIDATE | KIND_CALL_HANGUP => {
            let e = entry.ok_or(CallRefusal::UnknownCall)?;
            if mine(&e) {
                return Ok(e);
            }
            if e.pending.is_some() {
                return Err(CallRefusal::InFlight);
            }
            match kind {
                KIND_CALL_ANSWER if e.phase != Phase::Ringing => Err(CallRefusal::NotRinging),
                KIND_CALL_ANSWER if e.side != Side::Callee => Err(CallRefusal::WrongSide),
                // The caller can cancel during the device grace; that is not a ring.
                KIND_CALL_HANGUP if e.phase == Phase::AwaitingDevice => Ok(CallEntry { pending: Some(pending), ..e }),
                _ if !e.open() => Err(CallRefusal::UnknownCall),
                // ICE changes nothing once paid: no reservation needed.
                KIND_ICE_CANDIDATE => Ok(e),
                _ => Ok(CallEntry { pending: Some(pending), ..e }),
            }
        }
        _ => Err(CallRefusal::NotCallKind),
    }
}

/// The reserved signal's payment settled: publish its transition. Never
/// fails (money already moved); a call that ended meanwhile stays ended.
pub fn commit(entry: CallEntry, operation_id: &str, now_ms: u64) -> CallEntry {
    let Some(p) = entry.pending.clone().filter(|p| p.operation_id == operation_id) else {
        return entry;
    };
    let cleared = CallEntry { pending: None, ..entry };
    match (p.kind, cleared.phase) {
        // Paid, but the 60 s clock waits for the callee's ringing ack.
        // The safety cap keeps an answer admissible until that ack can arrive.
        (KIND_CALL_INVITE, Phase::Reserved) => CallEntry {
            phase: Phase::Ringing,
            deadline_ms: now_ms.saturating_add(DEVICE_RING_GRACE_MS).saturating_add(RING_TIMEOUT_MS),
            ring_anchored: false,
            ..cleared
        },
        (KIND_CALL_ANSWER, Phase::Ringing) => CallEntry { phase: Phase::Live, deadline_ms: now_ms.saturating_add(MAX_CALL_MS), ..cleared },
        (KIND_CALL_HANGUP, Phase::Ringing | Phase::Live | Phase::Reserved | Phase::AwaitingDevice) => {
            CallEntry { phase: Phase::Ended, deadline_ms: now_ms.saturating_add(TOMBSTONE_MS), ..cleared }
        }
        _ => cleared,
    }
}

/// The reserved signal was definitely not paid: undo the reservation. An
/// offer that never went out is forgotten (`None`); other signals just drop
/// their pending mark.
pub fn release(entry: CallEntry, operation_id: &str) -> Option<CallEntry> {
    match &entry.pending {
        Some(p) if p.operation_id == operation_id && p.kind == KIND_CALL_INVITE && entry.phase == Phase::Reserved => None,
        Some(p) if p.operation_id == operation_id => Some(CallEntry { pending: None, ..entry }),
        _ => Some(entry),
    }
}

/// A signal this node received (paid, gate-accepted). Returns the entry to store.
///
/// An invite is admitted without ringing. [`note_device_fetch`] starts the
/// 60 s clock once a paired device has that invite.
pub fn receive(entry: Option<CallEntry>, kind: u16, now_ms: u64) -> Result<CallEntry, CallRefusal> {
    match kind {
        KIND_CALL_INVITE => match entry {
            None => Ok(CallEntry {
                side: Side::Callee,
                phase: Phase::AwaitingDevice,
                deadline_ms: now_ms.saturating_add(DEVICE_RING_GRACE_MS),
                pending: None,
                ring_anchored: false,
            }),
            Some(_) => Err(CallRefusal::Replayed),
        },
        KIND_CALL_ANSWER => {
            let e = entry.ok_or(CallRefusal::UnknownCall)?;
            match (e.phase, e.side) {
                // A reserved offer was never paid, and an unreachable callee
                // never rang: nobody can answer it.
                (Phase::Reserved | Phase::Ended | Phase::Unreachable, _) => Err(CallRefusal::UnknownCall),
                (Phase::AwaitingDevice, _) => Err(CallRefusal::NotRinging),
                (Phase::Ringing, Side::Caller) => Ok(CallEntry { phase: Phase::Live, deadline_ms: now_ms.saturating_add(MAX_CALL_MS), ..e }),
                (Phase::Ringing, Side::Callee) => Err(CallRefusal::WrongSide),
                (Phase::Live, _) => Err(CallRefusal::NotRinging),
            }
        }
        KIND_ICE_CANDIDATE => entry.filter(|e| e.open()).ok_or(CallRefusal::UnknownCall),
        KIND_CALL_HANGUP => {
            let e = entry.filter(|e| e.open() || e.phase == Phase::AwaitingDevice).ok_or(CallRefusal::UnknownCall)?;
            // Their hangup wins; a signal of ours still being paid keeps its
            // mark so its settlement or release is still recorded.
            Ok(CallEntry { phase: Phase::Ended, deadline_ms: now_ms.saturating_add(TOMBSTONE_MS), ..e })
        }
        _ => Err(CallRefusal::NotCallKind),
    }
}

/// What a paired device's fetch of one invite did to the ring clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceFetch {
    /// First device to take this invite. The 60 s clock starts at `now_ms`.
    Started(CallEntry),
    /// The clock was already running (or the call is live). It is not restarted.
    Unchanged(CallEntry),
    /// Nothing is waiting for a device: grace already elapsed, or this call
    /// is not an incoming invite.
    NotWaiting(CallEntry),
}

/// A paired device fetched or received `entry`'s invite at `now_ms`.
///
/// The first fetch moves [`Phase::AwaitingDevice`] to [`Phase::Ringing`] and
/// sets the deadline to `now_ms + RING_TIMEOUT_MS`. A later fetch of the same
/// invite leaves that deadline alone.
pub fn note_device_fetch(entry: CallEntry, now_ms: u64) -> DeviceFetch {
    match entry.phase {
        Phase::AwaitingDevice if entry.deadline_ms > now_ms => DeviceFetch::Started(CallEntry {
            phase: Phase::Ringing,
            deadline_ms: now_ms.saturating_add(RING_TIMEOUT_MS),
            ring_anchored: true,
            ..entry
        }),
        Phase::Ringing | Phase::Live => DeviceFetch::Unchanged(entry),
        Phase::Reserved | Phase::AwaitingDevice | Phase::Ended | Phase::Unreachable => DeviceFetch::NotWaiting(entry),
    }
}

/// What the caller's first ringing acknowledgement did to the ring clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RingAck {
    /// This ack anchored the 60 s clock at `now_ms`.
    Started(CallEntry),
    /// The clock was already anchored. It is not restarted.
    Unchanged(CallEntry),
    /// Not a caller invite waiting for its ringing acknowledgement.
    Ignored,
}

/// Anchor the caller's 60 s ring clock to the first ringing acknowledgement.
///
/// The callee sends that ack at the device fetch and starts its own clock
/// then. Applying this at the same `now_ms` stores the same deadline. A later
/// ack does not move it. Payment time is not the anchor: until this runs, a
/// paid invite's deadline is only the grace-plus-ring safety cap.
pub fn note_ringing_ack(entry: CallEntry, now_ms: u64) -> RingAck {
    match (entry.side, entry.phase, entry.ring_anchored) {
        (Side::Caller, Phase::Ringing, false) => RingAck::Started(CallEntry {
            deadline_ms: now_ms.saturating_add(RING_TIMEOUT_MS),
            ring_anchored: true,
            ..entry
        }),
        (Side::Caller, Phase::Ringing, true) => RingAck::Unchanged(entry),
        (Side::Caller, Phase::Reserved | Phase::AwaitingDevice | Phase::Live | Phase::Ended | Phase::Unreachable, _)
        | (Side::Callee, _, _) => RingAck::Ignored,
    }
}

/// Stored call rows as of one instant, split by what they hold.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CallCounts {
    /// Open calls with this peer (reserved, awaiting a device, ringing, live, or pending).
    pub open_peer: u64,
    pub open_total: u64,
    /// Burned ids with this peer (ended or not reachable, replay protection not yet over).
    pub burned_peer: u64,
    pub burned_total: u64,
}

/// Room for one more open call? Open calls are bounded and never evicted.
/// Burned ids are bounded separately (see [`burned_excess`]), so ended calls
/// never block new ones for the whole tombstone.
pub fn has_room(counts: &CallCounts) -> Result<(), CallRefusal> {
    if counts.open_peer >= MAX_OPEN_CALLS_PER_PEER || counts.open_total >= MAX_OPEN_CALLS {
        Err(CallRefusal::Full)
    } else {
        Ok(())
    }
}

/// How many burned ids must make room before one more call id fits under `cap`.
pub fn burned_excess(burned: u64, cap: u64) -> u64 {
    burned.saturating_add(1).saturating_sub(cap)
}

/// A burned id may make room only if its replay protection ends at or before
/// this, i.e. it has been burned for at least [`BURN_MIN_MS`].
pub fn evictable_until(now_ms: u64) -> u64 {
    now_ms.saturating_add(TOMBSTONE_MS).saturating_sub(BURN_MIN_MS)
}

/// What to do with a reservation given its operation's journal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settlement {
    /// The payment settled: commit.
    Paid,
    /// Definitely not paid: release.
    Unpaid,
    /// Unknown: keep the reservation; a retry of the same operation resolves it.
    Ambiguous,
}

/// Classify an outbox operation state (`None`: the operation was never created).
pub fn settlement(state: Option<&str>) -> Settlement {
    match state {
        None | Some("prepared" | "released" | "abandoned") => Settlement::Unpaid,
        Some("paid" | "sent" | "acked" | "rejected_retryable" | "failed_paid") => Settlement::Paid,
        _ => Settlement::Ambiguous,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn each_kind_carries_only_its_own_fields() {
        let offer = CallSignal::parse(400, &format!(r#"{{"v":1,"call_id":"{ID}","media":"audio","sdp":"v=0"}}"#)).unwrap();
        assert_eq!(offer.media, Some(CallMedia::Audio));
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

    fn meeting_offer(roster: &[String]) -> String {
        let roster = roster.iter().map(|r| format!("\"{r}\"")).collect::<Vec<_>>().join(",");
        format!(r#"{{"v":1,"call_id":"{ID}","media":"audio","sdp":"v=0","meeting":{{"id":"{ID}","roster":[{roster}]}}}}"#)
    }

    fn node(b: u8) -> NodeId {
        NodeId::from_bytes([b; 32])
    }

    #[test]
    fn a_meeting_roster_is_2_to_4_distinct_ids_on_offers_only() {
        let ids: Vec<String> = (0xa1..=0xa5).map(|b| node(b).to_hex()).collect();
        let offer = CallSignal::parse(400, &meeting_offer(&ids[..4])).unwrap();
        assert_eq!(offer.meeting.as_ref().unwrap().roster.len(), MAX_MEETING_PARTICIPANTS);
        assert!(CallSignal::parse(400, &meeting_offer(&ids[..2])).is_ok());
        assert!(CallSignal::parse(400, &meeting_offer(&ids)).is_err(), "5 participants");
        assert!(CallSignal::parse(400, &meeting_offer(&ids[..1])).is_err(), "alone");
        assert!(CallSignal::parse(400, &meeting_offer(&[ids[0].clone(), ids[1].clone(), ids[0].clone()])).is_err(), "duplicate");
        assert!(CallSignal::parse(400, &meeting_offer(&[ids[0].clone(), ids[1].to_uppercase()])).is_err(), "not lowercase hex");
        assert!(CallSignal::parse(400, &meeting_offer(&[ids[0].clone(), ids[1][..62].to_string()])).is_err(), "short id");
        let bad_id = format!(r#"{{"v":1,"call_id":"{ID}","media":"audio","sdp":"v=0","meeting":{{"id":"x","roster":["{}","{}"]}}}}"#, ids[0], ids[1]);
        assert!(CallSignal::parse(400, &bad_id).is_err(), "meeting id");
        let extra = format!(r#"{{"v":1,"call_id":"{ID}","media":"audio","sdp":"v=0","meeting":{{"id":"{ID}","roster":["{}","{}"],"host":1}}}}"#, ids[0], ids[1]);
        assert!(CallSignal::parse(400, &extra).is_err(), "unknown meeting field");
        let answer = format!(r#"{{"v":1,"call_id":"{ID}","sdp":"v=0","meeting":{{"id":"{ID}","roster":["{}","{}"]}}}}"#, ids[0], ids[1]);
        assert!(CallSignal::parse(401, &answer).is_err(), "only an offer carries a meeting");
        let hangup = format!(r#"{{"v":1,"call_id":"{ID}","meeting":{{"id":"{ID}","roster":["{}","{}"]}}}}"#, ids[0], ids[1]);
        assert!(CallSignal::parse(403, &hangup).is_err());
    }

    #[test]
    fn a_meeting_leg_is_placed_by_the_earlier_participant() {
        let ids: Vec<String> = (1..=3).map(|b| node(b).to_hex()).collect();
        let offer = CallSignal::parse(400, &meeting_offer(&ids)).unwrap();
        // Host (1) calls both; invitee 2 calls invitee 3; never the other way.
        assert_eq!(offer.check_leg(&node(1), &node(2)), Ok(()));
        assert_eq!(offer.check_leg(&node(1), &node(3)), Ok(()));
        assert_eq!(offer.check_leg(&node(2), &node(3)), Ok(()));
        assert!(offer.check_leg(&node(3), &node(2)).is_err());
        assert!(offer.check_leg(&node(2), &node(1)).is_err());
        assert!(offer.check_leg(&node(1), &node(1)).is_err(), "not a leg");
        assert!(offer.check_leg(&node(1), &node(9)).is_err(), "callee outside the roster");
        assert!(offer.check_leg(&node(9), &node(1)).is_err(), "caller outside the roster");
        // A plain 1:1 call has no roster to check.
        let plain = CallSignal::parse(400, &format!(r#"{{"v":1,"call_id":"{ID}","media":"audio","sdp":"v=0"}}"#)).unwrap();
        assert_eq!(plain.check_leg(&node(9), &node(1)), Ok(()));
    }

    #[test]
    fn a_reserved_offer_rings_nobody_until_paid_and_unpaid_ones_are_forgotten() {
        let r = reserve(None, 400, "op1", "h", 0).unwrap();
        assert_eq!((r.phase, r.side), (Phase::Reserved, Side::Caller));
        // Same operation retrying: idempotent. Another operation: the id is taken.
        assert_eq!(reserve(Some(r.clone()), 400, "op1", "h", 1).unwrap(), r);
        assert_eq!(reserve(Some(r.clone()), 400, "op2", "h", 1), Err(CallRefusal::Replayed));
        // Codex P1: an answer cannot be accepted for an offer that was never paid.
        assert_eq!(receive(Some(r.clone()), 401, 1), Err(CallRefusal::UnknownCall));
        // Definite nonpayment: forgotten, so the same id can be offered again.
        assert_eq!(release(r.clone(), "op1"), None);
        // Paid: now it rings and accepts the callee's answer once.
        let ringing = commit(r, "op1", 5);
        assert_eq!((ringing.phase, ringing.pending.clone()), (Phase::Ringing, None));
        let live = receive(Some(ringing.clone()), 401, 6).unwrap();
        assert_eq!(live.phase, Phase::Live);
        assert_eq!(receive(Some(live), 401, 7), Err(CallRefusal::NotRinging));
        // Commit is idempotent and never fails after payment.
        assert_eq!(commit(ringing.clone(), "op1", 9), ringing);
    }

    fn device_rang(now: u64) -> CallEntry {
        match note_device_fetch(receive(None, 400, now).unwrap(), now) {
            DeviceFetch::Started(entry) => entry,
            other => panic!("first fetch starts the ring, got {other:?}"),
        }
    }

    #[test]
    fn our_answer_and_hangup_change_state_only_when_paid() {
        let ringing = device_rang(0);
        assert_eq!(reserve(Some(ringing.clone()), 401, "a", "h", 1).unwrap().phase, Phase::Ringing, "reserved, not yet live");
        let pending = reserve(Some(ringing.clone()), 401, "a", "h", 1).unwrap();
        // A second signal while the answer is being paid waits.
        assert_eq!(reserve(Some(pending.clone()), 403, "h", "h", 1), Err(CallRefusal::InFlight));
        // Codex P1: an unpaid answer leaves the call ringing, so it can be retried.
        let back = release(pending.clone(), "a").unwrap();
        assert_eq!(back, ringing);
        assert!(reserve(Some(back), 401, "a2", "h", 2).is_ok());
        let live = commit(pending, "a", 3);
        assert_eq!(live.phase, Phase::Live);
        let hang = reserve(Some(live.clone()), 403, "h", "h", 4).unwrap();
        assert_eq!(hang.phase, Phase::Live);
        assert_eq!(release(hang.clone(), "h").unwrap(), live);
        let ended = commit(hang, "h", 5);
        assert_eq!((ended.phase, ended.deadline_ms), (Phase::Ended, 5 + TOMBSTONE_MS));
        // The caller cannot answer its own call.
        let own = commit(reserve(None, 400, "o", "h", 0).unwrap(), "o", 0);
        assert_eq!(reserve(Some(own), 401, "x", "h", 1), Err(CallRefusal::WrongSide));
    }

    #[test]
    fn signals_need_an_open_call_and_ids_stay_burned_until_their_deadline() {
        for k in [401, 402, 403] {
            assert_eq!(receive(None, k, 0), Err(CallRefusal::UnknownCall));
            assert_eq!(reserve(None, k, "op", "h", 0), Err(CallRefusal::UnknownCall));
        }
        let waiting = receive(None, 400, 0).unwrap();
        assert_eq!(waiting.phase, Phase::AwaitingDevice);
        assert_eq!(receive(Some(waiting.clone()), 400, 1), Err(CallRefusal::Replayed));
        let ended = receive(Some(waiting), 403, 2).unwrap();
        assert_eq!(receive(Some(ended.clone()), 402, 3), Err(CallRefusal::UnknownCall));
        // Burned until the tombstone runs out, then free again.
        assert!(ended.clone().at(2 + TOMBSTONE_MS - 1).is_some());
        assert!(ended.at(2 + TOMBSTONE_MS).is_none());
        // No answer: the ring, started when a device fetched, stops at that deadline.
        let ringing = device_rang(0);
        let late = ringing.at(RING_TIMEOUT_MS).unwrap();
        assert_eq!((late.phase, late.deadline_ms), (Phase::Ended, RING_TIMEOUT_MS + TOMBSTONE_MS));
        assert_eq!(receive(Some(late.clone()), 401, RING_TIMEOUT_MS), Err(CallRefusal::UnknownCall));
        assert_eq!(late.replay_until_ms(), RING_TIMEOUT_MS + TOMBSTONE_MS);
    }

    #[test]
    fn an_invite_with_no_device_is_not_reachable_and_never_starts_the_ring_clock() {
        let invited_at = 1_000u64;
        let waiting = receive(None, 400, invited_at).unwrap();
        assert_eq!(waiting.phase, Phase::AwaitingDevice);
        assert_eq!(waiting.deadline_ms, invited_at + DEVICE_RING_GRACE_MS);
        assert_ne!(waiting.deadline_ms, invited_at + RING_TIMEOUT_MS, "the 60 s ring clock did not start");
        let still = waiting.clone().at(invited_at + DEVICE_RING_GRACE_MS - 1).unwrap();
        assert_eq!(still.phase, Phase::AwaitingDevice, "the grace has not elapsed");
        let missed = waiting.at(invited_at + DEVICE_RING_GRACE_MS).unwrap();
        assert_eq!(missed.phase, Phase::Unreachable);
        assert_eq!(missed.deadline_ms, invited_at + DEVICE_RING_GRACE_MS + TOMBSTONE_MS);
        assert!(matches!(note_device_fetch(missed, invited_at + DEVICE_RING_GRACE_MS), DeviceFetch::NotWaiting(_)));
    }

    #[test]
    fn a_device_fetch_starts_the_ring_clock_at_fetch_time() {
        let invited_at = 5_000u64;
        let fetch_at = invited_at + 4_000;
        let waiting = receive(None, 400, invited_at).unwrap();
        let ringing = match note_device_fetch(waiting, fetch_at) {
            DeviceFetch::Started(entry) => entry,
            other => panic!("fetch starts the ring, got {other:?}"),
        };
        assert_eq!(ringing.phase, Phase::Ringing);
        assert_eq!(ringing.deadline_ms, fetch_at + RING_TIMEOUT_MS);
        assert_ne!(ringing.deadline_ms, invited_at + RING_TIMEOUT_MS, "the 60 s runs from the fetch, not the invite");
        assert_eq!(ringing.clone().at(fetch_at + RING_TIMEOUT_MS - 1).unwrap().phase, Phase::Ringing);
        let no_answer = ringing.at(fetch_at + RING_TIMEOUT_MS).unwrap();
        assert_eq!((no_answer.phase, no_answer.deadline_ms), (Phase::Ended, fetch_at + RING_TIMEOUT_MS + TOMBSTONE_MS));
    }

    #[test]
    fn caller_and_callee_ring_deadlines_agree_at_the_ringing_ack() {
        let paid_at = 1_000u64;
        let fetch_at = paid_at + 10_000;
        let answer_at = paid_at + 65_000;
        let caller = commit(reserve(None, 400, "op", "h", paid_at).unwrap(), "op", paid_at);
        assert_eq!(caller.phase, Phase::Ringing);
        assert!(!caller.ring_anchored, "payment does not start the caller's 60 s clock");
        assert_eq!(caller.deadline_ms, paid_at + DEVICE_RING_GRACE_MS + RING_TIMEOUT_MS);
        assert!(answer_at < caller.deadline_ms, "the safety cap still covers a fetch-delayed answer");
        assert!(paid_at + RING_TIMEOUT_MS < answer_at, "a payment-anchored 60 s clock would already have ended");

        let callee = match note_device_fetch(receive(None, 400, paid_at).unwrap(), fetch_at) {
            DeviceFetch::Started(entry) => entry,
            other => panic!("fetch starts the callee clock, got {other:?}"),
        };
        assert_eq!(callee.deadline_ms, fetch_at + RING_TIMEOUT_MS);
        let caller = match note_ringing_ack(caller, fetch_at) {
            RingAck::Started(entry) => entry,
            other => panic!("the ringing ack anchors the caller, got {other:?}"),
        };
        assert!(caller.ring_anchored);
        assert_eq!(caller.deadline_ms, callee.deadline_ms, "caller and callee ring until the same instant");
        assert_eq!(callee.clone().at(answer_at).unwrap().phase, Phase::Ringing);
        assert_eq!(receive(Some(caller.clone()), 401, answer_at).unwrap().phase, Phase::Live);

        match note_ringing_ack(caller, fetch_at + 5_000) {
            RingAck::Unchanged(again) => assert_eq!(again.deadline_ms, fetch_at + RING_TIMEOUT_MS),
            other => panic!("a second ack must not restart the clock, got {other:?}"),
        }
    }

    #[test]
    fn a_second_device_fetch_does_not_restart_the_ring_clock() {
        let fetch_at = 8_000u64;
        let first = match note_device_fetch(receive(None, 400, 0).unwrap(), fetch_at) {
            DeviceFetch::Started(entry) => entry,
            other => panic!("first fetch starts the ring, got {other:?}"),
        };
        let later = fetch_at + 9_000;
        match note_device_fetch(first.clone(), later) {
            DeviceFetch::Unchanged(second) => {
                assert_eq!(second.deadline_ms, first.deadline_ms);
                assert_eq!(second.phase, Phase::Ringing);
                assert_ne!(second.deadline_ms, later + RING_TIMEOUT_MS);
            }
            other => panic!("second fetch must leave the clock, got {other:?}"),
        }
    }

    #[test]
    fn open_calls_are_bounded_and_burned_ids_are_bounded_separately() {
        // One peer cannot fill the global table: 4 open calls per peer × 1024 peers = 4096.
        assert_eq!(MAX_OPEN_CALLS_PER_PEER, 4);
        assert_eq!(MAX_OPEN_CALLS, 4096);
        let c = |open_peer, open_total, burned_peer, burned_total| CallCounts { open_peer, open_total, burned_peer, burned_total };
        assert!(has_room(&c(0, 0, 0, 0)).is_ok());
        assert_eq!(has_room(&c(MAX_OPEN_CALLS_PER_PEER, 0, 0, 0)), Err(CallRefusal::Full));
        assert_eq!(has_room(&c(0, MAX_OPEN_CALLS, 0, 0)), Err(CallRefusal::Full));
        // Burned ids never count against open calls (Fable N3).
        assert!(has_room(&c(MAX_OPEN_CALLS_PER_PEER - 1, MAX_OPEN_CALLS - 1, u64::MAX, u64::MAX)).is_ok());
        assert_eq!(burned_excess(MAX_BURNED_PER_PEER - 1, MAX_BURNED_PER_PEER), 0);
        assert_eq!(burned_excess(MAX_BURNED_PER_PEER, MAX_BURNED_PER_PEER), 1);
        // An id ended at t is evictable only from t + BURN_MIN_MS.
        let ended = commit(reserve(Some(receive(None, 400, 0).unwrap()), 403, "h", "h", 0).unwrap(), "h", 0);
        assert!(ended.replay_until_ms() > evictable_until(BURN_MIN_MS - 1));
        assert!(ended.replay_until_ms() <= evictable_until(BURN_MIN_MS));
    }

    #[test]
    fn journal_states_decide_commit_release_or_keep() {
        for s in [None, Some("prepared"), Some("released"), Some("abandoned")] {
            assert_eq!(settlement(s), Settlement::Unpaid);
        }
        for s in ["paid", "sent", "acked", "rejected_retryable", "failed_paid"] {
            assert_eq!(settlement(Some(s)), Settlement::Paid);
        }
        for s in ["paying", "payment_unknown", "something_new"] {
            assert_eq!(settlement(Some(s)), Settlement::Ambiguous);
        }
    }
}
